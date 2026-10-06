#include "platform/windows/race_sensor.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>

namespace comrace::win {
namespace {

std::wstring file_name_of(const std::string& path) {
  const std::wstring wide = widen(path);
  const std::size_t slash = wide.find_last_of(L"\\/");
  return slash == std::wstring::npos ? wide : wide.substr(slash + 1);
}

bool iequals(const std::wstring& a, const std::wstring& b) {
  return a.size() == b.size() &&
         std::equal(a.begin(), a.end(), b.begin(), [](wchar_t x, wchar_t y) {
           return std::towlower(x) == std::towlower(y);
         });
}

using NtQueryWnfStateDataFn = LONG(NTAPI*)(
    const unsigned long long* stateName,
    void* typeId,
    void* callbackContext,
    int* changeStamp,
    void* buffer,
    unsigned long* bufferSize);

NtQueryWnfStateDataFn nt_query_wnf_state_data() {
  static const NtQueryWnfStateDataFn fn = reinterpret_cast<NtQueryWnfStateDataFn>(
      reinterpret_cast<void*>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtQueryWnfStateData")));
  if (fn == nullptr) {
    throw std::runtime_error("NtQueryWnfStateData is unavailable in ntdll");
  }
  return fn;
}

}

TriggerKind parse_trigger_kind(const std::string& value) {
  if (value.empty() || value == "oplock_on_source") {
    return TriggerKind::FileOplock;
  }
  if (value == "directory_watch") {
    return TriggerKind::DirectoryWatch;
  }
  if (value == "wnf_state") {
    return TriggerKind::Wnf;
  }
  throw std::runtime_error("unsupported race_trigger: " + value);
}

std::string to_string(TriggerKind kind) {
  switch (kind) {
    case TriggerKind::DirectoryWatch:
      return "directory_watch";
    case TriggerKind::Wnf:
      return "wnf_state";
    case TriggerKind::FileOplock:
      return "oplock_on_source";
  }
  return "unknown";
}

RaceSensor::RaceSensor(
    TriggerKind kind,
    std::string baitPath,
    std::string baitDirectory,
    std::string wnfStateHex)
    : kind_(kind),
      baitPath_(std::move(baitPath)),
      baitDirectory_(std::move(baitDirectory)),
      baitFileName_(file_name_of(baitPath_)) {
  if (kind_ == TriggerKind::Wnf) {
    if (wnfStateHex.size() != 16) {
      throw std::runtime_error(
          "wnf_state trigger requires a 16 hex char state name");
    }
    for (const char c : wnfStateHex) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        throw std::runtime_error(
            "wnf state name must be hex: " + wnfStateHex);
      }
    }
    wnfStateName_ = std::stoull(wnfStateHex, nullptr, 16);
  }
}

RaceSensor::~RaceSensor() {
  release();
}

void RaceSensor::arm() {
  if (kind_ == TriggerKind::FileOplock) {
    oplock_.arm_on_file(baitPath_);
    return;
  }

  dirEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!dirEvent_) {
    throw_last_error("CreateEventW(directory watch)");
  }
  dirHandle_.reset(CreateFileW(
      widen(baitDirectory_).c_str(),
      FILE_LIST_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
      nullptr));
  if (!dirHandle_) {
    throw_last_error("CreateFileW(directory watch " + baitDirectory_ + ")");
  }
  if (!rearm_directory_watch()) {
    throw std::runtime_error("ReadDirectoryChangesW failed: " + last_error_message());
  }
  dirArmed_ = true;
}

bool RaceSensor::rearm_directory_watch() {
  dirRequestIssued_ = false;
  ZeroMemory(&dirOverlapped_, sizeof(dirOverlapped_));
  dirOverlapped_.hEvent = dirEvent_.get();
  ResetEvent(dirEvent_.get());
  DWORD bytes = 0;
  if (ReadDirectoryChangesW(
          dirHandle_.get(),
          dirBuffer_, sizeof(dirBuffer_),
          FALSE,
          FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_ACCESS |
              FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_LAST_WRITE |
              FILE_NOTIFY_CHANGE_SIZE,
          &bytes,
          &dirOverlapped_,
          nullptr)) {

    dirRequestIssued_ = true;
    return true;
  }
  if (GetLastError() == ERROR_IO_PENDING) {
    dirRequestIssued_ = true;
    return true;
  }
  return false;
}

bool RaceSensor::wait_for_signal(unsigned timeoutMs) {
  if (kind_ == TriggerKind::FileOplock) {
    return oplock_.wait_for_break(timeoutMs);
  }
  if (kind_ == TriggerKind::Wnf) {
    return wait_wnf_signal(timeoutMs);
  }
  return wait_directory_signal(timeoutMs);
}

void RaceSensor::arm_wnf() {
  unsigned long bufferSize = sizeof(wnfSnapshot_);
  int changeStamp = 0;
  const LONG status = nt_query_wnf_state_data()(
      &wnfStateName_,
      nullptr,
      nullptr,
      &changeStamp,
      wnfSnapshot_,
      &bufferSize);
  if (status < 0) {
    std::ostringstream out;
    out << "NtQueryWnfStateData(arm) failed with status 0x" << std::hex << status;
    throw std::runtime_error(out.str());
  }
  wnfSnapshotSize_ = bufferSize;
}

bool RaceSensor::wait_wnf_signal(unsigned timeoutMs) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  for (;;) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    alignas(8) unsigned char buffer[256]{};
    unsigned long bufferSize = sizeof(buffer);
    int changeStamp = 0;
    const LONG status = nt_query_wnf_state_data()(
        &wnfStateName_, nullptr, nullptr, &changeStamp, buffer, &bufferSize);
    if (status >= 0 &&
        (bufferSize != wnfSnapshotSize_ ||
         std::memcmp(
             buffer, wnfSnapshot_,
             static_cast<std::size_t>(
                 (std::min)(static_cast<std::size_t>(bufferSize), wnfSnapshotSize_))) != 0)) {
      return true;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
  }
}

bool RaceSensor::wait_directory_signal(unsigned timeoutMs) {
  if (!dirArmed_) {
    return false;
  }
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

  for (;;) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return false;
    }
    const DWORD remaining = static_cast<DWORD>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());

    const DWORD wait = WaitForSingleObject(dirEvent_.get(), remaining);
    if (wait == WAIT_TIMEOUT) {
      return false;
    }
    if (wait != WAIT_OBJECT_0) {
      throw_last_error("WaitForSingleObject(directory watch)");
    }

    DWORD transferred = 0;
    if (!GetOverlappedResult(dirHandle_.get(), &dirOverlapped_, &transferred, FALSE)) {
      const DWORD error = GetLastError();
      if (error == ERROR_IO_INCOMPLETE) {

        throw std::runtime_error(
            "directory watch event signalled before I/O completion");
      }
      dirRequestIssued_ = false;
      if (error == ERROR_OPERATION_ABORTED) {
        return false;
      }
      if (!rearm_directory_watch()) {
        return false;
      }
      continue;
    }
    dirRequestIssued_ = false;

    bool matched = false;
    if (transferred >= sizeof(FILE_NOTIFY_INFORMATION)) {
      const auto* record =
          reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(dirBuffer_);
      for (;;) {
        const std::wstring name(
            record->FileName, record->FileNameLength / sizeof(WCHAR));
        if ((record->Action == FILE_ACTION_ADDED ||
             record->Action == FILE_ACTION_MODIFIED ||
             record->Action == FILE_ACTION_RENAMED_NEW_NAME) &&
            iequals(name, baitFileName_)) {
          matched = true;
          break;
        }
        if (record->NextEntryOffset == 0) {
          break;
        }
        record = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
            reinterpret_cast<const unsigned char*>(record) + record->NextEntryOffset);
      }
    }

    if (matched) {
      return true;
    }
    if (!rearm_directory_watch()) {
      return false;
    }
  }
}

void RaceSensor::release() {
  if (kind_ == TriggerKind::FileOplock) {
    oplock_.release();
    return;
  }
  if (dirRequestIssued_ && dirHandle_) {

    CancelIoEx(dirHandle_.get(), &dirOverlapped_);
    DWORD bytes = 0;
    GetOverlappedResult(dirHandle_.get(), &dirOverlapped_, &bytes, TRUE);
    dirRequestIssued_ = false;
  }
  dirArmed_ = false;
  dirRequestIssued_ = false;
  dirHandle_.reset();
  dirEvent_.reset();
  ZeroMemory(&dirOverlapped_, sizeof(dirOverlapped_));
}

}
