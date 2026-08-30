#include "platform/windows/oplock.hpp"

#include <winioctl.h>

#include <cstring>
#include <stdexcept>

namespace comrace::win {

Oplock::~Oplock() {
  release();
}

void Oplock::arm_on_file(const std::string& path) {
  release();

  event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event_) {
    throw_last_error("CreateEventW");
  }

  // Read-only, full sharing: we only want to observe the server's open, never
  // to block it on sharing. FILE_FLAG_OVERLAPPED so the oplock FSCTL completes
  // asynchronously when the oplock breaks.
  file_.reset(CreateFileW(
      widen(path).c_str(),
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
      nullptr));
  if (!file_) {
    throw_last_error("CreateFileW(oplock " + path + ")");
  }

  ZeroMemory(&overlapped_, sizeof(overlapped_));
  overlapped_.hEvent = event_.get();

  // Modern oplock: request Read+Write+Handle caching. Any conflicting open by
  // the target breaks it and completes the overlapped FSCTL. Preferred over the
  // legacy FSCTL_REQUEST_BATCH_OPLOCK - explicit levels, structured break info,
  // and directory oplocks share this path.
  ZeroMemory(&request_, sizeof(request_));
  request_.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
  request_.StructureLength = sizeof(request_);
  request_.RequestedOplockLevel =
      OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE | OPLOCK_LEVEL_CACHE_WRITE;
  request_.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

  ZeroMemory(&response_, sizeof(response_));
  response_.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
  response_.StructureLength = sizeof(response_);

  DWORD bytes = 0;
  const BOOL ok = DeviceIoControl(
      file_.get(),
      FSCTL_REQUEST_OPLOCK,
      &request_, sizeof(request_),
      &response_, sizeof(response_),
      &bytes,
      &overlapped_);
  if (ok) {
    // A *granted* oplock request pends (ERROR_IO_PENDING) and only completes on
    // break. Synchronous completion means the oplock was not granted - usually
    // another handle is already open on the bait. Fail the arm so the attempt
    // is retried against a fresh bait rather than racing with no real trigger.
    release();
    throw std::runtime_error(
        "FSCTL_REQUEST_OPLOCK completed synchronously (oplock not granted; "
        "another handle open on the bait?)");
  }
  const DWORD error = GetLastError();
  if (error != ERROR_IO_PENDING) {
    throw std::runtime_error(
        "FSCTL_REQUEST_OPLOCK failed: " + last_error_message(error));
  }
  armed_ = true;
  requestPending_ = true;
}

bool Oplock::wait_for_break(unsigned timeoutMs) {
  if (!armed_) {
    return false;
  }
  const DWORD wait = WaitForSingleObject(event_.get(), timeoutMs);
  if (wait == WAIT_OBJECT_0) {
    // The FSCTL has completed. Reap it so the OVERLAPPED/response buffer is no
    // longer in use and we can read the granted/broken oplock level.
    DWORD bytes = 0;
    if (!GetOverlappedResult(file_.get(), &overlapped_, &bytes, FALSE)) {
      const DWORD error = GetLastError();
      // If a supposedly signalled event is observed before completion, retain
      // ownership state so release() drains the request before destroying its
      // OVERLAPPED and response buffer.
      if (error != ERROR_IO_INCOMPLETE) {
        requestPending_ = false;
      }
      throw std::runtime_error(
          "GetOverlappedResult(oplock break) failed: " +
          last_error_message(error));
    }
    requestPending_ = false;
    broken_ = true;
    return true;
  }
  if (wait == WAIT_TIMEOUT) {
    return false;
  }
  throw_last_error("WaitForSingleObject(oplock)");
}

void Oplock::release() {
  if (requestPending_ && file_) {
    // CancelIoEx only *requests* cancellation. The OVERLAPPED structure and the
    // event stay in use by the kernel until the operation actually finishes, so
    // wait for it (GetOverlappedResult with bWait) before tearing anything down.
    // A break that already completed reaps immediately.
    CancelIoEx(file_.get(), &overlapped_);
    DWORD bytes = 0;
    GetOverlappedResult(file_.get(), &overlapped_, &bytes, TRUE);
    requestPending_ = false;
    // Closing the handle then releases the oplock and acks any pending break.
  }
  armed_ = false;
  requestPending_ = false;
  broken_ = false;
  file_.reset();
  event_.reset();
  ZeroMemory(&overlapped_, sizeof(overlapped_));
  ZeroMemory(&request_, sizeof(request_));
  ZeroMemory(&response_, sizeof(response_));
}

}  // namespace comrace::win
