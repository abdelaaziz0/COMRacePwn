#include "platform/windows/junction.hpp"

#include "platform/windows/win_utils.hpp"

#include <winioctl.h>

#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace comrace::win {
namespace {

struct MountPointReparseBuffer {
  DWORD ReparseTag;
  WORD ReparseDataLength;
  WORD Reserved;
  WORD SubstituteNameOffset;
  WORD SubstituteNameLength;
  WORD PrintNameOffset;
  WORD PrintNameLength;
  WCHAR PathBuffer[1];
};

std::wstring nt_substitute_name(const std::wstring& normalizedTarget) {
  if (normalizedTarget.rfind(L"\\??\\", 0) == 0) {
    return normalizedTarget;
  }
  return L"\\??\\" + normalizedTarget;
}

}  // namespace

PreparedReparse prepare_mount_point(const std::string& targetDirectory) {
  const std::wstring normalizedTarget =
      normalize_windows_path(widen(targetDirectory));
  const std::wstring substitute = nt_substitute_name(normalizedTarget);
  const std::wstring printName = normalizedTarget;

  // Every length/offset below is narrowed to WORD or bounded by
  // MAXIMUM_REPARSE_DATA_BUFFER_SIZE. Validate before narrowing.
  const std::size_t substituteBytes = substitute.size() * sizeof(wchar_t);
  const std::size_t printBytes = printName.size() * sizeof(wchar_t);
  const std::size_t pathBytes =
      substituteBytes + sizeof(wchar_t) + printBytes + sizeof(wchar_t);
  const std::size_t reparseDataLength = sizeof(WORD) * 4 + pathBytes;
  const std::size_t bufferSize =
      offsetof(MountPointReparseBuffer, PathBuffer) + pathBytes;

  if (reparseDataLength > 0xFFFF ||
      bufferSize > MAXIMUM_REPARSE_DATA_BUFFER_SIZE) {
    throw std::runtime_error(
        "junction target path is too long for a mount-point reparse point: " +
        targetDirectory);
  }

  const WORD printOffset = static_cast<WORD>(substituteBytes + sizeof(wchar_t));

  PreparedReparse prepared;
  prepared.targetDirectory = targetDirectory;
  prepared.buffer.assign(bufferSize, 0);
  auto* buffer =
      reinterpret_cast<MountPointReparseBuffer*>(prepared.buffer.data());
  buffer->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
  buffer->SubstituteNameOffset = 0;
  buffer->SubstituteNameLength = static_cast<WORD>(substituteBytes);
  buffer->PrintNameOffset = printOffset;
  buffer->PrintNameLength = static_cast<WORD>(printBytes);
  buffer->ReparseDataLength = static_cast<WORD>(reparseDataLength);

  std::memcpy(buffer->PathBuffer, substitute.data(), substituteBytes);
  std::memcpy(
      reinterpret_cast<unsigned char*>(buffer->PathBuffer) + printOffset,
      printName.data(),
      printBytes);
  return prepared;
}

void set_mount_point(
    const std::string& linkDirectory,
    const PreparedReparse& prepared) {
  // Share the directory handle. Setting a reparse point does not require
  // exclusive access, and an exclusive open here can deadlock the race: the
  // privileged server may hold a create on linkDirectory\<file> that is frozen
  // pending our oplock-break acknowledgement, so an exclusive open of the parent
  // blocks before we ever reach oplock release.
  UniqueHandle directory(CreateFileW(
      widen(linkDirectory).c_str(),
      GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
      nullptr));
  if (!directory) {
    throw_last_error("CreateFileW(junction " + linkDirectory + ")");
  }

  set_mount_point_handle(directory.get(), prepared);
}

void set_mount_point_handle(
    HANDLE directory,
    const PreparedReparse& prepared) {
  if (directory == nullptr || directory == INVALID_HANDLE_VALUE) {
    throw std::runtime_error("invalid pinned directory handle for junction");
  }
  DWORD bytes = 0;
  if (!DeviceIoControl(
          directory,
          FSCTL_SET_REPARSE_POINT,
          const_cast<unsigned char*>(prepared.buffer.data()),
          static_cast<DWORD>(prepared.buffer.size()),
          nullptr,
          0,
          &bytes,
          nullptr)) {
    throw_last_error(
        "FSCTL_SET_REPARSE_POINT(target " + prepared.targetDirectory + ")");
  }
}

void create_junction(
    const std::string& linkDirectory,
    const std::string& targetDirectory) {
  ensure_directory_tree(targetDirectory);
  if (!CreateDirectoryW(widen(linkDirectory).c_str(), nullptr)) {
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) {
      throw_last_error("CreateDirectoryW(" + linkDirectory + ")");
    }
  }
  set_mount_point(linkDirectory, prepare_mount_point(targetDirectory));
}

bool remove_junction_if_exists(const std::string& linkDirectory) {
  if (!is_reparse_point(linkDirectory)) {
    return false;
  }
  return remove_directory_if_exists(linkDirectory);
}

}  // namespace comrace::win
