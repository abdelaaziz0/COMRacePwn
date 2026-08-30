#include "platform/windows/win_utils.hpp"

#include <aclapi.h>
#include <bcrypt.h>
#include <objbase.h>
#include <sddl.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <utility>
#include <vector>

namespace comrace::win {
namespace {

constexpr DWORD kCompareChunkBytes = 64 * 1024;

bool is_valid_handle(HANDLE handle) {
  return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

bool is_separator(wchar_t c) {
  return c == L'\\' || c == L'/';
}

std::string join_probe_path(const std::string& directory) {
  std::ostringstream name;
  name << ".comwriterace-precheck-" << GetCurrentProcessId() << "-" << GetTickCount64() << ".tmp";
  if (directory.empty()) {
    return name.str();
  }
  const char tail = directory.back();
  if (tail == '\\' || tail == '/') {
    return directory + name.str();
  }
  return directory + "\\" + name.str();
}

std::string filetime_to_utc_string(const FILETIME& filetime) {
  SYSTEMTIME systemTime{};
  if (!FileTimeToSystemTime(&filetime, &systemTime)) {
    return "unavailable";
  }

  char buffer[32]{};
  std::snprintf(
      buffer,
      sizeof(buffer),
      "%04u-%02u-%02uT%02u:%02u:%02uZ",
      systemTime.wYear,
      systemTime.wMonth,
      systemTime.wDay,
      systemTime.wHour,
      systemTime.wMinute,
      systemTime.wSecond);
  return buffer;
}

std::string sid_to_account(PSID sid) {
  if (sid == nullptr) {
    return "unavailable";
  }

  DWORD nameChars = 0;
  DWORD domainChars = 0;
  SID_NAME_USE use{};
  LookupAccountSidW(nullptr, sid, nullptr, &nameChars, nullptr, &domainChars, &use);

  if (nameChars != 0) {
    std::wstring name(nameChars, L'\0');
    std::wstring domain(domainChars, L'\0');
    if (LookupAccountSidW(
            nullptr,
            sid,
            name.data(),
            &nameChars,
            domain.data(),
            &domainChars,
            &use)) {
      name.resize(nameChars);
      domain.resize(domainChars);
      if (!domain.empty()) {
        return narrow(domain) + "\\" + narrow(name);
      }
      return narrow(name);
    }
  }

  LPWSTR sidString = nullptr;
  if (ConvertSidToStringSidW(sid, &sidString) && sidString != nullptr) {
    std::wstring value(sidString);
    LocalFree(sidString);
    return narrow(value);
  }

  return "unavailable";
}

std::string integrity_from_sacl(PACL sacl) {
  // Empty string = read OK, no explicit label ACE (object is implicitly Medium).
  // "unavailable" = the label could not be read at all.
  if (sacl == nullptr) {
    return {};
  }

  for (DWORD i = 0; i < sacl->AceCount; ++i) {
    void* ace = nullptr;
    if (!GetAce(sacl, i, &ace) || ace == nullptr) {
      continue;
    }
    auto* header = static_cast<ACE_HEADER*>(ace);
    if (header->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
      continue;
    }
    auto* label = static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(ace);
    PSID sid = reinterpret_cast<PSID>(&label->SidStart);
    const UCHAR* count = GetSidSubAuthorityCount(sid);
    if (count == nullptr || *count == 0) {
      continue;
    }
    const DWORD rid = *GetSidSubAuthority(sid, *count - 1);
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
      return "Low";
    }
    if (rid < SECURITY_MANDATORY_HIGH_RID) {
      return "Medium";
    }
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
      return "High";
    }
    return "System";
  }

  return {};
}

UniqueHandle open_read_file(const std::string& path) {
  UniqueHandle file(CreateFileW(
      widen(path).c_str(),
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr));
  return file;
}

bool file_size_from_attributes(const std::string& path, unsigned long long& size) {
  WIN32_FILE_ATTRIBUTE_DATA attributes{};
  if (!GetFileAttributesExW(widen(path).c_str(), GetFileExInfoStandard, &attributes)) {
    return false;
  }
  ULARGE_INTEGER value{};
  value.HighPart = attributes.nFileSizeHigh;
  value.LowPart = attributes.nFileSizeLow;
  size = value.QuadPart;
  return true;
}

bool compare_file_to_content(const std::string& path, const std::string& expectedContent) {
  unsigned long long size = 0;
  if (!file_size_from_attributes(path, size) || size != expectedContent.size()) {
    return false;
  }

  UniqueHandle file = open_read_file(path);
  if (!file) {
    return false;
  }

  std::vector<char> buffer(kCompareChunkBytes);
  std::size_t offset = 0;
  while (offset < expectedContent.size()) {
    const std::size_t remaining = expectedContent.size() - offset;
    const DWORD wanted = static_cast<DWORD>(std::min<std::size_t>(buffer.size(), remaining));
    DWORD read = 0;
    if (!ReadFile(file.get(), buffer.data(), wanted, &read, nullptr) || read != wanted) {
      return false;
    }
    if (std::memcmp(buffer.data(), expectedContent.data() + offset, read) != 0) {
      return false;
    }
    offset += read;
  }
  return true;
}

bool compare_file_to_file(const std::string& leftPath, const std::string& rightPath) {
  unsigned long long leftSize = 0;
  unsigned long long rightSize = 0;
  if (!file_size_from_attributes(leftPath, leftSize) ||
      !file_size_from_attributes(rightPath, rightSize) ||
      leftSize != rightSize) {
    return false;
  }

  UniqueHandle left = open_read_file(leftPath);
  UniqueHandle right = open_read_file(rightPath);
  if (!left || !right) {
    return false;
  }

  std::vector<unsigned char> leftBuffer(kCompareChunkBytes);
  std::vector<unsigned char> rightBuffer(kCompareChunkBytes);
  while (true) {
    DWORD leftRead = 0;
    DWORD rightRead = 0;
    if (!ReadFile(left.get(), leftBuffer.data(), static_cast<DWORD>(leftBuffer.size()), &leftRead, nullptr) ||
        !ReadFile(right.get(), rightBuffer.data(), static_cast<DWORD>(rightBuffer.size()), &rightRead, nullptr)) {
      return false;
    }
    if (leftRead != rightRead) {
      return false;
    }
    if (leftRead == 0) {
      return true;
    }
    if (std::memcmp(leftBuffer.data(), rightBuffer.data(), leftRead) != 0) {
      return false;
    }
  }
}

bool contains_text_case_insensitive(std::string content, std::string expectedText) {
  std::transform(content.begin(), content.end(), content.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  std::transform(
      expectedText.begin(),
      expectedText.end(),
      expectedText.begin(),
      [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
  if (content.find(expectedText) != std::string::npos) {
    return true;
  }

  std::string expectedUtf16Le;
  expectedUtf16Le.reserve(expectedText.size() * 2);
  for (const char c : expectedText) {
    expectedUtf16Le.push_back(c);
    expectedUtf16Le.push_back('\0');
  }
  return content.find(expectedUtf16Le) != std::string::npos;
}

FileObservation inspect_file_metadata(const std::string& path) {
  FileObservation observation;
  observation.exists = file_exists(path);
  if (!observation.exists) {
    return observation;
  }

  WIN32_FILE_ATTRIBUTE_DATA attributes{};
  if (GetFileAttributesExW(widen(path).c_str(), GetFileExInfoStandard, &attributes)) {
    ULARGE_INTEGER size{};
    size.HighPart = attributes.nFileSizeHigh;
    size.LowPart = attributes.nFileSizeLow;
    observation.size = size.QuadPart;
    observation.creationTimeUtc = filetime_to_utc_string(attributes.ftCreationTime);
    observation.lastWriteTimeUtc = filetime_to_utc_string(attributes.ftLastWriteTime);
  }

  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR ownerDescriptor = nullptr;
  std::wstring wide = widen(path);
  DWORD error = GetNamedSecurityInfoW(
      wide.data(),
      SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION,
      &owner,
      nullptr,
      nullptr,
      nullptr,
      &ownerDescriptor);
  observation.owner = error == ERROR_SUCCESS ? sid_to_account(owner) : "unavailable";
  if (ownerDescriptor != nullptr) {
    LocalFree(ownerDescriptor);
  }

  PACL sacl = nullptr;
  PSECURITY_DESCRIPTOR labelDescriptor = nullptr;
  wide = widen(path);
  error = GetNamedSecurityInfoW(
      wide.data(),
      SE_FILE_OBJECT,
      LABEL_SECURITY_INFORMATION,
      nullptr,
      nullptr,
      nullptr,
      &sacl,
      &labelDescriptor);
  observation.integrityLabel = error == ERROR_SUCCESS ? integrity_from_sacl(sacl) : "unavailable";
  if (labelDescriptor != nullptr) {
    LocalFree(labelDescriptor);
  }

  return observation;
}

}  // namespace

UniqueHandle::~UniqueHandle() {
  reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept {
  if (this != &other) {
    reset(other.release());
  }
  return *this;
}

HANDLE* UniqueHandle::put() {
  reset();
  return &handle_;
}

HANDLE UniqueHandle::release() {
  HANDLE handle = handle_;
  handle_ = INVALID_HANDLE_VALUE;
  return handle;
}

void UniqueHandle::reset(HANDLE handle) {
  if (is_valid_handle(handle_)) {
    CloseHandle(handle_);
  }
  handle_ = handle;
}

std::wstring widen(const std::string& value) {
  if (value.empty()) {
    return {};
  }
  const int needed = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (needed <= 0) {
    throw_last_error("MultiByteToWideChar");
  }
  std::wstring out(static_cast<std::size_t>(needed), L'\0');
  const int written = MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      value.data(),
      static_cast<int>(value.size()),
      out.data(),
      needed);
  if (written != needed) {
    throw_last_error("MultiByteToWideChar");
  }
  return out;
}

std::string narrow(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }
  const int needed = WideCharToMultiByte(
      CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    throw_last_error("WideCharToMultiByte");
  }
  std::string out(static_cast<std::size_t>(needed), '\0');
  const int written = WideCharToMultiByte(
      CP_UTF8,
      0,
      value.data(),
      static_cast<int>(value.size()),
      out.data(),
      needed,
      nullptr,
      nullptr);
  if (written != needed) {
    throw_last_error("WideCharToMultiByte");
  }
  return out;
}

std::string last_error_message(DWORD error) {
  LPWSTR buffer = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&buffer),
      0,
      nullptr);

  std::wstring message;
  if (length != 0 && buffer != nullptr) {
    message.assign(buffer, length);
    LocalFree(buffer);
  } else {
    message = L"unknown Windows error";
  }

  while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
    message.pop_back();
  }

  std::ostringstream out;
  out << narrow(message) << " (0x" << std::hex << error << ")";
  return out.str();
}

std::string hresult_message(HRESULT hr) {
  if (HRESULT_FACILITY(hr) == FACILITY_WIN32) {
    return last_error_message(HRESULT_CODE(hr));
  }
  std::ostringstream out;
  out << "HRESULT 0x" << std::hex << static_cast<unsigned long>(hr);
  return out.str();
}

[[noreturn]] void throw_last_error(const std::string& action) {
  throw std::runtime_error(action + " failed: " + last_error_message());
}

void throw_if_failed(HRESULT hr, const std::string& action) {
  if (FAILED(hr)) {
    throw std::runtime_error(action + " failed: " + hresult_message(hr));
  }
}

std::wstring normalize_windows_path(std::wstring path) {
  std::replace(path.begin(), path.end(), L'/', L'\\');
  return path;
}

std::string full_path_name(const std::string& path) {
  const std::wstring input = normalize_windows_path(widen(path));
  const DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
  if (needed == 0) {
    throw_last_error("GetFullPathNameW(" + path + ")");
  }

  std::wstring output(needed, L'\0');
  const DWORD written = GetFullPathNameW(input.c_str(), needed, output.data(), nullptr);
  if (written == 0 || written >= needed) {
    throw_last_error("GetFullPathNameW(" + path + ")");
  }

  output.resize(written);
  output = normalize_windows_path(output);
  while (output.size() > 3 && output.back() == L'\\') {
    output.pop_back();
  }
  return narrow(output);
}

PathIdentity path_identity(const std::string& path) {
  PathIdentity identity;
  UniqueHandle handle(CreateFileW(
      normalize_windows_path(widen(path)).c_str(),
      0,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,  // follow reparse points, open directories
      nullptr));
  if (!handle) {
    return identity;
  }
  FILE_ID_INFO info{};
  if (!GetFileInformationByHandleEx(handle.get(), FileIdInfo, &info, sizeof(info))) {
    return identity;
  }
  identity.ok = true;
  identity.volumeSerial = info.VolumeSerialNumber;
  std::ostringstream hex;
  for (unsigned char byte : info.FileId.Identifier) {
    hex << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<unsigned>(byte);
  }
  identity.fileId = hex.str();
  return identity;
}

namespace {

PathIdentity path_identity_from_handle(HANDLE handle) {
  PathIdentity identity;
  FILE_ID_INFO info{};
  if (!GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info))) {
    return identity;
  }
  identity.ok = true;
  identity.volumeSerial = info.VolumeSerialNumber;
  std::ostringstream hex;
  for (unsigned char byte : info.FileId.Identifier) {
    hex << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<unsigned>(byte);
  }
  identity.fileId = hex.str();
  return identity;
}

bool handle_is_reparse_point(HANDLE handle) {
  FILE_ATTRIBUTE_TAG_INFO info{};
  if (!GetFileInformationByHandleEx(
          handle, FileAttributeTagInfo, &info, sizeof(info))) {
    throw_last_error("GetFileInformationByHandleEx(FileAttributeTagInfo)");
  }
  return (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

std::vector<std::string> directory_components_below_root(
    const std::string& path) {
  const std::wstring full = normalize_windows_path(widen(full_path_name(path)));
  std::size_t rootEnd = 0;
  if (full.size() >= 3 && full[1] == L':' && full[2] == L'\\') {
    rootEnd = 3;
  } else if (full.rfind(L"\\\\", 0) == 0) {
    const std::size_t serverEnd = full.find(L'\\', 2);
    const std::size_t shareEnd = serverEnd == std::wstring::npos
        ? std::wstring::npos
        : full.find(L'\\', serverEnd + 1);
    if (serverEnd == std::wstring::npos) {
      throw std::runtime_error("UNC path is missing a share name: " + path);
    }
    rootEnd = shareEnd == std::wstring::npos ? full.size() : shareEnd + 1;
  } else {
    throw std::runtime_error("path is not drive-absolute or UNC: " + path);
  }

  std::vector<std::string> components;
  std::size_t end = rootEnd;
  while (end < full.size()) {
    const std::size_t slash = full.find(L'\\', end);
    const std::size_t componentEnd =
        slash == std::wstring::npos ? full.size() : slash;
    if (componentEnd > rootEnd) {
      components.push_back(narrow(full.substr(0, componentEnd)));
    }
    if (slash == std::wstring::npos) {
      break;
    }
    end = slash + 1;
  }
  return components;
}

}  // namespace

PinnedDirectoryTree::PinnedDirectoryTree(
    const std::string& path,
    bool writableLeaf) {
  paths_ = directory_components_below_root(path);
  if (paths_.empty()) {
    throw std::runtime_error(
        "refusing to pin a volume/share root as a workspace path");
  }
  handles_.reserve(paths_.size());
  identities_.reserve(paths_.size());
  for (std::size_t i = 0; i < paths_.size(); ++i) {
    const bool leaf = i + 1 == paths_.size();
    const DWORD access = FILE_READ_ATTRIBUTES |
        ((leaf && writableLeaf) ? GENERIC_WRITE : 0);
    // Every component denies delete sharing, which pins its name/object against
    // rename and replacement. Ordinary ancestors still share write access so
    // unrelated processes holding writable directory handles do not make the
    // run unusable. The tool-managed safe leaf is also write-exclusive because
    // its pre-opened handle performs the reparse FSCTL itself.
    const DWORD sharing = FILE_SHARE_READ |
        ((leaf && writableLeaf) ? 0 : FILE_SHARE_WRITE);
    UniqueHandle handle(CreateFileW(
        widen(paths_[i]).c_str(),
        access,
        sharing,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!handle) {
      throw_last_error("CreateFileW(pin directory " + paths_[i] + ")");
    }
    if (handle_is_reparse_point(handle.get())) {
      throw std::runtime_error(
          "refusing to pin reparse-point path component: " + paths_[i]);
    }
    const PathIdentity identity = path_identity_from_handle(handle.get());
    if (!identity.ok) {
      throw_last_error("GetFileInformationByHandleEx(pin " + paths_[i] + ")");
    }
    identities_.push_back(identity);
    handles_.push_back(std::move(handle));
  }
  leafIdentity_ = identities_.back();
}

HANDLE PinnedDirectoryTree::leaf_handle() const {
  return handles_.empty() ? INVALID_HANDLE_VALUE : handles_.back().get();
}

bool PinnedDirectoryTree::verify(bool allowLeafReparse) const {
  if (handles_.size() != identities_.size() || handles_.empty()) {
    return false;
  }
  for (std::size_t i = 0; i < handles_.size(); ++i) {
    const bool leaf = i + 1 == handles_.size();
    try {
      if (handle_is_reparse_point(handles_[i].get()) &&
          !(leaf && allowLeafReparse)) {
        return false;
      }
    } catch (...) {
      return false;
    }
    const PathIdentity current = path_identity_from_handle(handles_[i].get());
    if (!current.ok || current.volumeSerial != identities_[i].volumeSerial ||
        current.fileId != identities_[i].fileId) {
      return false;
    }
  }
  return true;
}

void PinnedDirectoryTree::reset() {
  handles_.clear();
  identities_.clear();
  paths_.clear();
  leafIdentity_ = {};
}

bool has_reparse_component(const std::string& path, std::string& firstReparse) {
  std::string current = full_path_name(path);
  // Check the path itself, then each ancestor, up to the volume root ("C:").
  while (current.size() > 2) {
    if (path_exists(current) && is_reparse_point(current)) {
      firstReparse = current;
      return true;
    }
    const std::size_t slash = current.find_last_of('\\');
    if (slash == std::string::npos || slash <= 2) {
      break;
    }
    current = current.substr(0, slash);
  }
  return false;
}

void ensure_directory_tree(const std::string& path) {
  std::wstring wide = normalize_windows_path(widen(path));
  if (wide.empty()) {
    return;
  }

  std::size_t start = 0;
  if (wide.size() >= 3 && wide[1] == L':' && is_separator(wide[2])) {
    start = 3;
  } else if (wide.size() >= 2 && is_separator(wide[0]) && is_separator(wide[1])) {
    std::size_t first = wide.find(L'\\', 2);
    std::size_t second = first == std::wstring::npos ? std::wstring::npos : wide.find(L'\\', first + 1);
    start = second == std::wstring::npos ? wide.size() : second + 1;
  }

  for (std::size_t pos = wide.find(L'\\', start); pos != std::wstring::npos;
       pos = wide.find(L'\\', pos + 1)) {
    const std::wstring part = wide.substr(0, pos);
    if (!part.empty() && !CreateDirectoryW(part.c_str(), nullptr)) {
      const DWORD error = GetLastError();
      if (error != ERROR_ALREADY_EXISTS) {
        throw std::runtime_error(
            "CreateDirectoryW(" + narrow(part) + ") failed: " + last_error_message(error));
      }
    }
  }

  if (!CreateDirectoryW(wide.c_str(), nullptr)) {
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) {
      throw std::runtime_error("CreateDirectoryW(" + path + ") failed: " + last_error_message(error));
    }
  }
}

bool path_exists(const std::string& path) {
  return GetFileAttributesW(widen(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool file_exists(const std::string& path) {
  const DWORD attributes = GetFileAttributesW(widen(path).c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool directory_exists(const std::string& path) {
  const DWORD attributes = GetFileAttributesW(widen(path).c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool is_reparse_point(const std::string& path) {
  const DWORD attributes = GetFileAttributesW(widen(path).c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool file_contains_text_case_insensitive(
    const std::string& path,
    const std::string& expectedText) {
  constexpr unsigned long long kMaximumMarkerBytes = 1024 * 1024;

  unsigned long long size = 0;
  if (expectedText.empty() ||
      !file_size_from_attributes(path, size) ||
      size == 0 ||
      size > kMaximumMarkerBytes) {
    return false;
  }

  UniqueHandle file = open_read_file(path);
  if (!file) {
    return false;
  }

  std::string content(static_cast<std::size_t>(size), '\0');
  std::size_t offset = 0;
  while (offset < content.size()) {
    DWORD read = 0;
    const DWORD wanted = static_cast<DWORD>(
        std::min<std::size_t>(content.size() - offset, kCompareChunkBytes));
    if (!ReadFile(file.get(), content.data() + offset, wanted, &read, nullptr)) {
      return false;
    }
    if (read == 0) {
      break;
    }
    offset += read;
  }
  content.resize(offset);
  return contains_text_case_insensitive(std::move(content), expectedText);
}

void delete_file_if_exists(const std::string& path) {
  if (DeleteFileW(widen(path).c_str())) {
    return;
  }
  const DWORD error = GetLastError();
  if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
    throw_last_error("DeleteFileW(" + path + ")");
  }
}

DWORD try_delete_file(const std::string& path) {
  if (DeleteFileW(widen(path).c_str())) {
    return ERROR_SUCCESS;
  }
  const DWORD error = GetLastError();
  if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
    return ERROR_SUCCESS;
  }
  return error;
}

std::string current_process_user_sid() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return "unavailable";
  }
  DWORD needed = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
  std::string result = "unavailable";
  if (needed != 0) {
    std::vector<unsigned char> buffer(needed);
    if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
      const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
      LPWSTR sidString = nullptr;
      if (ConvertSidToStringSidW(user->User.Sid, &sidString) && sidString) {
        result = narrow(sidString);
        LocalFree(sidString);
      }
    }
  }
  CloseHandle(token);
  return result;
}

std::string current_process_integrity() {
  HANDLE rawToken = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
    return "unavailable";
  }
  UniqueHandle token(rawToken);
  DWORD needed = 0;
  GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &needed);
  if (needed == 0) return "unavailable";
  std::vector<unsigned char> buffer(needed);
  if (!GetTokenInformation(
          token.get(), TokenIntegrityLevel, buffer.data(), needed, &needed)) {
    return "unavailable";
  }
  const auto* label =
      reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
  const DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
  if (count == 0) return "unavailable";
  const DWORD rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
  if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
  if (rid >= SECURITY_MANDATORY_HIGH_RID) return "High";
  if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
  if (rid >= SECURITY_MANDATORY_LOW_RID) return "Low";
  return "Untrusted";
}

std::string windows_build_string() {
  struct VersionInfo {
    ULONG size;
    ULONG major;
    ULONG minor;
    ULONG build;
    ULONG platform;
    WCHAR servicePack[128];
  };
  using RtlGetVersionFn = LONG(WINAPI*)(VersionInfo*);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) return "unavailable";
  FARPROC raw = GetProcAddress(ntdll, "RtlGetVersion");
  if (raw == nullptr) return "unavailable";
  RtlGetVersionFn getVersion = nullptr;
  static_assert(sizeof(getVersion) == sizeof(raw));
  std::memcpy(&getVersion, &raw, sizeof(raw));
  VersionInfo info{};
  info.size = sizeof(info);
  if (getVersion(&info) < 0) return "unavailable";
  std::ostringstream out;
  out << info.major << '.' << info.minor << '.' << info.build;
  return out.str();
}

std::string new_guid_token() {
  GUID guid{};
  if (FAILED(CoCreateGuid(&guid))) {
    return {};
  }
  wchar_t text[40]{};
  if (StringFromGUID2(guid, text, 40) == 0) {
    return {};
  }
  std::string token = narrow(text);
  if (token.size() >= 2 && token.front() == '{' && token.back() == '}') {
    token = token.substr(1, token.size() - 2);
  }
  return token;
}

void copy_file_with_nonce_overlay(
    const std::string& source,
    const std::string& destination,
    const std::string& nonce) {
  if (nonce.empty()) {
    throw std::runtime_error("refusing to stage a lab marker payload with an empty nonce");
  }
  if (!CopyFileW(widen(source).c_str(), widen(destination).c_str(), TRUE)) {
    throw_last_error("CopyFileW(nonce-staged payload)");
  }
  try {
    UniqueHandle file(CreateFileW(
        widen(destination).c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file) {
      throw_last_error("CreateFileW(nonce-staged payload)");
    }
    const std::string overlay =
        "\r\nCWR_EXPERIMENT_NONCE=" + nonce + "\r\n";
    DWORD written = 0;
    if (!WriteFile(
            file.get(), overlay.data(), static_cast<DWORD>(overlay.size()),
            &written, nullptr) ||
        static_cast<std::size_t>(written) != overlay.size()) {
      throw_last_error("WriteFile(nonce-staged payload)");
    }
    if (!FlushFileBuffers(file.get())) {
      throw_last_error("FlushFileBuffers(nonce-staged payload)");
    }
  } catch (...) {
    DeleteFileW(widen(destination).c_str());
    throw;
  }
}

void copy_file_exact(
    const std::string& source,
    const std::string& destination) {
  if (!CopyFileW(widen(source).c_str(), widen(destination).c_str(), TRUE)) {
    throw_last_error("CopyFileW(exact artifact staging)");
  }
}

unsigned long long file_size_bytes(const std::string& path) {
  WIN32_FILE_ATTRIBUTE_DATA data{};
  if (!GetFileAttributesExW(
          widen(path).c_str(), GetFileExInfoStandard, &data)) {
    throw_last_error("GetFileAttributesExW(" + path + ")");
  }
  ULARGE_INTEGER size{};
  size.HighPart = data.nFileSizeHigh;
  size.LowPart = data.nFileSizeLow;
  return size.QuadPart;
}

std::string sha256_file(const std::string& path) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::vector<unsigned char> object;
  std::vector<unsigned char> digest;
  auto fail = [&](const char* action, NTSTATUS status) {
    if (hash != nullptr) {
      BCryptDestroyHash(hash);
      hash = nullptr;
    }
    if (algorithm != nullptr) {
      BCryptCloseAlgorithmProvider(algorithm, 0);
      algorithm = nullptr;
    }
    std::ostringstream message;
    message << action << " failed with NTSTATUS 0x" << std::hex
            << static_cast<unsigned long>(status);
    throw std::runtime_error(message.str());
  };

  NTSTATUS status = BCryptOpenAlgorithmProvider(
      &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (status < 0) {
    fail("BCryptOpenAlgorithmProvider(SHA-256)", status);
  }
  DWORD objectLength = 0;
  DWORD digestLength = 0;
  DWORD bytes = 0;
  status = BCryptGetProperty(
      algorithm, BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &bytes, 0);
  if (status < 0) {
    fail("BCryptGetProperty(BCRYPT_OBJECT_LENGTH)", status);
  }
  status = BCryptGetProperty(
      algorithm, BCRYPT_HASH_LENGTH,
      reinterpret_cast<PUCHAR>(&digestLength), sizeof(digestLength), &bytes, 0);
  if (status < 0) {
    fail("BCryptGetProperty(BCRYPT_HASH_LENGTH)", status);
  }
  object.resize(objectLength);
  digest.resize(digestLength);
  status = BCryptCreateHash(
      algorithm, &hash, object.data(), objectLength, nullptr, 0, 0);
  if (status < 0) {
    fail("BCryptCreateHash(SHA-256)", status);
  }

  UniqueHandle file(CreateFileW(
      widen(path).c_str(), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  if (!file) {
    const DWORD error = GetLastError();
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    SetLastError(error);
    throw_last_error("CreateFileW(SHA-256 " + path + ")");
  }
  std::vector<unsigned char> buffer(kCompareChunkBytes);
  for (;;) {
    DWORD read = 0;
    if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                  &read, nullptr)) {
      const DWORD error = GetLastError();
      BCryptDestroyHash(hash);
      BCryptCloseAlgorithmProvider(algorithm, 0);
      SetLastError(error);
      throw_last_error("ReadFile(SHA-256 " + path + ")");
    }
    if (read == 0) {
      break;
    }
    status = BCryptHashData(hash, buffer.data(), read, 0);
    if (status < 0) {
      fail("BCryptHashData(SHA-256)", status);
    }
  }
  status = BCryptFinishHash(hash, digest.data(), digestLength, 0);
  if (status < 0) {
    fail("BCryptFinishHash(SHA-256)", status);
  }
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);

  std::ostringstream hex;
  hex << std::hex << std::setfill('0');
  for (unsigned char byte : digest) {
    hex << std::setw(2) << static_cast<unsigned>(byte);
  }
  return hex.str();
}

long long qpc_now() {
  LARGE_INTEGER value{};
  QueryPerformanceCounter(&value);
  return value.QuadPart;
}

long long qpc_frequency() {
  LARGE_INTEGER value{};
  QueryPerformanceFrequency(&value);
  return value.QuadPart;
}

double qpc_delta_ms(long long fromTicks, long long toTicks) {
  if (fromTicks <= 0 || toTicks <= 0 || toTicks < fromTicks) {
    return -1.0;
  }
  const long long freq = qpc_frequency();
  if (freq <= 0) {
    return -1.0;
  }
  return static_cast<double>(toTicks - fromTicks) * 1000.0 /
         static_cast<double>(freq);
}

bool remove_directory_if_exists(const std::string& path) {
  if (RemoveDirectoryW(widen(path).c_str())) {
    return true;
  }
  const DWORD error = GetLastError();
  if (error == ERROR_PATH_NOT_FOUND || error == ERROR_FILE_NOT_FOUND) {
    return false;
  }
  if (error == ERROR_DIR_NOT_EMPTY) {
    return false;
  }
  throw_last_error("RemoveDirectoryW(" + path + ")");
}

void write_text_file(const std::string& path, const std::string& content) {
  UniqueHandle file(CreateFileW(
      widen(path).c_str(),
      GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      nullptr));
  if (!file) {
    throw_last_error("CreateFileW(" + path + ")");
  }

  DWORD written = 0;
  if (!WriteFile(file.get(), content.data(), static_cast<DWORD>(content.size()), &written, nullptr) ||
      static_cast<std::size_t>(written) != content.size()) {
    throw_last_error("WriteFile(" + path + ")");
  }
}

TargetPrecheck precheck_target(
    const std::string& targetPath,
    const std::string& targetDirectory) {
  TargetPrecheck result;
  result.targetExists = path_exists(targetPath);
  result.directoryExists = directory_exists(targetDirectory);

  if (result.targetExists) {
    result.detail = "target already exists; remove it before collecting a clean result";
    return result;
  }

  if (!result.directoryExists) {
    result.detail = "target directory does not exist: " + targetDirectory;
    return result;
  }

  const std::string probePath = join_probe_path(targetDirectory);
  UniqueHandle probe(CreateFileW(
      widen(probePath).c_str(),
      GENERIC_WRITE,
      0,
      nullptr,
      CREATE_NEW,
      FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
      nullptr));

  if (probe) {
    result.directoryWritable = true;
    result.directoryWriteProbeConclusive = true;
    result.detail = "current user can create files in target directory";
    return result;
  }

  const DWORD error = GetLastError();
  if (error == ERROR_ACCESS_DENIED) {
    result.directoryWritable = false;
    result.directoryWriteProbeConclusive = true;
    result.detail = "current user cannot create files in target directory";
    return result;
  }

  result.directoryWritable = false;
  result.detail = "target directory write probe failed: " + last_error_message(error);
  return result;
}

FileObservation inspect_file_against_content(
    const std::string& path, const std::string& expectedContent) {
  FileObservation observation = inspect_file_metadata(path);
  observation.contentRead = observation.exists;
  observation.contentMatches =
      observation.exists && compare_file_to_content(path, expectedContent);
  return observation;
}

FileObservation inspect_file_against_file(
    const std::string& path, const std::string& expectedPath) {
  FileObservation observation = inspect_file_metadata(path);
  observation.contentRead = observation.exists && file_exists(expectedPath);
  observation.contentMatches =
      observation.contentRead && compare_file_to_file(path, expectedPath);
  return observation;
}

ExecutionMarker parse_execution_marker(const std::string& path) {
  ExecutionMarker marker;
  unsigned long long size = 0;
  if (!file_size_from_attributes(path, size) || size == 0 || size > 64 * 1024) {
    return marker;
  }
  UniqueHandle file = open_read_file(path);
  if (!file) {
    return marker;
  }
  std::string content(static_cast<std::size_t>(size), '\0');
  std::size_t offset = 0;
  while (offset < content.size()) {
    DWORD read = 0;
    const DWORD wanted = static_cast<DWORD>(content.size() - offset);
    if (!ReadFile(file.get(), content.data() + offset, wanted, &read, nullptr)) {
      return marker;
    }
    if (read == 0) {
      break;
    }
    offset += read;
  }
  content.resize(offset);

  std::size_t pos = 0;
  while (pos < content.size()) {
    std::size_t eol = content.find_first_of("\r\n", pos);
    if (eol == std::string::npos) {
      eol = content.size();
    }
    const std::string line = content.substr(pos, eol - pos);
    pos = content.find_first_not_of("\r\n", eol);
    if (pos == std::string::npos) {
      pos = content.size();
    }
    if (line == "CWR execution marker v1" ||
        line == "ComWriteRace passive DLL load evidence") {
      marker.markerHeaderPresent = true;
    }
    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string key = line.substr(0, eq);
    const std::string value = line.substr(eq + 1);
    if (key == "pid") marker.pid = value;
    else if (key == "process_image") marker.processImage = value;
    else if (key == "module_path" || key == "payload_path") {
      marker.modulePath = value;
    }
    else if (key == "account") marker.account = value;
    else if (key == "experiment_nonce") marker.experimentNonce = value;
    else if (key == "sid") marker.sid = value;
    else if (key == "integrity") marker.integrity = value;
    else if (key == "impersonating") marker.impersonating = (value == "true");
    else if (key == "thread_sid") marker.threadSid = value;
    else if (key == "thread_integrity") marker.threadIntegrity = value;
  }
  return marker;
}

std::string describe_file_observation(const FileObservation& observation) {
  if (!observation.exists) {
    return "target does not exist";
  }

  std::ostringstream out;
  out << "target file exists"
      << "; content_match=" << (observation.contentMatches ? "yes" : "no")
      << "; owner=" << (observation.owner.empty() ? "unavailable" : observation.owner)
      // The file's mandatory-label ACE, NOT the integrity level of whoever wrote
      // it. Absent on most files (they inherit Medium implicitly).
      << "; file_integrity_label="
      << (observation.integrityLabel.empty() ? "none(implicit-medium)" : observation.integrityLabel)
      << "; size=" << observation.size
      << "; created=" << (observation.creationTimeUtc.empty() ? "unavailable" : observation.creationTimeUtc)
      << "; modified=" << (observation.lastWriteTimeUtc.empty() ? "unavailable" : observation.lastWriteTimeUtc);
  return out.str();
}

}  // namespace comrace::win
