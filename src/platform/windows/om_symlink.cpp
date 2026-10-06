#include "platform/windows/om_symlink.hpp"

#include <sstream>
#include <stdexcept>

namespace comrace::win {
namespace {

struct UnicodeString {
  USHORT length;
  USHORT maximumLength;
  wchar_t* buffer;
};

struct ObjectAttributes {
  ULONG length;
  HANDLE rootDirectory;
  UnicodeString* objectName;
  ULONG attributes;
  void* securityDescriptor;
  void* securityQualityOfService;
};

constexpr ULONG objCaseInsensitive = 0x00000040;
constexpr LONG statusSuccess = 0;
constexpr ACCESS_MASK symbolicLinkQuery = 0x0001;
constexpr ACCESS_MASK symbolicLinkAllAccess =
    (ACCESS_MASK)(STANDARD_RIGHTS_REQUIRED | symbolicLinkQuery);

using NtCreateSymbolicLinkObjectFn = LONG(NTAPI*)(
    HANDLE*,
    ACCESS_MASK,
    ObjectAttributes*,
    UnicodeString*);

NtCreateSymbolicLinkObjectFn nt_create_symbolic_link_object() {
  static const NtCreateSymbolicLinkObjectFn fn =
      reinterpret_cast<NtCreateSymbolicLinkObjectFn>(
          reinterpret_cast<void*>(GetProcAddress(
              GetModuleHandleW(L"ntdll.dll"),
              "NtCreateSymbolicLinkObject")));
  if (fn == nullptr) {
    throw std::runtime_error("NtCreateSymbolicLinkObject is unavailable in ntdll");
  }
  return fn;
}

std::string status_hex(LONG status) {
  std::ostringstream out;
  out << "0x" << std::hex << status;
  return out.str();
}

}

OmSymlink create_om_symlink(
    const std::string& objectName,
    const std::string& ntTargetPath) {
  if (objectName.empty() || objectName.find('\\') != std::string::npos ||
      objectName.find('/') != std::string::npos) {
    throw std::runtime_error(
        "object symlink name must be a single path component: " + objectName);
  }
  if (ntTargetPath.empty() || ntTargetPath.front() != '\\') {
    throw std::runtime_error(
        "object symlink target must be a full NT path: " + ntTargetPath);
  }

  const std::string linkPath = "\\RPC Control\\" + objectName;
  std::wstring name = widen(linkPath);
  std::wstring target = widen(ntTargetPath);

  UnicodeString nameString{};
  nameString.length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
  nameString.maximumLength = nameString.length + sizeof(wchar_t);
  nameString.buffer = name.data();

  UnicodeString targetString{};
  targetString.length = static_cast<USHORT>(target.size() * sizeof(wchar_t));
  targetString.maximumLength = targetString.length + sizeof(wchar_t);
  targetString.buffer = target.data();

  ObjectAttributes attributes{};
  attributes.length = sizeof(attributes);
  attributes.rootDirectory = nullptr;
  attributes.objectName = &nameString;
  attributes.attributes = objCaseInsensitive;
  attributes.securityDescriptor = nullptr;
  attributes.securityQualityOfService = nullptr;

  HANDLE handle = nullptr;
  const LONG status =
      nt_create_symbolic_link_object()(&handle, symbolicLinkAllAccess, &attributes, &targetString);
  if (status != statusSuccess || handle == nullptr) {
    throw std::runtime_error(
        "NtCreateSymbolicLinkObject(" + linkPath + " -> " + ntTargetPath +
        ") failed with status " + status_hex(status));
  }

  OmSymlink result;
  result.handle.reset(handle);
  result.objectName = objectName;
  return result;
}

}
