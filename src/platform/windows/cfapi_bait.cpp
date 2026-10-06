#include "platform/windows/cfapi_bait.hpp"

#include <stdexcept>
#include <string>

typedef LONG NTSTATUS;

#include <cfapi.h>

namespace comrace::win {
namespace {

template <typename Fn>
Fn load_cldapi_function(const char* name) {
  static HMODULE cldapi = LoadLibraryW(L"cldapi.dll");
  if (cldapi == nullptr) {
    throw std::runtime_error("cldapi.dll is unavailable (Cloud Files mini-filter)");
  }
  const FARPROC proc = GetProcAddress(cldapi, name);
  if (proc == nullptr) {
    throw std::runtime_error(
        std::string("cldapi.dll is missing export: ") + name);
  }
  return reinterpret_cast<Fn>(proc);
}

using CfRegisterSyncRootFn = HRESULT(WINAPI*)(
    LPCWSTR,
    const CF_SYNC_REGISTRATION*,
    const CF_SYNC_POLICIES*,
    CF_REGISTER_FLAGS);
using CfUnregisterSyncRootFn = HRESULT(WINAPI*)(LPCWSTR);
using CfCreatePlaceholdersFn = HRESULT(WINAPI*)(
    LPCWSTR,
    CF_PLACEHOLDER_CREATE_INFO*,
    DWORD,
    CF_CREATE_FLAGS,
    PDWORD);

void unregister_quietly(const std::wstring& directoryWide) {
  try {
    (void)load_cldapi_function<CfUnregisterSyncRootFn>("CfUnregisterSyncRoot")(
        directoryWide.c_str());
  } catch (...) {
  }
}

}

void prepare_cloud_placeholder_bait(
    const std::string& safeDirectory,
    const std::string& baitFileName,
    const std::string& providerToken) {
  const std::wstring providerName =
      widen(providerToken.empty() ? "cwrcloud" : providerToken);
  const std::wstring directoryWide = widen(safeDirectory);
  const std::wstring baitNameWide = widen(baitFileName);

  CF_SYNC_REGISTRATION registration{};
  registration.StructSize = sizeof(registration);
  registration.ProviderName = providerName.c_str();
  registration.ProviderVersion = L"1.0";

  CF_SYNC_POLICIES policies{};
  policies.StructSize = sizeof(policies);

  const HRESULT registered = load_cldapi_function<CfRegisterSyncRootFn>(
      "CfRegisterSyncRoot")(
      directoryWide.c_str(), &registration, &policies,
      static_cast<CF_REGISTER_FLAGS>(0));
  if (FAILED(registered)) {
    throw std::runtime_error(
        "CfRegisterSyncRoot(" + safeDirectory + ") failed: " +
        hresult_message(registered));
  }

  CF_PLACEHOLDER_CREATE_INFO placeholder{};
  placeholder.RelativeFileName = baitNameWide.c_str();
  placeholder.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
  placeholder.FsMetadata.FileSize.QuadPart = 0;
  placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

  DWORD entriesProcessed = 0;
  const HRESULT created =
      load_cldapi_function<CfCreatePlaceholdersFn>("CfCreatePlaceholders")(
          directoryWide.c_str(), &placeholder, 1,
          static_cast<CF_CREATE_FLAGS>(0), &entriesProcessed);
  if (FAILED(created) || entriesProcessed != 1) {
    unregister_quietly(directoryWide);
    throw std::runtime_error(
        "CfCreatePlaceholders(" + baitFileName + ") failed: " +
        hresult_message(created));
  }
}

void teardown_cloud_bait(const std::string& safeDirectory) {
  const auto unregister =
      load_cldapi_function<CfUnregisterSyncRootFn>("CfUnregisterSyncRoot");
  const HRESULT status = unregister(widen(safeDirectory).c_str());
  if (FAILED(status)) {
    throw std::runtime_error(
        "CfUnregisterSyncRoot(" + safeDirectory + ") failed: " +
        hresult_message(status));
  }
}

}
