#include "comrace/inventory.hpp"

#include "platform/windows/win_utils.hpp"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace comrace {
namespace {

class RegistryKey {
 public:
  RegistryKey() = default;
  explicit RegistryKey(HKEY key) : key_(key) {}
  ~RegistryKey() {
    if (key_ != nullptr) {
      RegCloseKey(key_);
    }
  }

  RegistryKey(const RegistryKey&) = delete;
  RegistryKey& operator=(const RegistryKey&) = delete;

  RegistryKey(RegistryKey&& other) noexcept : key_(other.key_) {
    other.key_ = nullptr;
  }

  RegistryKey& operator=(RegistryKey&& other) noexcept {
    if (this != &other) {
      if (key_ != nullptr) {
        RegCloseKey(key_);
      }
      key_ = other.key_;
      other.key_ = nullptr;
    }
    return *this;
  }

  HKEY get() const { return key_; }
  explicit operator bool() const { return key_ != nullptr; }

 private:
  HKEY key_ = nullptr;
};

class ServiceHandle {
 public:
  ServiceHandle() = default;
  explicit ServiceHandle(SC_HANDLE handle) : handle_(handle) {}
  ~ServiceHandle() {
    if (handle_ != nullptr) {
      CloseServiceHandle(handle_);
    }
  }

  ServiceHandle(const ServiceHandle&) = delete;
  ServiceHandle& operator=(const ServiceHandle&) = delete;

  ServiceHandle(ServiceHandle&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }

  SC_HANDLE get() const { return handle_; }
  explicit operator bool() const { return handle_ != nullptr; }

 private:
  SC_HANDLE handle_ = nullptr;
};

RegistryKey open_key(
    HKEY root,
    const std::wstring& path,
    REGSAM view) {
  HKEY key = nullptr;
  const LSTATUS status =
      RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &key);
  return status == ERROR_SUCCESS ? RegistryKey(key) : RegistryKey();
}

RegistryKey open_subkey(
    HKEY parent,
    const std::wstring& name,
    REGSAM view) {
  HKEY key = nullptr;
  const LSTATUS status =
      RegOpenKeyExW(parent, name.c_str(), 0, KEY_READ | view, &key);
  return status == ERROR_SUCCESS ? RegistryKey(key) : RegistryKey();
}

std::optional<std::wstring> read_string_value(
    HKEY key,
    const wchar_t* valueName) {
  DWORD type = 0;
  DWORD bytes = 0;
  LSTATUS status =
      RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes);
  if (status != ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ)) {
    return std::nullopt;
  }

  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
  status = RegQueryValueExW(
      key,
      valueName,
      nullptr,
      &type,
      reinterpret_cast<BYTE*>(buffer.data()),
      &bytes);
  if (status != ERROR_SUCCESS) {
    return std::nullopt;
  }
  buffer.back() = L'\0';
  return std::wstring(buffer.data());
}

std::optional<std::wstring> read_subkey_default(
    HKEY parent,
    const wchar_t* subkey,
    REGSAM view) {
  RegistryKey key = open_subkey(parent, subkey, view);
  if (!key) {
    return std::nullopt;
  }
  return read_string_value(key.get(), nullptr);
}

struct ServiceConfiguration {
  std::string account;
  std::string imagePath;
};

ServiceConfiguration query_service(const std::wstring& serviceName) {
  ServiceConfiguration result;
  ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return result;
  }
  ServiceHandle service(OpenServiceW(
      manager.get(),
      serviceName.c_str(),
      SERVICE_QUERY_CONFIG));
  if (!service) {
    return result;
  }

  DWORD required = 0;
  QueryServiceConfigW(service.get(), nullptr, 0, &required);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
    return result;
  }

  std::vector<BYTE> buffer(required);
  auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
  if (!QueryServiceConfigW(service.get(), config, required, &required)) {
    return result;
  }
  if (config->lpServiceStartName != nullptr) {
    result.account = win::narrow(config->lpServiceStartName);
  }
  if (config->lpBinaryPathName != nullptr) {
    result.imagePath = win::narrow(config->lpBinaryPathName);
  }
  return result;
}

void enumerate_registry_view(
    HKEY hive,
    const char* hiveName,
    REGSAM view,
    const char* viewName,
    bool includeInproc,
    std::vector<ComInventoryEntry>& entries) {
  RegistryKey clsidRoot =
      open_key(hive, L"Software\\Classes\\CLSID", view);
  if (!clsidRoot) {
    return;
  }

  for (DWORD index = 0;; ++index) {
    std::vector<wchar_t> nameBuffer(256, L'\0');
    DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
    FILETIME lastWrite{};
    const LSTATUS status = RegEnumKeyExW(
        clsidRoot.get(),
        index,
        nameBuffer.data(),
        &nameLength,
        nullptr,
        nullptr,
        nullptr,
        &lastWrite);
    if (status == ERROR_NO_MORE_ITEMS) {
      break;
    }
    if (status != ERROR_SUCCESS) {
      continue;
    }

    const std::wstring clsid(nameBuffer.data(), nameLength);
    RegistryKey classKey = open_subkey(clsidRoot.get(), clsid, view);
    if (!classKey) {
      continue;
    }

    const auto displayName = read_string_value(classKey.get(), nullptr);
    const auto inproc =
        read_subkey_default(classKey.get(), L"InprocServer32", view);
    const auto localServer =
        read_subkey_default(classKey.get(), L"LocalServer32", view);
    const auto appId = read_string_value(classKey.get(), L"AppID");

    std::optional<std::wstring> localService;
    std::optional<std::wstring> dllSurrogate;
    std::optional<std::wstring> runAs;
    if (appId && !appId->empty()) {
      RegistryKey appKey = open_key(
          hive,
          L"Software\\Classes\\AppID\\" + *appId,
          view);
      if (appKey) {
        localService =
            read_string_value(appKey.get(), L"LocalService");
        dllSurrogate =
            read_string_value(appKey.get(), L"DllSurrogate");
        runAs = read_string_value(appKey.get(), L"RunAs");
      }
    }

    ComInventoryEntry entry;
    entry.clsid = win::narrow(clsid);
    entry.name = displayName ? win::narrow(*displayName) : "";
    entry.appId = appId ? win::narrow(*appId) : "";
    entry.localService =
        localService ? win::narrow(*localService) : "";
    entry.runAs = runAs ? win::narrow(*runAs) : "";
    entry.registryHive = hiveName;
    entry.registryView = viewName;

    if (localService && !localService->empty()) {
      entry.serverType = "local_service";
      const ServiceConfiguration service = query_service(*localService);
      entry.serviceAccount = service.account;
      entry.serviceImagePath = service.imagePath;
      entry.serverPath = service.imagePath;
    } else if (localServer && !localServer->empty()) {
      entry.serverType = "local_server";
      entry.serverPath = win::narrow(*localServer);
    } else if (dllSurrogate.has_value()) {
      entry.serverType = "dll_surrogate";
      entry.serverPath = inproc ? win::narrow(*inproc) : "";
    } else if (inproc && !inproc->empty()) {
      entry.serverType = "inproc";
      entry.serverPath = win::narrow(*inproc);
    } else {
      continue;
    }

    if (!includeInproc && entry.serverType == "inproc") {
      continue;
    }
    entries.push_back(std::move(entry));
  }
}

}  // namespace

std::vector<ComInventoryEntry> collect_com_inventory(bool includeInproc) {
  std::vector<ComInventoryEntry> entries;
  enumerate_registry_view(
      HKEY_LOCAL_MACHINE,
      "HKLM",
      KEY_WOW64_64KEY,
      "64",
      includeInproc,
      entries);
  enumerate_registry_view(
      HKEY_CURRENT_USER,
      "HKCU",
      KEY_WOW64_64KEY,
      "64",
      includeInproc,
      entries);
  enumerate_registry_view(
      HKEY_LOCAL_MACHINE,
      "HKLM",
      KEY_WOW64_32KEY,
      "32",
      includeInproc,
      entries);
  enumerate_registry_view(
      HKEY_CURRENT_USER,
      "HKCU",
      KEY_WOW64_32KEY,
      "32",
      includeInproc,
      entries);

  std::sort(
      entries.begin(),
      entries.end(),
      [](const ComInventoryEntry& left, const ComInventoryEntry& right) {
        return std::tie(
                   left.clsid,
                   left.registryHive,
                   left.registryView,
                   left.serverType) <
            std::tie(
                   right.clsid,
                   right.registryHive,
                   right.registryView,
                   right.serverType);
      });
  return entries;
}

}  // namespace comrace
