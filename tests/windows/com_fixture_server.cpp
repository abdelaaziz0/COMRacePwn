#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <new>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kClsid[] = L"{A67AA528-7B18-4B7A-92A4-18ED10263791}";
constexpr wchar_t kRegistryPath[] =
    L"Software\\Classes\\CLSID\\{A67AA528-7B18-4B7A-92A4-18ED10263791}";
constexpr wchar_t kMethodName[] = L"RaceWrite";
constexpr DISPID kRaceWriteDispid = 1;

HANDLE g_stopEvent = nullptr;
std::wstring g_labRoot;
constexpr DWORD kDefaultReopenDelayUs = 300000;

bool g_persistent = false;
constexpr DWORD kPersistentLifetimeMs = 600000;

bool g_service = false;
long long g_reopenDelayOverrideUs = -1;

std::wstring current_executable_path() {
  std::vector<wchar_t> buffer(512, L'\0');
  for (;;) {
    const DWORD length = GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) return {};
    if (length < buffer.size() - 1) {
      buffer.resize(length);
      return std::wstring(buffer.begin(), buffer.end());
    }
    buffer.resize(buffer.size() * 2);
  }
}

bool set_registry_string(HKEY key, const wchar_t* name, const std::wstring& value) {
  const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
  return RegSetValueExW(
      key, name, 0, REG_SZ,
      reinterpret_cast<const BYTE*>(value.c_str()), bytes) == ERROR_SUCCESS;
}

bool set_registry_dword(HKEY key, const wchar_t* name, DWORD value) {
  return RegSetValueExW(
      key, name, 0, REG_DWORD,
      reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
}

int register_server(const std::wstring& labRoot) {
  const std::wstring executable = current_executable_path();
  if (executable.empty()) return 2;

  HKEY clsidKey = nullptr;
  DWORD disposition = 0;
  if (RegCreateKeyExW(
          HKEY_CURRENT_USER, kRegistryPath, 0, nullptr, 0, KEY_WRITE,
          nullptr, &clsidKey, &disposition) != ERROR_SUCCESS) {
    return 3;
  }
  const bool rootStored = set_registry_string(clsidKey, L"LabRoot", labRoot);
  const bool delayStored = set_registry_dword(
      clsidKey, L"ReopenDelayUs", kDefaultReopenDelayUs);
  RegCloseKey(clsidKey);
  if (!rootStored || !delayStored) return 4;

  HKEY localServerKey = nullptr;
  const std::wstring localServerPath = std::wstring(kRegistryPath) + L"\\LocalServer32";
  if (RegCreateKeyExW(
          HKEY_CURRENT_USER, localServerPath.c_str(), 0, nullptr, 0, KEY_WRITE,
          nullptr, &localServerKey, &disposition) != ERROR_SUCCESS) {
    return 5;
  }
  const std::wstring command = L"\"" + executable + L"\" -Embedding";
  const bool commandStored = set_registry_string(localServerKey, nullptr, command);
  RegCloseKey(localServerKey);
  if (!commandStored) return 6;
  return 0;
}

int unregister_server() {
  const LSTATUS result = RegDeleteTreeW(HKEY_CURRENT_USER, kRegistryPath);
  return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND ? 0 : 7;
}

std::wstring full_path(const std::wstring& path) {
  std::vector<wchar_t> buffer(512, L'\0');
  for (;;) {
    const DWORD length = GetFullPathNameW(
        path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (length == 0) return {};
    if (length < buffer.size()) return std::wstring(buffer.data(), length);
    buffer.resize(static_cast<std::size_t>(length) + 1);
  }
}

std::wstring trim_trailing_separators(std::wstring value) {
  while (value.size() > 3 && (value.back() == L'\\' || value.back() == L'/')) {
    value.pop_back();
  }
  return value;
}

bool is_beneath_lab_root(const std::wstring& input) {
  const std::wstring root = trim_trailing_separators(full_path(g_labRoot));
  const std::wstring path = full_path(input);
  if (root.empty() || path.size() <= root.size()) return false;
  if (_wcsnicmp(path.c_str(), root.c_str(), root.size()) != 0) return false;
  return path[root.size()] == L'\\' || path[root.size()] == L'/';
}

std::wstring join_path(const std::wstring& left, const wchar_t* right) {
  if (!left.empty() && (left.back() == L'\\' || left.back() == L'/')) {
    return left + right;
  }
  return left + L"\\" + right;
}

void append_log(const char* line) {
  const std::wstring path = join_path(g_labRoot, L"server.log");
  HANDLE file = CreateFileW(
      path.c_str(), FILE_APPEND_DATA,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
  WriteFile(file, "\r\n", 2, &written, nullptr);
  CloseHandle(file);
}

void append_hresult(const char* stage, HRESULT value) {
  char line[96]{};
  std::snprintf(line, sizeof(line), "%s_0x%08lX", stage,
                static_cast<unsigned long>(value));
  append_log(line);
}

bool read_lab_root() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegistryPath, 0, KEY_READ, &key) !=
      ERROR_SUCCESS) {
    return false;
  }
  DWORD type = 0;
  DWORD bytes = 0;
  LSTATUS status = RegQueryValueExW(key, L"LabRoot", nullptr, &type, nullptr, &bytes);
  if (status != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t)) {
    RegCloseKey(key);
    return false;
  }
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
  status = RegQueryValueExW(
      key, L"LabRoot", nullptr, &type,
      reinterpret_cast<BYTE*>(buffer.data()), &bytes);
  RegCloseKey(key);
  if (status != ERROR_SUCCESS || buffer.front() == L'\0') return false;
  g_labRoot.assign(buffer.data());
  return true;
}

DWORD read_reopen_delay_us() {
  if (g_reopenDelayOverrideUs >= 0) {
    return static_cast<DWORD>(g_reopenDelayOverrideUs);
  }
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegistryPath, 0, KEY_READ, &key) !=
      ERROR_SUCCESS) {
    return kDefaultReopenDelayUs;
  }
  DWORD type = 0;
  DWORD value = kDefaultReopenDelayUs;
  DWORD bytes = sizeof(value);
  const LSTATUS status = RegQueryValueExW(
      key, L"ReopenDelayUs", nullptr, &type,
      reinterpret_cast<BYTE*>(&value), &bytes);
  RegCloseKey(key);
  if (status != ERROR_SUCCESS || type != REG_DWORD || bytes != sizeof(value) ||
      value > 10000000) {
    return kDefaultReopenDelayUs;
  }
  return value;
}

void wait_reopen_delay_us(DWORD delayUs) {
  if (delayUs == 0) return;
  LARGE_INTEGER frequency{};
  LARGE_INTEGER start{};
  LARGE_INTEGER current{};
  if (!QueryPerformanceFrequency(&frequency) ||
      !QueryPerformanceCounter(&start)) {
    return;
  }
  const LONGLONG targetTicks =
      (frequency.QuadPart * static_cast<LONGLONG>(delayUs)) / 1000000;
  do {
    YieldProcessor();
    if (!QueryPerformanceCounter(&current)) return;
  } while (current.QuadPart - start.QuadPart < targetTicks);
}

HRESULT describe_failure(EXCEPINFO* info, HRESULT code, const wchar_t* message) {
  if (info != nullptr) {
    info->scode = code;
    info->bstrSource = SysAllocString(L"CWR controlled COM fixture");
    info->bstrDescription = SysAllocString(message);
  }
  return DISP_E_EXCEPTION;
}

HRESULT perform_race_write(
    const std::wstring& baitPath,
    const std::wstring& payloadPath,
    EXCEPINFO* exceptionInfo);

HRESULT invoke_race_write(
    const VARIANTARG* arguments,
    UINT count,
    EXCEPINFO* exceptionInfo) {
  if (count != 2 || arguments == nullptr) {
    return describe_failure(exceptionInfo, DISP_E_BADPARAMCOUNT, L"expected bait and payload paths");
  }

  VARIANT baitVariant;
  VARIANT payloadVariant;
  VariantInit(&baitVariant);
  VariantInit(&payloadVariant);
  HRESULT hr = VariantChangeType(&baitVariant, &arguments[1], 0, VT_BSTR);
  if (SUCCEEDED(hr)) {
    hr = VariantChangeType(&payloadVariant, &arguments[0], 0, VT_BSTR);
  }
  if (FAILED(hr) || baitVariant.bstrVal == nullptr || payloadVariant.bstrVal == nullptr) {
    VariantClear(&baitVariant);
    VariantClear(&payloadVariant);
    return describe_failure(exceptionInfo, DISP_E_TYPEMISMATCH, L"expected string path arguments");
  }

  const std::wstring baitPath(baitVariant.bstrVal, SysStringLen(baitVariant.bstrVal));
  const std::wstring payloadPath(
      payloadVariant.bstrVal, SysStringLen(payloadVariant.bstrVal));
  VariantClear(&baitVariant);
  VariantClear(&payloadVariant);

  if (!is_beneath_lab_root(baitPath) || !is_beneath_lab_root(payloadPath)) {
    append_log("rejected_path_outside_lab_root");
    return describe_failure(exceptionInfo, E_ACCESSDENIED, L"paths must stay beneath the registered lab root");
  }

  return perform_race_write(baitPath, payloadPath, exceptionInfo);
}

HRESULT perform_race_write(
    const std::wstring& baitPath,
    const std::wstring& payloadPath,
    EXCEPINFO* exceptionInfo) {
  append_log("race_method_called");
  {
    WCHAR user[64]{};
    DWORD userLength = 64;
    if (GetUserNameW(user, &userLength)) {
      char userUtf8[64]{};
      WideCharToMultiByte(
          CP_UTF8, 0, user, -1, userUtf8, sizeof(userUtf8), nullptr, nullptr);
      const DWORD attrs = GetFileAttributesW(baitPath.c_str());
      char probe[640]{};
      int written = std::snprintf(
          probe, sizeof(probe), "victim_probe user=%s bait_attrs=%lu path=",
          userUtf8, static_cast<unsigned long>(attrs));
      if (written > 0) {
        const int pathBytes = WideCharToMultiByte(
            CP_UTF8, 0, baitPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (pathBytes > 0 && written + pathBytes < static_cast<int>(sizeof(probe))) {
          WideCharToMultiByte(
              CP_UTF8, 0, baitPath.c_str(), -1, probe + written, pathBytes,
              nullptr, nullptr);
        }
      }
      append_log(probe);
    }
  }

  const DWORD reopenDelayUs = read_reopen_delay_us();
  HANDLE firstOpen = CreateFileW(
      baitPath.c_str(), GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (firstOpen == INVALID_HANDLE_VALUE) {
    const DWORD openError = GetLastError();
    char line[64]{};
    std::snprintf(
        line, sizeof(line), "first_open_failed=%lu",
        static_cast<unsigned long>(openError));
    append_log(line);
    return describe_failure(exceptionInfo, HRESULT_FROM_WIN32(openError), L"first bait open failed");
  }
  CloseHandle(firstOpen);
  append_log("first_open_completed");

  wait_reopen_delay_us(reopenDelayUs);
  if (!CopyFileW(payloadPath.c_str(), baitPath.c_str(), FALSE)) {
    const DWORD error = GetLastError();
    char delayLine[64]{};
    std::snprintf(delayLine, sizeof(delayLine), "reopen_delay_us=%lu",
                  static_cast<unsigned long>(reopenDelayUs));
    append_log(delayLine);
    append_log("payload_copy_failed");
    return describe_failure(exceptionInfo, HRESULT_FROM_WIN32(error), L"second name-based payload copy failed");
  }
  char delayLine[64]{};
  std::snprintf(delayLine, sizeof(delayLine), "reopen_delay_us=%lu",
                static_cast<unsigned long>(reopenDelayUs));
  append_log(delayLine);
  append_log("payload_copy_succeeded");
  HANDLE copiedFile = CreateFileW(
      baitPath.c_str(), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (copiedFile != INVALID_HANDLE_VALUE) {
    std::vector<wchar_t> resolved(1024, L'\0');
    const DWORD resolvedLength = GetFinalPathNameByHandleW(
        copiedFile, resolved.data(), static_cast<DWORD>(resolved.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (resolvedLength > 0 && resolvedLength < resolved.size()) {
      const int bytes = WideCharToMultiByte(
          CP_UTF8, 0, resolved.data(), static_cast<int>(resolvedLength),
          nullptr, 0, nullptr, nullptr);
      if (bytes > 0) {
        std::string line(static_cast<std::size_t>(bytes), '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, resolved.data(), static_cast<int>(resolvedLength),
            line.data(), bytes, nullptr, nullptr);
        append_log(("copy_resolved_path=" + line).c_str());
      }
    }
    CloseHandle(copiedFile);
  } else {
    append_log("copy_verification_open_failed");
  }
  return S_OK;
}

class FixtureDispatch final : public IDispatch {
 public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
    if (object == nullptr) return E_POINTER;
    *object = nullptr;
    if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_IDispatch)) {
      *object = static_cast<IDispatch*>(this);
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override {
    return ++references_;
  }

  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG count = --references_;
    if (count == 0) {
      delete this;
      if (!(g_persistent || g_service) && CoReleaseServerProcess() == 0 &&
          g_stopEvent != nullptr) {
        SetEvent(g_stopEvent);
      }
    }
    return count;
  }

  HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override {
    if (count == nullptr) return E_POINTER;
    *count = 0;
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo** info) override {
    if (info != nullptr) *info = nullptr;
    return E_NOTIMPL;
  }

  HRESULT STDMETHODCALLTYPE GetIDsOfNames(
      REFIID iid, LPOLESTR* names, UINT count, LCID, DISPID* ids) override {
    if (!IsEqualIID(iid, IID_NULL)) return DISP_E_UNKNOWNINTERFACE;
    if (names == nullptr || ids == nullptr || count == 0) return E_POINTER;
    for (UINT index = 0; index < count; ++index) {
      if (names[index] == nullptr || _wcsicmp(names[index], kMethodName) != 0) {
        return DISP_E_UNKNOWNNAME;
      }
      ids[index] = kRaceWriteDispid;
    }
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE Invoke(
      DISPID id, REFIID iid, LCID, WORD flags, DISPPARAMS* parameters,
      VARIANT* result, EXCEPINFO* exceptionInfo, UINT*) override {
    if (!IsEqualIID(iid, IID_NULL)) return DISP_E_UNKNOWNINTERFACE;
    if (id != kRaceWriteDispid) return DISP_E_MEMBERNOTFOUND;
    if ((flags & DISPATCH_METHOD) == 0) return DISP_E_MEMBERNOTFOUND;
    if (parameters == nullptr) return E_POINTER;
    if (result != nullptr) VariantInit(result);
    return invoke_race_write(
        parameters->rgvarg, parameters->cArgs, exceptionInfo);
  }

 private:
  ~FixtureDispatch() = default;
  std::atomic<ULONG> references_{1};
};

class FixtureClassFactory final : public IClassFactory {
 public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
    if (object == nullptr) return E_POINTER;
    *object = nullptr;
    if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_IClassFactory)) {
      *object = static_cast<IClassFactory*>(this);
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }

  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG count = --references_;
    if (count == 0) delete this;
    return count;
  }

  HRESULT STDMETHODCALLTYPE CreateInstance(
      IUnknown* outer, REFIID iid, void** object) override {
    if (outer != nullptr) return CLASS_E_NOAGGREGATION;
    if (object == nullptr) return E_POINTER;
    *object = nullptr;
    CoAddRefServerProcess();
    auto* instance = new (std::nothrow) FixtureDispatch();
    if (instance == nullptr) {
      if (!(g_persistent || g_service) && CoReleaseServerProcess() == 0 && g_stopEvent != nullptr) {
        SetEvent(g_stopEvent);
      }
      return E_OUTOFMEMORY;
    }
    const HRESULT result = instance->QueryInterface(iid, object);
    instance->Release();
    return result;
  }

  HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
    if (lock) {
      CoAddRefServerProcess();
      return S_OK;
    }
    if (!(g_persistent || g_service) && CoReleaseServerProcess() == 0 && g_stopEvent != nullptr) {
      SetEvent(g_stopEvent);
    }
    return S_OK;
  }

 private:
  std::atomic<ULONG> references_{1};
};

int run_victim_loop() {
  if (g_labRoot.empty()) return 21;
  const std::wstring stopMarker = join_path(g_labRoot, L"stop-victim");
  const std::wstring requestDirectory = join_path(g_labRoot, L"requests");
  const std::wstring requestDoneDirectory =
      join_path(g_labRoot, L"requests-done");
  CreateDirectoryW(requestDirectory.c_str(), nullptr);
  CreateDirectoryW(requestDoneDirectory.c_str(), nullptr);
  append_log("victim_loop_started");
  for (;;) {
    if (GetFileAttributesW(stopMarker.c_str()) != INVALID_FILE_ATTRIBUTES) {
      append_log("victim_loop_stopped");
      return 0;
    }
    WIN32_FIND_DATAW find{};
    HANDLE finder = FindFirstFileW(
        join_path(requestDirectory, L"*.txt").c_str(), &find);
    if (finder != INVALID_HANDLE_VALUE) {
      do {
        const std::wstring requestPath =
            join_path(requestDirectory, find.cFileName);
        HANDLE file = CreateFileW(
            requestPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) continue;
        char buffer[2048]{};
        DWORD got = 0;
        const BOOL readOk = ReadFile(
            file, buffer, sizeof(buffer) - 1, &got, nullptr);
        CloseHandle(file);
        if (!readOk) continue;

        const std::wstring donePath =
            join_path(requestDoneDirectory, find.cFileName);
        if (!MoveFileW(requestPath.c_str(), donePath.c_str())) {
          const DWORD moveError = GetLastError();
          char line[96]{};
          std::snprintf(
              line, sizeof(line), "request_move_failed=%lu",
              static_cast<unsigned long>(moveError));
          append_log(line);
          continue;
        }
        const std::string content(buffer, buffer + got);
        std::wstring lines[3];
        std::size_t pos = 0;
        int index = 0;
        while (pos < content.size() && index < 3) {
          std::size_t eol = content.find('\n', pos);
          std::string line = content.substr(
              pos, eol == std::string::npos ? std::string::npos : eol - pos);
          pos = (eol == std::string::npos) ? content.size() : eol + 1;
          while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
          }
          if (line.empty()) continue;
          const int needed = MultiByteToWideChar(
              CP_UTF8, 0, line.c_str(), -1, nullptr, 0);
          if (needed <= 0) continue;
          std::wstring wide(static_cast<std::size_t>(needed), L'\0');
          MultiByteToWideChar(
              CP_UTF8, 0, line.c_str(), -1, &wide[0], needed);
          wide.resize(static_cast<std::size_t>(needed) - 1);
          lines[index++] = wide;
        }
        if (lines[0].empty() || lines[1].empty()) continue;
        if (index >= 3 && !lines[2].empty()) {
          g_reopenDelayOverrideUs = _wtoi64(lines[2].c_str());
        }
        if (!is_beneath_lab_root(lines[0]) ||
            !is_beneath_lab_root(lines[1])) {
          append_log("victim_loop_rejected_path_outside_lab_root");
          continue;
        }
        perform_race_write(lines[0], lines[1], nullptr);
      } while (FindNextFileW(finder, &find));
      FindClose(finder);
    }
    Sleep(250);
  }
}

int run_local_server() {

  if (g_labRoot.empty() && !read_lab_root()) return 10;
  const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(initialized)) return 11;

  g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (g_stopEvent == nullptr) {
    CoUninitialize();
    return 12;
  }

  CLSID classId{};
  HRESULT hr = CLSIDFromString(kClsid, &classId);
  if (FAILED(hr)) append_hresult("CLSIDFromString_failed", hr);
  auto* factory = new (std::nothrow) FixtureClassFactory();
  DWORD registration = 0;
  if (FAILED(hr) || factory == nullptr) {
    if (factory != nullptr) factory->Release();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    CoUninitialize();
    return 13;
  }
  hr = CoRegisterClassObject(
      classId, factory, CLSCTX_LOCAL_SERVER,
      REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED, &registration);
  if (FAILED(hr)) {
    append_hresult("CoRegisterClassObject_failed", hr);
    if (registration != 0) CoRevokeClassObject(registration);
    factory->Release();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    CoUninitialize();
    return 14;
  }
  hr = CoResumeClassObjects();
  if (FAILED(hr)) {
    append_hresult("CoResumeClassObjects_failed", hr);
    CoRevokeClassObject(registration);
    factory->Release();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    CoUninitialize();
    return 15;
  }
  append_log("server_ready");

  WaitForSingleObject(
      g_stopEvent,
      g_service ? INFINITE : (g_persistent ? kPersistentLifetimeMs : 120000));
  CoSuspendClassObjects();
  CoRevokeClassObject(registration);
  factory->Release();
  CloseHandle(g_stopEvent);
  g_stopEvent = nullptr;
  CoUninitialize();
  return 0;
}

}

namespace {

SERVICE_STATUS g_serviceStatus{};
SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;

void WINAPI service_control_handler(DWORD control) {
  if (g_serviceStatusHandle == nullptr) return;
  if (control == SERVICE_CONTROL_STOP) {
    if (g_stopEvent != nullptr) SetEvent(g_stopEvent);
    g_serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
  }
}

VOID WINAPI service_main(DWORD, wchar_t**) {
  g_serviceStatusHandle = RegisterServiceCtrlHandlerW(
      L"CwrPrivFixture", service_control_handler);
  if (g_serviceStatusHandle == nullptr) return;
  g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
  g_serviceStatus.dwWaitHint = 15000;
  SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);

  g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
  g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);

  run_local_server();

  g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

int run_service_entry() {
  SERVICE_TABLE_ENTRYW table[] = {
      {const_cast<LPWSTR>(L"CwrPrivFixture"), service_main},
      {nullptr, nullptr}};
  if (!StartServiceCtrlDispatcherW(table)) {
    return 20;
  }
  return 0;
}

}

int wmain(int argc, wchar_t** argv) {
  if (argc >= 2 && _wcsicmp(argv[1], L"/loop") == 0) {

    if (argc >= 3 && argv[2] != nullptr && argv[2][0] != L'\0') {
      g_labRoot = argv[2];
    }
    if (argc >= 4 && argv[3] != nullptr && argv[3][0] != L'\0') {
      g_reopenDelayOverrideUs = _wtoi64(argv[3]);
    }
    return run_victim_loop();
  }
  if (argc >= 2 && _wcsicmp(argv[1], L"/service") == 0) {

    g_service = true;
    if (argc >= 3 && argv[2] != nullptr && argv[2][0] != L'\0') {
      g_labRoot = argv[2];
    }
    if (argc >= 4 && argv[3] != nullptr && argv[3][0] != L'\0') {
      g_reopenDelayOverrideUs = _wtoi64(argv[3]);
    }
    return run_service_entry();
  }
  if (argc >= 2 && _wcsicmp(argv[1], L"/persistent") == 0) {

    g_persistent = true;
    if (argc >= 3 && argv[2] != nullptr && argv[2][0] != L'\0') {
      g_labRoot = argv[2];
    }
    if (argc >= 4 && argv[3] != nullptr && argv[3][0] != L'\0') {
      g_reopenDelayOverrideUs = _wtoi64(argv[3]);
    }
    return run_local_server();
  }
  if (argc == 3 && _wcsicmp(argv[1], L"/register") == 0) {
    return register_server(argv[2]);
  }
  if (argc == 2 && _wcsicmp(argv[1], L"/unregister") == 0) {
    return unregister_server();
  }
  return run_local_server();
}
