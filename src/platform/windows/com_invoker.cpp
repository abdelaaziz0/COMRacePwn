#include "platform/windows/com_invoker.hpp"

#include "comrace/json_output.hpp"
#include "comrace/native_adapter_api.hpp"
#include "platform/windows/win_utils.hpp"

#include <oleauto.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace comrace::win {
namespace {

class ComApartment {
 public:
  ComApartment() {
    hr_ = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr_) && hr_ != RPC_E_CHANGED_MODE) {
      throw_if_failed(hr_, "CoInitializeEx");
    }
  }

  ~ComApartment() {
    if (SUCCEEDED(hr_)) {
      CoUninitialize();
    }
  }

 private:
  HRESULT hr_ = E_FAIL;
};

class DispatchPtr {
 public:
  ~DispatchPtr() {
    if (dispatch_ != nullptr) {
      dispatch_->Release();
    }
  }

  IDispatch** put() { return &dispatch_; }
  IDispatch* get() const { return dispatch_; }

 private:
  IDispatch* dispatch_ = nullptr;
};

class ModuleHandle {
 public:
  explicit ModuleHandle(const std::string& path) {
    const std::string absolutePath = full_path_name(path);
    module_ = LoadLibraryExW(
        widen(absolutePath).c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (module_ == nullptr) {
      throw_last_error("LoadLibraryExW(native adapter: " + absolutePath + ")");
    }
  }

  ~ModuleHandle() {
    if (module_ != nullptr) {
      FreeLibrary(module_);
    }
  }

  ModuleHandle(const ModuleHandle&) = delete;
  ModuleHandle& operator=(const ModuleHandle&) = delete;

  FARPROC find(const std::string& entrypoint) const {
    FARPROC result = GetProcAddress(module_, entrypoint.c_str());
    if (result == nullptr) {
      throw_last_error("GetProcAddress(native adapter: " + entrypoint + ")");
    }
    return result;
  }

 private:
  HMODULE module_ = nullptr;
};

void assign_bstr(VARIANT& variant, const std::string& value) {
  variant.vt = VT_BSTR;
  variant.bstrVal = SysAllocString(widen(value).c_str());
  if (variant.bstrVal == nullptr) {
    throw std::runtime_error("SysAllocString failed");
  }
}

bool parse_bool_value(const std::string& value) {
  if (value == "true" || value == "1") {
    return true;
  }
  if (value == "false" || value == "0") {
    return false;
  }
  throw std::runtime_error("invalid boolean argument value: " + value);
}

void assign_variant(VARIANT& variant, const ResolvedArgument& argument) {
  VariantInit(&variant);
  switch (argument.type) {
    case ArgumentType::String:
    case ArgumentType::Path:
      assign_bstr(variant, argument.value);
      break;
    case ArgumentType::Int32:
      variant.vt = VT_I4;
      variant.lVal = std::stoi(argument.value);
      break;
    case ArgumentType::UInt32:
      variant.vt = VT_UI4;
      variant.ulVal = static_cast<ULONG>(std::stoul(argument.value));
      break;
    case ArgumentType::Int64:
      variant.vt = VT_I8;
      variant.llVal = std::stoll(argument.value);
      break;
    case ArgumentType::Boolean:
      variant.vt = VT_BOOL;
      variant.boolVal = parse_bool_value(argument.value) ? VARIANT_TRUE : VARIANT_FALSE;
      break;
  }
}

void activate_dispatch(const TargetDefinition& definition, DispatchPtr& dispatch) {
  CLSID clsid{};
  throw_if_failed(CLSIDFromString(widen(definition.clsid).c_str(), &clsid), "CLSIDFromString");
  if (!definition.iid.empty()) {
    IID requested{};
    throw_if_failed(
        IIDFromString(widen(definition.iid).c_str(), &requested),
        "IIDFromString");
    if (IsEqualIID(requested, IID_IDispatch)) {
      throw_if_failed(
          CoCreateInstance(
              clsid, nullptr, CLSCTX_LOCAL_SERVER, IID_IDispatch,
              reinterpret_cast<void**>(dispatch.put())),
          "CoCreateInstance(CLSCTX_LOCAL_SERVER, IID_IDispatch)");
      return;
    }
    IUnknown* requestedInterface = nullptr;
    throw_if_failed(
        CoCreateInstance(
            clsid, nullptr, CLSCTX_LOCAL_SERVER, requested,
            reinterpret_cast<void**>(&requestedInterface)),
        "CoCreateInstance(CLSCTX_LOCAL_SERVER, requested IID)");
    const HRESULT query = requestedInterface->QueryInterface(
        IID_IDispatch, reinterpret_cast<void**>(dispatch.put()));
    requestedInterface->Release();
    throw_if_failed(
        query,
        "requested COM interface does not expose IDispatch");
    return;
  }
  throw_if_failed(
      CoCreateInstance(
          clsid,
          nullptr,
          CLSCTX_LOCAL_SERVER,
          IID_IDispatch,
          reinterpret_cast<void**>(dispatch.put())),
      "CoCreateInstance(CLSCTX_LOCAL_SERVER, IID_IDispatch)");
}

DISPID activate_and_resolve_method(const TargetDefinition& definition, DispatchPtr& dispatch) {
  activate_dispatch(definition, dispatch);

  std::wstring methodName = widen(definition.method);
  LPOLESTR methodNames[] = {methodName.data()};
  DISPID dispid = 0;
  throw_if_failed(
      dispatch.get()->GetIDsOfNames(IID_NULL, methodNames, 1, LOCALE_USER_DEFAULT, &dispid),
      "IDispatch::GetIDsOfNames(" + definition.method + ")");
  return dispid;
}

std::uint32_t native_adapter_argument_type(ArgumentType type) {
  switch (type) {
    case ArgumentType::String:
      return COMWRITERACE_NATIVE_ADAPTER_STRING_V1;
    case ArgumentType::Path:
      return COMWRITERACE_NATIVE_ADAPTER_PATH_V1;
    case ArgumentType::Int32:
      return COMWRITERACE_NATIVE_ADAPTER_INT32_V1;
    case ArgumentType::UInt32:
      return COMWRITERACE_NATIVE_ADAPTER_UINT32_V1;
    case ArgumentType::Int64:
      return COMWRITERACE_NATIVE_ADAPTER_INT64_V1;
    case ArgumentType::Boolean:
      return COMWRITERACE_NATIVE_ADAPTER_BOOLEAN_V1;
  }
  throw std::runtime_error("unsupported native adapter argument type");
}

void call_native_adapter(
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments,
    ComWriteRaceNativeAdapterOperationV1 operation) {
  if (arguments.size() >
      static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
    throw std::runtime_error("too many arguments for native adapter ABI v1");
  }

  ModuleHandle module(definition.nativeAdapter.path);
  FARPROC rawEntry = module.find(definition.nativeAdapter.entrypoint);
  ComWriteRaceNativeAdapterEntryV1 entrypoint = nullptr;
  static_assert(sizeof(entrypoint) == sizeof(rawEntry));
  std::memcpy(&entrypoint, &rawEntry, sizeof(entrypoint));

  std::vector<std::wstring> names;
  std::vector<std::wstring> values;
  names.reserve(arguments.size());
  values.reserve(arguments.size());
  for (const ResolvedArgument& argument : arguments) {
    names.push_back(widen(argument.name));
    values.push_back(widen(argument.value));
  }

  std::vector<ComWriteRaceNativeAdapterArgumentV1> nativeArguments;
  nativeArguments.reserve(arguments.size());
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    nativeArguments.push_back(ComWriteRaceNativeAdapterArgumentV1{
        sizeof(ComWriteRaceNativeAdapterArgumentV1),
        native_adapter_argument_type(arguments[i].type),
        names[i].c_str(),
        values[i].c_str()});
  }

  const std::wstring clsid = widen(definition.clsid);
  const std::wstring iid = widen(definition.iid);
  const std::wstring method = widen(definition.method);
  const ComWriteRaceNativeAdapterRequestV1 request{
      sizeof(ComWriteRaceNativeAdapterRequestV1),
      COMWRITERACE_NATIVE_ADAPTER_ABI_V1,
      operation,
      clsid.c_str(),
      iid.c_str(),
      method.c_str(),
      nativeArguments.empty() ? nullptr : nativeArguments.data(),
      static_cast<std::uint32_t>(nativeArguments.size())};

  std::vector<wchar_t> errorBuffer(2048, L'\0');
  const HRESULT result = entrypoint(
      &request,
      errorBuffer.data(),
      static_cast<std::uint32_t>(errorBuffer.size()));
  errorBuffer.back() = L'\0';
  if (FAILED(result)) {
    std::string action =
        "native adapter " + definition.nativeAdapter.entrypoint;
    if (errorBuffer.front() != L'\0') {
      action += ": " + narrow(errorBuffer.data());
    }
    throw_if_failed(result, action);
  }
}

}

void probe_idispatch_method(const TargetDefinition& definition) {
  ComApartment apartment;
  DispatchPtr dispatch;
  (void)activate_and_resolve_method(definition, dispatch);
}

void invoke_idispatch_method(
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments) {
  ComApartment apartment;

  DispatchPtr dispatch;
  const DISPID dispid = activate_and_resolve_method(definition, dispatch);

  std::vector<VARIANT> variants(arguments.size());
  try {
    for (std::size_t i = 0; i < arguments.size(); ++i) {
      assign_variant(variants[arguments.size() - 1 - i], arguments[i]);
    }

    DISPPARAMS params{};
    params.cArgs = static_cast<UINT>(variants.size());
    params.rgvarg = variants.empty() ? nullptr : variants.data();

    VARIANT result;
    VariantInit(&result);
    EXCEPINFO exceptionInfo{};
    UINT argumentError = 0;
    const HRESULT hr = dispatch.get()->Invoke(
        dispid,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &params,
        &result,
        &exceptionInfo,
        &argumentError);

    VariantClear(&result);
    if (FAILED(hr)) {
      if (hr == DISP_E_EXCEPTION && exceptionInfo.bstrDescription != nullptr) {
        const std::string description = narrow(exceptionInfo.bstrDescription);
        SysFreeString(exceptionInfo.bstrSource);
        SysFreeString(exceptionInfo.bstrDescription);
        SysFreeString(exceptionInfo.bstrHelpFile);
        throw std::runtime_error("IDispatch::Invoke exception: " + description);
      }
      SysFreeString(exceptionInfo.bstrSource);
      SysFreeString(exceptionInfo.bstrDescription);
      SysFreeString(exceptionInfo.bstrHelpFile);
      throw_if_failed(hr, "IDispatch::Invoke(" + definition.method + ")");
    }
  } catch (...) {
    for (VARIANT& variant : variants) {
      VariantClear(&variant);
    }
    throw;
  }

  for (VARIANT& variant : variants) {
    VariantClear(&variant);
  }
}

void probe_target_method(const TargetDefinition& definition) {
  if (definition.invoker == "idispatch") {
    probe_idispatch_method(definition);
    return;
  }
  call_native_adapter(
      definition,
      {},
      COMWRITERACE_NATIVE_ADAPTER_PROBE_V1);
}

void invoke_target_method(
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments) {
  if (definition.invoker == "idispatch") {
    invoke_idispatch_method(definition, arguments);
    return;
  }
  call_native_adapter(
      definition,
      arguments,
      COMWRITERACE_NATIVE_ADAPTER_INVOKE_V1);
}

namespace {

const char* vartype_name(VARTYPE vt) {
  switch (vt & VT_TYPEMASK) {
    case VT_BSTR:    return "BSTR";
    case VT_LPWSTR:  return "LPWSTR";
    case VT_LPSTR:   return "LPSTR";
    case VT_I1: case VT_I2: case VT_I4: case VT_INT: return "int";
    case VT_UI1: case VT_UI2: case VT_UI4: case VT_UINT: return "uint";
    case VT_I8:      return "int64";
    case VT_UI8:     return "uint64";
    case VT_BOOL:    return "bool";
    case VT_VARIANT: return "variant";
    case VT_DISPATCH: return "IDispatch";
    case VT_UNKNOWN: return "IUnknown";
    case VT_VOID: case VT_EMPTY: return "void";
    default:        return "other";
  }
}

const char* param_type_name(const ELEMDESC& elem, bool& byref) {
  const TYPEDESC& td = elem.tdesc;
  if (td.vt == VT_PTR && td.lptdesc != nullptr) {
    byref = true;
    return vartype_name(td.lptdesc->vt);
  }
  byref = false;
  return vartype_name(td.vt);
}

bool is_iunknown_or_idispatch_member(MEMBERID memid) {
  const unsigned long id = static_cast<unsigned long>(memid);
  return id >= 0x60000000UL && id <= 0x6001FFFFUL;
}

std::string bstr_to_utf8(BSTR value) {
  if (value == nullptr) {
    return {};
  }
  const UINT length = SysStringLen(value);
  return narrow(std::wstring(value, length));
}

std::string hresult_hex(HRESULT hr) {
  std::ostringstream out;
  out << "0x" << std::hex << static_cast<unsigned long>(hr);
  return out.str();
}

}

std::string activation_probe_json(const TargetDefinition& definition) {
  ComApartment apartment;
  CLSID clsid{};
  const HRESULT parsed = CLSIDFromString(widen(definition.clsid).c_str(), &clsid);
  if (FAILED(parsed)) {
    return "{\"local_server\":false,\"local_server_hresult\":\"" +
           hresult_hex(parsed) + "\",\"idispatch\":false}";
  }

  IUnknown* unknown = nullptr;
  const HRESULT hr = CoCreateInstance(
      clsid, nullptr, CLSCTX_LOCAL_SERVER, IID_IUnknown,
      reinterpret_cast<void**>(&unknown));
  std::ostringstream out;
  out << "{\"local_server\":" << (SUCCEEDED(hr) ? "true" : "false")
      << ",\"local_server_hresult\":\"" << hresult_hex(hr) << "\"";
  if (SUCCEEDED(hr) && unknown != nullptr) {
    IDispatch* dispatch = nullptr;
    const bool hasDispatch = SUCCEEDED(unknown->QueryInterface(
        IID_IDispatch, reinterpret_cast<void**>(&dispatch)));
    HRESULT methodResult = E_NOINTERFACE;
    bool methodAvailable = false;
    if (hasDispatch && !definition.method.empty()) {
      std::wstring methodName = widen(definition.method);
      LPOLESTR methodNames[] = {methodName.data()};
      DISPID dispid = 0;
      methodResult = dispatch->GetIDsOfNames(
          IID_NULL, methodNames, 1, LOCALE_USER_DEFAULT, &dispid);
      methodAvailable = SUCCEEDED(methodResult);
    }
    if (dispatch != nullptr) {
      dispatch->Release();
    }
    out << ",\"idispatch\":" << (hasDispatch ? "true" : "false");
    if (!definition.method.empty()) {
      out << ",\"method_available\":"
          << (methodAvailable ? "true" : "false")
          << ",\"method_hresult\":\"" << hresult_hex(methodResult) << "\"";
    }
    unknown->Release();
  } else {
    out << ",\"idispatch\":false";
  }
  out << "}";
  return out.str();
}

std::string type_info_json(const TargetDefinition& definition) {
  ComApartment apartment;
  DispatchPtr dispatch;

  activate_dispatch(definition, dispatch);

  std::ostringstream out;
  out << "{\"activation\":\"ok\",\"clsid\":";
  json_output::write_string(out, definition.clsid);
  out << ",\"activation_context\":\"local_server_only\"";

  UINT count = 0;
  if (FAILED(dispatch.get()->GetTypeInfoCount(&count)) || count == 0) {
    out << ",\"type_info\":false,\"functions\":[]}";
    return out.str();
  }

  ITypeInfo* rawInfo = nullptr;
  if (FAILED(dispatch.get()->GetTypeInfo(0, LOCALE_USER_DEFAULT, &rawInfo)) ||
      rawInfo == nullptr) {
    out << ",\"type_info\":false,\"functions\":[]}";
    return out.str();
  }

  out << ",\"type_info\":true";

  BSTR ifaceName = nullptr;
  if (SUCCEEDED(rawInfo->GetDocumentation(MEMBERID_NIL, &ifaceName, nullptr, nullptr, nullptr))) {
    out << ",\"interface\":";
    json_output::write_string(out, bstr_to_utf8(ifaceName));
    SysFreeString(ifaceName);
  }

  TYPEATTR* attr = nullptr;
  out << ",\"functions\":[";
  if (SUCCEEDED(rawInfo->GetTypeAttr(&attr)) && attr != nullptr) {
    bool first = true;
    for (WORD i = 0; i < attr->cFuncs; ++i) {
      FUNCDESC* fd = nullptr;
      if (FAILED(rawInfo->GetFuncDesc(i, &fd)) || fd == nullptr) {
        continue;
      }
      if (fd->invkind == INVOKE_PROPERTYPUTREF ||
          is_iunknown_or_idispatch_member(fd->memid)) {
        rawInfo->ReleaseFuncDesc(fd);
        continue;
      }

      const UINT wanted = static_cast<UINT>(fd->cParams) + 1;
      std::vector<BSTR> names(wanted, nullptr);
      UINT got = 0;
      rawInfo->GetNames(fd->memid, names.data(), wanted, &got);

      out << (first ? "" : ",") << "{\"name\":";
      json_output::write_string(out, got > 0 ? bstr_to_utf8(names[0]) : std::string{});
      out << ",\"dispid\":" << fd->memid << ",\"invoke_kind\":";
      const char* kind = fd->invkind == INVOKE_FUNC ? "func"
                       : fd->invkind == INVOKE_PROPERTYGET ? "propget"
                       : "propput";
      out << "\"" << kind << "\",\"params\":[";
      bool firstParam = true;
      for (SHORT p = 0; p < fd->cParams; ++p) {
        const ELEMDESC& elem = fd->lprgelemdescParam[p];
        const USHORT flags = elem.paramdesc.wParamFlags;

        if (flags & (PARAMFLAG_FRETVAL | PARAMFLAG_FLCID)) {
          continue;
        }

        const bool isIn = (flags & PARAMFLAG_FIN) != 0 || flags == 0;
        bool byref = false;
        const char* typeName = param_type_name(elem, byref);
        out << (firstParam ? "" : ",") << "{\"name\":";
        firstParam = false;
        const UINT nameIndex = static_cast<UINT>(p) + 1;
        json_output::write_string(
            out, (nameIndex < got && names[nameIndex]) ? bstr_to_utf8(names[nameIndex])
                                                       : std::string{});
        out << ",\"type\":\"" << typeName << "\""
            << ",\"byref\":" << (byref ? "true" : "false")
            << ",\"in\":" << (isIn ? "true" : "false")
            << ",\"out\":" << ((flags & PARAMFLAG_FOUT) ? "true" : "false")
            << ",\"optional\":" << ((flags & PARAMFLAG_FOPT) ? "true" : "false")
            << "}";
      }
      out << "]}";
      first = false;

      for (BSTR name : names) {
        SysFreeString(name);
      }
      rawInfo->ReleaseFuncDesc(fd);
    }
    rawInfo->ReleaseTypeAttr(attr);
  }
  out << "]}";
  rawInfo->Release();
  return out.str();
}

}
