
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "comrace/json.hpp"
#include "comrace/target_definition.hpp"
#include "comrace/runner.hpp"
#include "platform/windows/com_invoker.hpp"
#include "platform/windows/win_utils.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_ipc_handle(HANDLE file) {
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
      size.QuadPart > 4LL * 1024 * 1024) {
    throw std::runtime_error("cannot size inherited broker request");
  }
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
    throw std::runtime_error("cannot rewind inherited broker request");
  }
  std::string content(static_cast<std::size_t>(size.QuadPart), '\0');
  std::size_t offset = 0;
  while (offset < content.size()) {
    DWORD read = 0;
    const DWORD wanted = static_cast<DWORD>(content.size() - offset);
    if (!ReadFile(file, content.data() + offset, wanted, &read, nullptr)) {
      throw std::runtime_error("cannot read inherited broker request");
    }
    if (read == 0) {
      break;
    }
    offset += read;
  }
  content.resize(offset);
  return content;
}

std::string str_field(const comrace::json::Value& object, const char* key) {
  const comrace::json::Value* value = object.find(key);
  return (value && value->is_string()) ? value->as_string() : std::string{};
}

std::string json_escape(const std::string& value) {
  std::string out;
  for (const char c : value) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (c == '\n' || c == '\r' || c == '\t') {
      out += ' ';
    } else {
      out += c;
    }
  }
  return out;
}

void write_result(
    HANDLE file,
    const std::string& sessionId,
    const std::string& status,
    const std::string& message,
    const std::string& hresult,
    const std::string& extraJson = {}) {
  std::ostringstream out;
  out << "{\"session_id\":\"" << json_escape(sessionId)
      << "\",\"status\":\"" << status << "\",\"message\":\""
      << json_escape(message) << "\",\"hresult\":\"" << hresult << "\"";
  if (!extraJson.empty()) {
    out << "," << extraJson;
  }
  out << "}";
  const std::string content = out.str();

  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) ||
      !SetEndOfFile(file)) {
    return;
  }
  DWORD written = 0;
  if (!WriteFile(
          file, content.data(), static_cast<DWORD>(content.size()),
          &written, nullptr) ||
      static_cast<std::size_t>(written) != content.size()) {
    return;
  }
  FlushFileBuffers(file);
}

comrace::TargetDefinition definition_from_request(const comrace::json::Value& request) {
  comrace::TargetDefinition definition;
  definition.invoker = str_field(request, "invoker");
  if (definition.invoker.empty()) {
    definition.invoker = "idispatch";
  }
  definition.clsid = str_field(request, "clsid");
  definition.iid = str_field(request, "iid");
  definition.method = str_field(request, "method");
  if (const comrace::json::Value* adapter = request.find("native_adapter")) {
    if (adapter->is_object()) {
      definition.nativeAdapter.path = str_field(*adapter, "path");
      const std::string entry = str_field(*adapter, "entrypoint");
      if (!entry.empty()) {
        definition.nativeAdapter.entrypoint = entry;
      }
    }
  }
  return definition;
}

std::vector<comrace::ResolvedArgument> args_from_request(
    const comrace::json::Value& request) {
  std::vector<comrace::ResolvedArgument> arguments;
  const comrace::json::Value* args = request.find("args");
  if (!args || !args->is_array()) {
    return arguments;
  }
  for (const comrace::json::Value& entry : args->as_array()) {
    if (!entry.is_object()) {
      continue;
    }
    comrace::ResolvedArgument argument;
    argument.name = str_field(entry, "name");
    argument.type = comrace::parse_argument_type(
        str_field(entry, "type").empty() ? "string" : str_field(entry, "type"));
    argument.value = str_field(entry, "value");
    arguments.push_back(std::move(argument));
  }
  return arguments;
}

HANDLE arg_handle(int argc, wchar_t** argv, const wchar_t* flag) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (wcscmp(argv[i], flag) != 0) {
      continue;
    }
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long long raw = wcstoull(argv[i + 1], &end, 10);
    if (errno != 0 || end == argv[i + 1] || *end != L'\0' || raw == 0) {
      return INVALID_HANDLE_VALUE;
    }
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(raw));
  }
  return INVALID_HANDLE_VALUE;
}

}

int wmain(int argc, wchar_t** argv) {
  comrace::win::UniqueHandle requestFile(
      arg_handle(argc, argv, L"--request-handle"));
  comrace::win::UniqueHandle resultFile(
      arg_handle(argc, argv, L"--result-handle"));
  if (!requestFile || !resultFile) {
    return 1;
  }

  comrace::TargetDefinition definition;
  std::vector<comrace::ResolvedArgument> arguments;
  std::string operation = "invoke";
  std::string sessionId;
  try {
    const comrace::json::Value request =
        comrace::json::parse(read_ipc_handle(requestFile.get()));
    sessionId = str_field(request, "session_id");
    if (sessionId.empty()) {
      throw std::runtime_error("request is missing session_id");
    }
    operation = str_field(request, "operation");
    if (operation != "probe" && operation != "invoke" &&
        operation != "inspect" && operation != "activation-probe") {
      throw std::runtime_error("request contains an unsupported operation");
    }
    definition = definition_from_request(request);
    arguments = args_from_request(request);
  } catch (const std::exception& ex) {
    write_result(resultFile.get(), sessionId, "bad_request", ex.what(), "");
    return 1;
  }
  const bool probe = operation == "probe";

  try {
    if (operation == "activation-probe") {
      const std::string info = comrace::win::activation_probe_json(definition);
      write_result(resultFile.get(), sessionId, "success", "activation probed", "",
                   "\"activation_probe\":" + info);
    } else if (operation == "inspect") {
      const std::string info = comrace::win::type_info_json(definition);
      write_result(resultFile.get(), sessionId, "success", "type information collected", "",
                   "\"type_info\":" + info);
    } else if (probe) {
      comrace::win::probe_target_method(definition);
      write_result(resultFile.get(), sessionId, "success", "activation and method resolution succeeded", "");
    } else {
      comrace::win::invoke_target_method(definition, arguments);
      write_result(resultFile.get(), sessionId, "success", "privileged method invoked", "");
    }
    return 0;
  } catch (const std::exception& ex) {
    const std::string what = ex.what();
    std::string hresult;
    const std::size_t marker = what.find("0x");
    if (marker != std::string::npos) {
      hresult = what.substr(marker, what.find_first_not_of("0123456789abcdefABCDEFx", marker) - marker);
    }
    write_result(resultFile.get(), sessionId, probe ? "activation_error" : "com_error", what, hresult);
    return 2;
  } catch (...) {
    write_result(resultFile.get(), sessionId, "internal_error", "unknown exception in invocation host", "");
    return 2;
  }
}
