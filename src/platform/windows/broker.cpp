#include "platform/windows/broker.hpp"

#include "comrace/json.hpp"
#include "comrace/json_output.hpp"
#include "platform/windows/win_utils.hpp"

#include <objbase.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace comrace::win {
namespace {

std::string argument_type_token(ArgumentType type) {
  switch (type) {
    case ArgumentType::String:  return "string";
    case ArgumentType::Path:    return "path";
    case ArgumentType::Int32:   return "int32";
    case ArgumentType::UInt32:  return "uint32";
    case ArgumentType::Int64:   return "int64";
    case ArgumentType::Boolean: return "bool";
  }
  return "string";
}

std::string serialize_request(
    BrokerOperation operation,
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments,
    const std::string& sessionId) {
  const char* op = operation == BrokerOperation::Probe ? "probe"
                 : operation == BrokerOperation::Inspect ? "inspect"
                 : operation == BrokerOperation::ActivationProbe ? "activation-probe"
                                                         : "invoke";
  std::ostringstream out;
  out << "{\"session_id\":";
  json_output::write_string(out, sessionId);
  out << ",\"operation\":\"" << op << "\"";
  out << ",\"invoker\":";
  json_output::write_string(out, definition.invoker);
  out << ",\"clsid\":";
  json_output::write_string(out, definition.clsid);
  out << ",\"iid\":";
  json_output::write_string(out, definition.iid);
  out << ",\"method\":";
  json_output::write_string(out, definition.method);
  out << ",\"native_adapter\":{\"path\":";
  json_output::write_string(out, definition.nativeAdapter.path);
  out << ",\"entrypoint\":";
  json_output::write_string(out, definition.nativeAdapter.entrypoint);
  out << "},\"args\":[";
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    if (i != 0) {
      out << ",";
    }
    out << "{\"name\":";
    json_output::write_string(out, arguments[i].name);
    out << ",\"type\":";
    json_output::write_string(out, argument_type_token(arguments[i].type));
    out << ",\"value\":";
    json_output::write_string(out, arguments[i].value);
    out << "}";
  }
  out << "]}";
  return out.str();
}

std::string json_string_field(const json::Value& object, const char* key) {
  const json::Value* value = object.find(key);
  return (value && value->is_string()) ? value->as_string() : std::string{};
}

std::string join_dir(const std::string& directory, const std::string& leaf) {
  std::string out = directory;
  if (!out.empty() && out.back() != '\\' && out.back() != '/') {
    out += "\\";
  }
  return out + leaf;
}

std::string broker_temp_directory() {
  std::wstring buffer(MAX_PATH + 1, L'\0');
  DWORD len = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
  if (len == 0 || len > buffer.size()) {
    return {};
  }
  buffer.resize(len);
  std::string dir = join_dir(narrow(buffer), "ComWriteRace");
  if (!CreateDirectoryW(widen(dir).c_str(), nullptr)) {
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) {
      return {};
    }
  }
  if (!directory_exists(dir) || is_reparse_point(dir)) {
    return {};
  }
  return dir;
}

UniqueHandle create_locked_ipc_file(const std::string& path) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  UniqueHandle file(CreateFileW(
      widen(path).c_str(),
      GENERIC_READ | GENERIC_WRITE | DELETE,
      0,
      &security,
      CREATE_NEW,
      FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
      nullptr));
  if (!file) {
    throw_last_error("CreateFileW(locked broker IPC " + path + ")");
  }
  return file;
}

void write_locked_ipc_file(
    HANDLE file,
    const std::string& path,
    const std::string& content) {
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) ||
      !SetEndOfFile(file)) {
    throw_last_error("truncate broker request " + path);
  }
  DWORD written = 0;
  if (!WriteFile(
          file, content.data(), static_cast<DWORD>(content.size()),
          &written, nullptr) ||
      static_cast<std::size_t>(written) != content.size()) {
    throw_last_error("WriteFile(broker request " + path + ")");
  }
  if (!FlushFileBuffers(file)) {
    throw_last_error("FlushFileBuffers(broker request " + path + ")");
  }
}

std::string read_locked_ipc_file(HANDLE file, const std::string& path) {
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file, &size)) {
    throw_last_error("GetFileSizeEx(broker result " + path + ")");
  }
  constexpr long long kMaximumResultBytes = 4LL * 1024 * 1024;
  if (size.QuadPart < 0 || size.QuadPart > kMaximumResultBytes) {
    throw std::runtime_error("broker result has an invalid/oversized length");
  }
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
    throw_last_error("rewind broker result " + path);
  }
  std::string content(static_cast<std::size_t>(size.QuadPart), '\0');
  std::size_t offset = 0;
  while (offset < content.size()) {
    DWORD read = 0;
    const DWORD wanted = static_cast<DWORD>(content.size() - offset);
    if (!ReadFile(file, content.data() + offset, wanted, &read, nullptr)) {
      throw_last_error("ReadFile(broker result " + path + ")");
    }
    if (read == 0) {
      break;
    }
    offset += read;
  }
  content.resize(offset);
  return content;
}

void sweep_stale_temp_files(const std::string& directory) {
  WIN32_FIND_DATAW found{};
  const std::wstring pattern = widen(join_dir(directory, ".cwr-broker-*"));
  HANDLE handle = FindFirstFileW(pattern.c_str(), &found);
  if (handle == INVALID_HANDLE_VALUE) {
    return;
  }
  FILETIME nowFt{};
  GetSystemTimeAsFileTime(&nowFt);
  ULARGE_INTEGER now{};
  now.HighPart = nowFt.dwHighDateTime;
  now.LowPart = nowFt.dwLowDateTime;
  do {
    ULARGE_INTEGER written{};
    written.HighPart = found.ftLastWriteTime.dwHighDateTime;
    written.LowPart = found.ftLastWriteTime.dwLowDateTime;
    const unsigned long long tenMinutes = 10ULL * 60ULL * 10'000'000ULL;
    if (now.QuadPart > written.QuadPart &&
        now.QuadPart - written.QuadPart > tenMinutes) {
      DeleteFileW(widen(join_dir(directory, narrow(found.cFileName))).c_str());
    }
  } while (FindNextFileW(handle, &found));
  FindClose(handle);
}

bool is_pe_32bit(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  char dos[64]{};
  if (!file.read(dos, sizeof(dos))) {
    return false;
  }
  if (dos[0] != 'M' || dos[1] != 'Z') {
    return false;
  }
  const std::uint32_t peOffset =
      static_cast<unsigned char>(dos[60]) |
      (static_cast<unsigned char>(dos[61]) << 8) |
      (static_cast<unsigned char>(dos[62]) << 16) |
      (static_cast<unsigned char>(dos[63]) << 24);
  file.seekg(peOffset);
  char pe[6]{};
  if (!file.read(pe, sizeof(pe))) {
    return false;
  }
  if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) {
    return false;
  }
  const std::uint16_t machine =
      static_cast<unsigned char>(pe[4]) |
      (static_cast<unsigned char>(pe[5]) << 8);
  return machine == 0x014c;
}

}

std::string module_directory() {
  std::wstring buffer(MAX_PATH, L'\0');
  for (;;) {
    const DWORD written =
        GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (written == 0) {
      return {};
    }
    if (written < buffer.size() - 1) {
      buffer.resize(written);
      break;
    }
    buffer.resize(buffer.size() * 2);
  }
  const std::size_t slash = buffer.find_last_of(L"\\/");
  if (slash == std::wstring::npos) {
    return {};
  }
  return narrow(buffer.substr(0, slash));
}

std::string resolve_host_executable(
    const std::string& hostArch,
    const TargetDefinition& definition) {
  const std::string dir = module_directory();
  std::string x64 = dir + "\\cwr-host64.exe";
  std::string x86 = dir + "\\cwr-host32.exe";

  if (!file_exists(x64)) x64 = dir + "\\comwrite_host.exe";
  if (!file_exists(x86)) x86 = dir + "\\comwrite_host_x86.exe";

  std::string arch = hostArch;
  if (arch == "auto" || arch.empty()) {
    arch = "x64";
    if (definition.invoker == "native_adapter" &&
        !definition.nativeAdapter.path.empty() &&
        is_pe_32bit(definition.nativeAdapter.path)) {
      arch = "x86";
    }
  }
  return arch == "x86" ? x86 : x64;
}

BrokerSession::BrokerSession(
    const std::string& hostExecutable,
    const std::string& workingDirectory,
    BrokerOperation operation,
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments) {
  if (!file_exists(hostExecutable)) {
    startError_ = "invocation host not found next to comwriterace.exe: " + hostExecutable;
    return;
  }

  std::string ipcDir = broker_temp_directory();
  if (!directory_exists(ipcDir)) {
    startError_ = "could not create the per-user broker IPC directory";
    return;
  }
  sweep_stale_temp_files(ipcDir);

  std::wstring childCwd;
  if (directory_exists(workingDirectory)) {
    childCwd = widen(full_path_name(workingDirectory));
  } else {
    const std::string moduleDir = module_directory();
    if (directory_exists(moduleDir)) {
      childCwd = widen(moduleDir);
    }
  }
  const wchar_t* childCwdArg = childCwd.empty() ? nullptr : childCwd.c_str();

  sessionId_ = new_guid_token();
  if (sessionId_.empty()) {
    startError_ = "CoCreateGuid failed while creating the broker session ID";
    return;
  }
  const std::string token = ".cwr-broker-" + sessionId_;
  requestPath_ = join_dir(ipcDir, token + ".req.json");
  resultPath_ = join_dir(ipcDir, token + ".res.json");

  try {
    requestFile_ = create_locked_ipc_file(requestPath_);
    resultFile_ = create_locked_ipc_file(resultPath_);
    write_locked_ipc_file(
        requestFile_.get(), requestPath_,
        serialize_request(operation, definition, arguments, sessionId_));
  } catch (const std::exception& ex) {
    startError_ = std::string("could not stage locked broker IPC: ") + ex.what();
    return;
  }

  job_.reset(CreateJobObjectW(nullptr, nullptr));
  if (!job_) {
    startError_ = "CreateJobObjectW failed: " + last_error_message();
    return;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation,
                               &limits, sizeof(limits))) {
    startError_ = "SetInformationJobObject failed: " + last_error_message();
    return;
  }

  std::wstring commandLine =
      L"\"" + widen(hostExecutable) + L"\" --request-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(requestFile_.get())) +
      L" --result-handle " +
      std::to_wstring(reinterpret_cast<std::uintptr_t>(resultFile_.get()));
  std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
  mutableCommand.push_back(L'\0');

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  SIZE_T attributeBytes = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
  if (attributeBytes == 0) {
    startError_ = "could not size the broker handle inheritance list: " +
                  last_error_message();
    return;
  }
  std::vector<unsigned char> attributeStorage(attributeBytes);
  startup.lpAttributeList = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(
      attributeStorage.data());
  if (!InitializeProcThreadAttributeList(
          startup.lpAttributeList, 1, 0, &attributeBytes)) {
    startError_ = "could not initialize the broker handle inheritance list: " +
                  last_error_message();
    return;
  }
  HANDLE inheritedHandles[] = {requestFile_.get(), resultFile_.get()};
  if (!UpdateProcThreadAttribute(
          startup.lpAttributeList,
          0,
          PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
          inheritedHandles,
          sizeof(inheritedHandles),
          nullptr,
          nullptr)) {
    startError_ = "could not restrict broker handle inheritance: " +
                  last_error_message();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    return;
  }
  PROCESS_INFORMATION process{};
  const BOOL created = CreateProcessW(
          widen(hostExecutable).c_str(),
          mutableCommand.data(),
          nullptr,
          nullptr,
          TRUE,
          CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
          nullptr,
          childCwdArg,
          &startup.StartupInfo,
          &process);
  const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
  DeleteProcThreadAttributeList(startup.lpAttributeList);

  SetHandleInformation(requestFile_.get(), HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(resultFile_.get(), HANDLE_FLAG_INHERIT, 0);
  if (!created) {
    startError_ = "CreateProcessW(host) failed: " + last_error_message(createError);
    return;
  }

  if (!AssignProcessToJobObject(job_.get(), process.hProcess)) {
    startError_ = "AssignProcessToJobObject failed: " + last_error_message();
    TerminateProcess(process.hProcess, 1);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return;
  }

  startTick_ = qpc_now();
  if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
    startError_ = "ResumeThread failed: " + last_error_message();
    TerminateJobObject(job_.get(), 1);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return;
  }
  CloseHandle(process.hThread);
  process_.reset(process.hProcess);
  started_ = true;
}

BrokerSession::~BrokerSession() {
  kill();
  requestFile_.reset();
  resultFile_.reset();
  if (!requestPath_.empty()) {
    try { delete_file_if_exists(requestPath_); } catch (...) {}
  }
  if (!resultPath_.empty()) {
    try { delete_file_if_exists(resultPath_); } catch (...) {}
  }
}

bool BrokerSession::kill() {
  if (finished_) {
    return true;
  }
  bool terminationRequested = false;
  if (job_) {
    terminationRequested = TerminateJobObject(job_.get(), 1) != FALSE;
  }

  if (process_) {
    if (!terminationRequested) {
      terminationRequested = TerminateProcess(process_.get(), 1) != FALSE;
    }
    const DWORD waited = WaitForSingleObject(process_.get(), 5000);
    finished_ = waited == WAIT_OBJECT_0;
    return finished_;
  }
  finished_ = true;
  return true;
}

BrokerOutcome BrokerSession::wait(unsigned timeoutMs) {
  BrokerOutcome outcome;
  outcome.started = started_;
  if (!started_) {
    outcome.status = "host_start_error";
    outcome.message = startError_;
    return outcome;
  }

  const DWORD waited = WaitForSingleObject(process_.get(), timeoutMs);
  if (waited == WAIT_FAILED) {
    const DWORD error = GetLastError();
    const bool terminated = kill();
    outcome.status = "wait_error";
    outcome.message = "WaitForSingleObject(host) failed: " +
                      last_error_message(error) +
                      (terminated ? std::string{} : "; host termination not observed");
    return outcome;
  }
  if (waited == WAIT_TIMEOUT) {
    const bool terminated = kill();
    outcome.timedOut = true;
    outcome.status = terminated ? "timeout" : "timeout_termination_unknown";
    outcome.message = "invocation host did not exit within " +
                      std::to_string(timeoutMs) + "ms" +
                      (terminated ? std::string{} : "; host termination not observed");
    return outcome;
  }

  outcome.completed = true;
  DWORD code = 0;
  if (GetExitCodeProcess(process_.get(), &code)) {
    outcome.exitCode = static_cast<int>(code);
  }
  finished_ = true;

  try {
    outcome.rawResult = read_locked_ipc_file(resultFile_.get(), resultPath_);
  } catch (const std::exception& ex) {
    outcome.status = "bad_result";
    outcome.message = std::string("could not read locked host result: ") + ex.what();
    return outcome;
  }
  if (outcome.rawResult.empty()) {
    outcome.status = "no_result";
    outcome.message =
        "host exited " + std::to_string(outcome.exitCode) + " without a result";
    return outcome;
  }
  try {
    const json::Value parsed = json::parse(outcome.rawResult);
    const std::string resultSession = json_string_field(parsed, "session_id");
    if (resultSession != sessionId_) {
      outcome.status = "bad_result";
      outcome.message = "host result session_id did not match the request";
      return outcome;
    }
    outcome.status = json_string_field(parsed, "status");
    outcome.message = json_string_field(parsed, "message");
    outcome.hresult = json_string_field(parsed, "hresult");
  } catch (const std::exception& ex) {
    outcome.status = "bad_result";
    outcome.message = std::string("could not parse host result: ") + ex.what();
  }
  if (outcome.status.empty()) {
    outcome.status = "bad_result";
    outcome.message = "host result did not contain a non-empty status";
  } else if (outcome.status == "success" && outcome.exitCode != 0) {
    outcome.status = "bad_result";
    outcome.message = "host result claimed success but the host exit code was " +
                      std::to_string(outcome.exitCode);
  }
  return outcome;
}

}
