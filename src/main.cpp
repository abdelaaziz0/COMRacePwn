#include "comrace/cli.hpp"
#include "comrace/discovery.hpp"
#include "comrace/inspect.hpp"
#include "comrace/inventory.hpp"
#include "comrace/json_output.hpp"
#include "comrace/target_definition.hpp"
#include "comrace/runner.hpp"
#include "comrace/target.hpp"
#include "comrace/version.hpp"

#include <exception>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <future>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

comrace::RunConfig make_run_config(
    const comrace::CliOptions& options,
    const comrace::TargetDefinition& target) {
  comrace::RunConfig config;
  config.target = target;
  config.mode = options.mode;
  config.execute = options.execute;
  config.allowUnsafeTarget = options.allowUnsafeTarget;
  config.allowWritableTarget = options.allowWritableTarget;
  config.allowPathOverlap = options.allowPathOverlap;
  config.allowUnsafeRetries = options.allowUnsafeRetries;
  config.releaseBeforeSwap = options.releaseBeforeSwap;
  config.adaptiveTiming = options.adaptiveTiming;
  config.verbose = options.verbose;
  config.probeCom = options.probeCom;
  config.prepareObservationBait = options.prepareObservationBait;
  config.attempts = options.attempts;
  config.swapStartOffsetUs = options.swapStartOffsetUs;
  config.swapWindowMs = options.swapWindowMs;
  config.invokeTimeoutMs = options.invokeTimeoutMs;
  config.hostArch = options.hostArch;
  config.oplockTimeoutMs = options.oplockTimeoutMs;
  config.workspace = options.workspace;
  config.targetPath = options.targetPath;
  config.content = options.content;
  config.payloadPath = options.payloadPath;
  config.payloadKindOverride = options.payloadKind;
  return config;
}

void write_output_file(
    const std::string& path,
    const std::string& content) {
  std::ofstream output(path, std::ios::binary);
  if (!output) {
    throw std::runtime_error("unable to create output file: " + path);
  }
  output.write(
      content.data(),
      static_cast<std::streamsize>(content.size()));
  if (!output) {
    throw std::runtime_error("unable to write output file: " + path);
  }
}

std::string read_input_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("unable to read input file: " + path);
  std::ostringstream content;
  content << input.rdbuf();
  return content.str();
}

std::filesystem::path write_evidence_bundle(
    const comrace::CliOptions& options,
    const comrace::RunConfig& config,
    const comrace::RunResult& result,
    const std::string& resultJson,
    const std::string& definitionSourcePath) {
  const std::filesystem::path root = options.evidenceDirectory.empty()
      ? std::filesystem::path(comrace::resolve_run(config).workspace) / "evidence"
      : std::filesystem::path(options.evidenceDirectory);
  const std::time_t now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &now);
#else
  gmtime_r(&now, &utc);
#endif
  std::ostringstream name;
  name << "session-" << std::put_time(&utc, "%Y%m%d-%H%M%S");
  if (!result.experimentNonce.empty()) {
    name << '-' << result.experimentNonce.substr(0, 8);
  }
  std::filesystem::path session = root / name.str();
  for (unsigned suffix = 1; std::filesystem::exists(session); ++suffix) {
    session = root / (name.str() + "-" + std::to_string(suffix));
  }
  std::filesystem::create_directories(session);

  write_output_file((session / "result.json").string(), resultJson);
  if (!definitionSourcePath.empty()) {
    const std::string definitionText = read_input_file(definitionSourcePath);
    const std::string fileName =
        std::filesystem::path(definitionSourcePath).extension() == ".cwr"
            ? "target.cwr"
            : "target-definition.json";
    write_output_file((session / fileName).string(), definitionText);
  }

  std::ostringstream payloadHashes;
  payloadHashes << "source_sha256="
           << (result.payloadSourceSha256.empty()
                   ? "not_applicable" : result.payloadSourceSha256)
           << "\ndestination_sha256="
           << (result.payloadDestinationSha256.empty()
                   ? "not_applicable" : result.payloadDestinationSha256)
           << "\nexact_match=" << (result.payloadExactMatch ? "true" : "false")
           << "\n";
  write_output_file(
      (session / "payload.sha256").string(), payloadHashes.str());

  std::ostringstream environment;
  environment << "{\n  \"tool_version\":\"" << COMWRITERACE_VERSION
              << "\",\n  \"os_build\":";
  comrace::json_output::write_string(
      environment, result.osBuild.empty() ? "unavailable" : result.osBuild);
  environment << ",\n  \"caller_sid\":";
  comrace::json_output::write_string(
      environment, result.callerSid.empty() ? "unknown" : result.callerSid);
  environment << ",\n  \"caller_integrity\":";
  comrace::json_output::write_string(
      environment,
      result.callerIntegrity.empty() ? "unavailable" : result.callerIntegrity);
  environment << ",\n  \"target_definition_sha256\":";
  comrace::json_output::write_string(
      environment,
      definitionSourcePath.empty()
          ? "unavailable"
          : comrace::sha256_file_platform(definitionSourcePath));
  environment << ",\n  \"clsid\":";
  comrace::json_output::write_string(environment, config.target.clsid);
  environment << ",\n  \"method\":";
  comrace::json_output::write_string(environment, config.target.method);
  environment << ",\n  \"host_architecture_request\":";
  comrace::json_output::write_string(environment, config.hostArch);
  environment << ",\n  \"cleanup_status\":";
  comrace::json_output::write_string(environment, result.cleanupStatus);
  environment << "\n}\n";
  write_output_file((session / "environment.json").string(), environment.str());

  const comrace::RaceTranscript& t = result.transcript;
  std::ostringstream transcript;
  transcript << "{\n  \"start_to_trigger_ms\":" << t.startToTriggerMs
             << ",\n  \"trigger_to_release_ms\":" << t.triggerToReleaseMs
             << ",\n  \"release_to_bait_gone_ms\":" << t.releaseToBaitGoneMs
             << ",\n  \"bait_gone_to_reparse_ms\":" << t.baitGoneToReparseMs
             << ",\n  \"reparse_to_invoke_return_ms\":"
             << t.reparseToInvokeReturnMs
             << ",\n  \"start_to_target_check_ms\":" << t.startToTargetCheckMs
             << ",\n  \"swap_retries\":" << t.swapRetries << "\n}\n";
  write_output_file(
      (session / "race-transcript.json").string(), transcript.str());
  return session;
}

int run_inventory(const comrace::CliOptions& options) {
  const bool includeInproc = !options.outOfProcessOnly;
  auto entries = comrace::collect_com_inventory(includeInproc);

  if (options.probeActivation) {
    const auto lower = [](std::string value) {
      std::transform(value.begin(), value.end(), value.begin(),
                     [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                     });
      return value;
    };
    const std::string include = lower(options.includeFilter);
    const std::string exclude = lower(options.excludeFilter);

    std::vector<std::string> uniqueClsids;
    {
      std::set<std::string> seen;
      for (const comrace::ComInventoryEntry& e : entries) {
        const std::string searchable = lower(e.clsid + " " + e.name + " " +
                                             e.localService + " " + e.serverPath);
        const bool selected =
            (include.empty() || searchable.find(include) != std::string::npos) &&
            (exclude.empty() || searchable.find(exclude) == std::string::npos);
        if (selected && e.serverType != "inproc" && !e.clsid.empty() &&
            seen.insert(e.clsid).second &&
            uniqueClsids.size() < static_cast<std::size_t>(options.maxProbes)) {
          uniqueClsids.push_back(e.clsid);
        }
      }
    }

    struct ActivationByArch {
      std::string x64 = "not_probed";
      std::string x86 = "not_probed";
    };
    std::map<std::string, ActivationByArch> byClsid;
    const std::size_t parallel =
        static_cast<std::size_t>(options.probeParallel);
    for (std::size_t base = 0; base < uniqueClsids.size(); base += parallel) {
      std::vector<std::pair<std::string, std::future<ActivationByArch>>> batch;
      for (std::size_t k = 0; k < parallel && base + k < uniqueClsids.size(); ++k) {
        const std::string clsid = uniqueClsids[base + k];
        const std::string hostArch = options.hostArch;
        const int timeoutMs = options.probeTimeoutMs;
        batch.emplace_back(clsid, std::async(std::launch::async, [clsid, hostArch, timeoutMs]() {
          ActivationByArch result;
          const auto probe = [&](const char* arch) {
            comrace::RunConfig config;
            config.target.clsid = clsid;
            config.target.invoker = "idispatch";
            config.hostArch = arch;
            config.invokeTimeoutMs = timeoutMs;
            return comrace::probe_activation_platform(config);
          };
          if (hostArch == "auto" || hostArch == "x64") result.x64 = probe("x64");
          if (hostArch == "auto" || hostArch == "x86") result.x86 = probe("x86");
          return result;
        }));
      }
      for (auto& [clsid, fut] : batch) {
        byClsid[clsid] = fut.get();
      }
    }

    std::size_t reachable = 0;
    for (comrace::ComInventoryEntry& entry : entries) {
      const auto it = byClsid.find(entry.clsid);
      if (it != byClsid.end()) {
        entry.activationX64 = it->second.x64;
        entry.activationX86 = it->second.x86;
        if (entry.activationX64.rfind("local_server+idispatch", 0) == 0 ||
            entry.activationX86.rfind("local_server+idispatch", 0) == 0) {
          entry.effectiveActivation = "local_server+idispatch";
        } else if (entry.activationX64.rfind("local_server", 0) == 0 ||
                   entry.activationX86.rfind("local_server", 0) == 0) {
          entry.effectiveActivation = "local_server";
        } else {
          entry.effectiveActivation = "not_activatable";
        }
      }
    }
    for (const auto& [clsid, status] : byClsid) {
      (void)clsid;
      if (status.x64.rfind("local_server", 0) == 0 ||
          status.x86.rfind("local_server", 0) == 0) {
        ++reachable;
      }
    }
    std::cout << "[*] activation probe: " << reachable << " / " << byClsid.size()
              << " unique CLSIDs activate out-of-process from this token "
              << "(active x64/x86 CLSID-level probe; not bound to a specific registration)\n";
  }

  const std::string json = comrace::com_inventory_json(entries, includeInproc);
  if (options.outputPath.empty()) {
    std::cout << json;
  } else {
    write_output_file(options.outputPath, json);
    std::cout << "[+] Wrote " << entries.size()
              << " COM registrations to " << options.outputPath << "\n";
  }
  return 0;
}

int run_analysis(const comrace::CliOptions& options) {
  comrace::DiscoveryOptions discovery;
  discovery.controlledRoot = options.controlledRoot;
  discovery.processFilter = options.processFilter;
  discovery.minimumScore = options.minScore;

  if (discovery.controlledRoot.empty() && !options.definitionPath.empty()) {
    const comrace::TargetDefinition definition =
        comrace::load_target_definition_file(options.definitionPath);
    discovery.controlledRoot =
        options.workspace.empty() ? definition.defaultWorkspace : options.workspace;
    if (discovery.controlledRoot.empty()) {
      discovery.controlledRoot = comrace::default_workspace_platform();
    }
  }

  const comrace::DiscoveryReport report =
      comrace::analyze_procmon_csv(options.tracePath, discovery);
  std::cout << comrace::discovery_report_text(report);
  if (!options.outputPath.empty()) {
    write_output_file(
        options.outputPath,
        comrace::discovery_report_json(report));
    std::cout << "\n[+] Wrote JSON report to "
              << options.outputPath << "\n";
  }
  return 0;
}

int run_inspect(const comrace::CliOptions& options) {
  comrace::TargetDefinition definition;
  if (!options.definitionPath.empty()) {
    definition = comrace::load_target_definition_file(options.definitionPath);
  } else {
    definition.name = "inspect";
    definition.method = "inspect";
    definition.invoker = "idispatch";
    definition.vulnerabilityPattern = "double_open_path_write";
  }
  if (!options.clsid.empty()) {
    definition.clsid = options.clsid;
  }
  if (!options.iid.empty()) {
    definition.iid = options.iid;
  }
  if (definition.clsid.empty()) {
    throw std::runtime_error("inspect needs a CLSID (--clsid or a definition with one)");
  }

  comrace::RunConfig config;
  config.target = definition;
  config.hostArch = options.hostArch;

  const std::string raw = comrace::inspect_platform(config);
  comrace::InspectionReport report = comrace::parse_inspection_json(raw);
  comrace::rank_inspection(report);

  std::cout << comrace::inspection_report_text(report, definition.clsid);

  const std::string candidates =
      comrace::inspection_candidates_json(report, definition.clsid, definition.iid);
  if (options.outputPath.empty()) {
    std::cout << "\nCandidate target definitions:\n" << candidates;
  } else {
    write_output_file(options.outputPath, candidates);
    std::cout << "\n[+] Wrote candidate target definitions to " << options.outputPath << "\n";
  }
  return report.typeInfo ? 0 : 2;
}

std::string targets_directory(
    const comrace::CliOptions& options,
    const char* executable) {
  if (!options.targetsDirectory.empty()) {
    return std::filesystem::absolute(options.targetsDirectory).string();
  }
  return (std::filesystem::absolute(executable).parent_path() / "targets").string();
}

const comrace::TargetModule& find_target(
    const std::vector<comrace::TargetModule>& targets,
    const std::string& id) {
  const auto found = std::find_if(
      targets.begin(), targets.end(),
      [&id](const comrace::TargetModule& target) { return target.id == id; });
  if (found == targets.end()) {
    throw std::runtime_error(
        "target module not installed: " + id + " (run 'cwr targets')");
  }
  return *found;
}

const comrace::TargetDefinition* detection_definition(
    const comrace::TargetVariant& variant) {
  for (const comrace::TargetAction action : {
           comrace::TargetAction::Check,
           comrace::TargetAction::Write,
           comrace::TargetAction::ExecDll,
           comrace::TargetAction::ExecScript}) {
    if (const auto* definition =
            comrace::target_action_definition(variant, action)) {
      return definition;
    }
  }
  return nullptr;
}

struct DetectionResult {
  bool reachable = false;
  std::string x64 = "not_probed";
  std::string x86 = "not_probed";
};

DetectionResult detect_variant(
    const comrace::TargetVariant& variant,
    const comrace::CliOptions& options) {
  DetectionResult result;
  const comrace::TargetDefinition* definition = detection_definition(variant);
  if (definition == nullptr) return result;
  const comrace::BuildGateDecision gate =
      comrace::target_build_gate(*definition, comrace::os_build_platform());
  if (gate != comrace::BuildGateDecision::Supported &&
      gate != comrace::BuildGateDecision::NoGate) {
    const bool unverifiable = gate == comrace::BuildGateDecision::Unverifiable;
    result.x64 = unverifiable ? "build_gate_unverifiable" : "outside_build_gate";
    result.x86 = result.x64;
    if (options.verbose) {
      std::cerr << "[*] variant " << variant.id << " skipped: "
                << (unverifiable
                        ? "host build unverifiable against build gate"
                        : "outside target build gate")
                << "\n";
    }
    return result;
  }
  if (definition->invoker == "native_adapter") {
    result.reachable = std::filesystem::is_regular_file(
        std::filesystem::path(definition->nativeAdapter.path));
    result.x64 = result.reachable ? "native_adapter_present" : "native_adapter_missing";
    result.x86 = "not_applicable";
    return result;
  }

  const auto probe = [&](const char* architecture) {
    comrace::RunConfig config;
    config.target = *definition;
    config.hostArch = architecture;
    config.invokeTimeoutMs = options.probeTimeoutMs;
    config.verbose = options.verbose;
    if (options.verbose) {
      std::cerr << "[*] activation probe start: variant=" << variant.id
                << " arch=" << architecture << "\n";
    }
    const std::string status = comrace::probe_activation_platform(config);
    if (options.verbose) {
      std::cerr << "[*] activation probe finish: variant=" << variant.id
                << " arch=" << architecture << " status=" << status << "\n";
    }
    return status;
  };
  if (options.hostArch == "auto" || options.hostArch == "x64") {
    result.x64 = probe("x64");
  }
  if (options.hostArch == "auto" || options.hostArch == "x86") {
    result.x86 = probe("x86");
  }
  const auto methodAvailable = [](const std::string& status) {
    return status.rfind("local_server+idispatch+method", 0) == 0;
  };
  result.reachable =
      methodAvailable(result.x64) || methodAvailable(result.x86);
  return result;
}

void print_capabilities(const comrace::TargetModule& target, const char* indent) {
  std::cout << indent << "arbitrary-write  "
            << (comrace::target_supports(target, comrace::TargetAction::Write)
                    ? "yes" : "no") << "\n";
  std::cout << indent << "dll-exec         "
            << (comrace::target_supports(target, comrace::TargetAction::ExecDll)
                    ? "yes" : "no") << "\n";
  std::cout << indent << "script-exec      "
            << (comrace::target_supports(target, comrace::TargetAction::ExecScript)
                    ? "yes" : "no") << "\n";
}

int run_targets(
    const std::vector<comrace::TargetModule>& targets,
    const std::string& directory) {
  if (targets.empty()) {
    std::cout << "No target modules installed in " << directory << "\n";
    return 0;
  }
  std::cout << "Installed targets (" << targets.size() << ")\n\n";
  for (const auto& target : targets) {
    std::cout << target.id << "  " << target.name << "\n";
    std::cout << "  Capabilities: write="
              << (comrace::target_supports(target, comrace::TargetAction::Write)
                      ? "yes" : "no")
              << " dll-exec="
              << (comrace::target_supports(target, comrace::TargetAction::ExecDll)
                      ? "yes" : "no")
              << " script-exec="
              << (comrace::target_supports(target, comrace::TargetAction::ExecScript)
                      ? "yes" : "no") << "\n";
  }
  return 0;
}

int run_info(
    const comrace::TargetModule& target,
    const comrace::CliOptions& options) {
  std::cout << target.name << "\nTarget: " << target.id << "\n";
  if (!target.description.empty()) std::cout << target.description << "\n";
  std::cout << "\nCapabilities\n";
  print_capabilities(target, "  ");
  std::cout << "\nVariants\n";
  for (const auto& variant : target.variants) {
    if (!options.variantId.empty() && variant.id != options.variantId) continue;
    std::cout << "  " << variant.id << "  " << variant.name << "\n"
              << "    Product: " << variant.product << "\n"
              << "    Version: " << variant.version << "\n"
              << "    Context: " << variant.context << "\n"
              << "    Actions:";
    for (const comrace::TargetAction action : {
             comrace::TargetAction::Check,
             comrace::TargetAction::Write,
             comrace::TargetAction::ExecDll,
             comrace::TargetAction::ExecScript}) {
      if (comrace::target_action_definition(variant, action)) {
        std::cout << ' ' << comrace::to_string(action);
      }
    }
    std::cout << "\n";
  }
  return 0;
}

int run_scan(
    const std::vector<comrace::TargetModule>& targets,
    const comrace::CliOptions& options,
    const std::string& directory) {
  if (targets.empty()) {
    std::cout << "No target modules installed in " << directory << "\n";
    return 0;
  }
  std::size_t reachable = 0;
  for (const auto& target : targets) {
    for (const auto& variant : target.variants) {
      const DetectionResult detection = detect_variant(variant, options);
      if (detection.reachable) {
        ++reachable;
        std::cout << "[+] " << variant.product << ' ' << variant.version << "\n"
                  << "    Target: " << target.id << "\n"
                  << "    Variant: " << variant.id << "\n"
                  << "    Context: " << variant.context << "\n"
                  << "    Reachable: yes (x64=" << detection.x64
                  << ", x86=" << detection.x86 << ")\n"
                  << "    Capabilities:\n";
        print_capabilities(target, "      ");
      }
    }
  }
  if (reachable == 0) std::cout << "No installed target variant was reachable.\n";
  return reachable == 0 ? 2 : 0;
}

comrace::RunMode run_mode_for_action(comrace::TargetAction action) {
  switch (action) {
    case comrace::TargetAction::Check:
      return comrace::RunMode::CheckReopen;
    case comrace::TargetAction::Write:
      return comrace::RunMode::Write;
    case comrace::TargetAction::ExecDll:
      return comrace::RunMode::ExecDll;
    case comrace::TargetAction::ExecScript:
      return comrace::RunMode::ExecScript;
  }
  return comrace::RunMode::CheckReopen;
}

int finish_run(
    const comrace::CliOptions& options,
    const comrace::RunConfig& config,
    const comrace::RunResult& result,
    const std::string& definitionSource) {
  const std::string resultJson = comrace::run_result_json(config, result);
  if (!options.outputPath.empty()) {
    write_output_file(options.outputPath, resultJson);
    std::cout << "[+] Wrote run result JSON to " << options.outputPath << "\n";
  }
  if (config.execute && options.writeEvidence) {
    const std::filesystem::path session =
        write_evidence_bundle(options, config, result, resultJson, definitionSource);
    std::cout << "[+] Wrote evidence session to " << session.string() << "\n";
  }
  return result.success ? 0 : 2;
}

std::vector<comrace::TargetAction> auto_action_preference(
    const comrace::CliOptions& options) {
  if (!options.actionOverride.empty()) {
    if (options.actionOverride == "check") return {comrace::TargetAction::Check};
    if (options.actionOverride == "write") return {comrace::TargetAction::Write};
    if (options.actionOverride == "exec-dll") return {comrace::TargetAction::ExecDll};
    if (options.actionOverride == "exec-script") {
      return {comrace::TargetAction::ExecScript};
    }
    throw std::runtime_error(
        "unknown --action: " + options.actionOverride +
        " (check, write, exec-dll, exec-script)");
  }
  if (options.payloadKind == "dll") return {comrace::TargetAction::ExecDll};
  if (options.payloadKind == "script") return {comrace::TargetAction::ExecScript};
  if (options.payloadKind == "file") return {comrace::TargetAction::Write};
  return {comrace::TargetAction::Check};
}

void validate_auto_action_requirements(
    comrace::TargetAction action,
    const comrace::CliOptions& options) {
  switch (action) {
    case comrace::TargetAction::Write:
      if (options.payloadKind != "file" || options.targetPath.empty()) {
        throw std::runtime_error(
            "auto write requires --file <path> and --dest <approved-path>");
      }
      return;
    case comrace::TargetAction::ExecDll:
      if (options.payloadKind != "dll") {
        throw std::runtime_error("auto exec-dll requires --dll <path>");
      }
      return;
    case comrace::TargetAction::ExecScript:
      if (options.payloadKind != "script") {
        throw std::runtime_error("auto exec-script requires --script <path>");
      }
      return;
    case comrace::TargetAction::Check:
      return;
  }
}

int run_auto(
    const std::vector<comrace::TargetModule>& targets,
    const comrace::CliOptions& options,
    const std::string& directory) {
  const std::vector<comrace::TargetAction> preference =
      auto_action_preference(options);
  for (const comrace::TargetAction action : preference) {
    validate_auto_action_requirements(action, options);
  }
  if (targets.empty()) {
    std::cout << "No target modules installed in " << directory << "\n";
    return 2;
  }
  std::size_t reachableVariants = 0;
  for (const auto& target : targets) {
    for (const auto& variant : target.variants) {
      if (!options.variantId.empty() && variant.id != options.variantId) continue;
      DetectionResult detection;
      try {
        detection = detect_variant(variant, options);
      } catch (const std::exception& error) {
        std::cout << "[-] Detection failed for variant " << variant.id
                  << ": " << error.what() << "\n";
        continue;
      }
      if (!detection.reachable) continue;
      ++reachableVariants;
      std::cout << "[+] Reachable: " << variant.product << ' ' << variant.version
                << " (target " << target.id << ", variant " << variant.id
                << ") x64=" << detection.x64 << " x86=" << detection.x86 << "\n";
      for (const comrace::TargetAction action : preference) {
        const comrace::TargetDefinition* definition =
            comrace::target_action_definition(variant, action);
        if (definition == nullptr) continue;
        std::cout << "[*] Attempting " << comrace::to_string(action)
                  << " via " << target.id << "/" << variant.id << "\n";
        comrace::RunConfig config;
        comrace::RunResult result;
        try {
          config = make_run_config(options, *definition);
          config.mode = run_mode_for_action(action);
          if (options.workspace.empty()) {
            config.workspace = comrace::new_workspace_platform();
          }
          if (options.verbose) {
            std::cout << comrace::describe_plan(config) << "\n";
          }
          result = comrace::run_target_action(config);
        } catch (const std::exception& error) {
          std::cout << "[-] " << error.what() << "\n";
          std::cout << "[*] Continuing to next candidate.\n";
          continue;
        }
        std::cout << (result.success ? "[+] " : "[-] ") << result.message << "\n";
        if (result.attempts > 0) {
          std::cout << "[*] Attempts used: " << result.attempts << "\n";
        }
        const int exitCode =
            finish_run(options, config, result, target.sourcePath);
        if (result.success) {
          std::cout << "[+] Auto succeeded via " << target.id << "/"
                    << variant.id << " (" << comrace::to_string(action) << ")\n";
          return exitCode;
        }
        std::cout << "[*] Continuing to next candidate.\n";
      }
    }
  }
  if (reachableVariants == 0) {
    std::cout << "No installed target variant was reachable.\n";
  } else {
    std::cout << "[-] No reachable variant produced the requested outcome.\n";
  }
  return 2;
}

const comrace::TargetVariant& select_variant(
    const comrace::TargetModule& target,
    comrace::TargetAction action,
    const comrace::CliOptions& options) {
  std::vector<const comrace::TargetVariant*> candidates;
  for (const auto& variant : target.variants) {
    if (!options.variantId.empty() && variant.id != options.variantId) continue;
    if (comrace::target_action_definition(variant, action)) {
      candidates.push_back(&variant);
    }
  }
  if (candidates.empty()) {
    if (!options.variantId.empty()) {
      throw std::runtime_error(
          "variant '" + options.variantId + "' does not implement " +
          comrace::to_string(action));
    }
    throw std::runtime_error(
        "target '" + target.id + "' capability " +
        comrace::to_string(action) + " is unavailable");
  }
  if (candidates.size() == 1 || !options.variantId.empty()) return *candidates[0];

  std::vector<const comrace::TargetVariant*> reachable;
  for (const auto* variant : candidates) {
    if (detect_variant(*variant, options).reachable) reachable.push_back(variant);
  }
  if (reachable.size() == 1) return *reachable[0];
  throw std::runtime_error(
      reachable.empty()
          ? "no variant implementing the requested action was reachable"
          : "multiple variants are reachable; use 'cwr info " + target.id +
                "' and choose --variant <id>");
}

}

int main(int argc, char** argv) {

  std::cout << std::unitbuf;
  try {
    const comrace::CliOptions options = comrace::parse_cli(argc, argv);
    if (options.showHelp) {
      std::cout << comrace::help_text();
      return 0;
    }

    if (options.command == comrace::CliCommand::DevInventory) {
      return run_inventory(options);
    }
    if (options.command == comrace::CliCommand::DevAnalyze) {
      return run_analysis(options);
    }
    if (options.command == comrace::CliCommand::DevInspect) {
      return run_inspect(options);
    }

    std::string definitionSource;
    comrace::RunConfig config;
    if (options.command == comrace::CliCommand::DevRun ||
        options.command == comrace::CliCommand::DevObserve) {
      const comrace::TargetDefinition definition =
          comrace::load_target_definition_file(options.definitionPath);
      config = make_run_config(options, definition);
      definitionSource = options.definitionPath;
      if (options.command == comrace::CliCommand::DevObserve) {
        std::cout << comrace::describe_observation(config) << "\n";
        const comrace::RunResult result = comrace::observe_target_action(config);
        std::cout << (result.success ? "[+] " : "[-] ") << result.message << "\n";
        return result.success ? 0 : 2;
      }
    } else {
      const std::string directory = targets_directory(options, argv[0]);
      const std::vector<comrace::TargetModule> targets =
          comrace::load_target_modules(directory);
      if (options.command == comrace::CliCommand::Targets) {
        return run_targets(targets, directory);
      }
      if (options.command == comrace::CliCommand::Scan) {
        return run_scan(targets, options, directory);
      }
      if (options.command == comrace::CliCommand::Auto) {
        return run_auto(targets, options, directory);
      }
      const comrace::TargetModule& target = find_target(targets, options.targetId);
      if (options.command == comrace::CliCommand::Info) {
        return run_info(target, options);
      }

      const comrace::TargetAction action =
          options.command == comrace::CliCommand::Check
              ? comrace::TargetAction::Check
              : options.command == comrace::CliCommand::Write
                    ? comrace::TargetAction::Write
                    : options.payloadKind == "dll"
                          ? comrace::TargetAction::ExecDll
                          : comrace::TargetAction::ExecScript;
      const comrace::TargetVariant& variant =
          select_variant(target, action, options);
      const comrace::TargetDefinition* definition =
          comrace::target_action_definition(variant, action);
      config = make_run_config(options, *definition);
      definitionSource = target.sourcePath;
      config.mode = run_mode_for_action(action);
      std::cout << "[*] Target: " << target.name << " (" << target.id << ")\n"
                << "[*] Variant: " << variant.name << " (" << variant.id << ")\n"
                << "[*] Action: " << comrace::to_string(action) << "\n";
    }

    const bool developerCommand =
        options.command == comrace::CliCommand::DevRun ||
        options.command == comrace::CliCommand::DevObserve;
    if (developerCommand || options.verbose) {
      std::cout
          << (config.probeCom
                  ? comrace::describe_probe(config)
                  : comrace::describe_plan(config))
          << "\n";
    } else if (!config.execute) {

      (void)comrace::resolve_run(config);
      std::cout << "[*] Dry run validated; no target action was executed.\n";
    }
    const comrace::RunResult result =
        comrace::run_target_action(config);
    std::cout << (result.success ? "[+] " : "[-] ") << result.message << "\n";
    if (result.attempts > 0) {
      std::cout << "[*] Attempts used: " << result.attempts << "\n";
    }
    if (options.command == comrace::CliCommand::Check && result.success &&
        config.execute) {
      std::cout << "[+] COM activation       OK\n"
                << "[+] path influence       OK\n"
                << "[+] re-resolution        confirmed\n"
                << "[+] race reliability     " << result.attempts << "/"
                << config.attempts << " attempts used\n\n"
                << "Target ready.\n";
    }
    return finish_run(options, config, result, definitionSource);
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << "\n";
    return 1;
  }
}
