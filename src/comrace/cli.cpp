#include "comrace/cli.hpp"

#include "comrace/version.hpp"

#include <stdexcept>
#include <string>

namespace comrace {
namespace {

bool is_flag(const std::string& value) { return value.rfind("--", 0) == 0; }

std::string require_value(
    int argc, char** argv, int& index, const std::string& flag) {
  if (index + 1 >= argc || is_flag(argv[index + 1])) {
    throw std::runtime_error("missing value for " + flag);
  }
  return argv[++index];
}

int positive_int(const std::string& value, const std::string& flag) {
  std::size_t consumed = 0;
  const int parsed = std::stoi(value, &consumed, 10);
  if (consumed != value.size() || parsed <= 0) {
    throw std::runtime_error(flag + " must be a positive integer");
  }
  return parsed;
}

int non_negative_int(const std::string& value, const std::string& flag) {
  std::size_t consumed = 0;
  const int parsed = std::stoi(value, &consumed, 10);
  if (consumed != value.size() || parsed < 0) {
    throw std::runtime_error(flag + " must be a non-negative integer");
  }
  return parsed;
}

bool parse_command(const std::string& value, CliOptions& options) {
  if (value == "scan") options.command = CliCommand::Scan;
  else if (value == "targets") options.command = CliCommand::Targets;
  else if (value == "info") options.command = CliCommand::Info;
  else if (value == "check") options.command = CliCommand::Check;
  else if (value == "write") options.command = CliCommand::Write;
  else if (value == "exec") options.command = CliCommand::Exec;
  else if (value == "dev-run") options.command = CliCommand::DevRun;
  else if (value == "dev-observe") options.command = CliCommand::DevObserve;
  else if (value == "dev-analyze") options.command = CliCommand::DevAnalyze;
  else if (value == "dev-inventory") options.command = CliCommand::DevInventory;
  else if (value == "dev-inspect") options.command = CliCommand::DevInspect;
  else return false;
  return true;
}

RunMode parse_mode(const std::string& value) {
  if (value == "redirect-write") return RunMode::RedirectWrite;
  if (value == "write") return RunMode::Write;
  if (value == "exec-dll") return RunMode::ExecDll;
  if (value == "exec-script") return RunMode::ExecScript;
  if (value == "check-reopen") return RunMode::CheckReopen;
  throw std::runtime_error("unknown developer mode: " + value);
}

bool command_needs_target(CliCommand command) {
  return command == CliCommand::Info || command == CliCommand::Check ||
         command == CliCommand::Write || command == CliCommand::Exec;
}

}  // namespace

CliOptions parse_cli(int argc, char** argv) {
  CliOptions options;
  bool commandSeen = false;
  bool payloadSeen = false;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (!is_flag(argument) && !commandSeen) {
      if (!parse_command(argument, options)) {
        throw std::runtime_error("unknown command: " + argument);
      }
      commandSeen = true;
    } else if (!is_flag(argument) && commandSeen &&
               command_needs_target(options.command) &&
               options.targetId.empty()) {
      options.targetId = argument;
    } else if (argument == "-h" || argument == "--help") {
      options.showHelp = true;
    } else if (argument == "--targets-dir") {
      options.targetsDirectory = require_value(argc, argv, index, argument);
    } else if (argument == "--variant") {
      options.variantId = require_value(argc, argv, index, argument);
    } else if (argument == "--definition") {
      options.definitionPath = require_value(argc, argv, index, argument);
    } else if (argument == "--dest") {
      options.targetPath = require_value(argc, argv, index, argument);
    } else if (argument == "--file") {
      if (payloadSeen) {
        throw std::runtime_error("specify exactly one payload input");
      }
      options.payloadPath = require_value(argc, argv, index, argument);
      options.payloadKind = "file";
      payloadSeen = true;
    } else if (argument == "--dll") {
      if (payloadSeen) {
        throw std::runtime_error("specify exactly one payload input");
      }
      options.payloadPath = require_value(argc, argv, index, argument);
      options.payloadKind = "dll";
      payloadSeen = true;
    } else if (argument == "--script") {
      if (payloadSeen) {
        throw std::runtime_error("specify exactly one payload input");
      }
      options.payloadPath = require_value(argc, argv, index, argument);
      options.payloadKind = "script";
      payloadSeen = true;
    } else if (argument == "--workspace") {
      options.workspace = require_value(argc, argv, index, argument);
    } else if (argument == "--content") {
      options.content = require_value(argc, argv, index, argument);
    } else if (argument == "--mode") {
      options.mode = parse_mode(require_value(argc, argv, index, argument));
    } else if (argument == "--attempts") {
      options.attempts = positive_int(require_value(argc, argv, index, argument), argument);
    } else if (argument == "--swap-start-offset-us") {
      options.swapStartOffsetUs =
          non_negative_int(require_value(argc, argv, index, argument), argument);
    } else if (argument == "--trigger-timeout-ms") {
      options.oplockTimeoutMs =
          positive_int(require_value(argc, argv, index, argument), argument);
    } else if (argument == "--swap-window-ms") {
      options.swapWindowMs =
          positive_int(require_value(argc, argv, index, argument), argument);
    } else if (argument == "--invoke-timeout-ms") {
      options.invokeTimeoutMs =
          positive_int(require_value(argc, argv, index, argument), argument);
    } else if (argument == "--host-arch") {
      options.hostArch = require_value(argc, argv, index, argument);
      if (options.hostArch != "auto" && options.hostArch != "x64" &&
          options.hostArch != "x86") {
        throw std::runtime_error("--host-arch must be auto, x64, or x86");
      }
    } else if (argument == "--output") {
      options.outputPath = require_value(argc, argv, index, argument);
    } else if (argument == "--evidence-dir") {
      options.evidenceDirectory = require_value(argc, argv, index, argument);
    } else if (argument == "--dry-run") {
      options.execute = false;
    } else if (argument == "--allow-unsafe-target") {
      options.allowUnsafeTarget = true;
    } else if (argument == "--allow-writable-target") {
      options.allowWritableTarget = true;
    } else if (argument == "--allow-path-overlap") {
      options.allowPathOverlap = true;
    } else if (argument == "--allow-unsafe-retries") {
      options.allowUnsafeRetries = true;
    } else if (argument == "--verbose") {
      options.verbose = true;
    } else if (argument == "--probe-com") {
      options.probeCom = true;
    } else if (argument == "--clsid") {
      options.clsid = require_value(argc, argv, index, argument);
    } else if (argument == "--iid") {
      options.iid = require_value(argc, argv, index, argument);
    } else if (argument == "--trace") {
      options.tracePath = require_value(argc, argv, index, argument);
    } else if (argument == "--controlled-root") {
      options.controlledRoot = require_value(argc, argv, index, argument);
    } else if (argument == "--process") {
      options.processFilter = require_value(argc, argv, index, argument);
    } else if (argument == "--min-score") {
      options.minScore = non_negative_int(
          require_value(argc, argv, index, argument), argument);
      if (options.minScore > 100) {
        throw std::runtime_error("--min-score must be between 0 and 100");
      }
    } else if (argument == "--parallel") {
      options.probeParallel = positive_int(
          require_value(argc, argv, index, argument), argument);
    } else if (argument == "--probe-timeout-ms") {
      options.probeTimeoutMs = positive_int(
          require_value(argc, argv, index, argument), argument);
    } else if (argument == "--max-probes") {
      options.maxProbes = positive_int(
          require_value(argc, argv, index, argument), argument);
    } else if (argument == "--include") {
      options.includeFilter = require_value(argc, argv, index, argument);
    } else if (argument == "--exclude") {
      options.excludeFilter = require_value(argc, argv, index, argument);
    } else if (argument == "--out-of-process-only") {
      options.outOfProcessOnly = true;
    } else if (argument == "--probe-activation") {
      options.probeActivation = true;
    } else if (argument == "--no-observation-bait") {
      options.prepareObservationBait = false;
    } else {
      throw std::runtime_error("unknown argument: " + argument);
    }
  }

  if (!commandSeen && argc > 1 && !options.showHelp) {
    throw std::runtime_error("a command is required");
  }
  if (!options.showHelp && command_needs_target(options.command) &&
      options.targetId.empty()) {
    throw std::runtime_error("this command requires a target id");
  }
  if (!options.showHelp && options.command == CliCommand::Write &&
      (options.payloadKind != "file" || options.targetPath.empty())) {
    throw std::runtime_error("write requires --file <path> and --dest <approved-path>");
  }
  if (!options.showHelp && options.command == CliCommand::Exec &&
      options.payloadKind != "dll" && options.payloadKind != "script") {
    throw std::runtime_error("exec requires exactly one of --dll <path> or --script <path>");
  }
  if (!options.showHelp &&
      (options.command == CliCommand::DevRun ||
       options.command == CliCommand::DevObserve) &&
      options.definitionPath.empty()) {
    throw std::runtime_error("developer command requires --definition <file.json>");
  }
  if (!options.showHelp && options.command == CliCommand::DevAnalyze &&
      options.tracePath.empty()) {
    throw std::runtime_error("dev-analyze requires --trace <procmon.csv>");
  }
  if (!options.showHelp && options.command == CliCommand::DevInspect &&
      options.clsid.empty() && options.definitionPath.empty()) {
    throw std::runtime_error("dev-inspect requires --clsid or --definition");
  }
  return options;
}

std::string help_text() {
  return std::string("CWR ") + COMWRITERACE_VERSION + "\n\n" +
      "COM filesystem-race target framework.\n\n"
      "Usage:\n"
      "  cwr scan [--targets-dir <dir>]\n"
      "  cwr targets [--targets-dir <dir>]\n"
      "  cwr info <target> [--variant <id>]\n"
      "  cwr check <target> [--variant <id>] [--dry-run]\n"
      "  cwr write <target> --file <path> --dest <approved-path> [--dry-run]\n"
      "  cwr exec <target> (--dll <path> | --script <path>) [--dry-run]\n\n"
      "Commands:\n"
      "  scan       Detect installed and reachable target variants. Active COM probe.\n"
      "  targets    List installed target modules and capabilities.\n"
      "  info       Describe a target's capabilities and variants.\n"
      "  check      Validate activation and controlled path re-resolution.\n"
      "  write      Place exact file bytes at an explicitly approved destination.\n"
      "  exec       Execute a DLL or script using a capability implemented by the target.\n\n"
      "Common options:\n"
      "  --targets-dir <dir>          Module directory. Default: targets beside cwr.exe.\n"
      "  --variant <id>               Expert override when automatic selection is ambiguous.\n"
      "  --dest <path>                Required for write; expert override for exec.\n"
      "  --attempts <n>               Race attempts. Default: 1; target safety policy applies.\n"
      "  --host-arch <auto|x64|x86>  Invocation host bitness. Default: auto.\n"
      "  --output <file>              Write structured result JSON.\n"
      "  --evidence-dir <dir>         Override the evidence-session directory.\n"
      "  --dry-run                    Validate the action without executing it.\n"
      "  --verbose                    Show attempt-level diagnostics.\n"
      "  -h, --help                   Show this help.\n";
}

}  // namespace comrace
