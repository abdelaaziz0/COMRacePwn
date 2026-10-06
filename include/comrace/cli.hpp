#pragma once

#include "comrace/target_definition.hpp"

#include <string>

namespace comrace {

enum class CliCommand {
  Scan,
  Auto,
  Targets,
  Info,
  Check,
  Write,
  Exec,
  DevRun,
  DevObserve,
  DevAnalyze,
  DevInventory,
  DevInspect
};

struct CliOptions {
  CliCommand command = CliCommand::Targets;
  bool showHelp = false;
  bool execute = true;
  bool allowUnsafeTarget = false;
  bool allowWritableTarget = false;
  bool allowPathOverlap = false;
  bool allowUnsafeRetries = false;
  bool releaseBeforeSwap = false;
  bool adaptiveTiming = false;
  bool verbose = false;
  bool probeCom = false;
  bool outOfProcessOnly = false;
  bool probeActivation = false;
  bool prepareObservationBait = true;
  RunMode mode = RunMode::RedirectWrite;
  int attempts = 1;
  int swapStartOffsetUs = 0;
  int oplockTimeoutMs = 5000;
  int swapWindowMs = 0;
  int invokeTimeoutMs = 0;
  int minScore = 25;
  int probeParallel = 1;
  int probeTimeoutMs = 6000;
  int maxProbes = 100;
  std::string hostArch = "auto";
  std::string clsid;
  std::string iid;
  std::string targetId;
  std::string targetsDirectory;
  std::string variantId;
  std::string actionOverride;
  std::string definitionPath;
  std::string targetPath;
  std::string workspace;
  std::string content;
  std::string payloadPath;
  std::string payloadKind;
  std::string tracePath;
  std::string outputPath;
  std::string controlledRoot;
  std::string processFilter;
  std::string includeFilter;
  std::string excludeFilter;
  std::string evidenceDirectory;
  bool writeEvidence = true;
};

CliOptions parse_cli(int argc, char** argv);
std::string help_text();

}
