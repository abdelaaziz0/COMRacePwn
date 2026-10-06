#pragma once

#include <string>
#include <utility>
#include <vector>

#include "comrace/target_definition.hpp"

namespace comrace {

enum class ArgumentSourceKind {
  Literal,
  BaitPath,
  Content,
  PayloadPath,
  TargetPath,
  MarkerPath,
  Composed
};

struct ResolvedArgument {
  std::string name;
  ArgumentType type = ArgumentType::String;
  std::string value;
  ArgumentSourceKind sourceKind = ArgumentSourceKind::Literal;
};

struct RunConfig {
  TargetDefinition target;
  RunMode mode = RunMode::RedirectWrite;
  bool execute = false;
  bool allowUnsafeTarget = false;
  bool allowWritableTarget = false;
  bool allowPathOverlap = false;
  bool allowUnsafeRetries = false;
  bool releaseBeforeSwap = false;
  bool adaptiveTiming = false;
  bool verbose = false;
  bool probeCom = false;
  bool prepareObservationBait = true;
  int attempts = 1;

  int swapStartOffsetUs = 0;

  int oplockTimeoutMs = 5000;

  int swapWindowMs = 0;

  int invokeTimeoutMs = 0;
  std::string hostArch = "auto";
  std::string workspace;
  std::string targetPath;
  std::string content;
  std::string payloadPath;
  std::string payloadKindOverride;
};

int swap_start_offset_for_attempt(const RunConfig& config, int attempt);

struct RaceTranscript {
  double startToTriggerMs = -1.0;
  double triggerToReleaseMs = -1.0;
  double releaseToBaitGoneMs = -1.0;
  double baitGoneToReparseMs = -1.0;
  double reparseToInvokeReturnMs = -1.0;
  double startToTargetCheckMs = -1.0;
  int swapRetries = 0;
  bool measured = false;
};

enum class AccessTest { NotTested, Allowed, Denied, Inconclusive };

enum class ServerCompletion {
  NotStarted,
  Returned,
  UnknownClientKilled,
  UnknownClientExited,
};

enum class ExecutionState {
  NotApplicable,
  PayloadPlaced,
  TriggeredUnconfirmed,
  ObservedIdentityMismatch,
  Confirmed
};

struct RunResult {
  RunResult() = default;
  RunResult(bool succeeded, int attemptCount, std::string detail)
      : success(succeeded), attempts(attemptCount), message(std::move(detail)) {}
  RunResult(
      bool succeeded,
      int attemptCount,
      std::string detail,
      RaceTranscript timing)
      : success(succeeded),
        attempts(attemptCount),
        message(std::move(detail)),
        transcript(std::move(timing)) {}

  bool success = false;
  int attempts = 0;
  std::string message;
  RaceTranscript transcript;

  std::string callerSid;
  std::string callerIntegrity;
  std::string osBuild;
  AccessTest callerCreateAccess = AccessTest::NotTested;

  AccessTest markerCreateAccess = AccessTest::NotTested;
  std::string fileOwner;
  std::string fileIntegrityLabel;
  unsigned long long fileSize = 0;
  std::string experimentNonce;

  bool triggerObserved = false;
  bool namespaceRedirectInstalled = false;
  bool targetContentMatchedAfterRedirect = false;
  bool placementConfirmed = false;
  ExecutionState executionState = ExecutionState::NotApplicable;
  bool executionObserved = false;
  bool executionIdentityMatch = false;
  bool effectStabilityUnknown = false;
  std::string expectedExecutionIdentity;
  std::string destinationHashStatus = "not_applicable";
  bool markerVerified = false;
  bool markerRecordValid = false;

  std::string codeExecSid;
  std::string codeExecProcessImage;
  std::string codeExecIntegrity;
  std::string codeExecAccount;
  std::string codeExecNonce;
  std::string codeExecThreadSid;
  std::string codeExecThreadIntegrity;
  bool codeExecImpersonating = false;
  bool codeExecMarkerTrusted = false;
  std::string payloadSourceSha256;
  std::string payloadStagedSha256;
  std::string payloadDestinationSha256;
  unsigned long long payloadSourceSize = 0;
  unsigned long long payloadStagedSize = 0;
  unsigned long long payloadDestinationSize = 0;
  bool payloadExactCopy = false;
  bool payloadExactMatch = false;
  bool payloadDevelopmentNonceOverlay = false;
  std::string cleanupStatus = "not_started";

  ServerCompletion serverCompletion = ServerCompletion::NotStarted;
};

struct ResolvedRun {
  std::string workspace;
  std::string targetPath;
  std::string targetDirectory;
  std::string targetFileName;
  std::string safeDirectory;
  std::string baitPath;
  std::string dosDeviceName;
  std::string content;
  std::string payloadPath;
  std::string markerPath;
  std::string markerDirectory;
  std::vector<ResolvedArgument> arguments;
};

bool execution_identity_matches_expected(
    const std::string& expectedIdentity,
    const std::string& identityScope,
    const std::string& processSid,
    const std::string& processAccount,
    bool impersonating,
    const std::string& threadSid);

ResolvedRun resolve_run(const RunConfig& config);
std::string default_workspace_platform();
std::string new_workspace_platform();
std::string os_build_platform();

enum class BuildGateDecision { NoGate, Supported, OutOfRange, Unverifiable };
BuildGateDecision target_build_gate(
    const TargetDefinition& definition,
    const std::string& build);
bool target_build_supported(const TargetDefinition& definition, const std::string& build);
std::string describe_plan(const RunConfig& config);
std::string describe_probe(const RunConfig& config);
std::string describe_observation(const RunConfig& config);
RunResult run_target_action(const RunConfig& config);
RunResult observe_target_action(const RunConfig& config);
std::string run_result_json(
    const RunConfig& config,
    const RunResult& result);

RunResult run_platform(const RunConfig& config);
RunResult probe_platform(const RunConfig& config);
RunResult observe_platform(const RunConfig& config);

std::string inspect_platform(const RunConfig& config);

std::string probe_activation_platform(const RunConfig& config);
std::string sha256_file_platform(const std::string& path);

}
