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
  bool verbose = false;
  bool probeCom = false;
  bool prepareObservationBait = true;
  int attempts = 1;
  // Calibration offset applied after the oplock is released and before the swap
  // loop starts. Debug/tuning only; the swap is otherwise driven by observing
  // that the bait became deletable, not by a blind delay.
  int swapStartOffsetUs = 0;
  // How long to wait for the race trigger to fire (oplock break / bait-name
  // directory notification). Also spelled --trigger-timeout-ms.
  int oplockTimeoutMs = 5000;
  // How long active_swap keeps racing on "the bait became deletable" after the
  // trigger fires. 0 = auto (min(trigger timeout, 5s)).
  int swapWindowMs = 0;
  // Total budget for the isolated COM call to return before the host is killed.
  // 0 = auto (oplockTimeoutMs + 30s).
  int invokeTimeoutMs = 0;
  std::string hostArch = "auto";  // "auto" | "x64" | "x86" - invocation-host bitness
  std::string workspace;
  std::string targetPath;
  std::string content;
  std::string payloadPath;
  std::string payloadKindOverride;  // empty | file | script
};

// High-resolution timing of the winning attempt (milliseconds; -1 = not measured).
struct RaceTranscript {
  double startToTriggerMs = -1.0;       // host resume -> trigger fired
  double triggerToReleaseMs = -1.0;
  double releaseToBaitGoneMs = -1.0;
  double baitGoneToReparseMs = -1.0;
  double reparseToInvokeReturnMs = -1.0;
  double startToTargetCheckMs = -1.0;   // host resume -> coordinator's post-return check
  int swapRetries = 0;
  bool measured = false;
};

// Tri-state: whether the caller could create files in the target directory
// (the "would this have been a boundary crossing" test).
enum class AccessTest { NotTested, Allowed, Denied, Inconclusive };

// Completion of the privileged server method cannot be inferred merely from
// the lifetime of the isolated client process.
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

  // Filled in by the Windows engine for the structured evidence model.
  std::string callerSid;               // SID of the process that drove the race
  std::string callerIntegrity;
  std::string osBuild;
  AccessTest callerCreateAccess = AccessTest::NotTested;
  // Independently probes the actual execution-marker parent. Target-directory
  // ACLs are not a substitute because target definitions may place markers elsewhere.
  AccessTest markerCreateAccess = AccessTest::NotTested;
  std::string fileOwner;               // owner of the written destination file
  std::string fileIntegrityLabel;      // file's mandatory label ACE, if any
  unsigned long long fileSize = 0;
  std::string experimentNonce;          // coordinator-generated per run
  // Atomic facts from one winning attempt. `success` is not itself evidence:
  // claim generation independently requires this complete chain.
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
  bool markerVerified = false;         // target-specific execution marker matched
  bool markerRecordValid = false;      // required fields + module path validated
  // Actual identity parsed from the target-specific execution marker (written
  // from inside the consuming process), not the expected identity string.
  std::string codeExecSid;
  std::string codeExecProcessImage;
  std::string codeExecIntegrity;
  std::string codeExecAccount;
  std::string codeExecNonce;
  std::string codeExecThreadSid;      // effective thread token if impersonating
  std::string codeExecThreadIntegrity;
  bool codeExecImpersonating = false;
  bool codeExecMarkerTrusted = false; // marker parent not writable by the caller
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

  // Killing or losing the client host does NOT establish completion of an
  // out-of-process privileged server method.
  ServerCompletion serverCompletion = ServerCompletion::NotStarted;
};

struct ResolvedRun {
  std::string workspace;
  std::string targetPath;
  std::string targetDirectory;
  std::string targetFileName;
  std::string safeDirectory;
  std::string baitPath;
  std::string content;
  std::string payloadPath;
  std::string markerPath;
  std::string markerDirectory;
  std::vector<ResolvedArgument> arguments;
};

// Compares the identity recorded by a target-specific execution observation
// with the target module's declared process/effective identity requirement.
bool execution_identity_matches_expected(
    const std::string& expectedIdentity,
    const std::string& identityScope,
    const std::string& processSid,
    const std::string& processAccount,
    bool impersonating,
    const std::string& threadSid);

ResolvedRun resolve_run(const RunConfig& config);
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

// Activate config.target.clsid in the isolated host and return the raw host
// result JSON (contains the type_info object). Throws on host-start failure.
std::string inspect_platform(const RunConfig& config);

// Out-of-process activation check for config.target.clsid via the isolated
// host. Returns a compact status string: "local_server" | "local_server+idispatch"
// | "<hresult/error>". Never throws for a plain activation denial.
std::string probe_activation_platform(const RunConfig& config);
std::string sha256_file_platform(const std::string& path);

}  // namespace comrace
