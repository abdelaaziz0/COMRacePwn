#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace comrace {

enum class PrivilegedOperation {
  FileWrite
};

enum class RaceTrigger {
  OplockOnSource,   // modern oplock on a pre-created bait file (default)
  DirectoryWatch    // ReadDirectoryChangesW on the bait's parent (no pre-created bait)
};

enum class SwapPrimitive {
  JunctionRedirect
};

enum class ArgumentType {
  String,
  Path,
  Int32,
  UInt32,
  Int64,
  Boolean
};

enum class ExecutionKind {
  None,
  DllLoad,
  Script
};

enum class RunMode {
  RedirectWrite,
  Write,
  ExecDll,
  ExecScript,
  CheckReopen
};

struct MethodArgument {
  std::string name;
  ArgumentType type = ArgumentType::String;
  std::string value;
  bool attackerControlled = false;
};

struct ExecutionStrategy {
  ExecutionKind kind = ExecutionKind::None;
  std::string targetPath;
  std::string payloadPath;
  std::string trigger;
  std::string expectedIdentity;
  std::string markerPath;
  std::string markerContains;
  std::string identityScope = "process";  // process | effective
  std::size_t markerTimeoutMs = 5000;
  bool markerRequired = false;
  // Development fixture only: appends the experiment nonce to a copied PE so
  // the bundled lab marker DLL can bind its execution record to this run.
  // Production/operator payloads remain byte-for-byte immutable by default.
  bool developmentNonceOverlay = false;
};

struct NativeAdapterDefinition {
  std::string path;
  std::string entrypoint = "ComWriteRaceInvokeV1";
};

struct PayloadSpec {
  std::string type = "content";  // content | file | script
  std::string source;
  bool preserveBytes = true;
};

struct TargetDefinition {
  std::string name;
  std::string description;
  std::string clsid;
  std::string iid;
  std::string invoker = "idispatch";
  std::string method;
  std::string vulnerabilityPattern = "double_open_path_write";
  PrivilegedOperation privilegedOperation = PrivilegedOperation::FileWrite;
  RaceTrigger raceTrigger = RaceTrigger::OplockOnSource;
  // Whether the harness pre-creates the bait file. False (implied by
  // directory_watch) for targets that expect the output path not to exist yet.
  bool baitPrecreated = true;
  SwapPrimitive swapPrimitive = SwapPrimitive::JunctionRedirect;
  std::size_t attackerControlledPathArg = 0;
  std::string defaultWorkspace = "C:\\Users\\Public\\ComWriteRace";
  std::string defaultTarget;
  std::string content = "CWR controlled content";
  bool retrySafe = false;
  std::size_t maxRecommendedAttempts = 1;
  std::string sideEffectLevel = "unknown";
  std::string operationNotes;
  std::size_t effectObservationMs = 0;
  bool targetRequired = false;  // compatibility default; production templates set true
  PayloadSpec payload;
  ExecutionStrategy execution;
  NativeAdapterDefinition nativeAdapter;
  std::vector<MethodArgument> methodArgs;
};

TargetDefinition load_target_definition_file(const std::string& path);
void validate_target_definition(const TargetDefinition& definition);

std::string to_string(PrivilegedOperation value);
std::string to_string(RaceTrigger value);
std::string to_string(SwapPrimitive value);
std::string to_string(ArgumentType value);
std::string to_string(ExecutionKind value);

PrivilegedOperation parse_privileged_operation(const std::string& value);
RaceTrigger parse_race_trigger(const std::string& value);
SwapPrimitive parse_swap_primitive(const std::string& value);
ArgumentType parse_argument_type(const std::string& value);
ExecutionKind parse_execution_kind(const std::string& value);

}  // namespace comrace
