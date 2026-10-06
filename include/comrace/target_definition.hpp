#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace comrace {

enum class PrivilegedOperation {
  FileWrite
};

enum class RaceTrigger {
  OplockOnSource,
  DirectoryWatch,
  WnfState
};

enum class SwapPrimitive {
  JunctionRedirect,
  ObjectManagerSymlink,
  DosDeviceSymlink
};

enum class BaitKind {
  File,
  CloudPlaceholder
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
  std::string identityScope = "process";
  std::size_t markerTimeoutMs = 5000;
  bool markerRequired = false;

  bool developmentNonceOverlay = false;
};

struct NativeAdapterDefinition {
  std::string path;
  std::string entrypoint = "ComWriteRaceInvokeV1";
};

struct PayloadSpec {
  std::string type = "content";
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

  bool baitPrecreated = true;
  BaitKind baitKind = BaitKind::File;
  std::string triggerWnfState;
  SwapPrimitive swapPrimitive = SwapPrimitive::JunctionRedirect;
  std::size_t attackerControlledPathArg = 0;

  std::string defaultWorkspace;
  std::string defaultTarget;
  std::string content = "CWR controlled content";
  bool retrySafe = false;
  std::size_t maxRecommendedAttempts = 1;

  std::size_t minOsBuild = 0;
  std::size_t maxOsBuild = 0;
  std::size_t minOsRevision = 0;
  std::size_t maxOsRevision = 0;
  std::string sideEffectLevel = "unknown";
  std::string operationNotes;
  std::size_t effectObservationMs = 0;
  bool targetRequired = false;
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
std::string to_string(BaitKind value);

PrivilegedOperation parse_privileged_operation(const std::string& value);
RaceTrigger parse_race_trigger(const std::string& value);
SwapPrimitive parse_swap_primitive(const std::string& value);
ArgumentType parse_argument_type(const std::string& value);
ExecutionKind parse_execution_kind(const std::string& value);
BaitKind parse_bait_kind(const std::string& value);

}
