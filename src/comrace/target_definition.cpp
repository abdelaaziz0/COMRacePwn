#include "comrace/target_definition.hpp"

#include "comrace/json.hpp"
#include "comrace/target_definition_parse.hpp"

#include <cmath>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

namespace comrace {
namespace {

std::string read_text_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("unable to open target definition: " + path);
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

const json::Value* find_field(const json::Value::Object& object, const std::string& key) {
  const auto it = object.find(key);
  if (it == object.end()) {
    return nullptr;
  }
  return &it->second;
}

std::string validate_target_definition_string(std::string value, const std::string& fieldName) {
  if (value.find('\0') != std::string::npos) {
    throw std::runtime_error("target-definition field contains an embedded NUL: " + fieldName);
  }
  return value;
}

std::string required_string(const json::Value::Object& object, const std::string& key) {
  const json::Value* value = find_field(object, key);
  if (value == nullptr) {
    throw std::runtime_error("target definition is missing required field: " + key);
  }
  return validate_target_definition_string(value->as_string(), key);
}

std::string optional_string(
    const json::Value::Object& object,
    const std::string& key,
    const std::string& fallback) {
  const json::Value* value = find_field(object, key);
  return value == nullptr ? fallback : validate_target_definition_string(value->as_string(), key);
}

void reject_unknown_fields(
    const json::Value::Object& object,
    std::initializer_list<const char*> allowed,
    const std::string& context) {
  std::set<std::string> names;
  for (const char* name : allowed) {
    names.emplace(name);
  }
  for (const auto& field : object) {
    if (names.count(field.first) == 0) {
      throw std::runtime_error(
          "unsupported " + context + " field: " + field.first);
    }
  }
}

std::string optional_nullable_string(
    const json::Value::Object& object,
    const std::string& key,
    const std::string& fallback) {
  const json::Value* value = find_field(object, key);
  if (value == nullptr) return fallback;
  if (value->is_null()) return {};
  return validate_target_definition_string(value->as_string(), key);
}

bool optional_bool(const json::Value::Object& object, const std::string& key, bool fallback) {
  const json::Value* value = find_field(object, key);
  return value == nullptr ? fallback : value->as_bool();
}

std::size_t number_to_size(double value, const std::string& fieldName) {
  if (value < 0 || std::floor(value) != value ||
      static_cast<long double>(value) >
          static_cast<long double>(std::numeric_limits<std::size_t>::max())) {
    throw std::runtime_error("target-definition field must be a non-negative integer: " + fieldName);
  }
  return static_cast<std::size_t>(value);
}

std::size_t optional_size(
    const json::Value::Object& object,
    const std::string& key,
    std::size_t fallback) {
  const json::Value* value = find_field(object, key);
  return value == nullptr ? fallback : number_to_size(value->as_number(), key);
}

std::string value_to_definition_string(const json::Value& value) {
  if (value.is_string()) {
    return validate_target_definition_string(value.as_string(), "method_args[].value");
  }
  if (value.is_bool()) {
    return value.as_bool() ? "true" : "false";
  }
  if (value.is_number()) {
    const double number = value.as_number();
    if (std::floor(number) == number) {
      constexpr double kMaxExactJsonInteger = 9007199254740991.0;
      if (number < -kMaxExactJsonInteger || number > kMaxExactJsonInteger) {
        throw std::runtime_error(
            "integer method argument exceeds the parser's exact numeric range; encode it as a string");
      }
      std::ostringstream out;
      out << std::fixed << std::setprecision(0) << number;
      return out.str();
    }
    std::ostringstream out;
    out << number;
    return out.str();
  }
  throw std::runtime_error("method argument value must be a string, boolean, or number");
}

std::vector<MethodArgument> parse_method_args(const json::Value::Object& object) {
  const json::Value* argsValue = find_field(object, "method_args");
  if (argsValue == nullptr) {
    return {};
  }

  std::vector<MethodArgument> args;
  const auto& array = argsValue->as_array();
  for (std::size_t i = 0; i < array.size(); ++i) {
    const auto& argObject = array[i].as_object();
    reject_unknown_fields(
        argObject,
        {"name", "type", "value", "attacker_controlled"},
        "method argument");
    MethodArgument arg;
    arg.name = optional_string(argObject, "name", "arg" + std::to_string(i));
    arg.type = parse_argument_type(optional_string(argObject, "type", "string"));
    const json::Value* rawValue = find_field(argObject, "value");
    if (rawValue != nullptr) {
      arg.value = value_to_definition_string(*rawValue);
    }
    arg.attackerControlled = optional_bool(argObject, "attacker_controlled", false);
    args.push_back(std::move(arg));
  }
  return args;
}

ExecutionStrategy parse_execution(const json::Value::Object& object) {
  ExecutionStrategy execution;
  const json::Value* executionValue = find_field(object, "execution");
  if (executionValue == nullptr || executionValue->is_null()) {
    return execution;
  }

  const auto& item = executionValue->as_object();
  reject_unknown_fields(
      item,
      {"kind", "target_path", "payload_path", "trigger",
       "expected_identity", "marker_path", "marker_contains",
       "identity_scope", "marker_timeout_ms", "marker_required",
       "development_nonce_overlay"},
      "execution");
  execution.kind = parse_execution_kind(optional_string(item, "kind", "none"));
  execution.targetPath = optional_string(item, "target_path", "");
  execution.payloadPath = optional_string(item, "payload_path", "");
  execution.trigger = optional_string(item, "trigger", "");
  execution.expectedIdentity = optional_string(item, "expected_identity", "");
  execution.markerPath = optional_string(item, "marker_path", "");
  execution.markerContains = optional_string(item, "marker_contains", "");
  execution.identityScope = optional_string(item, "identity_scope", "process");
  execution.markerTimeoutMs =
      optional_size(item, "marker_timeout_ms", execution.markerTimeoutMs);
  execution.markerRequired = optional_bool(item, "marker_required", false);
  execution.developmentNonceOverlay =
      optional_bool(item, "development_nonce_overlay", false);
  return execution;
}

void parse_operation_policy(
    const json::Value::Object& object,
    TargetDefinition& definition) {
  const json::Value* operationValue = find_field(object, "operation");
  if (operationValue == nullptr || operationValue->is_null()) {
    return;
  }
  const auto& operation = operationValue->as_object();
  reject_unknown_fields(
      operation,
      {"retry_safe", "max_recommended_attempts", "side_effect_level",
       "notes", "effect_observation_ms"},
      "operation");
  definition.retrySafe = optional_bool(operation, "retry_safe", definition.retrySafe);
  definition.maxRecommendedAttempts = optional_size(
      operation, "max_recommended_attempts", definition.maxRecommendedAttempts);
  definition.sideEffectLevel = optional_string(
      operation, "side_effect_level", definition.sideEffectLevel);
  definition.operationNotes = optional_string(operation, "notes", "");
  definition.effectObservationMs = optional_size(
      operation, "effect_observation_ms", definition.effectObservationMs);
}

NativeAdapterDefinition parse_native_adapter(const json::Value::Object& object) {
  NativeAdapterDefinition adapter;
  const json::Value* adapterValue = find_field(object, "native_adapter");
  if (adapterValue == nullptr || adapterValue->is_null()) {
    return adapter;
  }

  const auto& adapterObject = adapterValue->as_object();
  reject_unknown_fields(
      adapterObject, {"path", "entrypoint"}, "native_adapter");
  adapter.path = optional_string(adapterObject, "path", "");
  adapter.entrypoint =
      optional_string(adapterObject, "entrypoint", adapter.entrypoint);
  return adapter;
}

PayloadSpec parse_payload(const json::Value::Object& object) {
  PayloadSpec payload;
  const json::Value* value = find_field(object, "payload");
  if (value == nullptr || value->is_null()) return payload;
  const auto& item = value->as_object();
  reject_unknown_fields(
      item, {"type", "source", "preserve_bytes"}, "payload");
  payload.type = optional_string(item, "type", payload.type);
  payload.source = optional_nullable_string(item, "source", "");
  payload.preserveBytes = optional_bool(item, "preserve_bytes", true);
  return payload;
}

void parse_verification(
    const json::Value::Object& object,
    ExecutionStrategy& execution) {
  const json::Value* value = find_field(object, "verification");
  if (value == nullptr || value->is_null()) return;
  const auto& verification = value->as_object();
  reject_unknown_fields(
      verification,
      {"type", "marker_path", "marker_contains", "timeout_ms", "required"},
      "verification");
  const std::string type = optional_string(verification, "type", "optional");
  if (type != "optional" && type != "none" && type != "passive_marker") {
    throw std::runtime_error("unsupported verification.type: " + type);
  }
  if (type == "none") return;
  execution.markerPath = optional_string(
      verification, "marker_path", execution.markerPath);
  execution.markerContains = optional_string(
      verification, "marker_contains", execution.markerContains);
  execution.markerTimeoutMs = optional_size(
      verification, "timeout_ms", execution.markerTimeoutMs);
  execution.markerRequired = optional_bool(
      verification, "required", type == "passive_marker");
}

std::size_t resolve_attacker_path_index(
    const json::Value::Object& object,
    const std::vector<MethodArgument>& args) {
  const json::Value* explicitIndex = find_field(object, "attacker_controlled_path_arg");
  if (explicitIndex != nullptr) {
    return number_to_size(explicitIndex->as_number(), "attacker_controlled_path_arg");
  }

  for (std::size_t i = 0; i < args.size(); ++i) {
    if (args[i].attackerControlled) {
      return i;
    }
  }
  return 0;
}

}

std::string to_string(PrivilegedOperation value) {
  switch (value) {
    case PrivilegedOperation::FileWrite:
      return "file_write";
  }
  return "unknown";
}

std::string to_string(RaceTrigger value) {
  switch (value) {
    case RaceTrigger::OplockOnSource:
      return "oplock_on_source";
    case RaceTrigger::DirectoryWatch:
      return "directory_watch";
    case RaceTrigger::WnfState:
      return "wnf_state";
  }
  return "unknown";
}

std::string to_string(BaitKind value) {
  switch (value) {
    case BaitKind::File:
      return "file";
    case BaitKind::CloudPlaceholder:
      return "cloud_placeholder";
  }
  return "unknown";
}

std::string to_string(SwapPrimitive value) {
  switch (value) {
    case SwapPrimitive::JunctionRedirect:
      return "junction_redirect";
    case SwapPrimitive::ObjectManagerSymlink:
      return "om_symlink";
    case SwapPrimitive::DosDeviceSymlink:
      return "dos_device_symlink";
  }
  return "unknown";
}

std::string to_string(ArgumentType value) {
  switch (value) {
    case ArgumentType::String:
      return "string";
    case ArgumentType::Path:
      return "path";
    case ArgumentType::Int32:
      return "int32";
    case ArgumentType::UInt32:
      return "uint32";
    case ArgumentType::Int64:
      return "int64";
    case ArgumentType::Boolean:
      return "bool";
  }
  return "unknown";
}

std::string to_string(ExecutionKind value) {
  switch (value) {
    case ExecutionKind::None:
      return "none";
    case ExecutionKind::DllLoad:
      return "dll_load";
    case ExecutionKind::Script:
      return "script";
  }
  return "unknown";
}

PrivilegedOperation parse_privileged_operation(const std::string& value) {
  if (value == "file_write") {
    return PrivilegedOperation::FileWrite;
  }
  throw std::runtime_error("unsupported privileged_operation for ComWriteRace: " + value);
}

RaceTrigger parse_race_trigger(const std::string& value) {
  if (value == "oplock_on_source") {
    return RaceTrigger::OplockOnSource;
  }
  if (value == "directory_watch") {
    return RaceTrigger::DirectoryWatch;
  }
  if (value == "wnf_state") {
    return RaceTrigger::WnfState;
  }
  throw std::runtime_error("unsupported race_trigger for ComWriteRace: " + value);
}

SwapPrimitive parse_swap_primitive(const std::string& value) {
  if (value == "junction_redirect") {
    return SwapPrimitive::JunctionRedirect;
  }
  if (value == "om_symlink") {
    return SwapPrimitive::ObjectManagerSymlink;
  }
  if (value == "dos_device_symlink") {
    return SwapPrimitive::DosDeviceSymlink;
  }
  throw std::runtime_error("unsupported swap_primitive for ComWriteRace: " + value);
}

BaitKind parse_bait_kind(const std::string& value) {
  if (value == "file") {
    return BaitKind::File;
  }
  if (value == "cloud_placeholder") {
    return BaitKind::CloudPlaceholder;
  }
  throw std::runtime_error("unsupported bait_kind for ComWriteRace: " + value);
}

ArgumentType parse_argument_type(const std::string& value) {
  if (value == "string") {
    return ArgumentType::String;
  }
  if (value == "path") {
    return ArgumentType::Path;
  }
  if (value == "int32") {
    return ArgumentType::Int32;
  }
  if (value == "uint32") {
    return ArgumentType::UInt32;
  }
  if (value == "int64") {
    return ArgumentType::Int64;
  }
  if (value == "bool" || value == "boolean") {
    return ArgumentType::Boolean;
  }
  throw std::runtime_error("unknown method argument type: " + value);
}

ExecutionKind parse_execution_kind(const std::string& value) {
  if (value == "none") {
    return ExecutionKind::None;
  }
  if (value == "dll_load") {
    return ExecutionKind::DllLoad;
  }
  if (value == "script") {
    return ExecutionKind::Script;
  }
  throw std::runtime_error("unsupported execution strategy for ComWriteRace: " + value);
}

TargetDefinition parse_target_definition_object(
    const json::Value::Object& root,
    const std::filesystem::path& baseDirectory) {
  reject_unknown_fields(
      root,
       {"name", "description", "invoker", "clsid", "iid", "method",
        "vulnerability_pattern", "privileged_operation", "race_trigger",
        "bait_precreated", "bait_kind", "trigger_wnf_state", "swap_primitive",
        "default_workspace",
        "default_target", "target_required", "content", "operation",
        "execution", "payload", "verification", "native_adapter",
        "method_args", "attacker_controlled_path_arg",
        "min_os_build", "max_os_build", "min_os_revision", "max_os_revision"},
      "target definition");
  TargetDefinition definition;
  definition.name = required_string(root, "name");
  definition.description = optional_string(root, "description", "");
  definition.invoker = optional_string(root, "invoker", "idispatch");
  definition.clsid = optional_string(root, "clsid", "");
  definition.iid = optional_string(root, "iid", "");
  definition.method = required_string(root, "method");
  definition.vulnerabilityPattern = optional_string(root, "vulnerability_pattern", definition.vulnerabilityPattern);
  definition.privilegedOperation = parse_privileged_operation(
      optional_string(root, "privileged_operation", to_string(definition.privilegedOperation)));
  definition.raceTrigger = parse_race_trigger(
      optional_string(root, "race_trigger", to_string(definition.raceTrigger)));
  definition.baitPrecreated = optional_bool(root, "bait_precreated",
      definition.raceTrigger != RaceTrigger::DirectoryWatch);
  definition.baitKind = parse_bait_kind(
      optional_string(root, "bait_kind", to_string(definition.baitKind)));
  definition.triggerWnfState =
      optional_string(root, "trigger_wnf_state", definition.triggerWnfState);
  definition.swapPrimitive = parse_swap_primitive(
      optional_string(root, "swap_primitive", to_string(definition.swapPrimitive)));
  definition.defaultWorkspace = optional_string(root, "default_workspace", definition.defaultWorkspace);
  definition.defaultTarget = optional_nullable_string(root, "default_target", definition.defaultTarget);
  definition.targetRequired = optional_bool(root, "target_required", definition.targetRequired);
  definition.content = optional_string(root, "content", definition.content);
  definition.minOsBuild = optional_size(root, "min_os_build", definition.minOsBuild);
  definition.maxOsBuild = optional_size(root, "max_os_build", definition.maxOsBuild);
  definition.minOsRevision = optional_size(root, "min_os_revision", definition.minOsRevision);
  definition.maxOsRevision = optional_size(root, "max_os_revision", definition.maxOsRevision);
  parse_operation_policy(root, definition);
  definition.execution = parse_execution(root);
  definition.payload = parse_payload(root);
  parse_verification(root, definition.execution);
  if (definition.payload.source.empty()) {
    definition.payload.source = definition.execution.payloadPath;
  }
  if (definition.execution.payloadPath.empty()) {
    definition.execution.payloadPath = definition.payload.source;
  }
  if (definition.payload.type == "content" &&
      definition.execution.kind != ExecutionKind::None) {
    definition.payload.type =
        definition.execution.kind == ExecutionKind::Script ? "script" : "file";
  }
  definition.nativeAdapter = parse_native_adapter(root);
  if (!definition.nativeAdapter.path.empty()) {

    std::string portableAdapter = definition.nativeAdapter.path;
    for (char& value : portableAdapter) {
      if (value == '\\' || value == '/') {
        value = std::filesystem::path::preferred_separator;
      }
    }
    std::filesystem::path adapter(portableAdapter);
    if (adapter.is_relative()) {
      adapter = std::filesystem::absolute(
          baseDirectory / adapter);
    }
    definition.nativeAdapter.path = adapter.lexically_normal().string();
  }
  definition.methodArgs = parse_method_args(root);
  definition.attackerControlledPathArg = resolve_attacker_path_index(root, definition.methodArgs);

  validate_target_definition(definition);
  return definition;
}

TargetDefinition load_target_definition_file(const std::string& path) {
  const std::string text = read_text_file(path);
  const auto root = json::parse(text).as_object();
  return parse_target_definition_object(
      root, std::filesystem::absolute(path).parent_path());
}

void validate_target_definition(const TargetDefinition& definition) {
  if (definition.name.empty()) {
    throw std::runtime_error("target definition name cannot be empty");
  }
  if (definition.method.empty()) {
    throw std::runtime_error("target definition method cannot be empty");
  }
  if (definition.vulnerabilityPattern != "double_open_path_write") {
    throw std::runtime_error(
        "ComWriteRace only supports vulnerability_pattern \"double_open_path_write\"");
  }
  if (definition.invoker != "idispatch" && definition.invoker != "native_adapter") {
    throw std::runtime_error(
        "ComWriteRace supports invoker \"idispatch\" or \"native_adapter\"");
  }
  if (definition.invoker == "idispatch" && definition.clsid.empty()) {
    throw std::runtime_error("idispatch target definition clsid cannot be empty");
  }
  if (definition.invoker == "native_adapter") {
    if (definition.nativeAdapter.path.empty()) {
      throw std::runtime_error(
          "native_adapter invoker requires native_adapter.path");
    }
    if (definition.nativeAdapter.entrypoint.empty()) {
      throw std::runtime_error(
          "native_adapter invoker requires native_adapter.entrypoint");
    }
  }
  if (definition.methodArgs.empty()) {
    throw std::runtime_error("target definition must define method_args");
  }
  if (definition.attackerControlledPathArg >= definition.methodArgs.size()) {
    throw std::runtime_error("attacker_controlled_path_arg is outside method_args");
  }
  if (definition.methodArgs[definition.attackerControlledPathArg].type != ArgumentType::Path) {
    throw std::runtime_error("attacker-controlled argument should use type \"path\"");
  }
  if (definition.maxRecommendedAttempts == 0) {
    throw std::runtime_error("operation.max_recommended_attempts must be at least 1");
  }
  if (definition.minOsBuild != 0 && definition.maxOsBuild != 0 &&
      definition.minOsBuild > definition.maxOsBuild) {
    throw std::runtime_error("min_os_build must not exceed max_os_build");
  }
  if (definition.minOsBuild != 0 && definition.minOsBuild == definition.maxOsBuild &&
      definition.minOsRevision != 0 && definition.maxOsRevision != 0 &&
      definition.minOsRevision > definition.maxOsRevision) {
    throw std::runtime_error(
        "min_os_revision must not exceed max_os_revision");
  }
  if (definition.minOsRevision != 0 && definition.minOsBuild == 0) {
    throw std::runtime_error("min_os_revision requires min_os_build");
  }
  if (definition.maxOsRevision != 0 && definition.maxOsBuild == 0) {
    throw std::runtime_error("max_os_revision requires max_os_build");
  }
  if (definition.effectObservationMs > 600000) {
    throw std::runtime_error("operation.effect_observation_ms cannot exceed 600000");
  }
  if (definition.raceTrigger == RaceTrigger::OplockOnSource &&
      !definition.baitPrecreated) {
    throw std::runtime_error(
        "oplock_on_source requires bait_precreated=true");
  }
  if (definition.swapPrimitive == SwapPrimitive::ObjectManagerSymlink &&
      definition.raceTrigger != RaceTrigger::OplockOnSource) {
    throw std::runtime_error(
        "om_symlink swap primitive requires race_trigger \"oplock_on_source\"");
  }
  if (definition.baitKind == BaitKind::CloudPlaceholder &&
      definition.raceTrigger != RaceTrigger::OplockOnSource) {
    throw std::runtime_error(
        "bait_kind cloud_placeholder requires race_trigger \"oplock_on_source\"");
  }
  if (definition.baitKind == BaitKind::CloudPlaceholder &&
      definition.swapPrimitive == SwapPrimitive::ObjectManagerSymlink) {
    throw std::runtime_error(
        "bait_kind cloud_placeholder is incompatible with the om_symlink swap");
  }
  if (definition.raceTrigger == RaceTrigger::WnfState) {
    if (definition.triggerWnfState.size() != 16) {
      throw std::runtime_error(
          "race_trigger wnf_state requires trigger_wnf_state as 16 hex chars");
    }
    for (const char c : definition.triggerWnfState) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        throw std::runtime_error(
            "trigger_wnf_state must be 16 hex chars: " + definition.triggerWnfState);
      }
    }
  }
  if (definition.raceTrigger == RaceTrigger::DirectoryWatch &&
      definition.baitPrecreated) {
    throw std::runtime_error(
        "directory_watch requires bait_precreated=false");
  }
  if (definition.payload.type != "content" &&
      definition.payload.type != "file" &&
      definition.payload.type != "script") {
    throw std::runtime_error("payload.type must be content, file, or script");
  }
  if (!definition.payload.preserveBytes &&
      !definition.execution.developmentNonceOverlay) {
    throw std::runtime_error(
        "operator payloads must set payload.preserve_bytes to true");
  }
  if (definition.execution.kind == ExecutionKind::DllLoad ||
      definition.execution.kind == ExecutionKind::Script) {
    if (definition.execution.identityScope != "process" &&
        definition.execution.identityScope != "effective") {
      throw std::runtime_error(
          "execution.identity_scope must be process or effective");
    }
    if (definition.execution.targetPath.empty() && !definition.targetRequired) {
      throw std::runtime_error("execution strategy requires a target path or target_required");
    }
    if (definition.execution.trigger.empty()) {
      throw std::runtime_error("execution strategy requires a trigger");
    }
    if (definition.execution.expectedIdentity.empty()) {
      throw std::runtime_error("execution strategy requires expected_identity");
    }
    if (definition.execution.kind == ExecutionKind::DllLoad &&
        definition.payload.type == "script") {
      throw std::runtime_error("DLL execution requires a PE/file payload, not a script");
    }
    if (definition.execution.kind == ExecutionKind::Script &&
        definition.payload.type != "script") {
      throw std::runtime_error("script execution requires payload.type script");
    }
    if (definition.execution.markerRequired) {
      if (definition.execution.markerPath.empty()) {
        throw std::runtime_error(
            "execution verification with marker_required requires execution.marker_path");
      }
      if (definition.execution.markerContains.empty()) {
        throw std::runtime_error(
            "execution verification with marker_required requires execution.marker_contains");
      }
      if (definition.execution.markerTimeoutMs == 0 || definition.execution.markerTimeoutMs > 600000) {
        throw std::runtime_error(
            "execution.marker_timeout_ms must be between 1 and 600000");
      }
    }
  }
}

}
