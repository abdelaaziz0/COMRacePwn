#pragma once

#include "comrace/target_definition.hpp"

#include <optional>
#include <string>
#include <vector>

namespace comrace {

enum class TargetAction {
  Check,
  Write,
  ExecDll,
  ExecScript
};

struct TargetVariant {
  std::string id;
  std::string name;
  std::string description;
  std::string product;
  std::string version;
  std::string context;
  std::optional<TargetDefinition> check;
  std::optional<TargetDefinition> write;
  std::optional<TargetDefinition> execDll;
  std::optional<TargetDefinition> execScript;
};

struct TargetModule {
  std::string schema;
  std::string id;
  std::string name;
  std::string description;
  std::string sourcePath;
  std::vector<TargetVariant> variants;
};

TargetModule load_target_module(const std::string& path);
std::vector<TargetModule> load_target_modules(const std::string& directory);

const TargetDefinition* target_action_definition(
    const TargetVariant& variant,
    TargetAction action);
bool target_supports(const TargetModule& target, TargetAction action);
std::string to_string(TargetAction action);

}  // namespace comrace
