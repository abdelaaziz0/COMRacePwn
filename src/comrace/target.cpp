#include "comrace/target.hpp"

#include "comrace/json.hpp"
#include "comrace/target_definition_parse.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace comrace {
namespace {

const json::Value* find_field(
    const json::Value::Object& object,
    const std::string& key) {
  const auto found = object.find(key);
  return found == object.end() ? nullptr : &found->second;
}

std::string require_string(
    const json::Value::Object& object,
    const std::string& key) {
  const json::Value* value = find_field(object, key);
  if (value == nullptr) {
    throw std::runtime_error("target module is missing required field: " + key);
  }
  const std::string result = value->as_string();
  if (result.empty() || result.find('\0') != std::string::npos) {
    throw std::runtime_error("target module field is empty or invalid: " + key);
  }
  return result;
}

std::string optional_string(
    const json::Value::Object& object,
    const std::string& key,
    const std::string& fallback = {}) {
  const json::Value* value = find_field(object, key);
  if (value == nullptr) return fallback;
  const std::string result = value->as_string();
  if (result.find('\0') != std::string::npos) {
    throw std::runtime_error("target module field contains an embedded NUL: " + key);
  }
  return result;
}

std::optional<TargetDefinition> parse_action(
    const json::Value::Object& actions,
    const char* key,
    const std::filesystem::path& baseDirectory) {
  const json::Value* value = find_field(actions, key);
  if (value == nullptr || value->is_null()) return std::nullopt;
  return parse_target_definition_object(value->as_object(), baseDirectory);
}

bool valid_identifier(const std::string& value) {
  if (value.empty()) return false;
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return std::islower(character) || std::isdigit(character) ||
           character == '-' || character == '_';
  });
}

std::string read_text(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("unable to open target module: " + path);
  std::ostringstream text;
  text << input.rdbuf();
  return text.str();
}

}  // namespace

TargetModule load_target_module(const std::string& path) {
  const std::filesystem::path absolute = std::filesystem::absolute(path);
  const auto root = json::parse(read_text(path)).as_object();

  TargetModule module;
  module.schema = require_string(root, "schema");
  if (module.schema != "cwr.target.v1") {
    throw std::runtime_error(
        "unsupported target-module schema in " + path + ": " + module.schema);
  }
  module.id = require_string(root, "id");
  module.name = require_string(root, "name");
  module.description = optional_string(root, "description");
  module.sourcePath = absolute.lexically_normal().string();
  if (!valid_identifier(module.id)) {
    throw std::runtime_error(
        "target module id must contain only lowercase letters, digits, '-' or '_': " +
        module.id);
  }

  const json::Value* variantsValue = find_field(root, "variants");
  if (variantsValue == nullptr) {
    throw std::runtime_error("target module is missing required field: variants");
  }

  std::set<std::string> ids;
  for (const json::Value& value : variantsValue->as_array()) {
    const auto& item = value.as_object();
    TargetVariant variant;
    variant.id = require_string(item, "id");
    variant.name = optional_string(item, "name", variant.id);
    variant.description = optional_string(item, "description");
    variant.product = optional_string(item, "product", module.name);
    variant.version = optional_string(item, "version", "any supported version");
    variant.context = optional_string(item, "context", "unknown");
    if (!valid_identifier(variant.id) || !ids.insert(variant.id).second) {
      throw std::runtime_error(
          "target module has an invalid or duplicate variant id: " + variant.id);
    }

    const json::Value* actionsValue = find_field(item, "actions");
    if (actionsValue == nullptr) {
      throw std::runtime_error(
          "target variant " + variant.id + " is missing actions");
    }
    const auto& actions = actionsValue->as_object();
    variant.check = parse_action(actions, "check", absolute.parent_path());
    variant.write = parse_action(actions, "write", absolute.parent_path());
    variant.execDll = parse_action(actions, "exec_dll", absolute.parent_path());
    variant.execScript = parse_action(actions, "exec_script", absolute.parent_path());
    if (!variant.check && !variant.write && !variant.execDll && !variant.execScript) {
      throw std::runtime_error(
          "target variant " + variant.id + " defines no supported actions");
    }
    module.variants.push_back(std::move(variant));
  }
  if (module.variants.empty()) {
    throw std::runtime_error("target module must define at least one variant");
  }
  return module;
}

std::vector<TargetModule> load_target_modules(const std::string& directory) {
  const std::filesystem::path root = std::filesystem::absolute(directory);
  if (!std::filesystem::exists(root)) return {};
  if (!std::filesystem::is_directory(root)) {
    throw std::runtime_error("targets path is not a directory: " + root.string());
  }

  std::vector<TargetModule> modules;
  for (const auto& entry : std::filesystem::directory_iterator(root)) {
    if (entry.is_regular_file() && entry.path().extension() == ".cwr") {
      modules.push_back(load_target_module(entry.path().string()));
    }
  }
  std::sort(modules.begin(), modules.end(), [](const auto& left, const auto& right) {
    return left.id < right.id;
  });
  for (std::size_t index = 1; index < modules.size(); ++index) {
    if (modules[index - 1].id == modules[index].id) {
      throw std::runtime_error(
          "duplicate target module id: " + modules[index].id);
    }
  }
  return modules;
}

const TargetDefinition* target_action_definition(
    const TargetVariant& variant,
    TargetAction action) {
  switch (action) {
    case TargetAction::Check: return variant.check ? &*variant.check : nullptr;
    case TargetAction::Write: return variant.write ? &*variant.write : nullptr;
    case TargetAction::ExecDll: return variant.execDll ? &*variant.execDll : nullptr;
    case TargetAction::ExecScript:
      return variant.execScript ? &*variant.execScript : nullptr;
  }
  return nullptr;
}

bool target_supports(const TargetModule& target, TargetAction action) {
  return std::any_of(
      target.variants.begin(), target.variants.end(),
      [action](const TargetVariant& variant) {
        return target_action_definition(variant, action) != nullptr;
      });
}

std::string to_string(TargetAction action) {
  switch (action) {
    case TargetAction::Check: return "check";
    case TargetAction::Write: return "write";
    case TargetAction::ExecDll: return "exec_dll";
    case TargetAction::ExecScript: return "exec_script";
  }
  return "unknown";
}

}  // namespace comrace
