#pragma once

#include "comrace/json.hpp"
#include "comrace/target_definition.hpp"

#include <filesystem>

namespace comrace {

// Internal parser entry point used by .cwr target modules. Target authors can
// embed action definitions without exposing those mechanics in the CLI.
TargetDefinition parse_target_definition_object(
    const json::Value::Object& object,
    const std::filesystem::path& baseDirectory);

}  // namespace comrace
