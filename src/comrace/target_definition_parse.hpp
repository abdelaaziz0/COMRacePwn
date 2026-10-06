#pragma once

#include "comrace/json.hpp"
#include "comrace/target_definition.hpp"

#include <filesystem>

namespace comrace {

TargetDefinition parse_target_definition_object(
    const json::Value::Object& object,
    const std::filesystem::path& baseDirectory);

}
