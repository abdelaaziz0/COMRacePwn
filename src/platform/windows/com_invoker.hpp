#pragma once

#include "comrace/target_definition.hpp"
#include "comrace/runner.hpp"

namespace comrace::win {

void probe_target_method(const TargetDefinition& definition);

void invoke_target_method(
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments);

std::string type_info_json(const TargetDefinition& definition);

std::string activation_probe_json(const TargetDefinition& definition);

}
