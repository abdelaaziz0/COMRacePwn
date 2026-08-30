#pragma once

#include "comrace/target_definition.hpp"
#include "comrace/runner.hpp"

namespace comrace::win {

void probe_target_method(const TargetDefinition& definition);

void invoke_target_method(
    const TargetDefinition& definition,
    const std::vector<ResolvedArgument>& arguments);

// Activate the definition's CLSID and walk its ITypeInfo (if any). Returns a JSON
// object: {"type_info":bool,"interface":"...","functions":[{"name","dispid",
// "invoke_kind","params":[{"name","type"}]}]}. Throws on activation failure.
std::string type_info_json(const TargetDefinition& definition);

// Just answer "can this token activate this class OUT OF PROCESS, and does it
// expose IDispatch". Returns {"local_server":bool,"local_server_hresult":"0x..",
// "idispatch":bool}. Never loads an in-proc server. Does not throw for a plain
// activation denial - that is the answer.
std::string activation_probe_json(const TargetDefinition& definition);

}  // namespace comrace::win
