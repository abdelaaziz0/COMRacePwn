#pragma once

#include <string>
#include <vector>

namespace comrace {

struct InspectedParam {
  std::string name;
  std::string type;      // "BSTR", "int", ... (pointee type when byref)
  bool in = true;
  bool out = false;
  bool byref = false;    // passed by reference (VT_PTR) - the invoker cannot build it
  bool optional = false;
  int pathScore = 0;     // filled by rank_inspection
};

struct InspectedFunction {
  std::string name;
  std::string hostArch;
  long dispid = 0;
  std::string invokeKind;  // "func" | "propget" | "propput"
  std::vector<InspectedParam> params;
  int methodScore = 0;
};

struct InspectionReport {
  bool activationOk = false;
  bool typeInfo = false;
  std::string activationContext;
  std::vector<std::string> hostArchitectures;
  std::string interfaceName;
  std::vector<InspectedFunction> functions;
};

// Parse the host's {"activation":..,"type_info":bool|object,...} result body.
InspectionReport parse_inspection_json(const std::string& json);

// Fill in pathScore / methodScore heuristics.
void rank_inspection(InspectionReport& report);

std::string inspection_report_text(
    const InspectionReport& report,
    const std::string& clsid);

// For each (method, in BSTR path-parameter) candidate above the score
// threshold, ordered strongest first: a ready-to-run definition skeleton when the
// path arg AND every other required arg is something the IDispatch invoker can
// actually build (by-value string / bool / int), otherwise a
// "target_definition_generation":"unsupported: <reason>" note so the operator knows a
// candidate exists but needs a hand-written adapter.
std::string inspection_candidates_json(
    const InspectionReport& report,
    const std::string& clsid,
    const std::string& iid);

}  // namespace comrace
