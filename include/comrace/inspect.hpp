#pragma once

#include <string>
#include <vector>

namespace comrace {

struct InspectedParam {
  std::string name;
  std::string type;
  bool in = true;
  bool out = false;
  bool byref = false;
  bool optional = false;
  int pathScore = 0;
};

struct InspectedFunction {
  std::string name;
  std::string hostArch;
  long dispid = 0;
  std::string invokeKind;
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

InspectionReport parse_inspection_json(const std::string& json);

void rank_inspection(InspectionReport& report);

std::string inspection_report_text(
    const InspectionReport& report,
    const std::string& clsid);

std::string inspection_candidates_json(
    const InspectionReport& report,
    const std::string& clsid,
    const std::string& iid);

}
