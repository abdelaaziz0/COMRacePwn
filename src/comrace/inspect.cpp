#include "comrace/inspect.hpp"

#include "comrace/json.hpp"
#include "comrace/json_output.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <utility>

namespace comrace {
namespace {

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool contains(const std::string& haystack, const char* needle) {
  return haystack.find(needle) != std::string::npos;
}

// (substring, points) - a parameter name that looks like it names an output path.
constexpr std::array<std::pair<const char*, int>, 20> kParamHints{{
    {"outputpath", 45}, {"outpath", 40}, {"outfile", 40}, {"destination", 40},
    {"savepath", 40}, {"targetpath", 40}, {"filepath", 38}, {"exportpath", 40},
    {"logpath", 35}, {"path", 30}, {"filename", 28}, {"directory", 28},
    {"folder", 26}, {"target", 22}, {"output", 24}, {"dest", 24},
    {"location", 22}, {"file", 18}, {"save", 16}, {"dir", 16},
}};

// (substring, points) - a method name that looks like it writes somewhere.
constexpr std::array<std::pair<const char*, int>, 16> kMethodHints{{
    {"export", 25}, {"extract", 25}, {"install", 22}, {"backup", 22},
    {"save", 20}, {"write", 20}, {"dump", 20}, {"generate", 16},
    {"render", 16}, {"copy", 16}, {"import", 14}, {"restore", 16},
    {"create", 12}, {"build", 12}, {"report", 12}, {"log", 10},
}};

std::string str(const json::Value& obj, const char* key) {
  const json::Value* v = obj.find(key);
  return (v && v->is_string()) ? v->as_string() : std::string{};
}

bool boolean(const json::Value& obj, const char* key) {
  const json::Value* v = obj.find(key);
  return v && v->is_bool() && v->as_bool();
}

long number(const json::Value& obj, const char* key) {
  const json::Value* v = obj.find(key);
  return (v && v->is_number()) ? static_cast<long>(v->as_number()) : 0;
}

}  // namespace

InspectionReport parse_inspection_json(const std::string& text) {
  InspectionReport report;
  const json::Value root = json::parse(text);
  if (!root.is_object()) {
    return report;
  }

  const auto parseTypeInfo = [&](const json::Value& ti, const std::string& arch) {
    if (!ti.is_object()) {
      return;
    }
    report.activationOk =
        report.activationOk || str(ti, "activation") == "ok";
    const std::string context = str(ti, "activation_context");
    if (!context.empty()) {
      report.activationContext = context;
    }
    if (!arch.empty() &&
        std::find(report.hostArchitectures.begin(),
                  report.hostArchitectures.end(), arch) ==
            report.hostArchitectures.end()) {
      report.hostArchitectures.push_back(arch);
    }
    const bool hasTypeInfo = boolean(ti, "type_info");
    report.typeInfo = report.typeInfo || hasTypeInfo;
    if (report.interfaceName.empty()) {
      report.interfaceName = str(ti, "interface");
    }
    if (!hasTypeInfo) {
      return;
    }
    const json::Value* funcs = ti.find("functions");
    if (funcs == nullptr || !funcs->is_array()) {
      return;
    }
    for (const json::Value& f : funcs->as_array()) {
      if (!f.is_object()) {
        continue;
      }
      InspectedFunction fn;
      fn.name = str(f, "name");
      fn.hostArch = arch;
      fn.dispid = number(f, "dispid");
      fn.invokeKind = str(f, "invoke_kind");
      if (const json::Value* params = f.find("params");
          params && params->is_array()) {
        for (const json::Value& p : params->as_array()) {
          if (!p.is_object()) {
            continue;
          }
          InspectedParam param;
          param.name = str(p, "name");
          param.type = str(p, "type");
          param.in = boolean(p, "in");
          param.out = boolean(p, "out");
          param.byref = boolean(p, "byref");
          param.optional = boolean(p, "optional");
          fn.params.push_back(std::move(param));
        }
      }
      report.functions.push_back(std::move(fn));
    }
  };

  if (const json::Value* hosts = root.find("hosts");
      hosts && hosts->is_array()) {
    report.activationContext = str(root, "inspection_context");
    for (const json::Value& host : hosts->as_array()) {
      if (!host.is_object()) continue;
      const json::Value* result = host.find("result");
      if (result == nullptr || !result->is_object()) continue;
      const json::Value* ti = result->find("type_info");
      if (ti != nullptr) {
        parseTypeInfo(*ti, str(host, "arch"));
      }
    }
  } else if (const json::Value* ti = root.find("type_info");
             ti != nullptr) {
    parseTypeInfo(*ti, {});
  }
  return report;
}

void rank_inspection(InspectionReport& report) {
  for (InspectedFunction& fn : report.functions) {
    const std::string methodLower = lower(fn.name);
    for (const auto& [needle, points] : kMethodHints) {
      if (contains(methodLower, needle)) {
        fn.methodScore = std::max(fn.methodScore, points);
      }
    }
    for (InspectedParam& param : fn.params) {
      // Only a string parameter can carry a path we redirect.
      if (param.type != "BSTR" && param.type != "LPWSTR" && param.type != "LPSTR") {
        continue;
      }
      const std::string nameLower = lower(param.name);
      int best = 0;
      for (const auto& [needle, points] : kParamHints) {
        if (contains(nameLower, needle)) {
          best = std::max(best, points);
        }
      }
      // A string param on a write-shaped method is a weak candidate even with a
      // bland name.
      if (best == 0 && fn.methodScore >= 20) {
        best = 8;
      }
      param.pathScore = best + fn.methodScore / 3;
    }
  }
}

std::string inspection_report_text(
    const InspectionReport& report,
    const std::string& clsid) {
  std::ostringstream out;
  out << "CLSID: " << clsid << "\n";
  out << "Activation: " << (report.activationOk ? "ok" : "failed") << "\n";
  out << "Activation context: "
      << (report.activationContext.empty()
              ? "not reported" : report.activationContext)
      << "\n";
  if (!report.hostArchitectures.empty()) {
    out << "Host architectures:";
    for (const std::string& arch : report.hostArchitectures) {
      out << ' ' << arch;
    }
    out << "\n";
  }
  if (!report.typeInfo) {
    out << "Type information: none (hand-rolled IDispatch, no typelib).\n"
        << "  Supply the method name and arguments in a reviewed .cwr target\n"
        << "  module and identify the path argument from an authorized trace.\n";
    return out.str();
  }
  if (!report.interfaceName.empty()) {
    out << "Interface: " << report.interfaceName << "\n";
  }
  out << "Functions: " << report.functions.size() << "\n\n";

  for (const InspectedFunction& fn : report.functions) {
    out << "  " << fn.name << "  (dispid " << fn.dispid << ", " << fn.invokeKind << ")";
    if (!fn.hostArch.empty()) out << " [" << fn.hostArch << "]";
    if (fn.methodScore > 0) {
      out << "  [write-shaped method +" << fn.methodScore << "]";
    }
    out << "\n";
    for (const InspectedParam& param : fn.params) {
      out << "      " << param.type << (param.byref ? "*" : "") << " " << param.name;
      if (param.byref) out << " (by ref)";
      if (param.optional) out << " (optional)";
      if (!param.in && param.out) out << " (out)";
      else if (param.in && param.out) out << " (in/out)";
      if (param.pathScore > 0) {
        out << "   <- path-argument likelihood " << param.pathScore;
      }
      out << "\n";
    }
  }
  return out.str();
}

namespace {

// TargetDefinition argument token the IDispatch invoker can actually build from a string
// value, or "" if it cannot represent this parameter at all. By-reference
// parameters (every [out]/[in,out] and [in] struct/enum) are never
// representable: the invoker only passes by value.
std::string invoker_arg_token(const InspectedParam& param, bool asPath) {
  if (param.byref) {
    return {};
  }
  if (param.type == "BSTR") {
    return asPath ? "path" : "string";
  }
  if (param.type == "bool") return "bool";
  if (param.type == "int") return "int32";
  if (param.type == "uint") return "uint32";
  if (param.type == "int64") return "int64";
  // uint64, variant, IDispatch, IUnknown, void, other: no invoker mapping.
  return {};
}

std::string placeholder_value(const std::string& token) {
  if (token == "string") return "{content}";
  if (token == "bool") return "false";
  return "0";  // int32 / uint32 / int64
}

// Why a generated definition can't be run as-is (empty => it can).
std::string target_definition_blocker(
    const InspectedFunction& fn,
    std::size_t pathIndex) {
  const InspectedParam& path = fn.params[pathIndex];
  if (!path.in) {
    return "path parameter '" + path.name + "' is [out], not an input";
  }
  if (path.byref) {
    return "path parameter '" + path.name + "' is by reference (" + path.type +
           "*); the idispatch invoker only passes arguments by value";
  }
  if (path.type != "BSTR") {
    return "path parameter '" + path.name + "' uses " + path.type +
           "; generated IDispatch target definitions marshal string/path values as VT_BSTR";
  }
  // Every parameter up to and including the last non-optional one (and the path)
  // must be buildable - the invoker fills DISPPARAMS positionally and can only
  // drop a contiguous optional tail.
  std::size_t lastKeep = pathIndex;
  for (std::size_t i = 0; i < fn.params.size(); ++i) {
    if (!fn.params[i].optional) {
      lastKeep = (std::max)(lastKeep, i);
    }
  }
  for (std::size_t i = 0; i <= lastKeep; ++i) {
    if (i == pathIndex) {
      continue;
    }
    if (invoker_arg_token(fn.params[i], false).empty()) {
      const InspectedParam& p = fn.params[i];
      return "parameter '" + p.name + "' (" + p.type + (p.byref ? "*" : "") +
             ") cannot be built by the idispatch invoker";
    }
  }
  return {};
}

}  // namespace

std::string inspection_candidates_json(
    const InspectionReport& report,
    const std::string& clsid,
    const std::string& iid) {
  struct Candidate {
    const InspectedFunction* fn;
    std::size_t paramIndex;
    int score;
  };
  std::vector<Candidate> candidates;
  for (const InspectedFunction& fn : report.functions) {
    // The IDispatch invoker only issues DISPATCH_METHOD calls. Property
    // get/put candidates would not be executable, so do not emit them.
    if (fn.invokeKind != "func") {
      continue;
    }
    for (std::size_t i = 0; i < fn.params.size(); ++i) {
      if (fn.params[i].pathScore >= 18) {
        candidates.push_back({&fn, i, fn.params[i].pathScore});
      }
    }
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

  std::ostringstream out;
  out << "{\n  \"schema\":\"comwriterace.inspect-candidates.v1\",\n  \"clsid\":";
  json_output::write_string(out, clsid);
  out << ",\n  \"inspection_context\":";
  json_output::write_string(
      out, report.activationContext.empty()
               ? "unknown" : report.activationContext);
  out << ",\n  \"activation_context\":";
  json_output::write_string(
      out, report.activationContext.empty()
               ? "unknown" : report.activationContext);
  out << ",\n  \"host_architectures\":[";
  for (std::size_t i = 0; i < report.hostArchitectures.size(); ++i) {
    if (i != 0) out << ',';
    json_output::write_string(out, report.hostArchitectures[i]);
  }
  out << ']';
  out << ",\n  \"candidates\":[";
  for (std::size_t c = 0; c < candidates.size(); ++c) {
    const Candidate& cand = candidates[c];
    const InspectedFunction& fn = *cand.fn;
    const std::string blocker =
        target_definition_blocker(fn, cand.paramIndex);

    out << (c == 0 ? "\n    " : ",\n    ") << "{\n"
        << "      \"score\":" << cand.score << ",\n"
        << "      \"method\":";
    json_output::write_string(out, fn.name);
    out << ",\n      \"path_param\":";
    json_output::write_string(out, fn.params[cand.paramIndex].name);
    out << ",\n      \"path_param_index\":" << cand.paramIndex
        << ",\n      \"candidate\":true";
    if (!fn.hostArch.empty()) {
      out << ",\n      \"host_arch\":";
      json_output::write_string(out, fn.hostArch);
    }

    if (!blocker.empty()) {
      // A candidate exists but the built-in invoker can't drive it - say so
      // instead of emitting a definition that would fail at Invoke time. Every key
      // is still present (target_definition == null) so consumers need not probe.
      out << ",\n      \"auto_target_definition_supported\":false,\n"
          << "      \"target_definition_generation\":\"unsupported\",\n"
          << "      \"reason\":";
      json_output::write_string(out, blocker);
      out << ",\n      \"target_definition\":null\n    }";
      continue;
    }

    // Contiguous optional tail we can leave off the generated arg list.
    std::size_t lastKeep = cand.paramIndex;
    for (std::size_t i = 0; i < fn.params.size(); ++i) {
      if (!fn.params[i].optional) {
        lastKeep = (std::max)(lastKeep, i);
      }
    }

    out << ",\n      \"auto_target_definition_supported\":true,\n"
        << "      \"target_definition_generation\":\"ok\",\n"
        << "      \"reason\":\"\",\n"
        << "      \"target_definition\":{\n"
        << "        \"name\":";
    json_output::write_string(out, fn.name + "PathRedirect");
    out << ",\n        \"clsid\":";
    json_output::write_string(out, clsid);
    out << ",\n        \"iid\":";
    json_output::write_string(out, iid);
    out << ",\n        \"invoker\":\"idispatch\",\n"
        << "        \"method\":";
    json_output::write_string(out, fn.name);
    out << ",\n        \"vulnerability_pattern\":\"double_open_path_write\",\n"
        << "        \"privileged_operation\":\"file_write\",\n"
        << "        \"race_trigger\":\"oplock_on_source\",\n"
        << "        \"swap_primitive\":\"junction_redirect\",\n"
        << "        \"attacker_controlled_path_arg\":" << cand.paramIndex << ",\n"
        << "        \"default_workspace\":\"C:\\\\Users\\\\Public\\\\ComWriteRace\",\n"
        << "        \"default_target\":null,\n"
        << "        \"target_required\":true,\n"
        << "        \"content\":\"CWR controlled content\",\n"
        << "        \"operation\":{\"side_effect_level\":\"unknown\",\"retry_safe\":false,\"max_recommended_attempts\":1},\n"
        << "        \"method_args\":[";
    bool firstArg = true;
    for (std::size_t p = 0; p <= lastKeep; ++p) {
      const InspectedParam& param = fn.params[p];
      const bool isPath = p == cand.paramIndex;
      const std::string token = invoker_arg_token(param, isPath);
      out << (firstArg ? "\n          " : ",\n          ") << "{\"name\":";
      json_output::write_string(out, param.name.empty() ? "arg" + std::to_string(p)
                                                        : param.name);
      out << ",\"type\":\"" << token << "\",\"value\":";
      if (isPath) {
        out << "\"{bait_path}\",\"attacker_controlled\":true}";
      } else {
        json_output::write_string(out, placeholder_value(token));
        out << "}";
      }
      firstArg = false;
    }
    out << "\n        ]\n      }\n    }";
  }
  out << (candidates.empty() ? "" : "\n  ") << "]\n}\n";
  return out.str();
}

}  // namespace comrace
