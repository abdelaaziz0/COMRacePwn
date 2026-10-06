#include "comrace/inventory.hpp"

#include "comrace/json_output.hpp"

#include <ostream>
#include <sstream>

namespace comrace {
namespace {

void write_field(
    std::ostream& out,
    const char* name,
    const std::string& value,
    bool comma = true) {
  json_output::write_string(out, name);
  out << ':';
  json_output::write_string(out, value);
  if (comma) {
    out << ',';
  }
}

}

std::string com_inventory_json(
    const std::vector<ComInventoryEntry>& entries,
    bool includeInproc) {
  std::ostringstream out;
  out << "{\n  \"schema\":\"comwriterace.inventory.v1\",\n"
      << "  \"include_inproc\":" << (includeInproc ? "true" : "false") << ",\n"
      << "  \"count\":" << entries.size() << ",\n"
      << "  \"classes\":[";

  for (std::size_t i = 0; i < entries.size(); ++i) {
    const ComInventoryEntry& entry = entries[i];
    out << (i == 0 ? "\n    {" : ",\n    {");
    write_field(out, "clsid", entry.clsid);
    write_field(out, "name", entry.name);
    write_field(out, "server_type", entry.serverType);
    write_field(out, "server_path", entry.serverPath);
    write_field(out, "app_id", entry.appId);
    write_field(out, "local_service", entry.localService);
    write_field(out, "service_account", entry.serviceAccount);
    write_field(out, "service_image_path", entry.serviceImagePath);
    write_field(out, "run_as", entry.runAs);
    write_field(out, "registry_hive", entry.registryHive);
    write_field(out, "registry_view", entry.registryView);

    json_output::write_string(out, "effective_activation");
    out << ":{\"status\":";
    json_output::write_string(out, entry.effectiveActivation);
    out << ",\"x64\":";
    json_output::write_string(out, entry.activationX64);
    out << ",\"x86\":";
    json_output::write_string(out, entry.activationX86);
    out << ",\"registration_binding\":\"unresolved\"}";
    out << '}';
  }

  if (!entries.empty()) {
    out << '\n';
  }
  out << "  ]\n}\n";
  return out.str();
}

}
