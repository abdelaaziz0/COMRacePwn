#pragma once

#include <string>
#include <vector>

namespace comrace {

struct ComInventoryEntry {
  std::string clsid;
  std::string name;
  std::string serverType;
  std::string serverPath;
  std::string appId;
  std::string localService;
  std::string serviceAccount;
  std::string serviceImagePath;
  std::string runAs;
  std::string registryHive;
  std::string registryView;
  // Filled in by `inventory --probe-activation`. This is a CLSID-level result -
  // CoCreateInstance takes only the CLSID and resolves the *effective*
  // registration for the token, which is not necessarily THIS raw HKLM/HKCU/32
  // /64 row. Do not read it as "this specific registration is reachable".
  // Values: "not_probed" | "local_server" | "local_server+idispatch" |
  // "denied 0x........" | "<error>".
  std::string effectiveActivation = "not_probed";
  std::string activationX64 = "not_probed";
  std::string activationX86 = "not_probed";
};

std::vector<ComInventoryEntry> collect_com_inventory(bool includeInproc);
std::string com_inventory_json(
    const std::vector<ComInventoryEntry>& entries,
    bool includeInproc);

}  // namespace comrace
