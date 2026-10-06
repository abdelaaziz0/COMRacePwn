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

  std::string effectiveActivation = "not_probed";
  std::string activationX64 = "not_probed";
  std::string activationX86 = "not_probed";
};

std::vector<ComInventoryEntry> collect_com_inventory(bool includeInproc);
std::string com_inventory_json(
    const std::vector<ComInventoryEntry>& entries,
    bool includeInproc);

}
