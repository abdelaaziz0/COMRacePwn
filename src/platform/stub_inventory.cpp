#include "comrace/inventory.hpp"

#include <stdexcept>

namespace comrace {

std::vector<ComInventoryEntry> collect_com_inventory(bool) {
  throw std::runtime_error("COM inventory is only available in Windows builds");
}

}
