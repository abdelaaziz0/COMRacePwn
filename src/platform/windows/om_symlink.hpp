#pragma once

#include "platform/windows/win_utils.hpp"

#include <string>

namespace comrace::win {

struct OmSymlink {
  UniqueHandle handle;
  std::string objectName;
};

OmSymlink create_om_symlink(const std::string& objectName, const std::string& ntTargetPath);

}
