#pragma once

#include "platform/windows/win_utils.hpp"

#include <string>

namespace comrace::win {

void set_dos_device(const std::string& deviceName, const std::string& ntTargetPath);

bool remove_dos_device(const std::string& deviceName);

bool remove_dos_device_exact(
    const std::string& deviceName,
    const std::string& ntTargetPath);

bool dos_device_exists(const std::string& deviceName);

}
