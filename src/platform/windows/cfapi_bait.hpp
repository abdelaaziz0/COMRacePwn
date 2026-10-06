#pragma once

#include "platform/windows/win_utils.hpp"

#include <string>

namespace comrace::win {

void prepare_cloud_placeholder_bait(
    const std::string& safeDirectory,
    const std::string& baitFileName,
    const std::string& providerToken);

void teardown_cloud_bait(const std::string& safeDirectory);

}
