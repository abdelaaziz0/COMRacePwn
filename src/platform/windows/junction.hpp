#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace comrace::win {

struct PreparedReparse {
  std::vector<unsigned char> buffer;
  std::string targetDirectory;
};

PreparedReparse prepare_mount_point(const std::string& targetDirectory);

PreparedReparse prepare_mount_point_nt(
    const std::string& ntSubstituteTarget,
    const std::string& printName);

void set_mount_point(const std::string& linkDirectory, const PreparedReparse& prepared);

void set_mount_point_handle(HANDLE directory, const PreparedReparse& prepared);

void create_junction(const std::string& linkDirectory, const std::string& targetDirectory);

void create_junction_to_nt(
    const std::string& linkDirectory,
    const std::string& ntSubstituteTarget);

bool remove_junction_if_exists(const std::string& linkDirectory);

}
