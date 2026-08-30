#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace comrace::win {

// A fully-formed IO_REPARSE_TAG_MOUNT_POINT REPARSE_DATA_BUFFER, built ahead of
// the race so the hot path only has to open the directory and issue one FSCTL.
struct PreparedReparse {
  std::vector<unsigned char> buffer;
  std::string targetDirectory;  // diagnostics only
};

PreparedReparse prepare_mount_point(const std::string& targetDirectory);

// Open linkDirectory (must already exist and be empty) and set the reparse
// point. Does not create directories. Safe to call from the hot path.
void set_mount_point(const std::string& linkDirectory, const PreparedReparse& prepared);

// Set the reparse point through an already pinned, writable directory handle.
// This avoids a name-based reopen in the race hot path.
void set_mount_point_handle(HANDLE directory, const PreparedReparse& prepared);

// Convenience for non-race callers: ensure the target tree and the link
// directory exist, then set the reparse point.
void create_junction(const std::string& linkDirectory, const std::string& targetDirectory);

bool remove_junction_if_exists(const std::string& linkDirectory);

}  // namespace comrace::win
