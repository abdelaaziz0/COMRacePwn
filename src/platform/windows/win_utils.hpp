#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>
#include <vector>

namespace comrace::win {

struct TargetPrecheck {
  bool targetExists = false;
  bool directoryExists = false;
  bool directoryWritable = false;
  bool directoryWriteProbeConclusive = false;
  std::string detail;
};

struct FileObservation {
  bool exists = false;
  bool contentRead = false;
  bool contentMatches = false;
  unsigned long long size = 0;
  std::string owner;
  std::string integrityLabel;
  std::string creationTimeUtc;
  std::string lastWriteTimeUtc;
};

class UniqueHandle {
 public:
  UniqueHandle() = default;
  explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
  ~UniqueHandle();

  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;

  UniqueHandle(UniqueHandle&& other) noexcept;
  UniqueHandle& operator=(UniqueHandle&& other) noexcept;

  HANDLE get() const { return handle_; }
  HANDLE* put();
  HANDLE release();
  void reset(HANDLE handle = INVALID_HANDLE_VALUE);
  explicit operator bool() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

 private:
  HANDLE handle_ = INVALID_HANDLE_VALUE;
};

std::wstring widen(const std::string& value);
std::string narrow(const std::wstring& value);
std::string last_error_message(DWORD error = GetLastError());
std::string hresult_message(HRESULT hr);

[[noreturn]] void throw_last_error(const std::string& action);
void throw_if_failed(HRESULT hr, const std::string& action);

std::wstring normalize_windows_path(std::wstring path);
std::string full_path_name(const std::string& path);

// Resolved filesystem identity of a directory: volume serial + 128-bit file id,
// following any reparse points. `ok` is false if the path could not be opened.
struct PathIdentity {
  bool ok = false;
  unsigned long long volumeSerial = 0;
  std::string fileId;  // hex, 16 bytes
};
PathIdentity path_identity(const std::string& path);

// Pins every existing directory component below the volume/share root without
// delete sharing. While held, another process cannot rename, delete, or turn
// those namespace objects into reparse points. The optional writable leaf is
// also opened without write sharing and lets the race engine set its own
// reparse point without reopening the directory by name.
class PinnedDirectoryTree {
 public:
  PinnedDirectoryTree() = default;
  PinnedDirectoryTree(const std::string& path, bool writableLeaf);

  PinnedDirectoryTree(const PinnedDirectoryTree&) = delete;
  PinnedDirectoryTree& operator=(const PinnedDirectoryTree&) = delete;
  PinnedDirectoryTree(PinnedDirectoryTree&&) noexcept = default;
  PinnedDirectoryTree& operator=(PinnedDirectoryTree&&) noexcept = default;

  HANDLE leaf_handle() const;
  const PathIdentity& leaf_identity() const { return leafIdentity_; }
  bool verify(bool allowLeafReparse = false) const;
  void reset();
  explicit operator bool() const { return !handles_.empty(); }

 private:
  std::vector<std::string> paths_;
  std::vector<UniqueHandle> handles_;
  std::vector<PathIdentity> identities_;
  PathIdentity leafIdentity_;
};

// True if `path` itself OR any of its ancestors up to the volume root is a
// reparse point. `firstReparse` receives the offending component's path.
bool has_reparse_component(const std::string& path, std::string& firstReparse);
void ensure_directory_tree(const std::string& path);
bool path_exists(const std::string& path);
bool file_exists(const std::string& path);
bool directory_exists(const std::string& path);
bool is_reparse_point(const std::string& path);
bool file_contains_text_case_insensitive(
    const std::string& path,
    const std::string& expectedText);
void delete_file_if_exists(const std::string& path);
// Returns ERROR_SUCCESS if the file was deleted or already absent, otherwise the
// Win32 error (e.g. ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED). Never throws.
DWORD try_delete_file(const std::string& path);
bool remove_directory_if_exists(const std::string& path);

// SID (string form) of the token running this process. "unavailable" on error.
std::string current_process_user_sid();
std::string current_process_integrity();
std::string windows_build_string();
// Cryptographically strong GUID token. Empty on failure (callers fail closed).
std::string new_guid_token();
// Copy a PE payload to a new path and append a nonce overlay. The PE loader
// ignores the overlay; the bundled lab marker DLL reads and records it.
void copy_file_with_nonce_overlay(
    const std::string& source,
    const std::string& destination,
    const std::string& nonce);
// Copy without changing the artifact bytes. Existing destinations are rejected.
void copy_file_exact(const std::string& source, const std::string& destination);
std::string sha256_file(const std::string& path);
unsigned long long file_size_bytes(const std::string& path);

// QueryPerformanceCounter tick and frequency, for race timing transcripts.
long long qpc_now();
long long qpc_frequency();
double qpc_delta_ms(long long fromTicks, long long toTicks);
void write_text_file(const std::string& path, const std::string& content);
TargetPrecheck precheck_target(
    const std::string& targetPath,
    const std::string& targetDirectory);
FileObservation inspect_file_against_content(
    const std::string& path, const std::string& expectedContent);
FileObservation inspect_file_against_file(
    const std::string& path, const std::string& expectedPath);
std::string describe_file_observation(const FileObservation& observation);

// Fields recorded by a target-specific execution marker. The bundled lab DLL's
// legacy passive-load record is accepted as the development fixture format.
struct ExecutionMarker {
  bool markerHeaderPresent = false;
  std::string pid;
  std::string processImage;
  std::string modulePath;
  std::string account;
  std::string experimentNonce;
  std::string sid;
  std::string integrity;
  bool impersonating = false;
  std::string threadSid;
  std::string threadIntegrity;
};
ExecutionMarker parse_execution_marker(const std::string& path);

}  // namespace comrace::win
