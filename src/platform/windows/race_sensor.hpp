#pragma once

#include "platform/windows/oplock.hpp"
#include "platform/windows/win_utils.hpp"

#include <string>

namespace comrace::win {

// How the harness learns the privileged server has touched the controlled path.
enum class TriggerKind {
  // Modern oplock on a pre-created bait file. Strongest: it also *holds* the
  // server's first open until we release, so we control the timing.
  FileOplock,
  // ReadDirectoryChangesW on the bait's parent directory. Weaker (does not hold
  // the server) but the only option when the server expects the output path to
  // NOT exist (CREATE_NEW / CREATE_ALWAYS on a fresh name).
  DirectoryWatch,
};

TriggerKind parse_trigger_kind(const std::string& value);
std::string to_string(TriggerKind kind);

// Unified interface over the oplock and the directory watch.
class RaceSensor {
 public:
  RaceSensor(TriggerKind kind, std::string baitPath, std::string baitDirectory);
  ~RaceSensor();

  RaceSensor(const RaceSensor&) = delete;
  RaceSensor& operator=(const RaceSensor&) = delete;

  void arm();
  // For FileOplock: returns true when the oplock breaks (the server opened the
  // bait). For DirectoryWatch: returns true ONLY after a change notification
  // naming the bait file itself is parsed out of the buffer - an unrelated
  // change in the directory re-arms the watch and keeps waiting. This return
  // value is the sole signal the runner acts on; it is what keeps
  // directory_watch from turning a single unrelated open into a false
  // "name re-resolution proven".
  bool wait_for_signal(unsigned timeoutMs);
  void release();

  TriggerKind kind() const { return kind_; }
  bool holds_the_server() const { return kind_ == TriggerKind::FileOplock; }

 private:
  bool wait_directory_signal(unsigned timeoutMs);
  bool rearm_directory_watch();

  TriggerKind kind_;
  std::string baitPath_;
  std::string baitDirectory_;
  std::wstring baitFileName_;

  Oplock oplock_;

  UniqueHandle dirHandle_;
  UniqueHandle dirEvent_;
  OVERLAPPED dirOverlapped_{};
  alignas(DWORD) unsigned char dirBuffer_[8192]{};
  bool dirArmed_ = false;
  bool dirRequestIssued_ = false;  // OVERLAPPED/buffer may still be kernel-owned
};

}  // namespace comrace::win
