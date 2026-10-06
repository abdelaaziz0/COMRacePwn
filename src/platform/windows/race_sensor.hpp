#pragma once

#include "platform/windows/oplock.hpp"
#include "platform/windows/win_utils.hpp"

#include <string>

namespace comrace::win {

enum class TriggerKind {

  FileOplock,

  DirectoryWatch,

  Wnf,
};

TriggerKind parse_trigger_kind(const std::string& value);
std::string to_string(TriggerKind kind);

class RaceSensor {
 public:
  RaceSensor(
      TriggerKind kind,
      std::string baitPath,
      std::string baitDirectory,
      std::string wnfStateHex = {});
  ~RaceSensor();

  RaceSensor(const RaceSensor&) = delete;
  RaceSensor& operator=(const RaceSensor&) = delete;

  void arm();

  bool wait_for_signal(unsigned timeoutMs);
  void release();

  TriggerKind kind() const { return kind_; }
  bool holds_the_server() const { return kind_ == TriggerKind::FileOplock; }

 private:
  bool wait_directory_signal(unsigned timeoutMs);
  bool rearm_directory_watch();
  void arm_wnf();
  bool wait_wnf_signal(unsigned timeoutMs);

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
  bool dirRequestIssued_ = false;

  unsigned long long wnfStateName_ = 0;
  alignas(8) unsigned char wnfSnapshot_[256]{};
  std::size_t wnfSnapshotSize_ = 0;
};

}
