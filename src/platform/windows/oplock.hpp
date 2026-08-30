#pragma once

#include "platform/windows/win_utils.hpp"

#include <winioctl.h>

#include <string>

namespace comrace::win {

class Oplock {
 public:
  Oplock() = default;
  ~Oplock();

  Oplock(const Oplock&) = delete;
  Oplock& operator=(const Oplock&) = delete;

  void arm_on_file(const std::string& path);
  bool wait_for_break(unsigned timeoutMs);
  void release();

 private:
  UniqueHandle file_;
  UniqueHandle event_;
  OVERLAPPED overlapped_{};
  REQUEST_OPLOCK_INPUT_BUFFER request_{};
  REQUEST_OPLOCK_OUTPUT_BUFFER response_{};
  bool armed_ = false;
  bool requestPending_ = false;  // OVERLAPPED/response remain kernel-owned
  bool broken_ = false;  // the FSCTL has already completed (no CancelIoEx needed)
};

}  // namespace comrace::win
