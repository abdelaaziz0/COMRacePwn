#pragma once

#include "comrace/target_definition.hpp"
#include "comrace/runner.hpp"
#include "platform/windows/win_utils.hpp"

#include <string>
#include <vector>

namespace comrace::win {

// The COM invocation runs in a short-lived helper process (comwrite_host*.exe),
// not on a thread inside this process. The job contains and kills that client
// host (and child processes it creates); it does NOT contain an out-of-process
// COM server. This isolates client-side faults and provides a path to x86
// targets without claiming server-side cancellation.

enum class BrokerOperation { Probe, Invoke, Inspect, ActivationProbe };

struct BrokerOutcome {
  bool started = false;      // the host process launched
  bool completed = false;    // it exited on its own within the timeout
  bool timedOut = false;     // it was killed by the watchdog
  int exitCode = -1;
  std::string status;        // "success" | "com_error" | "exception" | ...
  std::string message;
  std::string hresult;       // "0x........" when the host reported one
  std::string rawResult;     // the full result JSON (for inspect)
};

// RAII: launches the host (suspended) inside a kill-on-close job object and
// resumes it. The destructor terminates the job and removes the temp files.
class BrokerSession {
 public:
  BrokerSession(
      const std::string& hostExecutable,
      const std::string& workingDirectory,
      BrokerOperation operation,
      const TargetDefinition& definition,
      const std::vector<ResolvedArgument>& arguments);
  ~BrokerSession();

  BrokerSession(const BrokerSession&) = delete;
  BrokerSession& operator=(const BrokerSession&) = delete;

  bool started() const { return started_; }
  const std::string& startError() const { return startError_; }
  // QPC tick captured immediately before the host thread was resumed (0 if the
  // session never started).
  long long startTick() const { return startTick_; }

  // Wait up to timeoutMs for the host to finish. On timeout the job is killed
  // and outcome.timedOut is set.
  BrokerOutcome wait(unsigned timeoutMs);

  // Request termination and drain the process handle. Returns true once the
  // host is observed exited (used by the destructor and abort paths).
  bool kill();

 private:
  bool started_ = false;
  std::string startError_;
  std::string requestPath_;
  std::string resultPath_;
  std::string sessionId_;
  UniqueHandle requestFile_;
  UniqueHandle resultFile_;
  UniqueHandle job_;
  UniqueHandle process_;
  long long startTick_ = 0;
  bool finished_ = false;
};

// Directory containing the running comwriterace.exe.
std::string module_directory();

// Resolve the host executable path for an architecture ("x64", "x86", "auto").
// "auto" picks x64, or x86 when the native-adapter DLL is a 32-bit image.
std::string resolve_host_executable(const std::string& hostArch, const TargetDefinition& definition);

}  // namespace comrace::win
