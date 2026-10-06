#pragma once

#include "comrace/target_definition.hpp"
#include "comrace/runner.hpp"
#include "platform/windows/win_utils.hpp"

#include <string>
#include <vector>

namespace comrace::win {

enum class BrokerOperation { Probe, Invoke, Inspect, ActivationProbe };

struct BrokerOutcome {
  bool started = false;
  bool completed = false;
  bool timedOut = false;
  int exitCode = -1;
  std::string status;
  std::string message;
  std::string hresult;
  std::string rawResult;
};

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

  long long startTick() const { return startTick_; }

  BrokerOutcome wait(unsigned timeoutMs);

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

std::string module_directory();

std::string resolve_host_executable(const std::string& hostArch, const TargetDefinition& definition);

}
