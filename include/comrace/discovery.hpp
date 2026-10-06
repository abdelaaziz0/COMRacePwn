#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace comrace {

enum class DiscoveredPrimitive {
  DoubleOpen,
  FileWrite,
  FileDelete,
  FileMoveReplace,
  FileRead,
  DllLoad
};

struct DiscoveryOptions {
  std::string controlledRoot;
  std::string processFilter;
  int minimumScore = 25;
};

struct DiscoveryCandidate {
  std::string processName;
  unsigned long processId = 0;
  std::string user;
  std::string path;
  DiscoveredPrimitive primitive = DiscoveredPrimitive::DoubleOpen;
  int score = 0;
  std::string confidence;
  std::size_t eventCount = 0;
  std::size_t openCount = 0;
  std::size_t successfulOpenCount = 0;
  std::size_t pathProbeCount = 0;
  std::size_t failedResolutionCount = 0;
  std::size_t closeCount = 0;
  std::size_t attemptedEffectCount = 0;
  std::size_t successfulEffectCount = 0;
  bool openCloseReopenObserved = false;
  bool sameThreadOpenCloseReopenObserved = false;
  std::vector<std::string> operations;
  std::vector<std::string> reasons;
};

struct DiscoveryReport {
  std::string tracePath;
  std::size_t inputRecordCount = 0;
  std::size_t fileEventCount = 0;
  std::size_t candidateCountBeforeThreshold = 0;
  std::vector<DiscoveryCandidate> candidates;
};

DiscoveryReport analyze_procmon_csv(
    const std::string& path,
    const DiscoveryOptions& options);

std::string discovery_report_json(const DiscoveryReport& report);
std::string discovery_report_text(const DiscoveryReport& report);
std::string to_string(DiscoveredPrimitive primitive);

}
