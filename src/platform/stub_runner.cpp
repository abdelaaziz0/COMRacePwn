#include "comrace/runner.hpp"

#include <stdexcept>
#include <string>

namespace comrace {

RunResult run_platform(const RunConfig&) {
  return RunResult{
      false,
      0,
      "execution is only available in Windows builds; this build supports target-definition parsing and dry-run planning"};
}

RunResult probe_platform(const RunConfig&) {
  return RunResult{
      false,
      0,
      "target probing is only available in Windows builds"};
}

RunResult observe_platform(const RunConfig&) {
  return RunResult{
      false,
      0,
      "observation invocation is only available in Windows builds"};
}

std::string inspect_platform(const RunConfig&) {
  throw std::runtime_error("inspect is only available in Windows builds");
}

std::string probe_activation_platform(const RunConfig&) {
  return "windows_only";
}

std::string sha256_file_platform(const std::string&) {
  return "unavailable";
}

}  // namespace comrace
