#include "comrace/runner.hpp"

#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

namespace comrace {

std::string new_workspace_platform() {
  std::random_device device;
  std::ostringstream token;
  token << std::hex << std::setw(8) << std::setfill('0')
        << (device() & 0xffffffffu);
  return (std::filesystem::temp_directory_path() / token.str()).string();
}

std::string default_workspace_platform() {
  static const std::string workspace = new_workspace_platform();
  return workspace;
}

std::string os_build_platform() {
  return {};
}

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

}
