#include "platform/windows/dos_symlink.hpp"

#include <stdexcept>
#include <vector>

namespace comrace::win {
namespace {

void define_dos_device(DWORD flags, const std::string& deviceName, const std::string& target) {
  if (deviceName.empty()) {
    throw std::runtime_error("dos device name is empty");
  }
  if (!DefineDosDeviceW(
          flags | DDD_RAW_TARGET_PATH,
          widen(deviceName).c_str(),
          widen(target).c_str())) {
    throw_last_error("DefineDosDeviceW(" + deviceName + " -> " + target + ")");
  }
}

std::wstring query_dos_device(const std::string& deviceName) {
  std::vector<wchar_t> buffer(1024);
  for (;;) {
    const DWORD chars = QueryDosDeviceW(
        widen(deviceName).c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
    if (chars > 0) {

      return std::wstring(buffer.data());
    }
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && buffer.size() < 32768) {
      buffer.resize(buffer.size() * 2);
      continue;
    }
    return {};
  }
}

}

void set_dos_device(const std::string& deviceName, const std::string& ntTargetPath) {
  if (ntTargetPath.empty() || ntTargetPath.front() != '\\') {
    throw std::runtime_error(
        "dos device target must be a raw NT path: " + ntTargetPath);
  }
  define_dos_device(0, deviceName, ntTargetPath);
}

bool dos_device_exists(const std::string& deviceName) {
  return !query_dos_device(deviceName).empty();
}

bool remove_dos_device(const std::string& deviceName) {
  for (int round = 0; round < 8; ++round) {
    if (!dos_device_exists(deviceName)) {
      return true;
    }
    if (!DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH,
                          widen(deviceName).c_str(), L"")) {
      return false;
    }
  }
  return !dos_device_exists(deviceName);
}

bool remove_dos_device_exact(
    const std::string& deviceName,
    const std::string& ntTargetPath) {
  if (!dos_device_exists(deviceName)) {
    return true;
  }
  if (ntTargetPath.empty()) {
    return remove_dos_device(deviceName);
  }
  if (!DefineDosDeviceW(
          DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE | DDD_RAW_TARGET_PATH,
          widen(deviceName).c_str(),
          widen(ntTargetPath).c_str())) {
    return false;
  }
  return !dos_device_exists(deviceName);
}

}
