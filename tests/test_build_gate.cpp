#include "comrace/runner.hpp"
#include "comrace/target_definition.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>

namespace {

using comrace::BuildGateDecision;
using comrace::TargetDefinition;
using comrace::target_build_gate;
using comrace::target_build_supported;

void test_no_gate() {
  TargetDefinition definition;
  assert(target_build_gate(definition, "10.0.19045.4291") ==
         BuildGateDecision::NoGate);
  assert(target_build_gate(definition, "") == BuildGateDecision::NoGate);
  assert(target_build_gate(definition, "garbage") == BuildGateDecision::NoGate);
  assert(target_build_supported(definition, ""));
}

void test_unverifiable_fails_closed() {
  TargetDefinition minOnly;
  minOnly.minOsBuild = 19045;
  assert(target_build_gate(minOnly, "") == BuildGateDecision::Unverifiable);
  assert(target_build_gate(minOnly, "garbage") ==
         BuildGateDecision::Unverifiable);
  assert(target_build_gate(minOnly, "10.0") == BuildGateDecision::Unverifiable);
  assert(target_build_gate(minOnly, "10.0.abc") ==
         BuildGateDecision::Unverifiable);
  TargetDefinition range;
  range.minOsBuild = 19041;
  range.maxOsBuild = 19045;
  assert(target_build_gate(range, "10.0.19043.xy") ==
         BuildGateDecision::Unverifiable);
  assert(target_build_gate(range, "..") == BuildGateDecision::Unverifiable);
  assert(!target_build_supported(minOnly, ""));
  assert(!target_build_supported(minOnly, "garbage"));
}

void test_min_only() {
  TargetDefinition minOnly;
  minOnly.minOsBuild = 19045;
  assert(target_build_gate(minOnly, "10.0.19045.4291") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(minOnly, "10.0.19046") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(minOnly, "10.0.22631") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(minOnly, "10.0.19044") ==
         BuildGateDecision::OutOfRange);
  assert(!target_build_supported(minOnly, "6.1.7601"));
}

void test_max_only() {
  TargetDefinition maxOnly;
  maxOnly.maxOsBuild = 19045;
  assert(target_build_gate(maxOnly, "10.0.19045") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(maxOnly, "10.0.19044.999") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(maxOnly, "10.0.26100") ==
         BuildGateDecision::OutOfRange);
  assert(!target_build_supported(maxOnly, "10.0.26100.1742"));
}

void test_build_range() {
  TargetDefinition range;
  range.minOsBuild = 19041;
  range.maxOsBuild = 19045;
  assert(target_build_gate(range, "10.0.19043.546") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(range, "10.0.19041") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(range, "10.0.19045") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(range, "6.1.7601") ==
         BuildGateDecision::OutOfRange);
  assert(target_build_gate(range, "10.0.26100") ==
         BuildGateDecision::OutOfRange);
}

void test_revision_refinement() {
  TargetDefinition exactRevision;
  exactRevision.minOsBuild = 19045;
  exactRevision.maxOsBuild = 19045;
  exactRevision.minOsRevision = 4291;
  exactRevision.maxOsRevision = 4291;
  assert(target_build_gate(exactRevision, "10.0.19045.4291") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(exactRevision, "10.0.19045.3000") ==
         BuildGateDecision::OutOfRange);
  assert(target_build_gate(exactRevision, "10.0.19045") ==
         BuildGateDecision::OutOfRange);

  TargetDefinition minRevOpen;
  minRevOpen.minOsBuild = 26100;
  minRevOpen.minOsRevision = 1742;
  assert(target_build_gate(minRevOpen, "10.0.26100.1741") ==
         BuildGateDecision::OutOfRange);
  assert(target_build_gate(minRevOpen, "10.0.26100.1742") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(minRevOpen, "10.0.26100.9999") ==
         BuildGateDecision::Supported);

  TargetDefinition maxRevOpen;
  maxRevOpen.maxOsBuild = 19045;
  maxRevOpen.maxOsRevision = 3000;
  assert(target_build_gate(maxRevOpen, "10.0.19045.3000") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(maxRevOpen, "10.0.19045.3001") ==
         BuildGateDecision::OutOfRange);

  TargetDefinition crossBuild;
  crossBuild.minOsBuild = 19044;
  crossBuild.maxOsBuild = 19045;
  assert(target_build_gate(crossBuild, "10.0.19044.1") ==
         BuildGateDecision::Supported);
  assert(target_build_gate(crossBuild, "10.0.19045.0") ==
         BuildGateDecision::Supported);
}

void test_workspace_invariants() {
  const std::string first = comrace::new_workspace_platform();
  const std::string second = comrace::new_workspace_platform();
  assert(first != second);
  assert(!first.empty());
  const std::string firstLeaf =
      std::filesystem::path(first).filename().string();
  const std::string secondLeaf =
      std::filesystem::path(second).filename().string();
  assert(firstLeaf.size() == 8);
  assert(secondLeaf.size() == 8);
  assert(std::filesystem::exists(
      std::filesystem::path(first).parent_path()));
  assert(comrace::default_workspace_platform() ==
         comrace::default_workspace_platform());
  assert(comrace::new_workspace_platform() !=
         comrace::default_workspace_platform());
}

#ifdef _WIN32
void test_relative_workspace_overlap_is_rejected() {
  const std::filesystem::path workspace =
      std::filesystem::current_path() / "cwr-relative-overlap-test";
  comrace::RunConfig config;
  config.workspace = "cwr-relative-overlap-test";
  config.targetPath = (workspace / "target.bin").string();

  bool rejected = false;
  try {
    (void)comrace::resolve_run(config);
  } catch (const std::runtime_error&) {
    rejected = true;
  }
  assert(rejected);
}
#endif

}

int main() {
  test_no_gate();
  test_unverifiable_fails_closed();
  test_min_only();
  test_max_only();
  test_build_range();
  test_revision_refinement();
  test_workspace_invariants();
#ifdef _WIN32
  test_relative_workspace_overlap_is_rejected();
#endif
  std::puts("comrace_tests: all cases pass");
  return 0;
}
