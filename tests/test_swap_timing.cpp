#include "comrace/runner.hpp"

#include <cassert>
#include <cstdio>

int main() {
  comrace::RunConfig fixed;
  fixed.swapStartOffsetUs = 700;
  fixed.adaptiveTiming = false;
  assert(comrace::swap_start_offset_for_attempt(fixed, 1) == 700);
  assert(comrace::swap_start_offset_for_attempt(fixed, 5) == 700);

  comrace::RunConfig adaptive;
  adaptive.swapStartOffsetUs = 100;
  adaptive.adaptiveTiming = true;
  assert(comrace::swap_start_offset_for_attempt(adaptive, 1) == 100);
  assert(comrace::swap_start_offset_for_attempt(adaptive, 2) == 1100);
  assert(comrace::swap_start_offset_for_attempt(adaptive, 3) == 5100);
  assert(comrace::swap_start_offset_for_attempt(adaptive, 4) == 10100);
  assert(comrace::swap_start_offset_for_attempt(adaptive, 5) == 20100);
  assert(comrace::swap_start_offset_for_attempt(adaptive, 99) == 500100);

  std::puts("comrace_timing_tests: all cases pass");
  return 0;
}
