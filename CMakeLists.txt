cmake_minimum_required(VERSION 3.20)

project(ComWriteRace
  VERSION 0.7.0
  DESCRIPTION "Validated COM filesystem-race operator tool"
  LANGUAGES CXX)

add_library(comrace_core
  src/comrace/cli.cpp
  src/comrace/discovery.cpp
  src/comrace/file_compare.cpp
  src/comrace/inspect.cpp
  src/comrace/inventory.cpp
  src/comrace/json.cpp
  src/comrace/runner.cpp
  src/comrace/target.cpp
  src/comrace/target_definition.cpp)

target_include_directories(comrace_core
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(comrace_core PUBLIC cxx_std_17)

if(MSVC)
  target_compile_options(comrace_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(comrace_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
  target_sources(comrace_core PRIVATE
    src/platform/windows/broker.cpp
    src/platform/windows/cfapi_bait.cpp
    src/platform/windows/com_invoker.cpp
    src/platform/windows/com_inventory.cpp
    src/platform/windows/dos_symlink.cpp
    src/platform/windows/junction.cpp
    src/platform/windows/om_symlink.cpp
    src/platform/windows/oplock.cpp
    src/platform/windows/race_sensor.cpp
    src/platform/windows/win_utils.cpp
    src/platform/windows/windows_runner.cpp)
  target_compile_definitions(comrace_core PRIVATE UNICODE _UNICODE NOMINMAX)
  target_link_libraries(comrace_core PRIVATE ole32 oleaut32 advapi32 bcrypt)
else()
  target_sources(comrace_core PRIVATE
    src/platform/stub_inventory.cpp
    src/platform/stub_runner.cpp)
endif()

add_executable(comwriterace src/main.cpp)
target_link_libraries(comwriterace PRIVATE comrace_core)
set_target_properties(comwriterace PROPERTIES OUTPUT_NAME "cwr")

enable_testing()
add_executable(comrace_tests tests/test_build_gate.cpp)
target_link_libraries(comrace_tests PRIVATE comrace_core)
target_compile_features(comrace_tests PRIVATE cxx_std_17)
if(MSVC)
  target_compile_options(comrace_tests PRIVATE /W4 /permissive-)
else()
  target_compile_options(comrace_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME build_gate_and_workspace COMMAND comrace_tests)

add_executable(comrace_timing_tests tests/test_swap_timing.cpp)
target_link_libraries(comrace_timing_tests PRIVATE comrace_core)
target_compile_features(comrace_timing_tests PRIVATE cxx_std_17)
if(MSVC)
  target_compile_options(comrace_timing_tests PRIVATE /W4 /permissive-)
else()
  target_compile_options(comrace_timing_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME adaptive_swap_timing COMMAND comrace_timing_tests)

if(WIN32)
  add_executable(comwrite_host src/host/host_main.cpp)
  target_link_libraries(comwrite_host PRIVATE comrace_core)
  target_include_directories(comwrite_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(comwrite_host PRIVATE UNICODE _UNICODE NOMINMAX)
  if(MSVC)
    target_compile_options(comwrite_host PRIVATE /W4 /permissive-)
  endif()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(comwrite_host PROPERTIES OUTPUT_NAME "cwr-host64")
  else()
    set_target_properties(comwrite_host PROPERTIES OUTPUT_NAME "cwr-host32")
  endif()
  add_executable(cwr_fixture_server tests/windows/com_fixture_server.cpp)
  target_compile_features(cwr_fixture_server PRIVATE cxx_std_17)
  target_compile_definitions(cwr_fixture_server PRIVATE UNICODE _UNICODE NOMINMAX)
  target_link_libraries(cwr_fixture_server PRIVATE ole32 oleaut32 advapi32)
  if(MSVC)
    target_compile_options(cwr_fixture_server PRIVATE /W4 /permissive-)
  endif()
  install(TARGETS comwriterace comwrite_host RUNTIME DESTINATION .)
else()
  install(TARGETS comwriterace RUNTIME DESTINATION .)
endif()
