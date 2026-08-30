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
    src/platform/windows/com_invoker.cpp
    src/platform/windows/com_inventory.cpp
    src/platform/windows/junction.cpp
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
  install(TARGETS comwriterace comwrite_host RUNTIME DESTINATION .)
else()
  install(TARGETS comwriterace RUNTIME DESTINATION .)
endif()
