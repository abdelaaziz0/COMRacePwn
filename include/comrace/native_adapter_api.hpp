#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>

extern "C" {

constexpr std::uint32_t COMWRITERACE_NATIVE_ADAPTER_ABI_V1 = 1;

enum ComWriteRaceNativeAdapterOperationV1 : std::uint32_t {
  COMWRITERACE_NATIVE_ADAPTER_PROBE_V1 = 1,
  COMWRITERACE_NATIVE_ADAPTER_INVOKE_V1 = 2
};

enum ComWriteRaceNativeAdapterArgumentTypeV1 : std::uint32_t {
  COMWRITERACE_NATIVE_ADAPTER_STRING_V1 = 1,
  COMWRITERACE_NATIVE_ADAPTER_PATH_V1 = 2,
  COMWRITERACE_NATIVE_ADAPTER_INT32_V1 = 3,
  COMWRITERACE_NATIVE_ADAPTER_UINT32_V1 = 4,
  COMWRITERACE_NATIVE_ADAPTER_INT64_V1 = 5,
  COMWRITERACE_NATIVE_ADAPTER_BOOLEAN_V1 = 6
};

struct ComWriteRaceNativeAdapterArgumentV1 {
  std::uint32_t size;
  std::uint32_t type;
  const wchar_t* name;
  const wchar_t* value;
};

struct ComWriteRaceNativeAdapterRequestV1 {
  std::uint32_t size;
  std::uint32_t abiVersion;
  std::uint32_t operation;
  const wchar_t* clsid;
  const wchar_t* iid;
  const wchar_t* method;
  const ComWriteRaceNativeAdapterArgumentV1* arguments;
  std::uint32_t argumentCount;
};

using ComWriteRaceNativeAdapterEntryV1 = HRESULT(WINAPI*)(
    const ComWriteRaceNativeAdapterRequestV1* request,
    wchar_t* errorBuffer,
    std::uint32_t errorBufferChars);

}

#endif
