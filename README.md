# ComWriteRace

Windows CLI for running validated COM filesystem-race target modules in
authorized environments.

## Build

Requires Visual Studio with the C++ workload and CMake.

```powershell
cmake -S . -B build-x64 -A x64
cmake --build build-x64 --config Release

cmake -S . -B build-x86 -A Win32
cmake --build build-x86 --config Release --target comwrite_host
Copy-Item build-x86\Release\cwr-host32.exe build-x64\Release\
```

The working directory needs `cwr.exe`, `cwr-host64.exe`, `cwr-host32.exe`, and
a `targets` directory containing reviewed product-specific `*.cwr` modules.

## Use

```text
cwr scan
cwr targets
cwr info <target>
cwr check <target>
cwr write <target> --file <path> --dest <approved-path>
cwr exec <target> --dll <path>
cwr exec <target> --script <path>
```

Use `--dry-run` to validate without invoking COM or changing the filesystem.
Exit codes are `0` for success, `1` for invalid input, and `2` when the requested
outcome was not established.
