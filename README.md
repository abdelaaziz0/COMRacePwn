# ComWriteRace

ComWriteRace is a Windows red-team tool for finding reachable COM targets and testing filesystem-race modules. It scans COM registrations, checks target modules, places file payloads, and runs target-defined DLL or script actions. Run evidence can include JSON results, payload hashes, target definitions, and race transcripts.

## Build

Build the native x64 CLI with Visual Studio C++ Build Tools and CMake 3.20 or later:

```powershell
cmake -S . -B build-x64 -A x64
cmake --build build-x64 --config Release
```

The binaries are written to `build-x64\Release\`. CMake builds `cwr.exe` and `cwr-host64.exe`.

## Run

Place target definition files (`*.cwr`) in a `targets\` directory beside `cwr.exe`, or set `--targets-dir`.

```powershell
$cwr = ".\build-x64\Release\cwr.exe"
& $cwr scan
& $cwr targets
```

Use a target ID from `cwr targets` with `info` or `check`:

```text
cwr info TARGET_ID
cwr check TARGET_ID
```

Run a target action with a file, DLL, or script payload:

```text
cwr write <target> --file <path> --dest <destination>
cwr exec <target> --dll <path>
cwr exec <target> --script <path>
```

`scan` checks installed target variants. `check` validates activation and controlled path re-resolution. `write` places exact file bytes at the destination. `exec` uses an execution capability defined by the target module. `auto` checks installed targets and runs the best reachable variant.

Use `--dry-run` to validate a run without invoking COM or changing files. Runs save evidence under a randomized temporary workspace by default. Set `--workspace <path>` to choose a workspace, `--output <file>` to write result JSON, or `--no-evidence` to skip evidence files. Run `cwr --help` for all commands and options.

Exit codes: `0` success, `1` invalid input, `2` requested outcome not established.

## SharpCwr

`sharp\SharpCwr` is a C# 5 / .NET Framework 4.0 port for in-process use. It supports `auto`, `targets`, `info`, `check`, and `write` with IDispatch and the mount-point junction primitive. DLL and script execution, other swap primitives, and evidence bundles are available in the native CLI.

Build it with the .NET Framework compiler from `sharp\SharpCwr`:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /t:exe /out:SharpCwr.exe /optimize+ /langversion:5 Program.cs Core.cs Engine.cs
```
