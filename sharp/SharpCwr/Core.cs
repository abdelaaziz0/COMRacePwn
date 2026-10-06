using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace SharpCwr {

public static class Json {
  public static object Parse(string text) {
    int index = 0;
    SkipWs(text, ref index);
    object value = ParseValue(text, ref index);
    SkipWs(text, ref index);
    if (index != text.Length) throw new FormatException("trailing JSON data at byte " + index);
    return value;
  }

  private static void SkipWs(string t, ref int i) {
    while (i < t.Length && " \t\r\n".IndexOf(t[i]) >= 0) i++;
  }

  private static object ParseValue(string t, ref int i) {
    if (i >= t.Length) throw new FormatException("unexpected end of JSON");
    char c = t[i];
    if (c == '{') return ParseObject(t, ref i);
    if (c == '[') return ParseArray(t, ref i);
    if (c == '"') return ParseString(t, ref i);
    if (c == 't') { Expect(t, ref i, "true"); return true; }
    if (c == 'f') { Expect(t, ref i, "false"); return false; }
    if (c == 'n') { Expect(t, ref i, "null"); return null; }
    return ParseNumber(t, ref i);
  }

  private static void Expect(string t, ref int i, string word) {
    if (i + word.Length > t.Length ||
        t.Substring(i, word.Length) != word) {
      throw new FormatException("invalid JSON literal at byte " + i);
    }
    i += word.Length;
  }

  private static Dictionary<string, object> ParseObject(string t, ref int i) {
    i++;
    var result = new Dictionary<string, object>(StringComparer.Ordinal);
    SkipWs(t, ref i);
    if (i < t.Length && t[i] == '}') { i++; return result; }
    for (;;) {
      SkipWs(t, ref i);
      if (i >= t.Length || t[i] != '"') throw new FormatException("expected key at byte " + i);
      string key = ParseString(t, ref i);
      SkipWs(t, ref i);
      if (i >= t.Length || t[i] != ':') throw new FormatException("expected ':' at byte " + i);
      i++;
      SkipWs(t, ref i);
      result[key] = ParseValue(t, ref i);
      SkipWs(t, ref i);
      if (i < t.Length && t[i] == ',') { i++; continue; }
      if (i < t.Length && t[i] == '}') { i++; return result; }
      throw new FormatException("expected ',' or '}' at byte " + i);
    }
  }

  private static List<object> ParseArray(string t, ref int i) {
    i++;
    var result = new List<object>();
    SkipWs(t, ref i);
    if (i < t.Length && t[i] == ']') { i++; return result; }
    for (;;) {
      SkipWs(t, ref i);
      result.Add(ParseValue(t, ref i));
      SkipWs(t, ref i);
      if (i < t.Length && t[i] == ',') { i++; continue; }
      if (i < t.Length && t[i] == ']') { i++; return result; }
      throw new FormatException("expected ',' or ']' at byte " + i);
    }
  }

  private static string ParseString(string t, ref int i) {
    i++;
    var sb = new StringBuilder();
    while (i < t.Length && t[i] != '"') {
      char c = t[i];
      if (c == '\\') {
        i++;
        if (i >= t.Length) throw new FormatException("bad escape");
        char e = t[i];
        switch (e) {
          case '"': sb.Append('"'); break;
          case '\\': sb.Append('\\'); break;
          case '/': sb.Append('/'); break;
          case 'b': sb.Append('\b'); break;
          case 'f': sb.Append('\f'); break;
          case 'n': sb.Append('\n'); break;
          case 'r': sb.Append('\r'); break;
          case 't': sb.Append('\t'); break;
          case 'u':
            if (i + 4 >= t.Length) throw new FormatException("bad unicode escape");
            sb.Append((char)Convert.ToInt32(t.Substring(i + 1, 4), 16));
            i += 4;
            break;
          default: throw new FormatException("bad escape '\\" + e + "'");
        }
        i++;
      } else {
        sb.Append(c);
        i++;
      }
    }
    if (i >= t.Length) throw new FormatException("unterminated string");
    i++;
    return sb.ToString();
  }

  private static double ParseNumber(string t, ref int i) {
    int start = i;
    while (i < t.Length && "-+.eE0123456789".IndexOf(t[i]) >= 0) i++;
    if (i == start) throw new FormatException("invalid JSON value at byte " + i);
    double parsed;
    if (!double.TryParse(
            t.Substring(start, i - start),
            NumberStyles.Float,
            CultureInfo.InvariantCulture,
            out parsed)) {
      throw new FormatException("invalid number at byte " + start);
    }
    return parsed;
  }
}

public sealed class TargetDefinition {
  public string Name = "";
  public string Description = "";
  public string Clsid = "";
  public string Iid = "";
  public string Invoker = "idispatch";
  public string Method = "";
  public string DefaultTarget = "";
  public string DefaultWorkspace = "";
  public string Content = "CWR controlled content";
  public string SideEffectLevel = "unknown";
  public bool TargetRequired;
  public bool RetrySafe;
  public int MaxRecommendedAttempts = 1;
  public long MinOsBuild;
  public long MaxOsBuild;
  public long MinOsRevision;
  public long MaxOsRevision;
  public string SourcePath = "";

  public sealed class MethodArg {
    public string Name = "arg";
    public string Type = "string";
    public string Value = "";
    public bool AttackerControlled;
  }

  public readonly List<MethodArg> MethodArgs = new List<MethodArg>();
  public int AttackerControlledPathArg;

  public bool IsUngated {
    get { return MinOsBuild == 0 && MaxOsBuild == 0; }
  }
}

public static class Targets {
  public static string ModuleId(string path) {
    var root = Json.Parse(File.ReadAllText(path)) as Dictionary<string, object>;
    if (root == null) throw new FormatException("target module is not a JSON object: " + path);
    return String(root, "id");
  }

  public static TargetDefinition LoadModule(string path, string actionKey, string variantId) {
    var root = Json.Parse(File.ReadAllText(path)) as Dictionary<string, object>;
    if (root == null) throw new FormatException("target module is not a JSON object: " + path);
    string schema = String(root, "schema");
    if (schema != "cwr.target.v1") {
      throw new FormatException("unsupported target-module schema: " + schema);
    }
    return SelectVariant(root, path, actionKey, variantId);
  }

  public static TargetDefinition LoadModuleById(
      string path, string moduleId, string actionKey, string variantId) {
    var root = Json.Parse(File.ReadAllText(path)) as Dictionary<string, object>;
    if (root == null) throw new FormatException("target module is not a JSON object: " + path);
    string schema = String(root, "schema");
    if (schema != "cwr.target.v1") {
      throw new FormatException("unsupported target-module schema: " + schema);
    }
    if (String(root, "id") != moduleId) return null;
    return SelectVariant(root, path, actionKey, variantId);
  }

  private static TargetDefinition SelectVariant(
      Dictionary<string, object> root, string path, string actionKey, string variantId) {
    var variants = Array(root, "variants");
    if (variants == null || variants.Count == 0) {
      throw new FormatException("target module has no variants: " + path);
    }
    foreach (object item in variants) {
      var variant = item as Dictionary<string, object>;
      if (variant == null) continue;
      string id = String(variant, "id");
      if (id == null) continue;
      if (variantId.Length > 0 && id != variantId) continue;
      var actions = Item(variant, "actions") as Dictionary<string, object>;
      if (actions == null) continue;
      var body = Item(actions, actionKey) as Dictionary<string, object>;
      if (body == null) continue;
      var definition = ParseDefinition(body);
      definition.Name = String(variant, "product", "variant " + id);
      definition.SourcePath = path;
      return definition;
    }
    throw new InvalidOperationException(
        "no variant" + (variantId.Length > 0 ? " '" + variantId + "'" : "") +
        " implements action '" + actionKey + "': " + path);
  }

  private static TargetDefinition ParseDefinition(Dictionary<string, object> body) {
    var d = new TargetDefinition();
    d.Name = String(body, "name", d.Name);
    d.Description = String(body, "description", "");
    d.Clsid = String(body, "clsid", "");
    d.Iid = String(body, "iid", "");
    d.Invoker = String(body, "invoker", d.Invoker);
    d.Method = String(body, "method", null) ?? "";
    d.DefaultTarget = String(body, "default_target", "");
    d.DefaultWorkspace = String(body, "default_workspace", "");
    d.Content = String(body, "content", d.Content);
    d.TargetRequired = Bool(body, "target_required", d.TargetRequired);
    var args = Array(body, "method_args");
    if (args != null) {
      int index = 0;
      foreach (object item in args) {
        var argObject = item as Dictionary<string, object>;
        if (argObject == null) continue;
        var arg = new TargetDefinition.MethodArg();
        arg.Name = String(argObject, "name", "arg" + index);
        arg.Type = String(argObject, "type", "string");
        arg.Value = String(argObject, "value", "");
        arg.AttackerControlled = Bool(argObject, "attacker_controlled", false);
        d.MethodArgs.Add(arg);
        index++;
      }
    }
    var explicitIndex = Item(body, "attacker_controlled_path_arg");
    if (explicitIndex is double) {
      d.AttackerControlledPathArg = (int)(double)explicitIndex;
    } else {
      for (int i = 0; i < d.MethodArgs.Count; ++i) {
        if (d.MethodArgs[i].AttackerControlled) {
          d.AttackerControlledPathArg = i;
          break;
        }
      }
    }
    var operation = Item(body, "operation") as Dictionary<string, object>;
    if (operation != null) {
      d.RetrySafe = Bool(operation, "retry_safe", d.RetrySafe);
      var max = Item(operation, "max_recommended_attempts");
      if (max is double) d.MaxRecommendedAttempts = (int)(double)max;
      d.SideEffectLevel = String(operation, "side_effect_level", d.SideEffectLevel);
    }
    d.MinOsBuild = Long(body, "min_os_build", 0);
    d.MaxOsBuild = Long(body, "max_os_build", 0);
    d.MinOsRevision = Long(body, "min_os_revision", 0);
    d.MaxOsRevision = Long(body, "max_os_revision", 0);
    if (d.MinOsBuild != 0 && d.MaxOsBuild != 0 && d.MinOsBuild > d.MaxOsBuild) {
      throw new FormatException("min_os_build must not exceed max_os_build");
    }
    if (d.MinOsBuild != 0 && d.MinOsBuild == d.MaxOsBuild &&
        d.MinOsRevision != 0 && d.MaxOsRevision != 0 &&
        d.MinOsRevision > d.MaxOsRevision) {
      throw new FormatException("min_os_revision must not exceed max_os_revision");
    }
    if (d.MethodArgs.Count == 0) {
      throw new FormatException("target definition must define method_args");
    }
    if (d.AttackerControlledPathArg >= d.MethodArgs.Count) {
      throw new FormatException("attacker_controlled_path_arg is outside method_args");
    }
    if (d.MethodArgs[d.AttackerControlledPathArg].Type != "path") {
      throw new FormatException("attacker-controlled argument should use type \"path\"");
    }
    return d;
  }

  public static string String(Dictionary<string, object> o, string key) {
    object v;
    if (o.TryGetValue(key, out v) && v is string) return (string)v;
    return null;
  }

  public static string String(Dictionary<string, object> o, string key, string fallback) {
    string v = String(o, key);
    return v ?? fallback;
  }

  public static bool Bool(Dictionary<string, object> o, string key, bool fallback) {
    object v;
    if (o.TryGetValue(key, out v) && v is bool) return (bool)v;
    return fallback;
  }

  public static long Long(Dictionary<string, object> o, string key, long fallback) {
    object v;
    if (o.TryGetValue(key, out v) && v is double) return (long)(double)v;
    return fallback;
  }

  public static List<object> Array(Dictionary<string, object> o, string key) {
    object v;
    if (o.TryGetValue(key, out v) && v is List<object>) return (List<object>)v;
    return null;
  }

  public static object Item(Dictionary<string, object> o, string key) {
    object v;
    return o.TryGetValue(key, out v) ? v : null;
  }
}

public static class BuildGate {
  public static string HostBuild() {
    try {
      using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
          @"SOFTWARE\Microsoft\Windows NT\CurrentVersion")) {
        if (key == null) return "";
        var major = key.GetValue("CurrentMajorVersionNumber");
        var minor = key.GetValue("CurrentMinorVersionNumber");
        var build = key.GetValue("CurrentBuildNumber") as string;
        var ubr = key.GetValue("UBR");
        if (major is int && minor is int && build != null) {
          string result = (int)major + "." + (int)minor + "." + build;
          if (ubr is int) result += "." + (int)ubr;
          return result;
        }
        return "";
      }
    } catch {
      return "";
    }
  }

  public static string RefusalReason(TargetDefinition d, string build) {
    if (d.IsUngated) return null;
    long parsedBuild;
    long parsedRevision;
    bool verified = TryParse(build, out parsedBuild, out parsedRevision);
    if (!verified) {
      return "host OS build could not be determined or parsed ('" +
             (build.Length == 0 ? "unknown" : build) +
             "'); refusing a build-gated definition";
    }
    bool outOfRange =
        (d.MinOsBuild != 0 &&
         (parsedBuild < d.MinOsBuild ||
          (parsedBuild == d.MinOsBuild && d.MinOsRevision != 0 &&
           parsedRevision < d.MinOsRevision))) ||
        (d.MaxOsBuild != 0 &&
         (parsedBuild > d.MaxOsBuild ||
          (parsedBuild == d.MaxOsBuild && d.MaxOsRevision != 0 &&
           parsedRevision > d.MaxOsRevision)));
    if (!outOfRange) return null;
    var bounds = new StringBuilder();
    if (d.MinOsBuild != 0) {
      bounds.Append("min ").Append(d.MinOsBuild);
      if (d.MinOsRevision != 0) bounds.Append('.').Append(d.MinOsRevision);
    }
    if (d.MaxOsBuild != 0) {
      if (bounds.Length > 0) bounds.Append(", ");
      bounds.Append("max ").Append(d.MaxOsBuild);
      if (d.MaxOsRevision != 0) bounds.Append('.').Append(d.MaxOsRevision);
    }
    return "host OS build " + build +
           " is outside the target definition's supported build range (" +
           bounds + ")";
  }

  private static bool TryParse(string build, out long parsedBuild, out long parsedRevision) {
    parsedBuild = 0;
    parsedRevision = 0;
    if (build.Length == 0) return false;
    var parts = build.Split('.');
    if (parts.Length < 3) return false;
    long b;
    if (!long.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out b)) return false;
    parsedBuild = b;
    if (parts.Length > 3) {
      long r;
      if (!long.TryParse(parts[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return false;
      parsedRevision = r;
    }
    return true;
  }
}

public sealed class ResolvedArg {
  public string Name;
  public string Type;
  public string Value;
}

public sealed class ResolvedRun {
  public string Workspace;
  public string TargetPath;
  public string TargetDirectory;
  public string TargetFileName;
  public string SafeDirectory;
  public string BaitPath;
  public string Content;
  public List<ResolvedArg> Arguments = new List<ResolvedArg>();
}

public static class Plan {
  public static ResolvedRun Resolve(
      TargetDefinition target, string workspace, string targetPath,
      string content, bool checkReopen, string payloadPath) {
    var run = new ResolvedRun();
    run.Workspace = workspace.Length > 0
        ? Path.GetFullPath(workspace)
        : (target.DefaultWorkspace.Length > 0
               ? target.DefaultWorkspace
               : NewRandomWorkspace());
    if (checkReopen) {
      if (targetPath.Length > 0) {
        throw new InvalidOperationException(
            "check derives its destination inside the controlled workspace; --dest is not accepted");
      }
      string checkFileName = Path.GetFileName(target.DefaultTarget ?? "");
      if (checkFileName.Length == 0 || checkFileName == "." || checkFileName == "..") {
        checkFileName = "reopen-check.txt";
      }
      run.TargetPath = Path.Combine(Path.Combine(run.Workspace, "reopen-check"), checkFileName);
    } else if (target.TargetRequired || targetPath.Length > 0) {
      if (targetPath.Length == 0) {
        throw new InvalidOperationException("this target variant requires --dest <approved-path>");
      }
      run.TargetPath = Path.GetFullPath(targetPath);
    } else {
      run.TargetPath = target.DefaultTarget;
    }
    if (run.TargetPath == null || run.TargetPath.Length == 0) {
      throw new InvalidOperationException("target path cannot be empty");
    }
    run.TargetFileName = Path.GetFileName(run.TargetPath);
    if (run.TargetFileName.Length == 0) {
      throw new InvalidOperationException("target path must include a file name");
    }
    run.TargetDirectory = Path.GetDirectoryName(run.TargetPath);
    run.SafeDirectory = Path.Combine(run.Workspace, "safe");
    run.BaitPath = Path.Combine(run.SafeDirectory, run.TargetFileName);
    run.Content = content;
    if (!checkReopen) {
      string targetDirectory = Path.GetFullPath(run.TargetDirectory);
      if (string.Equals(targetDirectory, Path.GetFullPath(run.Workspace), StringComparison.OrdinalIgnoreCase) ||
          targetDirectory.StartsWith(Path.GetFullPath(run.Workspace) + "\\", StringComparison.OrdinalIgnoreCase) ||
          Path.GetFullPath(run.Workspace).StartsWith(targetDirectory + "\\", StringComparison.OrdinalIgnoreCase)) {
        throw new InvalidOperationException(
            "workspace/target path overlap (pass --allow-path-overlap on the native tool)");
      }
    }
    for (int i = 0; i < target.MethodArgs.Count; ++i) {
      var arg = new ResolvedArg();
      arg.Name = target.MethodArgs[i].Name;
      arg.Type = target.MethodArgs[i].Type;
      arg.Value = i == target.AttackerControlledPathArg
          ? run.BaitPath
          : (target.MethodArgs[i].Value ?? "")
              .Replace("{workspace}", run.Workspace)
              .Replace("{payload_path}", payloadPath);
      run.Arguments.Add(arg);
    }
    return run;
  }

  public static string NewRandomWorkspace() {
    string baseDirectory = Environment.GetEnvironmentVariable("LOCALAPPDATA");
    string directory = null;
    if (!string.IsNullOrEmpty(baseDirectory)) {
      directory = Path.Combine(baseDirectory, "Temp");
      if (!Directory.Exists(directory)) directory = null;
    }
    if (directory == null) directory = Path.GetTempPath();
    return Path.Combine(directory, Guid.NewGuid().ToString("N").Substring(0, 8));
  }
}

}
