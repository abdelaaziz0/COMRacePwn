#include "comrace/discovery.hpp"

#include "comrace/json_output.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace comrace {
namespace {

struct TraceEvent {
  std::size_t sequence = 0;
  std::string processName;
  unsigned long processId = 0;
  unsigned long threadId = 0;
  std::string operation;
  std::string path;
  std::string result;
  std::string detail;
  std::string user;
};

struct EventFlags {
  bool fileEvent = false;
  bool inspect = false;
  bool open = false;
  bool realOpen = false;
  bool probe = false;
  bool succeeded = false;
  bool notFound = false;
  bool close = false;
  bool write = false;
  bool remove = false;
  bool rename = false;
  bool read = false;
  bool load = false;
};

struct CandidateAccumulator {
  struct SequenceState {
    bool openSeen = false;
    bool closeAfterOpenSeen = false;
  };

  DiscoveryCandidate candidate;
  std::set<std::string> uniqueOperations;
  SequenceState sequence;
  std::map<unsigned long, SequenceState> threadSequences;
  std::size_t firstInspect = std::numeric_limits<std::size_t>::max();
  std::size_t firstEffect = std::numeric_limits<std::size_t>::max();
  std::size_t successfulEvents = 0;
  bool hasWrite = false;
  bool hasDelete = false;
  bool hasRename = false;
  bool hasRead = false;
  bool hasLoad = false;
  bool attemptedEffect = false;
};

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool contains(const std::string& value, std::string_view needle) {
  return value.find(needle) != std::string::npos;
}

std::string normalize_path(std::string value) {
  std::replace(value.begin(), value.end(), '/', '\\');
  value = lower_ascii(std::move(value));
  if (value.rfind("\\\\?\\", 0) == 0) {
    value.erase(0, 4);
  }
  while (value.size() > 3 && value.back() == '\\') {
    value.pop_back();
  }
  return value;
}

bool path_is_inside(const std::string& path, const std::string& root) {
  const std::string normalizedPath = normalize_path(path);
  const std::string normalizedRoot = normalize_path(root);
  if (normalizedRoot.empty()) {
    return false;
  }
  if (normalizedPath == normalizedRoot) {
    return true;
  }
  return normalizedPath.size() > normalizedRoot.size() &&
      normalizedPath.compare(0, normalizedRoot.size(), normalizedRoot) == 0 &&
      normalizedPath[normalizedRoot.size()] == '\\';
}

bool looks_like_file_path(const std::string& path) {
  if (path.size() >= 3 &&
      std::isalpha(static_cast<unsigned char>(path[0])) &&
      path[1] == ':' &&
      (path[2] == '\\' || path[2] == '/')) {
    return true;
  }
  return path.rfind("\\\\", 0) == 0 ||
      path.rfind("\\Device\\", 0) == 0 ||
      path.rfind("\\??\\", 0) == 0;
}

void append_utf8(std::string& out, std::uint32_t codepoint) {
  if (codepoint <= 0x7F) {
    out.push_back(static_cast<char>(codepoint));
  } else if (codepoint <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
  } else if (codepoint <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
  }
}

std::string decode_utf16(const std::string& bytes, bool bigEndian) {
  if ((bytes.size() - 2) % 2 != 0) {
    throw std::runtime_error("UTF-16 trace has an odd byte count");
  }

  auto unit_at = [&](std::size_t offset) {
    const auto first = static_cast<unsigned char>(bytes[offset]);
    const auto second = static_cast<unsigned char>(bytes[offset + 1]);
    return static_cast<std::uint16_t>(
        bigEndian ? (first << 8) | second : (second << 8) | first);
  };

  std::string out;
  for (std::size_t i = 2; i < bytes.size(); i += 2) {
    std::uint32_t codepoint = unit_at(i);
    if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
      if (i + 3 >= bytes.size()) {
        throw std::runtime_error("UTF-16 trace ends with an unpaired high surrogate");
      }
      const std::uint32_t low = unit_at(i + 2);
      if (low < 0xDC00 || low > 0xDFFF) {
        throw std::runtime_error("UTF-16 trace contains an invalid surrogate pair");
      }
      codepoint =
          0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
      i += 2;
    } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
      throw std::runtime_error("UTF-16 trace contains an unpaired low surrogate");
    }
    append_utf8(out, codepoint);
  }
  return out;
}

std::string read_trace_text(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("unable to open trace: " + path);
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  std::string bytes = buffer.str();

  if (bytes.size() >= 2 &&
      static_cast<unsigned char>(bytes[0]) == 0xFF &&
      static_cast<unsigned char>(bytes[1]) == 0xFE) {
    return decode_utf16(bytes, false);
  }
  if (bytes.size() >= 2 &&
      static_cast<unsigned char>(bytes[0]) == 0xFE &&
      static_cast<unsigned char>(bytes[1]) == 0xFF) {
    return decode_utf16(bytes, true);
  }
  if (bytes.size() >= 3 &&
      static_cast<unsigned char>(bytes[0]) == 0xEF &&
      static_cast<unsigned char>(bytes[1]) == 0xBB &&
      static_cast<unsigned char>(bytes[2]) == 0xBF) {
    bytes.erase(0, 3);
  }
  return bytes;
}

char detect_delimiter(std::string_view text) {
  std::size_t comma = 0;
  std::size_t semicolon = 0;
  std::size_t tab = 0;
  bool quoted = false;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (c == '"') {
      if (quoted && i + 1 < text.size() && text[i + 1] == '"') {
        ++i;
      } else {
        quoted = !quoted;
      }
      continue;
    }
    if (!quoted && (c == '\r' || c == '\n')) {
      break;
    }
    if (!quoted && c == ',') {
      ++comma;
    } else if (!quoted && c == ';') {
      ++semicolon;
    } else if (!quoted && c == '\t') {
      ++tab;
    }
  }
  if (tab > comma && tab > semicolon) {
    return '\t';
  }
  return semicolon > comma ? ';' : ',';
}

std::vector<std::vector<std::string>> parse_csv(
    const std::string& text,
    char delimiter) {
  std::vector<std::vector<std::string>> rows;
  std::vector<std::string> row;
  std::string field;
  bool quoted = false;

  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (quoted) {
      if (c == '"') {
        if (i + 1 < text.size() && text[i + 1] == '"') {
          field.push_back('"');
          ++i;
        } else {
          quoted = false;
        }
      } else {
        field.push_back(c);
      }
      continue;
    }

    if (c == '"' && field.empty()) {
      quoted = true;
    } else if (c == delimiter) {
      row.push_back(std::move(field));
      field.clear();
    } else if (c == '\r' || c == '\n') {
      if (c == '\r' && i + 1 < text.size() && text[i + 1] == '\n') {
        ++i;
      }
      row.push_back(std::move(field));
      field.clear();
      if (!(row.size() == 1 && row.front().empty())) {
        rows.push_back(std::move(row));
      }
      row.clear();
    } else {
      field.push_back(c);
    }
  }

  if (quoted) {
    throw std::runtime_error("trace CSV contains an unterminated quoted field");
  }
  if (!field.empty() || !row.empty()) {
    row.push_back(std::move(field));
    rows.push_back(std::move(row));
  }
  return rows;
}

std::string header_key(std::string value) {
  value = lower_ascii(std::move(value));
  value.erase(
      std::remove_if(value.begin(), value.end(), [](unsigned char c) {
        return !std::isalnum(c);
      }),
      value.end());
  return value;
}

std::size_t find_column(
    const std::map<std::string, std::size_t>& columns,
    std::initializer_list<const char*> names,
    bool required) {
  for (const char* name : names) {
    const auto it = columns.find(name);
    if (it != columns.end()) {
      return it->second;
    }
  }
  if (required) {
    throw std::runtime_error(
        "trace CSV is missing a required Process Monitor column");
  }
  return std::numeric_limits<std::size_t>::max();
}

std::string field_at(
    const std::vector<std::string>& row,
    std::size_t index) {
  if (index == std::numeric_limits<std::size_t>::max() ||
      index >= row.size()) {
    return {};
  }
  return row[index];
}

unsigned long parse_pid(const std::string& value) {
  if (value.empty()) {
    return 0;
  }
  try {
    std::size_t consumed = 0;
    const unsigned long parsed = std::stoul(value, &consumed, 10);
    return consumed == value.size() ? parsed : 0;
  } catch (...) {
    return 0;
  }
}

std::vector<TraceEvent> rows_to_events(
    const std::vector<std::vector<std::string>>& rows) {
  if (rows.empty()) {
    throw std::runtime_error("trace CSV is empty");
  }

  std::map<std::string, std::size_t> columns;
  for (std::size_t i = 0; i < rows.front().size(); ++i) {
    columns.emplace(header_key(rows.front()[i]), i);
  }

  const std::size_t processColumn =
      find_column(columns, {"processname", "process"}, false);
  const std::size_t pidColumn =
      find_column(columns, {"pid", "processid"}, false);
  const std::size_t operationColumn =
      find_column(columns, {"operation"}, true);
  const std::size_t tidColumn =
      find_column(columns, {"tid", "threadid"}, false);
  const std::size_t pathColumn =
      find_column(columns, {"path"}, true);
  const std::size_t resultColumn =
      find_column(columns, {"result"}, false);
  const std::size_t detailColumn =
      find_column(columns, {"detail", "details"}, false);
  const std::size_t userColumn =
      find_column(columns, {"user", "username"}, false);

  std::vector<TraceEvent> events;
  events.reserve(rows.size() - 1);
  for (std::size_t i = 1; i < rows.size(); ++i) {
    TraceEvent event;
    event.sequence = i - 1;
    event.processName = field_at(rows[i], processColumn);
    event.processId = parse_pid(field_at(rows[i], pidColumn));
    event.threadId = parse_pid(field_at(rows[i], tidColumn));
    event.operation = field_at(rows[i], operationColumn);
    event.path = field_at(rows[i], pathColumn);
    event.result = field_at(rows[i], resultColumn);
    event.detail = field_at(rows[i], detailColumn);
    event.user = field_at(rows[i], userColumn);
    if (!event.operation.empty() && !event.path.empty()) {
      events.push_back(std::move(event));
    }
  }
  return events;
}

EventFlags classify_event(const TraceEvent& event) {
  EventFlags flags;
  const std::string operation = lower_ascii(event.operation);
  const std::string detail = lower_ascii(event.detail);

  if (operation.rfind("reg", 0) == 0 || !looks_like_file_path(event.path)) {
    return flags;
  }
  flags.fileEvent = true;
  const std::string result = lower_ascii(event.result);
  flags.succeeded = (result == "success");
  flags.notFound =
      contains(result, "name not found") || contains(result, "path not found");
  flags.realOpen =
      contains(operation, "createfile") || contains(operation, "openfile");
  flags.probe =
      contains(operation, "queryopen") ||
      contains(operation, "getfileattributes");
  flags.open = flags.realOpen || flags.probe;
  flags.close = contains(operation, "closefile");
  flags.inspect =
      flags.open ||
      contains(operation, "query") ||
      contains(operation, "getfileattributes");
  flags.remove =
      contains(operation, "delete") ||
      contains(operation, "disposition");
  flags.rename = contains(operation, "rename");
  flags.write =
      contains(operation, "writefile") ||
      contains(operation, "setendoffile") ||
      contains(operation, "setallocation") ||
      (contains(operation, "createfile") &&
       (contains(detail, "generic write") ||
        contains(detail, "write data") ||
        contains(detail, "append data") ||
        contains(detail, "delete")));
  flags.read = contains(operation, "readfile");
  flags.load = contains(operation, "load image");
  return flags;
}

bool privileged_identity(const std::string& user) {
  const std::string value = lower_ascii(user);
  return value == "nt authority\\system" || value == "system" ||
      value == "s-1-5-18" ||
      value == "nt service\\trustedinstaller" ||
      value == "trustedinstaller";
}

bool service_identity(const std::string& user) {
  const std::string value = lower_ascii(user);
  return value == "nt authority\\local service" ||
      value == "local service" || value == "localservice" ||
      value == "nt authority\\network service" ||
      value == "network service" || value == "networkservice";
}

void add_reason(
    CandidateAccumulator& candidate,
    int points,
    const std::string& reason) {
  candidate.candidate.score += points;
  candidate.candidate.reasons.push_back(reason);
}

DiscoveredPrimitive choose_primitive(const CandidateAccumulator& candidate) {
  if (candidate.hasDelete) {
    return DiscoveredPrimitive::FileDelete;
  }
  if (candidate.hasRename) {
    return DiscoveredPrimitive::FileMoveReplace;
  }
  if (candidate.hasLoad) {
    return DiscoveredPrimitive::DllLoad;
  }
  if (candidate.hasWrite) {
    return DiscoveredPrimitive::FileWrite;
  }
  if (candidate.hasRead) {
    return DiscoveredPrimitive::FileRead;
  }
  return DiscoveredPrimitive::DoubleOpen;
}

std::string confidence_for_score(int score) {
  if (score >= 70) {
    return "high";
  }
  if (score >= 45) {
    return "medium";
  }
  return "low";
}

void write_string_array(
    std::ostream& out,
    const std::vector<std::string>& values) {
  out << '[';
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      out << ',';
    }
    json_output::write_string(out, values[i]);
  }
  out << ']';
}

}

std::string to_string(DiscoveredPrimitive primitive) {
  switch (primitive) {
    case DiscoveredPrimitive::DoubleOpen:
      return "double_open";
    case DiscoveredPrimitive::FileWrite:
      return "file_write";
    case DiscoveredPrimitive::FileDelete:
      return "file_delete";
    case DiscoveredPrimitive::FileMoveReplace:
      return "file_move_replace";
    case DiscoveredPrimitive::FileRead:
      return "file_read";
    case DiscoveredPrimitive::DllLoad:
      return "dll_load";
  }
  return "unknown";
}

DiscoveryReport analyze_procmon_csv(
    const std::string& path,
    const DiscoveryOptions& options) {
  if (options.minimumScore < 0 || options.minimumScore > 100) {
    throw std::runtime_error("minimum discovery score must be between 0 and 100");
  }

  const std::string text = read_trace_text(path);
  const auto rows = parse_csv(text, detect_delimiter(text));
  const auto events = rows_to_events(rows);

  DiscoveryReport report;
  report.tracePath = path;
  report.inputRecordCount = events.size();

  std::map<std::string, CandidateAccumulator> groups;
  const std::string processFilter = lower_ascii(options.processFilter);

  for (const TraceEvent& event : events) {
    if (!processFilter.empty() &&
        lower_ascii(event.processName) != processFilter) {
      continue;
    }

    const EventFlags flags = classify_event(event);
    if (!flags.fileEvent) {
      continue;
    }
    ++report.fileEventCount;

    const std::string key =
        lower_ascii(event.processName) + '\n' +
        std::to_string(event.processId) + '\n' +
        normalize_path(event.path);
    CandidateAccumulator& group = groups[key];
    if (group.candidate.eventCount == 0) {
      group.candidate.processName = event.processName;
      group.candidate.processId = event.processId;
      group.candidate.path = event.path;
      group.candidate.user = event.user;
    } else if (group.candidate.user.empty() && !event.user.empty()) {
      group.candidate.user = event.user;
    }

    ++group.candidate.eventCount;
    if (flags.open) {
      ++group.candidate.openCount;
      if (flags.realOpen && flags.succeeded) {
        ++group.candidate.successfulOpenCount;
      }
      if (flags.probe && flags.succeeded) {
        ++group.candidate.pathProbeCount;
      }
      if (flags.notFound) {
        ++group.candidate.failedResolutionCount;
      }

      if (flags.succeeded && flags.realOpen) {
        if (group.sequence.closeAfterOpenSeen) {
          group.candidate.openCloseReopenObserved = true;
        }
        group.sequence.openSeen = true;
        if (event.threadId != 0) {
          CandidateAccumulator::SequenceState& threadState =
              group.threadSequences[event.threadId];
          if (threadState.closeAfterOpenSeen) {
            group.candidate.sameThreadOpenCloseReopenObserved = true;
          }
          threadState.openSeen = true;
        }
      }
    }
    if (flags.close) {
      ++group.candidate.closeCount;
      if (group.sequence.openSeen) {
        group.sequence.closeAfterOpenSeen = true;
      }
      if (event.threadId != 0) {
        CandidateAccumulator::SequenceState& threadState =
            group.threadSequences[event.threadId];
        if (threadState.openSeen) {
          threadState.closeAfterOpenSeen = true;
        }
      }
    }
    group.uniqueOperations.insert(event.operation);
    if (flags.inspect) {
      group.firstInspect = std::min(group.firstInspect, event.sequence);
    }
    const bool effectAttempt =
        flags.write || flags.remove || flags.rename || flags.read || flags.load;
    if (effectAttempt) {
      group.attemptedEffect = true;
      ++group.candidate.attemptedEffectCount;
    }
    if (effectAttempt && flags.succeeded) {
      group.firstEffect = std::min(group.firstEffect, event.sequence);
      ++group.candidate.successfulEffectCount;
    }
    group.hasWrite = group.hasWrite || (flags.write && flags.succeeded);
    group.hasDelete = group.hasDelete || (flags.remove && flags.succeeded);
    group.hasRename = group.hasRename || (flags.rename && flags.succeeded);
    group.hasRead = group.hasRead || (flags.read && flags.succeeded);
    group.hasLoad = group.hasLoad || (flags.load && flags.succeeded);
    if (lower_ascii(event.result) == "success") {
      ++group.successfulEvents;
    }
  }

  for (auto& item : groups) {
    CandidateAccumulator& group = item.second;
    const bool hasEffect =
        group.hasWrite || group.hasDelete || group.hasRename ||
        group.hasRead || group.hasLoad;
    const bool inspectionBeforeEffect =
        group.firstInspect != std::numeric_limits<std::size_t>::max() &&
        group.firstEffect != std::numeric_limits<std::size_t>::max() &&
        group.firstInspect < group.firstEffect;

    const std::size_t successfulOpens = group.candidate.successfulOpenCount;
    const std::size_t probes = group.candidate.pathProbeCount;
    const std::size_t resolutionCount = successfulOpens + probes;
    if (resolutionCount < 2) {
      continue;
    }

    if (successfulOpens >= 2) {
      add_reason(group, 25, "same path successfully opened for a handle at least twice");
    } else if (successfulOpens >= 1 && probes >= 1) {
      add_reason(group, 22, "path probed then opened for a handle (classic validate-then-use shape)");
    } else {
      add_reason(group, 12, "same pathname resolved twice, but only via attribute probes");
    }
    if (group.candidate.failedResolutionCount > 0 && successfulOpens > 0) {
      add_reason(group, 8, "the path was absent on an early lookup, then opened successfully later");
    }
    if (group.candidate.openCloseReopenObserved) {
      add_reason(
          group,
          15,
          "successful handle open-close-open sequence appears in trace order");
    }
    if (group.candidate.sameThreadOpenCloseReopenObserved) {
      add_reason(
          group,
          10,
          "successful handle open-close-open sequence appears on the same captured thread");
    }
    if (hasEffect) {
      add_reason(group, 25, "security-relevant file operation returned SUCCESS");
    } else if (group.attemptedEffect) {
      add_reason(group, 5, "security-relevant file operation attempted but did not succeed");
    }
    if (inspectionBeforeEffect) {
      add_reason(group, 20, "inspection or open occurs before the effect");
    }
    if (!options.controlledRoot.empty() &&
        path_is_inside(group.candidate.path, options.controlledRoot)) {
      add_reason(group, 20, "path is under the supplied controlled root");
    }
    if (privileged_identity(group.candidate.user)) {
      add_reason(group, 15, "SYSTEM or TrustedInstaller identity appears in the trace");
    } else if (service_identity(group.candidate.user)) {
      add_reason(group, 8, "Windows service identity appears in the trace");
    }
    if (group.candidate.eventCount >= 4) {
      add_reason(group, 5, "four or more correlated events observed");
    }
    if (group.successfulEvents == group.candidate.eventCount &&
        group.candidate.eventCount != 0) {
      add_reason(group, 5, "all correlated operations returned SUCCESS");
    }

    group.candidate.score = std::min(group.candidate.score, 100);
    group.candidate.primitive = choose_primitive(group);
    group.candidate.confidence =
        confidence_for_score(group.candidate.score);
    group.candidate.operations.assign(
        group.uniqueOperations.begin(),
        group.uniqueOperations.end());
    ++report.candidateCountBeforeThreshold;
    if (group.candidate.score >= options.minimumScore) {
      report.candidates.push_back(std::move(group.candidate));
    }
  }

  std::sort(
      report.candidates.begin(),
      report.candidates.end(),
      [](const DiscoveryCandidate& left, const DiscoveryCandidate& right) {
        if (left.score != right.score) {
          return left.score > right.score;
        }
        if (left.processName != right.processName) {
          return left.processName < right.processName;
        }
        return left.path < right.path;
      });
  return report;
}

std::string discovery_report_json(const DiscoveryReport& report) {
  std::ostringstream out;
  out << "{\n  \"schema\":\"comwriterace.discovery.v1\",\n  \"trace\":";
  json_output::write_string(out, report.tracePath);
  out << ",\n  \"input_records\":" << report.inputRecordCount
      << ",\n  \"file_events\":" << report.fileEventCount
      << ",\n  \"candidates_before_threshold\":"
      << report.candidateCountBeforeThreshold
      << ",\n  \"candidates\":[";

  for (std::size_t i = 0; i < report.candidates.size(); ++i) {
    const DiscoveryCandidate& candidate = report.candidates[i];
    out << (i == 0 ? "\n    {" : ",\n    {");
    out << "\"process\":";
    json_output::write_string(out, candidate.processName);
    out << ",\"pid\":" << candidate.processId << ",\"user\":";
    json_output::write_string(out, candidate.user);
    out << ",\"path\":";
    json_output::write_string(out, candidate.path);
    out << ",\"primitive\":";
    json_output::write_string(out, to_string(candidate.primitive));
    out << ",\"score\":" << candidate.score
        << ",\"heuristic_confidence\":";
    json_output::write_string(out, candidate.confidence);
    out << ",\"evidence_level\":\"passive_heuristic\""
        << ",\"later_name_resolution_proven\":false";
    out << ",\"event_count\":" << candidate.eventCount
        << ",\"open_count\":" << candidate.openCount
        << ",\"successful_open_count\":" << candidate.successfulOpenCount
        << ",\"path_probe_count\":" << candidate.pathProbeCount
        << ",\"failed_resolution_count\":" << candidate.failedResolutionCount
        << ",\"close_count\":" << candidate.closeCount
        << ",\"attempted_effect_count\":" << candidate.attemptedEffectCount
        << ",\"successful_effect_count\":" << candidate.successfulEffectCount
        << ",\"open_close_reopen_observed\":"
        << (candidate.openCloseReopenObserved ? "true" : "false")
        << ",\"same_thread_open_close_reopen_observed\":"
        << (candidate.sameThreadOpenCloseReopenObserved ? "true" : "false")
        << ",\"operations\":";
    write_string_array(out, candidate.operations);
    out << ",\"reasons\":";
    write_string_array(out, candidate.reasons);
    out << '}';
  }
  if (!report.candidates.empty()) {
    out << '\n';
  }
  out << "  ]\n}\n";
  return out.str();
}

std::string discovery_report_text(const DiscoveryReport& report) {
  std::ostringstream out;
  out << "Trace: " << report.tracePath << '\n'
      << "Records parsed: " << report.inputRecordCount << '\n'
      << "Filesystem events considered: " << report.fileEventCount << '\n'
      << "Candidates before threshold: "
      << report.candidateCountBeforeThreshold << '\n'
      << "Candidates reported: " << report.candidates.size() << '\n'
      << "Evidence level: passive heuristic only; use a target module's check action for active validation\n";

  for (const DiscoveryCandidate& candidate : report.candidates) {
    out << "\n[" << candidate.score << "/100 heuristic-"
        << candidate.confidence << "] "
        << to_string(candidate.primitive) << '\n'
        << "  Process: " << candidate.processName
        << " (" << candidate.processId << ")\n"
        << "  User: " << (candidate.user.empty() ? "not captured" : candidate.user) << '\n'
        << "  Path: " << candidate.path << '\n'
        << "  Opens/events: " << candidate.openCount
        << '/' << candidate.eventCount << '\n'
        << "  Close events: " << candidate.closeCount << '\n'
        << "  Passive real-handle open-close-open evidence: "
        << (candidate.openCloseReopenObserved ? "yes" : "no")
        << " (same thread: "
        << (candidate.sameThreadOpenCloseReopenObserved ? "yes" : "no")
        << ")\n";
    for (const std::string& reason : candidate.reasons) {
      out << "  - " << reason << '\n';
    }
  }
  return out.str();
}

}
