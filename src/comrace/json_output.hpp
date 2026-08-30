#pragma once

#include <iomanip>
#include <ostream>
#include <string_view>

namespace comrace::json_output {

inline void write_string(std::ostream& out, std::string_view value) {
  out << '"';
  for (const unsigned char c : value) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u"
              << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<unsigned>(c)
              << std::dec << std::setw(0) << std::setfill(' ');
        } else {
          out << static_cast<char>(c);
        }
        break;
    }
  }
  out << '"';
}

}  // namespace comrace::json_output
