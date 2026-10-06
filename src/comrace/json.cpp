#include "comrace/json.hpp"

#include <cctype>
#include <cmath>
#include <cstdlib>
#include <sstream>

namespace comrace::json {
namespace {

std::string type_name(Value::Type type) {
  switch (type) {
    case Value::Type::Null:
      return "null";
    case Value::Type::Boolean:
      return "boolean";
    case Value::Type::Number:
      return "number";
    case Value::Type::String:
      return "string";
    case Value::Type::Array:
      return "array";
    case Value::Type::Object:
      return "object";
  }
  return "unknown";
}

void append_utf8(std::string& out, unsigned codepoint) {
  if (codepoint <= 0x7F) {
    out.push_back(static_cast<char>(codepoint));
  } else if (codepoint <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | ((codepoint >> 6) & 0x1F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
  } else if (codepoint <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | ((codepoint >> 12) & 0x0F)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | ((codepoint >> 18) & 0x07)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
  }
}

unsigned hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<unsigned>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<unsigned>(c - 'a' + 10);
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<unsigned>(c - 'A' + 10);
  }
  throw ParseError("invalid JSON unicode escape");
}

class Parser {
 public:
  explicit Parser(std::string_view input) : input_(input) {}

  Value parse_document() {
    skip_ws();
    Value value = parse_value();
    skip_ws();
    if (!eof()) {
      fail("unexpected trailing data");
    }
    return value;
  }

 private:
  Value parse_value() {
    skip_ws();
    if (eof()) {
      fail("unexpected end of input");
    }

    const char c = peek();
    if (c == 'n') {
      consume_literal("null");
      return Value(nullptr);
    }
    if (c == 't') {
      consume_literal("true");
      return Value(true);
    }
    if (c == 'f') {
      consume_literal("false");
      return Value(false);
    }
    if (c == '"') {
      return Value(parse_string());
    }
    if (c == '[') {
      return Value(parse_array());
    }
    if (c == '{') {
      return Value(parse_object());
    }
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
      return Value(parse_number());
    }
    fail("unexpected character");
    return Value(nullptr);
  }

  Value::Array parse_array() {
    expect('[');
    Value::Array array;
    skip_ws();
    if (consume_if(']')) {
      return array;
    }

    while (true) {
      array.push_back(parse_value());
      skip_ws();
      if (consume_if(']')) {
        return array;
      }
      expect(',');
    }
  }

  Value::Object parse_object() {
    expect('{');
    Value::Object object;
    skip_ws();
    if (consume_if('}')) {
      return object;
    }

    while (true) {
      skip_ws();
      if (peek() != '"') {
        fail("expected object key string");
      }
      std::string key = parse_string();
      skip_ws();
      expect(':');
      Value value = parse_value();
      const auto inserted = object.emplace(std::move(key), std::move(value));
      if (!inserted.second) {
        fail("duplicate object key");
      }
      skip_ws();
      if (consume_if('}')) {
        return object;
      }
      expect(',');
    }
  }

  std::string parse_string() {
    expect('"');
    std::string out;
    while (!eof()) {
      char c = get();
      if (c == '"') {
        return out;
      }
      if (static_cast<unsigned char>(c) < 0x20) {
        fail("control character in JSON string");
      }
      if (c != '\\') {
        out.push_back(c);
        continue;
      }

      if (eof()) {
        fail("unterminated escape sequence");
      }
      const char escaped = get();
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          out.push_back(escaped);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u':
          out.append(parse_unicode_escape());
          break;
        default:
          fail("invalid escape sequence");
      }
    }
    fail("unterminated string");
    return {};
  }

  std::string parse_unicode_escape() {
    unsigned codepoint = parse_hex_quad();
    if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
      const std::size_t saved = pos_;
      if (remaining() >= 6 && input_[pos_] == '\\' && input_[pos_ + 1] == 'u') {
        pos_ += 2;
        const unsigned low = parse_hex_quad();
        if (low >= 0xDC00 && low <= 0xDFFF) {
          codepoint = 0x10000 + (((codepoint - 0xD800) << 10) | (low - 0xDC00));
        } else {
          fail("invalid JSON surrogate pair");
        }
      } else {
        pos_ = saved;
        fail("missing low surrogate in JSON unicode escape");
      }
    } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
      fail("unexpected low surrogate in JSON unicode escape");
    }

    std::string out;
    append_utf8(out, codepoint);
    return out;
  }

  unsigned parse_hex_quad() {
    if (remaining() < 4) {
      fail("short JSON unicode escape");
    }
    unsigned value = 0;
    for (int i = 0; i < 4; ++i) {
      value = (value << 4) | hex_value(get());
    }
    return value;
  }

  double parse_number() {
    const std::size_t start = pos_;
    consume_if('-');

    if (consume_if('0')) {

    } else {
      if (!consume_digits()) {
        fail("invalid JSON number");
      }
    }

    if (consume_if('.')) {
      if (!consume_digits()) {
        fail("invalid JSON fractional number");
      }
    }

    if (consume_if('e') || consume_if('E')) {
      if (!consume_if('+')) {
        consume_if('-');
      }
      if (!consume_digits()) {
        fail("invalid JSON exponent");
      }
    }

    const std::string text(input_.substr(start, pos_ - start));
    char* end = nullptr;
    const double number = std::strtod(text.c_str(), &end);
    if (end == nullptr || *end != '\0' || !std::isfinite(number)) {
      fail("invalid JSON number");
    }
    return number;
  }

  bool consume_digits() {
    const std::size_t start = pos_;
    while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) {
      ++pos_;
    }
    return pos_ != start;
  }

  void consume_literal(std::string_view literal) {
    for (char expected : literal) {
      if (eof() || get() != expected) {
        fail("invalid literal");
      }
    }
  }

  void skip_ws() {
    while (!eof()) {
      const char c = peek();
      if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
        return;
      }
      ++pos_;
    }
  }

  void expect(char expected) {
    if (eof() || get() != expected) {
      std::ostringstream message;
      message << "expected '" << expected << "'";
      fail(message.str());
    }
  }

  bool consume_if(char c) {
    if (!eof() && peek() == c) {
      ++pos_;
      return true;
    }
    return false;
  }

  char peek() const { return input_[pos_]; }

  char get() {
    if (eof()) {
      fail("unexpected end of input");
    }
    return input_[pos_++];
  }

  bool eof() const { return pos_ >= input_.size(); }

  std::size_t remaining() const {
    if (pos_ >= input_.size()) {
      return 0;
    }
    return input_.size() - pos_;
  }

  [[noreturn]] void fail(const std::string& message) const {
    std::ostringstream out;
    out << "JSON parse error at byte " << pos_ << ": " << message;
    throw ParseError(out.str());
  }

  std::string_view input_;
  std::size_t pos_ = 0;
};

template <typename T>
const T& expect_type(Value::Type actual, Value::Type expected, const T& value) {
  if (actual != expected) {
    throw ParseError("JSON value is " + type_name(actual) + ", expected " + type_name(expected));
  }
  return value;
}

}

bool Value::as_bool() const {
  if (type_ != Type::Boolean) {
    throw ParseError("JSON value is " + type_name(type_) + ", expected boolean");
  }
  return boolean_;
}

double Value::as_number() const {
  if (type_ != Type::Number) {
    throw ParseError("JSON value is " + type_name(type_) + ", expected number");
  }
  return number_;
}

const std::string& Value::as_string() const {
  return expect_type(type_, Type::String, string_);
}

const Value::Array& Value::as_array() const {
  return expect_type(type_, Type::Array, array_);
}

const Value::Object& Value::as_object() const {
  return expect_type(type_, Type::Object, object_);
}

const Value* Value::find(std::string_view key) const {
  if (type_ != Type::Object) {
    return nullptr;
  }
  const auto it = object_.find(std::string(key));
  if (it == object_.end()) {
    return nullptr;
  }
  return &it->second;
}

Value parse(std::string_view input) {
  if (input.size() >= 3 &&
      static_cast<unsigned char>(input[0]) == 0xEF &&
      static_cast<unsigned char>(input[1]) == 0xBB &&
      static_cast<unsigned char>(input[2]) == 0xBF) {
    input.remove_prefix(3);
  }
  return Parser(input).parse_document();
}

}
