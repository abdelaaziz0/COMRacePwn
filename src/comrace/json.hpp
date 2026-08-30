#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace comrace::json {

class ParseError : public std::runtime_error {
 public:
  explicit ParseError(const std::string& message) : std::runtime_error(message) {}
};

class Value {
 public:
  enum class Type {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object
  };

  using Array = std::vector<Value>;
  using Object = std::map<std::string, Value>;

  Value() = default;
  explicit Value(std::nullptr_t) {}
  explicit Value(bool value) : type_(Type::Boolean), boolean_(value) {}
  explicit Value(double value) : type_(Type::Number), number_(value) {}
  explicit Value(std::string value) : type_(Type::String), string_(std::move(value)) {}
  explicit Value(Array value) : type_(Type::Array), array_(std::move(value)) {}
  explicit Value(Object value) : type_(Type::Object), object_(std::move(value)) {}

  Type type() const { return type_; }
  bool is_null() const { return type_ == Type::Null; }
  bool is_bool() const { return type_ == Type::Boolean; }
  bool is_number() const { return type_ == Type::Number; }
  bool is_string() const { return type_ == Type::String; }
  bool is_array() const { return type_ == Type::Array; }
  bool is_object() const { return type_ == Type::Object; }

  bool as_bool() const;
  double as_number() const;
  const std::string& as_string() const;
  const Array& as_array() const;
  const Object& as_object() const;

  const Value* find(std::string_view key) const;

 private:
  Type type_ = Type::Null;
  bool boolean_ = false;
  double number_ = 0.0;
  std::string string_;
  Array array_;
  Object object_;
};

Value parse(std::string_view input);

}  // namespace comrace::json
