#pragma once

// Internal header: not part of the public API.
//
// Minimal JSON support for the envelope layer. The serializer reproduces the
// Python reference implementation's json.dumps(..., sort_keys=True,
// ensure_ascii=False) byte-for-byte, both compact (separators=(",", ":")) and
// indented (indent=2), so signatures and AAD computed over serialized
// headers are identical across the two implementations.

#include <cstdint>
#include <cmath>
#include <map>
#include <string>
#include <vector>

#include "qprotect/error.hpp"

namespace qprotect::cpp::json {

class Value;
using Array = std::vector<Value>;
// std::map iterates keys in sorted order, which is what Python's
// sort_keys=True produces. UTF-8 byte order matches Python's codepoint order.
using Object = std::map<std::string, Value>;

class Value {
public:
    enum class Type { Null, Boolean, Integer, Number, String, Array, Object };

    Value() = default;
    Value(std::nullptr_t) {}
    Value(bool value) : type_(Type::Boolean), boolean_(value) {}
    Value(int value) : Value(static_cast<long long>(value)) {}
    Value(long long value) : type_(Type::Integer), integer_(value) {}
    Value(double value) : type_(Type::Number), number_(value) {
        if (!std::isfinite(value)) {
            throw EnvelopeError("JSON number must be finite");
        }
    }
    Value(const char* value) : type_(Type::String), string_(value) {}
    Value(std::string value) : type_(Type::String), string_(std::move(value)) {}
    Value(Array value) : type_(Type::Array), array_(std::move(value)) {}
    Value(Object value) : type_(Type::Object), object_(std::move(value)) {}

    Type type() const noexcept { return type_; }
    bool is_null() const noexcept { return type_ == Type::Null; }
    bool is_boolean() const noexcept { return type_ == Type::Boolean; }
    bool is_integer() const noexcept { return type_ == Type::Integer; }
    bool is_number() const noexcept { return type_ == Type::Integer || type_ == Type::Number; }
    bool is_string() const noexcept { return type_ == Type::String; }
    bool is_array() const noexcept { return type_ == Type::Array; }
    bool is_object() const noexcept { return type_ == Type::Object; }

    bool as_boolean() const;
    long long as_integer() const;
    double as_number() const;
    const std::string& as_string() const;
    const Array& as_array() const;
    const Object& as_object() const;

    /// Throws EnvelopeError unless the value is an object.
    const Object& expect_object(const char* what) const;

    /// Compact canonical form: sorted keys, separators=(",", ":").
    std::string canonical() const;

    /// Indented form matching json.dumps(..., indent=2, sort_keys=True).
    std::string pretty(int indent) const;

    /// Parse a complete JSON document. Throws EnvelopeError on malformed
    /// input. Integers and finite floating-point values are accepted; the
    /// envelope schema still validates its integer-only fields explicitly.
    static Value parse(const std::string& text);

private:
    Type type_ = Type::Null;
    bool boolean_ = false;
    long long integer_ = 0;
    double number_ = 0.0;
    std::string string_;
    Array array_;
    Object object_;
};

} // namespace qprotect::cpp::json
