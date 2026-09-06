#pragma once

#include <stdexcept>

namespace qprotect::cpp {

/// Exception thrown by the qprotect C++ cryptographic module.
class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Exception thrown for malformed, unsupported, or unauthenticated envelopes.
class EnvelopeError : public CryptoError {
public:
    using CryptoError::CryptoError;
};

} // namespace qprotect::cpp
