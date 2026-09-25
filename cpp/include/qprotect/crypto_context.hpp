#pragma once

#include <memory>
#include <span>
#include <string>

#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

/// Internal OpenSSL handles used by the module implementation.
///
/// Only declared here so CryptoContext::handles() can be part of the class
/// interface. The definition lives in the module sources and is not part of
/// the public API; consumers never need OpenSSL types.
struct CryptoContextHandles;

/// Owns an OpenSSL library context and the providers used by the module.
class CryptoContext {
public:
    explicit CryptoContext(const std::string& provider = "default");
    ~CryptoContext();

    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;
    CryptoContext(CryptoContext&&) = delete;
    CryptoContext& operator=(CryptoContext&&) = delete;

    std::string provider_name() const noexcept { return provider_; }
    /// Throws if the selected provider does not expose every required algorithm.
    void assert_ready() const;

    /// Best-effort OpenSSL provider self-test.
    bool provider_self_test() const;

    /// Cryptographically secure random bytes from the selected OpenSSL context.
    SecureBytes random_bytes(std::size_t length) const;

    /// Internal OpenSSL handles used by the module implementation.
    CryptoContextHandles handles() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string provider_;
};

} // namespace qprotect::cpp
