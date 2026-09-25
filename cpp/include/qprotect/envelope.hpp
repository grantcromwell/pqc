#pragma once

#include <optional>
#include <span>
#include <string>
#include <vector>

#include "qprotect/crypto_context.hpp"
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

/// One ML-KEM-1024 recipient entry: the KEM ciphertext and the AES-256-GCM
/// wrapped content key in the qprotect-envelope-v1 format.
struct EnvelopeRecipient {
    std::string key_id;          // 32 lowercase hex characters
    SecureBytes kem_ciphertext;  // ML-KEM-1024 ciphertext, 1568 bytes
    SecureBytes wrap_iv;         // AES-256-GCM nonce, 12 bytes
    SecureBytes wrapped_key;     // wrapped content key, 32 bytes
    SecureBytes wrap_tag;         // AES-256-GCM tag, 16 bytes
};

/// Authenticated post-quantum KEM/AEAD envelope.
struct Envelope {
    int version = 1;
    std::string context;
    std::string created_at;
    SecureBytes payload_iv;   // AES-256-GCM nonce, 12 bytes
    SecureBytes ciphertext;
    SecureBytes tag;           // AES-256-GCM tag, 16 bytes
    std::vector<EnvelopeRecipient> recipients;
    std::optional<std::string> signer_key_id;
    std::optional<SecureBytes> signature;

    /// Serialized envelope JSON with sorted keys and two-space indentation.
    std::string to_json() const;

    /// Parse and strictly validate an envelope document.
    /// Throws EnvelopeError on malformed or unsupported input.
    static Envelope from_json(const std::string& text);
};

struct EncryptOptions {
    /// Non-empty context string, at most 128 characters, no control characters.
    std::string context;
    /// SubjectPublicKeyInfo DER of each recipient ML-KEM-1024 public key.
    std::vector<SecureBytes> recipient_public_key_der;
    /// Optional ML-DSA-87 signing private key (PKCS#8 DER).
    std::optional<SecureBytes> signer_private_key_der;
};

struct DecryptOptions {
    /// Recipient ML-KEM-1024 private key (PKCS#8 DER).
    SecureBytes recipient_private_key_der;
    /// Required when the envelope is signed.
    std::optional<SecureBytes> signer_public_key_der;
    /// Require sender authentication even when no signer key is otherwise supplied.
    bool require_signature = false;
};

/// Encrypt plaintext into an authenticated envelope for each recipient.
/// Throws EnvelopeError on invalid options, CryptoError on provider failures.
Envelope encrypt_envelope(const CryptoContext& context,
                          std::span<const unsigned char> plaintext,
                          const EncryptOptions& options);

/// Decrypt and fully authenticate an envelope with one recipient private key.
/// Throws EnvelopeError on any validation or authentication failure.
SecureBytes decrypt_envelope(const CryptoContext& context,
                             const Envelope& envelope,
                             const DecryptOptions& options);

} // namespace qprotect::cpp
