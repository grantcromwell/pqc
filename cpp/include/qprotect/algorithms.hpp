#pragma once

#include <span>
#include <string>
#include <vector>

#include "qprotect/crypto_context.hpp"
#include "qprotect/error.hpp"
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

enum class DigestAlgorithm { Sha384, Sha512 };

struct KEMKeyPair {
    SecureBytes private_key_der;
    SecureBytes public_key_der;
    std::string key_id;
};

struct KEMEncapsulation {
    SecureBytes ciphertext;
    SecureBytes shared_secret;
};

struct SignatureKeyPair {
    SecureBytes private_key_der;
    SecureBytes public_key_der;
    std::string key_id;
};

struct AeadResult {
    SecureBytes ciphertext;
    SecureBytes tag;
};

/// SHA-384 or SHA-512 digest.
SecureBytes digest(const CryptoContext& context,
                   DigestAlgorithm algorithm,
                   std::span<const unsigned char> input);

/// HKDF-SHA-384.
SecureBytes hkdf_sha384(const CryptoContext& context,
                        std::span<const unsigned char> ikm,
                        std::span<const unsigned char> salt,
                        std::span<const unsigned char> info,
                        std::size_t output_length);

/// AES-256-GCM encryption. The nonce must be exactly 12 bytes.
AeadResult aes_256_gcm_encrypt(const CryptoContext& context,
                               std::span<const unsigned char> key,
                               std::span<const unsigned char> nonce,
                               std::span<const unsigned char> plaintext,
                               std::span<const unsigned char> aad);

/// AES-256-GCM authenticated decryption. The nonce and tag must be 12 and 16 bytes.
SecureBytes aes_256_gcm_decrypt(const CryptoContext& context,
                                std::span<const unsigned char> key,
                                std::span<const unsigned char> nonce,
                                std::span<const unsigned char> ciphertext,
                                std::span<const unsigned char> tag,
                                std::span<const unsigned char> aad);

/// Generate ML-KEM-1024 keypair and DER encodings.
KEMKeyPair generate_ml_kem_1024(const CryptoContext& context);

/// Encapsulate against an ML-KEM-1024 public key.
KEMEncapsulation encapsulate_ml_kem_1024(const CryptoContext& context,
                                          std::span<const unsigned char> public_key_der);

/// Decapsulate an ML-KEM-1024 ciphertext.
SecureBytes decapsulate_ml_kem_1024(const CryptoContext& context,
                                    std::span<const unsigned char> private_key_der,
                                    std::span<const unsigned char> ciphertext);

/// Generate ML-DSA-87 keypair and DER encodings.
SignatureKeyPair generate_ml_dsa_87(const CryptoContext& context);

/// Sign a message with ML-DSA-87.
SecureBytes sign_ml_dsa_87(const CryptoContext& context,
                           std::span<const unsigned char> private_key_der,
                           std::span<const unsigned char> message);

/// Verify an ML-DSA-87 signature.
bool verify_ml_dsa_87(const CryptoContext& context,
                      std::span<const unsigned char> public_key_der,
                      std::span<const unsigned char> message,
                      std::span<const unsigned char> signature);

} // namespace qprotect::cpp
