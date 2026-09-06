#pragma once

#include <span>
#include <string>

#include "qprotect/crypto_context.hpp"
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

/// Load a public key file (PEM SubjectPublicKeyInfo or raw DER) and return
/// its SubjectPublicKeyInfo DER encoding, the form used for key_id and the
/// KEM. PEM files interoperate with the Python CLI and OpenSSL pkey output.
SecureBytes load_public_key_file(const CryptoContext& context,
                                 const std::string& path);

/// Load a private key file (PEM PKCS#8 or raw DER) and return the DER
/// encoding accepted by the KEM and signature functions.
SecureBytes load_private_key_file(const CryptoContext& context,
                                  const std::string& path);

/// SubjectPublicKeyInfo DER of the public half of a private key.
SecureBytes public_key_of_private(const CryptoContext& context,
                                  std::span<const unsigned char> private_key_der);

/// key_id used by the envelope format: SHA-384 of the SubjectPublicKeyInfo
/// DER, first 16 bytes as lowercase hex (32 characters).
std::string key_id_for_public_key(const CryptoContext& context,
                                  std::span<const unsigned char> public_key_der);

/// Write a private key as a PKCS#8 PEM file ("-----BEGIN PRIVATE KEY-----").
/// The file is created with owner-only 0600 permissions, matching the
/// Python CLI.
void write_private_key_pem(const CryptoContext& context,
                           std::span<const unsigned char> private_key_der,
                           const std::string& path,
                           bool overwrite = false);

/// Write a public key as a SubjectPublicKeyInfo PEM file
/// ("-----BEGIN PUBLIC KEY-----"), created with 0644 permissions.
void write_public_key_pem(const CryptoContext& context,
                          std::span<const unsigned char> public_key_der,
                          const std::string& path,
                          bool overwrite = false);

} // namespace qprotect::cpp
