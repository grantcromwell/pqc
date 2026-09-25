// Negative-path and behavior unit tests for the qprotect C++ module.
//
// The algorithm self-test executable covers known-answer and pairwise
// consistency checks. This suite covers everything the self-tests do not:
// parameter validation, tamper rejection, malformed input handling, JSON
// canonicalization, and envelope round-trips including failure paths.

#include "qprotect/algorithms.hpp"
#include "qprotect/crypto_context.hpp"
#include "qprotect/envelope.hpp"
#include "qprotect/disk.hpp"
#include "qprotect/hardware.hpp"
#include "qprotect/error.hpp"
#include "qprotect/keys.hpp"
#include "qprotect/secure_bytes.hpp"

#include "json_minimal.hpp"
#include "identity.hpp"
#include "hardware_internal.hpp"
#include "disk_internal.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using qprotect::cpp::AeadResult;
using qprotect::cpp::CryptoContext;
using qprotect::cpp::CryptoError;
using qprotect::cpp::DecryptOptions;
using qprotect::cpp::DigestAlgorithm;
using qprotect::cpp::Envelope;
using qprotect::cpp::EnvelopeError;
using qprotect::cpp::EncryptOptions;
using qprotect::cpp::KEMEncapsulation;
using qprotect::cpp::KEMKeyPair;
using qprotect::cpp::SecureBytes;
using qprotect::cpp::SignatureKeyPair;
using qprotect::cpp::aes_256_gcm_decrypt;
using qprotect::cpp::aes_256_gcm_encrypt;
using qprotect::cpp::decapsulate_ml_kem_1024;
using qprotect::cpp::decrypt_envelope;
using qprotect::cpp::digest;
using qprotect::cpp::encapsulate_ml_kem_1024;
using qprotect::cpp::encrypt_envelope;
using qprotect::cpp::generate_ml_dsa_87;
using qprotect::cpp::generate_ml_kem_1024;
using qprotect::cpp::hkdf_sha384;
using qprotect::cpp::key_id_for_public_key;
using qprotect::cpp::load_private_key_file;
using qprotect::cpp::load_public_key_file;
using qprotect::cpp::sign_ml_dsa_87;
using qprotect::cpp::verify_ml_dsa_87;
using qprotect::cpp::write_private_key_pem;
using qprotect::cpp::write_public_key_pem;

int g_failures = 0;
int g_checks = 0;

void report(bool condition, const char* file, int line, const char* expression) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::cerr << "FAIL " << file << ":" << line << ": " << expression << "\n";
    }
}

#define CHECK(condition) report((condition), __FILE__, __LINE__, #condition)

#define CHECK_THROWS(exception_type, expression)                       \
    do {                                                                \
        bool threw = false;                                             \
        try {                                                           \
            static_cast<void>(expression);                              \
        } catch (const exception_type&) {                               \
            threw = true;                                               \
        } catch (...) {                                                \
        }                                                               \
        report(threw, __FILE__, __LINE__, "throws: " #expression);      \
    } while (false)

#define CHECK_NO_THROW(expression)                                      \
    do {                                                                \
        bool threw = false;                                             \
        try {                                                           \
            static_cast<void>(expression);                              \
        } catch (const std::exception& error) {                         \
            threw = true;                                               \
            std::cerr << "unexpected: " << error.what() << "\n";         \
        }                                                               \
        report(!threw, __FILE__, __LINE__, "no-throw: " #expression);  \
    } while (false)

SecureBytes bytes(const std::string& value) {
    return SecureBytes(
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size()
    );
}

SecureBytes bytes(const char* value) {
    return bytes(std::string(value));
}

bool same(const SecureBytes& left, const std::string& right) {
    return left.size() == right.size() &&
           std::memcmp(left.data(), right.data(), right.size()) == 0;
}

// ---------------------------------------------------------------- digests

void test_digests(const CryptoContext& context) {
    CHECK(context.random_bytes(0).empty());

    const SecureBytes abc = bytes("abc");
    CHECK(digest(context, DigestAlgorithm::Sha384, abc).size() == 48);
    CHECK(digest(context, DigestAlgorithm::Sha512, abc).size() == 64);
    CHECK(digest(context, DigestAlgorithm::Sha384, SecureBytes{}).size() == 48);

    // RFC 6234 known-answer: SHA-384("abc")
    const SecureBytes sha384_abc = digest(context, DigestAlgorithm::Sha384, abc);
    CHECK(same(
        sha384_abc,
        std::string(
            "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
            "\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
            "\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7",
            48
        )
    ));
}

// -------------------------------------------------------------------- HKDF

void test_hkdf(const CryptoContext& context) {
    const SecureBytes ikm = bytes("secret");
    const SecureBytes salt = bytes("salt");
    const SecureBytes info = bytes("info");

    CHECK_THROWS(
        CryptoError,
        hkdf_sha384(context, ikm, salt, info, 0));
    CHECK_THROWS(
        CryptoError,
        hkdf_sha384(context, ikm, salt, info, 255 * 48 + 1));
    // The RFC 5869 upper bound (255 * HashLen) is accepted.
    CHECK_NO_THROW(
        hkdf_sha384(context, ikm, salt, info, 255 * 48));

    const SecureBytes derived = hkdf_sha384(context, ikm, salt, info, 32);
    CHECK(derived.size() == 32);
    CHECK(same(
        derived,
        std::string(
            "\x29\xc0\x42\x77\x51\x83\xec\x5d\xbc\x2c\x08\x5e\xb4\x95\x02\xb1"
            "\x5d\x9e\x8a\xbe\x4a\x4c\x1e\xf9\x8e\x8e\x0f\xb9\x5a\xd5\xf6\xa9",
            32
        )
    ));
}

// ---------------------------------------------------------------- AES-GCM

void test_aes_gcm(const CryptoContext& context) {
    const SecureBytes key = context.random_bytes(32);
    const SecureBytes nonce = context.random_bytes(12);
    const SecureBytes plaintext = bytes("attack at dawn");
    const SecureBytes aad = bytes("header");

    const SecureBytes short_key = context.random_bytes(16);
    const SecureBytes bad_nonce = context.random_bytes(16);

    CHECK_THROWS(CryptoError, aes_256_gcm_encrypt(context, short_key, nonce, plaintext, aad));
    CHECK_THROWS(CryptoError, aes_256_gcm_encrypt(context, key, bad_nonce, plaintext, aad));
    CHECK_THROWS(CryptoError, aes_256_gcm_decrypt(context, short_key, nonce, plaintext, SecureBytes(16), aad));
    CHECK_THROWS(CryptoError, aes_256_gcm_decrypt(context, key, nonce, plaintext, SecureBytes(15), aad));

    const AeadResult sealed = aes_256_gcm_encrypt(context, key, nonce, plaintext, aad);
    CHECK(sealed.ciphertext.size() == plaintext.size());
    CHECK(sealed.tag.size() == 16);
    CHECK(same(aes_256_gcm_decrypt(context, key, nonce, sealed.ciphertext, sealed.tag, aad), "attack at dawn"));

    // Empty plaintext and empty AAD are valid.
    const AeadResult empty_sealed =
        aes_256_gcm_encrypt(context, key, nonce, SecureBytes{}, SecureBytes{});
    CHECK(empty_sealed.ciphertext.empty());
    CHECK_NO_THROW(
        aes_256_gcm_decrypt(context, key, nonce, empty_sealed.ciphertext, empty_sealed.tag, SecureBytes{}));

    // Larger input exercises the chunked update loop.
    const SecureBytes large = context.random_bytes(300 * 1024);
    const AeadResult large_sealed = aes_256_gcm_encrypt(context, key, nonce, large, aad);
    const SecureBytes large_recovered =
        aes_256_gcm_decrypt(context, key, nonce, large_sealed.ciphertext, large_sealed.tag, aad);
    CHECK(large_recovered == large);

    // Tampered ciphertext must be rejected.
    SecureBytes broken_ciphertext(sealed.ciphertext);
    broken_ciphertext[0] ^= 0x01;
    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(context, key, nonce, broken_ciphertext, sealed.tag, aad));

    // Tampered tag must be rejected.
    SecureBytes broken_tag(sealed.tag);
    broken_tag[15] ^= 0x01;
    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(context, key, nonce, sealed.ciphertext, broken_tag, aad));

    // Tampered AAD must be rejected.
    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(context, key, nonce, sealed.ciphertext, sealed.tag, bytes("headex")));

    // Truncated ciphertext must be rejected.
    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(
            context,
            key,
            nonce,
            SecureBytes(sealed.ciphertext.data(), sealed.ciphertext.size() - 1),
            sealed.tag,
            aad));
}

// ----------------------------------------------------------------- ML-KEM

void test_ml_kem(const CryptoContext& context) {
    const KEMKeyPair key_pair = generate_ml_kem_1024(context);
    const KEMEncapsulation encapsulation =
        encapsulate_ml_kem_1024(context, key_pair.public_key_der);
    CHECK(encapsulation.ciphertext.size() == 1568);
    CHECK(encapsulation.shared_secret.size() == 32);
    CHECK(decapsulate_ml_kem_1024(
              context, key_pair.private_key_der, encapsulation.ciphertext) ==
          encapsulation.shared_secret);

    // Malformed keys are rejected.
    CHECK_THROWS(CryptoError, encapsulate_ml_kem_1024(context, bytes("not a key")));
    CHECK_THROWS(CryptoError, decapsulate_ml_kem_1024(context, bytes("not a key"), encapsulation.ciphertext));

    // Wrong ciphertext lengths are rejected.
    CHECK_THROWS(CryptoError,
        decapsulate_ml_kem_1024(context, key_pair.private_key_der, SecureBytes(16)));
    CHECK_THROWS(CryptoError,
        decapsulate_ml_kem_1024(context, key_pair.private_key_der, SecureBytes(1567)));

    // A different recipient decapsulates to a different (implicitly rejected)
    // secret rather than the sender's shared secret.
    const KEMKeyPair other = generate_ml_kem_1024(context);
    const SecureBytes other_secret = decapsulate_ml_kem_1024(
        context, other.private_key_der, encapsulation.ciphertext);
    CHECK(other_secret.size() == 32);
    CHECK(!(other_secret == encapsulation.shared_secret));
}

// ---------------------------------------------------------------- ML-DSA

void test_ml_dsa(const CryptoContext& context) {
    const SignatureKeyPair key_pair = generate_ml_dsa_87(context);
    const SecureBytes message = bytes("classified");

    const SecureBytes signature = sign_ml_dsa_87(context, key_pair.private_key_der, message);
    CHECK(signature.size() == 4627);
    CHECK(verify_ml_dsa_87(context, key_pair.public_key_der, message, signature));
    CHECK(!verify_ml_dsa_87(context, key_pair.public_key_der, bytes("tampered"), signature));
    CHECK(!verify_ml_dsa_87(context, key_pair.public_key_der, message, SecureBytes(signature.size() - 1, 0)));

    // Empty messages sign and verify.
    const SecureBytes empty_signature =
        sign_ml_dsa_87(context, key_pair.private_key_der, SecureBytes{});
    CHECK(empty_signature.size() == 4627);
    CHECK(verify_ml_dsa_87(context, key_pair.public_key_der, SecureBytes{}, empty_signature));

    // Malformed keys are rejected.
    CHECK_THROWS(CryptoError, sign_ml_dsa_87(context, bytes("not a key"), message));
    CHECK_THROWS(CryptoError, verify_ml_dsa_87(context, bytes("not a key"), message, signature));

    // A signature from another key does not verify.
    const SignatureKeyPair other = generate_ml_dsa_87(context);
    CHECK(!verify_ml_dsa_87(context, other.public_key_der, message, signature));
}

// ------------------------------------------------------------- SecureBytes

void test_secure_bytes() {
    SecureBytes value = bytes("sensitive");
    value.zeroize();
    CHECK(value.empty());
    for (const unsigned char byte : value) {
        static_cast<void>(byte);
    }

    SecureBytes original = bytes("sensitive");
    SecureBytes moved = std::move(original);
    CHECK(original.empty());
    CHECK(same(moved, "sensitive"));

    SecureBytes assigned = bytes("first");
    assigned.assign(bytes("second"));
    CHECK(same(assigned, "second"));

    const SecureBytes left = bytes("same");
    const SecureBytes right = bytes("same");
    CHECK(left == right);
    CHECK(!(left == bytes("different")));
}

// ----------------------------------------------------------------- context

void test_context() {
    CHECK_THROWS(CryptoError, CryptoContext("bogus"));
    const CryptoContext context;
    CHECK(context.provider_name() == "default");
    CHECK_NO_THROW(context.assert_ready());
}

// -------------------------------------------------------------------- JSON

void test_json_canonical() {
    // Compact JSON sorts object keys and preserves UTF-8 characters.
    const qprotect::cpp::json::Object object = {
        {"b", qprotect::cpp::json::Value(1)},
        {"a", qprotect::cpp::json::Value("x")},
    };
    CHECK(qprotect::cpp::json::Value(object).canonical() == R"({"a":"x","b":1})");

    const qprotect::cpp::json::Array array = {
        qprotect::cpp::json::Value(2),
        qprotect::cpp::json::Value(nullptr),
        qprotect::cpp::json::Value(true),
        qprotect::cpp::json::Value("s"),
    };
    CHECK(qprotect::cpp::json::Value(array).canonical() == R"([2,null,true,"s"])");

    // Control characters use short escapes where available and lowercase
    // \u00xx otherwise. DEL passes through unchanged.
    const std::string tricky = std::string("q\"uote\\back") + '\x1f' + '\x7f' + '\n';
    const qprotect::cpp::json::Object escape_object = {
        {"a", qprotect::cpp::json::Value(tricky)},
    };
    CHECK(qprotect::cpp::json::Value(escape_object).canonical() ==
          "{\"a\":\"q\\\"uote\\\\back\\u001f\x7f\\n\"}");

    // Nested containers keep their keys sorted at every level.
    const qprotect::cpp::json::Object inner = {
        {"z", qprotect::cpp::json::Value(1)},
        {"a", qprotect::cpp::json::Value(2)},
    };
    const qprotect::cpp::json::Object outer = {
        {"nested", qprotect::cpp::json::Value(inner)},
    };
    CHECK(qprotect::cpp::json::Value(outer).canonical() ==
          R"({"nested":{"a":2,"z":1}})");

    // Pretty output uses two-space indentation and sorted keys.
    const qprotect::cpp::json::Object pretty_object = {
        {"b", qprotect::cpp::json::Value(1)},
        {"a", qprotect::cpp::json::Value("x")},
    };
    CHECK(qprotect::cpp::json::Value(pretty_object).pretty(2) ==
          "{\n  \"a\": \"x\",\n  \"b\": 1\n}");
}

void test_json_parse() {
    using qprotect::cpp::json::Value;

    CHECK_THROWS(EnvelopeError, Value::parse(""));
    CHECK_THROWS(EnvelopeError, Value::parse("{"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1,}"));
    CHECK_THROWS(EnvelopeError, Value::parse("[1,2]x"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1 \"b\":2}"));
    CHECK(Value::parse("{\"a\":1.5}").canonical() == R"({"a":1.5})");
    CHECK(Value::parse("{\"a\":1e-5}").canonical() == R"({"a":1e-05})");
    CHECK(Value(1.0).canonical() == "1.0");
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":01}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1.}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1e+}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1e9999}"));
    std::string deeply_nested(66, '[');
    deeply_nested += "0";
    deeply_nested.append(66, ']');
    CHECK_THROWS(EnvelopeError, Value::parse(deeply_nested));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":\x01}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":\"\\q\"}"));
    CHECK_THROWS(EnvelopeError, Value::parse("nul"));
    CHECK_THROWS(EnvelopeError, Value::parse("\"\\ud800\""));

    const Value parsed = Value::parse(
        R"({"a":1,"b":[true,null,"x"],"c":{"d":"é"}})");
    CHECK(parsed.is_object());
    CHECK(parsed.as_object().at("a").as_integer() == 1);
    CHECK(parsed.as_object().at("b").as_array().size() == 3);
    CHECK(parsed.as_object().at("c").as_object().at("d").as_string() == "é");
}

void test_identity_normalization() {
    using qprotect::cpp::detail::normalize_identity;
    using qprotect::cpp::json::Value;

    // Synthetic identifiers and coordinates; no captured device records.
    const Value normalized = normalize_identity(Value::parse(
        R"({"ip":"2001:0DB8:0:0:0:0:0:1","mac":"02-00-00-00-00-0A","serial":" TEST-DEVICE ","uuid":"00000000-0000-4000-A000-000000000001","wifi_bssid":"02.00.00.00.00.0B","gps":{"latitude":0,"longitude":0,"accuracy_m":8},"browser_fingerprint":{"timezone":"UTC"},"site":"test-site"})"));
    const auto& fields = normalized.as_object();
    CHECK(fields.at("ip_address").as_string() == "2001:db8::1");
    CHECK(fields.at("mac_address").as_string() == "02:00:00:00:00:0a");
    CHECK(fields.at("hardware_serial").as_string() == "TEST-DEVICE");
    CHECK(fields.at("uuid").as_string() == "00000000-0000-4000-a000-000000000001");
    CHECK(fields.at("wifi_bssid").as_string() == "02:00:00:00:00:0b");
    CHECK(fields.at("gps").as_object().at("latitude").as_number() == 0.0);
    CHECK(fields.at("gps").as_object().at("longitude").as_number() == 0.0);
    CHECK(fields.at("additional").as_object().at("site").as_string() == "test-site");
    CHECK(fields.at("browser_fingerprint").as_object().at("timezone").as_string() == "UTC");
    CHECK(fields.at("guid").is_null());
    const Value timestamped = normalize_identity(Value::parse(
        R"({"gps":{"latitude":0,"longitude":0,"timestamp":"2026-09-22T12:30:45.123Z"}})"));
    CHECK(timestamped.as_object().at("gps").as_object().at("timestamp").as_string() ==
          "2026-09-22T12:30:45.123Z");

    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"ip":"not-an-ip"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"mac":"00:11"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"uuid":"bad"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"serial":"\u0000"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"gps":{"latitude":91,"longitude":0}})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"gps":{"latitude":true,"longitude":0}})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"gps":{"latitude":0,"longitude":0,"timestamp":"2026-02-30T00:00:00Z"}})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"ip":"127.0.0.1"," ip ":"127.0.0.2"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"additional":[]})")));
}

// --------------------------------------------------------------- envelope

EncryptOptions options_for(
    const std::vector<SecureBytes>& recipients,
    const std::string& context_value,
    const SecureBytes* signer_private = nullptr
) {
    EncryptOptions options;
    options.context = context_value;
    options.recipient_public_key_der = recipients;
    if (signer_private != nullptr) {
        options.signer_private_key_der = *signer_private;
    }
    return options;
}

void test_envelope_roundtrip(const CryptoContext& context) {
    const KEMKeyPair alice = generate_ml_kem_1024(context);
    const KEMKeyPair bob = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);

    const SecureBytes payload = bytes("top secret identity record");

    // Unsigned, single recipient.
    const Envelope single = encrypt_envelope(
        context, payload, options_for({alice.public_key_der}, "test"));
    CHECK(single.context == "test");
    CHECK(single.signer_key_id == std::nullopt);
    const SecureBytes single_recovered = decrypt_envelope(
        context,
        single,
        DecryptOptions{alice.private_key_der, std::nullopt});
    CHECK(single_recovered == payload);

    // Multi-recipient, signed.
    const Envelope dual = encrypt_envelope(
        context,
        payload,
        options_for({alice.public_key_der, bob.public_key_der}, "test", &signer.private_key_der));
    CHECK(dual.recipients.size() == 2);
    CHECK(dual.signer_key_id.has_value());
    CHECK(*dual.signer_key_id == signer.key_id);

    const DecryptOptions signed_decrypt{
        alice.private_key_der, signer.public_key_der};
    CHECK(decrypt_envelope(context, dual, signed_decrypt) == payload);
    const DecryptOptions bob_decrypt{bob.private_key_der, signer.public_key_der};
    CHECK(decrypt_envelope(context, dual, bob_decrypt) == payload);

    // Empty payload round-trips.
    const Envelope empty = encrypt_envelope(
        context, SecureBytes{}, options_for({alice.public_key_der}, "test"));
    CHECK(empty.ciphertext.empty());
    const SecureBytes empty_recovered = decrypt_envelope(
        context, empty, DecryptOptions{alice.private_key_der, std::nullopt});
    CHECK(empty_recovered.empty());
}

void test_envelope_failures(const CryptoContext& context) {
    const KEMKeyPair alice = generate_ml_kem_1024(context);
    const KEMKeyPair mallory = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);
    const SignatureKeyPair other_signer = generate_ml_dsa_87(context);

    const SecureBytes payload = bytes("payload");
    const Envelope envelope = encrypt_envelope(
        context,
        payload,
        options_for({alice.public_key_der}, "test", &signer.private_key_der));

    // No recipients.
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({}, "test")));

    // Duplicate recipient keys are rejected before serialization.
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(
            context,
            payload,
            options_for({alice.public_key_der, alice.public_key_der}, "test")));

    // Invalid contexts.
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, "")));
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, std::string(129, 'x'))));
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, "bad\x01context")));
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, "não-ascii")));

    // Wrong recipient key.
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            envelope,
            DecryptOptions{mallory.private_key_der, signer.public_key_der}));

    // Signed envelope without a signer public key.
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            envelope,
            DecryptOptions{alice.private_key_der, std::nullopt}));

    // Providing an expected signer requires the envelope to be signed.
    const Envelope unsigned_for_signer = encrypt_envelope(
        context, payload, options_for({alice.public_key_der}, "test"));
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            unsigned_for_signer,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    // Wrong signer public key: key_id mismatch.
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            envelope,
            DecryptOptions{alice.private_key_der, other_signer.public_key_der}));

    // Tampered payload ciphertext.
    Envelope broken = envelope;
    broken.ciphertext[0] ^= 0x01;
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    // Tampered wrapped key.
    Envelope broken_wrap = envelope;
    broken_wrap.recipients[0].wrapped_key[0] ^= 0x01;
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken_wrap,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    // Tampered signature.
    Envelope broken_sig = envelope;
    (*broken_sig.signature)[0] ^= 0x01;
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken_sig,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    // Tampered context changes the HKDF info and AAD together.
    Envelope broken_context = envelope;
    broken_context.context = "other";
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken_context,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));
}

void test_envelope_serialization(const CryptoContext& context) {
    const KEMKeyPair alice = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);

    const Envelope envelope = encrypt_envelope(
        context,
        bytes("roundtrip"),
        options_for({alice.public_key_der}, "serial", &signer.private_key_der));

    const std::string json = envelope.to_json();
    const Envelope reparsed = Envelope::from_json(json);
    // Re-serializing the parsed envelope is byte-identical.
    CHECK(reparsed.to_json() == json);
    // And it still decrypts.
    CHECK(decrypt_envelope(
              context,
              reparsed,
              DecryptOptions{alice.private_key_der, signer.public_key_der}) ==
          bytes("roundtrip"));

    // Malformed and unsupported documents are rejected.
    CHECK_THROWS(EnvelopeError, Envelope::from_json(""));
    CHECK_THROWS(EnvelopeError, Envelope::from_json("[]"));
    CHECK_THROWS(EnvelopeError, Envelope::from_json("{"));

    const auto replace_once = [](std::string text,
                                 const std::string& from,
                                 const std::string& to) {
        const std::size_t position = text.find(from);
        if (position == std::string::npos) {
            return text;
        }
        text.replace(position, from.size(), to);
        return text;
    };

    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"version\": 1", "\"version\": 2")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "qprotect-envelope-v1", "qprotect-envelope-v2")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"kem\": \"ML-KEM-1024\"", "\"kem\": \"ML-KEM-512\"")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"aead\": \"AES-256-GCM\"", "\"aead\": \"AES-128-GCM\"")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"ciphertext\": \"", "\"ciphertext\": \"!!!")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"key_id\": \"", "\"key_id\": \"ZZZZ")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"payload_iv\": \"", "\"payload_iv\": \"AAAA\"")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(
        json, "\"version\": 1", "\"unknown\": 1,\n  \"version\": 1")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(
        json, envelope.created_at, "not-a-timestamp")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(
        json, envelope.created_at, "2026-02-30T12:00:00.000000Z")));

    // Duplicated recipient entries are rejected.
    const KEMKeyPair bob = generate_ml_kem_1024(context);
    const Envelope two = encrypt_envelope(
        context,
        bytes("dup"),
        options_for({alice.public_key_der, bob.public_key_der}, "serial"));
    const std::string two_json = two.to_json();
    std::string duplicated = two_json;
    const std::size_t first = duplicated.find("    {\n");
    const std::size_t second = duplicated.find("    {\n", first + 1);
    const std::string block = duplicated.substr(first, second - first);
    duplicated.insert(second, block);
    CHECK_THROWS(EnvelopeError, Envelope::from_json(duplicated));

    // Signature metadata without a signature is rejected.
    const Envelope unsigned_envelope = encrypt_envelope(
        context, bytes("unsigned"), options_for({alice.public_key_der}, "serial"));
    const std::string unsigned_json = unsigned_envelope.to_json();
    CHECK_THROWS(EnvelopeError,
        Envelope::from_json(replace_once(
            unsigned_json,
            "\"signature_algorithm\": null",
            "\"signature_algorithm\": \"ML-DSA-87\"")));
}

// -------------------------------------------------------------------- keys

void test_key_files(const CryptoContext& context) {
    char temporary[] = "./qprotect-cpp-unit-keys-XXXXXX";
    char* created = ::mkdtemp(temporary);
    CHECK(created != nullptr);
    if (created == nullptr) return;
    const std::string directory = created;
    const std::string private_pem = directory + "/device-private.pem";
    const std::string public_pem = directory + "/device-public.pem";

    const KEMKeyPair key_pair = generate_ml_kem_1024(context);
    write_private_key_pem(context, key_pair.private_key_der, private_pem);
    write_public_key_pem(context, key_pair.public_key_der, public_pem);

    // PEM round-trips through the same key_id.
    const SecureBytes loaded_public = load_public_key_file(context, public_pem);
    CHECK(key_id_for_public_key(context, loaded_public) == key_pair.key_id);
    const SecureBytes loaded_private = load_private_key_file(context, private_pem);
    CHECK(qprotect::cpp::public_key_of_private(context, loaded_private) == loaded_public);
    struct stat status {};
    CHECK(::stat(private_pem.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600);
    CHECK_THROWS(EnvelopeError,
        write_private_key_pem(context, key_pair.private_key_der, private_pem));
    CHECK(load_private_key_file(context, private_pem) == loaded_private);

    // Wrong key type in a public key slot is rejected.
    CHECK_THROWS(EnvelopeError, load_public_key_file(context, private_pem));
    CHECK_THROWS(EnvelopeError, load_private_key_file(context, public_pem));

    ::unlink(private_pem.c_str());
    ::unlink(public_pem.c_str());
    ::rmdir(directory.c_str());
}

void test_private_key_envelopes(const CryptoContext& context) {
    // Every private key is generated for this test run.
    const KEMKeyPair recipient = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);
    const KEMKeyPair kem_owner = generate_ml_kem_1024(context);
    const SignatureKeyPair signing_owner = generate_ml_dsa_87(context);
    const DecryptOptions decrypt_options{recipient.private_key_der, signer.public_key_der, true};
    const auto protect_and_recover = [&](const SecureBytes& private_key) {
        const EncryptOptions options = options_for(
            {recipient.public_key_der}, "private-key", &signer.private_key_der);
        const Envelope sealed = encrypt_envelope(context, private_key, options);
        const Envelope parsed = Envelope::from_json(sealed.to_json());
        const SecureBytes recovered = decrypt_envelope(context, parsed, decrypt_options);
        CHECK(recovered == private_key);

        Envelope tampered = parsed;
        tampered.ciphertext[0] ^= 1;
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, tampered, decrypt_options));
        tampered = parsed;
        tampered.signature.reset();
        tampered.signer_key_id.reset();
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, tampered, decrypt_options));
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, parsed,
            (DecryptOptions{kem_owner.private_key_der, signer.public_key_der, true})));
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, parsed,
            (DecryptOptions{recipient.private_key_der, signing_owner.public_key_der, true})));
        return recovered;
    };

    const SecureBytes recovered_kem = protect_and_recover(kem_owner.private_key_der);
    const KEMEncapsulation encapsulation = encapsulate_ml_kem_1024(context, kem_owner.public_key_der);
    CHECK(decapsulate_ml_kem_1024(context, recovered_kem, encapsulation.ciphertext) ==
          encapsulation.shared_secret);

    const SecureBytes recovered_signer = protect_and_recover(signing_owner.private_key_der);
    const SecureBytes message = bytes("recovered signing key test");
    const SecureBytes signature = sign_ml_dsa_87(context, recovered_signer, message);
    CHECK(verify_ml_dsa_87(context, signing_owner.public_key_der, message, signature));
}

void test_disk_plan_helpers() {
    qprotect::cpp::DiskPlanOptions options;
    options.device = "/dev/example";
    options.mapper_name = "secure-root";
    const auto arguments = qprotect::cpp::format_luks2_arguments(options);
    CHECK(arguments.front() == "cryptsetup");
    CHECK(arguments[1] == "luksFormat");
    CHECK(arguments.back() == "/dev/example");
    CHECK(qprotect::cpp::format_confirmation(arguments, "example", 8, 1) ==
          "FORMAT-example-05A0BBE818CD0BF5");
    CHECK(qprotect::cpp::format_confirmation(arguments, "example", 8, 1) !=
          qprotect::cpp::format_confirmation(arguments, "example", 8, 2));
    CHECK(qprotect::cpp::shell_quote("a'b") == "'a'\\''b'");
    options.mapper_name = "bad/name";
    CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));
    options.mapper_name = "valid";
    options.iter_time_ms = 999;
    CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));
}

void test_disk_safety_report_validation() {
    const auto validate = [](const std::string& report) {
        qprotect::cpp::detail::validate_lsblk_safety_json(report);
    };
    CHECK_NO_THROW(validate(R"({"blockdevices":[{"path":"/dev/fake","mountpoints":[null]}]})"));
    CHECK_THROWS(EnvelopeError, validate("not json"));
    CHECK_THROWS(EnvelopeError, validate(R"({"blockdevices":[]})"));
    CHECK_THROWS(EnvelopeError, validate(R"({"blockdevices":[{"mountpoints":["/mnt/data"]}]})"));
    CHECK_THROWS(EnvelopeError, validate(
        R"({"blockdevices":[{"mountpoints":[null],"children":[{"mountpoints":["/boot"]}]}]})"));
    CHECK_THROWS(EnvelopeError, validate(
        R"({"blockdevices":[{"mountpoints":[null],"children":[{"mountpoints":[null]}]}]})"));
}

void test_hardware_report_schema(const std::string& report_text) {
    std::istringstream input_stream(report_text);
    std::string line;
    CHECK(static_cast<bool>(std::getline(input_stream, line)) && line == "qprotect-hardware-v1");
    std::string previous;
    std::size_t records = 0;
    while (std::getline(input_stream, line)) {
        if (line.empty()) continue;
        std::size_t separators = 0;
        for (const char character : line) if (character == '\t') ++separators;
        CHECK(separators == 4);
        CHECK(previous.empty() || previous <= line);
        CHECK(line.find('\r') == std::string::npos);
        previous = line;
        ++records;
    }
    CHECK(records > 0);
}

void test_hardware_fixture_discovery() {
    char temporary[] = "./qprotect-hardware-fixture-XXXXXX";
    char* directory = ::mkdtemp(temporary);
    CHECK(directory != nullptr);
    if (directory == nullptr) return;
    const std::filesystem::path root = std::filesystem::absolute(directory);
    qprotect::cpp::detail::HardwarePaths paths;
    paths.efi_root = root / "efi";
    paths.pci_root = root / "pci";
    paths.net_root = root / "net";
    paths.usb_root = root / "usb";
    paths.dev_root = root / "dev";
    paths.tpm_root = root / "tpm";
    paths.iommu_root = root / "iommu";
    paths.rng_root = root / "rng";
    paths.block_root = root / "block";
    paths.cpu_vulnerabilities = root / "cpu-vulnerabilities";

    const auto write = [](const std::filesystem::path& file, const std::string& value, bool binary = false) {
        std::filesystem::create_directories(file.parent_path());
        std::ofstream stream(file, binary ? std::ios::binary : std::ios::out);
        stream.write(value.data(), static_cast<std::streamsize>(value.size()));
    };
    const auto efi_variable = [](unsigned char value) {
        return std::string(4, '\0') + static_cast<char>(value);
    };
    const std::filesystem::path variables = paths.efi_root / "efivars";
    write(variables / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", efi_variable(1), true);
    write(variables / "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", efi_variable(0), true);

    const std::filesystem::path pci_device = paths.pci_root / "0000:00:01.0";
    write(pci_device / "class", "0x020000\n");
    write(pci_device / "vendor", "0x1234\n");
    write(pci_device / "device", "0xabcd\n");
    std::filesystem::create_directories(paths.iommu_root / "17");
    std::filesystem::create_symlink(paths.iommu_root / "17", pci_device / "iommu_group");
    const std::filesystem::path driver = root / "drivers" / "sample_net";
    std::filesystem::create_directories(driver);
    std::filesystem::create_directories(paths.net_root / "eth-test" / "wireless");
    std::filesystem::create_symlink(pci_device, paths.net_root / "eth-test" / "device");
    std::filesystem::create_symlink(driver, pci_device / "driver");
    write(paths.net_root / "eth-test" / "operstate", "up\tfixture\n");
    write(paths.net_root / "eth-test" / "carrier", "1\n");

    write(paths.usb_root / "2-1" / "idVendor", "beef\n");
    write(paths.usb_root / "2-1" / "idProduct", "cafe\n");
    write(paths.dev_root / "tpm0", "not a device node");
    write(paths.tpm_root / "tpm0" / "tpm_version_major", "2\n");
    write(paths.rng_root / "rng_available", "sample-rng none\n");
    write(paths.rng_root / "rng_current", "sample-rng\n");
    write(paths.block_root / "disk-test" / "dev", "8:0\n");
    write(paths.block_root / "disk-test" / "ro", "0\n");
    write(paths.block_root / "disk-test" / "size", "1024\n");
    write(paths.cpu_vulnerabilities / "sample-vulnerability", "Mitigated\tby fixture\n");

    const std::string parsed_fixture = qprotect::cpp::detail::hardware_report_text(paths);
    test_hardware_report_schema(parsed_fixture);
    CHECK(parsed_fixture.find("boot\tsecure_boot\tenabled") != std::string::npos);
    CHECK(parsed_fixture.find("network\tpci_controller\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("iommu_group=17") != std::string::npos);
    CHECK(parsed_fixture.find("dma_security\tiommu_groups\tavailable") != std::string::npos);
    CHECK(parsed_fixture.find("network\tinterface\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("kind=wireless") != std::string::npos);
    CHECK(parsed_fixture.find("driver=sample_net") != std::string::npos);
    CHECK(parsed_fixture.find("%09") != std::string::npos);
    CHECK(parsed_fixture.find("bus\tusb_device\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("entropy\thardware_rng\tavailable") != std::string::npos);
    CHECK(parsed_fixture.find("storage\tblock_device\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("cpu_security\tvulnerability\treported") != std::string::npos);
    CHECK(parsed_fixture.find("trust\ttpm_device_nodes\tunavailable") != std::string::npos);
    CHECK(parsed_fixture.find("trust\ttpm_sysfs_device\tpresent") != std::string::npos);

    std::filesystem::remove(variables / "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    const std::string unknown_boot = qprotect::cpp::detail::hardware_report_text(paths);
    CHECK(unknown_boot.find("boot\tsecure_boot\tunknown") != std::string::npos);

    std::error_code cleanup_error;
    std::filesystem::remove_all(root, cleanup_error);
    CHECK(!cleanup_error);
}

} // namespace

int main() {
    try {
        const CryptoContext context;
        context.assert_ready();

        test_digests(context);
        test_hkdf(context);
        test_aes_gcm(context);
        test_ml_kem(context);
        test_ml_dsa(context);
        test_secure_bytes();
        test_context();
        test_json_canonical();
        test_json_parse();
        test_identity_normalization();
        test_envelope_roundtrip(context);
        test_envelope_failures(context);
        test_envelope_serialization(context);
        test_key_files(context);
        test_private_key_envelopes(context);
        test_disk_plan_helpers();
        test_disk_safety_report_validation();
        test_hardware_fixture_discovery();
    } catch (const std::exception& error) {
        std::cerr << "unit test harness error: " << error.what() << "\n";
        return 1;
    }

    std::cout << "unit tests: " << g_checks << " checks, " << g_failures
              << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
