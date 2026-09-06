#include "qprotect/self_test.hpp"

#include "qprotect/algorithms.hpp"
#include "qprotect/constants.hpp"
#include "qprotect/error.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <exception>
#include <iomanip>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace qprotect::cpp {
namespace {

std::vector<unsigned char> from_hex(const std::string& value) {
    if (value.size() % 2 != 0) {
        throw CryptoError("invalid hex test vector length");
    }
    std::vector<unsigned char> output;
    output.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        unsigned int byte = 0;
        const auto result = std::from_chars(
            value.data() + i,
            value.data() + i + 2,
            byte,
            16
        );
        if (result.ec != std::errc{} || result.ptr != value.data() + i + 2) {
            throw CryptoError("invalid hex test vector");
        }
        output.push_back(static_cast<unsigned char>(byte));
    }
    return output;
}

void add_check(SelfTestReport& report, const std::string& name, bool passed) {
    report.checks.push_back(SelfTestCheck{name, passed});
    report.passed = report.passed && passed;
}

template <typename Function>
void run_check(SelfTestReport& report, const std::string& name, Function&& function) {
    bool passed = false;
    try {
        passed = function();
    } catch (const std::exception&) {
        passed = false;
    }
    add_check(report, name, passed);
}


} // namespace

SelfTestReport run_self_tests(const CryptoContext& context) {
    SelfTestReport report;
    report.passed = true;
    report.provider = context.provider_name();

    run_check(report, "provider_self_test", [&context]() {
        return context.provider_self_test();
    });

    run_check(report, "provider_algorithm_inventory", [&context]() {
        context.assert_ready();
        return true;
    });

    run_check(report, "random_bytes", [&context]() {
        const SecureBytes first = context.random_bytes(64);
        const SecureBytes second = context.random_bytes(64);
        // Two independent random outputs must differ. Do not require every
        // byte position to differ: for uniform 64-byte strings that has only
        // a (255/256)^64 ~= 78% chance of holding and makes the test flaky.
        return first.size() == 64 && second.size() == 64 && first != second;
    });

    run_check(report, "sha384_known_answer", [&context]() {
        const std::string input = "abc";
        const SecureBytes output = digest(
            context,
            DigestAlgorithm::Sha384,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(input.data()),
                input.size()
            )
        );
        const auto expected = from_hex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        );
        return output.size() == expected.size() &&
               std::equal(output.begin(), output.end(), expected.begin());
    });

    run_check(report, "sha512_known_answer", [&context]() {
        const std::string input = "abc";
        const SecureBytes output = digest(
            context,
            DigestAlgorithm::Sha512,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(input.data()),
                input.size()
            )
        );
        const auto expected = from_hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        return output.size() == expected.size() &&
               std::equal(output.begin(), output.end(), expected.begin());
    });

    run_check(report, "hkdf_sha384_known_answer", [&context]() {
        const std::string ikm = "secret";
        const std::string salt = "salt";
        const std::string info = "info";
        const SecureBytes output = hkdf_sha384(
            context,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(ikm.data()),
                ikm.size()
            ),
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(salt.data()),
                salt.size()
            ),
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(info.data()),
                info.size()
            ),
            32
        );
        const auto expected = from_hex(
            "29c042775183ec5dbc2c085eb49502b15d9e8abe4a4c1ef98e8e0fb95ad5f6a9"
        );
        return output.size() == expected.size() &&
               std::equal(output.begin(), output.end(), expected.begin());
    });

    run_check(report, "aes_256_gcm_known_answer", [&context]() {
        const auto key = from_hex(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
        );
        const auto nonce = from_hex("cafebabefacedbaddecaf888");
        const auto plaintext = from_hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        );
        const auto aad = from_hex(
            "feedfacedeadbeeffeedfacedeadbeefabaddad2"
        );
        const auto expected_ciphertext = from_hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        );
        const auto expected_tag = from_hex(
            "2df7cd675b4f09163b41ebf980a7f638"
        );

        const AeadResult result = aes_256_gcm_encrypt(
            context,
            key,
            nonce,
            plaintext,
            aad
        );
        const SecureBytes recovered = aes_256_gcm_decrypt(
            context,
            key,
            nonce,
            result.ciphertext,
            result.tag,
            aad
        );
        return result.ciphertext.size() == expected_ciphertext.size() &&
               std::equal(
                   result.ciphertext.begin(),
                   result.ciphertext.end(),
                   expected_ciphertext.begin()
               ) &&
               result.tag.size() == expected_tag.size() &&
               std::equal(
                   result.tag.begin(),
                   result.tag.end(),
                   expected_tag.begin()
               ) &&
               recovered.size() == plaintext.size() &&
               std::equal(recovered.begin(), recovered.end(), plaintext.begin());
    });

    run_check(report, "ml_kem_1024_pairwise_consistency", [&context]() {
        const KEMKeyPair key_pair = generate_ml_kem_1024(context);
        const KEMEncapsulation encapsulation = encapsulate_ml_kem_1024(
            context,
            key_pair.public_key_der
        );
        const SecureBytes recovered_secret = decapsulate_ml_kem_1024(
            context,
            key_pair.private_key_der,
            encapsulation.ciphertext
        );
        return key_pair.key_id.size() == 32 &&
               encapsulation.ciphertext.size() == 1568 &&
               encapsulation.shared_secret.size() == 32 &&
               recovered_secret.size() == 32 &&
               encapsulation.shared_secret == recovered_secret;
    });

    run_check(report, "ml_dsa_87_pairwise_consistency", [&context]() {
        const SignatureKeyPair key_pair = generate_ml_dsa_87(context);
        const std::string message = "qprotect C++ module self-test";
        const SecureBytes signature = sign_ml_dsa_87(
            context,
            key_pair.private_key_der,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            )
        );
        const bool valid = verify_ml_dsa_87(
            context,
            key_pair.public_key_der,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            ),
            signature
        );

        SecureBytes invalid_signature(signature);
        if (!invalid_signature.empty()) {
            invalid_signature[0] ^= 0x01;
        }
        const bool invalid_rejected = !verify_ml_dsa_87(
            context,
            key_pair.public_key_der,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            ),
            invalid_signature
        );
        // ML-DSA-87 signatures are exactly 4627 bytes (FIPS 204).
        return key_pair.key_id.size() == 32 && signature.size() == 4627 &&
               valid && invalid_rejected;
    });

    return report;
}

} // namespace qprotect::cpp
