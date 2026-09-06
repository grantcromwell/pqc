// qprotect C++ tool: key generation and KEM/AEAD envelope encryption for
// files, interoperating with the Python qprotect CLI's PEM keys and
// envelope JSON format.

#include "qprotect/algorithms.hpp"
#include "qprotect/crypto_context.hpp"
#include "qprotect/envelope.hpp"
#include "qprotect/error.hpp"
#include "qprotect/keys.hpp"
#include "qprotect/secure_bytes.hpp"
#include "qprotect/self_test.hpp"

#include "secure_file.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

using qprotect::cpp::CryptoContext;
using qprotect::cpp::CryptoError;
using qprotect::cpp::Envelope;
using qprotect::cpp::EnvelopeError;
using qprotect::cpp::SecureBytes;

struct Arguments {
    std::string command;
    std::string provider = "default";
    bool force = false;
    std::string key_type;
    std::string private_path;
    std::string public_path;
    std::string input_path;
    std::string output_path;
    std::vector<std::string> recipients;
    std::string signer_private_path;
    std::string recipient_private_path;
    std::string signer_public_path;
    std::string context = "file";
};

void usage(std::ostream& out) {
    out << "usage: qprotect_cpp_tool <command> [options]\n"
        << "\n"
        << "commands:\n"
        << "  keygen   --type kem|sign --private PATH --public PATH\n"
        << "  encrypt  --input PATH --output PATH --recipient PEM [--recipient PEM ...]\n"
        << "           [--signer PRIVPEM] [--context STR]\n"
        << "  decrypt  --input PATH --output PATH --recipient-private PRIVPEM\n"
        << "           [--signer-public PUBPEM]\n"
        << "\n"
        << "options:\n"
        << "  --provider NAME           select an installed OpenSSL provider\n"
        << "  --force                   atomically replace an existing output\n";
}

bool parse_arguments(int argc, char* argv[], Arguments& args) {
    if (argc < 2) {
        usage(std::cerr);
        return false;
    }
    args.command = argv[1];
    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                throw std::string("missing value for ") + argument;
            }
            return argv[++i];
        };
        try {
            if (argument == "--provider") {
                args.provider = value();
            } else if (argument == "--force") {
                args.force = true;
            } else if (argument == "--type") {
                args.key_type = value();
            } else if (argument == "--private") {
                args.private_path = value();
            } else if (argument == "--public") {
                args.public_path = value();
            } else if (argument == "--input") {
                args.input_path = value();
            } else if (argument == "--output") {
                args.output_path = value();
            } else if (argument == "--recipient") {
                args.recipients.push_back(value());
            } else if (argument == "--signer") {
                args.signer_private_path = value();
            } else if (argument == "--recipient-private") {
                args.recipient_private_path = value();
            } else if (argument == "--signer-public") {
                args.signer_public_path = value();
            } else if (argument == "--context") {
                args.context = value();
            } else {
                std::cerr << "unknown option: " << argument << "\n";
                usage(std::cerr);
                return false;
            }
        } catch (const std::string& error) {
            std::cerr << "error: " << error << "\n";
            return false;
        }
    }
    return true;
}

SecureBytes read_binary_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw EnvelopeError("unable to open input file: " + path);
    }
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    constexpr std::streamoff kMaximumPayload = 64LL * 1024 * 1024;
    if (size < 0 || size > kMaximumPayload) {
        throw EnvelopeError("input exceeds the 64 MiB envelope-v1 limit");
    }
    file.seekg(0, std::ios::beg);
    SecureBytes data(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
        if (!file) {
            throw EnvelopeError("unable to read input file: " + path);
        }
    }
    if (file.peek() != std::char_traits<char>::eof()) {
        throw EnvelopeError("input changed while it was being read");
    }
    return data;
}

void write_binary_file(
    const std::string& path,
    std::span<const unsigned char> data,
    bool overwrite
) {
    qprotect::cpp::detail::secure_write_file(path, data, 0600, overwrite);
}

std::string read_text_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw EnvelopeError("unable to open envelope file: " + path);
    }
    constexpr std::streamoff kMaximumEnvelope = 96LL * 1024 * 1024;
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0 || size > kMaximumEnvelope) {
        throw EnvelopeError("envelope document exceeds the format limit");
    }
    file.seekg(0, std::ios::beg);
    std::string contents(static_cast<std::size_t>(size), '\0');
    if (size > 0) {
        file.read(contents.data(), size);
        if (!file) {
            throw EnvelopeError("unable to read envelope file: " + path);
        }
    }
    if (file.peek() != std::char_traits<char>::eof()) {
        throw EnvelopeError("envelope changed while it was being read");
    }
    return contents;
}

void reject_same_path(const std::string& input, const std::string& output) {
    std::error_code error;
    const auto left = std::filesystem::weakly_canonical(input, error);
    if (error) {
        throw EnvelopeError("unable to resolve input path");
    }
    const auto right = std::filesystem::weakly_canonical(output, error);
    if (error) {
        throw EnvelopeError("unable to resolve output path");
    }
    if (left == right) {
        throw EnvelopeError("input and output must be different paths");
    }
}

int run_keygen(const CryptoContext& context, const Arguments& args) {
    if (args.key_type != "kem" && args.key_type != "sign") {
        std::cerr << "error: --type must be kem or sign\n";
        return 2;
    }
    if (args.private_path.empty() || args.public_path.empty()) {
        std::cerr << "error: keygen requires --private and --public\n";
        return 2;
    }
    reject_same_path(args.private_path, args.public_path);
    if (!args.force &&
        (std::filesystem::exists(args.private_path) || std::filesystem::exists(args.public_path))) {
        throw EnvelopeError("key output exists (use --force)");
    }

    if (args.key_type == "kem") {
        const qprotect::cpp::KEMKeyPair key_pair =
            qprotect::cpp::generate_ml_kem_1024(context);
        qprotect::cpp::write_private_key_pem(
            context, key_pair.private_key_der, args.private_path, args.force);
        qprotect::cpp::write_public_key_pem(
            context, key_pair.public_key_der, args.public_path, args.force);
        std::cout << "generated ML-KEM-1024 keypair, key_id " << key_pair.key_id << "\n";
    } else {
        const qprotect::cpp::SignatureKeyPair key_pair =
            qprotect::cpp::generate_ml_dsa_87(context);
        qprotect::cpp::write_private_key_pem(
            context, key_pair.private_key_der, args.private_path, args.force);
        qprotect::cpp::write_public_key_pem(
            context, key_pair.public_key_der, args.public_path, args.force);
        std::cout << "generated ML-DSA-87 keypair, key_id " << key_pair.key_id << "\n";
    }
    return 0;
}

int run_encrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() || args.recipients.empty()) {
        std::cerr << "error: encrypt requires --input, --output, and at least one --recipient\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);

    const SecureBytes plaintext = read_binary_file(args.input_path);

    qprotect::cpp::EncryptOptions options;
    options.context = args.context;
    for (const std::string& recipient : args.recipients) {
        options.recipient_public_key_der.push_back(
            qprotect::cpp::load_public_key_file(context, recipient));
    }
    if (!args.signer_private_path.empty()) {
        options.signer_private_key_der =
            qprotect::cpp::load_private_key_file(context, args.signer_private_path);
    }

    const Envelope envelope = qprotect::cpp::encrypt_envelope(
        context,
        std::span<const unsigned char>(plaintext.data(), plaintext.size()),
        options
    );
    const std::string json = envelope.to_json();
    write_binary_file(
        args.output_path,
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(json.data()),
            json.size()
        ),
        args.force
    );
    return 0;
}

int run_decrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() ||
        args.recipient_private_path.empty()) {
        std::cerr << "error: decrypt requires --input, --output, and --recipient-private\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);

    const std::string json = read_text_file(args.input_path);
    const Envelope envelope = Envelope::from_json(json);

    qprotect::cpp::DecryptOptions options;
    options.recipient_private_key_der =
        qprotect::cpp::load_private_key_file(context, args.recipient_private_path);
    if (!args.signer_public_path.empty()) {
        options.signer_public_key_der =
            qprotect::cpp::load_public_key_file(context, args.signer_public_path);
    }

    const SecureBytes plaintext = qprotect::cpp::decrypt_envelope(
        context, envelope, options);
    write_binary_file(
        args.output_path,
        std::span<const unsigned char>(plaintext.data(), plaintext.size()),
        args.force
    );
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    Arguments args;
    if (!parse_arguments(argc, argv, args)) {
        return 2;
    }

    try {
        const CryptoContext context(args.provider);
        const qprotect::cpp::SelfTestReport health = qprotect::cpp::run_self_tests(context);
        if (!health.passed) {
            throw CryptoError("required algorithm self-test failed");
        }
        if (args.command == "keygen") {
            return run_keygen(context, args);
        }
        if (args.command == "encrypt") {
            return run_encrypt(context, args);
        }
        if (args.command == "decrypt") {
            return run_decrypt(context, args);
        }
        std::cerr << "unknown command: " << args.command << "\n";
        usage(std::cerr);
        return 2;
    } catch (const EnvelopeError& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    } catch (const CryptoError& error) {
        std::cerr << "crypto error: " << error.what() << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "unexpected error: " << error.what() << "\n";
        return 1;
    }
}
