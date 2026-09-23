#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

int run(const std::vector<std::string>& arguments) {
    const pid_t child = ::fork();
    if (child < 0) return -1;
    if (child == 0) {
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const std::string& item : arguments) argv.push_back(const_cast<char*>(item.c_str()));
        argv.push_back(nullptr);
        ::execv(argv[0], argv.data());
        _exit(127);
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

bool check(bool passed, const char* name) {
    std::cout << (passed ? "PASS " : "FAIL ") << name << '\n';
    return passed;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: qprotect_native_integration /path/to/qprotect\n";
        return 2;
    }
    char temporary[] = "/tmp/qprotect-native-integration-XXXXXX";
    char* directory = ::mkdtemp(temporary);
    if (directory == nullptr) return 1;
    const std::filesystem::path root(directory);
    const auto path = [&root](const char* name) { return root / name; };
    bool passed = true;
    const std::string tool = std::filesystem::absolute(argv[1]).string();
    passed &= check(run({tool, "--version"}) == 0, "native version command");
    passed &= check(run({tool, "doctor"}) == 0, "native doctor command");
    passed &= check(run({tool, "selftest"}) == 0, "native selftest command");

    passed &= check(run({tool, "keygen", "--type", "kem", "--private", path("recipient.pem").string(),
                         "--public", path("recipient.pub").string()}) == 0,
                    "native KEM key generation");
    passed &= check(run({tool, "keygen", "--type", "kem", "--private", path("other.pem").string(),
                         "--public", path("other.pub").string()}) == 0,
                    "second recipient key generation");
    passed &= check(run({tool, "keygen", "--type", "kem", "--private", path("wrong.pem").string(),
                         "--public", path("wrong.pub").string()}) == 0,
                    "unrelated recipient key generation");
    passed &= check(run({tool, "keygen", "--type", "sign", "--private", path("signer.pem").string(),
                         "--public", path("signer.pub").string()}) == 0,
                    "native signing key generation");

    const std::string message = "qprotect C++20 integration payload\n";
    { std::ofstream stream(path("plain.bin"), std::ios::binary); stream << message; }
    passed &= check(run({tool, "encrypt", "--input", path("plain.bin").string(), "--output",
                         path("payload.qpe").string(), "--recipient", path("recipient.pub").string(),
                         "--recipient", path("other.pub").string(), "--signer", path("signer.pem").string(),
                         "--context", "native-integration"}) == 0,
                    "signed multi-recipient encryption");
    passed &= check(run({tool, "decrypt", "--input", path("payload.qpe").string(), "--output",
                         path("recovered.bin").string(), "--recipient-private", path("recipient.pem").string(),
                         "--signer-public", path("signer.pub").string()}) == 0 &&
                    read_file(path("recovered.bin")) == message,
                    "signed envelope decrypt and payload comparison");
    passed &= check(run({tool, "decrypt", "--input", path("payload.qpe").string(), "--output",
                         path("wrong.bin").string(), "--recipient-private", path("wrong.pem").string(),
                         "--signer-public", path("signer.pub").string()}) != 0 && !std::filesystem::exists(path("wrong.bin")),
                    "wrong recipient rejected without plaintext output");

    const std::string identity = R"({"ip":"192.0.2.10","serial":"SN-7","gps":{"latitude":12.5,"longitude":-7.25}})";
    { std::ofstream stream(path("identity.json")); stream << identity; }
    passed &= check(run({tool, "identity-encrypt", "--input", path("identity.json").string(), "--output",
                         path("identity.qpe").string(), "--recipient", path("recipient.pub").string()}) == 0,
                    "identity encryption");
    passed &= check(run({tool, "identity-decrypt", "--input", path("identity.qpe").string(), "--output",
                         path("identity.out.json").string(), "--recipient-private", path("recipient.pem").string()}) == 0 &&
                    read_file(path("identity.out.json")).find("\"hardware_serial\": \"SN-7\"") != std::string::npos,
                    "identity normalization after authenticated decryption");

    struct stat status {};
    passed &= check(::stat(path("recipient.pem").c_str(), &status) == 0 && (status.st_mode & 0077) == 0,
                    "private key file permissions");
    passed &= check(run({tool, "disk", "plan", "--device", "/dev/null", "--mapper", "integration-test"}) != 0,
                    "disk planner rejects a non-block device");
    std::error_code cleanup_error;
    std::filesystem::remove_all(root, cleanup_error);
    return passed && !cleanup_error ? 0 : 1;
}
