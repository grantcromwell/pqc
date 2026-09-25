#include "qprotect/crypto_context.hpp"
#include "qprotect/error.hpp"
#include "qprotect/self_test.hpp"

#include <iostream>
#include <string>

namespace {

enum class Result { Pass, Fail, Throw };
Result result = Result::Pass;
int calls = 0;

}

namespace qprotect::cpp {

SelfTestReport run_self_tests(const CryptoContext& context) {
    ++calls;
    if (result == Result::Throw) {
        throw CryptoError("startup test exception");
    }
    const bool passed = result == Result::Pass;
    return SelfTestReport{passed, context.provider_name(), {{"startup_fixture", passed}}};
}

}

int main() {
    using qprotect::cpp::CryptoContext;
    using qprotect::cpp::CryptoError;
    try {
        const CryptoContext context;
        if (calls != 1) return 1;
        for (const Result failure : {Result::Fail, Result::Throw}) {
            result = failure;
            bool rejected = false;
            try {
                const CryptoContext blocked;
            } catch (const CryptoError& error) {
                const std::string expected = failure == Result::Fail
                    ? "required algorithm self-test failed" : "startup test exception";
                rejected = error.what() == expected;
            }
            if (!rejected) return 1;
        }
        if (calls != 3) return 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "startup gate: success, failure, and exception checks passed\n";
    return 0;
}
