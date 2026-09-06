#pragma once

// Internal header: not part of the public API. Defines the OpenSSL handle
// bundle that CryptoContext::handles() returns. Kept out of the public
// headers so consumers of the library never need OpenSSL types.

#include <openssl/provider.h>
#include <openssl/types.h>

namespace qprotect::cpp {

struct CryptoContextHandles {
    OSSL_LIB_CTX* libctx = nullptr;
    OSSL_PROVIDER* algorithm_provider = nullptr;
    OSSL_PROVIDER* base_provider = nullptr;
    const char* properties = nullptr;
};

} // namespace qprotect::cpp