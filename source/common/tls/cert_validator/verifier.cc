#include "verifier.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

ValidationResults::ValidationStatus CryptoMBVerifier::verify(X509_STORE_CTX *ctx) {
    // int n = (int)sk_X509_num(ctx->chain);
    // n--;
    // X509 *xi = sk_X509_value(ctx->chain, n);
    // EVP_PKEY *pkey = X509_get_pubkey(xi);

    if (X509_verify_cert(ctx) == 1) {
        return ValidationResults::ValidationStatus::Successful;
    }
    return ValidationResults::ValidationStatus::Failed;
}

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy