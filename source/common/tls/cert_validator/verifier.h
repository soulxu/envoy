#pragma once

#include "source/common/tls/cert_validator/cert_validator.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

class CryptoMBVerifier {
public: 
    ValidationResults::ValidationStatus verify(X509_STORE_CTX *ctx);
};

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy