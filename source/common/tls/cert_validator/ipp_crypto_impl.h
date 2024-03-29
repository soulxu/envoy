#pragma once

#include "source/common/tls/cert_validator/ipp_crypto.h"
#include "crypto_mb/cpu_features.h"
#include "crypto_mb/ec_nistp256.h"
#include "crypto_mb/rsa.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

class IppCryptoImpl : public virtual IppCrypto {
public:
  int mbxIsCryptoMbApplicable(uint64_t features) override {
    return ::mbx_is_crypto_mb_applicable(features);
  }
  uint32_t mbx_nistp256_ecdsa_verify_ssl_mb8(const ECDSA_SIG* const pa_sig[8],
                                             const uint8_t*  const pa_msg[8],
                                             const BIGNUM* const pa_pubx[8],
                                             const BIGNUM* const pa_puby[8],
                                             const BIGNUM* const pa_pubz[8],                                       
                                                   uint8_t* pBuffer) override {
    return ::mbx_nistp256_ecdsa_verify_ssl_mb8(pa_sig, pa_msg, pa_pubx, pa_puby, pa_pubz, pBuffer);
  }
};

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy