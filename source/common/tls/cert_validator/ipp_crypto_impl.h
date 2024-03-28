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
  uint32_t mbx_nistp256_ecdsa_verify_mb8(const uint8_t* const pa_sign_r[8],
                                                  const uint8_t* const pa_sign_s[8],
                                                  const uint8_t* const pa_msg[8],
                                                 const uint64_t* const pa_pubx[8],
                                                 const uint64_t* const pa_puby[8],
                                                 const uint64_t* const pa_pubz[8],
                                                        uint8_t* pBuffer) override {
    return ::mbx_nistp256_ecdsa_verify_mb8(pa_sign_r, pa_sign_s, pa_msg,
                                           reinterpret_cast<const unsigned long long *const *>(&pa_pubx[0]),
                                           reinterpret_cast<const unsigned long long *const *>(&pa_puby[0]),
                                           reinterpret_cast<const unsigned long long *const *>(&pa_pubz[0]), pBuffer);
  }
};

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy