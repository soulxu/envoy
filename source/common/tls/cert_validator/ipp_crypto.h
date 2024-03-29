#pragma once

#include "envoy/common/pure.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

class IppCrypto {
public:
  virtual ~IppCrypto() = default;

  virtual int mbxIsCryptoMbApplicable(uint64_t features) PURE;
  virtual uint32_t mbx_nistp256_ecdsa_verify_ssl_mb8(const ECDSA_SIG* const pa_sig[8],
                                             const uint8_t*  const pa_msg[8],
                                             const BIGNUM* const pa_pubx[8],
                                             const BIGNUM* const pa_puby[8],
                                             const BIGNUM* const pa_pubz[8],                                       
                                                   uint8_t* pBuffer) PURE;
};

using IppCryptoSharedPtr = std::shared_ptr<IppCrypto>;

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy