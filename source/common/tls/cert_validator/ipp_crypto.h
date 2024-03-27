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
  virtual uint32_t mbx_nistp256_ecdsa_verify_mb8(const uint8_t* const pa_sign_r[8],
                                                  const uint8_t* const pa_sign_s[8],
                                                  const uint8_t* const pa_msg[8],
                                                 const uint64_t* const pa_pubx[8],
                                                 const uint64_t* const pa_puby[8],
                                                 const uint64_t* const pa_pubz[8],
                                                        uint8_t* pBuffer) PURE;
};

using IppCryptoSharedPtr = std::shared_ptr<IppCrypto>;

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy