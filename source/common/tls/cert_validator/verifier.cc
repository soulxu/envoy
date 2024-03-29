#include "verifier.h"

#include "source/common/tls/cert_validator/ipp_crypto_impl.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

int custom_verify(EVP_PKEY_CTX *ctx, 
                  const uint8_t *sig, size_t siglen,
                  const uint8_t * tbs,
                  size_t //tbslen
                  ) {
    ENVOY_LOG_MISC(debug, "custom verify!!!!!!!!!!!!!!!!!!\n");

    // uint8_t pa_sign_r[8][32];
    // uint8_t pa_sign_s[8][32];
    // EVP_PKEY_fetch_parameters(ctx, sig, siglen, &pa_sign_r[0][0], &pa_sign_s[0][0]);

    // uint8_t pa_pubx[8][32];
    // uint8_t pa_puby[8][32];
    // uint8_t pa_pubz[8][32];
    // EVP_PKEY_fetch_points(ctx, &pa_pubx[0][0], &pa_puby[0][0], &pa_pubz[0][0]);

    // uint8_t *sign_r[8];
    // for (int i = 0; i < 8; i++) {
    //   sign_r[i] = &pa_sign_r[i][0];
    // }
    // uint8_t *sign_s[8];
    // for (int i = 0; i < 8; i++) {
    //   sign_s[i] = &pa_sign_s[i][0];
    // }

    // const uint64_t* pubx[8];
    // for (int i = 0; i < 8; i++) {
    //   pubx[i] = reinterpret_cast<uint64_t*>(&pa_pubx[i][0]);
    // }
    // const uint64_t* puby[8];
    // for (int i = 0; i < 8; i++) {
    //   puby[i] = reinterpret_cast<uint64_t*>(&pa_puby[i][0]);
    // }
    // const uint64_t* pubz[8];
    // for (int i = 0; i < 8; i++) {
    //   pubz[i] = reinterpret_cast<uint64_t*>(&pa_pubz[i][0]);
    // }
    

    ECDSA_SIG *ec_sigs[8] = {nullptr};
    for (int i = 0; i < 8; i++) {
      ec_sigs[i] = ECDSA_SIG_from_bytes(sig, siglen);
      if (ec_sigs[i] == nullptr) {
          ENVOY_LOG_MISC(debug, "parse the signature failed");
      }
    }
    const uint8_t* msg[8];
    for (int i = 0; i < 8; i++) {
      msg[i] = tbs;
    }

    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    if (ec_key == nullptr || group == nullptr) {
      ENVOY_LOG_MISC(debug, "parse the pub key failed");
      return 0;
    }

    BIGNUM x;
    BIGNUM y;
    EC_POINT_get_affine_coordinates_GFp(group, pub_key, &x, &y, nullptr);

    BIGNUM* pubx[8] = {nullptr};
    BIGNUM* puby[8] = {nullptr};
    for (int i = 0; i < 8; i++) {
      pubx[i] = &x;
      puby[i] = &y;
    }
    // OPENSSL_EXPORT int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
    //                                                    const EC_POINT *point,
    //                                                    BIGNUM *x, BIGNUM *y,
    //                                                    BN_CTX *ctx);
    IppCryptoImpl crypto;
    return crypto.mbx_nistp256_ecdsa_verify_ssl_mb8(ec_sigs, msg, pubx, puby, nullptr, nullptr);
    // uint32_t mbx_nistp256_ecdsa_verify_ssl_mb8(const ECDSA_SIG* const pa_sig[8],
    //                                          const uint8_t*  const pa_msg[8],
    //                                          const BIGNUM* const pa_pubx[8],
    //                                          const BIGNUM* const pa_puby[8],
    //                                          const BIGNUM* const pa_pubz[8],                                       
    //                                                uint8_t* pBuffer)
  
    // return crypto.mbx_nistp256_ecdsa_verify_mb8(sign_r, sign_s, msg, pubx, puby, pubz, nullptr) == 0;
    // mbx_status mbx_nistp256_ecdsa_verify_mb8(const int8u* const pa_sign_r[8],
    //                                               const int8u* const pa_sign_s[8],
    //                                               const int8u* const pa_msg[8],
    //                                              const int64u* const pa_pubx[8],
    //                                              const int64u* const pa_puby[8],
    //                                              const int64u* const pa_pubz[8],
    //                                                     int8u* pBuffer);
    // return 0;
}

ValidationResults::ValidationStatus CryptoMBVerifier::verify(X509_STORE_CTX *ctx) {
    ENVOY_LOG_MISC(debug, "####### CryptoMBVerifier::verify");
    // int n = (int)sk_X509_num(ctx->chain);
    // n--;
    // X509 *xi = sk_X509_value(ctx->chain, n);
    // EVP_PKEY *pkey = X509_get_pubkey(xi);
    EVP_PKEY_set_ec_verify_method(custom_verify);
    if (X509_verify_cert(ctx) == 1) {
        return ValidationResults::ValidationStatus::Successful;
    }
    return ValidationResults::ValidationStatus::Failed;
}

} // Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy