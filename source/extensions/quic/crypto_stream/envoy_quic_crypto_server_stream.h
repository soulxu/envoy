#pragma once

#include "envoy/extensions/quic/crypto_stream/v3/crypto_stream.pb.h"
#include "envoy/registry/registry.h"
#include "envoy/ssl/private_key/private_key.h"

#include "source/common/quic/envoy_quic_server_crypto_stream_factory.h"
#include "quiche/quic/core/tls_server_handshaker.h"

namespace Envoy {
namespace Quic {

class EnvoyQuicCryptoServerStreamFactoryImpl : public EnvoyQuicCryptoServerStreamFactoryInterface {
public:
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::quic::crypto_stream::v3::CryptoServerStreamConfig>();
  }
  std::string name() const override { return "envoy.quic.crypto_stream.server.quiche"; }
  std::unique_ptr<quic::QuicCryptoServerStreamBase> createEnvoyQuicCryptoServerStream(
      const quic::QuicCryptoServerConfig* crypto_config,
      quic::QuicCompressedCertsCache* compressed_certs_cache, quic::QuicSession* session,
      quic::QuicCryptoServerStreamBase::Helper* helper,
      OptRef<const Network::DownstreamTransportSocketFactory> transport_socket_factory,
      Envoy::Event::Dispatcher& dispatcher,
      Envoy::Ssl::PrivateKeyMethodProviderSharedPtr private_key_method = nullptr) override;
};

DECLARE_FACTORY(EnvoyQuicCryptoServerStreamFactoryImpl);


class TlsServerHandshakerWrapper : public quic::TlsServerHandshaker, Ssl::PrivateKeyConnectionCallbacks {
public:
  TlsServerHandshakerWrapper(quic::QuicSession* session,
                      const quic::QuicCryptoServerConfig* crypto_config,
                      Envoy::Event::Dispatcher& dispatcher,
                      Envoy::Ssl::PrivateKeyMethodProviderSharedPtr private_key_method = nullptr) : quic::TlsServerHandshaker(session, crypto_config), dispatcher_(dispatcher), private_key_method_(private_key_method) {
    private_key_method_->registerPrivateKeyMethod(GetSsl(), *this, dispatcher_);
  }
  ~TlsServerHandshakerWrapper() override {
    private_key_method_->unregisterPrivateKeyMethod(GetSsl());
  }

  ssl_private_key_result_t PrivateKeySign(uint8_t* out, size_t* out_len,
                                          size_t max_out, uint16_t sig_alg,
                                          absl::string_view in) override {
    return private_key_method_->getBoringSslPrivateKeyMethod()->sign(GetSsl(), out, out_len, max_out, sig_alg, reinterpret_cast<const uint8_t *>(in.data()), in.size());
  }
  ssl_private_key_result_t PrivateKeyComplete(uint8_t* out, size_t* out_len,
                                              size_t max_out) override {
    return private_key_method_->getBoringSslPrivateKeyMethod()->complete(GetSsl(), out, out_len, max_out);                    
  }

  void onPrivateKeyMethodComplete() override {
    AdvanceHandshake();
  }
private:
  Envoy::Event::Dispatcher& dispatcher_;
  Envoy::Ssl::PrivateKeyMethodProviderSharedPtr private_key_method_;
};

} // namespace Quic
} // namespace Envoy
