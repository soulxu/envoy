#include "source/extensions/quic/crypto_stream/envoy_quic_crypto_server_stream.h"
#include "envoy_quic_crypto_server_stream.h"

namespace Envoy {
namespace Quic {

std::unique_ptr<quic::QuicCryptoServerStreamBase> CreateCryptoServerStreamWrapper(
    const quic::QuicCryptoServerConfig* crypto_config,
    quic::QuicCompressedCertsCache* compressed_certs_cache, quic::QuicSession* session,
    quic::QuicCryptoServerStreamBase::Helper* helper,
    Envoy::Event::Dispatcher& dispatcher,
    Envoy::Ssl::PrivateKeyMethodProviderSharedPtr private_key_method) {
  switch (session->connection()->version().handshake_protocol) {
    case quic::PROTOCOL_QUIC_CRYPTO:
      return quic::CreateCryptoServerStream(crypto_config, compressed_certs_cache, session, helper);
    case quic::PROTOCOL_TLS1_3:
      return std::unique_ptr<TlsServerHandshakerWrapper>(
          new TlsServerHandshakerWrapper(session, crypto_config, dispatcher, private_key_method));
    case quic::PROTOCOL_UNSUPPORTED:
      break;
  }
  return nullptr;
}

std::unique_ptr<quic::QuicCryptoServerStreamBase>
EnvoyQuicCryptoServerStreamFactoryImpl::createEnvoyQuicCryptoServerStream(
    const quic::QuicCryptoServerConfig* crypto_config,
    quic::QuicCompressedCertsCache* compressed_certs_cache, quic::QuicSession* session,
    quic::QuicCryptoServerStreamBase::Helper* helper,
    // Though this extension doesn't use the two parameters below, they might be used by
    // downstreams. Do not remove them.
    OptRef<const Network::DownstreamTransportSocketFactory> /*transport_socket_factory*/,
    Envoy::Event::Dispatcher& dispatcher,
     Envoy::Ssl::PrivateKeyMethodProviderSharedPtr private_key_method) {
  return CreateCryptoServerStreamWrapper(crypto_config, compressed_certs_cache, session, helper, dispatcher, private_key_method);
}

REGISTER_FACTORY(EnvoyQuicCryptoServerStreamFactoryImpl,
                 EnvoyQuicCryptoServerStreamFactoryInterface);

} // namespace Quic
} // namespace Envoy
