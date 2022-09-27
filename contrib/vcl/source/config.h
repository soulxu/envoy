#pragma once

#include "source/common/network/socket_interface.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace Vcl {

class VclSocketInterfaceExtension : public Envoy::Network::SocketInterfaceExtension {
public:
  VclSocketInterfaceExtension(Envoy::Network::SocketInterface& sock_interface)
      : Envoy::Network::SocketInterfaceExtension(sock_interface) {}
};

class VclSocketInterface : public Envoy::Network::SocketInterfaceBase {
public:
  // Network::SocketInterface
  Envoy::Network::IoHandlePtr socket(Envoy::Network::Socket::Type socket_type,
                                     Envoy::Network::Address::Type addr_type,
                                     Envoy::Network::Address::IpVersion version, bool socket_v6only,
                                     const Envoy::Network::SocketCreationOptions&) const override;
  Envoy::Network::IoHandlePtr socket(Envoy::Network::Socket::Type socket_type,
                                     const Envoy::Network::Address::InstanceConstSharedPtr addr,
                                     const Envoy::Network::SocketCreationOptions&) const override;
  bool ipFamilySupported(int domain) override;

  // Server::Configuration::BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override { return "envoy.extensions.vcl.vcl_socket_interface"; };
};

DECLARE_FACTORY(VclSocketInterface);

class VclSocketInterfaceFactory : public Envoy::Network::SocketInterfaceFactory {
public:
  Envoy::Network::SocketInterfaceSharedPtr createSocketInterface(
      const Protobuf::Message& config,
      Server::Configuration::ServerFactoryContext& server_factory_context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override {
    return "envoy.network.socket_interface.vcl_socket_interface";
  };
};

} // namespace Vcl
} // namespace Network
} // namespace Extensions
} // namespace Envoy
