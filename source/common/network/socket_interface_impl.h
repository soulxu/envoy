#pragma once

#include "envoy/network/socket.h"

#include "source/common/io/io_uring.h"
#include "source/common/network/socket_interface.h"

namespace Envoy {
namespace Network {

class SocketInterfaceImpl : public SocketInterfaceBase {
public:
  SocketInterfaceImpl() = default;
  SocketInterfaceImpl(std::shared_ptr<Io::IoUringFactory> io_uring_factory)
      : io_uring_factory_(io_uring_factory) {}

  // SocketInterface
  IoHandlePtr socket(Socket::Type socket_type, Address::Type addr_type, Address::IpVersion version,
                     bool socket_v6only, const SocketCreationOptions& options) const override;
  IoHandlePtr socket(Socket::Type socket_type, const Address::InstanceConstSharedPtr addr,
                     const SocketCreationOptions& options) const override;
  bool ipFamilySupported(int domain) override;

  // Server::Configuration::BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override {
    return "envoy.extensions.network.socket_interface.default_socket_interface";
  };

  static IoHandlePtr makePlatformSpecificSocket(int socket_fd, bool socket_v6only,
                                                absl::optional<int> domain,
                                                Io::IoUringFactory* io_uring_factory = nullptr);

  // TODO (soulxu): making those configurable if needed.
  static constexpr uint32_t DefaultIoUringSize = 300;
  static constexpr uint32_t DefaultReadBufferSize = 8192;
  static constexpr bool UseSubmissionQueuePolling = false;

protected:
  virtual IoHandlePtr makeSocket(int socket_fd, bool socket_v6only, absl::optional<int> domain,
                                 Io::IoUringFactory* io_uring_factory = nullptr) const;

private:
  std::shared_ptr<Io::IoUringFactory> io_uring_factory_{nullptr};
};

DECLARE_FACTORY(SocketInterfaceImpl);

class DefaultSocketInterfaceFactory : public SocketInterfaceFactory {
public:
  SocketInterfaceSharedPtr createSocketInterface(
      const Protobuf::Message& config,
      Server::Configuration::ServerFactoryContext& server_factory_context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override {
    return "envoy.network.socket_interface.default_socket_interface";
  };
};

} // namespace Network
} // namespace Envoy
