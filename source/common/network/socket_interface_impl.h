#pragma once

#include "envoy/network/socket.h"

#include "source/common/io/io_uring_impl.h"
#include "source/common/network/socket_interface.h"

namespace Envoy {
namespace Network {

class SocketInterfaceImpl : public SocketInterfaceBase {
public:
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
                                                absl::optional<int> domain);

protected:
  virtual int createFlags(Socket::Type socket_type) const;

  virtual IoHandlePtr makeSocket(int socket_fd, bool socket_v6only,
                                 absl::optional<int> domain) const;
};

DECLARE_FACTORY(SocketInterfaceImpl);

class IoUringSocketInterfaceExtension : public SocketInterfaceExtension {
public:
  IoUringSocketInterfaceExtension(Network::SocketInterface& sock_interface,
                                  std::shared_ptr<Io::IoUringFactory> io_uring_factory);

  // Server::BootstrapExtension
  void onServerInitialized() override;

protected:
  std::shared_ptr<Io::IoUringFactory> io_uring_factory_;
};

class IoUringSocketInterfaceImpl : public SocketInterfaceImpl {
public:
  // Server::Configuration::BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override {
    return "envoy.extensions.network.socket_interface.io_uring_socket_interface";
  };

  static IoHandlePtr makePlatformSpecificSocket(int socket_fd, bool socket_v6only,
                                                absl::optional<int> domain,
                                                const Io::IoUringFactory* io_uring_factory);

  // TODO (soulxu): making those configurable if needed.
  static constexpr uint32_t default_io_uring_size_ = 300;
  static constexpr uint32_t default_read_buffer_size = 8192;
  static constexpr bool use_submission_queue_polling_ = false;

protected:
  int createFlags(Socket::Type socket_type) const override;

  IoHandlePtr makeSocket(int socket_fd, bool socket_v6only,
                         absl::optional<int> domain) const override;

private:
  std::weak_ptr<Io::IoUringFactory> io_uring_factory_;
};

DECLARE_FACTORY(IoUringSocketInterfaceImpl);

} // namespace Network
} // namespace Envoy
