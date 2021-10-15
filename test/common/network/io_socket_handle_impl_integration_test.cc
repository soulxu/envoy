#include "source/common/network/address_impl.h"
#include "source/common/network/listen_socket_impl.h"
#include "source/common/common/logger.h"

#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Network {
namespace {

// Only do the integration tests in supported platforms.
// This test requires external internet connectivity and as a result it might
// not work under in environments that limit the external connectivity.
// As such it is tagged with `requires-network` and is not executed in CI.
#if defined(TCP_INFO) || defined(SIO_TCP_INFO)
TEST(IoSocketHandleImplIntegration, LastRoundTripIntegrationTest) {
  struct sockaddr_in server;
  // TCP info can not be calculated on loopback.
  // For that reason we connect to a public dns server.
  server.sin_addr.s_addr = inet_addr("1.1.1.1");
  server.sin_family = AF_INET;
  server.sin_port = htons(80);

  Address::InstanceConstSharedPtr addr(new Address::Ipv4Instance(&server));
  auto socket_ = std::make_shared<Envoy::Network::ClientSocketImpl>(addr, nullptr);
  socket_->setBlockingForTest(true);
  EXPECT_TRUE(socket_->connect(addr).return_value_ == 0);

  EXPECT_TRUE(socket_->ioHandle().lastRoundTripTime() != absl::nullopt);
}
#endif


class IoSocketHandleImplPeekTest : public TcpListenerCallbacks, public testing::TestWithParam<Address::IpVersion>, public Logger::Loggable<Logger::Id::connection> {
public:
  void initialize() {
    api_ = Api::createApiForTest();
    dispatcher_ = api_->allocateDispatcher("test_thread");
    listener_socket_ = std::make_shared<Network::Test::TcpListenSocketImmediateListen>(
      Network::Test::getCanonicalLoopbackAddress(GetParam()));
    listener_ = dispatcher_->createListener(listener_socket_, *this, true);

    client_connection_ = dispatcher_->createClientConnection(
      listener_socket_->connectionInfoProvider().localAddress(), Network::Address::InstanceConstSharedPtr(),
      Network::Test::createRawBufferSocket(), nullptr);
    client_connection_->connect();
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    EXPECT_TRUE(new_socket_ != nullptr);
    new_socket_->ioHandle().initializeFileEvent(
        *dispatcher_,
        [&](uint32_t events) {
          EXPECT_EQ(Event::FileReadyType::Read, events);
          cb_();
        },
        Event::PlatformDefaultTriggerType,
        Event::FileReadyType::Read);
  }

  void onAccept(ConnectionSocketPtr&& socket) override {
    new_socket_ = std::move(socket);
  }
  void onReject(RejectCause cause) override {}

  
  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  std::shared_ptr<Network::TcpListenSocket> listener_socket_;
  Network::ListenerPtr listener_;
  ConnectionSocketPtr new_socket_{nullptr};
  Network::ClientConnectionPtr client_connection_;
  std::function<void()> cb_;
};
INSTANTIATE_TEST_SUITE_P(IpVersions, IoSocketHandleImplPeekTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);
                  
TEST_P(IoSocketHandleImplPeekTest, basic) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ("abcd", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, multiplePeeks) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("a");
  char buf[3] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ("a", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  buffer->drain(1);
  buffer->add("b");
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ("ab", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, recvAfterPeek) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf, 3, MSG_PEEK);
    EXPECT_EQ("abc", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  char buf2[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf2, 3, 0);
    EXPECT_EQ("abc", std::string(buf2));
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  char buf3[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf3, 3, 0);
    EXPECT_EQ("d", std::string(buf3));
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  char buf4[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf4, 3, MSG_PEEK);
    EXPECT_EQ("abc", std::string(buf4));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  char buf5[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf5, 4, 0);
    EXPECT_EQ("abcd", std::string(buf5));
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, readAfterPeek) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  std::unique_ptr<Buffer::Instance> read_buffer = std::make_unique<Buffer::OwnedImpl>();
  char buf[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf, 3, MSG_PEEK);
    EXPECT_EQ("abc", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  cb_ = [&]() {
    new_socket_->ioHandle().read(*read_buffer, 3);
    EXPECT_EQ("abc", read_buffer->toString());
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  read_buffer->drain(read_buffer->length());
  cb_ = [&]() {
    new_socket_->ioHandle().read(*read_buffer, 3);
    EXPECT_EQ("d", read_buffer->toString());
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  char buf2[5] = {'\0'};
  cb_ = [&]() {
    new_socket_->ioHandle().recv(buf2, 3, MSG_PEEK);
    EXPECT_EQ("abc", std::string(buf2));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  read_buffer->drain(read_buffer->length());
  cb_ = [&]() {
    new_socket_->ioHandle().read(*read_buffer, 4);
    EXPECT_EQ("abcd", read_buffer->toString());
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

  client_connection_->close(ConnectionCloseType::NoFlush);
}

} // namespace
} // namespace Network
} // namespace Envoy
