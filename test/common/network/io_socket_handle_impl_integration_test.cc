#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/common/logger.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/listen_socket_impl.h"

#include "test/mocks/api/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/threadsafe_singleton_injector.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::AnyNumber;
using testing::Invoke;
using testing::Return;

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

class IoSocketHandleImplPeekTest : public TcpListenerCallbacks,
                                   public testing::TestWithParam<Address::IpVersion> {
public:
  void initialize() {
    api_ = Api::createApiForTest();
    dispatcher_ = api_->allocateDispatcher("test_thread");
    listener_socket_ = std::make_shared<Network::Test::TcpListenSocketImmediateListen>(
        Network::Test::getCanonicalLoopbackAddress(GetParam()));
    listener_ = dispatcher_->createListener(listener_socket_, *this, true);

    client_connection_ = dispatcher_->createClientConnection(
        listener_socket_->connectionInfoProvider().localAddress(),
        Network::Address::InstanceConstSharedPtr(), Network::Test::createRawBufferSocket(),
        nullptr);
    client_connection_->connect();
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    EXPECT_TRUE(new_socket_ != nullptr);
    new_socket_->ioHandle().initializeFileEvent(
        *dispatcher_,
        [&](uint32_t events) {
          EXPECT_EQ(Event::FileReadyType::Read, events);
          cb_();
        },
        Event::PlatformDefaultTriggerType, Event::FileReadyType::Read);
  }

  void onAccept(ConnectionSocketPtr&& socket) override { new_socket_ = std::move(socket); }
  void onReject(RejectCause) override {}

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

TEST_P(IoSocketHandleImplPeekTest, Basic) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  bool is_called = false;
  cb_ = [&]() {
    is_called = true;
    auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ(4, result.return_value_);
    EXPECT_EQ("abcd", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_TRUE(is_called);
  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, Error) {
  Api::MockOsSysCalls os_sys_calls;
  Api::OsSysCallsImpl os_sys_calls_actual;
  TestThreadsafeSingletonInjector<Api::OsSysCallsImpl> os_calls(&os_sys_calls);
  EXPECT_CALL(os_sys_calls, connect(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t sockfd, const sockaddr* addr, socklen_t addrlen) {
        return os_sys_calls_actual.connect(sockfd, addr, addrlen);
      }));
#ifdef WIN32
  EXPECT_CALL(os_sys_calls, readv(_, _, _))
      .Times(AnyNumber())
      .WillOnce(Return(Api::SysCallSizeResult{-1, 0}));
#else
  EXPECT_CALL(os_sys_calls, recv(_, _, _, _))
      .Times(AnyNumber())
      .WillOnce(Return(Api::SysCallSizeResult{-1, 0}));
  EXPECT_CALL(os_sys_calls, readv(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t fd, const iovec* iov, int iovcnt) {
        return os_sys_calls_actual.readv(fd, iov, iovcnt);
      }));
#endif
  EXPECT_CALL(os_sys_calls, writev(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t fd, const iovec* iov, int iovcnt) {
        return os_sys_calls_actual.writev(fd, iov, iovcnt);
      }));
  EXPECT_CALL(os_sys_calls, getsockopt_(_, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t sockfd, int level, int optname, void* optval,
                                 socklen_t* optlen) -> int {
        return os_sys_calls_actual.getsockopt(sockfd, level, optname, optval, optlen).return_value_;
      }));
  EXPECT_CALL(os_sys_calls, getsockname(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(
          Invoke([&](os_fd_t sockfd, sockaddr* name, socklen_t* namelen) -> Api::SysCallIntResult {
            return os_sys_calls_actual.getsockname(sockfd, name, namelen);
          }));
  EXPECT_CALL(os_sys_calls, shutdown(_, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(
          [&](os_fd_t sockfd, int how) { return os_sys_calls_actual.shutdown(sockfd, how); }));
  EXPECT_CALL(os_sys_calls, close(_)).Times(AnyNumber()).WillRepeatedly(Invoke([&](os_fd_t fd) {
    return os_sys_calls_actual.close(fd);
  }));
  EXPECT_CALL(os_sys_calls, accept(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(
          [&](os_fd_t sockfd, sockaddr* addr, socklen_t* addrlen) -> Api::SysCallSocketResult {
            return os_sys_calls_actual.accept(sockfd, addr, addrlen);
          }));
  EXPECT_CALL(os_sys_calls, socket(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](int domain, int type, int protocol) -> Api::SysCallSocketResult {
        return os_sys_calls_actual.socket(domain, type, protocol);
      }));
  EXPECT_CALL(os_sys_calls, setsocketblocking(_, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t sockfd, bool blocking) -> Api::SysCallIntResult {
        return os_sys_calls_actual.setsocketblocking(sockfd, blocking);
      }));
  EXPECT_CALL(os_sys_calls, bind(_, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(
          [&](os_fd_t sockfd, const sockaddr* addr, socklen_t addrlen) -> Api::SysCallIntResult {
            return os_sys_calls_actual.bind(sockfd, addr, addrlen);
          }));
  EXPECT_CALL(os_sys_calls, listen(_, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t sockfd, int backlog) -> Api::SysCallIntResult {
        return os_sys_calls_actual.listen(sockfd, backlog);
      }));
  EXPECT_CALL(os_sys_calls, setsockopt_(_, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke([&](os_fd_t sockfd, int level, int optname, const void* optval,
                                 socklen_t optlen) -> int {
        return os_sys_calls_actual.setsockopt(sockfd, level, optname, optval, optlen).return_value_;
      }));

  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  bool is_called = false;
  cb_ = [&]() {
    is_called = true;
    auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_FALSE(result.ok());
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_TRUE(is_called);
  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, RemoteClose) {
  initialize();
  char buf[5] = {'\0'};
  bool is_called = false;
  cb_ = [&]() {
    is_called = true;
    auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ(0, result.return_value_);
    EXPECT_TRUE(result.ok());
  };
  client_connection_->close(ConnectionCloseType::NoFlush);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_TRUE(is_called);
}

TEST_P(IoSocketHandleImplPeekTest, RemoteClose2) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  bool is_called = false;
  cb_ = [&]() {
    is_called = true;
    auto result = new_socket_->ioHandle().recv(buf, 5, MSG_PEEK);
    EXPECT_EQ(0, result.return_value_);
    EXPECT_TRUE(result.ok());
  };
  client_connection_->write(*buffer, false);
  client_connection_->close(ConnectionCloseType::NoFlush);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_TRUE(is_called);
}

TEST_P(IoSocketHandleImplPeekTest, EnsureReadEventWillbeEmitAfterInitializeFileEvent) {
  initialize();
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  int call_count = 0;
  cb_ = [&]() {
    call_count++;
    auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ(4, result.return_value_);
    EXPECT_EQ("abcd", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  new_socket_->ioHandle().resetFileEvents();
  new_socket_->ioHandle().initializeFileEvent(
      *dispatcher_,
      [&](uint32_t events) {
        EXPECT_EQ(Event::FileReadyType::Read, events);
        cb_();
      },
      Event::PlatformDefaultTriggerType, Event::FileReadyType::Read);
  char buf2[5] = {'\0'};
  cb_ = [&]() {
    call_count++;
    auto result = new_socket_->ioHandle().recv(buf2, 4, 0);
    EXPECT_EQ(4, result.return_value_);
    EXPECT_EQ("abcd", std::string(buf2));
  };
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_EQ(2, call_count);
  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, MultiplePeeks) {
  initialize();

  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("a");
  char buf[3] = {'\0'};

  // Test there is no data in the socket yet.
  auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
  EXPECT_EQ(result.return_value_, 0);
  EXPECT_TRUE(result.wouldBlock());

  int call_count = 0;
  cb_ = [&]() {
    call_count++;
    auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ(1, result.return_value_);
    EXPECT_EQ("a", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  buffer->drain(1);
  buffer->add("b");
  cb_ = [&]() {
    call_count++;
    auto result = new_socket_->ioHandle().recv(buf, 4, MSG_PEEK);
    EXPECT_EQ(2, result.return_value_);
    EXPECT_EQ("ab", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_EQ(2, call_count);
  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, RecvAfterPeek) {
  initialize();
  bool is_called = false;
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  char buf[5] = {'\0'};
  cb_ = [&]() {
    is_called = true;
    auto result = new_socket_->ioHandle().recv(buf, 3, MSG_PEEK);
    EXPECT_EQ(3, result.return_value_);
    EXPECT_EQ("abc", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_TRUE(is_called);

  char buf2[5] = {'\0'};
  auto result1 = new_socket_->ioHandle().recv(buf2, 4, 0);
  EXPECT_EQ(3, result1.return_value_);

  char buf3[5] = {'\0'};
  auto result2 = new_socket_->ioHandle().recv(buf3, 4, 0);
  EXPECT_EQ(1, result2.return_value_);
  EXPECT_EQ("d", std::string(buf3));

  client_connection_->close(ConnectionCloseType::NoFlush);
}

TEST_P(IoSocketHandleImplPeekTest, ReadAfterPeek) {
  initialize();
  bool is_called = false;
  std::unique_ptr<Buffer::Instance> buffer = std::make_unique<Buffer::OwnedImpl>();
  buffer->add("abcd");
  std::unique_ptr<Buffer::Instance> read_buffer = std::make_unique<Buffer::OwnedImpl>();
  char buf[5] = {'\0'};
  cb_ = [&]() {
    is_called = true;
    auto result = new_socket_->ioHandle().recv(buf, 3, MSG_PEEK);
    EXPECT_EQ(3, result.return_value_);
    EXPECT_EQ("abc", std::string(buf));
  };
  client_connection_->write(*buffer, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  EXPECT_TRUE(is_called);

  auto result = new_socket_->ioHandle().read(*read_buffer, 4);
  EXPECT_EQ(3, result.return_value_);
  EXPECT_EQ("abc", read_buffer->toString());

  read_buffer->drain(read_buffer->length());
  auto result2 = new_socket_->ioHandle().read(*read_buffer, 4);
  EXPECT_EQ(1, result2.return_value_);
  EXPECT_EQ("d", read_buffer->toString());

  client_connection_->close(ConnectionCloseType::NoFlush);
}

} // namespace
} // namespace Network
} // namespace Envoy
