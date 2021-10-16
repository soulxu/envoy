#include "envoy/api/io_error.h"

#include "source/common/http/utility.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/listener_filter_buffer_impl.h"
#include "source/extensions/filters/listener/tls_inspector/tls_inspector.h"

#include "test/extensions/filters/listener/tls_inspector/tls_utility.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/threadsafe_singleton_injector.h"

#include "gtest/gtest.h"
#include "openssl/ssl.h"

using testing::_;
using testing::ByMove;
using testing::Eq;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::NiceMock;
using testing::Return;
using testing::ReturnNew;
using testing::ReturnRef;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {
namespace {

class TlsInspectorTest : public testing::TestWithParam<std::tuple<uint16_t, uint16_t>> {
public:
  TlsInspectorTest() : cfg_(std::make_shared<Config>(store_)) {}

  void init() {
    filter_ = std::make_unique<Filter>(cfg_);

    EXPECT_CALL(cb_, socket()).WillRepeatedly(ReturnRef(socket_));
    EXPECT_CALL(socket_, ioHandle()).WillRepeatedly(ReturnRef(io_handle_));
    EXPECT_CALL(io_handle_, createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                                             Event::FileReadyType::Read))
        .WillOnce(SaveArg<1>(&file_event_callback_));

    buffer_ = std::make_unique<Network::ListenerFilterBufferImpl>(
        io_handle_, dispatcher_, []() {}, []() {}, cfg_->maxClientHelloSize());
    filter_->onAccept(cb_);
  }

  Stats::IsolatedStoreImpl store_;
  ConfigSharedPtr cfg_;
  std::unique_ptr<Filter> filter_;
  Network::MockListenerFilterCallbacks cb_;
  Network::MockConnectionSocket socket_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  Event::FileReadyCb file_event_callback_;
  Network::MockIoHandle io_handle_;
  std::unique_ptr<Network::ListenerFilterBufferImpl> buffer_;
};

INSTANTIATE_TEST_SUITE_P(TlsProtocolVersions, TlsInspectorTest,
                         testing::Values(std::make_tuple(Config::TLS_MIN_SUPPORTED_VERSION,
                                                         Config::TLS_MAX_SUPPORTED_VERSION),
                                         std::make_tuple(TLS1_VERSION, TLS1_VERSION),
                                         std::make_tuple(TLS1_1_VERSION, TLS1_1_VERSION),
                                         std::make_tuple(TLS1_2_VERSION, TLS1_2_VERSION),
                                         std::make_tuple(TLS1_3_VERSION, TLS1_3_VERSION)));

// Test that an exception is thrown for an invalid value for max_client_hello_size
TEST_P(TlsInspectorTest, MaxClientHelloSize) {
  EXPECT_THROW_WITH_MESSAGE(Config(store_, Config::TLS_MAX_CLIENT_HELLO + 1), EnvoyException,
                            "max_client_hello_size of 65537 is greater than maximum of 65536.");
}

// Test that a ClientHello with an SNI value causes the correct name notification.
TEST_P(TlsInspectorTest, SniRegistered) {
  init();
  const std::string servername("example.com");
  std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
      std::get<0>(GetParam()), std::get<1>(GetParam()), servername, "");
  EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
      .WillOnce(
          Invoke([&client_hello](void* buffer, size_t length, int) -> Api::IoCallUint64Result {
            ASSERT(length >= client_hello.size());
            memcpy(buffer, client_hello.data(), client_hello.size());
            return Api::IoCallUint64Result(client_hello.size(),
                                           Api::IoErrorPtr(nullptr, [](Api::IoError*) {}));
          }));
  EXPECT_CALL(socket_, setRequestedServerName(Eq(servername)));
  EXPECT_CALL(socket_, setRequestedApplicationProtocols(_)).Times(0);
  EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
  // trigger the event to copy the client hello message into buffer
  file_event_callback_(Event::FileReadyType::Read);
  auto state = filter_->onData(*buffer_);
  EXPECT_EQ(Network::FilterStatus::Continue, state);
  EXPECT_EQ(1, cfg_->stats().tls_found_.value());
  EXPECT_EQ(1, cfg_->stats().sni_found_.value());
  EXPECT_EQ(1, cfg_->stats().alpn_not_found_.value());
}

// Test that a ClientHello with an ALPN value causes the correct name notification.
TEST_P(TlsInspectorTest, AlpnRegistered) {
  init();
  const auto alpn_protos = std::vector<absl::string_view>{Http::Utility::AlpnNames::get().Http2,
                                                          Http::Utility::AlpnNames::get().Http11};
  std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
      std::get<0>(GetParam()), std::get<1>(GetParam()), "", "\x02h2\x08http/1.1");
  EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
      .WillOnce(
          Invoke([&client_hello](void* buffer, size_t length, int) -> Api::IoCallUint64Result {
            ASSERT(length >= client_hello.size());
            memcpy(buffer, client_hello.data(), client_hello.size());
            return Api::IoCallUint64Result(client_hello.size(),
                                           Api::IoErrorPtr(nullptr, [](Api::IoError*) {}));
          }));
  EXPECT_CALL(socket_, setRequestedServerName(_)).Times(0);
  EXPECT_CALL(socket_, setRequestedApplicationProtocols(alpn_protos));
  EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
  // trigger the event to copy the client hello message into buffer
  file_event_callback_(Event::FileReadyType::Read);
  auto state = filter_->onData(*buffer_);
  EXPECT_EQ(Network::FilterStatus::Continue, state);
  EXPECT_EQ(1, cfg_->stats().tls_found_.value());
  EXPECT_EQ(1, cfg_->stats().sni_not_found_.value());
  EXPECT_EQ(1, cfg_->stats().alpn_found_.value());
}

// Test with the ClientHello spread over multiple socket reads.
TEST_P(TlsInspectorTest, MultipleReads) {
  init();
  const auto alpn_protos = std::vector<absl::string_view>{Http::Utility::AlpnNames::get().Http2};
  const std::string servername("example.com");
  std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
      std::get<0>(GetParam()), std::get<1>(GetParam()), servername, "\x02h2");
  {
    InSequence s;
    EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
        .WillOnce(InvokeWithoutArgs([]() -> Api::IoCallUint64Result {
          return Api::IoCallUint64Result(
              -1, Api::IoErrorPtr(Network::IoSocketError::getIoSocketEagainInstance(),
                                  Network::IoSocketError::deleteIoError));
        }));
    for (size_t i = 1; i <= client_hello.size(); i++) {
      EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
          .WillOnce(Invoke(
              [&client_hello, i](void* buffer, size_t length, int) -> Api::IoCallUint64Result {
                ASSERT(length >= client_hello.size());
                memcpy(buffer, client_hello.data(), client_hello.size());
                return Api::IoCallUint64Result(i, Api::IoErrorPtr(nullptr, [](Api::IoError*) {}));
              }));
    }
  }

  bool got_continue = false;
  EXPECT_CALL(socket_, setRequestedServerName(Eq(servername)));
  EXPECT_CALL(socket_, setRequestedApplicationProtocols(alpn_protos));
  EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
  while (!got_continue) {
    // trigger the event to copy the client hello message into buffer
    file_event_callback_(Event::FileReadyType::Read);
    auto state = filter_->onData(*buffer_);
    if (state == Network::FilterStatus::Continue) {
      got_continue = true;
    }
  }
  EXPECT_EQ(1, cfg_->stats().tls_found_.value());
  EXPECT_EQ(1, cfg_->stats().sni_found_.value());
  EXPECT_EQ(1, cfg_->stats().alpn_found_.value());
}

// Test that the filter correctly handles a ClientHello with no extensions present.
TEST_P(TlsInspectorTest, NoExtensions) {
  init();
  std::vector<uint8_t> client_hello =
      Tls::Test::generateClientHello(std::get<0>(GetParam()), std::get<1>(GetParam()), "", "");
  EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
      .WillOnce(
          Invoke([&client_hello](void* buffer, size_t length, int) -> Api::IoCallUint64Result {
            ASSERT(length >= client_hello.size());
            memcpy(buffer, client_hello.data(), client_hello.size());
            return Api::IoCallUint64Result(client_hello.size(),
                                           Api::IoErrorPtr(nullptr, [](Api::IoError*) {}));
          }));
  EXPECT_CALL(socket_, setRequestedServerName(_)).Times(0);
  EXPECT_CALL(socket_, setRequestedApplicationProtocols(_)).Times(0);
  EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
  // trigger the event to copy the client hello message into buffer
  file_event_callback_(Event::FileReadyType::Read);
  auto state = filter_->onData(*buffer_);
  EXPECT_EQ(Network::FilterStatus::Continue, state);
  EXPECT_EQ(1, cfg_->stats().tls_found_.value());
  EXPECT_EQ(1, cfg_->stats().sni_not_found_.value());
  EXPECT_EQ(1, cfg_->stats().alpn_not_found_.value());
}

// Test that the filter fails if the ClientHello is larger than the
// maximum allowed size.
TEST_P(TlsInspectorTest, ClientHelloTooBig) {
  const size_t max_size = 50;
  cfg_ = std::make_shared<Config>(store_, static_cast<uint32_t>(max_size));
  std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
      std::get<0>(GetParam()), std::get<1>(GetParam()), "example.com", "");
  ASSERT(client_hello.size() > max_size);

  filter_ = std::make_unique<Filter>(cfg_);

  EXPECT_CALL(cb_, socket()).WillRepeatedly(ReturnRef(socket_));
  EXPECT_CALL(socket_, ioHandle()).WillRepeatedly(ReturnRef(io_handle_));
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType, Event::FileReadyType::Read))
      .WillOnce(SaveArg<1>(&file_event_callback_));
  buffer_ = std::make_unique<Network::ListenerFilterBufferImpl>(
      io_handle_, dispatcher_, []() {}, []() {}, cfg_->maxClientHelloSize());

  filter_->onAccept(cb_);

  EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
      .WillOnce(
          Invoke([=, &client_hello](void* buffer, size_t length, int) -> Api::IoCallUint64Result {
            ASSERT(length == max_size);
            memcpy(buffer, client_hello.data(), length);
            return Api::IoCallUint64Result(length, Api::IoErrorPtr(nullptr, [](Api::IoError*) {}));
          }));
  EXPECT_CALL(io_handle_, close())
      .WillOnce(Return(
          ByMove(Api::IoCallUint64Result(0, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})))));

  // trigger the event to copy the client hello message into buffer
  file_event_callback_(Event::FileReadyType::Read);
  auto state = filter_->onData(*buffer_);
  EXPECT_EQ(Network::FilterStatus::StopIteration, state);
  EXPECT_EQ(1, cfg_->stats().client_hello_too_large_.value());
}

// Test that the filter fails on non-SSL data
TEST_P(TlsInspectorTest, NotSsl) {
  init();
  std::vector<uint8_t> data;

  // Use 100 bytes of zeroes. This is not valid as a ClientHello.
  data.resize(100);

  EXPECT_CALL(io_handle_, recv(_, _, MSG_PEEK))
      .WillOnce(Invoke([&data](void* buffer, size_t length, int) -> Api::IoCallUint64Result {
        ASSERT(length >= data.size());
        memcpy(buffer, data.data(), data.size());
        return Api::IoCallUint64Result(data.size(), Api::IoErrorPtr(nullptr, [](Api::IoError*) {}));
      }));
  // trigger the event to copy the client hello message into buffer
  file_event_callback_(Event::FileReadyType::Read);
  auto state = filter_->onData(*buffer_);
  EXPECT_EQ(Network::FilterStatus::Continue, state);
  EXPECT_EQ(1, cfg_->stats().tls_not_found_.value());
}

// Test that the deprecated extension name still functions.
TEST(TlsInspectorConfigFactoryTest, DEPRECATED_FEATURE_TEST(DeprecatedExtensionFilterName)) {
  const std::string deprecated_name = "envoy.listener.tls_inspector";

  ASSERT_NE(
      nullptr,
      Registry::FactoryRegistry<
          Server::Configuration::NamedListenerFilterConfigFactory>::getFactory(deprecated_name));
}

} // namespace
} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
