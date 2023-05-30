#include "envoy/extensions/regex_engines/v3/google_re2.pb.h"
#include "envoy/type/matcher/v3/regex.pb.h"

#include "test/integration/base_integration_test.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace {

class RegexEngineIntegrationTest
    : public testing::TestWithParam<
          std::tuple<Network::Address::IpVersion, Network::DefaultSocketInterface>>,
      public BaseIntegrationTest {
public:
  RegexEngineIntegrationTest()
      : BaseIntegrationTest(std::get<0>(GetParam()), std::get<1>(GetParam()), config()) {}

  // Ensure that regex definitions in the stats matcher config will parse too
  static std::string config() {
    return absl::StrCat(ConfigHelper::baseConfigNoListeners(), R"EOF(
stats_config:
  stats_matcher:
    exclusion_list:
      patterns:
        - safe_regex:
            regex: "foobar.+"
        - safe_regex:
            regex: "barbaz.+"

default_regex_engine:
  name: envoy.regex_engines.google_re2
  typed_config:
    '@type': type.googleapis.com/envoy.extensions.regex_engines.v3.GoogleRE2
    )EOF");
  }
};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, RegexEngineIntegrationTest,
    testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                     testing::ValuesIn(TestEnvironment::getSocketInterfacesForTest())),
    TestUtility::ipAndSocketInterfaceTestParamsToString);

TEST_P(RegexEngineIntegrationTest, GoogleRE2) {
  initialize();

  envoy::type::matcher::v3::RegexMatcher matcher;
  *matcher.mutable_regex() = ".*";

  EXPECT_NO_THROW(Regex::Utility::parseRegex(matcher));
};

} // namespace
} // namespace Envoy
