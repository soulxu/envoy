load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
    "envoy_cmake",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cmake(
    name = "ipp-crypto",
    cache_entries = {
        "BORINGSSL": "on",
        "DYNAMIC_LIB": "off",
        "MB_STANDALONE": "off",
    },
    defines = [
        "OPENSSL_USE_STATIC_LIBS=TRUE",
    ],
    lib_source = "@com_github_intel_ipp_crypto_crypto_mb//:all",
    out_lib_dir = "lib/intel64",
    out_static_libs = ["libcrypto_mb.a"],
    tags = ["skip_on_windows"],
    visibility = ["//visibility:private"],
    working_directory = "sources/ippcp/crypto_mb",
    # Use boringssl alias to select fips vs non-fips version.
    deps = ["//bazel:boringssl"],
)

envoy_cc_library(
    name = "ipp_crypto_wrapper_lib",
    hdrs = ["ipp_crypto.h"] + select({
        "//bazel:linux_x86_64": [
            "ipp_crypto_impl.h",
        ],
        "//conditions:default": [
        ],
    }),
    defines = select({
        "//bazel:linux_x86_64": [],
        "//conditions:default": [
            "IPP_CRYPTO_DISABLED=1",
        ],
    }),
    external_deps = ["ssl"],
    repository = "@envoy",
    deps = select({
        "//bazel:linux_x86_64": [
            ":ipp-crypto",
        ],
        "//conditions:default": [],
    }),
)

envoy_cc_library(
    name = "cert_validator_lib",
    srcs = [
        "default_validator.cc",
        "factory.cc",
        "san_matcher.cc",
        "utility.cc",
        "verifier.cc",
    ],
    hdrs = [
        "cert_validator.h",
        "default_validator.h",
        "factory.h",
        "san_matcher.h",
        "utility.h",
        "verifier.h",
    ],
    external_deps = [
        "ssl",
        "abseil_base",
        "abseil_hash",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":ipp_crypto_wrapper_lib",
        "//envoy/config:typed_config_interface",
        "//envoy/ssl:context_config_interface",
        "//envoy/ssl:ssl_socket_extended_info_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:matchers_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/common:utility_lib",
        "//source/common/config:utility_lib",
        "//source/common/stats:symbol_table_lib",
        "//source/common/stats:utility_lib",
        "//source/common/tls:stats_lib",
        "//source/common/tls:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/matcher/v3:pkg_cc_proto",
    ],
    alwayslink = 1,
)
