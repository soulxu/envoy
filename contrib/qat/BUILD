load("//bazel:envoy_build_system.bzl", "envoy_contrib_package")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load(
    "//contrib:all_contrib_extensions.bzl",
    "envoy_contrib_linux_x86_64_constraints",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

# Have qatlib outside of any extensions because it may be used by both
# QAT compression library extension and QAT private key provider
# extension.

configure_make(
    name = "qatlib",
    autogen = False,
    configure_in_place = True,
    #configure_options = [
    #    "--enable-icp-sriov=guest",
    #],
    copts = [
        "-Wno-unused-command-line-argument",
        "-Wno-enum-conversion",
        "-Wno-error=sizeof-array-decay",
        "-Wno-error=unneeded-internal-declaration",
    ],
    #copts = ["-Qunused-arguments",
    #         "-Qenum-conversion"],
    #env = {
    #      "CXX": "/home/xuhj/clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04/bin/clang++",
    #      "CC": "/home/xuhj/clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04/bin/clang",
    #},
    lib_source = "@com_github_intel_qatlib//:all",
    out_shared_libs = [
        "libqat_s.so",
        "libusdm_drv_s.so",
    ],
    target_compatible_with = envoy_contrib_linux_x86_64_constraints(),
    visibility = ["//visibility:public"],
    #deps = ["@boringssl//:ssl"],
    #alwayslink = True,
)
