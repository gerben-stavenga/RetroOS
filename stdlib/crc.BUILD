load("@rules_rust//rust:defs.bzl", "rust_library")
load("@retro_os//toolchain:panic.bzl", "panic_strategy")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "crc",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "crc",
    edition = "2021",
    rustc_flags = [
        "--cap-lints=allow",
    ] + panic_strategy(),
    deps = ["@crc_catalog//:crc_catalog"],
)
