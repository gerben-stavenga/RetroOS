load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "crc",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "crc",
    edition = "2021",
    rustc_flags = [
        "--cap-lints=allow",
        "-Cpanic=abort",
        "-Copt-level=z",
    ],
    deps = ["@crc_catalog//:crc_catalog"],
)
