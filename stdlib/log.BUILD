load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "log",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "log",
    edition = "2021",
    rustc_flags = [
        "--cap-lints=allow",
        "-Cpanic=abort",
    ],
)
