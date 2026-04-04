load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "bitflags",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "bitflags",
    edition = "2021",
    rustc_flags = [
        "--cap-lints=allow",
        "-Cpanic=abort",
        "-Copt-level=z",
    ],
)
