load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "ext4_view",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "ext4_view",
    edition = "2021",
    rustc_flags = [
        "--cap-lints=allow",
        "-Cpanic=abort",
        "-Copt-level=z",
    ],
    deps = [
        "@bitflags//:bitflags",
        "@crc//:crc",
    ],
)
