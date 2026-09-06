load("@rules_rust//rust:defs.bzl", "rust_library")
load("@retro_os//toolchain:panic.bzl", "panic_strategy")

package(default_visibility = ["//visibility:public"])

# no_std flavour: alloc + LFN, no chrono/std/unicode. `log_level_warn`
# compile-time-limits its logging to warnings and errors.
rust_library(
    name = "fatfs",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "fatfs",
    edition = "2021",
    crate_features = [
        "alloc",
        "lfn",
        "log_level_warn",
    ],
    deps = [
        "@bitflags//:bitflags",
        "@log//:log",
    ],
    rustc_flags = [
        "--cap-lints=allow",
    ] + panic_strategy(),
)
