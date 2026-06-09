load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

# spin 0.9.8 — minimal features (just the spinlock Mutex), so no `lock_api` /
# `portable-atomic` deps. Edition 2015 (the crate declares no edition).
rust_library(
    name = "spin",
    srcs = glob(["src/**/*.rs"]),
    crate_name = "spin",
    crate_features = ["mutex", "spin_mutex"],
    edition = "2015",
    rustc_flags = [
        "--cap-lints=allow",
        "-Cpanic=abort",
        "-Copt-level=z",
    ],
)
