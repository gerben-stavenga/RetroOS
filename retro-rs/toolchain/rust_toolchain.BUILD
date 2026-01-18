# BUILD file for downloaded rust toolchain
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "rustc_bin",
    srcs = ["rustc/bin/rustc"],
)

filegroup(
    name = "rustc_lib",
    srcs = glob(["rustc/lib/**/*"]),
)

filegroup(
    name = "rustc",
    srcs = [":rustc_bin", ":rustc_lib"],
)

filegroup(
    name = "rustdoc_bin",
    srcs = ["rustc/bin/rustdoc"],
)

filegroup(
    name = "rust_std",
    srcs = glob(["rust-std-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/*"]),
)

exports_files(glob(["**/*"]))
