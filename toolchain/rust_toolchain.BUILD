# BUILD file for downloaded rust toolchain
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "rustc_bin",
    srcs = ["rustc/bin/rustc"],
)

filegroup(
    name = "rustc_lib",
    # rustc/lib (librustc_driver + LLVM) plus the real clippy-driver, so both land
    # under the toolchain's single sysroot root and the clippy wrapper can reach them.
    srcs = glob(["rustc/lib/**/*"]) + ["clippy-preview/bin/clippy-driver"],
)

filegroup(
    name = "rustc",
    srcs = [":rustc_bin", ":rustc_lib"],
)

filegroup(
    name = "rustdoc_bin",
    srcs = ["rustc/bin/rustdoc"],
)

# The real clippy-driver binary, bundled into the toolchain's rustc_lib sysroot
# tree (see :rustc_lib below) so the //toolchain wrapper can exec it. clippy_driver
# itself points at that wrapper, which fixes up LD_LIBRARY_PATH for librustc_driver.
filegroup(
    name = "clippy_driver_real",
    srcs = ["clippy-preview/bin/clippy-driver"],
)

filegroup(
    name = "rust_std",
    srcs = glob(["rust-std-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/*"]),
)

exports_files(glob(["**/*"]))
