load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

# nuked-opl3 0.1.0 — pure-Rust Nuked-OPL3 (YMF262) FM synthesis core, patched
# no_std (see nuked_opl3_no_std.patch): only the integer-math `Opl3Chip` is
# compiled; the `Opl3Device` wrapper (f64 timers) and stereo-ext panning
# (f64::sin) stay behind features we never enable — the metal kernel builds
# with -sse and must not emit float code. Opt-level 2, not z: the per-sample
# synthesis loop runs at 49716 Hz while FM music plays.
rust_library(
    name = "nuked_opl3",
    srcs = glob(["src/**/*.rs"]),
    compile_data = ["src/docs.md"],
    crate_name = "nuked_opl3",
    edition = "2021",
    rustc_flags = [
        "--cap-lints=allow",
        "-Cpanic=abort",
        "-Copt-level=2",
    ],
)
