# BUILD file for rust-src archive
package(default_visibility = ["//visibility:public"])

# Include all library files needed for core (including .md docs for include_str!)
filegroup(
    name = "core_src",
    srcs = glob([
        "library/**/*",
    ]),
)

filegroup(
    name = "alloc_src",
    srcs = glob([
        "library/**/*",
    ]),
)

# In-tree compiler-builtins source — matches nightly's std build and uses
# `core` by path, so the compiler accepts the internal Debug/Display
# derives without tripping the "upstream monomorphizations" check that
# the crates.io shim runs into.
filegroup(
    name = "compiler_builtins_intree_src",
    srcs = glob([
        "library/compiler-builtins/compiler-builtins/src/**/*",
        "library/compiler-builtins/libm/src/**/*",
    ]),
)


exports_files(glob(["**/*"]))
