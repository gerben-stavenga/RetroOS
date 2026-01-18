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


exports_files(glob(["**/*"]))
