package(default_visibility = ["//visibility:public"])

exports_files([
    "binl64/wcc386",
    "binl64/wlink",
])

filegroup(
    name = "os2_c_runtime",
    srcs = glob([
        "binl64/**",
        "h/**",
        "lib386/**",
    ]),
)

alias(
    name = "c_runtime",
    actual = ":os2_c_runtime",
)
