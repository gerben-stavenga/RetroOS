"""Platform transitions for building Rust binaries targeting linux-musl."""

def _musl_transition_impl(settings, attr):
    return {"//command_line_option:platforms": str(Label("//toolchain:i686_linux_musl"))}

_musl_transition = transition(
    implementation = _musl_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _musl_binary_impl(ctx):
    bin = ctx.attr.binary[0]
    return [DefaultInfo(
        files = bin[DefaultInfo].files,
        runfiles = bin[DefaultInfo].default_runfiles,
    )]

musl_binary = rule(
    implementation = _musl_binary_impl,
    attrs = {
        "binary": attr.label(cfg = _musl_transition, mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

def _musl64_transition_impl(settings, attr):
    return {"//command_line_option:platforms": str(Label("//toolchain:x86_64_linux_musl"))}

_musl64_transition = transition(
    implementation = _musl64_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

musl64_binary = rule(
    implementation = _musl_binary_impl,
    attrs = {
        "binary": attr.label(cfg = _musl64_transition, mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
