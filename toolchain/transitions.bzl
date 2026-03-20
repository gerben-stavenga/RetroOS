"""Platform transitions for building multi-arch binaries."""

def _x86_64_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//toolchain:x86_64_retro_none"}

_x86_64_transition = transition(
    implementation = _x86_64_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _x86_64_target_impl(ctx):
    return [DefaultInfo(files = ctx.attr.dep[0][DefaultInfo].files)]

x86_64_target = rule(
    implementation = _x86_64_target_impl,
    attrs = {
        "dep": attr.label(cfg = _x86_64_transition),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    doc = "Build a target for the x86_64 platform.",
)
