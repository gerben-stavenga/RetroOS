"""Bootstrap mode for building stdlib without stdlib."""

# Config setting for bootstrap mode
BootstrapModeInfo = provider(fields = ["enabled"])

def _bootstrap_mode_flag_impl(ctx):
    return BootstrapModeInfo(enabled = ctx.build_setting_value)

bootstrap_mode_flag = rule(
    implementation = _bootstrap_mode_flag_impl,
    build_setting = config.bool(flag = True),
)

# Transition to enable bootstrap mode
def _enable_bootstrap_transition_impl(settings, attr):
    return {"//toolchain:bootstrap_mode": True}

enable_bootstrap_transition = transition(
    implementation = _enable_bootstrap_transition_impl,
    inputs = [],
    outputs = ["//toolchain:bootstrap_mode"],
)

# Rule that wraps a target and applies bootstrap transition
def _with_bootstrap_impl(ctx):
    target = ctx.attr.actual[0]
    return [
        target[DefaultInfo],
    ]

with_bootstrap = rule(
    implementation = _with_bootstrap_impl,
    attrs = {
        "actual": attr.label(mandatory = True, cfg = enable_bootstrap_transition),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
