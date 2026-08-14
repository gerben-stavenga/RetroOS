"""Run a test target in Bazel's host platform configuration."""

def _host_transition_impl(_settings, _attr):
    return {"//command_line_option:platforms": str(Label("@platforms//host"))}

_host_transition = transition(
    implementation = _host_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _host_platform_test_impl(ctx):
    test = ctx.attr.test[0][DefaultInfo]
    launcher = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(
        output = launcher,
        target_file = test.files_to_run.executable,
        is_executable = True,
    )
    return [DefaultInfo(
        executable = launcher,
        files = depset([launcher], transitive = [test.files]),
        runfiles = test.default_runfiles,
    )]

host_platform_test = rule(
    implementation = _host_platform_test_impl,
    attrs = {
        "test": attr.label(cfg = _host_transition, mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    test = True,
    doc = "Forwards a test executable built for @platforms//host.",
)
