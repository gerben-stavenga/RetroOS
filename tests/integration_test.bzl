"""Integration tests consume declared host/metal artifacts in private workspaces."""

def _host_impl(_settings, _attr):
    return {"//command_line_option:platforms": str(Label("@platforms//host"))}

def _metal_impl(_settings, _attr):
    return {"//command_line_option:platforms": str(Label("//toolchain:i686_retro_none"))}

_host = transition(implementation = _host_impl, inputs = [], outputs = ["//command_line_option:platforms"])
_metal = transition(implementation = _metal_impl, inputs = [], outputs = ["//command_line_option:platforms"])

def _impl(ctx):
    sources = ctx.files.sources
    artifacts = ctx.files.metal + ctx.files.host
    manifest = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(manifest, json.encode({
        "command": ctx.attr.command,
        "env": ctx.attr.env,
        "targets": {"//" + t.label.package + ":" + t.label.name: [f.short_path for f in t[DefaultInfo].files.to_list()] for t in ctx.attr.metal + ctx.attr.host},
        "sources": [{"key": ctx.workspace_name + "/" + f.short_path, "path": f.short_path} for f in sources],
        "artifacts": [{"key": ctx.workspace_name + "/" + f.short_path, "path": f.short_path} for f in artifacts],
    }))
    launcher = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(launcher, """#!/bin/bash
set -eu
exec "$TEST_SRCDIR/%s/%s" "$TEST_SRCDIR/%s/%s" "$@"
""" % (ctx.workspace_name, ctx.executable._runner.short_path, ctx.workspace_name, manifest.short_path), is_executable = True)
    return [DefaultInfo(
        executable = launcher,
        runfiles = ctx.runfiles(files = sources + artifacts + [manifest]).merge(ctx.attr._runner[DefaultInfo].default_runfiles),
    )]

_integration_test = rule(
    implementation = _impl,
    test = True,
    attrs = {
        "command": attr.string_list(mandatory = True),
        "env": attr.string_dict(),
        "sources": attr.label_list(allow_files = True),
        "metal": attr.label_list(cfg = _metal, allow_files = True),
        "host": attr.label_list(cfg = _host, allow_files = True),
        "_runner": attr.label(default = "//tests:runner", executable = True, cfg = "exec"),
        "_allowlist_function_transition": attr.label(default = "@bazel_tools//tools/allowlists/function_transition_allowlist"),
    },
)

def integration_test(name, tags = [], **kwargs):
    """Declare one test; tags select suites, dependencies select build platforms."""
    defaults = {"size": "small", "timeout": "short"} if "unit" in tags else {"size": "large", "timeout": "long"}
    defaults.update(kwargs)
    # Guest clocks, frame presentation and audio are affected by concurrent
    # compilers/emulators. Bazel schedules these after builds and serially.
    execution_tags = tags if "unit" in tags else tags + ["exclusive"]
    _integration_test(name = name, tags = execution_tags, **defaults)
