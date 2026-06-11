"""Pin a dependency to the canonical retro target platform.

The workspace default is `--platforms=//toolchain:i686_retro_none`; building
host-side binaries (retroos-host) overrides it to the host platform — which
would drag config-sensitive subtrees (the bootfs tar: in-OS TCC → image_min →
the i686 bootloader) into the host configuration and break them. Wrapping
such a dep in `retro_platform_cc` transitions it back to the canonical
platform, so it builds identically no matter who links it.
"""

def _retro_transition_impl(_settings, _attr):
    return {"//command_line_option:platforms": ["//toolchain:i686_retro_none"]}

_retro_transition = transition(
    implementation = _retro_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _retro_platform_files_impl(ctx):
    return [DefaultInfo(files = ctx.attr.dep[0][DefaultInfo].files)]

retro_platform_files = rule(
    implementation = _retro_platform_files_impl,
    attrs = {
        "dep": attr.label(cfg = _retro_transition),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    doc = "Forwards the files of a dep built in the canonical retro platform config.",
)
