"""Platform transition for building freestanding no_std Rust for the bare
i686 target (//toolchain:i686_retro_none), mirroring toolchain/musl_transition.bzl.

There is no existing freestanding Rust *binary* in apps/ (all are musl-Linux),
so this transition is the new piece the dosrt scaffold needs. `retro_lib`
forwards a rust_static_library built under the bare platform; the BUILD then
links it with `ld -m elf_i386 -T <script>` (the kernel pattern).
"""

def _retro_transition_impl(_settings, _attr):
    return {"//command_line_option:platforms": str(Label("//toolchain:i686_retro_none"))}

_retro_transition = transition(
    implementation = _retro_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _retro_lib_impl(ctx):
    lib = ctx.attr.lib[0]
    return [DefaultInfo(files = lib[DefaultInfo].files)]

retro_lib = rule(
    implementation = _retro_lib_impl,
    attrs = {
        "lib": attr.label(cfg = _retro_transition, mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
