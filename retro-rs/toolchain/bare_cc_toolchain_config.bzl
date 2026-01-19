"""Minimal CC toolchain config for bare-metal targets."""

def _bare_cc_toolchain_config_impl(ctx):
    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "i686-retro-none",
        host_system_name = "x86_64-unknown-linux-gnu",
        target_system_name = "i686-retro-none",
        target_cpu = "i686",
        target_libc = "none",
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = [],
        cxx_builtin_include_directories = [],
    )

bare_cc_toolchain_config = rule(
    implementation = _bare_cc_toolchain_config_impl,
    attrs = {},
    provides = [CcToolchainConfigInfo],
)
