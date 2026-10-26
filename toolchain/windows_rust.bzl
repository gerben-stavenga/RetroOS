"""Compile no_std guest Rust to COFF for the existing Windows DLL linker.

This emits code, not a Windows process runtime. Kernel gates are linked from
small NASM objects; guest callbacks use Rust's normal Win32 system ABI.
"""

def _windows_rust_library_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".lib")
    stdlib = ctx.files._stdlib
    sysroot = stdlib[0].path.split("/lib/rustlib/")[0]
    ctx.actions.run(
        executable = ctx.executable._rustc,
        arguments = [
            ctx.file.crate_root.path,
            "--crate-name=" + ctx.label.name,
            "--edition=2024",
            "--target=i686-pc-windows-gnu",
            "--sysroot=" + sysroot,
            "--crate-type=staticlib",
            "-Clto=fat",
            "-Cpanic=abort",
            "-Copt-level=z",
            "-Ccodegen-units=1",
            "-o", output.path,
        ],
        inputs = depset(
            ctx.files.srcs + [ctx.file.crate_root] + stdlib,
            transitive = [ctx.attr._rustc_lib[DefaultInfo].files],
        ),
        outputs = [output],
        mnemonic = "WindowsRustLibrary",
        progress_message = "Compiling guest Rust DLL code %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

windows_rust_library = rule(
    implementation = _windows_rust_library_impl,
    attrs = {
        "crate_root": attr.label(allow_single_file = [".rs"], mandatory = True),
        "srcs": attr.label_list(allow_files = [".rs"]),
        "_rustc": attr.label(
            default = "@rust_toolchain_x86_64_linux//:rustc_bin",
            executable = True,
            cfg = "exec",
        ),
        "_rustc_lib": attr.label(default = "@rust_toolchain_x86_64_linux//:rustc_lib"),
        "_stdlib": attr.label(default = "@rust_windows_std//:rustlib"),
    },
)
