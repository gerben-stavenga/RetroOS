"""Hermetic Open Watcom rules for 32-bit Windows PE programs and DLLs."""

def _windows_watcom_binary_impl(ctx):
    source = ctx.file.src
    output = ctx.outputs.exe
    watcom_root = ctx.executable._driver.dirname + "/.."
    runtime = ctx.attr._runtime[DefaultInfo].files
    ctx.actions.run(
        executable = ctx.executable._driver,
        arguments = [
            "-q",
            "-bt=nt",
            "-l=nt",
            "-fe=" + output.path,
            source.path,
        ],
        env = {
            "WATCOM": watcom_root,
            "INCLUDE": watcom_root + "/h:" + watcom_root + "/h/nt",
            "LIB": watcom_root + "/lib386/nt:" + watcom_root + "/lib386",
            "PATH": watcom_root + "/binl64:/usr/bin:/bin",
        },
        inputs = depset([source], transitive = [runtime]),
        outputs = [output],
        mnemonic = "WindowsWatcomCrtLink",
        progress_message = "Building normal Open Watcom Win32 program %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

windows_watcom_binary = rule(
    implementation = _windows_watcom_binary_impl,
    outputs = {"exe": "%{name}.exe"},
    attrs = {
        "src": attr.label(allow_single_file = [".c"], mandatory = True),
        "_driver": attr.label(
            default = "@open_watcom//:binl64/wcl386",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_runtime": attr.label(default = "@open_watcom//:c_runtime"),
    },
)

def _windows_dll_impl(ctx):
    obj = ctx.file.obj
    output = ctx.outputs.out
    response = ctx.actions.declare_file(ctx.label.name + ".lnk")
    watcom_root = ctx.executable._linker.dirname + "/.."
    ctx.actions.write(
        output = response,
        content = "\n".join([
            "format windows nt dll",
            "option quiet",
            "option modname=%s" % ctx.attr.module_name,
            "name %s" % output.path,
            "file %s" % obj.path,
        ] + ["export %s" % symbol for symbol in ctx.attr.exports]) + "\n",
    )
    ctx.actions.run(
        executable = ctx.executable._linker,
        arguments = ["@" + response.path],
        env = {"WATCOM": watcom_root},
        inputs = depset([obj, response], transitive = [ctx.attr._runtime[DefaultInfo].files]),
        outputs = [output],
        mnemonic = "WindowsWatcomDllLink",
        progress_message = "Linking Win32 DLL %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

windows_dll = rule(
    implementation = _windows_dll_impl,
    attrs = {
        "obj": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.output(mandatory = True),
        "module_name": attr.string(mandatory = True),
        "exports": attr.string_list(mandatory = True),
        "_linker": attr.label(
            default = "@open_watcom//:binl64/wlink",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_runtime": attr.label(default = "@open_watcom//:c_runtime"),
    },
)

def _windows16_dll_impl(ctx):
    obj = ctx.file.obj
    output = ctx.outputs.out
    response = ctx.actions.declare_file(ctx.label.name + ".lnk")
    watcom_root = ctx.executable._linker.dirname + "/.."
    ctx.actions.write(
        output = response,
        content = "\n".join([
            "format windows dll",
            "option quiet",
            "option modname=%s" % ctx.attr.module_name,
            "name %s" % output.path,
            "file %s" % obj.path,
        ] + ["export %s" % symbol for symbol in ctx.attr.exports]) + "\n",
    )
    ctx.actions.run(
        executable = ctx.executable._linker,
        arguments = ["@" + response.path],
        env = {"WATCOM": watcom_root},
        inputs = depset([obj, response], transitive = [ctx.attr._runtime[DefaultInfo].files]),
        outputs = [output],
        mnemonic = "Windows16WatcomDllLink",
        progress_message = "Linking Win16 NE DLL %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

windows16_dll = rule(
    implementation = _windows16_dll_impl,
    attrs = {
        "obj": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.output(mandatory = True),
        "module_name": attr.string(mandatory = True),
        "exports": attr.string_list(mandatory = True),
        "_linker": attr.label(
            default = "@open_watcom//:binl64/wlink",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_runtime": attr.label(default = "@open_watcom//:c_runtime"),
    },
)
