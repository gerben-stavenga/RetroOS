"""Small, hermetic Open Watcom rules for 32-bit OS/2 LX programs."""

def _os2_watcom_binary_impl(ctx):
    source = ctx.file.src
    output = ctx.outputs.exe
    watcom_root = ctx.executable._driver.dirname + "/.."
    runtime = ctx.attr._runtime[DefaultInfo].files
    ctx.actions.run(
        executable = ctx.executable._driver,
        arguments = [
            "-q",
            "-bt=os2",
            "-l=os2v2",
            "-fe=" + output.path,
            source.path,
        ],
        env = {
            "WATCOM": watcom_root,
            "INCLUDE": watcom_root + "/h:" + watcom_root + "/h/os2",
            "LIB": watcom_root + "/lib386/os2:" + watcom_root + "/lib386",
            "PATH": watcom_root + "/binl64:/usr/bin:/bin",
        },
        inputs = depset([source], transitive = [runtime]),
        outputs = [output],
        mnemonic = "Os2WatcomCrtLink",
        progress_message = "Building normal Open Watcom OS/2 program %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

os2_watcom_binary = rule(
    implementation = _os2_watcom_binary_impl,
    outputs = {"exe": "%{name}.exe"},
    attrs = {
        "src": attr.label(allow_single_file = [".c"], mandatory = True),
        "_driver": attr.label(
            default = "@open_watcom//:binl64/wcl386",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_runtime": attr.label(default = "@open_watcom//:os2_c_runtime"),
    },
)

def _os2_c_binary_impl(ctx):
    source = ctx.file.src
    output = ctx.outputs.exe
    obj = ctx.actions.declare_file(ctx.label.name + ".obj")
    response = ctx.actions.declare_file(ctx.label.name + ".lnk")

    # File.dirname is a string in Bazel's Starlark API. Keeping the `..` in
    # this path also avoids depending on a separate path utility module.
    watcom_root = ctx.executable._compiler.dirname + "/.."
    env = {"WATCOM": watcom_root}
    inputs = depset([source], transitive = [ctx.attr._runtime[DefaultInfo].files])

    ctx.actions.run(
        executable = ctx.executable._compiler,
        arguments = [
            "-q",
            "-bt=os2",
            "-mf",
            "-s",
            "-zl",
            "-i=" + watcom_root + "/h/os2",
            "-fo=" + obj.path,
            source.path,
        ],
        env = env,
        inputs = inputs,
        outputs = [obj],
        mnemonic = "Os2WatcomCompile",
        progress_message = "Compiling OS/2 C %{label}",
    )

    import_lines = []
    for symbol, target in sorted(ctx.attr.imports.items()):
        import_lines.append("import %s %s" % (symbol, target))
    ctx.actions.write(
        output = response,
        content = "\n".join([
            "format os2 lx",
            "option quiet",
            "option nostub",
            "option start=%s" % ctx.attr.entry,
            "option stack=%d" % ctx.attr.stack,
            "name %s" % output.path,
            "file %s" % obj.path,
        ] + import_lines) + "\n",
    )
    ctx.actions.run(
        executable = ctx.executable._linker,
        arguments = ["@" + response.path],
        env = env,
        inputs = depset([obj, response], transitive = [ctx.attr._runtime[DefaultInfo].files]),
        outputs = [output],
        mnemonic = "Os2WatcomLink",
        progress_message = "Linking OS/2 LX %{label}",
    )

    return [DefaultInfo(files = depset([output]))]

os2_c_binary = rule(
    implementation = _os2_c_binary_impl,
    outputs = {"exe": "%{name}.exe"},
    attrs = {
        "src": attr.label(allow_single_file = [".c"], mandatory = True),
        # Open Watcom's default C naming appends an underscore.
        "entry": attr.string(default = "_start_"),
        "imports": attr.string_dict(),
        "stack": attr.int(default = 65536),
        "_compiler": attr.label(
            default = "@open_watcom//:binl64/wcc386",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_linker": attr.label(
            default = "@open_watcom//:binl64/wlink",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_runtime": attr.label(default = "@open_watcom//:os2_c_runtime"),
    },
)

def _os2_binary_from_obj_impl(ctx):
    obj = ctx.file.obj
    output = ctx.outputs.out
    response = ctx.actions.declare_file(ctx.label.name + ".lnk")
    watcom_root = ctx.executable._linker.dirname + "/.."
    import_lines = [
        "import %s %s" % (symbol, target)
        for symbol, target in sorted(ctx.attr.imports.items())
    ]

    ctx.actions.write(
        output = response,
        content = "\n".join([
            "format os2 lx",
            "option quiet",
            "option nostub",
            "option start=%s" % ctx.attr.entry,
            "option stack=%d" % ctx.attr.stack,
            "name %s" % output.path,
            "file %s" % obj.path,
        ] + import_lines) + "\n",
    )
    ctx.actions.run(
        executable = ctx.executable._linker,
        arguments = ["@" + response.path],
        env = {"WATCOM": watcom_root},
        inputs = depset(
            [obj, response],
            transitive = [ctx.attr._runtime[DefaultInfo].files],
        ),
        outputs = [output],
        mnemonic = "Os2WatcomLink",
        progress_message = "Linking OS/2 LX %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

os2_binary_from_obj = rule(
    implementation = _os2_binary_from_obj_impl,
    attrs = {
        "obj": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.output(mandatory = True),
        "entry": attr.string(mandatory = True),
        "imports": attr.string_dict(),
        "stack": attr.int(default = 65536),
        "_linker": attr.label(
            default = "@open_watcom//:binl64/wlink",
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
        "_runtime": attr.label(default = "@open_watcom//:os2_c_runtime"),
    },
)

def _os2_dll_impl(ctx):
    obj = ctx.file.obj
    output = ctx.outputs.out
    response = ctx.actions.declare_file(ctx.label.name + ".lnk")
    watcom_root = ctx.executable._linker.dirname + "/.."

    ctx.actions.write(
        output = response,
        content = "\n".join([
            "format os2 lx dll initglobal termglobal",
            "option quiet",
            "option nostub",
            "option modname=%s" % ctx.attr.module_name,
            "name %s" % output.path,
            "file %s" % obj.path,
        ] + ["export %s" % symbol for symbol in ctx.attr.exports]) + "\n",
    )
    ctx.actions.run(
        executable = ctx.executable._linker,
        arguments = ["@" + response.path],
        env = {"WATCOM": watcom_root},
        inputs = depset(
            [obj, response],
            transitive = [ctx.attr._runtime[DefaultInfo].files],
        ),
        outputs = [output],
        mnemonic = "Os2WatcomDllLink",
        progress_message = "Linking OS/2 DLL %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

os2_dll = rule(
    implementation = _os2_dll_impl,
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
        "_runtime": attr.label(default = "@open_watcom//:os2_c_runtime"),
    },
)
