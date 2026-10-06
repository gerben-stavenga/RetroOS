load("@rules_nasm//nasm:defs.bzl", "nasm_library")
load("//toolchain:windows_watcom.bzl", "windows_dll")

def compat_dll(name, module, exports):
    nasm_library(
        name = name + "_obj",
        srcs = [name + ".asm"],
        copts = ["-fwin32"],
    )
    windows_dll(
        name = name + "_dll",
        obj = ":" + name + "_obj",
        out = module + ".DLL",
        module_name = module,
        exports = exports,
        visibility = ["//visibility:public"],
    )
