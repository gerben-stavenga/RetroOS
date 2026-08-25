load("@rules_nasm//nasm:defs.bzl", "nasm_library")
load("//toolchain:windows_watcom.bzl", "windows16_dll")

def win16_dll(name, module, exports):
    nasm_library(
        name = name + "_obj",
        srcs = [name + ".asm"],
        copts = ["-fobj"],
    )
    windows16_dll(
        name = name + "_dll",
        obj = ":" + name + "_obj",
        out = module + ".DLL",
        module_name = module,
        exports = exports,
        visibility = ["//visibility:public"],
    )
