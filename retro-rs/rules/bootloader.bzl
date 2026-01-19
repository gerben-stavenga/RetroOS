"""Bootloader and kernel build rules for linking, binary extraction, and disk image creation."""

def _link_impl(ctx, mnemonic, progress_msg):
    """Common linking implementation for bootloader and kernel."""
    out = ctx.actions.declare_file(ctx.label.name + ".elf")

    inputs = []
    args = ["-m", "elf_i386", "-T", ctx.file.linker_script.path, "-o", out.path]
    inputs.append(ctx.file.linker_script)

    for obj in ctx.files.asm_objs:
        args.append(obj.path)
        inputs.append(obj)

    for lib in ctx.files.rust_libs:
        args.append(lib.path)
        inputs.append(lib)

    ctx.actions.run(
        inputs = inputs,
        outputs = [out],
        executable = "ld",
        arguments = args,
        mnemonic = mnemonic,
        progress_message = progress_msg,
    )

    return [DefaultInfo(files = depset([out]))]

def _bootloader_link_impl(ctx):
    return _link_impl(ctx, "LinkBootloader", "Linking bootloader %{output}")

def _kernel_link_impl(ctx):
    return _link_impl(ctx, "LinkKernel", "Linking kernel %{output}")

_link_attrs = {
    "asm_objs": attr.label_list(
        allow_files = [".o"],
        doc = "Assembly object files",
    ),
    "rust_libs": attr.label_list(
        allow_files = [".a"],
        doc = "Rust static libraries",
    ),
    "linker_script": attr.label(
        mandatory = True,
        allow_single_file = [".ld"],
        doc = "Linker script",
    ),
}

bootloader_link = rule(
    implementation = _bootloader_link_impl,
    attrs = _link_attrs,
)

kernel_link = rule(
    implementation = _kernel_link_impl,
    attrs = _link_attrs,
)

def _binary_impl(ctx, mnemonic, progress_msg):
    """Common binary extraction implementation."""
    out = ctx.actions.declare_file(ctx.label.name + ".bin")
    elf = ctx.file.elf

    ctx.actions.run(
        inputs = [elf],
        outputs = [out],
        executable = "objcopy",
        arguments = ["-O", "binary", elf.path, out.path],
        mnemonic = mnemonic,
        progress_message = progress_msg,
    )

    return [DefaultInfo(files = depset([out]))]

def _bootloader_binary_impl(ctx):
    return _binary_impl(ctx, "ObjcopyBootloader", "Extracting bootloader binary from %{input}")

def _kernel_binary_impl(ctx):
    return _binary_impl(ctx, "ObjcopyKernel", "Extracting kernel binary from %{input}")

_binary_attrs = {
    "elf": attr.label(
        mandatory = True,
        allow_single_file = [".elf"],
        doc = "ELF file to extract binary from",
    ),
}

bootloader_binary = rule(
    implementation = _bootloader_binary_impl,
    attrs = _binary_attrs,
)

kernel_binary = rule(
    implementation = _kernel_binary_impl,
    attrs = _binary_attrs,
)

