"""Re-exports all custom rules."""

load(
    ":bootloader.bzl",
    _bootloader_binary = "bootloader_binary",
    _bootloader_link = "bootloader_link",
    _kernel_binary = "kernel_binary",
    _kernel_link = "kernel_link",
)

bootloader_link = _bootloader_link
bootloader_binary = _bootloader_binary
kernel_link = _kernel_link
kernel_binary = _kernel_binary
