"""Panic strategy flags shared by code that builds for metal and hosted targets."""

def panic_strategy():
    return select({
        Label("@retro_os//toolchain:freestanding"): ["-Cpanic=immediate-abort"],
        "//conditions:default": ["-Cpanic=abort"],
    })
