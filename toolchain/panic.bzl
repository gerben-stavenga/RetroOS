"""Keep panic handlers active in both freestanding and hosted builds."""

def panic_strategy():
    # immediate-abort bypasses the handler, hiding diagnostics in release images.
    # Match the custom target specs and the core/alloc bootstrap builds.
    return ["-Cpanic=abort"]
