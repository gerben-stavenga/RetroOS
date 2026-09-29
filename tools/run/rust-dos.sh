# Rust-DOS boots RetroOS's native BIOS loader and the shared data disk.
launch() {
    [ "$FIRMWARE" = bios ] || fail "Rust-DOS requires BIOS firmware"
    [ "$HD" = ata ] || fail "Rust-DOS supports the ATA disk layout only"
    [ "$ARCH" != x64 ] || fail "Rust-DOS does not emulate an x64 CPU"
    [ "$SOUND" = sb ] || [ "$SOUND" = none ] || fail "Rust-DOS supports sb or none"
    [ "$HEADLESS$KVM" = 00 ] || fail "Rust-DOS does not support --headless or --kvm"
    [ -z "$COMMAND$HOST_DIR$WAV$SHOT$SB_AUDIO" ] && [ "$TRACE" = 0 ] ||
        fail "--cmd, --host, --wav, --screenshot, --trace and --sb-audio are unavailable with Rust-DOS"

    local binary="${RUST_DOS_BIN:-$SCRIPT_DIR/tmp/rust-dos/target/release/rust-dos}"
    [ -x "$binary" ] || fail "Rust-DOS binary missing: $binary (build it with cd tmp/rust-dos && cargo build --release)"
    binary=$(realpath "$binary")
    local cpu=486 sbtype=sb16
    [ "$ARCH" != 686 ] || cpu=pentium
    [ "$SOUND" != none ] || sbtype=none

    # Rust-DOS classifies .bin as a CD image regardless of -t hdd, and
    # resolves symlinks before checking the extension. A hard link preserves
    # writes to the locked persistent data disk without copying it.
    local data_link="${DATA_IMAGE}.rust-dos-$$.img"
    ln -L "$DATA_IMAGE" "$data_link" || fail "Rust-DOS needs a hard link next to the data image"
    RUST_DOS_IMAGE_LINK="$data_link"

    {
        printf '[emulator]\nmemsize=64\ncpu=%s\nmachine=svga\n' "$cpu"
        printf '[sound]\nsbtype=%s\n' "$sbtype"
        printf '[autoexec]\n'
        if [ "$FREEDOS" = 1 ]; then
            printf 'IMGMOUNT 2 "%s" -t hdd -fs none\n' "$RUST_DOS_IMAGE_LINK"
        else
            printf 'IMGMOUNT 2 "%s" -t hdd -fs none\n' "$WORK/boot.img"
            printf 'IMGMOUNT 3 "%s" -t hdd -fs none\n' "$RUST_DOS_IMAGE_LINK"
        fi
        printf 'BOOT -l 2\n'
    } > "$WORK/rust-dos.conf"

    cd "$WORK"
    run_vm "$binary" --config "$WORK/rust-dos.conf" --dir "$WORK" "${PASS[@]}"
}
