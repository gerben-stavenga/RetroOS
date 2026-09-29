# Run Rust-DOS's own DOS shell with a disposable FAT16 copy of the packaged C:.
launch() {
    [ "$FIRMWARE" = bios ] || fail "Rust-DOS games mode requires BIOS firmware"
    [ "$FREEDOS" = 0 ] || fail "use the rust-dos backend for FreeDOS boot"
    [ "$ARCH" != x64 ] || fail "Rust-DOS does not emulate an x64 CPU"
    [ "$SOUND" = sb ] || [ "$SOUND" = none ] || fail "Rust-DOS supports sb or none"
    [ "$HEADLESS$KVM" = 00 ] || fail "Rust-DOS does not support --headless or --kvm"
    [ -z "$HOST_DIR$WAV$SHOT$SB_AUDIO" ] && [ "$TRACE" = 0 ] ||
        fail "--host, --wav, --screenshot, --trace and --sb-audio are unavailable with Rust-DOS"

    local binary="${RUST_DOS_BIN:-$SCRIPT_DIR/tmp/rust-dos/target/release/rust-dos}"
    [ -x "$binary" ] || fail "Rust-DOS binary missing: $binary (build it with cd tmp/rust-dos && cargo build --release)"
    binary=$(realpath "$binary")
    local cpu=486 sbtype=sb16 startup='C:\RETROOS\DN\DN.COM'
    [ "$ARCH" != 686 ] || cpu=pentium
    [ "$SOUND" != none ] || sbtype=none

    {
        printf '[emulator]\nmemsize=64\ncpu=%s\nmachine=svga\n' "$cpu"
        printf '[sound]\nsbtype=%s\n' "$sbtype"
        printf '[autoexec]\nIMGMOUNT C "%s" -t hdd\nC:\n' "$GAMES_IMAGE"
        # Use RetroOS's own DOS settings, keeping PATH and DN's writable
        # directories in step with the packaged CONFIG.SYS.
        while IFS= read -r setting; do
            case "$setting" in
                PATH=*) printf 'PATH %s\n' "${setting#PATH=}" ;;
                DN=*|DNSWP=*|TEMP=*) printf 'SET %s\n' "$setting" ;;
                START=*) startup="${setting#START=}" ;;
            esac
        done < "$SCRIPT_DIR/etc/CONFIG.SYS"
        [ -z "$COMMAND" ] || printf '%s\n' "$COMMAND"
        printf '%s\n' "$startup"
    } > "$WORK/rust-dos.conf"

    echo "Rust-DOS C: is a disposable FAT16 copy of the packaged DOS files."
    cd "$WORK"
    run_vm "$binary" --config "$WORK/rust-dos.conf" --dir "$WORK" "${PASS[@]}"
}
