# Run Rust-DOS's own DOS shell with a disposable FAT16 copy of the packaged C:.
launch() {
    [ "$FIRMWARE" = bios ] || fail "Rust-DOS games mode requires BIOS firmware"
    [ "$FREEDOS" = 0 ] || fail "use the rust-dos backend for FreeDOS boot"
    [ "$ARCH" != x64 ] || fail "Rust-DOS does not emulate an x64 CPU"
    [ "$SOUND" = sb ] || [ "$SOUND" = none ] || fail "Rust-DOS supports sb or none"
    [ "$HEADLESS$KVM" = 00 ] || fail "Rust-DOS does not support --headless or --kvm"
    [ -z "$HOST_DIR$WAV$SHOT$SB_AUDIO" ] && [ "$TRACE" = 0 ] ||
        fail "--host, --wav, --screenshot, --trace and --sb-audio are unavailable with Rust-DOS"

    local binary="${RUST_DOS_BIN:-${RUST_DOS_PREFIX:-$HOME/.local}/bin/rust-dos}"
    [ -x "$binary" ] || fail "Rust-DOS binary missing: $binary (install it with bash tools/install_rust_dos.sh)"
    binary=$(realpath "$binary")
    local cpu=486 sbtype=sb16 startup='C:\DN\DN.COM'
    [ "$ARCH" != 686 ] || cpu=pentium
    [ "$SOUND" != none ] || sbtype=none

    {
        printf '[emulator]\nmemsize=64\ncpu=%s\nmachine=vga\ncycles=auto 20000\ncore=dynamic\n' "$cpu"
        printf '[sound]\nsbtype=%s\n' "$sbtype"
        printf '[autoexec]\nIMGMOUNT C "%s" -t hdd\nC:\n' "$GAMES_IMAGE"
        # Use Rust-DOS's shell for child launches. The C:\RETROOS shell uses
        # RetroOS-specific services and cannot replace COMMAND.COM here.
        printf 'SET COMSPEC=Z:\\COMMAND.COM\n'
        # Consume the environment/startup settings from the bundled INI.
        while IFS= read -r setting; do
            case "$setting" in
                PATH=*) printf 'PATH Z:\\;%s\n' "${setting#PATH=}" ;;
                DN=*|DNSWP=*|TEMP=*) printf 'SET %s\n' "$setting" ;;
                start=*) startup="${setting#start=}" ;;
            esac
        done < "$SCRIPT_DIR/etc/RETROOS.INI"
        if [ -n "$COMMAND" ]; then
            python3 "$SCRIPT_DIR/tools/rust_dos_startup.py" "$COMMAND"
        else
            printf '%s\n' "$startup"
        fi
    } > "$WORK/rust-dos.conf"

    echo "Rust-DOS C: is a disposable FAT16 copy of the packaged DOS files."
    cd "$WORK"
    run_vm "$binary" --config "$WORK/rust-dos.conf" --dir "$WORK" "${PASS[@]}"
}
