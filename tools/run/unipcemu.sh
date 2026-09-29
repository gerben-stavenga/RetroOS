# UniPCemu uses SETTINGS.INI and images under its UNIPCEMU data directory.
# The emulator may rewrite settings on exit, so keep its whole directory in WORK.
launch() {
    local vm="$WORK/unipcemu" binary
    binary="${UNIPCEMU_BIN:-$(command -v UniPCemu || command -v unipcemu || true)}"
    [ -n "$binary" ] || fail "UniPCemu executable not found; set UNIPCEMU_BIN"
    mkdir -p "$vm/disks"
    if [ "$FREEDOS" = 1 ]; then
        ln -s "$DATA_IMAGE" "$vm/disks/boot.img"
    else
        ln -s "$BOOT_IMAGE" "$vm/disks/boot.img"
        ln -s "$DATA_IMAGE" "$vm/disks/data.img"
    fi
    local second_disk=data.img soundblaster=4
    [ "$FREEDOS" = 0 ] || second_disk=
    [ "$SOUND" = sb ] || soundblaster=0
    cat > "$vm/SETTINGS.INI" <<CFG
[general]
firstrun=0

[machine]
architecture=4
executionmode=0
cpu=5
clockingmode=1

[bios]
bootorder=14

[video]
videocard=0

[sound]
soundblaster=$soundblaster

[disks]
hdd0=boot.img
hdd1=$second_disk

[i430fxCMOS]
memory=134217728
cpu=5
videocard=0
soundblaster=$soundblaster
soundblasterirq=0
CFG
    export UNIPCEMU="$vm"
    run_vm "$binary" "${PASS[@]}"
}
