first_file() { local file; for file in "$@"; do [ ! -f "$file" ] || { echo "$file"; return; }; done; fail "file not found: $*"; }
bochs_disk() {
    printf 'type=disk, path="%s", mode=flat, cylinders=%s, heads=16, spt=63, biosdetect=auto, translation=lba' \
        "$1" "$(( $(stat -c%s "$1") / 512 / 1008 ))"
}
launch() {
    local vm="${VM_DIR:-$HOME/.local/share/Bochs/RetroOS}" bios vga cpu="${BOCHS_CPU_MODEL:-pentium}"
    local binary="${BOCHS_BIN:-$(command -v bochs || true)}" args=()
    [ -n "$binary" ] || binary="$HOME/bin/bochs"
    mkdir -p "$vm"
    if [ "$FIRMWARE" = uefi ]; then
        bios="${OVMF_PATH:-$vm/OVMF_2M.fd}"
        [ -f "$bios" ] || fail "Bochs UEFI requires a 2 MiB OVMF image; set OVMF_PATH"
        bios="file=\"$bios\", address=0xffe00000"
        cpu="${BOCHS_CPU_MODEL:-core2_penryn_t9600}"
    else
        bios=$(first_file "${BOCHS_BIOS:-}" "${BOCHS_SHARE:-${BXSHARE:-/usr/share/bochs}}/BIOS-bochs-legacy" /usr/share/bochs/BIOS-bochs-latest)
        bios="file=\"$bios\""
    fi
    vga=$(first_file "${BOCHS_VGA_ROM:-}" "${BOCHS_SHARE:-${BXSHARE:-/usr/share/bochs}}/VGABIOS-lgpl-latest.bin" /usr/share/vgabios/vgabios.bin /usr/share/seabios/vgabios-stdvga.bin)
    cat > "$vm/bochsrc.txt" <<CFG
megs: 128
cpu: model=$cpu, count=1, ips=${BOCHS_IPS:-50000000}, reset_on_triple_fault=1
port_e9_hack: enabled=1
romimage: $bios
vgaromimage: file="$vga"
vga: extension=vbe, update_freq=${BOCHS_VGA_UPDATE_FREQ:-60}
clock: sync=${BOCHS_SYNC:-realtime}, time0=local
mouse: enabled=1, type=ps2
log: "$vm/bochs.log"
com1: enabled=1, mode=file, dev="$vm/serial.out"
boot: disk
CFG
    if [ "$FREEDOS" = 1 ]; then
        echo "ata0-master: $(bochs_disk "$DATA_IMAGE")" >> "$vm/bochsrc.txt"
    else
        printf 'ata0-master: %s\nata0-slave: %s\n' "$(bochs_disk "$BOOT_IMAGE")" "$(bochs_disk "$DATA_IMAGE")" >> "$vm/bochsrc.txt"
    fi
    [ "$SOUND" = none ] || echo "sb16: wavemode=1, midimode=0, dmatimer=750000, log=\"$vm/sb16.log\", loglevel=2" >> "$vm/bochsrc.txt"
    [ -z "${BOCHS_DISPLAY:-}" ] || echo "display_library: $BOCHS_DISPLAY" >> "$vm/bochsrc.txt"
    args=(-q -f "$vm/bochsrc.txt" -unlock)
    if [ "${BOCHS_DEBUG:-0}" != 1 ]; then printf 'c\n' > "$vm/bochs.rc"; args+=(-rc "$vm/bochs.rc"); fi
    run_vm "$binary" "${args[@]}" "${PASS[@]}"
}
