# UniPCemu uses SETTINGS.INI and images under its UNIPCEMU data directory.
# The emulator may rewrite settings on exit, so keep its whole directory in WORK.
launch() {
    local vm="$WORK/unipcemu" binary rom_dir usb_image video_card=0 et4000_extensions=0
    binary="${UNIPCEMU_BIN:-$(command -v UniPCemu || command -v unipcemu || true)}"
    [ -n "$binary" ] || fail "UniPCemu executable not found; set UNIPCEMU_BIN"
    rom_dir="${UNIPCEMU_ROM_DIR:-}"
    [ -n "$rom_dir" ] && [ -d "$rom_dir" ] || fail "UniPCemu Pentium needs a motherboard BIOS ROM; set UNIPCEMU_ROM_DIR to a UniPCemu ROM directory"
    if ! compgen -G "$rom_dir/BIOSROM*.BIN" > /dev/null; then
        fail "no BIOSROM*.BIN in UNIPCEMU_ROM_DIR: $rom_dir"
    fi
    usb_image="${UNIPCEMU_USB_IMAGE:-}"
    if [ -n "$usb_image" ]; then
        [ "$FREEDOS" = 0 ] || fail "UNIPCEMU_USB_IMAGE cannot be used with --freedos"
        [ -f "$usb_image" ] || fail "UniPCemu USB image does not exist: $usb_image"
    fi
    case "${UNIPCEMU_VIDEO:-vga}" in
        vga) ;;
        et4000w32) video_card=6; et4000_extensions=1 ;;
        *) fail "UNIPCEMU_VIDEO must be vga or et4000w32" ;;
    esac
    mkdir -p "$vm/disks" "$vm/ROM"
    cp -a "$rom_dir/." "$vm/ROM/"
    if [ "$FREEDOS" = 1 ]; then
        ln -s "$DATA_IMAGE" "$vm/disks/boot.img"
    else
        if [ -n "$usb_image" ]; then
            ln -s "$(realpath "$usb_image")" "$vm/disks/boot.img"
        else
            ln -s "$BOOT_IMAGE" "$vm/disks/boot.img"
        fi
        ln -s "$DATA_IMAGE" "$vm/disks/data.img"
    fi
    local second_disk=data.img soundblaster=4
    [ "$FREEDOS" = 0 ] || second_disk=
    [ "$SOUND" = sb ] || soundblaster=0
    local first_disk=boot.img cdrom= boot_order=14
    cat > "$vm/SETTINGS.INI" <<CFG
[general]
firstrun=0
backgroundpolicy=1

[machine]
architecture=4
executionmode=4
cpu=5
clockingmode=1

[bios]
bootorder=$boot_order

[video]
videocard=$video_card
ET4000_extensions=$et4000_extensions

[sound]
soundblaster=$soundblaster

[disks]
hdd0=$first_disk
hdd1=$second_disk
cdrom0=$cdrom

[i430fxCMOS]
memory=134217728
cpu=5
videocard=$video_card
soundblaster=$soundblaster
soundblasterirq=0
CFG
    export UNIPCEMU="$vm"
    run_vm "$binary" "${PASS[@]}"
}
