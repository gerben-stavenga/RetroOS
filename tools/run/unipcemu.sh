# UniPCemu uses SETTINGS.INI and images under its UNIPCEMU data directory.
# The emulator may rewrite settings on exit, so keep its whole directory in WORK.
launch() {
    local vm="$WORK/unipcemu" binary rom_dir usb_image iso_image
    local machine_arch cmos_section cpu video_card=0 et4000_extensions=0
    binary="${UNIPCEMU_BIN:-$(command -v UniPCemu || command -v unipcemu || true)}"
    [ -n "$binary" ] || fail "UniPCemu executable not found; set UNIPCEMU_BIN"
    rom_dir="${UNIPCEMU_ROM_DIR:-}"
    [ -n "$rom_dir" ] && [ -d "$rom_dir" ] || fail "UniPCemu needs a motherboard BIOS ROM; set UNIPCEMU_ROM_DIR to its ROM directory"
    case "${UNIPCEMU_ARCH:-i430fx}" in
        i430fx) machine_arch=4; cmos_section=i430fxCMOS; cpu=5 ;;
        i440fx) machine_arch=5; cmos_section=i440fxCMOS; cpu=7 ;;
        *) fail "UNIPCEMU_ARCH must be i430fx or i440fx" ;;
    esac
    [ -f "$rom_dir/BIOSROM.${UNIPCEMU_ARCH:-i430fx}.BIN" ] ||
        fail "missing BIOSROM.${UNIPCEMU_ARCH:-i430fx}.BIN in UNIPCEMU_ROM_DIR: $rom_dir"
    usb_image="${UNIPCEMU_USB_IMAGE:-}"
    iso_image="${UNIPCEMU_ISO_IMAGE:-}"
    [ -z "$usb_image" ] || [ -z "$iso_image" ] || fail "choose either UNIPCEMU_USB_IMAGE or UNIPCEMU_ISO_IMAGE"
    if [ -n "$usb_image" ]; then
        [ "$FREEDOS" = 0 ] || fail "UNIPCEMU_USB_IMAGE cannot be used with --freedos"
        [ -f "$usb_image" ] || fail "UniPCemu USB image does not exist: $usb_image"
    fi
    if [ -n "$iso_image" ]; then
        [ "$FREEDOS" = 0 ] || fail "UNIPCEMU_ISO_IMAGE cannot be used with --freedos"
        [ -f "$iso_image" ] || fail "UniPCemu ISO image does not exist: $iso_image"
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
    elif [ -n "$iso_image" ]; then
        ln -s "$(realpath "$iso_image")" "$vm/disks/boot.iso"
        ln -s "$DATA_IMAGE" "$vm/disks/data.img"
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
    if [ -n "$iso_image" ]; then
        first_disk=data.img
        second_disk=
        cdrom=boot.iso
        boot_order=13
    fi
    cat > "$vm/SETTINGS.INI" <<CFG
[general]
firstrun=0
backgroundpolicy=1

[machine]
architecture=$machine_arch
executionmode=4

[bios]
bootorder=$boot_order

[$cmos_section]
memory=134217728
cpu=$cpu
clockingmode=1
videocard=$video_card
ET4000_extensions=$et4000_extensions
soundblaster=$soundblaster
soundblasterirq=0
hdd0=$first_disk
hdd1=$second_disk
cdrom0=$cdrom
CFG
    export UNIPCEMU="$vm"
    run_vm "$binary" "${PASS[@]}"
}
