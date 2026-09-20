# QEMU transport and devices. Disk construction belongs to run.sh.
launch() {
    local qemu=qemu-system-i386
    local args=() cpu=() display="${QEMU_DISPLAY:-sdl}"
    [ "$ARCH" != x64 ] || qemu=qemu-system-x86_64
    [ "$ARCH" != 386 ] || cpu=(-cpu 486)
    [ "$HEADLESS" = 0 ] || display=none
    if [ "$FIRMWARE" = uefi ]; then
        qemu=qemu-system-x86_64
        cpu=(-cpu max)
        cp "${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}" "$WORK/vars.fd"
        args=(-M q35 -m 512 -nodefaults -device bochs-display -device qemu-xhci
              -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
              -drive "if=pflash,format=raw,file=$WORK/vars.fd"
              -drive "file=$DATA_IMAGE,if=none,id=data,format=raw"
              -device nvme,drive=data,serial=retro1
              -drive "file=$BOOT_IMAGE,if=none,id=boot,format=raw"
              # The kernel supports one NVMe controller; boot files use ATA.
              -device piix3-ide,id=boot-ide
              -device ide-hd,drive=boot,bus=boot-ide.0,unit=0,bootindex=1)
    elif [ "$FREEDOS" = 1 ]; then
        args=(-m 64 -drive "file=$DATA_IMAGE,format=raw")
    else
        args=(-m 128 -drive "file=$BOOT_IMAGE,format=raw" -drive "file=$DATA_IMAGE,format=raw")
    fi
    qemu="${RETROOS_QEMU_BIN:-$qemu}"
    [ "$KVM" = 0 ] || cpu=(-accel kvm -cpu host)
    if [ "$FIRMWARE" = bios ]; then
        local rom="${VGABIOS_ROM:-$SCRIPT_DIR/third_party/vgabios/vgabios-stdvga.bin}"
        [ ! -f "$rom" ] || args+=(-device "VGA,romfile=$rom")
    fi
    if [ "$SOUND" != none ]; then
        args+=(-audiodev "${AUDIO_BACKEND:-pa},id=snd0" -machine pcspk-audiodev=snd0)
        case "$SOUND" in
            hda) args+=(-device intel-hda -device hda-duplex,audiodev=snd0) ;;
            ac97) args+=(-device AC97,audiodev=snd0) ;;
            sb)
                local irq=5
                [ "$FREEDOS" = 0 ] || irq=7
                args+=(-device adlib,audiodev=snd0
                       -device "sb16,audiodev=snd0,iobase=0x220,irq=$irq,dma=1,dma16=5") ;;
        esac
    fi
    local directive="$COMMAND" cwd=
    if [ -n "$HOST_DIR" ]; then
        args+=(-serial chardev:hostfs -chardev "socket,id=hostfs,path=$WORK/hostfs.sock,server=on,wait=on")
        "$SCRIPT_DIR/hostfs.py" "$HOST_DIR" "$WORK/hostfs.sock" & HOSTFS_PID=$!
        sleep 0.1
        kill -0 "$HOSTFS_PID" 2>/dev/null || fail "HostFS server exited during startup"
        directive="hostfs=com1${COMMAND:+;$COMMAND}"
        cwd=H:
    else
        # Avoid exposing a disconnected COM1 as a phantom HostFS peer.
        args+=(-serial none)
        [ -z "$COMMAND" ] || cwd=$(dirname "${COMMAND%% *}")
    fi
    if [ -n "$directive" ]; then
        printf '%s' "$directive" > "$WORK/cmdline"
        args+=(-fw_cfg "name=opt/cmdline,file=$WORK/cmdline")
    fi
    if [ -n "$cwd" ] && [ "$cwd" != . ]; then
        args+=(-fw_cfg "name=opt/cwd,string=$cwd")
    fi
    [ -z "$SB_AUDIO" ] || args+=(-fw_cfg "name=opt/audio,string=$SB_AUDIO")
    run_vm "$qemu" "${cpu[@]}" "${args[@]}" -rtc base=localtime \
        -debugcon stdio -display "$display" -no-reboot "${PASS[@]}"
}
