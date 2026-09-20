launch() {
    local flatpak_id= source_dir="${RETROOS_86BOX_SOURCE:-$SCRIPT_DIR/../86Box}" binary="${BOX86:-}"
    if command -v flatpak >/dev/null; then
        flatpak_id=$(flatpak list --app --columns=application | awk 'tolower($0) ~ /86box/ {print; exit}')
    fi
    local vm="${VM_DIR:-${flatpak_id:+$HOME/.var/app/$flatpak_id/data/86Box/RetroOS}}"
    vm="${vm:-$HOME/.local/share/86Box/RetroOS}"
    mkdir -p "$vm"
    vm=$(realpath "$vm")
    [ -f "$vm/86box.cfg" ] || cp "$SCRIPT_DIR/tools/run/86box.cfg" "$vm/86box.cfg"
    python3 "$SCRIPT_DIR/tools/configure_shared_86box.py" "$vm/86box.cfg" "$BOOT_IMAGE" "$DATA_IMAGE" "$FREEDOS" "$SOUND"
    export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-xcb}"
    local grants=("--filesystem=$vm" "--filesystem=$WORK" "--filesystem=$(dirname "$DATA_IMAGE")")
    if [ -n "$binary" ]; then
        run_vm "$binary" --vmpath "$vm" "${PASS[@]}"
    elif [ -x "$source_dir/build/regular/src/86Box" ]; then
        source_dir=$(realpath "$source_dir")
        binary="$source_dir/build/regular/src/86Box"
        if [ -n "$flatpak_id" ]; then
            run_vm flatpak run --devel --env=QT_QPA_PLATFORM="$QT_QPA_PLATFORM" "${grants[@]}" \
                "--filesystem=$source_dir" "--command=$binary" "$flatpak_id" --vmpath "$vm" "${PASS[@]}"
        else
            run_vm "$binary" --vmpath "$vm" "${PASS[@]}"
        fi
    elif [ -x "$HOME/bin/86Box.AppImage" ]; then
        run_vm "$HOME/bin/86Box.AppImage" --vmpath "$vm" "${PASS[@]}"
    elif [ -n "$flatpak_id" ]; then
        run_vm flatpak run --env=QT_QPA_PLATFORM="$QT_QPA_PLATFORM" "${grants[@]}" "$flatpak_id" --vmpath "$vm" "${PASS[@]}"
    else
        run_vm 86box --vmpath "$vm" "${PASS[@]}"
    fi
}
