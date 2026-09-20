launch() {
    local engine= target=retroos-play package=play args=()
    [ "$KVM" = 0 ] || engine=-kvm
    if [ "$HEADLESS" = 1 ]; then package=kernel; target=retroos-host; fi
    "$BAZEL" build "//$package:$target$engine" --platforms=@platforms//host
    [ -z "$COMMAND" ] || args+=(--cmd "$COMMAND")
    [ -z "$WAV" ] || args+=(--wav "$WAV")
    if [ -n "$SHOT" ]; then
        [ "$HEADLESS" = 1 ] || fail "--screenshot requires hosted --headless"
        args+=(--screenshot "$SHOT")
    fi
    [ "$TRACE" = 0 ] || export RETRO_TRACE=1
    if [ -n "$HOST_DIR" ]; then
        args+=(--host "$HOST_DIR")
    else
        args+=(--boot-disk "$BOOT_IMAGE" "$DATA_IMAGE")
    fi
    run_vm "bazel-bin/$package/$target$engine" "${args[@]}" "${PASS[@]}"
}
