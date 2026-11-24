launch() {
    local engine= target=retroos-play package=play args=()
    [ "$KVM" = 0 ] || engine=-kvm
    if [ "$HEADLESS" = 1 ]; then package=kernel; target=retroos-host; fi
    build_artifacts "//$package:$target$engine" //:hosted_runtime_tar --platforms=@platforms//host 9>&-
    tar -xf bazel-bin/hosted_runtime_tar.tar -C "$WORK"
    if [ "$HEADLESS" = 0 ] && [ "$SOUND" = none ]; then args+=(--no-audio); fi
    [ -z "$COMMAND" ] || args+=(--cmd "$COMMAND")
    [ -z "$WAV" ] || args+=(--wav "$WAV")
    if [ -n "$SHOT" ]; then
        [ "$HEADLESS" = 1 ] || fail "--screenshot requires hosted --headless"
        args+=(--screenshot "$SHOT")
    fi
    [ "$TRACE" = 0 ] || export RETRO_TRACE=1
    args+=("${PASS[@]}" --host-c-root "$HOST_C_DIRECTORY"
           --boot-runtime "$WORK/RETROOS" /)
    run_vm "bazel-bin/$package/$target$engine" "${args[@]}"
}
