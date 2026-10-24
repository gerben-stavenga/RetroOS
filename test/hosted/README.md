# Hosted-build smoke test

A minimal static 32-bit Linux ELF (`write` + `exit` via `int 0x80`) used to
verify the hosted (interpreter) kernel build runs a real ELF end-to-end through
the kernel's Linux personality.

Build and run:

    mkdir -p /tmp/retroos-hello
    gcc -m32 -static -nostdlib -no-pie -fno-pic -O2 -e _start -o /tmp/retroos-hello/hello.elf test/hosted/hello.c
    bazelisk build //kernel:retroos-host --platforms=@platforms//host
    python3 test/disk_fixture.py --root /tmp/retroos-hello -- bazel-bin/kernel/retroos-host --cmd /hello.elf --cwd /

Expected stdout: `Hello from an interpreted 32-bit Linux ELF!`
