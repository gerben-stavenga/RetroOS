# Hosted-build smoke test

A minimal static 32-bit Linux ELF (`write` + `exit` via `int 0x80`) used to
verify the hosted (interpreter) kernel build runs a real ELF end-to-end through
the kernel's Linux personality.

Build and run:

    gcc -m32 -static -nostdlib -no-pie -fno-pic -O2 -e _start -o /tmp/hello.elf apps/hosted-test/hello.c
    cargo run -p kernel -- /tmp/hello.elf

Expected stdout: `Hello from an interpreted 32-bit Linux ELF!`
