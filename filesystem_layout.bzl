"""Filesystem layout: paths are relative to their destination volume.

BOOT_FILES and LINUX_FILES are rebuilt with the kernel. DATA_FILES seed
one writable data disk once; editing that mapping never updates a live disk.
RETROOS/ and bin/ are kernel/runtime contracts, not arbitrary mount names.
"""

BOOT_SIZE_MB = 128
DOS_SIZE_MB = 3072
LINUX_SIZE_MB = 512

BOOT_FILES = {
    "etc/RETROOS.INI": "RETROOS/RETROOS.INI",
    "etc/BOOT.INI": "RETROOS/BOOT.INI",
    # boot-bundle/** is not listed here. BUILD.bazel globs it onto the boot
    # disk: DN/ is the default shell; system files live under RETROOS/.

    "//tools/command:command_com": "RETROOS/COMMAND.COM",
    # Kernel symbols for the stack tracer. kernel.elf itself is stripped, so
    # this is where panic backtraces get their names; without it they are
    # addresses. Ordinary content on C:, like everything else here.
    "//kernel:kernel_sym": "RETROOS/KERNEL.SYM",
    # Bridge into the Linux personality: a DN-launchable ELF that execs
    # /bin/busybox as `sh`.
    "//shell:shell_elf": "RETROOS/SHELL.ELF",
    # Personality DLL facades travel with the matched kernel. All supported
    # boot sources expose RETROOS/ through a writable session overlay.
    "//lib/windows/kernel32:kernel32_dll": "RETROOS/WINDOWS/SYSTEM32/KERNEL32.DLL",
    "//lib/windows/user32:user32_dll":     "RETROOS/WINDOWS/SYSTEM32/USER32.DLL",
    "//lib/windows/compat:advapi32_dll":   "RETROOS/WINDOWS/SYSTEM32/ADVAPI32.DLL",
    "//lib/windows/compat:comctl32_dll":   "RETROOS/WINDOWS/SYSTEM32/COMCTL32.DLL",
    "//lib/windows/compat:dwmapi_dll":     "RETROOS/WINDOWS/SYSTEM32/DWMAPI.DLL",
    "//lib/windows/compat:gdi32_dll":      "RETROOS/WINDOWS/SYSTEM32/GDI32.DLL",
    "//lib/windows/compat:shell32_dll":    "RETROOS/WINDOWS/SYSTEM32/SHELL32.DLL",
    "//lib/windows/compat:winmm_dll":      "RETROOS/WINDOWS/SYSTEM32/WINMM.DLL",
    "//lib/windows/compat:gdiplus_dll": "RETROOS/WINDOWS/SYSTEM32/GDIPLUS.DLL",
    "//lib/windows/compat:iphlpapi_dll": "RETROOS/WINDOWS/SYSTEM32/IPHLPAPI.DLL",
    "//lib/windows/compat:mpr_dll": "RETROOS/WINDOWS/SYSTEM32/MPR.DLL",
    "//lib/windows/compat:ntdll_dll": "RETROOS/WINDOWS/SYSTEM32/NTDLL.DLL",
    "//lib/windows/compat:ole32_dll": "RETROOS/WINDOWS/SYSTEM32/OLE32.DLL",
    "//lib/windows/compat:wininet_dll": "RETROOS/WINDOWS/SYSTEM32/WININET.DLL",
    "//lib/windows/compat:wsock32_dll": "RETROOS/WINDOWS/SYSTEM32/WSOCK32.DLL",
    "//lib/windows/compat:msvcrt_dll": "RETROOS/WINDOWS/SYSTEM32/MSVCRT.DLL",
    "//lib/windows/win16:kernel_dll":     "RETROOS/WINDOWS/SYSTEM/KERNEL.DLL",
    "//lib/windows/win16:user_dll":       "RETROOS/WINDOWS/SYSTEM/USER.DLL",
    "//lib/windows/win16:gdi_dll":        "RETROOS/WINDOWS/SYSTEM/GDI.DLL",
    "//lib/windows/win16:shell_dll":      "RETROOS/WINDOWS/SYSTEM/SHELL.DLL",
    "//lib/windows/win16:sound_dll":      "RETROOS/WINDOWS/SYSTEM/SOUND.DLL",
    "//lib/windows/win16:keyboard_dll":   "RETROOS/WINDOWS/SYSTEM/KEYBOARD.DLL",
    "//lib/os2/doscalls:doscalls_dll":     "RETROOS/OS2/DLL/DOSCALLS.DLL",
    "//lib/os2/kbdcalls:kbdcalls_dll":     "RETROOS/OS2/DLL/KBDCALLS.DLL",
    "//lib/os2/viocalls:viocalls_dll":     "RETROOS/OS2/DLL/VIOCALLS.DLL",
    "//lib/os2/moucalls:moucalls_dll": "RETROOS/OS2/DLL/MOUCALLS.DLL",
    "//lib/os2/msg:msg_dll": "RETROOS/OS2/DLL/MSG.DLL",
    "//lib/os2/pmwp:pmwp_dll": "RETROOS/OS2/DLL/PMWP.DLL",
    "//lib/os2/uconv:uconv_dll":         "RETROOS/OS2/DLL/UCONV.DLL",
    "//lib/os2/nls:nls_dll":             "RETROOS/OS2/DLL/NLS.DLL",
    "//lib/os2/pmwin:pmwin_dll":         "RETROOS/OS2/DLL/PMWIN.DLL",
    "//lib/os2/pmgpi:pmgpi_dll":         "RETROOS/OS2/DLL/PMGPI.DLL",
    "//lib/os2/pmshapi:pmshapi_dll":     "RETROOS/OS2/DLL/PMSHAPI.DLL",
    "//lib/os2/helpmgr:helpmgr_dll":     "RETROOS/OS2/DLL/HELPMGR.DLL",
}

DATA_FILES = {
    # In-OS tinkering source for COMMAND.COM (used to ride the boot TAR).
    "//tools/command:command.c": "SRC/COMMAND.C",
    # COMMAND.COM is not here: it lives at C:\RETROOS\COMMAND.COM (see
    # _BOOT_DIR_FILES), which is where COMSPEC points.
    "//test/dos/printmsg:printmsg_elf":   "TESTS/printmsg.elf",
    "//test/dos/stress:stress_elf":       "TESTS/stress.elf",
    "//test/dos/stress64:stress64_elf":   "TESTS/stress64.elf",
    "//test/dos/hello_com:hello_com":     "TESTS/HELLO.COM",
    "//test/dos/wr_com:wr_com":           "TESTS/WR.COM",

    "//test/dos/hostfs_commands:hostfs_commands_com": "TESTS/HFSOPS.COM",

    "//test/dos/hostfs_lifecycle:hostfs_probe_com": "TESTS/HFS_PROBE.COM",
    "//test/dos/hostfs_lifecycle:hostfs_recover_com": "TESTS/HFSRECV.COM",
    "//test/dos/gfx_com:gfx_com":         "TESTS/GFX.COM",
    "//test/dos/svgaprobe:svgaprobe_com": "TESTS/SVGAPROBE.COM",
    "//test/dos/lfnprobe:lfnprobe_com": "TESTS/LFNPROBE.COM",
    "//test/dos/int13_com:int13_com":     "TESTS/INT13T.COM",
    "//test/dos/xmsprobe:xmsprobe_com": "TESTS/XMSPROBE.COM",
    "//test/dos/vifiret:vifiret_com": "TESTS/VIFIRET.COM",
    "//test/dos/hello_com:TEST.BAT":      "TESTS/TEST.BAT",
    "//test/dos/trexec:trexec_com":       "TESTS/TREXEC.COM",
    "//test/dos/hello32_linux:hello32_linux": "TESTS/HI.ELF",
    "//test/dos/hello64_linux:hello64_linux": "TESTS/HI64.ELF",
    # DOS and OS/2 share C:. The OS/2 personality changes the executable/API
    # environment, not the filesystem namespace.
    "//test/os2/hello:hello_lx":         "OS2/APPS/HELLO.EXE",
    "//test/os2/pm_smoke:pm_smoke":      "OS2/APPS/PMSMOKE.EXE",
    "//test/os2/watcom_io:watcom_io":    "OS2/APPS/WATCIO.EXE",
    "//test/windows/hello:hello":            "WINDOWS/APPS/HELLO.EXE",
    "//test/windows/watcom_io:watcom_io":    "WINDOWS/APPS/WATCIO.EXE",
    # DPMI smoke-test fixture (compiled by BCC in test/dpmi_smoke.sh).
    "test/dpmi/hello.c":                    "TESTS/DPMIHI.C",
    # Japheth's HX DPMI conformance probe (freeware; see test/dpmi/HX-CREDITS.txt).
    # `DPMI.EXE -r` dumps the DPMI host state; test/dpmi_hx.sh asserts the dump.
    "test/dpmi/DPMI.EXE":                   "TESTS/DPMI.EXE",
    # SB DMA test: MODPLAY.EXE (stub + Rust payload) supersedes the C
    # `sbtest` -- modplay drives the same SB+8237 in both poll and IRQ
    # modes. RLOADER.BIN is the in-OS PM loader the stub fopens from cwd.
    # No build cycle: `image_min` (used to build the stub) uses
    # _MIN_EXTRA_FILES below, not these.
    "//test/dos/modplay:modplay_exe":     "TESTS/MODPLAY.EXE",
    # SB single-cycle completion-protocol probes (busy flicker, status TC,
    # count underflow) — hosted_games.sh asserts SBTEST prints TC-OK.
    "//test/dos/sbproto:sbtest_com":      "TESTS/SBTEST.COM",
    "//test/dos/sbproto:sbdisc_com":      "TESTS/SBDISC.COM",
    "//test/dos/sbproto:sbirq_com":       "TESTS/SBIRQ.COM",
    "//test/dos/sbproto:sbdoor_com":      "TESTS/SBDOOR.COM",
    # PC speaker probe — hosted_games.sh asserts SPKTEST prints OUT-OK (the
    # PIT ch2 OUT line at port 61h bit 5); its tone sequence is the fixture
    # the WAV-capture check measures.
    "//test/dos/spkproto:spktest_com":    "TESTS/SPKTEST.COM",
    # GUS (GF1) emulation probe — hosted_games.sh asserts its G*-OK markers.
    "//test/dos/gusproto:gustest_exe":    "TESTS/GUSTEST.EXE",
    "//tools/dosrt:dosrt_exe":               "TESTS/DOSRT.EXE",
    "//tools/dosrt:rloader_bin":             "TESTS/RLOADER.BIN",

}

LINUX_FILES = {
    # Static i686 busybox — single-binary Unix userland (sh + coreutils).
    # Standalone-shell mode dispatches applets via basename(argv[0]); the
    # binary's compiled-in re-exec path is /bin/busybox, hence the location.
    "//:boot-bundle/bin/busybox":               "bin/busybox",
}
