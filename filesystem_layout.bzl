"""Filesystem layout: paths are relative to their destination volume.

BOOT_FILES is rebuilt with the kernel. DATA_FILES and LINUX_FILES seed
one writable data disk once; editing these mappings never updates a live disk.
RETROOS/ and bin/ are kernel/runtime contracts, not arbitrary mount names.
"""

BOOT_SIZE_MB = 128
DOS_SIZE_MB = 3072
LINUX_SIZE_MB = 512

BOOT_FILES = {
    # DN program/resources stay versioned with the boot image.
    "apps-boot/dn/DN.COM": "RETROOS/DN/DN.COM",
    "apps-boot/dn/DN.PRG": "RETROOS/DN/DN.PRG",
    "apps-boot/dn/DN.OVR": "RETROOS/DN/DN.OVR",
    "apps-boot/dn/DN.DLG": "RETROOS/DN/DN.DLG",
    "apps-boot/dn/DN.LNG": "RETROOS/DN/DN.LNG",
    "apps-boot/dn/DN.HLP": "RETROOS/DN/DN.HLP",

    "//tools/command:command_com": "RETROOS/COMMAND.COM",
    # Kernel symbols for the stack tracer. kernel.elf itself is stripped, so
    # this is where panic backtraces get their names; without it they are
    # addresses. Ordinary content on C:, like everything else here.
    "//kernel:kernel_sym": "RETROOS/KERNEL.SYM",
    # Bridge into the Linux personality: a DN-launchable ELF that execs
    # /bin/busybox as `sh`.
    "//shell:shell_elf": "RETROOS/SHELL.ELF",
}

DATA_FILES = {
    # DN= selects this writable directory; history/desktop are created at runtime.
    "apps-boot/dn/DN.EDT": "CONFIG/DN/DN.EDT",
    "apps-boot/dn/DN.EXT": "CONFIG/DN/DN.EXT",
    "apps-boot/dn/DN.HGL": "CONFIG/DN/DN.HGL",
    "apps-boot/dn/DN.MNU": "CONFIG/DN/DN.MNU",
    "apps-boot/dn/DN.VWR": "CONFIG/DN/DN.VWR",
    "apps-boot/dn/DN.XRN": "CONFIG/DN/DN.XRN",

    # User-editable launch settings survive boot rebuilds.
    "//tools/command:LOADFIX.CFG": "CONFIG/LOADFIX.CFG",
    "etc/CONFIG.SYS": "CONFIG.SYS",
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
    "//apps/os2/doscalls:doscalls_dll": "OS2/DLL/DOSCALLS.DLL",
    "//apps/os2/kbdcalls:kbdcalls_dll": "OS2/DLL/KBDCALLS.DLL",
    "//apps/os2/viocalls:viocalls_dll":   "OS2/DLL/VIOCALLS.DLL",
    "//apps/os2/nls:nls_dll":           "OS2/DLL/NLS.DLL",
    "//apps/os2/pmwin:pmwin_dll":       "OS2/DLL/PMWIN.DLL",
    "//apps/os2/pmgpi:pmgpi_dll":       "OS2/DLL/PMGPI.DLL",
    "//apps/os2/pmshapi:pmshapi_dll":   "OS2/DLL/PMSHAPI.DLL",
    "//apps/os2/helpmgr:helpmgr_dll":   "OS2/DLL/HELPMGR.DLL",
    "//test/os2/hello:hello_lx":         "OS2/APPS/HELLO.EXE",
    "//test/os2/pm_smoke:pm_smoke":      "OS2/APPS/PMSMOKE.EXE",
    "//test/os2/watcom_io:watcom_io":    "OS2/APPS/WATCIO.EXE",
    "//apps/os2/sweeper:SWEEPER.EXE":    "OS2/APPS/SWEEPER/SWEEPER.EXE",
    "//apps/os2/sweeper:SWEEPER.HLP":    "OS2/APPS/SWEEPER/SWEEPER.HLP",
    "//apps/os2/sweeper:README.DOC":     "OS2/APPS/SWEEPER/README.DOC",
    "//apps/os2/sweeper:SWEEPER.DOC":    "OS2/APPS/SWEEPER/SWEEPER.DOC",
    "//apps/windows/kernel32:kernel32_dll": "WINDOWS/SYSTEM32/KERNEL32.DLL",
    "//apps/windows/user32:user32_dll":     "WINDOWS/SYSTEM32/USER32.DLL",
    "//apps/windows/compat:advapi32_dll":   "WINDOWS/SYSTEM32/ADVAPI32.DLL",
    "//apps/windows/compat:comctl32_dll":   "WINDOWS/SYSTEM32/COMCTL32.DLL",
    "//apps/windows/compat:dwmapi_dll":     "WINDOWS/SYSTEM32/DWMAPI.DLL",
    "//apps/windows/compat:gdi32_dll":      "WINDOWS/SYSTEM32/GDI32.DLL",
    "//apps/windows/compat:shell32_dll":    "WINDOWS/SYSTEM32/SHELL32.DLL",
    "//apps/windows/compat:winmm_dll":      "WINDOWS/SYSTEM32/WINMM.DLL",
    "//apps/windows/win16:kernel_dll":       "WINDOWS/SYSTEM/KERNEL.DLL",
    "//apps/windows/win16:user_dll":         "WINDOWS/SYSTEM/USER.DLL",
    "//apps/windows/win16:gdi_dll":          "WINDOWS/SYSTEM/GDI.DLL",
    "//apps/windows/win16:shell_dll":        "WINDOWS/SYSTEM/SHELL.DLL",
    "//apps/windows/win16:sound_dll":        "WINDOWS/SYSTEM/SOUND.DLL",
    "//apps/windows/win16:keyboard_dll":     "WINDOWS/SYSTEM/KEYBOARD.DLL",
    "//apps/windows/minesweeper:MINESWPR.EXE": "WINDOWS/APPS/MINESWPR.EXE",
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
    "//:apps/busybox/busybox":               "bin/busybox",
}
