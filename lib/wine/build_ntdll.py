#!/usr/bin/env python3
"""Build Wine's PE NTDLL with ordinary imports from RETROOS.DLL.

The Wine runtime sources are retained. Only the i386 syscall veneers and the
eight Unix host-call connections are adapted. No Unix implementation is linked.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

HOST_CALLS = {
    "unix_load_so_dll": "RetroLoadBuiltin",
    "unix_unwind_builtin_dll": "RetroUnwindBuiltin",
    "unix_wine_dbg_write": "RetroDebugWrite",
    "unix_wine_server_call": "RetroServerCall",
    "unix_wine_server_fd_to_handle": "RetroFileToHandle",
    "unix_wine_server_handle_to_fd": "RetroHandleToFile",
    "unix_wine_spawnvp": "RetroSpawn",
    "unix_system_time_precise": "RetroSystemTimePrecise",
}


def prepare(source, work):
    header = (source / "dlls/ntdll/ntsyscalls.h").read_text()
    section = header.split("#define ALL_SYSCALLS32", 1)[1].split("#define ALL_SYSCALLS ", 1)[0]
    calls = {name: int(size) for name, size in re.findall(
        r"SYSCALL_ENTRY(?:_\w+)?\(\s*0x[0-9a-f]+,\s*(\w+),\s*(\d+)\s*\)", section)}
    if len(calls) != 264:
        raise RuntimeError(f"Unexpected Wine 11 i386 syscall contract: {len(calls)} entries")

    signal = source / "dlls/ntdll/signal_i386.c"
    text = signal.read_text()
    start = text.index("#undef SYSCALL_ENTRY_NtQueryInformationProcess")
    end = text.index("#undef SYSCALL_ENTRY", text.index("ALL_SYSCALLS\n", start)) + len("#undef SYSCALL_ENTRY")
    # Stdcall callers keep their normal stack and register convention. No
    # service number, dispatcher, interrupt, or syscall instruction is needed.
    bridge = r'''
#undef SYSCALL_ENTRY_NtQueryInformationProcess
#define SYSCALL_ENTRY_NtQueryInformationProcess(id,name,args) SYSCALL_ENTRY(id,name,args)
#define SYSCALL_ENTRY(id,name,args) \
    __ASM_STDCALL_FUNC(name, args, "jmp *\"__imp__Retro" #name "@" #args "\"")
ALL_SYSCALLS
#undef SYSCALL_ENTRY
'''
    signal.write_text(text[:start] + bridge + text[end:])

    unix = source / "dlls/ntdll/unixlib.h"
    text = unix.read_text()
    declarations = "\n#undef WINE_UNIX_CALL\n#define WINE_UNIX_CALL(code,args) retroos_##code(args)\n"
    for token, name in HOST_CALLS.items():
        declarations += f"__declspec(dllimport) int __stdcall {name}(void *);\n#define retroos_{token} {name}\n"
    text = text.replace("extern unixlib_handle_t __wine_unixlib_handle;", declarations + "\nextern unixlib_handle_t __wine_unixlib_handle;")
    unix.write_text(text)

    contract = {**{"Retro" + name: size for name, size in calls.items()}, **{name: 4 for name in HOST_CALLS.values()}}
    definition = work / "retroos.def"
    definition.write_text("LIBRARY RETROOS.DLL\nEXPORTS\n" + "".join(f"{name}@{size}\n" for name, size in contract.items()))
    subprocess.run(["llvm-dlltool", "-m", "i386", "-k", "-d", str(definition),
                    "-l", str(work / "retroos.lib")], check=True)
    return contract


def run(command, cwd, env, log):
    result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        log.flush()
        raise RuntimeError(f"Command failed: {' '.join(map(str, command))}\n" + Path(log.name).read_text()[-16000:])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--flex", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--abi", type=Path, required=True)
    args = parser.parse_args()
    output, abi = args.output.resolve(), args.abi.resolve()
    env = dict(os.environ)
    env["PATH"] = str(args.flex.resolve().parent) + ":/usr/bin:/bin"
    for tool in ("clang", "ld.lld", "llvm-dlltool", "gcc", "make", "bison", "flex"):
        if not shutil.which(tool, path=env["PATH"]):
            raise RuntimeError(f"Building Wine NTDLL requires {tool}")
    with tempfile.TemporaryDirectory(prefix="retroos-wine-build-") as directory:
        work = Path(directory)
        with tarfile.open(args.source) as archive:
            archive.extractall(work, filter="data")
        source = work / "wine-11.0"
        contract = prepare(source, work)
        build = work / "build"
        build.mkdir()
        with (work / "build.log").open("w") as log:
            run([str(source / "configure"), "--enable-win64", "--enable-archs=i386",
                 "--without-x", "--without-wayland", "--without-freetype", "--without-fontconfig",
                 "--without-vulkan", "--without-opengl", "--without-alsa", "--without-pulse",
                 "--without-dbus", "--without-gnutls", "--without-gstreamer", "--disable-tests",
                 "CFLAGS=-O2", "i386_CFLAGS=-O2"], build, env, log)
            with (build / "Makefile").open("a") as makefile:
                makefile.write(f"\ni386_LDFLAGS += {work / 'retroos.lib'}\n")
            run(["make", "-j8", "dlls/ntdll/i386-windows/ntdll.dll"], build, env, log)
        shutil.copyfile(build / "dlls/ntdll/i386-windows/ntdll.dll", output)
        abi.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
