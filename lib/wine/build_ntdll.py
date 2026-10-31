#!/usr/bin/env python3
"""Build Wine NTDLL, Win16 kernel and userspace graphics for RetroOS.

The Wine runtime sources are retained. NTDLL host calls become named imports.
The graphics patch builds the drawing/window implementation as PE, using RTL
synchronization and RetroOS backend imports instead of Unix services.
"""
from build_freetype import prepare_fonts, build_fonts
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

    # Reuse Wine's own PEB initialization for the NE startup path as well as
    # loader_init; without FastPebLock environment access reads a bogus lock.
    loader = source / "dlls/ntdll/loader.c"
    text = loader.read_text()
    first = text.index("        peb->LdrData            = &ldr;")
    last = text.index("        init_user_process_params();", first)
    body = text[first:last]
    text = text[:first] + "        RetroWineInitializePeb();\n\n" + text[last:]
    at = text.index("void loader_init( CONTEXT *context, void **entry )")
    initializer = ("void WINAPI RetroWineInitializePeb(void)\n{\n"
        "    PEB *peb = NtCurrentTeb()->Peb;\n    unsigned int i;\n"
        "    TEB *teb = NtCurrentTeb();\n"
        "    if (peb->FastPebLock == &peb_lock) return;\n"
        "    teb->ActivationContextStackPointer = &teb->ActivationContextStack;\n"
        "    InitializeListHead(&teb->ActivationContextStack.FrameListCache);\n"
        "    teb->RealClientId = teb->ClientId;\n" + body + "}\n\n")
    adapters = r"""
void WINAPI RetroWineThreadStart(PRTL_THREAD_START_ROUTINE entry, void *arg)
{
    NTSTATUS status;
    RtlEnterCriticalSection(&loader_section);
    NtCurrentTeb()->FlsSlots=fls_alloc_data();
    status=alloc_thread_tls();
    if (!status) thread_attach();
    RtlLeaveCriticalSection(&loader_section);
    if (status) NtTerminateThread(GetCurrentThread(),status);
    RtlExitUserThread(((LPTHREAD_START_ROUTINE)entry)(arg));
}

NTSTATUS WINAPI RetroWineDispatchException(EXCEPTION_RECORD *record,CONTEXT *context)
{
    return dispatch_exception(record,context);
}

NTSTATUS WINAPI RetroWineDispatchCallback(void *args, ULONG len, ULONG id)
{
    return dispatch_user_callback(args, len, id);
}

NTSTATUS WINAPI RetroWineRegisterModule(HMODULE module, const WCHAR *path)
{
    UNICODE_STRING name;
    WINE_MODREF *wm;
    RtlInitUnicodeString(&name, path);
    RtlEnterCriticalSection(&loader_section);
    wm = get_modref(module);
    if (!wm) wm = alloc_module(module, &name, TRUE);
    if (wm) {
        wm->ldr.Flags &= ~LDR_DONT_RESOLVE_REFS;
        wm->ldr.LoadCount = -1;
        if (!wcsicmp(wm->ldr.BaseDllName.Buffer, L"ntdll.dll")) node_ntdll = wm->ldr.DdagNode;
        if (!wcsicmp(wm->ldr.BaseDllName.Buffer, L"kernel32.dll")) node_kernel32 = wm->ldr.DdagNode;
    }
    RtlLeaveCriticalSection(&loader_section);
    return wm ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}
BOOL WINAPI RetroWineAttachModule(HMODULE module, DWORD reason, void *reserved)
{
    WINE_MODREF *wm;
    NTSTATUS status;
    RtlEnterCriticalSection(&loader_section);
    wm = get_modref(module);
    status = wm ? process_attach(wm->ldr.DdagNode, reserved) : STATUS_DLL_NOT_FOUND;
    RtlLeaveCriticalSection(&loader_section);
    return !status;
}
void WINAPI RetroWineInitializeLocale(void)
{
    default_load_path = NtCurrentTeb()->Peb->ProcessParameters->DllPath.Buffer;
    version_init();
    locale_init();
}
"""
    # NE tasks have no PE executable modref. DLL detach still runs normally;
    # executable TLS callbacks only apply when a PE main module is registered.
    text = text[:at] + initializer + adapters + text[at:]
    text = text.replace("if (wm->ldr.TlsIndex == -1) call_tls_callbacks( wm->ldr.DllBase, DLL_THREAD_DETACH );",
                        "if (wm && wm->ldr.TlsIndex == -1) call_tls_callbacks( wm->ldr.DllBase, DLL_THREAD_DETACH );")
    loader.write_text(text)
    with (source / "dlls/ntdll/ntdll.spec").open("a") as stream:
        stream.write("\n@ stdcall RetroWineDispatchException(ptr ptr)\n@ stdcall RetroWineThreadStart(ptr ptr)\n@ stdcall RetroWineDispatchCallback(ptr long long)\n@ stdcall RetroWineInitializePeb()\n@ stdcall RetroWineInitializeLocale()\n@ stdcall RetroWineRegisterModule(long wstr)\n@ stdcall RetroWineAttachModule(long long ptr)\n")

    contract = {**{"Retro" + name: size for name, size in calls.items()}, **{name: 4 for name in HOST_CALLS.values()}, "RetroUserCallback": 20, "RetroServerSendFile": 4}
    definition = work / "retroos.def"
    definition.write_text("LIBRARY RETROOS.DLL\nEXPORTS\n" + "".join(f"{name}@{size}\n" for name, size in contract.items()) + "RetroDosMemory@16\nRetroGraphics@12\n")
    subprocess.run(["llvm-dlltool", "-m", "i386", "-k", "-d", str(definition),
                    "-l", str(work / "retroos.lib")], check=True)
    return contract


def run(command, cwd, env, log):
    result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        log.flush()
        details = Path(log.name).read_text()
        errors = "\n".join(line for line in details.splitlines() if "error:" in line or "undefined" in line or "Error " in line)
        raise RuntimeError(f"Command failed: {' '.join(map(str, command))}\n" + errors + "\n" + details[-8000:])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--freetype", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--flex", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--abi", type=Path, required=True)
    parser.add_argument("--kernel16", type=Path, required=True)
    parser.add_argument("--graphics", type=Path, required=True)
    parser.add_argument("--graphics-patch", type=Path, required=True)
    parser.add_argument("--graphics-driver", type=Path, required=True)
    args = parser.parse_args()
    output, abi = args.output.resolve(), args.abi.resolve()
    kernel16 = args.kernel16.resolve()
    env = dict(os.environ)
    env["PATH"] = str(args.flex.resolve().parent) + ":/usr/bin:/bin"
    for tool in ("clang-19", "ld.lld", "llvm-dlltool", "llvm-ar", "gcc", "make", "bison", "flex"):
        if not shutil.which(tool, path=env["PATH"]):
            raise RuntimeError(f"Building Wine NTDLL requires {tool}")
    with tempfile.TemporaryDirectory(prefix="retroos-wine-build-") as directory:
        work = Path(directory)
        with tarfile.open(args.source) as archive:
            archive.extractall(work, filter="data")
        source = work / "wine-11.0"
        subprocess.run(["patch", "-p1", "-i", str(args.graphics_patch.resolve())], cwd=source, check=True, stdout=subprocess.DEVNULL)
        shutil.copyfile(args.graphics_driver, source / "dlls/win32u/retro_graphics.c")
        spec32 = source / "dlls/win32u/win32u.spec"
        spec32.write_text(spec32.read_text().replace(" -syscall", ""))
        ft = prepare_fonts(source, args.freetype, work)
        contract = prepare(source, work)
        # Expose Wine's own relay assembly and its selector variables. RetroOS
        # supplies the process/thread state; no replacement thunk implementation.
        spec = source / "dlls/krnl386.exe16/krnl386.exe16.spec"
        with spec.open("a") as stream:
            stream.write("\n@ cdecl -arch=win32 RetroWineCallFrom16() __wine_call_from_16\n"
                         "@ cdecl -arch=win32 RetroWineCallFrom16Regs() __wine_call_from_16_regs\n"
                         "@ stdcall -arch=win32 RetroWineConfigureSelectors(long long)\n"
                         "@ stdcall -arch=win32 RetroWineImportSelectors(long)\n"
                         "@ stdcall -arch=win32 RetroWineStartTask(str str)\n")
        with (source / "dlls/krnl386.exe16/kernel.c").open("a") as stream:
            stream.write("\nvoid WINAPI RetroWineConfigureSelectors(DWORD data, DWORD teb)\n"
                         "{ CallTo16_DataSelector = data; CallTo16_TebSelector = teb; }\n")
        # Run the initial NE task on the already-created process thread. Use
        # Wine's module loader, TDB/TIB creation and callback entry, just as its
        # TASK_SpawnTask does for subsequent tasks.
        with (source / "dlls/krnl386.exe16/task.c").open("a") as stream:
            stream.write(r"""
DWORD RetroWineRunTask(NE_MODULE *module, const char *command)
{
    struct create_data *data;
    TDB *task = TASK_Create(module, 1, command, min(strlen(command), 255));
    WIN16_SUBSYSTEM_TIB *tib;
    if (!task) return ERROR_NOT_ENOUGH_MEMORY;
    if (!(tib = allocate_win16_tib(task))) {
        TASK_DeleteTask(task->hSelf);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!(data = HeapAlloc(GetProcessHeap(), 0, sizeof(*data)))) {
        free_win16_tib(tib);
        TASK_DeleteTask(task->hSelf);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    data->task = task;
    data->tib = tib;
    /* NE_CreateThread posts this startup event before the new task runs. */
    PostEvent16(task->hSelf);
    return task_start(data);
}
""")
        with (source / "dlls/krnl386.exe16/ne_module.c").open("a") as stream:
            stream.write(r"""
extern DWORD RetroWineRunTask(NE_MODULE *, const char *);
DWORD WINAPI RetroWineStartTask(const char *path, const char *command)
{
    HMODULE16 module;
    DWORD result;
    _EnterWin16Lock();
    /* Match winevdm: USER/GDI are EXE modules and must be registered before
     * implicit imports try the default .DLL suffix. */
    if (LoadLibrary16("gdi.exe") < 32 || LoadLibrary16("user.exe") < 32 ||
        LoadLibrary16("mmsystem.dll") < 32) {
        _LeaveWin16Lock();
        return ERROR_MOD_NOT_FOUND;
    }
    module = MODULE_LoadModule16(path, FALSE, FALSE);
    _LeaveWin16Lock();
    if (module < 32) return module;
    result = RetroWineRunTask(NE_GetPtr(module), command);
    return result;
}
""")
        selectors = source / "dlls/krnl386.exe16/selector.c"
        selectors.write_text(selectors.read_text().replace("void init_selectors(void)\n{",
            "static BOOL retroos_imported_selectors;\nvoid init_selectors(void)\n{\n"
            "    if (retroos_imported_selectors) return;"))
        with selectors.open("a") as stream:
            stream.write("\nvoid WINAPI RetroWineImportSelectors(DWORD count)\n"
                         "{ retroos_imported_selectors = TRUE; first_ldt_entry = 32; RtlSetBits(&ldt_bitmap, 0, count); }\n")
        dosmem = source / "dlls/krnl386.exe16/dosmem.c"
        text = dosmem.read_text()
        def replace_body(signature, body):
            nonlocal text
            start = text.index("{", text.index(signature))
            depth, end = 1, start + 1
            while depth:
                depth += (text[end] == "{") - (text[end] == "}")
                end += 1
            text = text[:start] + "{\n" + body + "\n}" + text[end:]
        replace_body("BOOL DOSMEM_Init(void)", r"""
    if (!RetroDosMemory(0, 0, 0, 0)) return FALSE;
    DOSMEM_dosmem = DOSMEM_sysmem = 0;
    DOSMEM_protect = 0;
    DOSMEM_0000H = GLOBAL_CreateBlock(GMEM_FIXED, 0, DOSMEM_64KB, 0, data_segment);
    DOSMEM_BiosDataSeg = GLOBAL_CreateBlock(GMEM_FIXED, (void *)0x400, 0x100, 0, data_segment);
    DOSMEM_BiosSysSeg = GLOBAL_CreateBlock(GMEM_FIXED, (void *)0xf0000, DOSMEM_64KB, 0, data_segment);
    return DOSMEM_0000H && DOSMEM_BiosDataSeg && DOSMEM_BiosSysSeg;
""")
        replace_body("BOOL DOSMEM_InitDosMemory(void)", "    static BOOL done; if (!done) { DOSMEM_InitSegments(); done = TRUE; } return TRUE;")
        replace_body("BOOL DOSMEM_MapDosLayout(void)", "    return DOSMEM_InitDosMemory();")
        replace_body("LPVOID DOSMEM_AllocBlock(UINT size, UINT16* pseg)", "    DWORD address = RetroDosMemory(1, 0, size, 0); if (pseg) *pseg = address >> 4; return (void *)address;")
        replace_body("BOOL DOSMEM_FreeBlock(void* ptr)", "    return RetroDosMemory(2, (DWORD)ptr, 0, 0);")
        replace_body("UINT DOSMEM_ResizeBlock(void *ptr, UINT size, BOOL exact)", "    return RetroDosMemory(3, (DWORD)ptr, size, exact);")
        replace_body("UINT DOSMEM_Available(void)", "    return RetroDosMemory(4, 0, 0, 0);")
        text = text.replace('static char *DOSMEM_dosmem;', '__declspec(dllimport) DWORD WINAPI RetroDosMemory(DWORD, DWORD, DWORD, DWORD);\nstatic char *DOSMEM_dosmem;')
        dosmem.write_text(text)
        build = work / "build"
        build.mkdir()
        with (work / "build.log").open("w") as log:
            run([str(source / "configure"), "--enable-win64", "--enable-archs=i386",
                 "--without-x", "--without-wayland", "--without-freetype", "--without-fontconfig",
                 "--without-vulkan", "--without-opengl", "--without-alsa", "--without-pulse",
                 "--without-dbus", "--without-gnutls", "--without-gstreamer", "--disable-tests",
                 "CFLAGS=-O2", "i386_CFLAGS=-O2", "i386_CC=clang-19"], build, env, log)
            ftlib = build_fonts(ft, source, build, work, env, log, run)
            with (build / "Makefile").open("a") as makefile:
                makefile.write(f"\ndlls/win32u/i386-windows/freetype.o: i386_CFLAGS += -I{ft / 'include'}\n")
                makefile.write(f"dlls/win32u/i386-windows/win32u.dll: i386_LDFLAGS += {ftlib}\n")
                makefile.write(f"\ni386_LDFLAGS += {work / 'retroos.lib'}\n")
            run(["make", "-j8", "dlls/ntdll/i386-windows/ntdll.dll",
                 "dlls/krnl386.exe16/i386-windows/krnl386.exe16", "dlls/win32u/i386-windows/win32u.dll"], build, env, log)
        shutil.copyfile(build / "dlls/ntdll/i386-windows/ntdll.dll", output)
        shutil.copyfile(build / "dlls/krnl386.exe16/i386-windows/krnl386.exe16", kernel16)
        shutil.copyfile(build / "dlls/win32u/i386-windows/win32u.dll", args.graphics.resolve())
        abi.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
