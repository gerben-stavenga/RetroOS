"""Generate named host-function exports, with explicit traps for unported services."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

IMPLEMENTED = {"RetroNtAllocateLocallyUniqueId": 4, "RetroNtTerminateProcess": 8, "RetroNtYieldExecution": 0, "RetroDebugWrite": 4, "RetroNtAllocateVirtualMemory": 24, "RetroNtFreeVirtualMemory": 16, "RetroNtQueryInformationProcess": 20, "RetroNtInitializeNlsFiles": 12, "RetroNtGetNlsSectionPtr": 20, "RetroNtQueryDefaultLocale": 8}
IMPLEMENTED.update({"RetroNtQueryKey": 20, "RetroNtEnumerateKey": 24, "RetroNtEnumerateValueKey": 24, "RetroNtDeleteKey": 4, "RetroNtCreateSemaphore": 20, "RetroNtReleaseSemaphore": 12, "RetroNtQuerySemaphore": 20, "RetroNtCreateMutant": 16, "RetroNtReleaseMutant": 8, "RetroNtQueryMutant": 20, "RetroNtDelayExecution": 8, "RetroNtSetInformationFile": 20, "RetroNtWriteFile": 36, "RetroNtFlushBuffersFile": 8, "RetroUserCallback": 20, "RetroNtCallbackReturn": 12, "RetroServerCall": 4, "RetroNtOpenDirectoryObject": 12, "RetroNtCreateKey": 28, "RetroNtOpenKey": 12, "RetroNtOpenKeyEx": 16, "RetroNtQueryValueKey": 24, "RetroNtSetValueKey": 24, "RetroNtDeleteValueKey": 8, "RetroNtClose": 4, "RetroNtQueryInformationToken": 20, "RetroNtQuerySystemInformation": 16, "RetroNtQuerySystemTime": 4, "RetroNtQueryPerformanceCounter": 8, "RetroNtSetInformationProcess": 16, "RetroNtSetLdtEntries": 24, "RetroNtProtectVirtualMemory": 20, "RetroNtSetInformationThread": 16, "RetroNtWow64IsProcessorFeaturePresent": 4, "RetroNtQueryVolumeInformationFile": 20, "RetroNtFsControlFile": 40, "RetroNtQuerySection": 20, "RetroNtWaitForSingleObject": 12, "RetroNtWaitForMultipleObjects": 20, "RetroNtQueryVirtualMemory": 24, "RetroNtCreateSection": 28, "RetroNtOpenSection": 12, "RetroNtMapViewOfSection": 40, "RetroNtUnmapViewOfSection": 8, "RetroNtOpenFile": 24, "RetroNtCreateFile": 44, "RetroNtAddAtom": 12, "RetroNtFindAtom": 12, "RetroNtDeleteAtom": 4, "RetroNtQueryInformationAtom": 20, "RetroNtQueryAttributesFile": 8, "RetroNtQueryFullAttributesFile": 8, "RetroNtQueryDirectoryFile": 44, "RetroNtReadFile": 36, "RetroNtQueryInformationFile": 20, "RetroNtCreateEvent": 20, "RetroNtSetEvent": 8, "RetroNtResetEvent": 8, "RetroNtClearEvent": 4, "RetroNtQueryEvent": 20})
IMPLEMENTED.update({"RetroNtWaitForAlertByThreadId":8,"RetroNtAlertThreadByThreadId":4,"RetroNtContinue":8,"RetroNtCreateThreadEx":44,"RetroNtResumeThread":8,"RetroNtTerminateThread":8,"RetroNtQueryInformationThread":20})
PRIVATE = {"RetroRestoreContext":4,"RetroThread":12,"RetroUniqueId": 4, "RetroGraphics": 12, "RetroProcessExit": 4, "RetroWriteFile": 20, "RetroYield": 0, "RetroUnsupported": 4, "RetroMemoryReserve": 8, "RetroMemoryCommit": 12, "RetroMemoryDecommit": 8, "RetroMemoryRelease": 4, "RetroMapFile": 12, "RetroLocaleId": 0, "RetroRegistry": 28, "RetroClock": 4, "RetroSetSelectors": 24, "RetroMemoryProtect": 12, "RetroSystemInfo": 4, "RetroClearTls": 4, "RetroFileKind": 4, "RetroDosMemory": 16, "RetroEvent": 16, "RetroSync": 24, "RetroQueue": 12, "RetroFile": 28, "RetroWait": 20, "RetroMemoryQuery": 8, "RetroSection": 24, "RetroSession": 24, "RetroUserObject": 24, "RetroWindow": 24, "RetroWindowTree": 12, "RetroCursor": 8, "RetroClass": 20, "RetroAtom": 20}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--abi", type=Path, required=True)
    parser.add_argument("--asm", type=Path)
    parser.add_argument("--obj", type=Path)
    parser.add_argument("--server", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--linker", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    contract = json.loads(args.abi.read_text())
    assert all(contract.get(name) == size for name, size in IMPLEMENTED.items())
    if args.asm:
        text = "bits 32\nsection .text\n"
        for name, size in PRIVATE.items():
            text += f"global {name}, _{name}@{size}\n{name}:\n_{name}@{size}: int 0x83\n"
        text += """
; Save the userspace callback continuation, including its SEH chain.
global _RetroCallbackSave, _RetroCallbackRestore
_RetroCallbackSave:
    mov eax,[esp+4]
    mov [eax],ebp
    mov [eax+4],ebx
    mov [eax+8],esi
    mov [eax+12],edi
    lea edx,[esp+4]
    mov [eax+16],edx
    mov edx,[esp]
    mov [eax+20],edx
    mov edx,[fs:0]
    mov [eax+24],edx
    xor eax,eax
    ret
_RetroCallbackRestore:
    mov eax,[esp+4]
    mov ebp,[eax]
    mov ebx,[eax+4]
    mov esi,[eax+8]
    mov edi,[eax+12]
    mov ecx,[eax+20]
    mov edx,[eax+24]
    mov [fs:0],edx
    mov esp,[eax+16]
    mov eax,1
    jmp ecx
"""
        messages = "section .rdata\n"
        for index, (name, size) in enumerate(contract.items()):
            text += f"global {name}\n{name}:\n"
            if name in IMPLEMENTED:
                text += f"extern _{name}@{size}\njmp _{name}@{size}\n"
            else:
                text += f"push missing_{index}\ncall RetroUnsupported\nud2\n"
                messages += f"missing_{index}: db '{name}', 0\n"
        args.asm.write_text(text + messages)
    else:
        with tempfile.TemporaryDirectory(prefix="retroos-backend-link-") as directory:
            script = Path(directory) / "backend.lnk"
            script.write_text("format windows nt dll\noption quiet\noption modname=RETROOS\nexport RetroDispatchFault='_RetroDispatchFault@8'\n" +
                f"name {args.output}\nfile {args.obj}\nfile {args.server}\nlibrary {args.library}\n" +
                "import '_RetroWineDispatchException@8' NTDLL.RetroWineDispatchException\n"
                "import '_RetroWineThreadStart@8' NTDLL.RetroWineThreadStart\n"
                "import '_RetroWineDispatchCallback@12' NTDLL.RetroWineDispatchCallback\n"
                "import '_RtlFlsAlloc@8' NTDLL.RtlFlsAlloc\n"
                "import '_RtlFlsGetValue@8' NTDLL.RtlFlsGetValue\n"
                "import '_RtlFlsSetValue@8' NTDLL.RtlFlsSetValue\n"
                "import '_RtlAllocateHeap@12' NTDLL.RtlAllocateHeap\n"
                "import '_RtlFreeHeap@12' NTDLL.RtlFreeHeap\n"
                "import '_RtlUpcaseUnicodeChar@4' NTDLL.RtlUpcaseUnicodeChar\n"
                "import '_RtlAcquireSRWLockExclusive@4' NTDLL.RtlAcquireSRWLockExclusive\n"
                "import '_RtlReleaseSRWLockExclusive@4' NTDLL.RtlReleaseSRWLockExclusive\n" +
                "".join(f"export {name}\n" for name in [*PRIVATE, *contract]))
            subprocess.run([str(args.linker), "@" + str(script)], check=True)


if __name__ == "__main__":
    main()
