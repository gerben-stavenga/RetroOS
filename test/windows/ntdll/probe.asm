bits 32
section .text
global _start
extern RtlInitAnsiString, RtlInitUnicodeString, RtlMoveMemory
extern RtlCompareMemory, RtlZeroMemory, NtTerminateProcess, RetroWriteFile
extern RtlCreateHeap, RtlAllocateHeap, RtlReAllocateHeap, RtlFreeHeap
extern NtAllocateVirtualMemory, NtFreeVirtualMemory
extern LdrLoadDll, LdrGetDllHandle, LdrGetProcedureAddress, LdrResolveDelayLoadedAPI
_start:
    push ansi
    push counted
    call RtlInitAnsiString
    cmp dword [counted], 0x00050004
    jne failed
    cmp dword [counted + 4], ansi
    jne failed
    push wide
    push counted
    call RtlInitUnicodeString
    cmp dword [counted], 0x00060004
    jne failed
    cmp dword [counted + 4], wide
    jne failed
    push 0
    push counted
    call RtlInitUnicodeString
    cmp dword [counted], 0
    jne failed
    cmp dword [counted + 4], 0
    jne failed
    push 4
    push overlap
    push overlap + 1
    call RtlMoveMemory
    push 5
    push expected
    push overlap
    call RtlCompareMemory
    cmp eax, 5
    jne failed
    push 8
    push counted
    call RtlZeroMemory
    cmp dword [counted], 0
    jne failed
    cmp dword [counted + 4], 0
    jne failed
    ; An invalid process handle must not accidentally terminate this process.
    push 42
    push 1234
    call NtTerminateProcess
    cmp eax, 0xc0000008
    jne failed
    ; Reserve without backing, then commit a page through Wine's real veneers.
    mov dword [memory_size], 8193
    push 1
    push 0x2000
    push memory_size
    push 0
    push memory_base
    push -1
    call NtAllocateVirtualMemory
    test eax, eax
    jnz failed
    cmp dword [memory_size], 12288
    jne failed
    mov eax, [memory_base]
    test eax, 65535
    jnz failed
    mov [saved_base], eax
    mov dword [memory_size], 4096
    call commit_page
    test eax, eax
    jnz failed
    mov eax, [memory_base]
    cmp dword [eax], 0
    jne failed
    mov dword [eax], 0x12345678
    call commit_page
    test eax, eax
    jnz failed
    mov eax, [memory_base]
    cmp dword [eax], 0x12345678
    jne failed
    push 0x4000
    push memory_size
    push memory_base
    push -1
    call NtFreeVirtualMemory
    test eax, eax
    jnz failed
    call commit_page
    test eax, eax
    jnz failed
    mov eax, [memory_base]
    cmp dword [eax], 0
    jne failed
    ; RELEASE requires size=0, and a failed call must leave the mapping intact.
    push 0x8000
    push memory_size
    push memory_base
    push -1
    call NtFreeVirtualMemory
    cmp eax, 0xc000000d
    jne failed
    mov eax, [memory_base]
    mov dword [eax], 42
    mov dword [memory_size], 0
    call release_region
    test eax, eax
    jnz failed
    ; Reusing exactly that reservation must succeed and provide fresh zeroes.
    mov eax, [saved_base]
    mov [memory_base], eax
    mov dword [memory_size], 4096
    push 4
    push 0x3000
    push memory_size
    push 0
    push memory_base
    push -1
    call NtAllocateVirtualMemory
    test eax, eax
    jnz failed
    mov eax, [memory_base]
    cmp eax, [saved_base]
    jne failed
    cmp dword [eax], 0
    jne failed
    mov dword [memory_size], 0
    call release_region
    test eax, eax
    jnz failed
    ; Exercise Wine's allocator, including a large allocation and growth.
    push 0
    push 0
    push 0
    push 0
    push 0
    push 2
    call RtlCreateHeap
    test eax, eax
    jz failed
    mov [wine_heap], eax
    push 32
    push 8
    push eax
    call RtlAllocateHeap
    test eax, eax
    jz failed
    cmp dword [eax], 0
    jne failed
    mov dword [eax], 0xdeadbeef
    push 1048576
    push eax
    push 8
    push dword [wine_heap]
    call RtlReAllocateHeap
    test eax, eax
    jz failed
    cmp dword [eax], 0xdeadbeef
    jne failed
    cmp dword [eax + 1048572], 0
    jne failed
    push eax
    push 0
    push dword [wine_heap]
    call RtlFreeHeap
    test al, al
    jz failed
%ifndef PORTABLE_ONLY
    ; Delay-load LAZY, which requires INITDEP's initializer before its own.
    push 0
    push lazy_iat
    push 0
    push 0
    push delay
    push 0
    call LdrResolveDelayLoadedAPI
    test eax, eax
    jz failed
    cmp eax, [lazy_iat]
    jne failed
    call eax
    cmp eax, 1
    jne failed
    ; Loading an already loaded DLL must not run DllMain again.
    push found_module
    push lazy_unicode
    push 0
    push 0
    call LdrLoadDll
    test eax, eax
    jnz failed
    mov eax, [found_module]
    cmp eax, [lazy_handle]
    jne failed
    call [lazy_iat]
    cmp eax, 1
    jne failed
    ; Ordinal-only lookup uses the same export path.
    push found_proc
    push 1
    push 0
    push dword [found_module]
    call LdrGetProcedureAddress
    test eax, eax
    jnz failed
    mov eax, [found_proc]
    cmp eax, [lazy_iat]
    jne failed
    ; Wine descriptors normally contain RVAs, including the named thunk.
    mov eax, [fs:0x30]
    mov ebx, [eax + 8]
    mov [image_base], ebx
    mov dword [delay], 1
    sub [delay + 4], ebx
    sub [delay + 8], ebx
    sub [delay + 12], ebx
    sub [delay + 16], ebx
    mov eax, lazy_proc
    sub eax, ebx
    mov [lazy_names], eax
    push 0
    push lazy_iat
    push 0
    push 0
    push delay
    push ebx
    call LdrResolveDelayLoadedAPI
    cmp eax, [found_proc]
    jne failed
    mov dword [lazy_names], 0x80000001
    push 0
    push lazy_iat
    push 0
    push 0
    push delay
    push ebx
    call LdrResolveDelayLoadedAPI
    cmp eax, [found_proc]
    jne failed
    ; Missing procedures go through the application's failure hook.
    mov eax, missing_proc
    sub eax, ebx
    mov [lazy_names], eax
    push 0
    push lazy_iat
    push 0
    push failure_hook
    push delay
    push ebx
    call LdrResolveDelayLoadedAPI
    cmp eax, hook_value
    jne failed
    call eax
    cmp eax, 4567
    jne failed
    ; A rejected attach must roll the new module out of the loader list.
    push found_module
    push reject_unicode
    push 0
    push 0
    call LdrLoadDll
    cmp eax, 0xc0000142
    jne failed
    cmp dword [found_module], 0
    jne failed
    push found_module
    push reject_unicode
    push 0
    push 0
    call LdrGetDllHandle
    cmp eax, 0xc0000135
    jne failed
%endif
    mov esi, success
    mov edi, success_end - success
    xor ebx, ebx
    jmp report
failed:
    mov esi, failure
    mov edi, failure_end - failure
    mov ebx, 1
report:
    push 0
    push written
    push edi
    push esi
    push 1
    call RetroWriteFile
    push ebx
    push -1
    call NtTerminateProcess
    ud2
commit_page:
    push 4
    push 0x1000
    push memory_size
    push 0
    push memory_base
    push -1
    call NtAllocateVirtualMemory
    ret
release_region:
    push 0x8000
    push memory_size
    push memory_base
    push -1
    call NtFreeVirtualMemory
    ret
failure_hook:
    cmp dword [esp + 4], 4
    jne .bad
    mov eax, [esp + 8]
    cmp dword [eax + 32], 0xc0000139
    jne .bad
    mov eax, hook_value
    ret 8
.bad:
    xor eax, eax
    ret 8
hook_value:
    mov eax, 4567
    ret
section .data
delay dd 0, lazy_name, lazy_handle, lazy_iat, lazy_names, 0, 0, 0
lazy_name db 'LAZY.DLL', 0
lazy_names dd lazy_proc, 0
lazy_proc dw 0
    db 'Value', 0
missing_proc dw 0
    db 'Missing', 0
lazy_unicode dw 16, 18
    dd lazy_wide
lazy_wide dw 'L','A','Z','Y','.','D','L','L',0
reject_unicode dw 20, 22
    dd reject_wide
reject_wide dw 'R','E','J','E','C','T','.','D','L','L',0
ansi db 'wine', 0
wide dw 'N', 'T', 0
overlap db 'abcde'
expected db 'aabcd'
success db 'NTDLL PASS', 13, 10
success_end:
failure db 'NTDLL FAIL', 13, 10
failure_end:
section .bss
counted resd 2
written resd 1
lazy_handle resd 1
lazy_iat resd 1
found_module resd 1
found_proc resd 1
image_base resd 1

memory_base resd 1
memory_size resd 1
saved_base resd 1
wine_heap resd 1
