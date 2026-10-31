extern NtWaitForAlertByThreadId, NtAlertThreadByThreadId
extern NtCreateThreadEx, NtResumeThread, NtQueryInformationThread
extern RtlGetFullPathName_U
extern RetroGraphics
extern NtQueryKey, NtEnumerateKey, NtEnumerateValueKey, NtDeleteKey
extern NtCreateSemaphore, NtReleaseSemaphore, NtQuerySemaphore, NtCreateMutant, NtReleaseMutant, NtQueryMutant, NtDelayExecution
extern NtWriteFile, NtSetInformationFile, NtFlushBuffersFile, NtCreateFile
extern NtCallbackReturn, RetroUserCallback
extern NtQuerySection
extern NtWaitForSingleObject, NtWaitForMultipleObjects
extern NtQueryVirtualMemory
extern NtCreateSection
extern NtQueryAttributesFile, NtQueryFullAttributesFile
extern NtQueryDirectoryFile
extern NtAddAtom, NtFindAtom, NtDeleteAtom, NtQueryInformationAtom
bits 32
section .text
global _start
extern RtlInitAnsiString, RtlInitUnicodeString, RtlMoveMemory
extern RtlCompareMemory, RtlZeroMemory, NtTerminateProcess, RetroWriteFile
extern RtlCreateHeap, RtlAllocateHeap, RtlReAllocateHeap, RtlFreeHeap
extern wine_server_call
extern NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection
extern NtOpenFile, NtReadFile, NtQueryInformationFile
extern NtCreateEvent, NtSetEvent, NtResetEvent, NtQueryEvent
extern NtProtectVirtualMemory, NtSetInformationThread
extern NtSetLdtEntries, NtQueryInformationToken, NtQuerySystemTime, NtQueryPerformanceCounter
extern NtDeleteValueKey
extern NtCreateKey, NtSetValueKey, NtQueryValueKey, NtClose
extern __wine_dbg_strdup
extern RetroWineInitializeLocale, RetroWineInitializePeb, RtlAcquirePebLock, RtlReleasePebLock
extern NtInitializeNlsFiles, NtGetNlsSectionPtr, NtQueryDefaultLocale, NtQueryInformationProcess
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
    mov byte [failure_stage], '1'
    ; Bootstrap Wine's actual PEB lock before any environment lookup. Repeating
    ; the initializer must not replace the heap or reset live lock/TLS state.
    call RetroWineInitializePeb
    call RetroWineInitializeLocale
    mov eax, [fs:0x30]
    cmp dword [eax + 0x1c], 0
    je failed
    mov ebx, [eax + 0x18]
    test ebx, ebx
    jz failed
    ; Wine's scratch strings follow the TEB and must not overwrite the PEB.
    mov esi, [eax + 0x1c]
    push debug_scratch
    call __wine_dbg_strdup
    add esp, 4
    mov eax, [fs:0x30]
    cmp esi, [eax + 0x1c]
    jne failed
    call RtlAcquirePebLock
    call RtlReleasePebLock
    call RetroWineInitializePeb
    mov eax, [fs:0x30]
    cmp ebx, [eax + 0x18]
    jne failed
    mov byte [failure_stage], '2'
    ; Registry keys retain typed values, report short buffers, and close handles.
    push written
    push 0
    push 0
    push 0
    push reg_attributes
    push 0xf003f
    push reg_handle
    call NtCreateKey
    test eax, eax
    jnz failed
    push 4
    push reg_value
    push 4
    push 0
    push reg_name
    push dword [reg_handle]
    call NtSetValueKey
    test eax, eax
    jnz failed
    push written
    push 0
    push 0
    push 2
    push reg_name
    push dword [reg_handle]
    call NtQueryValueKey
    cmp eax, 0xc0000023
    jne failed
    cmp dword [written], 16
    jne failed
    push written
    push 16
    push reg_result
    push 2
    push reg_name
    push dword [reg_handle]
    call NtQueryValueKey
    test eax, eax
    jnz failed
    cmp dword [reg_result + 4], 4
    jne failed
    cmp dword [reg_result + 8], 4
    jne failed
    cmp dword [reg_result + 12], 0x12345678
    jne failed
    ; Registry links resolve to the target, while the creation handle addresses
    ; the link itself so deleting it cannot delete the target.
    push written
    push 2
    push 0
    push 0
    push reg_link_attributes
    push 0xf003f
    push reg_link_handle
    call NtCreateKey
    test eax,eax
    jnz failed
    push reg_path_end-reg_path_text
    push reg_path_text
    push 6
    push 0
    push reg_link_value
    push dword [reg_link_handle]
    call NtSetValueKey
    test eax,eax
    jnz failed
    push written
    push 0
    push 0
    push 0
    push reg_link_attributes
    push 0xf003f
    push reg_link_target
    call NtCreateKey
    test eax,eax
    jnz failed
    cmp dword [written],2
    jne failed
    push written
    push 16
    push reg_result
    push 2
    push reg_name
    push dword [reg_link_target]
    call NtQueryValueKey
    test eax,eax
    jnz failed
    cmp dword [reg_result+12],0x12345678
    jne failed
    push dword [reg_link_target]
    call NtClose
    push dword [reg_link_handle]
    call NtDeleteKey
    test eax,eax
    jnz failed
    push dword [reg_link_handle]
    call NtClose
    push written
    push 64
    push registry_info
    push 2
    push dword [reg_handle]
    call NtQueryKey
    test eax,eax
    jnz failed
    cmp dword [registry_info+32],1
    jne failed
    cmp dword [registry_info+36],10
    jne failed
    mov eax,[registry_info]
    or eax,[registry_info+4]
    jz failed
    push written
    push 64
    push registry_info
    push 1
    push 0
    push dword [reg_handle]
    call NtEnumerateValueKey
    test eax,eax
    jnz failed
    cmp dword [written],36
    jne failed
    cmp dword [registry_info+8],32
    jne failed
    cmp dword [registry_info+32],0x12345678
    jne failed
    cmp word [registry_info+20],'V'
    jne failed
    push written
    push 64
    push registry_info
    push 0
    push 0
    push dword [reg_handle]
    call NtEnumerateKey
    cmp eax,0x8000001a
    jne failed
    push reg_name
    push dword [reg_handle]
    call NtDeleteValueKey
    test eax, eax
    jnz failed
    push reg_name
    push dword [reg_handle]
    call NtDeleteValueKey
    cmp eax, 0xc0000034
    jne failed
    push dword [reg_handle]
    call NtDeleteKey
    test eax,eax
    jnz failed
    push written
    push 64
    push registry_info
    push 2
    push dword [reg_handle]
    call NtQueryKey
    cmp eax,0xc000017c
    jne failed
    push dword [reg_handle]
    call NtClose
    test eax, eax
    jnz failed
    push dword [reg_handle]
    call NtClose
    cmp eax, 0xc0000008
    jne failed
    mov byte [failure_stage], '3'
    ; Wine's selector shadow must describe the selector actually loaded by CPU.
    mov eax, [fs:0x30]
    mov dword [eax + 0x220], ldt_copy
    mov eax, reg_value
    mov edx, eax
    shl eax, 16
    or eax, 0xff
    mov ebx, edx
    shr edx, 16
    and edx, 0xff
    and ebx, 0xff000000
    or edx, ebx
    or edx, 0x0040f300
    push 0
    push 0
    push 0
    push edx
    push eax
    push 0x4007
    call NtSetLdtEntries
    test eax, eax
    jnz failed
    cmp dword [ldt_copy + 0x800 * 4], reg_value
    jne failed
    cmp dword [ldt_copy + 32768 + 0x800 * 4], 0x530000ff
    jne failed
    mov ax, 0x4007
    mov es, ax
    mov eax, [es:0]
    push ds
    pop es
    cmp eax, 0x12345678
    jne failed
    mov byte [failure_stage], '4'
    push written
    push 36
    push token_info
    push 1
    push -6
    call NtQueryInformationToken
    test eax, eax
    jnz failed
    mov eax, [token_info]
    cmp byte [eax], 1
    jne failed
    cmp byte [eax+1], 5
    jne failed
    cmp dword [eax+24], 1000
    jne failed
    mov byte [failure_stage], '5'
    push clock_value
    call NtQuerySystemTime
    test eax, eax
    jnz failed
    cmp dword [clock_value+4], 0
    je failed
    mov byte [failure_stage], '6'
    push clock_frequency
    push clock_value
    call NtQueryPerformanceCounter
    test eax, eax
    jnz failed
    cmp dword [clock_frequency], 10000000
    jne failed
    mov byte [failure_stage], '7'
    mov dword [fs:0xe14], 0x87654321
    push 4
    push tls_index
    push 10
    push -2
    call NtSetInformationThread
    test eax, eax
    jnz failed
    cmp dword [fs:0xe14], 0
    jne failed
    ; Process and locale services expose real process state and Wine data.
    push written
    push 24
    push process_info
    push 0
    push -1
    call NtQueryInformationProcess
    test eax, eax
    jnz failed
    cmp dword [written], 24
    jne failed
    cmp dword [process_info + 4], 0
    je failed
    cmp dword [process_info + 16], 0
    je failed
    push nls_size
    push locale_id
    push nls_base
    call NtInitializeNlsFiles
    test eax, eax
    jnz failed
    cmp dword [nls_size], 0
    je failed
    push expected_locale
    push 1
    call NtQueryDefaultLocale
    test eax, eax
    jnz failed
    mov eax, [expected_locale]
    cmp eax, [locale_id]
    jne failed
    push nls_size
    push nls_base
    push 0
    push 1252
    push 11
    call NtGetNlsSectionPtr
    test eax, eax
    jnz failed
    mov eax, [nls_base]
    cmp word [eax + 2], 1252
    jne failed
    mov byte [failure_stage], '8'
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
    push old_protection
    push 2
    push memory_size
    push memory_base
    push -1
    call NtProtectVirtualMemory
    test eax, eax
    jnz failed
    cmp dword [old_protection], 4
    jne failed
    push old_protection
    push 4
    push memory_size
    push memory_base
    push -1
    call NtProtectVirtualMemory
    test eax, eax
    jnz failed
    cmp dword [old_protection], 2
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
    ; Callbacks are direct DLL calls, including nested nonlocal returns.
    mov byte [failure_stage], 'C'
    mov eax,[fs:0x30]
    push dword [eax+0x2c]
    mov dword [eax+0x2c],callback_table
    push 0
    push 0
    push 0
    call NtCallbackReturn
    cmp eax,0xc0000258
    jne failed
    push callback_size
    push callback_result
    push 0
    push 0
    push 0
    call RetroUserCallback
    cmp eax,0x123
    jne failed
    cmp dword [callback_size],4
    jne failed
    mov eax,[callback_result]
    cmp dword [eax],0xdeadbeef
    jne failed
    ; Ordinary callback return also resumes the same wrapper.
    push callback_size
    push callback_result
    push 0
    push 0
    push 2
    call RetroUserCallback
    cmp eax,0x456
    jne failed
    cmp dword [callback_size],0
    jne failed
    mov eax,[fs:0x30]
    pop dword [eax+0x2c]
    mov byte [failure_stage], 's'
    push 2
    push 1
    push 0
    push 0x1f0003
    push sem_handle
    call NtCreateSemaphore
    test eax,eax
    jnz failed
    push zero_timeout
    push 0
    push dword [sem_handle]
    call NtWaitForSingleObject
    test eax,eax
    jnz failed
    push zero_timeout
    push 0
    push dword [sem_handle]
    call NtWaitForSingleObject
    cmp eax,0x102
    jne failed
    push sync_info
    push 2
    push dword [sem_handle]
    call NtReleaseSemaphore
    test eax,eax
    jnz failed
    cmp dword [sync_info],0
    jne failed
    push 0
    push 1
    push dword [sem_handle]
    call NtReleaseSemaphore
    cmp eax,0xc0000047
    jne failed
    push 0
    push 8
    push sync_info
    push 0
    push dword [sem_handle]
    call NtQuerySemaphore
    test eax,eax
    jnz failed
    cmp dword [sync_info],2
    jne failed
    push 1
    push 0
    push 0x1f0001
    push mutant_handle
    call NtCreateMutant
    test eax,eax
    jnz failed
    push zero_timeout
    push 0
    push dword [mutant_handle]
    call NtWaitForSingleObject
    test eax,eax
    jnz failed
    push 0
    push 8
    push sync_info
    push 0
    push dword [mutant_handle]
    call NtQueryMutant
    test eax,eax
    jnz failed
    cmp dword [sync_info],-1
    jne failed
    cmp byte [sync_info+4],1
    jne failed
    push 0
    push dword [mutant_handle]
    call NtReleaseMutant
    cmp eax,0
    jne failed
    push 0
    push dword [mutant_handle]
    call NtReleaseMutant
    cmp eax,0
    jne failed
    push 0
    push dword [mutant_handle]
    call NtReleaseMutant
    cmp eax,0xc0000046
    jne failed
    push dword [sem_handle]
    call NtClose
    test eax,eax
    jnz failed
    push dword [mutant_handle]
    call NtClose
    test eax,eax
    jnz failed
    push delay_timeout
    push 0
    call NtDelayExecution
    test eax,eax
    jnz failed
%ifdef PORTABLE_ONLY
    mov byte [failure_stage], 'p'
    push 0
    push full_path_buffer
    push 128
    push relative_path
    call RtlGetFullPathName_U
    cmp eax,expected_full_path_end-expected_full_path
    jne failed
    mov esi,full_path_buffer
    mov edi,expected_full_path
    mov ecx,expected_full_path_end-expected_full_path
    repe cmpsb
    jne failed
%endif
    mov byte [failure_stage], 'W'
    ; Wine 11's server union is 64 bytes, followed by count/reply/iovecs.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req], 174
    push server_req
    call wine_server_call
    add esp, 4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],170
    mov dword [server_req+4],station_name_end-station_name
    mov dword [server_req+16],0xf037f
    mov dword [server_req+20],0xc0
    mov dword [server_req+64],1
    mov dword [server_req+72],station_name
    mov dword [server_req+76],station_name_end-station_name
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    mov [station_handle],eax
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],175
    mov eax,[station_handle]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov dword [server_req],174
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[station_handle]
    cmp [server_req+8],eax
    jne failed
    push eax
    call NtClose
    cmp eax,0xc0000022
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],177
    mov dword [server_req+4],desktop_name_end-desktop_name
    mov dword [server_req+16],0xf01ff
    mov dword [server_req+20],0xc0
    mov dword [server_req+64],1
    mov dword [server_req+72],desktop_name
    mov dword [server_req+76],desktop_name_end-desktop_name
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    mov [desktop_handle],eax
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],183
    mov eax,[desktop_handle]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0
    je failed
    mov eax,[server_req+16]
    mov [desktop_offset],eax
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],182
    mov eax,[fs:0x24]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[desktop_handle]
    cmp [server_req+24],eax
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],173
    mov dword [server_req+12],1
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],2
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],173
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],2
    jne failed
    ; Create a class with extra bytes and verify the shared class layout.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],203
    mov dword [server_req+16],0x8001
    mov dword [server_req+20],3
    mov dword [server_req+32],0x12345678
    mov word [server_req+40],4096
    mov word [server_req+42],8
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    mov [class_id],eax
    mov eax,[server_req+16]
    mov [class_offset],eax
    and eax,0xffff0000
    mov [class_map_offset],eax
    push session_attrs
    push 4
    push session_handle
    call NtOpenSection
    test eax,eax
    jnz failed
    push 2
    push 0
    push 2
    push class_view_size
    push class_map_offset
    push 0
    push 0
    push class_view_base
    push -1
    push dword [session_handle]
    call NtMapViewOfSection
    test eax,eax
    jnz failed
    mov edi,[class_offset]
    and edi,65535
    add edi,[class_view_base]
    mov eax,[class_id]
    cmp [edi+8],eax
    jne failed
    cmp dword [edi+16],0x8001
    jne failed
    cmp dword [edi+20],3
    jne failed
    cmp dword [edi+24],4096
    jne failed
    cmp dword [edi+28],8
    jne failed
    mov esi,[edi]
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],204
    mov dword [server_req+12],0x8001
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0x12345678
    jne failed
    cmp dword [edi+8],0
    jne failed
    cmp [edi],esi
    je failed
    push dword [class_view_base]
    push -1
    call NtUnmapViewOfSection
    test eax,eax
    jnz failed
    push dword [session_handle]
    call NtClose
    test eax,eax
    jnz failed
    mov byte [failure_stage], 'S'
    push session_attrs
    push 4
    push session_handle
    call NtOpenSection
    test eax, eax
    jnz failed
    push 2
    push 0
    push 2
    push session_size
    push 0
    push 0
    push 0
    push session_base
    push -1
    push dword [session_handle]
    call NtMapViewOfSection
    test eax, eax
    jnz failed
    cmp dword [session_size], 1048576
    jne failed
    mov eax, [session_base]
    cmp dword [eax], 0
    jne failed
    ; Closing the section handle does not unmap the view.
    push dword [session_handle]
    call NtClose
    test eax, eax
    jnz failed
    mov eax, [session_base]
    cmp dword [eax], 0
    jne failed
    ; Desktop roots use actual shared USER entries and keep their classes alive.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],203
    mov dword [server_req+16],32769
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],203
    mov dword [server_req+4],14
    mov dword [server_req+64],1
    mov dword [server_req+72],message_class_name
    mov dword [server_req+76],14
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],144
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov esi,[server_req+8]
    mov edi,[server_req+12]
    test esi,esi
    jz failed
    cmp esi,edi
    je failed
    mov ecx,esi
    and ecx,0xffff
    sub ecx,0x20
    shl ecx,4
    add ecx,[session_base]
    cmp dword [ecx],0
    je failed
    cmp dword [ecx+16],0
    je failed
    mov eax,esi
    and eax,0xffff0000
    or eax,1
    cmp [ecx+24],eax
    jne failed
    ; Repeated queries preserve identity.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],144
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp [server_req+8],esi
    jne failed
    cmp [server_req+12],edi
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],204
    mov dword [server_req+12],32769
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0xc0010584
    jne failed
    ; Desktop clipping is a real region with a size negotiation path.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],160
    mov [server_req+12],esi
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0x80000005
    jne failed
    cmp dword [server_req+48],16
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],160
    mov dword [server_req+8],16
    mov [server_req+12],esi
    mov dword [server_req+68],desktop_region
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+4],16
    jne failed
    cmp dword [desktop_region+8],640
    jne failed
    cmp dword [desktop_region+12],480
    jne failed
    ; Application windows share the same tree used for enumeration and queries.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],203
    mov dword [server_req+16],0x8002
    mov dword [server_req+32],0x12345678
    mov word [server_req+42],12
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],142
    mov dword [server_req+20],0x8002
    mov dword [server_req+40],0x12
    mov dword [server_req+44],0x10000000
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    mov [test_window],eax
    cmp [server_req+12],esi
    jne failed
    cmp dword [server_req+20],12
    jne failed
    cmp dword [server_req+24],0x12345678
    jne failed
    push graphics_screen
    push 0
    push 0
    call RetroGraphics
    test eax,eax
    jnz failed
    cmp dword [graphics_screen],640
    jne failed
    cmp dword [graphics_screen+4],480
    jne failed
    mov eax,[test_window]
    mov [graphics_params],eax
    push 0
    push graphics_params
    push 1
    call RetroGraphics
    test eax,eax
    jnz failed
    push 0
    push graphics_params
    push 2
    call RetroGraphics
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],148
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+16],4
    mov dword [server_req+20],8
    mov dword [server_req+24],0x11223344
    mov dword [server_req+28],0x55667788
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],146
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+16],4
    mov dword [server_req+20],8
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+16],0x11223344
    jne failed
    cmp dword [server_req+20],0x55667788
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],155
    mov word [server_req+12],0x40
    mov eax,[test_window]
    mov [server_req+20],eax
    mov dword [server_req+28],10
    mov dword [server_req+32],20
    mov dword [server_req+36],110
    mov dword [server_req+40],220
    mov dword [server_req+44],12
    mov dword [server_req+48],40
    mov dword [server_req+52],108
    mov dword [server_req+56],218
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],151
    mov dword [server_req+8],16
    mov dword [server_req+68],window_list
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],1
    jne failed
    mov eax,[test_window]
    cmp [window_list],eax
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],154
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp [server_req+8],esi
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],156
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+16],3
    mov dword [server_req+20],96
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],10
    jne failed
    cmp dword [server_req+12],20
    jne failed
    cmp dword [server_req+24],12
    jne failed
    cmp dword [server_req+28],40
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],161
    mov dword [server_req+8],16
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+16],1
    mov dword [server_req+68],window_region
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [window_region],10
    jne failed
    cmp dword [window_region+12],220
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],162
    mov dword [server_req+4],16
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+64],1
    mov dword [server_req+72],test_shape
    mov dword [server_req+76],16
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],161
    mov dword [server_req+8],16
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+68],window_region
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [window_region],5
    jne failed
    cmp dword [window_region+12],30
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],153
    mov dword [server_req+8],16
    mov [server_req+12],esi
    mov dword [server_req+16],15
    mov dword [server_req+20],26
    mov dword [server_req+24],96
    mov dword [server_req+68],window_list
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],2
    jne failed
    mov eax,[test_window]
    cmp [window_list],eax
    jne failed
    cmp [window_list+4],esi
    jne failed
    ; Server titles retain UTF-16, drop an odd input byte, and report the full
    ; character count even when the reply buffer truncates the payload.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],158
    mov dword [server_req+4],7
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+64],1
    mov dword [server_req+72],test_title
    mov dword [server_req+76],7
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],157
    mov dword [server_req+8],3
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+68],window_region
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],3
    jne failed
    cmp dword [server_req+4],3
    jne failed
    cmp word [window_region],0x0043
    jne failed
    cmp byte [window_region+2],0xe9
    jne failed
    ; Reparenting cannot introduce a cycle; unlink/relink preserves the handle.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],149
    mov eax,[test_window]
    mov [server_req+12],eax
    mov [server_req+16],eax
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0xc000000d
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],149
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp [server_req+8],esi
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],149
    mov eax,[test_window]
    mov [server_req+12],eax
    mov [server_req+16],esi
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp [server_req+12],esi
    jne failed
    ; Activate, focus and capture through the shared USER input queue.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],192
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0
    jne failed
    cmp dword [server_req+16],0
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],194
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],192
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[test_window]
    cmp [server_req+8],eax
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],188
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    test eax,eax
    jz failed
    mov [foreground_id],eax
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],188
    mov eax,[fs:0x24]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[foreground_id]
    cmp [server_req+8],eax
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],193
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],193
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[test_window]
    cmp [server_req+8],eax
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],195
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],195
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[test_window]
    cmp [server_req+8],eax
    jne failed
    ; Caret state belongs to the thread input queue, shared by both Windows ABIs.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],196
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+16],2
    mov dword [server_req+20],16
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],197
    mov dword [server_req+12],7
    mov eax,[test_window]
    mov [server_req+16],eax
    mov dword [server_req+20],10
    mov dword [server_req+24],20
    mov dword [server_req+28],-1
    mov dword [server_req+32],1
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+20],2
    jne failed
    cmp dword [server_req+28],1
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],197
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+12],10
    jne failed
    cmp dword [server_req+16],20
    jne failed
    cmp dword [server_req+20],12
    jne failed
    cmp dword [server_req+24],36
    jne failed
    cmp dword [server_req+28],0
    jne failed
    cmp dword [server_req+32],1
    jne failed
    ; Ordinary windows have no layered attributes.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],275
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0xc0010578
    jne failed
    ; Positioning invalidates the window. Removing WM_PAINT does not validate it.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],122
    mov dword [server_req+12],1
    mov eax,[test_window]
    mov [server_req+16],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+12],0xf
    jne failed
    cmp dword [server_req+32],6 ; Wine MSG_POSTED, not MSG_OTHER_PROCESS
    jne failed
    ; An undersized region reply must preserve the damage for retry.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],163
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+20],15
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0x80000005
    jne failed
    cmp dword [server_req+16],16
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],163
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+20],15
    mov dword [server_req+8],16
    mov dword [server_req+68],window_region
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    test dword [server_req+12],4
    jz failed
    cmp dword [server_req+16],16
    jne failed
    cmp dword [window_region],10
    jne failed
    cmp dword [window_region+12],220
    jne failed
    ; BeginPaint-style validation clears pending paint.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],163
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+20],0x4f
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+12],0
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],126
    mov eax,[test_window]
    mov [server_req+12],eax
    mov dword [server_req+16],0x113
    mov dword [server_req+20],1
    mov dword [server_req+24],0x44
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0x44
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],188
    mov eax,[fs:0x24]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0
    je failed
    cmp dword [server_req+16],0
    je failed
    push delay_timeout
    push 0
    call NtDelayExecution
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],122
    mov dword [server_req+12],1
    mov eax,[test_window]
    mov [server_req+16],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[test_window]
    cmp [server_req+8],eax
    jne failed
    cmp dword [server_req+16],0x44
    jne failed
    cmp dword [server_req+32],6
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],143
    mov eax,[test_window]
    mov [server_req+12],eax
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    ; Destroying the active window clears the input queue's handle.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],194
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],204
    mov dword [server_req+12],0x8002
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    ; Cursor clipping applies to positions and releases back to the desktop.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],279
    mov dword [server_req+12],12
    mov dword [server_req+24],100
    mov dword [server_req+28],0
    mov dword [server_req+32],10
    mov dword [server_req+36],20
    mov dword [server_req+40],50
    mov dword [server_req+44],60
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+24],49
    jne failed
    cmp dword [server_req+28],20
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],279
    mov dword [server_req+12],20
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+40],640
    jne failed
    cmp dword [server_req+44],480
    jne failed
    ; Window properties retain full-width data and accept Win16 handles.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],166
    mov eax,esi
    mov [server_req+12],eax
    mov dword [server_req+16],0x12345678
    mov dword [server_req+20],0xabcdef01
    mov dword [server_req+24],0x1234
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],168
    mov eax,esi
    and eax,0xffff
    mov [server_req+12],eax
    mov dword [server_req+16],0x1234
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0x12345678
    jne failed
    cmp dword [server_req+12],0xabcdef01
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],167
    mov eax,esi
    mov [server_req+12],eax
    mov dword [server_req+16],0x1234
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0x12345678
    jne failed
    cmp dword [server_req+12],0xabcdef01
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],168
    mov eax,esi
    and eax,0xffff
    mov [server_req+12],eax
    mov dword [server_req+16],0x1234
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],0
    jne failed
    cmp dword [server_req+12],0
    jne failed
    ; A stale generation must not resolve to a live root window.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],168
    mov eax,esi
    xor eax,0x10000
    add eax,0x20000
    mov [server_req+12],eax
    mov dword [server_req+16],0x1234
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0xc0010578
    jne failed
    ; Client-owned USER handles have a type and generation, and cannot be freed twice.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],277
    mov word [server_req+12],2
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov esi,[server_req+8]
    mov ecx,esi
    and ecx,0xffff
    sub ecx,0x20
    shl ecx,4
    add ecx,[session_base]
    mov eax,[fs:0x24]
    cmp [ecx+8],eax
    jne failed
    mov eax,esi
    and eax,0xffff0000
    or eax,2
    cmp [ecx+24],eax
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],278
    mov word [server_req+12],2
    mov [server_req+16],esi
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],278
    mov word [server_req+12],2
    mov [server_req+16],esi
    push server_req
    call wine_server_call
    add esp,4
    cmp eax,0xc0000008
    jne failed
    ; Apps cannot make the kernel's session view writable.
    push old_protection
    push 4
    push session_size
    push session_base
    push -1
    call NtProtectVirtualMemory
    test eax, eax
    jz failed
    push dword [session_base]
    push -1
    call NtUnmapViewOfSection
    test eax, eax
    jnz failed
    push dword [session_base]
    push -1
    call NtUnmapViewOfSection
    cmp eax, 0xc0000019
    jne failed
    ; Synchronous file lifecycle: create/write/seek/read/truncate/flush.
    mov byte [failure_stage], 'f'
    push 0
    push 0
    push 0x60
    push 5
    push 3
    push 0
    push 0
    push file_io
    push write_attrs
    push 0xc0100000
    push write_handle
    call NtCreateFile
    test eax,eax
    jnz failed
    push 0
    push 0
    push 4
    push write_payload
    push file_io
    push 0
    push 0
    push 0
    push dword [write_handle]
    call NtWriteFile
    test eax,eax
    jnz failed
    cmp dword [file_io+4],4
    jne failed
    push 14
    push 8
    push seek_one
    push file_io
    push dword [write_handle]
    call NtSetInformationFile
    test eax,eax
    jnz failed
    push 0
    push 0
    push 3
    push file_buffer
    push file_io
    push 0
    push 0
    push 0
    push dword [write_handle]
    call NtReadFile
    test eax,eax
    jnz failed
    cmp dword [file_io+4],3
    jne failed
    cmp word [file_buffer],0x6362
    jne failed
    cmp byte [file_buffer+2],0x64
    jne failed
    push 20
    push 8
    push size_two
    push file_io
    push dword [write_handle]
    call NtSetInformationFile
    test eax,eax
    jnz failed
    push 5
    push 24
    push file_buffer
    push file_io
    push dword [write_handle]
    call NtQueryInformationFile
    test eax,eax
    jnz failed
    cmp dword [file_buffer+8],2
    jne failed
    push file_io
    push dword [write_handle]
    call NtFlushBuffersFile
    test eax,eax
    jnz failed
    push dword [write_handle]
    call NtClose
    test eax,eax
    jnz failed
    ; USER timers wake the queue and survive a peek until removed.
    mov byte [failure_stage], 'q'
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],113
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    mov [queue_handle],eax
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],116
    mov dword [server_req+12],0x10
    mov dword [server_req+16],0x10
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],126
    mov dword [server_req+16],0x113
    mov dword [server_req+20],50
    mov dword [server_req+32],0x12345678
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov esi,[server_req+8]
    test esi,esi
    jz failed
    push queue_timeout
    push 0
    push dword [queue_handle]
    call NtWaitForSingleObject
    test eax,eax
    jnz failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],122
    mov dword [server_req+12],0
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+12],0x113
    jne failed
    cmp dword [server_req+16],esi
    jne failed
    cmp dword [server_req+24],0x12345678
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],122
    mov dword [server_req+12],0
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+12],0x113
    jne failed
    cmp dword [server_req+16],esi
    jne failed
    cmp dword [server_req+24],0x12345678
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],122
    mov dword [server_req+12],1
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+12],0x113
    jne failed
    cmp dword [server_req+16],esi
    jne failed
    cmp dword [server_req+24],0x12345678
    jne failed
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],127
    mov [server_req+16],esi
    mov dword [server_req+24],0x113
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    push zero_timeout
    push 0
    push dword [queue_handle]
    call NtWaitForSingleObject
    cmp eax,0x102
    jne failed
    mov byte [failure_stage], 'F'
    push 0x60
    push 3
    push file_io
    push file_attrs
    push 0x80100000
    push file_handle
    call NtOpenFile
    test eax, eax
    jnz failed
    mov byte [failure_stage], 'G'
    push dword [file_handle]
    push 0x8000000
    push 2
    push 0
    push 0
    push 5
    push mapped_file_handle
    call NtCreateSection
    test eax,eax
    jnz failed
    push 2
    push 0
    push 1
    push mapped_file_size
    push 0
    push 0
    push 0
    push mapped_file_base
    push -1
    push dword [mapped_file_handle]
    call NtMapViewOfSection
    test eax,eax
    jnz failed
    push dword [mapped_file_handle]
    call NtClose
    test eax,eax
    jnz failed
    push written
    push 28
    push memory_info
    push 0
    push dword [mapped_file_base]
    push -1
    call NtQueryVirtualMemory
    test eax,eax
    jnz failed
    cmp dword [memory_info+16],0x1000
    jne failed
    cmp dword [memory_info+20],2
    jne failed
    cmp dword [memory_info+24],0x40000
    jne failed
    mov eax,[mapped_file_base]
    cmp word [eax],0x5a4d
    jne failed
    push eax
    push -1
    call NtUnmapViewOfSection
    test eax,eax
    jnz failed
    push dword [mapped_file_base]
    push -1
    call NtUnmapViewOfSection
    cmp eax,0xc0000019
    jne failed

    ; The loader maps PE sections by RVA, queries image metadata and relocates
    ; in Wine. This mapping must remain independent of the original NTDLL.
    mov dword [mapped_file_base],0
    mov dword [mapped_file_size],0
    push dword [file_handle]
    push 0x1000000
    push 0x20
    push 0
    push 0
    push 13
    push mapped_file_handle
    call NtCreateSection
    test eax,eax
    jnz failed
    push written
    push 48
    push image_info
    push 1
    push dword [mapped_file_handle]
    call NtQuerySection
    test eax,eax
    jnz failed
    cmp word [image_info+32],0x14c
    jne failed
    push 0x20
    push 0
    push 1
    push mapped_file_size
    push 0
    push 0
    push 0
    push mapped_file_base
    push -1
    push dword [mapped_file_handle]
    call NtMapViewOfSection
    test eax,eax
    js failed
    push written
    push 28
    push memory_info
    push 0
    push dword [mapped_file_base]
    push -1
    call NtQueryVirtualMemory
    test eax,eax
    jnz failed
    cmp dword [memory_info+24],0x1000000
    jne failed
    mov eax,[mapped_file_base]
    mov ecx,[eax+0x3c]
    cmp dword [eax+ecx],0x4550
    jne failed
    push dword [mapped_file_handle]
    call NtClose
    test eax,eax
    jnz failed
    push dword [mapped_file_base]
    push -1
    call NtUnmapViewOfSection
    test eax,eax
    jnz failed

    push 0
    push file_offset
    push 2
    push file_bytes
    push file_io
    push 0
    push 0
    push 0
    push dword [file_handle]
    call NtReadFile
    test eax, eax
    jnz failed
    cmp word [file_bytes], 0x5a4d
    jne failed
    cmp dword [file_io+4], 2
    jne failed
    mov byte [failure_stage], 'H'
    push 14
    push 8
    push file_position
    push file_io
    push dword [file_handle]
    call NtQueryInformationFile
    test eax, eax
    jnz failed
    cmp dword [file_position], 2
    jne failed
    push dword [file_handle]
    call NtClose
    test eax, eax
    jnz failed
    push dword [file_handle]
    call NtClose
    cmp eax, 0xc0000008
    jne failed
    ; USER registered-message atoms use their own namespace, and are strings
    ; even when their spelling resembles an integer atom.
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],111
    mov dword [server_req+4],8
    mov dword [server_req+64],1
    mov dword [server_req+72],user_atom_name
    mov dword [server_req+76],8
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    mov eax,[server_req+8]
    cmp eax,0xc000
    jb failed
    mov [user_atom],eax
    push 112
    push server_req
    call RtlZeroMemory
    mov dword [server_req],112
    mov eax,[user_atom]
    mov [server_req+12],eax
    mov dword [server_req+8],4
    mov dword [server_req+68],atom_info
    push server_req
    call wine_server_call
    add esp,4
    test eax,eax
    jnz failed
    cmp dword [server_req+8],8
    jne failed
    cmp dword [server_req+4],4
    jne failed
    cmp dword [atom_info],0x00310023
    jne failed
    ; Atom names share a case-insensitive, reference-counted namespace.
    mov byte [failure_stage], 'A'
    push atom_first
    push 10
    push atom_name
    call NtAddAtom
    test eax, eax
    jnz failed
    push atom_second
    push 10
    push atom_lower
    call NtAddAtom
    test eax, eax
    jnz failed
    movzx eax, word [atom_first]
    cmp ax, [atom_second]
    jne failed
    push written
    push 32
    push atom_info
    push 0
    push eax
    call NtQueryInformationAtom
    test eax, eax
    jnz failed
    cmp word [atom_info], 2
    jne failed
    cmp word [atom_info+4], 10
    jne failed
    cmp dword [written], 18
    jne failed
    movzx eax, word [atom_first]
    push eax
    call NtDeleteAtom
    test eax, eax
    jnz failed
    push atom_second
    push 10
    push atom_lower
    call NtFindAtom
    test eax, eax
    jnz failed
    movzx eax, word [atom_second]
    push eax
    call NtDeleteAtom
    test eax, eax
    jnz failed
    push atom_second
    push 10
    push atom_lower
    call NtFindAtom
    cmp eax, 0xc0000034
    jne failed
    mov byte [failure_stage], 'D'
    push dir_info
    push dir_attrs
    call NtQueryAttributesFile
    test eax,eax
    jnz failed
    test dword [dir_info+32],0x10
    jz failed
    push dir_info
    push file_attrs
    call NtQueryFullAttributesFile
    test eax,eax
    jnz failed
    cmp dword [dir_info+40],0
    je failed
    test dword [dir_info+48],0x10
    jnz failed

    push 0x21
    push 7
    push file_io
    push dir_attrs
    push 0x100001
    push file_handle
    call NtOpenFile
    test eax, eax
    jnz failed
    push 1
    push dir_mask
    call query_directory
    test eax, eax
    jnz failed
    cmp dword [dir_info+8], 18
    jne failed
    cmp dword [file_io+4], 30
    jne failed
    push 0
    push 0
    call query_directory
    cmp eax, 0x80000006
    jne failed
    ; Restart retains the original case-insensitive search mask.
    push 1
    push 0
    call query_directory
    test eax, eax
    jnz failed
    push dword [file_handle]
    call NtClose
    test eax, eax
    jnz failed
    mov byte [failure_stage], 'E'
    push 0
    push 0
    push 0
    push 0x1f0003
    push event_handle
    call NtCreateEvent
    test eax, eax
    jnz failed
    push written
    push dword [event_handle]
    call NtSetEvent
    test eax, eax
    jnz failed
    cmp dword [written], 0
    jne failed
    push written
    push 8
    push event_info
    push 0
    push dword [event_handle]
    call NtQueryEvent
    test eax, eax
    jnz failed
    cmp dword [event_info], 0
    jne failed
    cmp dword [event_info+4], 1
    jne failed
    push written
    push dword [event_handle]
    call NtResetEvent
    test eax, eax
    jnz failed
    cmp dword [written], 1
    jne failed
    push timeout_zero
    push 0
    push dword [event_handle]
    call NtWaitForSingleObject
    cmp eax,0x102
    jne failed
    push 0
    push before_wait
    call NtQueryPerformanceCounter
    test eax,eax
    jnz failed
    push timeout_short
    push 0
    push dword [event_handle]
    call NtWaitForSingleObject
    cmp eax,0x102
    jne failed
    push 0
    push clock_value
    call NtQueryPerformanceCounter
    test eax,eax
    jnz failed
    mov eax,[clock_value]
    mov edx,[clock_value+4]
    sub eax,[before_wait]
    sbb edx,[before_wait+4]
    test edx,edx
    jnz .wait_elapsed
    cmp eax,100000
    jb failed
.wait_elapsed:
    push 0
    push dword [event_handle]
    call NtSetEvent
    test eax,eax
    jnz failed
    push 0
    push 0
    push dword [event_handle]
    call NtWaitForSingleObject
    test eax,eax
    jnz failed
    push dword [event_handle]
    call NtClose
    test eax, eax
    jnz failed
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
    ; Deliver a real #GP through Wine SEH, then resume the saved context.
    mov byte [failure_stage], 'X'
    fld1
    push exception_handler
    push dword [fs:0]
    mov [fs:0],esp
    mov eax,0xffff
exception_fault:
    mov es,ax
    jmp failed
exception_resumed:
    cmp eax,0x31415926
    jne failed
    pop dword [fs:0]
    add esp,4
    cmp dword [exception_seen],1
    jne failed
    fstp dword [exception_float]
    cmp dword [exception_float],0x3f800000
    jne failed
    mov byte [failure_stage], 'T'
    mov eax,[fs:0x24]
    mov [parent_tid],eax
    ; Alerts are sticky and coalesce, even before a wait starts.
    push eax
    call NtAlertThreadByThreadId
    test eax,eax
    jnz failed
    push dword [parent_tid]
    call NtAlertThreadByThreadId
    test eax,eax
    jnz failed
    push alert_zero
    push 0
    call NtWaitForAlertByThreadId
    cmp eax,0x101
    jne failed
    push alert_zero
    push 0
    call NtWaitForAlertByThreadId
    cmp eax,0x102
    jne failed
    push 0xffffffff
    call NtAlertThreadByThreadId
    cmp eax,0xc000000b
    jne failed
    mov eax,[fs:0x18]
    mov [parent_teb],eax
    mov dword [fs:0x34],0x12345678
    push 0
    push 0
    push 0
    push 0
    push 1
    push 0xabcdef
    push thread_worker
    push -1
    push 0
    push 0x1fffff
    push worker_handle
    call NtCreateThreadEx
    test eax,eax
    jnz failed
    cmp dword [worker_ran],0
    jne failed
    push previous_suspend
    push dword [worker_handle]
    call NtResumeThread
    test eax,eax
    jnz failed
    cmp dword [previous_suspend],1
    jne failed
    ; The worker alerts us after yielding; this wait must park and resume.
    push worker_timeout
    push 0
    call NtWaitForAlertByThreadId
    cmp eax,0x101
    jne failed
    push worker_timeout
    push 0
    push dword [worker_handle]
    call NtWaitForSingleObject
    test eax,eax
    jnz failed
    cmp dword [worker_ran],0xabcdef
    jne failed
    mov eax,[fs:0x18]
    cmp eax,[parent_teb]
    jne failed
    cmp dword [fs:0x34],0x12345678
    jne failed
    push 0
    push 28
    push worker_info
    push 0
    push dword [worker_handle]
    call NtQueryInformationThread
    test eax,eax
    jnz failed
    cmp dword [worker_info],42
    jne failed
    mov eax,[worker_info+4]
    cmp eax,[worker_teb]
    jne failed
    push dword [worker_handle]
    call NtClose
    test eax,eax
    jnz failed
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
exception_handler:
    fninit ; The interrupted FPU state must survive handler work.
    mov eax,[esp+4]
    cmp dword [eax],0xc0000005
    jne failed
    mov eax,[esp+12]
    cmp dword [eax+184],exception_fault
    jne failed
    mov dword [eax+184],exception_resumed
    mov dword [eax+176],0x31415926
    mov dword [exception_seen],1
    xor eax,eax
    ret

thread_worker:
    mov eax,[fs:0x18]
    cmp eax,[parent_teb]
    je failed
    cmp dword [fs:0x34],0
    jne failed
    mov [worker_teb],eax
    mov dword [fs:0x34],0xfedcba98
    mov eax,[esp+4]
    mov [worker_ran],eax
    ; Exercise scheduling while the new thread owns its TEB.
    push delay_timeout
    push 0
    call NtDelayExecution
    cmp dword [fs:0x34],0xfedcba98
    jne failed
    push dword [parent_tid]
    call NtAlertThreadByThreadId
    test eax,eax
    jnz failed
    mov eax,42
    ret 4

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
failure db 'NTDLL FAIL stage '
failure_stage db '0', 13, 10
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
process_info resd 6
nls_size resd 2
nls_base resd 1
locale_id resd 1
expected_locale resd 1

section .rdata
debug_scratch: times 1000 db 0x58
    db 0

section .data
align 4
reg_handle: dd 0
reg_value: dd 0x12345678
reg_result: times 16 db 0
reg_attributes: dd 24, 0, reg_path, 0x40, 0, 0
reg_link_attributes: dd 24,0,reg_link_path,0x40,0,0
reg_link_path: dw reg_link_end-reg_link_text,reg_link_end-reg_link_text
    dd reg_link_text
reg_link_text: dw __utf16__('\Registry\Machine\RetroOSProbeLink')
reg_link_end:
reg_link_value: dw 34,34
    dd reg_link_value_text
reg_link_value_text: dw __utf16__('SymbolicLinkValue')
reg_link_handle: dd 0
reg_link_target: dd 0
reg_path: dw reg_path_end-reg_path_text, reg_path_end-reg_path_text
    dd reg_path_text
reg_path_text: dw __utf16__('\Registry\Machine\RetroOSProbe')
reg_path_end:
reg_name: dw 10, 10
    dd reg_name_text
reg_name_text: dw __utf16__('Value')

section .bss
alignb 8
ldt_copy: resb 65536
token_info: resb 36
alignb 8
clock_value: resq 1
clock_frequency: resq 1

section .data
tls_index: dd 1
old_protection: dd 0

section .data
file_attrs: dd 24, 0, file_name, 0x40, 0, 0
file_name: dw file_path_end-file_path, file_path_end-file_path
 dd file_path
file_path: dw __utf16__('\??\C:\RETROOS\WINDOWS\SYSTEM32\NTDLL.DLL')
file_path_end:
file_handle: dd 0
file_io: dd 0,0
file_offset: dq 0
file_position: dq 0
file_bytes: dd 0
event_handle: dd 0
event_info: dd 0,0

section .data
session_attrs: dd 24,0,session_name,0,0,0
session_name: dw session_path_end-session_path, session_path_end-session_path
 dd session_path
session_path: dw __utf16__('\KernelObjects\__wine_session')
session_path_end:
session_handle: dd 0
session_base: dd 0
session_size: dd 0

section .data
align 8
server_req: times 112 db 0
station_handle: dd 0
desktop_handle: dd 0
desktop_offset: dq 0
station_name: dw __utf16__('RetroOSProbeStation')
station_name_end:
desktop_name: dw __utf16__('Default')
desktop_name_end:

section .data
class_id: dq 0
class_offset: dq 0
class_map_offset: dq 0
class_view_base: dd 0
class_view_size: dd 0

section .data
atom_first: dw 0
atom_second: dw 0
atom_name: dw __utf16__('Probe')
user_atom_name: dw __utf16__('#123')
user_atom: dd 0
atom_lower: dw __utf16__('probe')
align 4
atom_info: times 32 db 0

section .text
query_directory:
    pop edx
    pop eax
    pop ecx
    push edx
    push ecx
    push eax
    push 1
    push 12
    push 1024
    push dir_info
    push file_io
    push 0
    push 0
    push 0
    push dword [file_handle]
    call NtQueryDirectoryFile
    ret
section .data
dir_attrs: dd 24,0,dir_name,0x40,0,0
dir_name: dw dir_path_end-dir_path,dir_path_end-dir_path
 dd dir_path
dir_path: dw __utf16__('\??\C:\RETROOS\WINDOWS\SYSTEM32')
dir_path_end:
dir_mask: dw 18,18
 dd dir_filter
dir_filter: dw __utf16__('ntdll.dll')
dir_info: times 1024 db 0

section .data
mapped_file_handle: dd 0
mapped_file_base: dd 0
mapped_file_size: dd 0

section .data
memory_info: times 28 db 0

section .data
align 8
timeout_zero: dq 0
timeout_short: dq -100000
before_wait: dq 0

section .data
image_info: times 48 db 0

section .data
message_class_name: dw __utf16__("Message")

section .text
callback_outer:
    sub esp,12
    lea eax,[esp+4]
    push eax
    lea eax,[esp+4]
    push eax
    push 0
    push 0
    push 1
    call RetroUserCallback
    cmp eax,0x234
    jne failed
    cmp dword [esp+4],4
    jne failed
    mov eax,[esp]
    cmp dword [eax],0xcafebabe
    jne failed
    mov dword [esp+8],0xdeadbeef
    lea eax,[esp+8]
    push 0x123
    push 4
    push eax
    call NtCallbackReturn
    jmp failed
callback_inner:
    push 0xcafebabe
    mov eax,esp
    push 0x234
    push 4
    push eax
    call NtCallbackReturn
    jmp failed
callback_normal:
    mov eax,0x456
    ret 8
section .data
callback_table: dd callback_outer,callback_inner,callback_normal
callback_size: dd 0
callback_result: dd 0

section .data
write_handle: dd 0
write_attrs: dd 24,0,write_name,0x40,0,0
write_name: dw write_path_end-write_path,write_path_end-write_path
    dd write_path
write_path: dw __utf16__('\??\C:\IO.TMP')
write_path_end:
write_payload: db 'abcd'
seek_one: dq 1
size_two: dq 2
file_buffer: times 32 db 0

section .data
sem_handle: dd 0
mutant_handle: dd 0
sync_info: dd 0,0
zero_timeout: dq 0
delay_timeout: dq -100000

section .data
desktop_region: dd 0,0,0,0

section .data
registry_info: times 64 db 0

section .data
queue_handle: dd 0
queue_timeout: dq -10000000

section .data
test_window:dd 0
foreground_id:dd 0
window_list:times 4 dd 0

section .data
relative_path:dw __utf16__('REL.DAT'),0
expected_full_path:dw __utf16__('C:\PROBE\REL.DAT')
expected_full_path_end:
full_path_buffer:times 64 dw 0

section .data
window_region:times 4 dd 0
test_shape:dd 5,6,20,30
test_title:dw 0x0043,0x00e9,0x6c34,0xffff
graphics_screen: times 3 dd 0
graphics_params: dd 0,10,20,2,1,graphics_pixels,0,0,2,1,1,0
graphics_pixels: dd 0xff0000,0x0000ff

section .data
worker_handle: dd 0
parent_teb: dd 0
parent_tid: dd 0
alert_zero: dq 0
worker_teb: dd 0
worker_ran: dd 0
previous_suspend: dd 0
worker_info: times 7 dd 0
worker_timeout: dq -50000000

section .data
exception_seen: dd 0

section .data
exception_float: dd 0
