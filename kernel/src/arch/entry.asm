; RetroOS Kernel Entry Assembly
; Multiboot header, boot stub, interrupt entry points.
; Supports both 32-bit and 64-bit userspace with unified Regs struct.

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

; Constants from linker script
KERNEL_BASE equ 0xC0B00000
KERNEL_PHYS equ 0x00100000

; External symbols defined in Rust
extern BOOT_GDT            ; boot GDT table (descriptors.rs)
extern KERNEL_STACK        ; kernel stack (lib.rs)
extern boot_kernel         ; Rust entry point (arch/boot.rs)
extern isr_handler         ; ISR dispatcher (arch/traps.rs)
extern SYSCALL_USER_RSP    ; SYSCALL scratch slot (descriptors.rs)
extern SYSCALL_KERNEL_RSP  ; SYSCALL kernel stack (descriptors.rs)

; =============================================================================
; Multiboot header (must be in first 8KB of binary)
; =============================================================================
section .multiboot
align 4
MULTIBOOT_MAGIC  equ 0x1BADB002
MULTIBOOT_FLAGS  equ 0x00000003  ; align modules + provide memory map
MULTIBOOT_CHECK  equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

dd MULTIBOOT_MAGIC
dd MULTIBOOT_FLAGS
dd MULTIBOOT_CHECK

; =============================================================================
; 32-bit code: boot stub, mode toggle, protected-mode entry, ISR dispatch
; =============================================================================
section .text
[bits 32]

; -----------------------------------------------------------------------------
; Boot entry stub — runs at physical address with offset segments
; -----------------------------------------------------------------------------
global _start
_start:
    ; We arrive here from the bootloader with paging off.
    ; ELF was loaded at KERNEL_PHYS but linked at KERNEL_BASE.
    ; BOOT_GDT's segments have base = KERNEL_PHYS - KERNEL_BASE so that
    ; linked addresses (0xC0B0xxxx) access physical memory correctly via
    ; 32-bit wrapping: 0xC0B0xxxx + 0x40600000 = 0x010xxxxx.
    ;
    ; Multiboot hands us: EAX = bootloader magic (0x2BADB002),
    ;                     EBX = physical pointer to multiboot info.
    ; Neither is touched by anything below (we use DX for segment loads),
    ; so we can push them straight into the boot_kernel call.

    ; Load offset GDT — boot_gdtr/BOOT_GDT are at linked addresses,
    ; so we adjust to physical.
    lgdt [boot_gdtr - KERNEL_BASE + KERNEL_PHYS]

    ; Reload segments with offset-based descriptors
    jmp 0x08:.reload_cs
.reload_cs:
    mov dx, 0x10
    mov ds, dx
    mov es, dx
    mov ss, dx
    mov fs, dx
    mov gs, dx

    ; Set kernel stack (linked address — works through offset segment)
    lea esp, [KERNEL_STACK + 32 * 1024]
    xor ebp, ebp

    ; Call boot_kernel(magic, info) — cdecl, push right-to-left
    push ebx            ; arg 2: multiboot info pointer
    push eax            ; arg 1: bootloader magic
    call boot_kernel
    ud2

; -----------------------------------------------------------------------------
; GDTR pointing at BOOT_GDT (defined in descriptors.rs)
; -----------------------------------------------------------------------------
boot_gdtr:
    dw 3 * 8 - 1                              ; limit (3 entries)
    dd BOOT_GDT - KERNEL_BASE + KERNEL_PHYS   ; physical address of GDT

; -----------------------------------------------------------------------------
; toggle_prot_compat — switch between PAE and long/compat mode
; fastcall: ECX = new CR3
;
; Placed early in .text so it lands in the first page (physical KERNEL_PHYS).
; The caller (paging2::ensure_trampoline_mapped) installs an identity PTE
; for that page; we jmp from the virtual linked address to the physical
; address, toggle paging off, flip EFER.LME, load new CR3, re-enable paging,
; then jmp back to the virtual address and return.
; -----------------------------------------------------------------------------
global toggle_prot_compat
toggle_prot_compat:
    jmp .phys - KERNEL_BASE + KERNEL_PHYS
.phys:
    mov eax, cr0
    and eax, ~(1 << 31)
    mov cr0, eax

    mov cr3, ecx

    mov ecx, 0xC0000080
    rdmsr
    xor eax, (1 << 8)
    wrmsr

    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    ret

; -----------------------------------------------------------------------------
; Shared dispatch entered from the unified vector table. Byte sequence is
; mode-agnostic: same encoding under 32-bit and 64-bit CS, so both IDT32 and
; IDT64 can point at `int_vector`. CS low byte distinguishes 0x08 vs 0x10.
; -----------------------------------------------------------------------------
common_dispatch_no_err:
    push dword [esp]        ; dup int_num as err_code slot
common_dispatch:
    push eax
    mov eax, cs             ; 2-byte form (no 66 prefix) — clobbers eax, pop restores
    cmp al, 0x10
    pop eax                 ; doesn't touch flags
    je entry_wrapper_64
    ; fall through to entry_wrapper_32

; -----------------------------------------------------------------------------
; Common 32-bit interrupt entry — saves all registers as 64-bit values
; Stack on entry: [err_code], eip, cs, eflags [, esp, ss]
; int_num was pushed by vector table
; -----------------------------------------------------------------------------

; Macro to push a 32-bit register as 64-bit (with high dword = 0)
%macro push64_32 1
    push dword 0            ; high 32 bits
    push %1                 ; low 32 bits
%endmacro

entry_wrapper_32:
    ; Stack: int_num(32), err_code(32), eip, cs, eflags [, esp, ss]
    ; Need: int_num(64), err_code(64), Frame32._pad(20), eip, ...
    sub esp, 12             ; partial space for padding
    ; Push 64-bit err_code (high=0, low=value)
    push dword 0
    push dword [esp+20]     ; err_code was at ESP+4, now at ESP+20
    ; Push 64-bit int_num (high=0, low=value)
    push dword 0
    push dword [esp+24]     ; int_num was at ESP+0, now at ESP+24
    ; Layout: int_num(64), err_code(64), 12-byte gap, old_int/err(8), eip
    ; Padding between err_code and eip = 12 + 8 = 20 bytes

    ; Save general purpose registers (zero-extended to 64-bit)
    push64_32 eax
    push64_32 ecx
    push64_32 edx
    push64_32 ebx
    push64_32 esp           ; dummy esp
    push64_32 ebp
    push64_32 esi
    push64_32 edi

    ; Push r8-r15 as zeros (not available in 32-bit mode)
    times 8 push dword 0    ; r8 low
    times 8 push dword 0    ; r8 high ... r15 high (8 registers * 8 bytes = 64 bytes total, but need 16 pushes)

    ; Save segment registers (zero-extended to 64-bit)
    xor eax, eax
    mov ax, ds
    push64_32 eax
    mov ax, es
    push64_32 eax
    mov ax, fs
    push64_32 eax
    mov ax, gs
    push64_32 eax

    ; Set all segments to kernel data selector
    mov eax, 0x18           ; kernel data selector
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax

    ; Build 16-byte mock frame: [ebp, eip, 0, 0] — rip==0 signals 32-bit user
    mov eax, esp
    push dword 0
    push dword 0
    push dword [eax + 196]      ; user's eip
    push dword [eax + 112]      ; user's ebp
    mov ebp, esp
    jmp call_isr_handler

exit_interrupt_32:
    ; Restore segment registers (push64_32 stores low at [ESP], high at [ESP+4])
    pop eax                 ; gs low (value)
    mov gs, ax
    add esp, 4              ; skip gs high
    pop eax                 ; fs low (value)
    mov fs, ax
    add esp, 4              ; skip fs high
    pop eax                 ; es low (value)
    mov es, ax
    add esp, 4              ; skip es high
    pop eax                 ; ds low (value)
    mov ds, ax
    add esp, 4              ; skip ds high

    ; Skip r15-r8 (64 bytes = 8 registers * 8 bytes)
    add esp, 64

    ; Restore general purpose registers (skip high dwords)
    pop edi
    add esp, 4              ; skip high dword
    pop esi
    add esp, 4
    pop ebp
    add esp, 4
    add esp, 8              ; skip rsp_dummy
    pop ebx
    add esp, 4
    pop edx
    add esp, 4
    pop ecx
    add esp, 4
    pop eax
    add esp, 4

    ; Skip int_num and err_code (16 bytes total, both 64-bit)
    add esp, 16

    ; Remove frame padding (20 bytes)
    add esp, 20

    ; Return from interrupt (CPU pops eip, cs, eflags [, esp, ss])
    iret

; -----------------------------------------------------------------------------
; Common ISR dispatch — entered from 32-bit entry wrappers and (via the
; 64→32 trampoline) from 64-bit entry wrappers. Dispatches exit based on
; current CPU mode (EFER.LMA).
; Stack: [mock frame 16B] [Regs] [Frame] [VM86 segs]
; EAX = pointer to FullRegs
; -----------------------------------------------------------------------------
call_isr_handler:
    cld
    push eax                ; arg: pointer to FullRegs

    call isr_handler
global isr_return
isr_return:
    add esp, 4              ; clean up arg

    add esp, 16             ; clean up mock frame

    ; Dispatch exit based on cpu-mode (EFER.LMA = long mode active)
    mov ecx, 0xC0000080     ; EFER MSR
    rdmsr
    test eax, (1 << 10)     ; LMA bit
    jnz .exit_long
    jmp exit_interrupt_32
.exit_long:
    ; Direct far jump — valid in 32-bit mode (EA ptr16:32). CS=0x10 is the
    ; 64-bit kernel code segment; CPU zero-extends the 32-bit offset to RIP.
    jmp 0x10:exit_interrupt_64

; -----------------------------------------------------------------------------
; Trampoline for 64-bit → 32-bit transition.
; Reached from 64-bit entry wrappers via `jmp far [rel far_ptr_32]`.
; -----------------------------------------------------------------------------
trampoline_64_to_32:
    ; Now in 32-bit mode, ESP = low 32 bits of RSP (points to Regs)
    ; SS is null (long mode same-privilege interrupt sets SS=0).
    ; Must load a valid 32-bit data segment before any push/pop.
    mov ax, 0x18
    mov ss, ax
    ; Build mock stack frame with full 64-bit rbp/rip values
    ; Offset to Frame64.rip: 32 + 64 + 64 + 16 = 176
    ; Offset to rbp: 112
    ; Build 16-byte mock stack frame (64-bit ebp/eip for stack traces)
    mov eax, esp
    push dword [eax + 180]  ; user's rip high 32
    push dword [eax + 176]  ; user's rip low 32
    push dword [eax + 116]  ; user's rbp high 32
    push dword [eax + 112]  ; user's rbp low 32
    mov ebp, esp
    jmp call_isr_handler

; -----------------------------------------------------------------------------
; Unified interrupt vector table.
; Each entry is 8 bytes (aligned), pushes interrupt number and jumps to
; common_dispatch. `push imm8` and `jmp rel32` have identical encodings in
; 32-bit and 64-bit mode, so the same table serves both IDT32 and IDT64.
; Vectors 0-127 push imm8 (positive, 2 bytes). Vectors 128-255 push imm8
; with negative value (sign-extended by CPU); handler masks with & 0xFF.
; -----------------------------------------------------------------------------
align 64
global int_vector
int_vector:
%assign i 0
%rep 256
    align 8
%if i >= 128
    push i - 256
%else
    push i
%endif
    ; Exceptions that push an error code: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp common_dispatch
%else
    jmp common_dispatch_no_err
%endif
%assign i (i + 1)
%endrep

; =============================================================================
; 64-bit code: long-mode interrupt entry, SYSCALL, vector table
; =============================================================================
[bits 64]

; -----------------------------------------------------------------------------
; Common 64-bit interrupt entry — saves all registers.
; Entered via common_dispatch (below KERNEL_CS64 branch). int_num/err_code
; (both 8 bytes) have already been pushed by the vector table + dispatch.
; -----------------------------------------------------------------------------
entry_wrapper_64:
    ; Stack: int_num, err_code, rip, cs, rflags, rsp, ss (all 64-bit)
    ; Frame64 is 40 bytes, no padding needed (unlike Frame32 which has 20-byte _pad)

    ; Save general purpose registers
    push rax
    push rcx
    push rdx
    push rbx
    push rsp                ; dummy rsp
    push rbp
    push rsi
    push rdi

    ; Save r8-r15
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Save segment registers: DS/ES as selectors, FS/GS as MSR bases (64-bit TLS)
    xor rax, rax
    mov ax, ds
    push rax
    mov ax, es
    push rax
    mov ecx, 0xC0000100     ; FS_BASE MSR
    rdmsr
    shl rdx, 32
    or rax, rdx
    push rax
    mov ecx, 0xC0000101     ; GS_BASE MSR
    rdmsr
    shl rdx, 32
    or rax, rdx
    push rax

    ; Set segments to kernel data selector
    mov ax, 0x18
    mov ds, ax
    mov es, ax

    ; Far jump to 32-bit trampoline (indirect via memory; direct far jmp
    ; is invalid in long mode).
    jmp far [rel far_ptr_32]

exit_interrupt_64:
    ; Restore GS base (MSR 0xC0000101)
    pop rax
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000101
    wrmsr
    ; Restore FS base (MSR 0xC0000100)
    pop rax
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000100
    wrmsr
    ; Restore ES, DS selectors
    pop rax
    mov es, ax
    pop rax
    mov ds, ax

    ; Restore r15-r8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8

    ; Restore general purpose registers
    pop rdi
    pop rsi
    pop rbp
    add rsp, 8              ; skip rsp_dummy
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ; Skip int_num and err_code (16 bytes in 64-bit mode)
    add rsp, 16

    iretq

; -----------------------------------------------------------------------------
; SYSCALL entry (64-bit)
; CPU sets: RCX=user_rip, R11=user_rflags, CS=STAR[47:32], SS=STAR[47:32]+8
; RSP unchanged (still user stack). RCX/R11 clobbered from user's perspective.
; Builds a Regs frame identical to entry_wrapper_64, then joins the same path.
; -----------------------------------------------------------------------------
global syscall_entry_64
syscall_entry_64:
    ; Swap to kernel stack — save user RSP in scratch variable
    mov [rel SYSCALL_USER_RSP], rsp
    mov rsp, [rel SYSCALL_KERNEL_RSP]

    ; Build Frame64: SS, RSP, RFLAGS, CS, RIP (high address → low)
    push qword 0x2B            ; SS  = USER_DS  (0x28 | 3)
    push qword [rel SYSCALL_USER_RSP] ; RSP = user stack pointer
    push r11                    ; RFLAGS (saved by SYSCALL)
    push qword 0x33            ; CS  = USER_CS64 (0x30 | 3)
    push rcx                    ; RIP (saved by SYSCALL)

    ; int_num / err_code (match interrupt vector layout)
    push qword 0               ; err_code
    push qword 0x80            ; int_num = syscall

    jmp entry_wrapper_64

; -----------------------------------------------------------------------------
; Far jump pointer — needed only for 64-bit → 32-bit transitions because the
; direct far-jump opcode (EA) is invalid in long mode. The reverse direction
; uses a direct `jmp 0x10:exit_interrupt_64`.
; -----------------------------------------------------------------------------
align 8
far_ptr_32:
    dq trampoline_64_to_32  ; 64-bit offset (used from 64-bit mode, m16:64)
    dw 0x08                 ; 32-bit code segment

