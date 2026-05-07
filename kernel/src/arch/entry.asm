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
extern KERNEL_STACK_TOP    ; top of kernel stack (kernel.ld)
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

    ; Set kernel stack (linked address — works through offset segment).
    ; KERNEL_STACK_TOP is a linker symbol at the high end of the stack.
    mov esp, KERNEL_STACK_TOP
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

; =============================================================================
; Mode-agnostic entry: int_vector + common_dispatch. Every instruction below
; has the same encoding under 32-bit and 64-bit CS, so the same table serves
; both IDT32 and IDT64. CS low byte distinguishes 0x08 vs 0x10.
; =============================================================================

; -----------------------------------------------------------------------------
; Unified interrupt vector table.
; Each entry is 8 bytes (aligned), pushes interrupt number and jumps to
; common_dispatch. Vectors 0-127 push imm8 (positive, 2 bytes). Vectors
; 128-255 push imm8 with negative value (sign-extended by CPU); handler
; masks with & 0xFF.
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

common_dispatch_no_err:
    push dword [esp]        ; dup int_num as err_code slot
common_dispatch:
    push eax
    mov eax, cs             ; 2-byte form (no 66 prefix) — clobbers eax, pop restores
    cmp al, 0x10
    pop eax                 ; doesn't touch flags
    je entry_wrapper_64
    ; fall through to entry_wrapper_32

; =============================================================================
; 32-bit-only code: entry_wrapper_32, common_call, exit_interrupt_32
;
; Stack layout matches `Raw32` in arch/traps.rs (216 bytes total):
;   [low ↑]  gs, fs, es, ds                            (4 segs as u32)
;            edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax  (pushad order)
;            <140 bytes of pad — fills the slots Regs uses for r8..r15
;             and the high halves of segs/GP; left uninitialized>
;            int_num, err_code                         (sw-pushed)
;            eip, cs, eflags, esp, ss                  (CPU-pushed IRET)
;
; VM86 segs (CPU-pushed only when EFLAGS.VM=1) sit just past the Raw32 slot
; and are accessed by Rust via `vm86_segs_after()` — not part of the struct.
; =============================================================================

entry_wrapper_32:
    ; CPU pushed (lowest-up): err_code (or none), eip, cs, eflags
    ; cross-priv adds: esp, ss; VM86 adds: es, ds, fs, gs.
    ; int_vector pushed int_num; common_dispatch[_no_err] ensured an
    ; err_code slot above it (either real or duplicated int_num).

    ; Allocate the 140-byte pad. Asm-32 pushes natively below; the upper
    ; portion of Raw32 (where Regs would put r8..r15) sits here unused.
    sub esp, 140
    ; Save 8 GP regs in pushad order: edi (low addr) ... eax (high).
    pushad
    ; Save segment regs as u32 selectors. Order on stack: gs at lowest.
    push ds
    push es
    push fs
    push gs
    ; ESP now points at offset 0 of Raw32 (= gs).

    xor ebx, ebx                  ; ebx = from_64 = false
    jmp common_call

; -----------------------------------------------------------------------------
; common_call: shared dispatch tail. Caller has:
;   - pushed StackFrame (216B) — its own native form (Raw32 or Regs)
;   - set ebx = from_64 flag
;
; ebp is left untouched between trap entry and `call isr_handler`. For ring-1
; entries the trapped ebp is a valid C frame pointer, and Rust's prologue
; saves it as `isr_handler`'s prev_ebp -- the stack-trace walker can then
; chain naturally from a panic into the ring-1 call site. For ring-0 / ring-3
; / VM86 the trapped ebp is junk-or-untrusted; the walker stops at the
; `isr_return` boundary (see stacktrace.rs) and uses regs.rip explicitly.
; -----------------------------------------------------------------------------
common_call:
    cld
    ; Set kernel data selectors. SS *must* be reloaded before any push: on
    ; the 64→32 path the same-privilege long-mode interrupt clears SS.
    mov eax, 0x18
    mov ss, eax
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax

    ; Call isr_handler(stack_ptr, from_64). cdecl: args right-to-left.
    push ebx                      ; from_64
    lea eax, [esp + 4]             ; ptr to StackFrame (skip from_64 we just pushed)
    push eax                      ; stack_ptr
    call isr_handler
    add esp, 8                    ; pop args

global isr_return
isr_return:
    ; AL = 1 → long-mode exit; AL = 0 → 32-bit exit.
    test al, al
    jz exit_interrupt_32
    ; Direct far jmp 0x10:offset is valid in 32-bit; CPU zero-extends offset
    ; to RIP. Reaches exit_interrupt_64 in 64-bit code seg.
    jmp 0x10:exit_interrupt_64

exit_interrupt_32:
    ; ESP at Raw32 offset 0. Pop in reverse of entry_wrapper_32.
    pop gs
    pop fs
    pop es
    pop ds
    popad
    add esp, 140                ; skip pad
    add esp, 8                  ; skip int_num + err_code
    iret                        ; CPU pops eip, cs, eflags [, esp, ss [, vm86 segs]]

; =============================================================================
; 64-bit-only code: long-mode interrupt entry, SYSCALL
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

    xor rax, rax
    mov ax, ds
    push rax
    mov ax, es
    push rax

    ; FS/GS save format depends on user mode (long-mode IDT routes both
    ; 64-bit users and 32-bit-compat users through here):
    ;   - 64-bit user (cs=0x33): the meaningful state is the FS_BASE /
    ;     GS_BASE MSRs (selectors are typically null and unused). rdmsr
    ;     them and push the 64-bit bases.
    ;   - 32-bit user (cs=0x23) / compat: TLS rides on the descriptor
    ;     loaded via `mov fs/gs, sel`, so push the selectors.
    ; User CS sits at [rsp + 168]: 16 bytes (es+ds we just pushed) + 64
    ; bytes (r8..r15) + 64 bytes (rax..rdi) + 16 bytes (int_num+err_code)
    ; below the trap-pushed `cs` slot.
    cmp qword [rsp + 168], 0x33
    jne .save_segs_32

    mov ecx, 0xC0000100         ; IA32_FS_BASE
    rdmsr
    shl rdx, 32
    or rax, rdx
    push rax
    mov ecx, 0xC0000101         ; IA32_GS_BASE
    rdmsr
    shl rdx, 32
    or rax, rdx
    push rax
    jmp .save_segs_done
.save_segs_32:
    xor rax, rax
    mov ax, fs
    push rax
    mov ax, gs
    push rax
.save_segs_done:

    ; rbp is left untouched -- see common_call's comment for why.

    ; Tell common_call we entered via the 64-bit path (from_64 = 1).
    mov ebx, 1

    ; Far jump to 32-bit common_call (indirect via memory; direct far jmp
    ; is invalid in long mode).
    jmp far [rel far_ptr_32]

exit_interrupt_64:
    ; Restore FS/GS in the inverse format chosen on entry. CS sits at
    ; [rsp + 184] = 16 (gs+fs) + 16 (es+ds) + 64 (r8..r15) + 64 (rax..rdi)
    ; + 16 (int_num+err_code) below the trap-pushed cs slot. wrmsr in 64-
    ; bit code (here, before `mov ds/es`) so a same-CPL `mov fs/gs, sel`
    ; in compat mode can never undo it.
    cmp qword [rsp + 184], 0x33
    jne .rest_segs_32

    pop rax                     ; saved GS_BASE
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000101
    wrmsr
    pop rax                     ; saved FS_BASE
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000100
    wrmsr
    jmp .rest_segs_done
.rest_segs_32:
    pop rax                     ; saved gs selector
    mov gs, ax
    pop rax                     ; saved fs selector
    mov fs, ax
.rest_segs_done:
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

    ; int_num / err_code (match interrupt vector layout). int_num = 256
    ; (out of the 0..255 IDT range) so `isr_handler` can distinguish a
    ; SYSCALL instruction from an `INT 0x80` soft interrupt.
    push qword 0               ; err_code
    push qword 256             ; int_num = SYSCALL sentinel

    jmp entry_wrapper_64

; -----------------------------------------------------------------------------
; Far jump pointer — needed only for 64-bit → 32-bit transitions because the
; direct far-jump opcode (EA) is invalid in long mode. The reverse direction
; uses a direct `jmp 0x10:exit_interrupt_64`.
; -----------------------------------------------------------------------------
align 8
far_ptr_32:
    dq common_call          ; 64-bit offset (used from 64-bit mode, m16:64)
    dw 0x08                 ; 32-bit code segment

