; Win16 register-call x87 runtime. Computation stays in the guest FPU.
bits 16
segment _TEXT public class=CODE use16
global __FPMATH
__FPMATH:
    cmp bx, 2
    jbe .init
    cmp bx, 3
    je .handler
    cmp bx, 4
    je .control
    cmp bx, 5
    je .get_control
    cmp bx, 6
    je .round
    cmp bx, 7
    je .integer
    cmp bx, 8
    je .status
    cmp bx, 9
    je .clear
    cmp bx, 11
    je .installed
    mov ax, -1
    mov dx, ax
    retf
.init:
    fninit
    ; Windows runtime default: extended precision, round to nearest.
    push word 0x1332
    push bp
    mov bp, sp
    fldcw [ss:bp+2]
    pop bp
    add sp, 2
.clear:
    fnclex
    xor ax, ax
    retf
.handler:
    ; No software emulator: native x87 instructions handle arithmetic.
    ; Exception callback delivery is not implemented yet.
    retf
.control:
    push ax
    push bp
    mov bp, sp
    fldcw [ss:bp+2]
    pop bp
    add sp, 2
    retf
.get_control:
    push bp
    mov bp, sp
    sub sp, 2
    fnstcw [ss:bp-2]
    mov ax, [ss:bp-2]
    mov sp, bp
    pop bp
    retf
.round:
.integer:
    push bp
    mov bp, sp
    sub sp, 8
    fnstcw [ss:bp-2]
    and ax, 0x0c00
    mov dx, [ss:bp-2]
    and dx, 0xf3ff
    or ax, dx
    mov [ss:bp-4], ax
    fldcw [ss:bp-4]
    cmp bx, 7
    je .pop_integer
    frndint
    mov ax, [ss:bp-2]
    jmp .restore
.pop_integer:
    fistp dword [ss:bp-8]
    mov ax, [ss:bp-8]
    mov dx, [ss:bp-6]
.restore:
    fldcw [ss:bp-2]
    mov sp, bp
    pop bp
    retf
.status:
    fnstsw ax
    and ax, 0x3f
    retf
.installed:
    mov ax, 1
    xor dx, dx
    retf
