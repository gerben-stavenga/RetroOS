; Minimal Linux i386 ELF — write "Hello from Linux!\n" + exit_group(0)
; Uses INT 0x80 with Linux i386 register conventions:
;   EAX=nr, EBX=a0, ECX=a1, EDX=a2

BITS 32

; ELF header
                org     0x08048000

ehdr:
                db      0x7F, "ELF"             ; e_ident[EI_MAG]
                db      1                       ; EI_CLASS = ELFCLASS32
                db      1                       ; EI_DATA = ELFDATA2LSB
                db      1                       ; EI_VERSION
                db      0                       ; EI_OSABI = ELFOSABI_NONE
                times 8 db 0                    ; padding
                dw      2                       ; e_type = ET_EXEC
                dw      3                       ; e_machine = EM_386
                dd      1                       ; e_version
                dd      _start                  ; e_entry
                dd      phdr - ehdr             ; e_phoff
                dd      0                       ; e_shoff
                dd      0                       ; e_flags
                dw      52                      ; e_ehsize
                dw      32                      ; e_phentsize
                dw      1                       ; e_phnum
                dw      40                      ; e_shentsize
                dw      0                       ; e_shnum
                dw      0                       ; e_shstrndx

phdr:
                dd      1                       ; p_type = PT_LOAD
                dd      0                       ; p_offset
                dd      ehdr                    ; p_vaddr
                dd      ehdr                    ; p_paddr
                dd      file_end - ehdr         ; p_filesz
                dd      file_end - ehdr         ; p_memsz
                dd      5                       ; p_flags = PF_R | PF_X
                dd      0x1000                  ; p_align

_start:
                ; write(1, msg, 18)
                mov     eax, 4                  ; __NR_write
                mov     ebx, 1                  ; fd = stdout
                mov     ecx, msg                ; buf
                mov     edx, msg_len            ; count
                int     0x80

                ; exit_group(0)
                mov     eax, 252                ; __NR_exit_group
                xor     ebx, ebx                ; status = 0
                int     0x80

msg:            db      "Hello from Linux!", 10
msg_len         equ     $ - msg

file_end:
