/* Both halves of the x86-64-only SIMD registers must survive a thread switch. */
static unsigned char stack[65536] __attribute__((aligned(16),used));
__asm__(
".section .rodata\n"
"parent_pattern: .quad 0x1122334455667788,0x99aabbccddeeff00\n"
"child_pattern: .quad 0x8899aabbccddeeff,0x0011223344556677\n"
".text\n.global _start\n_start:\n"
"mov $56,%eax\nmov $0x10f00,%edi\nlea stack+65536(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\nxor %r8d,%r8d\nsyscall\n"
"test %rax,%rax\njs failure\njz child\nlea parent_pattern(%rip),%r12\njmp run\n"
"child: lea child_pattern(%rip),%r12\n"
"run: movdqu (%r12),%xmm8\nmovdqu (%r12),%xmm15\nmov $30,%r13d\n"
"again: mov $24,%eax\nsyscall\n"
"movdqu (%r12),%xmm0\npcmpeqb %xmm8,%xmm0\npmovmskb %xmm0,%eax\ncmp $65535,%eax\njne failure\n"
"movdqu (%r12),%xmm0\npcmpeqb %xmm15,%xmm0\npmovmskb %xmm0,%eax\ncmp $65535,%eax\njne failure\n"
"dec %r13d\njnz again\nxor %edi,%edi\nmov $60,%eax\nsyscall\n"
"failure: mov $71,%edi\nmov $231,%eax\nsyscall\nud2\n");
