/* DPMI smoke-test fixture: minimal C source that BCC+TLINK must compile
   and link without crashing the kernel. BCC.EXE runs as a 16-bit DPMI
   client (via its embedded DPMI16BI.OVL loader), so a clean exit here
   means PM->RM->PM cross-mode dispatch + INT 21 simulation in PM all work
   end-to-end. */
#include <stdio.h>

int main(void)
{
    printf("dpmi smoke ok\n");
    return 0;
}
