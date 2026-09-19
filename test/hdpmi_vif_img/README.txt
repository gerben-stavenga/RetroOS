vifiret-hdpmi.img — FreeDOS + HDPMI32I + SETPVI + VIFIRET
=========================================================

A 16 MB bootable HDD image. It is a 32-bit DPMI client at CPL 3 / IOPL 0
with CR4.PVI set. It IRETDs from a 32-bit CS with VIF=0 in the frame.

  PASS        IRETD at CPL>0 did not load VIF (SDM; real CPU; patched 86Box)
  FAIL stage 6  IRETD copied VIF from the stack (unpatched 86Box pmodeiret)

86Box
-----
  Machine:  [Socket 7] ASUS TX97  (or any Pentium-class; not 8086/286)
  CPU:      Intel Pentium, 75 MHz or faster
  Memory:   32 MB or more
  HDD:      vifiret-hdpmi.img on IDE 0:0
            CHS 63 sectors, 16 heads, 32 cylinders  (type=IDE)
  Floppy:   1.44 M empty drive on A: so AMI POST does not hang
  No JEMM/EMM386. The image already loads HIMEMX only.

Boot. The screen should print VIFIRET PASS or VIFIRET FAIL stage N, then
wait for a key.

What it runs
------------
  HDPMI32I.EXE -r -b    Japheth HX DPMI host, clients at IOPL 0
  SETPVI.COM            CR4.PVI from real mode (VSBHDA-style)
  VIFIRET.COM /H        32-bit DPMI client, 32-bit CS IRETD

Rebuild (from the RetroOS tree)
-------------------------------
  bash test/hdpmi_vif_img/make.sh

GitHub
------
  The zip is uploaded as a GitHub Actions artifact named
  vifiret-hdpmi-freedos (workflow "vifiret-freedos-image", 90-day retention).
  After a push, download it from the run's Artifacts section.
