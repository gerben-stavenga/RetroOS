@echo off
rem Compile + run the SB DMA test (TCC on PATH). Mode arg:
rem   SBTEST          (default) single-cycle + Dune2 CLI tick-wait (IF repro)
rem   SBTEST auto     auto-init ring (Doom/Raptor)
rem   SBTEST sing     single-cycle blocks (Dune2 speech)
TCC -mt -lt TESTS\SBTEST.C
SBTEST %1
