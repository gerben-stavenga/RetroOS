# Showcase commanders

Disk installs read these programs on demand. USB boots load one showcase
module containing all commanders and games by default. Choose “Core only
(less RAM)” in GRUB to omit it. DN remains the startup commander. The directories below live under
`showcase-bundle/COMMANDER/` and appear at `C:\COMMANDER\`.

| Directory | Platform | Entry point |
| --- | --- | --- |
| VC | DOS | VC.COM |
| MC | Windows (Midnight Commander) | MC.EXE |
| RC | Linux x64 | RC.EXE |
| NDN-D32 | DOS | NDN.COM |
| NDN-W32 | Windows | NDN.EXE |
| NDN-O32 | OS/2 | NDN.EXE |
| DN2D214 | DOS | DN.COM |
| DN2W214 | Windows | DN.EXE |
| DN2O214 | OS/2 | DN.EXE |

NDN and the Windows/OS/2 DN/2 distributions were copied intact from the existing
local applications. DOS DN/2 2.14 beta (rev A) comes from the
[FreeDOS package](https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/repositories/1.3/html/en/apps/dn2/20220217.0/index.html);
its source package, checksum and attribution are recorded in `DN2D214/SOURCE.TXT`.
DN/2 is based on Dos Navigator by RIT Research Labs. Original notices and
license terms are preserved with the distributions.

The platform labels identify the packaged executable format; they do not imply
that every application feature has been validated in RetroOS.
