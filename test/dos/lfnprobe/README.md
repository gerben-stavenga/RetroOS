# DOS long filenames

INT 21h/AH=71h is implemented by `kernel/src/kernel/dos/lfn.rs`, using
the DFS long-name resolver in `dfs_lfn.rs`. VFS stays exact-case regardless
of storage format. DFS matches long names and 8.3 aliases case-insensitively;
it preserves FAT's stored aliases and assigns collision-free aliases on ext4.
Names are exchanged with DOS in CP437 and with VFS in UTF-8. Unrepresentable
names in FindData use underscores and set the Unicode-conversion result bit;
their short aliases remain available.

The call layouts follow [RBIL's Windows 95 LFN interface](https://fd.lod.bz/rbil/interrup/dos_kernel/2171.html).

| AX | Service |
| --- | --- |
| 7139/713A/713B | Make/remove/change directory |
| 7141 | Delete file, including the optional wildcard search |
| 7143 | Get/set DOS attributes; get/set last-write date/time (BL=0,1,3,4) |
| 7147 | Get current directory in long form |
| 714E/714F/71A1 | Independent FindFirst/FindNext/FindClose handles |
| 7156 | Rename/move file or directory within a drive |
| 7160 | Lexical absolute path, short path, and canonical long path (CL=0,1,2) |
| 716C | Extended open/create/replace using ordinary DOS file handles |
| 71A0 | Namespace capabilities and limits: 255-byte component, 260-byte DOS path |
| 71A6 | File information by DOS handle |
| 71A7 | FILETIME/DOS time conversion, including hundredths and the 1980–2107 range |
| 71A8 | Short-name generation without a numeric tail (OEM input/output) |

LFN searches use a separate per-process handle table, not the DTA. Exhaustion
returns an error instead of evicting an active search. Legacy APIs continue
to use short aliases, including when a long-name call changed the directory.
Overlong or unterminated guest names fail rather than being truncated.

## Remaining limits

- DOS attributes are shared session metadata; setters do not yet persist them
  into FAT directory entries or ext4 extended attributes. Existing FAT flags
  are read from disk. DOS read-only is independent of, and cannot relax,
  RetroOS's ext4 group-write grant. Legacy AH=43 and LFN AH=7143 share this view.
- Creation/access timestamps are returned as zero (unsupported). Compressed
  size queries and creation/access timestamp setters return AX=7100h.
- Last-write metadata uses VFS's existing 32-bit Unix seconds; the standalone
  71A7 conversion supports the full DOS time range. No timezone offset is
  configured, so UTC and the DOS clock use the same time base.
- Explicit alias hints, ANSI/UTF-16 variants of 71A8, SUBST, and server-specific
  calls return AX=7100h. The normal 71xx pathname APIs use CP437.
- Ext4 aliases are derived from directory contents, not persisted. Case-only
  rename is not implemented. Underlying storage limits still apply.

## Tests

`python3 test/lfn.py` runs `LFNPROBE.COM` on a fresh writable ext4 image with
the hosted interpreter. It never writes the read-only Bazel artifact.
`python3 test/grub_fat.py` runs the same probe on FAT12, FAT16, and FAT32 GRUB
module roots, including a 32 MiB FAT12 boot. Both are in `test/run_all.sh`.

The probe checks preserved spelling, case-folded lookup, long/short conversion,
legacy opens through aliases, 200-character names, CP437 accents, independent
search handles, stale/closed-handle errors, file information, timestamps,
read-only attributes, rename/delete, and rejection of unterminated input.
