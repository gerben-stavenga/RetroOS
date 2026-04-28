#!/usr/bin/env python3
"""Disassemble [STEP] instruction traces from a DPMI log.

Matches lines of the form:
    [STEP]      009F:00000550 op=66556655668BEC66 EAX=... ...   (legacy, --bits decides)
    [STEP RM]   01C4:0000099F op=...              EAX=... ...   (16-bit RM)
    [STEP PM16] 0087:000003AE op=...              EAX=... ...   (16-bit PM client)
    [STEP PM32] 0027:00006F8E op=...              EAX=... ...   (32-bit PM client)

By default emits the trace in execution order (one disasm per step).
With --unique, deduplicates by CS:EIP for a flat code-coverage view.

Each step is decoded with the operand size implied by its tag:
    RM, PM16  → 16-bit operand size
    PM32      → 32-bit operand size
Legacy [STEP] (no tag) follows --bits (default 16).

Usage:
    tools/disasm_step_log.py <logfile> [--start N] [--end N] [--unique] [--out FILE]
"""
import argparse
import re
import sys

import capstone


STEP_RE = re.compile(
    r"^\[STEP(?:\s+(PM16|PM32|PM|RM))?\]\s+([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+op=([0-9A-Fa-f]+)"
)


def extract_steps(path, start, end, unique):
    """Yield (mode, cs, eip_str, eip_int, ophex) per matching line."""
    seen = set()
    with open(path) as f:
        for i, line in enumerate(f, 1):
            if start is not None and i < start:
                continue
            if end is not None and i > end:
                break
            m = STEP_RE.match(line)
            if not m:
                continue
            mode = m.group(1) or ""           # "PM16"/"PM32"/"PM"/"RM"/""
            cs, eip, op = m.group(2), m.group(3), m.group(4)
            if unique:
                key = (cs, eip)
                if key in seen:
                    continue
                seen.add(key)
            yield mode, cs, eip, int(eip, 16), op


def disasm_step(md16, md32, default_bits, mode, eip_val, ophex):
    """Return the first decoded instruction at eip_val."""
    if mode == "PM32":
        md = md32
    elif mode in ("PM16", "RM"):
        md = md16
    elif mode == "PM":
        md = md32 if default_bits == 32 else md16
    else:
        md = md32 if default_bits == 32 else md16
    try:
        data = bytes.fromhex(ophex) + b"\x00" * 8
    except ValueError:
        return f"<bad ophex {ophex!r}>"
    for ins in md.disasm(data, eip_val):
        return f"{ins.mnemonic} {ins.op_str}".strip()
    return "???"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--start", type=int, default=None, help="first log line (1-based)")
    ap.add_argument("--end", type=int, default=None, help="last log line (1-based)")
    ap.add_argument("--bits", type=int, default=16, choices=(16, 32),
                    help="default operand size for legacy [STEP] / [STEP PM] (RM/PM16/PM32 follow their tag)")
    ap.add_argument("--unique", action="store_true",
                    help="emit each CS:EIP once in first-seen order")
    ap.add_argument("--out", default="-", help="output path, '-' for stdout")
    args = ap.parse_args()

    md16 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    fout = sys.stdout if args.out == "-" else open(args.out, "w")
    n = 0
    for mode, cs, eip, eip_val, op in extract_steps(args.logfile, args.start, args.end, args.unique):
        ins = disasm_step(md16, md32, args.bits, mode, eip_val, op)
        tag = f"[{mode}] " if mode else ""
        fout.write(f"{tag}{cs}:{eip}  {ins}\n")
        n += 1
    if args.out != "-":
        fout.close()
        print(f"wrote {n} instructions to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
