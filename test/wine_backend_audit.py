#!/usr/bin/env python3
"""Inventory the pinned Wine host contract and RetroOS implementations.

An implemented entry means there is an adapter, not that every information
class/flag is supported. Unsupported variants must return their NT error.
"""
import argparse
import collections
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parent.parent
GROUPS = {
    "files": ("File", "Directory", "Volume", "IoCompletion", "IoFile"),
    "registry": ("Key", "Registry"),
    "memory": ("Memory", "Section", "WriteWatch", "Mapped", "Cache"),
    "threads_and_sync": ("Thread", "Event", "Wait", "Semaphore", "Mutant", "Timer", "Delay", "Apc", "Alert"),
    "processes": ("Process", "Job", "Spawn"),
    "security": ("Token", "Security", "Privilege", "AccessCheck", "Audit"),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    contract = json.loads((ROOT / "bazel-bin/lib/wine/ntdll/backend-abi.json").read_text())
    implemented = runpy.run_path(str(ROOT / "lib/wine/build_backend.py"))["IMPLEMENTED"]
    assert all(contract.get(n) == size for n, size in implemented.items()), "backend ABI mismatch"
    report = {"imports": [], "server_requests": []}
    counts = collections.defaultdict(lambda: [0, 0])
    for name, size in sorted(contract.items()):
        group = next((g for g, terms in GROUPS.items() if any(t in name for t in terms)), "other")
        present = name in implemented
        counts[group][0] += present
        counts[group][1] += 1
        report["imports"].append(dict(name=name, stack_bytes=size, group=group, adapter=present))
    # The adapter switch is the authoritative list; no hand-maintained second manifest.
    report["server_requests"] = sorted(set(re.findall(r"\bREQ_(\w+)", (ROOT / "lib/wine/server.c").read_text())))
    for group, (done, total) in sorted(counts.items()):
        print(f"{group}: {done}/{total} adapters")
    print(f"total: {len(implemented)}/{len(contract)} imports; {len(report['server_requests'])} server requests")
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")

if __name__ == "__main__":
    main()
