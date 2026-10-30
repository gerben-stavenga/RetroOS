"""Generate named host-function exports, with explicit traps for unported services."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

IMPLEMENTED = {"RetroNtTerminateProcess": 8, "RetroNtYieldExecution": 0, "RetroDebugWrite": 4, "RetroNtAllocateVirtualMemory": 24, "RetroNtFreeVirtualMemory": 16}
PRIVATE = {"RetroProcessExit": 4, "RetroWriteFile": 20, "RetroYield": 0, "RetroUnsupported": 4, "RetroMemoryReserve": 8, "RetroMemoryCommit": 12, "RetroMemoryDecommit": 8, "RetroMemoryRelease": 4}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--abi", type=Path, required=True)
    parser.add_argument("--asm", type=Path)
    parser.add_argument("--obj", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--linker", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    contract = json.loads(args.abi.read_text())
    assert all(contract.get(name) == size for name, size in IMPLEMENTED.items())
    if args.asm:
        text = "bits 32\nsection .text\n"
        for name, size in PRIVATE.items():
            text += f"global {name}, _{name}@{size}\n{name}:\n_{name}@{size}: int 0x83\n"
        messages = "section .rdata\n"
        for index, (name, size) in enumerate(contract.items()):
            text += f"global {name}\n{name}:\n"
            if name in IMPLEMENTED:
                text += f"extern _{name}@{size}\njmp _{name}@{size}\n"
            else:
                text += f"push missing_{index}\ncall RetroUnsupported\nud2\n"
                messages += f"missing_{index}: db '{name}', 0\n"
        args.asm.write_text(text + messages)
    else:
        with tempfile.TemporaryDirectory(prefix="retroos-backend-link-") as directory:
            script = Path(directory) / "backend.lnk"
            script.write_text("format windows nt dll\noption quiet\noption modname=RETROOS\n" +
                f"name {args.output}\nfile {args.obj}\nlibrary {args.library}\n" +
                "".join(f"export {name}\n" for name in [*PRIVATE, *contract]))
            subprocess.run([str(args.linker), "@" + str(script)], check=True)


if __name__ == "__main__":
    main()
