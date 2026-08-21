#!/bin/bash
# Regenerate rust-project.json for rust-analyzer
# Run this after adding/removing crates or changing dependencies

set -e
bazelisk run @rules_rust//tools/rust_analyzer:gen_rust_project \
    --platforms=@platforms//host \
    -- //kernel:kernel //lib:lib //boot:boot

# Workaround for the ongoing rules_rust rust-analyzer sysroot issue:
# https://github.com/bazelbuild/rules_rust/issues/3985
# Its analyzer repository contains rust-src but not compiled host libcore*.rlib;
# use the matching Bazel host sysroot and retain the analyzer rust-src path.
python3 - <<'PY'
import json
import subprocess
from pathlib import Path

project = Path("rust-project.json")
config = json.loads(project.read_text())
analyzer = Path(config["sysroot"])
version = subprocess.check_output(
    [analyzer / "bin/rustc", "--version"], text=True
).strip()
triples = {
    p.name for p in (analyzer / "lib/rustlib").iterdir()
    if p.is_dir() and (p / "bin").is_dir()
}

matches = []
for core in analyzer.parent.rglob("libcore-*.rlib"):
    triple = core.parents[1].name
    sysroot = core.parents[4]
    rustc = sysroot / "bin/rustc"
    if (triple in triples and rustc.is_file()
            and (sysroot / "libexec/rust-analyzer-proc-macro-srv").is_file()
            and subprocess.check_output([rustc, "--version"], text=True).strip() == version):
        matches.append((sysroot, triple))

if len(matches) != 1:
    raise SystemExit(f"expected one matching Bazel host sysroot, found {matches}")

config["sysroot"] = str(matches[0][0])
print(f"Using Bazel host sysroot: {matches[0][0]} ({matches[0][1]})")
project.write_text(json.dumps(config, indent=2) + "\n")
PY

echo "rust-project.json regenerated with the Bazel host sysroot. Restart rust-analyzer to pick it up."
