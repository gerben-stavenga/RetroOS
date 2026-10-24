#!/usr/bin/env python3
"""Measure a tiny native Bazel/Rust build in RetroOS, optionally against Linux.

Uses two genrules deliberately: compile one Rust source, then run its output.
No rules_rust repository downloads or host compilation outputs are reused.
The installed compiler/sysroot are supplied explicitly through the action env.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def summarize(profile, log):
    events = json.loads(profile.read_text())["traceEvents"]
    actions = {event["name"]: round(event["dur"] / 1e6, 3)
               for event in events
               if event.get("cat") == "action processing" and event.get("ph") == "X"}
    output = log.read_text()
    elapsed = re.search(r"Elapsed time: ([\d.]+)s", output)
    result = {"bazel_seconds": float(elapsed[1]) if elapsed else None,
              "action_seconds": actions}
    phases = {phase: float(seconds) for seconds, phase in
              re.findall(r"time:\s*([\d.]+);[^\n]*\t(\S+)", output)}
    if phases:
        # Rust phases nest: these durations must not be summed.
        result["rust_phase_seconds"] = {phase: phases[phase] for phase in
            ("LLVM_passes", "run_linker", "total") if phase in phases}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path)
    parser.add_argument("--install-base", type=Path)
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build/ci/bazel-rust")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--compare-host", action="store_true")
    parser.add_argument("--compiler-timings", action="store_true",
                        help="Use nightly rustc -Ztime-passes and glibc loader statistics")
    args = parser.parse_args()
    install = args.install_base or Path(subprocess.check_output(
        ["bazelisk", "info", "install_base"], cwd=ROOT, text=True).strip())
    toolchain = args.toolchain
    if toolchain is None:
        output = Path(subprocess.check_output(
            ["bazelisk", "info", "output_base"], cwd=ROOT, text=True).strip())
        candidates = list((output / "external").glob("*rust_toolchain_x86_64_linux"))
        if len(candidates) != 1:
            parser.error("Specify --toolchain: expected one extracted Linux Rust distribution")
        toolchain = candidates[0]
    install = install.resolve(strict=True)
    toolchain = toolchain.resolve(strict=True)
    work = args.work_dir.resolve()
    workspace = work / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    expected = "BAZEL RUST PASS " + uuid.uuid4().hex + "\n"
    (workspace / "WORKSPACE").write_text('workspace(name="retroos_bazel_rust_probe")\n')
    (workspace / "main.rs").write_text("fn main() { println!(" + json.dumps(expected.rstrip()) + "); }\n")
    compiler_flags = "-Ztime-passes " if args.compiler_timings else ""
    (workspace / "BUILD").write_text('''genrule(
    name = "hello",
    srcs = ["main.rs"],
    outs = ["hello-bin"],
    cmd = "$$RUSTC ''' + compiler_flags + '''--edition=2024 --sysroot=$$RUST_SYSROOT $(location main.rs) -o $@",
    executable = True,
)
genrule(
    name = "check",
    srcs = [":hello"],
    outs = ["result.txt"],
    cmd = "$(location :hello) > $@",
)
''')
    common = ["--enable_bzlmod=false",
              "--action_env=RUSTC=" + str(toolchain / "rustc/bin/rustc"),
              "--action_env=RUST_SYSROOT=" + str(toolchain / "rust-std-x86_64-unknown-linux-gnu")]
    if args.compiler_timings:
        common.append("--action_env=LD_DEBUG=statistics")
    results = {}
    if args.compare_host:
        command = ["bazelisk", "--batch", "--nosystem_rc", "--nohome_rc",
                   "--install_base=" + str(install), "--output_user_root=" + str(work / "host-cache"),
                   "--host_jvm_args=-Xmx512m", "--host_jvm_args=-XX:CompressedClassSpaceSize=64m",
                   "--host_jvm_args=-XX:ReservedCodeCacheSize=64m", "build",
                   "--spawn_strategy=standalone", "--genrule_strategy=standalone", "--jobs=1",
                   "--loading_phase_threads=1", "--legacy_globbing_threads=1",
                   "--symlink_prefix=" + str(work / "host-bazel-"),
                   "--profile=" + str(work / "host-profile.json"), *common, "//:check"]
        env = os.environ.copy()
        env["USE_BAZEL_VERSION"] = (ROOT / ".bazelversion").read_text().strip()
        env["MALLOC_ARENA_MAX"] = "2"
        with (work / "host.log").open("w") as log:
            subprocess.run(command, cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT,
                           timeout=args.timeout, check=True)
        assert (work / "host-bazel-bin/result.txt").read_text() == expected
        results["linux"] = summarize(work / "host-profile.json", work / "host.log")
    start = time.monotonic()
    subprocess.run(["python3", str(ROOT / "tools/try_self_build.py"), "//:check",
                    "--workspace", str(workspace), "--work-dir", str(work / "guest"),
                    "--install-base", str(install), "--timeout", str(args.timeout),
                    "--bazel-arg=--profile=/home/retroos/bazel-profile.json",
                    *["--bazel-arg=" + arg for arg in common]], cwd=ROOT, check=True)
    home = work / "guest/c"
    outputs = list((home / "cache").glob(
        "*/execroot/retroos_bazel_rust_probe/bazel-out/*/bin/result.txt"))
    assert any(path.read_text() == expected for path in outputs), "Guest compiled output did not run correctly"
    results["retroos"] = summarize(home / "bazel-profile.json", home / "build.err")
    results["retroos"]["wall_seconds_including_boot"] = round(time.monotonic() - start, 3)
    (work / "timings.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    print("PASS: Bazel compiled and ran fresh Rust source inside RetroOS; diagnostics: " + str(work))


if __name__ == "__main__":
    main()
