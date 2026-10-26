#!/usr/bin/env python3
"""Build external Wine USER32 tests and measure them under RetroOS.

Reads rust-dos's unchanged Wine 1.2.3 tests and standalone test runtime; none
of their implementation sources are copied into RetroOS. Results are observations,
not a claim of Windows compatibility. A matching baseline may contain failures.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
SUMMARY = re.compile(r"(\w+): (\d+) tests executed \((\d+) marked as todo, (\d+) failures?\), (\d+) skipped\.")
LIBS = ["ddraw", "dsound", "dinput", "winmm", "ole32", "user32", "gdi32", "kernel32", "advapi32", "dxguid", "uuid", "ksuser"]
DLLS = {"kernel32": "lib/windows/kernel32", "user32": "lib/windows/user32",
        **{name: "lib/windows/compat" for name in ("gdi32", "advapi32", "winmm", "ole32", "ntdll")}}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, *, cwd=ROOT, env=None):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def executable(value):
    found = shutil.which(value)
    if found is None:
        raise RuntimeError(f"Required tool not found: {value}; tests were not run")
    return str(Path(found).resolve())


def observe(log, host_returncode, timeout):
    summaries = [dict(zip(("unit", "checks", "todo", "failures", "skipped"),
                         (m[0], *(int(n) for n in m[1:])))) for m in SUMMARY.findall(log)]
    diagnostics = sorted(set(re.findall(r"Windows: (?:unresolved|missing) [^\r\n]+", log)))
    failures = Counter()
    for line in log.splitlines():
        match = re.search(r"([\w.-]+\.c:\d+): (Test failed|Tests skipped|Test succeeded inside todo block):", line)
        if match:
            failures[f"{match[1]}: {match[2]}"] += 1
    guest_exits = [int(n) for n in re.findall(r"\[mem\] exit tid=\d+ code=(-?\d+)", log)]
    if diagnostics:
        status = "loader-blocked"
    elif timeout:
        status = "timeout"
    elif re.search(r"PANIC|SEGV|Stack Overflow|!!! KERNEL|!!! FATAL", log):
        status = "crash"
    elif host_returncode != 0:
        status = "host-error"
    elif not summaries:
        status = "no-summary"
    elif not guest_exits:
        status = "incomplete"
    elif any(s["failures"] for s in summaries) or any(guest_exits):
        status = "failed"
    else:
        status = "passed"
    return {"status": status, "summaries": summaries, "diagnostics": diagnostics,
            "checks_by_location": dict(sorted(failures.items())), "guest_exit_codes": guest_exits}


def run_guest(target, program, unit, out, timeout):
    with tempfile.TemporaryDirectory(prefix=f"retroos-wine-{unit}-") as directory:
        drive = Path(directory)
        system = drive / "RETROOS/WINDOWS/SYSTEM32"
        system.mkdir(parents=True)
        for name, folder in DLLS.items():
            shutil.copyfile(ROOT / "bazel-bin" / folder / f"{name.upper()}.DLL", system / f"{name.upper()}.DLL")
        # Each invocation gets a fresh disk, including test-created files.
        shutil.copyfile(program, drive / program.name)
        (drive / "WINDOWS/SYSTEM").mkdir(parents=True)
        (drive / "WINDOWS/REGEDIT.EXE").write_bytes(b"")
        args = ["python3", str(ROOT / "test/disk_fixture.py"), "--root", directory, "--",
                str(ROOT / "bazel-bin/kernel" / target), "--c-root", "/", "--cmd", f"/{program.name} {unit}"]
        with (out / f"{unit}.log").open("w") as log:
            process = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            timed_out = False
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                try:
                    process.wait(timeout=min(0.25, max(0.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    current_log = (out / f"{unit}.log").read_text(errors="replace")
                    fatal = "!!! FATAL !!!" in current_log or "!!! KERNEL PANIC !!!" in current_log
                    timed_out = time.monotonic() >= deadline
                    if not fatal and not timed_out:
                        continue
                    # Stop this test's entire process group, including the guest.
                    # The fixture gets time to clean up its temporary disk.
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    break
        return observe((out / f"{unit}.log").read_text(errors="replace"), process.returncode, timed_out)


def import_audit(program, exports, fallback):
    """List static imports absent from both guest DLL exports and fallback gates.

    Availability is not implementation quality: a success-returning stub still
    appears available here. Runtime observations remain the authoritative result.
    """
    imports = []
    module = None
    for line in command(["objdump", "-p", program]).splitlines():
        match = re.search(r"DLL Name: (\S+)", line)
        if match:
            module = match[1].lower().removesuffix(".dll")
        elif module:
            match = re.match(r"\s+[0-9a-f]+\s+\d+\s+(\S+)(?:\s+[0-9a-fA-F]{8})?\s*$", line)
            if match:
                imports.append((module, match[1]))
            elif line.startswith("The "):
                module = None
    missing = [f"{module.upper()}.DLL!{name}" for module, name in imports
               if name.lower() not in exports.get(module, set())
               and (module, name.lower()) not in fallback]
    return sorted(set(missing))


def exported_names(path):
    output = command(["objdump", "-p", path])
    table = output.split("[Ordinal/Name Pointer] Table", 1)
    if len(table) != 2:
        return set()
    return {m.lower() for m in re.findall(r"^\s*\[\s*\d+\] (\S+)", table[1], re.MULTILINE)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "tmp/rust-dos/tests/conformance")
    parser.add_argument("--cc", default=os.environ.get("CONFORMANCE_CC", "i686-w64-mingw32-gcc"))
    parser.add_argument("--windres", default=os.environ.get("CONFORMANCE_WINDRES", "i686-w64-mingw32-windres"))
    parser.add_argument("--engine", choices=("kvm", "tcg"), default=os.environ.get("ENGINE", "kvm"))
    parser.add_argument("--only", help="Comma-separated USER32 test names; default: all")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--output", type=Path, default=ROOT / "tmp/wine-conformance")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write-baseline", type=Path)
    mode.add_argument("--baseline", type=Path, help="Check recorded outcomes, including known failures")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    source = args.source.resolve()
    units = sorted(p.stem for p in (source / "wine/user32").glob("*.c"))
    if not units or not (source / "runtime/runtime.c").is_file():
        parser.error(f"Wine test sources and test runtime are missing from {source}")
    if args.only:
        wanted = set(args.only.split(","))
        if wanted - set(units):
            parser.error(f"Unknown USER32 tests: {sorted(wanted - set(units))}")
        units = [u for u in units if u in wanted]
    cc, windres = executable(args.cc), executable(args.windres)
    env = dict(os.environ)
    env["PATH"] = str(Path(cc).parent) + os.pathsep + env.get("PATH", "")
    out = args.output.resolve() / args.engine
    out.mkdir(parents=True, exist_ok=True)
    target = "retroos-host-kvm" if args.engine == "kvm" else "retroos-host"
    subprocess.run(["bazelisk", "build", f"//kernel:{target}",
                    *(f"//{folder}:{name}_dll" for name, folder in DLLS.items()),
                    "--platforms=@platforms//host"], cwd=ROOT, check=True)
    exports = {name: exported_names(ROOT / "bazel-bin" / folder / f"{name.upper()}.DLL")
               for name, folder in DLLS.items()}
    fallback = {(module.lower(), name.lower()) for module, name in re.findall(
        r'spec\(b"([^"\n]+)", b"([^"\n]+)"',
        (ROOT / "kernel/src/kernel/windows/extra.rs").read_text())}
    flags = ["-O1", "-march=i486", "-w", "-D__USE_MINGW_ANSI_STDIO=0", "-D__NO_CTYPE_INLINES"]
    runtime = out / "runtime.o"
    command([cc, *flags, "-ffreestanding", "-fno-tree-loop-distribute-patterns", "-c",
             source / "runtime/runtime.c", "-o", runtime], env=env)
    resources = out / "resource.o"
    command([windres, f"--preprocessor={cc}", "--preprocessor-arg=-E",
             "--preprocessor-arg=-xc", "--preprocessor-arg=-DRC_INVOKED", f"-I{source / 'wine/include'}", "resource.rc",
             "-O", "coff", "-o", resources], cwd=source / "wine/user32", env=env)
    expected = (source / "expected.txt").read_text()
    report = {"engine": args.engine, "compiler": command([cc, "--version"]).splitlines()[0],
              "reference_expected_sha256": digest(source / "expected.txt"),
              "test_runtime_sha256": digest(source / "runtime/runtime.c"), "tests": {}}
    for unit in units:
        print(f"USER32/{unit}: building", flush=True)
        listing = out / f"{unit}_list.c"
        listing.write_text('#define STANDALONE\n#include "wine/test.h"\n'
                           f'extern void func_{unit}(void);\n'
                           f'const struct test winetest_testlist[] = {{{{"{unit}", func_{unit}}}, {{0, 0}}}};\n')
        program = out / f"{unit[:8].upper()}.EXE"
        extra = ["-Ddump_region=conformance_dump_region"] if unit == "win" else []
        try:
            build_log = command([cc, *flags, f"-I{source / 'wine/include'}", "-include",
                                 source / "runtime/compat.h", *extra, source / f"wine/user32/{unit}.c",
                                 "-nostdlib", "-Wl,-e,_mainCRTStartup", listing, runtime, resources,
                                 *(f"-l{lib}" for lib in LIBS), "-lgcc", "-o", program], env=env)
            (out / f"{unit}.build.log").write_text(build_log)
            result = run_guest(target, program, unit, out, args.timeout)
            result["exe_sha256"] = digest(program)
            result["missing_static_imports"] = import_audit(program, exports, fallback)
        except RuntimeError as error:
            (out / f"{unit}.build.log").write_text(str(error))
            result = {"status": "build-error"}
        result["source_sha256"] = digest(source / f"wine/user32/{unit}.c")
        result["reference_summaries"] = [line for line in expected.splitlines()
                                          if line.startswith(f"user32/{unit}:") and " tests executed (" in line]
        report["tests"][unit] = result
        print(f"USER32/{unit}: {result['status']} {', '.join(result.get('diagnostics', []))}", flush=True)
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    # Baselines deliberately exclude executable hashes and compiler metadata:
    # those are recorded in the report, but PE timestamps change on every build.
    baseline = {u: {k: v for k, v in r.items() if k not in ("exe_sha256", "reference_summaries")}
                for u, r in report["tests"].items()}
    if args.write_baseline:
        if any(r["status"] == "build-error" for r in baseline.values()):
            raise SystemExit("Build errors cannot be blessed as a runtime baseline")
        args.write_baseline.write_text(json.dumps(baseline, indent=2) + "\n")
        print(f"Recorded observations in {args.write_baseline}; this does not mean conformance passed.")
    elif args.baseline:
        previous = json.loads(args.baseline.read_text())
        compared = {u: previous.get(u) for u in units}
        if not args.only and set(previous) != set(baseline):
            raise SystemExit("Baseline test set differs")
        if baseline != compared:
            raise SystemExit(f"Conformance results changed; inspect {out / 'results.json'}")
        print("Recorded outcomes match (including any known failures).")
    elif any(r["status"] != "passed" for r in baseline.values()):
        raise SystemExit(f"Conformance is incomplete; inspect {out / 'results.json'}")
    print(f"Logs and report: {out}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
