#!/usr/bin/env python3
"""Opt-in, isolated DOS game regression runs on the hosted RetroOS kernel."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
KEYS = {
    "ENTER": b"\r", "SPACE": b" ", "TAB": b"\t",
    "UP": b"\x1b[A", "DOWN": b"\x1b[B",
    "RIGHT": b"\x1b[C", "LEFT": b"\x1b[D",
    "F1": b"\x1bOP",
    # The hosted stdin decoder reads ahead after ESC. A second ESC ends
    # that lookahead without blocking or introducing another guest key.
    "ESC": b"\x1b\x1b",
}
FORBIDDEN = ("KERNEL PANIC", "panicked at", "!!! FATAL !!!", "not found", "Unhandled exception")


class Failure(Exception):
    pass


def ppm(data):
    """Parse the canonical P6 captures the hosted kernel writes."""
    match = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\n", data)
    if not match:
        raise Failure("invalid or incomplete PPM header")
    width, height = map(int, match.groups())
    pixels = data[match.end():]
    if width <= 0 or height <= 0 or len(pixels) != width * height * 3:
        raise Failure("incomplete PPM pixels")
    return width, height, pixels


def picture_stats(data):
    width, height, pixels = ppm(data)
    colours = set(zip(pixels[::3], pixels[1::3], pixels[2::3]))
    lit = sum(max(c) > 16 for c in zip(pixels[::3], pixels[1::3], pixels[2::3]))
    return {"width": width, "height": height, "colours": len(colours),
            "lit_fraction": lit / (width * height),
            "sha256": hashlib.sha256(pixels).hexdigest()}


def picture_difference(actual, expected, channel_tolerance=16):
    aw, ah, a = ppm(actual)
    ew, eh, e = ppm(expected)
    if (aw, ah) != (ew, eh):
        raise Failure(f"picture size changed: {ew}x{eh} -> {aw}x{ah}")
    changed = sum(any(abs(a[i + c] - e[i + c]) > channel_tolerance
                      for c in range(3)) for i in range(0, len(a), 3))
    return changed / (aw * ah)


def audio_stats(data):
    # WavSink patches the length every 1024 frames. Include the complete
    # physical tail as well, so killing the guest doesn't hide short sounds.
    if (len(data) < 44 or data[:4] != b"RIFF" or data[8:16] != b"WAVEfmt "
            or data[36:40] != b"data"):
        raise Failure("missing or invalid hosted WAV capture")
    fmt, channels, rate = struct.unpack_from("<HHI", data, 20)
    bits = struct.unpack_from("<H", data, 34)[0]
    if fmt != 1 or channels != 2 or bits != 16 or rate == 0:
        raise Failure("expected stereo 16-bit PCM")
    payload = data[44:44 + ((len(data) - 44) // 4) * 4]
    samples = [x[0] for x in struct.iter_unpack("<h", payload)]
    return {"frames": len(samples) // 2, "rate": rate,
            "seconds": len(samples) / (2 * rate),
            "peak": max(map(abs, samples), default=0),
            "sha256": hashlib.sha256(payload).hexdigest()}


def safe_relative(value):
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"expected relative path: {value!r}")
    return path


def load_catalog(path):
    catalog = json.loads(path.read_text())
    ids = set()
    for case in catalog:
        name = case["id"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name) or name in ids:
            raise ValueError(f"invalid or duplicate scenario id: {name}")
        ids.add(name)
        safe_relative(case["directory"])
        safe_relative(case["executable"])
        for file in case.get("files", {}):
            safe_relative(file)
        if not case.get("steps"):
            raise ValueError(f"{name}: empty script")
        if "expect_failure" in case and not case["expect_failure"]:
            raise ValueError(f"{name}: expect_failure must be a nonempty message")
        for field in ("timeout", "boot_timeout"):
            if field in case and (not math.isfinite(case[field]) or case[field] <= 0):
                raise ValueError(f"{name}: {field} must be positive and finite")
        for step in case["steps"]:
            if step["op"] not in {"wait", "key", "text", "log", "shot", "listen", "exit"}:
                raise ValueError(f"{name}: unknown operation {step['op']}")
            if step["op"] in {"shot", "listen"}:
                if not re.fullmatch(r"[a-z0-9_-]+", step["name"]):
                    raise ValueError(f"{name}: invalid checkpoint name")
            if step["op"] == "key" and step["key"] not in KEYS:
                raise ValueError(f"{name}: unknown key {step['key']}")
            if "repeat" in step and (not isinstance(step["repeat"], int) or step["repeat"] < 1):
                raise ValueError(f"{name}: repeat must be a positive integer")
            if step["op"] == "exit" and (step is not case["steps"][-1] or not step.get("contains")):
                raise ValueError(f"{name}: exit must be last and specify a completion marker")
            for field in ("seconds", "settle", "interval", "timeout"):
                if field in step and (not math.isfinite(step[field]) or step[field] < 0):
                    raise ValueError(f"{name}: {field} must be nonnegative and finite")
        labels = [s["name"] for s in case["steps"] if s["op"] in {"shot", "listen"}]
        if len(set(labels)) != len(labels):
            raise ValueError(f"{name}: duplicate checkpoint name")
    return catalog


def read(path):
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


class Machine:
    def __init__(self, command, directory, timeout):
        self.directory = directory
        self.deadline = time.monotonic() + timeout
        self.log_path = directory / "retroos.log"
        self.log_file = self.log_path.open("wb")
        try:
            self.process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
                                            stdout=self.log_file, stderr=self.log_file)
        except Exception:
            self.log_file.close()
            raise

    def check(self, allow_exit=False):
        log = read(self.log_path).decode(errors="replace")
        for marker in FORBIDDEN:
            if marker in log:
                raise Failure(f"log contains {marker!r}")
        code = self.process.poll()
        if code is not None and (not allow_exit or code != 0):
            raise Failure(f"guest exited early (status {code})")
        if time.monotonic() >= self.deadline:
            raise Failure("scenario deadline exceeded")

    def wait_for(self, predicate, seconds, description, allow_exit=False):
        end = min(self.deadline, time.monotonic() + seconds)
        while True:
            self.check(allow_exit)
            if predicate():
                return
            if time.monotonic() >= end:
                raise Failure(f"timed out waiting for {description}")
            time.sleep(0.05)

    def wait(self, seconds):
        end = time.monotonic() + seconds
        self.wait_for(lambda: time.monotonic() >= end, seconds + 0.1, "delay")

    def capture(self, seconds=5):
        path = self.directory / "screen.txt.ppm"
        def ready():
            try:
                ppm(read(path))
                return True
            except Failure:
                return False
        self.wait_for(ready, seconds, "complete graphics capture")
        # Recheck the actual bytes, since the watcher may be rewriting them.
        for _ in range(10):
            data = read(path)
            try:
                ppm(data)
                return data
            except Failure:
                self.wait(0.05)
        raise Failure("could not read complete graphics capture")

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process.stdin.close()
        self.log_file.close()


def run_case(case, args):
    started = time.monotonic()
    result = {"id": case["id"], "status": "fail", "checks": [], "error": ""}
    # A unique invocation directory means concurrent suites and earlier
    # failures can never supply stale screenshots or overwrite a drive.
    directory = args.output / case["id"]
    directory.mkdir()
    (directory / "scenario.json").write_text(json.dumps(case, indent=2) + "\n")
    machine = None
    pending_goldens = []
    try:
        drive = directory / "c"
        source = args.source / safe_relative(case["directory"])
        destination = drive / safe_relative(case["directory"])
        shutil.copytree(source, destination)
        exe = destination / safe_relative(case["executable"])
        if not exe.is_file():
            raise Failure(f"game executable missing: {exe}")
        for file, contents in case.get("files", {}).items():
            target = destination / safe_relative(file)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents)
        runtime = drive / "RETROOS"
        runtime.mkdir()
        for name in ("BOOT.INI", "RETROOS.INI"):
            shutil.copyfile(ROOT / "etc" / name, runtime / name)
        inputs = {str(p.relative_to(drive)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(drive.rglob("*")) if p.is_file()}
        (directory / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
        guest_exe = (Path(case["directory"]) / case["executable"]).as_posix()
        command = [str(args.host_bin),
                   "--cmd", guest_exe + (" " + case["arguments"] if case.get("arguments") else ""),
                   "--cwd", case["directory"] + "/", "--screenshot", str(directory / "screen.txt"),
                   "--wav", str(directory / "audio.wav")]
        if args.storage == "disk":
            image = directory / "c.img"
            occupied = sum(p.stat().st_size for p in drive.rglob("*") if p.is_file())
            size = max(64 * 1024 * 1024, occupied * 2 + 32 * 1024 * 1024)
            with image.open("wb") as file:
                file.truncate(size)
            with (directory / "format.log").open("wb") as log:
                subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(drive), str(image)],
                               stdout=log, stderr=log, check=True)
            command.append(str(image))
        else:
            command += ["--host", str(drive)]
        (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        machine = Machine(command, directory, case.get("timeout", 60))
        # Require the actual program to enter the kernel's event loop.
        machine.wait_for(lambda: b"event_loop entered" in read(machine.log_path),
                         case.get("boot_timeout", 20), "game event loop")
        for step in case["steps"]:
            op = step["op"]
            if op == "wait":
                machine.wait(step["seconds"])
            elif op == "key":
                for _ in range(step.get("repeat", 1)):
                    machine.check()
                    try:
                        machine.process.stdin.write(KEYS[step["key"]])
                        machine.process.stdin.flush()
                    except BrokenPipeError as exc:
                        raise Failure("guest closed its keyboard input") from exc
                    machine.wait(step.get("interval", 0.2))
            elif op in {"text", "log"}:
                path = directory / "screen.txt" if op == "text" else machine.log_path
                machine.wait_for(lambda: step["contains"] in read(path).decode(errors="replace"),
                                 step.get("timeout", 15), f"{op}: {step['contains']}")
                result["checks"].append({"kind": op, "contains": step["contains"]})
            elif op == "shot":
                # Wait for a watcher cycle after preceding input. The hosted
                # capture uses a one-frame mailbox, which adds another cycle.
                machine.wait(step.get("settle", 2.2))
                data = machine.capture()
                target = directory / (step["name"] + ".ppm")
                target.write_bytes(data)
                stats = picture_stats(data)
                result["checks"].append({"kind": "shot", "name": step["name"], **stats})
                if "size" in step and [stats["width"], stats["height"]] != step["size"]:
                    raise Failure(f"{step['name']}: expected graphics size {step['size']}, got {stats['width']}x{stats['height']}")
                if stats["colours"] < step.get("min_colours", 4):
                    raise Failure(f"{step['name']}: too few colours ({stats['colours']})")
                if stats["lit_fraction"] < step.get("min_lit", 0.01):
                    raise Failure(f"{step['name']}: blank picture")
                if "different_from" in step:
                    previous = read(directory / (step["different_from"] + ".ppm"))
                    change = picture_difference(data, previous)
                    if change < step.get("min_change", 0.01):
                        raise Failure(f"{step['name']}: screen did not change ({change:.2%})")
                golden = args.golden / args.engine / case["id"] / target.name
                if args.compare and step.get("reference", True):
                    if not golden.is_file():
                        raise Failure(f"missing reference: {golden}; inspect captures and --bless first")
                    expected = golden.read_bytes()
                    (directory / (step["name"] + ".expected.ppm")).write_bytes(expected)
                    difference = picture_difference(data, expected, step.get("channel_tolerance", 16))
                    result["checks"][-1]["changed_fraction"] = difference
                    if difference > step.get("max_changed", 0.05):
                        raise Failure(f"{step['name']}: {difference:.2%} of pixels differ from reference")
                if args.bless and step.get("reference", True):
                    pending_goldens.append((golden, data))
            elif op == "listen":
                path = directory / "audio.wav"
                before = len(read(path))
                machine.wait(step["seconds"])
                data = read(path)
                # Keep the header but inspect only the samples from this interval.
                interval = bytearray(data[:44] + data[max(before, 44):])
                if len(interval) >= 44:
                    struct.pack_into("<I", interval, 4, len(interval) - 8)
                    struct.pack_into("<I", interval, 40, len(interval) - 44)
                (directory / (step["name"] + ".wav")).write_bytes(interval)
                stats = audio_stats(interval)
                result["checks"].append({"kind": "listen", "name": step["name"], **stats})
                if stats["seconds"] < step.get("min_seconds", 0.05) or stats["peak"] < step.get("min_peak", 1):
                    raise Failure(f"{step['name']}: missing audio or silence")
            elif op == "exit":
                machine.wait_for(lambda: machine.process.poll() == 0,
                                 step.get("timeout", 30), "successful game exit", allow_exit=True)
                # Shutdown returns 0 for some failure paths too. Require the
                # supplied completion marker in addition to the exit status.
                if step["contains"] not in read(machine.log_path).decode(errors="replace"):
                    raise Failure(f"exit missing completion marker {step['contains']!r}")
                result["checks"].append({"kind": "exit", "contains": step["contains"]})
        machine.check(allow_exit=case["steps"][-1]["op"] == "exit")
        if case.get("expect_failure"):
            result["status"] = "unexpected-pass"
            result["error"] = "known failure now passes; remove expect_failure from the catalog"
        else:
            for golden, data in pending_goldens:
                golden.parent.mkdir(parents=True, exist_ok=True)
                golden.write_bytes(data)
            result["status"] = "pass"
    except (Failure, OSError, ValueError, subprocess.CalledProcessError) as exc:
        result["error"] = str(exc)
        if case.get("expect_failure") and case["expect_failure"] in result["error"]:
            result["status"] = "known-fail"
    finally:
        if machine:
            machine.close()
    result["seconds"] = round(time.monotonic() - started, 2)
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['status'].upper()}: {case['id']} ({result['seconds']}s) {result['error']}", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "test/games/catalog.json")
    parser.add_argument("--source", type=Path, default=ROOT / "showcase-bundle",
                        help="installed games root, with GAMES/... directories")
    parser.add_argument("--engine", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument("--storage", choices=("disk", "hostfs"), default="disk",
                        help="fresh ext4 disk (requires mkfs.ext4) or native host filesystem")
    parser.add_argument("--host-bin", type=Path, help="override built hosted kernel")
    parser.add_argument("--select", default="", help="comma-separated scenario name substrings")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "tmp/game-suite")
    parser.add_argument("--golden", type=Path, default=ROOT / "test/games/golden")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--compare", action="store_true", help="require reference image comparisons")
    mode.add_argument("--bless", action="store_true", help="record references after all case checks pass")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    try:
        cases = load_catalog(args.catalog)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    filters = [x.strip() for x in args.select.split(",") if x.strip()]
    cases = [c for c in cases if not filters or any(f in c["id"] for f in filters)]
    if not cases:
        parser.error("no scenarios selected")
    if args.list:
        for case in cases:
            print(f"{case['id']}: {case.get('description', '')}")
        return 0
    target = "retroos-host" + ("-kvm" if args.engine == "kvm" else "")
    if args.host_bin is None:
        args.host_bin = ROOT / "bazel-bin/kernel" / target
        if not args.no_build:
            bazel = shutil.which("bazelisk") or shutil.which("bazel")
            if not bazel:
                parser.error("Bazel required; use --no-build with an existing binary")
            subprocess.run([bazel, "build", f"//kernel:{target}", "--platforms=@platforms//host"],
                           cwd=ROOT, check=True)
    for key in ("source", "host_bin", "output", "golden"):
        setattr(args, key, getattr(args, key).resolve())
    if not args.host_bin.is_file():
        parser.error(f"hosted kernel missing: {args.host_bin}")
    if args.storage == "disk" and not shutil.which("mkfs.ext4"):
        parser.error("disk scenarios require mkfs.ext4 (e2fsprogs)")
    args.output.mkdir(parents=True, exist_ok=True)
    import tempfile
    args.output = Path(tempfile.mkdtemp(prefix="run-", dir=args.output))
    metadata = {"engine": args.engine, "storage": args.storage,
                "host_bin": str(args.host_bin),
                "kernel_sha256": hashlib.sha256(args.host_bin.read_bytes()).hexdigest(),
                "compare": args.compare, "bless": args.bless}
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda case: run_case(case, args), cases))
    (args.output / "report.json").write_text(json.dumps(results, indent=2) + "\n")
    report = ["# Game suite", "", f"Engine: {args.engine}; storage: {args.storage}", "",
              "| Scenario | Result | Seconds | Details |", "|---|---|---:|---|"]
    for result in results:
        details = result["error"].replace("|", "\\|").replace("\n", " ")
        report.append(f"| [{result['id']}]({result['id']}/result.json) | {result['status']} | {result['seconds']} | {details} |")
    (args.output / "report.md").write_text("\n".join(report) + "\n")
    print(f"Artifacts: {args.output}")
    return int(any(r["status"] not in {"pass", "known-fail"} for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
