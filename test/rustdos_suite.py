#!/usr/bin/env python3
"""Replay the complete pinned RustDOS game catalog against RetroOS."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import configparser
import hashlib
import json
import math
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time

import game_suite as common

ROOT = common.ROOT
CATALOG = ROOT / "test/games/rustdos.json"
SCAN = {"escape": (0x01,), "enter": (0x1c,), "space": (0x39,), "ctrl": (0x1d,),
        "up": (0xe0, 0x48), "down": (0xe0, 0x50), "left": (0xe0, 0x4b), "right": (0xe0, 0x4d),
        "f1": (0x3b,), "a": (0x1e,)}
LETTER_CODES = dict(zip("qwertyuiopasdfghjklzxcvbnm", [0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,
                   0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32]))
SCAN.update({key: (code,) for key, code in LETTER_CODES.items()})


def config(ini):
    parser = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    parser.read_string(ini)
    return parser


def deviations(case):
    """Never silently substitute native hardware for requested variants."""
    cfg = config(case["ini"])
    cpu = cfg.get('emulator', 'cpu', fallback='486')
    result = [] if cpu in {"486", "pentium"} else [f"CPU model {cpu}: generation selection unavailable"]
    if cfg.get("emulator", "core", fallback="normal") == "dynamic":
        result.append("RustDOS dynamic-recompiler core has no RetroOS counterpart")
    video = cfg.get("emulator", "machine", fallback="vga")
    if video != "vga":
        result.append(f"{video.upper()} adapter identification is not selectable (native VGA supports its modes)")
    sb = cfg.get("sound", "sbtype", fallback="sb16")
    if sb != "sb16":
        result.append(f"SB type {sb}: native virtual SB16 cannot be changed or hidden")
    if cfg.get("sound", "gus", fallback="true") == "false":
        result.append("native virtual GUS cannot be hidden")
    if cfg.has_option("sound", "lpt_dac"):
        result.append("Disney/Covox DAC selection unavailable")
    if case["partner"]:
        result.append("two-machine IPX/null-modem/modem transport adapter unavailable")
    return result


def cache_directory():
    return Path(os.environ.get("GAME_SUITE_CACHE", Path.home() / ".cache/rust-dos/game-suite"))


def installed(game, cache):
    return cache / "installed" / (game["id"] + "-" + game["archives"][0]["sha256"][:8])


def fetch(catalog, cache, checkout):
    """Use the upstream installer scripts for exactly the upstream game bytes.

    This is provisioning only: all replay and validation below runs RetroOS.
    The reference checkout is separate from the user's existing RustDOS tree.
    """
    if not (checkout / ".git").exists():
        checkout.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", catalog["upstream"]], check=True)
    try:
        revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                                           text=True, stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        revision = ""
    if revision != catalog["revision"]:
        if revision:
            raise common.Failure(f"reference checkout is at {revision}; expected {catalog['revision']}")
        subprocess.run(["git", "-C", str(checkout), "fetch", "--depth", "1", "origin", catalog["revision"]], check=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"], check=True)
    environment = dict(os.environ, GAME_SUITE_CACHE=str(cache))
    subprocess.run(["cargo", "test", "--locked", "--release", "--no-default-features", "--test", "game_suite",
                    "--", "--ignored", "fetch", "--nocapture"], cwd=checkout, env=environment, check=True)
    for game in catalog["games"]:
        for archive in game["archives"]:
            data = (cache / "dl" / archive["file"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != archive["sha256"]:
                raise common.Failure(f"archive checksum mismatch: {archive['file']}")
        if not installed(game, cache).is_dir():
            raise common.Failure(f"installation missing: {game['id']}")


class Machine(common.Machine):
    def __init__(self, command, directory, timeout):
        self.directory = directory
        self.deadline = time.monotonic() + timeout
        self.log_path = directory / "retroos.log"
        self.log_file = self.log_path.open("wb")
        self.ms = 0
        self.finished = False
        try:
            self.process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=self.log_file, bufsize=0)
        except Exception:
            self.log_file.close()
            raise
        try:
            if self.response() != "READY":
                raise common.Failure("hosted kernel did not enter suite control")
        except Exception:
            self.close()
            raise

    def response(self):
        data = bytearray()
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise common.Failure("scenario wall-clock deadline exceeded")
            if select.select([self.process.stdout], [], [], min(0.1, remaining))[0]:
                chunk = os.read(self.process.stdout.fileno(), 1)
                if not chunk:
                    raise common.Failure(f"guest exited during control (status {self.process.poll()})")
                if chunk == b"\n":
                    return data.decode().strip()
                data.extend(chunk)
            self.check()

    def command(self, text):
        self.check()
        try:
            self.process.stdin.write((text + "\n").encode())
        except BrokenPipeError as exc:
            raise common.Failure("guest closed control input") from exc
        try:
            response = self.response()
        except common.Failure as failure:
            try:
                code = self.process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                raise failure
            if code == 0 and b"RETROOS-SUITE-DONE" in common.read(self.log_path):
                self.finished = True
                return
            raise
        if not response.startswith("OK "):
            raise common.Failure(response)
        self.ms = int(response.split()[1]) / 1_000_000

    def run(self, ms):
        # Bound each command so the host deadline can interrupt even long waits.
        while ms > 0:
            if self.finished:
                return
            chunk = min(ms, 1000)
            self.command(f"run {chunk}")
            ms -= chunk

    def snapshot(self):
        if not self.finished:
            self.command("snapshot")

    def scan(self, codes, down):
        sequence = list(codes)
        if not down:
            sequence[-1] |= 0x80
        self.command("scan " + " ".join(f"{code:02x}" for code in sequence))

    def press(self, name, held=60, gap=60):
        if self.finished:
            raise common.Failure("input after game completion")
        codes = SCAN[name]
        self.scan(codes, True)
        try:
            self.run(held)
        finally:
            if self.process.poll() is None:
                self.scan(codes, False)
        self.run(gap)

    def type_text(self, text):
        for character in text:
            lower = character.lower()
            name = {"\n": "enter", " ": "space"}.get(lower, lower)
            if name not in SCAN:
                raise common.Failure(f"unsupported text character {character!r}")
            shift = character.isupper()
            if shift:
                self.scan((0x2a,), True)
            self.press(name, 30, 30)
            if shift:
                self.scan((0x2a,), False)

    def condition(self, condition):
        kind, values = condition["kind"], condition["args"]
        if kind == "Not":
            return not self.condition(values[0])
        if kind == "Running":
            return self.process.poll() is None
        if kind == "ShellIdle":
            return self.process.poll() == 0 and b"RETROOS-SUITE-DONE" in common.read(self.log_path)
        if self.process.poll() is None:
            self.snapshot()
        if kind == "Text":
            if not self.finished and common.read(self.directory / "screen.txt.mode") not in {b"0", b"1", b"2", b"3", b"7"}:
                return False
            path = self.log_path if self.finished else self.directory / "screen.txt"
            return values[0] in common.read(path).decode(errors="replace")
        if kind == "Mode":
            return common.read(self.directory / "screen.txt.mode").decode() == str(values[0])
        if kind == "Colours":
            return common.picture_stats(common.read(self.directory / "screen.txt.ppm"))["colours"] >= values[0]
        raise common.Failure(f"unknown condition {kind}")

    def close(self):
        super().close()
        self.process.stdout.close()


def replay(machine, steps, directory):
    checkpoints = []
    for number, step in enumerate(steps):
        kind, values = step["kind"], step["args"]
        try:
            if kind == "Cycles":
                machine.command(f"cycles {values[0]}")
            elif kind == "Focus":
                if values[0] != 0:
                    raise common.Failure("partner machine unavailable")
            elif kind == "Wait":
                machine.run(values[0])
            elif kind == "Key":
                machine.press(values[0])
            elif kind == "Keys":
                for name in values[0]:
                    machine.press(name, 60, max(0, values[1] - 60))
            elif kind == "Hold":
                machine.press(values[0], values[1], 60)
            elif kind == "Type":
                machine.type_text(values[0])
            elif kind == "PressUntil":
                name, condition, gap, maximum = values
                for _ in range(maximum):
                    if machine.condition(condition):
                        break
                    machine.press(name, 60, max(0, gap - 60))
                if not machine.condition(condition):
                    raise common.Failure(f"{condition} did not hold after {maximum} presses")
            elif kind == "WaitFor":
                condition, limit = values
                end = machine.ms + limit
                while not machine.condition(condition):
                    if machine.ms >= end:
                        raise common.Failure(f"condition timeout: {condition}")
                    machine.run(20)
            elif kind == "Check":
                if not machine.condition(values[0]):
                    raise common.Failure(f"condition failed: {values[0]}")
            elif kind == "Shot":
                machine.snapshot()
                data = common.read(directory / "screen.txt.ppm")
                if not data:
                    raise common.Failure("graphics capture missing")
                stats = common.picture_stats(data)
                (directory / (values[0] + ".ppm")).write_bytes(data)
                checkpoints.append({"kind": kind, "label": values[0], **stats})
            elif kind in {"Listen", "Record"}:
                before = len(common.read(directory / "audio.wav"))
                machine.run(values[1])
                data = common.read(directory / "audio.wav")
                interval = bytearray(data[:44] + data[max(44, before):])
                import struct
                if len(interval) >= 44:
                    struct.pack_into("<I", interval, 4, len(interval) - 8)
                    struct.pack_into("<I", interval, 40, len(interval) - 44)
                (directory / (values[0] + ".wav")).write_bytes(interval)
                stats = common.audio_stats(interval)
                checkpoints.append({"kind": kind, "label": values[0], **stats})
                if kind == "Listen" and stats["peak"] == 0:
                    raise common.Failure("silence")
            else:
                raise common.Failure(f"unimplemented upstream operation {kind}")
        except common.Failure as exc:
            (directory / "checkpoints.json").write_text(json.dumps(checkpoints, indent=2) + "\n")
            raise common.Failure(f"step {number} {kind} at {machine.ms:.3f} ms: {exc}") from exc
    return checkpoints


def prepare_disk(source, case, directory, support):
    drive = directory / "c"
    shutil.copytree(source, drive)
    # RustDOS exposes its built-in Ultrasound software on a synthetic drive.
    # Match those support files on C:, where RetroOS's ULTRADIR points.
    if not support.is_dir():
        raise common.Failure(f"upstream Ultrasound support assets missing: {support}; run --fetch")
    shutil.copytree(support, drive / "ULTRASND", dirs_exist_ok=True)
    for name, data in case["files"].items():
        relative = common.safe_relative(name.replace("\\", "/"))
        path = drive
        for part in relative.parts:
            existing = next((p for p in path.iterdir() if p.name.casefold() == part.casefold()), None) if path.is_dir() else None
            path = existing or path / part
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(data))
    runtime = drive / "RETROOS"
    runtime.mkdir(exist_ok=True)
    for name in ("BOOT.INI", "RETROOS.INI"):
        shutil.copyfile(ROOT / "etc" / name, runtime / name)
    shutil.copyfile(ROOT / "bazel-bin/tools/command/COMMAND.COM", runtime / "COMMAND.COM")
    # ConfigParser cannot represent command-only INI sections. Preserve the
    # lines verbatim rather than treating commands as option names.
    autoexec = case["ini"].split("[autoexec]\n", 1)[1]
    (drive / "SUITE.BAT").write_text("@echo off\n" + autoexec + "\necho RETROOS-SUITE-DONE\n")
    image = directory / "c.img"
    occupied = sum(p.stat().st_size for p in drive.rglob("*") if p.is_file())
    with image.open("wb") as stream:
        stream.truncate(max(64 * 1024 * 1024, occupied * 2 + 32 * 1024 * 1024))
    with (directory / "format.log").open("wb") as log:
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(drive), str(image)],
                       stdout=log, stderr=log, check=True)
    manifest = {str(p.relative_to(drive)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(drive.rglob("*")) if p.is_file()}
    (directory / "inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return image


def run_case(case, game, args):
    name = case["name"].replace("/", "__")
    directory = args.output / name
    directory.mkdir()
    (directory / "scenario.json").write_text(json.dumps(case, indent=2) + "\n")
    result = {"name": case["name"], "status": "fail", "error": "", "deviations": deviations(case)}
    started = time.monotonic()
    machine = None
    try:
        if case["partner"] or (result["deviations"] and not args.native_profile):
            result["status"] = "unsupported"
            raise common.Failure("; ".join(result["deviations"]))
        source = installed(game, args.cache)
        if not source.is_dir():
            raise common.Failure(f"game not installed: {source}; run --fetch")
        image = prepare_disk(source, case, directory,
                             args.reference_checkout / "crates/gus/assets/ultrasnd")
        command = [str(args.host_bin), "--suite-control", "--cmd", "RETROOS/COMMAND.COM /B SUITE.BAT",
                   "--cwd", "/", "--screenshot", str(directory / "screen.txt"),
                   "--wav", str(directory / "audio.wav"), str(image)]
        cpu = config(case["ini"]).get("emulator", "cpu", fallback="486")
        if cpu in {"486", "pentium"}:
            command[1:1] = ["--suite-cpu", cpu]
        (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        machine = Machine(command, directory, args.timeout or case["timeout"])
        machine.command("cycles " + config(case["ini"]).get("emulator", "cycles", fallback="6000"))
        result["checkpoints"] = replay(machine, case["steps"], directory)
        expected = args.golden / (case["golden"] or case["name"]).replace("/", "__")
        hashes = [{"kind": c["kind"], "label": c["label"], "sha256": c["sha256"]} for c in result["checkpoints"]]
        reference = expected / "hashes.json"
        if args.compare:
            if not reference.is_file():
                raise common.Failure(f"reference missing: {reference}")
            profile = expected / "profile.json"
            if not profile.is_file() or json.loads(profile.read_text())["native_profile"] != args.native_profile:
                raise common.Failure("reference hardware profile differs from this run")
            for checkpoint in result["checkpoints"]:
                suffix = ".ppm" if checkpoint["kind"] == "Shot" else ".wav"
                artifact = expected / (checkpoint["label"] + suffix)
                if artifact.is_file():
                    shutil.copyfile(artifact, directory / (checkpoint["label"] + ".expected" + suffix))
                    if suffix == ".ppm":
                        width, height, _ = common.ppm(artifact.read_bytes())
                        if (width, height) != (checkpoint["width"], checkpoint["height"]):
                            raise common.Failure(f"{checkpoint['label']}: reference dimensions differ")
            if json.loads(reference.read_text()) != hashes:
                raise common.Failure("checkpoint hashes differ from RetroOS references")
        if args.bless:
            expected.mkdir(parents=True, exist_ok=True)
            reference.write_text(json.dumps(hashes, indent=2) + "\n")
            (expected / "profile.json").write_text(json.dumps({"native_profile": args.native_profile}, indent=2) + "\n")
            for checkpoint in result["checkpoints"]:
                suffix = ".ppm" if checkpoint["kind"] == "Shot" else ".wav"
                shutil.copyfile(directory / (checkpoint["label"] + suffix), expected / (checkpoint["label"] + suffix))
        result["status"] = "pass-native" if result["deviations"] else "pass"
    except (common.Failure, OSError, ValueError, subprocess.CalledProcessError, KeyError) as exc:
        result["error"] = str(exc)
    finally:
        if machine:
            machine.close()
    result["seconds"] = round(time.monotonic() - started, 2)
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['status'].upper()}: {case['name']} {result['error']}", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--select", default=os.environ.get("GAME_SUITE", ""))
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--fetch", action="store_true", help="download, verify and install the exact upstream game archives")
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--cache", type=Path, default=cache_directory())
    parser.add_argument("--reference-checkout", type=Path,
                        default=Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "retroos/rust-dos/source")
    parser.add_argument("--native-profile", action="store_true",
                        help="explicitly replay single-machine scripts on native hardware; report every configuration deviation")
    parser.add_argument("--jobs", type=int, default=int(os.environ.get("GAME_SUITE_JOBS", "1")))
    parser.add_argument("--timeout", type=float, help="override per-case wall-clock limit")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--host-bin", type=Path, default=ROOT / "bazel-bin/kernel/retroos-host")
    parser.add_argument("--output", type=Path, default=ROOT / "tmp/rustdos-suite")
    parser.add_argument("--golden", type=Path, default=ROOT / "test/games/rustdos-golden")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--compare", action="store_true")
    modes.add_argument("--bless", action="store_true")
    args = parser.parse_args()
    catalog = json.loads(CATALOG.read_text())
    filters = [s.strip() for s in args.select.split(",") if s.strip()]
    cases = [c for c in catalog["scenarios"] if not filters or any(f in c["name"] for f in filters)]
    if not cases or args.jobs < 1:
        parser.error("select at least one scenario and a positive job count")
    if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
        parser.error("--timeout must be positive and finite")
    if args.list:
        for case in cases:
            print(case["name"])
        print(f"{len(cases)} scenarios; {len(set(c['game'] for c in cases))} game installations")
        return 0
    for name in ("cache", "reference_checkout", "host_bin", "output", "golden"):
        setattr(args, name, getattr(args, name).resolve())
    if args.fetch or args.fetch_only:
        fetch(catalog, args.cache, args.reference_checkout)
        if args.fetch_only:
            return 0
    if not args.no_build:
        bazel = shutil.which("bazelisk") or shutil.which("bazel")
        if not bazel:
            parser.error("Bazel required")
        subprocess.run([bazel, "build", "//kernel:retroos-host", "--platforms=@platforms//host"], cwd=ROOT, check=True)
        subprocess.run([bazel, "build", "//tools/command:command_com"], cwd=ROOT, check=True)
    args.output.mkdir(parents=True, exist_ok=True)
    args.output = Path(tempfile.mkdtemp(prefix="run-", dir=args.output))
    if args.host_bin.is_file():
        pinned_binary = args.output / "retroos-host"
        shutil.copyfile(args.host_bin, pinned_binary)
        pinned_binary.chmod(0o755)
        args.host_bin = pinned_binary
    (args.output / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n")
    (args.output / "metadata.json").write_text(json.dumps({
        "revision": catalog["revision"], "native_profile": args.native_profile,
        "kernel_sha256": hashlib.sha256(args.host_bin.read_bytes()).hexdigest()
        if args.host_bin.is_file() else None}, indent=2) + "\n")
    games = {g["id"]: g for g in catalog["games"]}
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: run_case(c, games[c["game"]], args), cases))
    (args.output / "report.json").write_text(json.dumps(results, indent=2) + "\n")
    report = ["# RustDOS catalog on RetroOS", "", f"Upstream revision: `{catalog['revision']}`", "",
              "| Scenario | Result | Details |", "|---|---|---|"]
    for result in results:
        path = result["name"].replace("/", "__")
        detail = result["error"].replace("|", "\\|").replace("\n", " ")
        report.append(f"| [{result['name']}]({path}/result.json) | {result['status']} | {detail} |")
    (args.output / "report.md").write_text("\n".join(report) + "\n")
    print("Results: " + ", ".join(f"{count} {status}" for status, count in sorted(Counter(r["status"] for r in results).items())))
    print(f"Artifacts: {args.output}")
    return int(any(r["status"] not in {"pass", "pass-native"} for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
