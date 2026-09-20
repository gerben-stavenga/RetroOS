#!/usr/bin/env python3
"""Check that HDA keeps delivering audible PCM, not merely a startup marker."""
import argparse
import array
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import wave


def check_pcm(samples, rate, channels, seconds):
    needed = rate * channels * seconds
    if len(samples) < needed:
        raise AssertionError(f"only {len(samples) / (rate * channels):.1f}s of PCM, need {seconds}s")
    tail = samples[-needed:]
    stride = rate * channels
    # Allow short game transitions, but never a sustained silent output.
    quiet = 0
    for offset in range(0, len(tail), stride):
        block = tail[offset:offset + stride]
        audible = sum(abs(value) > 32 for value in block) > len(block) // 100
        quiet = 0 if audible else quiet + 1
        if quiet >= 3:
            raise AssertionError("three consecutive seconds of silent PCM")


def dump(log, why):
    """Fail with the guest log attached: CI keeps no temp dirs."""
    tail = ""
    try:
        tail = "\n".join(log.read_text(errors="replace").splitlines()[-40:])
    except OSError as e:
        tail = f"(could not read {log}: {e})"
    raise AssertionError(f"{why}\n=== {log} last 40 lines ===\n{tail}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kvm", action="store_true")
    parser.add_argument("seconds", nargs="?", type=int, default=60)
    args = parser.parse_args()
    if args.seconds < 10:
        parser.error("record at least 10 seconds")
    work = Path(tempfile.mkdtemp(prefix="retroos-audio-steady-"))
    log = work / "guest.log"
    recording = work / "hda.wav"
    env = dict(os.environ, QEMU_DISPLAY="none", AUDIO_BACKEND=f"wav,path={recording}")
    subprocess.run(["bazelisk", "build", "//:data_disk"], check=True)
    data = work / "data.bin"
    subprocess.run([sys.executable, "test/private_data_disk.py", "bazel-bin/data_disk.bin", str(data)], check=True)
    cmd = ["./run.sh", "qemu", "--arch", "x64", "--firmware", "uefi", "--data-image", str(data),
           "--sound", "hda", "--cmd", "GAMES/DOOMS/DOOM.EXE"]
    if args.kvm:
        cmd.append("--kvm")
    with log.open("wb") as output:
        proc = subprocess.Popen(cmd, stdout=output, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
        try:
            deadline = time.monotonic() + 90
            while "sink: first frame played" not in log.read_text(errors="replace"):
                if proc.poll() is not None or time.monotonic() > deadline:
                    dump(log, f"HDA did not start (qemu rc={proc.poll()})")
                time.sleep(0.1)
            # Wait for the game to be RUNNING, not for a fixed delay: DOOM's
            # own startup banner is the only host-speed-independent signal.
            # A slow TCG runner spent the whole fixed settle+window still in
            # startup and recorded real silence, which read as a dropout bug.
            deadline = time.monotonic() + 300
            while "ST_Init" not in log.read_text(errors="replace"):
                if proc.poll() is not None or time.monotonic() > deadline:
                    dump(log, f"game never started (qemu rc={proc.poll()})")
                time.sleep(0.1)
            # Then let the mixer and pacer settle before measuring.
            measurement_start = time.monotonic() + 10
            deadline = measurement_start + args.seconds
            initial_underruns = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise AssertionError(f"emulator exited during playback; see {log}")
                if initial_underruns is None and time.monotonic() >= measurement_start:
                    # The sink starts before DOS loads the game. Loading-time
                    # recovery is outside this steady-state measurement.
                    initial_underruns = log.read_text(errors="replace").count("WARNING: sound underrun")
                time.sleep(0.2)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
    text = log.read_text(errors="replace")
    if re.search(r"KERNEL PANIC|panicked|SEGV|Segmentation", text):
        dump(log, "kernel/guest crash")
    if initial_underruns is None:
        raise AssertionError("steady-state measurement never started")
    if text.count("WARNING: sound underrun") - initial_underruns > 2:
        dump(log, "repeated audio underruns")
    with wave.open(str(recording), "rb") as wav:
        if wav.getsampwidth() != 2 or wav.getnchannels() != 2:
            raise AssertionError("expected signed 16-bit stereo PCM")
        samples = array.array("h", wav.readframes(wav.getnframes()))
        if sys.byteorder != "little":
            samples.byteswap()
        try:
            check_pcm(samples, wav.getframerate(), wav.getnchannels(), args.seconds)
        except AssertionError as e:
            dump(log, str(e))
    print(f"PASS: HDA delivered sustained PCM for {args.seconds}s ({work})")


if __name__ == "__main__":
    main()
