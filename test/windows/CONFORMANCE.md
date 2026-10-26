# External Wine USER32 tests

`test/windows_conformance.py` builds the unchanged Wine 1.2.3 USER32 tests
and standalone runtime from `tmp/rust-dos/tests/conformance`, then runs each
executable in a fresh RetroOS disk fixture. The reference project's emulator
implementation is not used or copied. Its runtime and test-source hashes are
recorded so results can be traced to the inputs.

Requirements: the reference checkout, i686 MinGW GCC/binutils, Bazel, and the
normal hosted-test dependencies. KVM also needs access to `/dev/kvm`.

```sh
python3 test/windows_conformance.py --engine kvm
python3 test/windows_conformance.py --engine tcg --only class,dce,resource
```

Use `--cc` and `--windres` for tools outside PATH. Logs, executables, import
inventories and `results.json` are written under `tmp/wine-conformance/<engine>`.
The compiler version is recorded; the local GCC 13 toolchain differs from the
reference project's recorded GCC 10 build, so counts are not assumed identical.

Without baseline options the command fails unless every selected suite passes.
`--write-baseline FILE` records observations, including failures; it does **not**
mean the implementation conforms. `--baseline FILE` detects changed outcomes,
including improvements that require review of the baseline.

- `user32-conformance-baseline.json`: initial loader-blocked measurements.
- `user32-conformance-current.json`: current KVM measurements and missing imports.

These tests do not establish Windows game compatibility or Windows 2000 support.
Remaining gaps include MDI, scrolling, asynchronous message delivery,
cross-process input-idle/event coordination, complete control interaction,
complete non-client behavior and menu interaction. Guest USER32 now draws basic
title bars and menus, translates client coordinates, and handles pointer-driven
menu commands; popups are currently constrained to their owner surface. Font requests currently substitute the
stock bitmap raster font; the layout is US English. Input tests can skip APIs
not available through dynamic lookup; the report preserves skipped counts.

Additional independent regressions exercise callbacks, named and multi-object
event waits, nonrectangular GDI clipping, DIB orientation/colors, INI profiles,
client/window DC separation, frame geometry, menu commands, and numeric dialog fields:

```sh
ENGINE=kvm python3 test/windows_callbacks.py
ENGINE=tcg python3 test/windows_callbacks.py
ENGINE=kvm python3 test/windows_threads.py
ENGINE=kvm python3 test/windows_repaint.py
python3 -m unittest discover -s test -p test_windows_conformance.py
```

For an interactive PE application, hosted builds accept `--input-control` and
`--screenshot PATH`. Send newline-delimited `mouse DX DY BUTTONS`, `scan HEX...`,
`run MILLISECONDS` (up to 1000 per command), and `snapshot` commands on stdin.
Button bits are left=1, right=2, middle=4. This uses real time and works with KVM;
`--suite-control` instead uses the deterministic TCG instruction clock.

Win32 Minesweeper has also been exercised with a user-supplied PE executable:
board clicks, flagging, F2 reset, difficulty selection, editable custom dimensions,
and closing through the title bar. The downloaded executable is not in the tree.
Win16 still uses its existing kernel implementation; the assembly thunks into
shared guest Rust have not been implemented yet.

The repaint regression checks actual presented pixels after GetDC drawing,
without sending input or using EndPaint to trigger damage. Menu/frame updates
are composed offscreen and copied to the window together.
