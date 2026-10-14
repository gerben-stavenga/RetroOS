# RustDOS game catalog

Unmodified `tests/gamesuite/catalog.rs` from
[dividebysandwich/rust-dos](https://github.com/dividebysandwich/rust-dos), pinned
at the revision in `UPSTREAM`. Its upstream GPL license is preserved in
`COPYING`. This source is used only by the catalog exporter; it is not linked
into the RetroOS kernel or runtime.

`tools/export_rustdos_suite.rs` supplies the catalog's data types and evaluates
its game and scenario constructors. `tools/import_rustdos_suite.py` parses
that output into `test/games/rustdos.json`, retaining every archive, install
script, hardware setting, file override, input step and golden group.

Regenerate with `python3 tools/import_rustdos_suite.py`. Update the vendored
source and revision together when intentionally tracking a newer upstream
suite. Archive hashes and game scripts must not be replaced with assumptions
about the similarly named games in `showcase-bundle`.
