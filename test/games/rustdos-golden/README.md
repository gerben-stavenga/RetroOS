# RetroOS references for the RustDOS catalog

These are RetroOS's captures of the unmodified upstream scripts, rather than
RustDOS's framebuffer/audio hashes. References retain upstream golden groups.

`keen1__vga-20000` uses the configured 486/VGA/native SB16+GUS profile.
Alley Cat, Digger, Sopwith and Rogue use explicitly adapted native profiles;
their requested 386 and CGA identification cannot currently be selected.
`profile.json` records this distinction and comparisons must match it.

Captures were inspected, and the early-game gameplay hashes passed repeated
runs. `Record` permits silence; it does not assert audible sound. `Listen`
continues to fail while the hosted audio output remains disconnected.

See [the suite guide](../../../docs/game-suite.md) for recording and comparing
references. The game images retain their original games' copyright; these
files contain test captures and no game executables.
