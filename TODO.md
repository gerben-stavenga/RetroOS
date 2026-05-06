# DOS Game Compatibility — Bug Sprint

## Alley Cat
- [ ] Hangs after intro screen (intro displays, then no progress)

## Digger
- [ ] Exits immediately on launch
- [ ] After running Digger, other games stop working too — suggests Digger leaves DOS/VM86/DPMI state corrupted on exit

## Offroad
- [ ] Doesn't work — failure mode TBD

## Test Drive 1
- [ ] Crashes — capture fault vector / address

## Borland C IDE
- [ ] Still throws an exception (carryover from previous session) — identify vector and trigger

## Dark Forces
- [ ] Crashes — likely DOS/4GW or similar PM extender; capture fault and diagnose

## Prince of Persia
- [ ] Stopped working (regression) — capture failure mode and diagnose
