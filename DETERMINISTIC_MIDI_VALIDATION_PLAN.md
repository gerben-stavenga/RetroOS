# RetroOS Deterministic Audio Validation Phase: DOOM General MIDI on the Final Audio Architecture Foundation

## 1. Purpose

This document defines the first implementation and validation phase of the deterministic RetroOS audio architecture.

The goal is deliberately narrower than implementing every emulated audio device, but the infrastructure built during this phase should already follow the intended final architecture wherever its shape is sufficiently understood.

The validation target is:

```text
DOOM
+
General MIDI through MPU-401
+
timer-driven deterministic rendering
+
existing experimental HDA transport
```

For this phase, the DOS personality should behave like a PC containing:

```text
MPU-401 / General MIDI       present
Sound Blaster                absent
Gravis UltraSound            absent
other optional audio cards   absent
```

This allows the architecture to be validated without first solving:

- Sound Blaster DMA history;
- Sound Blaster virtual IRQ semantics;
- GUS mutable sample RAM;
- GUS render barriers;
- cross-device event ordering.

The infrastructure should nevertheless be suitable for adding those devices afterward without replacing the scheduling, timing, source, mixer, queue, or sink foundations.

The validation should prove:

> Guest hardware operations are handled synchronously when the guest must immediately observe their effects, while their audio-relevant history is timestamped and may be replayed later by a deterministic audio renderer. The renderer progresses according to `AudioTime`, independently of VM86/event-loop cadence, and continuously feeds the real-time sink.

---

# 2. Source Branch and Existing Work

Start from:

```text
https://github.com/nistvan86/RetroOS/tree/experiment/audio-preroll-resume-gate
```

Create a separate branch, for example:

```text
experiment/deterministic-midi-validation
```

Do not modify the original experimental branch directly.

Relevant existing work includes:

```text
HDA preroll
pause/resume handling
sink pacing
sink queue diagnostics
underrun/recovery handling
blocking-operation handling
```

The HPET timer-correction work is:

```text
https://github.com/nistvan86/RetroOS/commit/65dfcf20dabafd2eb2f85df7d38fa1750974dd16
```

Relevant current source areas include:

```text
lib/sound/src/mpu401.rs

kernel/src/kernel/dos/machine/vmpu.rs

kernel/src/kernel/dos/machine/mod.rs

kernel/src/kernel/sound.rs

kernel/src/kernel/startup.rs

arch-metal/src/irq.rs
```

Inspect the actual branch before changing code because names and ownership may have shifted.

---

# 3. Validation Scope

Implement now:

- architecture-neutral `AudioTime`;
- deterministic audio-service scheduling;
- reusable fixed timestamp-event queue primitive;
- source abstraction suitable for future SB/OPL/GUS;
- canonical mixer usage;
- persistent DOS-personality MPU-401 hardware;
- persistent MIDI synthesizer;
- ordered timestamped MPU port-write history;
- deterministic MIDI rendering;
- existing HDA real-time sink integration;
- HPET-derived elapsed-time handling;
- preroll compatibility;
- real underrun recovery;
- instrumentation.

Do not implement yet:

- Sound Blaster PCM;
- Sound Blaster DMA staging;
- Sound Blaster IRQ timing;
- OPL;
- GUS;
- cross-device global event ordering;
- hosted `arch-interp` scheduling;
- Play real-time host output;
- Linux PCM sources;
- final clock-drift correction strategy;
- HDA IRQ scheduling.

The first registered audio source will be MIDI.

The architecture must not assume that MIDI will remain the only source.

## 3.1 Findings from the completed foundation work

The following observations were discovered while implementing and testing only
the reusable time, queue, MPU frontend, and persistent-synth foundations. They
are recorded here without changing the requirements for the later stages.

### The existing audio backend remains active during this phase

The initial integration does not replace the audio runtime. The current path
is still:

```text
MPU guest write
    |
    v
synchronous MPU frontend + timestamp queue
    |
    v
existing event-loop audio service
    |
    v
existing MIDI synth, canonical mixer, and HDA sink
```

Consequently, underruns and event-loop pacing artifacts remain possible until
the timer-driven `AudioRuntime` service described later in this document is
implemented. The completed foundation alone is not an end-to-end proof of
deterministic playback.

### Phase 22 transition result

The validation branch now admits the PCM render/mixer/sink service only on an
audio service opportunity. On physical timer backends, the opportunity comes
from the timer-owned audio wakeup counter; hosted backends retain the divider
fallback. The ordinary event loop still advances guest timers, devices, and
display work, but those paths no longer invoke PCM service on every loop
iteration. This is the first timer-gated transition, not yet proof of the
final interrupt-driven audio architecture: the service still executes in the
kernel event-loop context after the timer wakeup is observed, and later phases
must complete the source/sink wiring and continuity validation.

The remaining event-loop MIDI replay call has now been removed. MPU timestamp
consumption occurs at the `Midi` source render boundary, before the source
writes its span into the canonical mixer. This closes the ownership gap where
the runtime was timer-gated but MPU replay was still a separate adjacent
event-loop operation. The service itself still executes outside IRQ context;
the timer wakeup only authorizes the runtime service opportunity.

### Sink ownership boundary resolved during full-wiring review

The `AudioRuntime` now owns the sink together with the timeline, source
service, and scheduler state. `run()` creates one runtime and passes a mutable
reference through both headless program launches and the interactive DN event
loop. This preserves one sink/runtime lifetime across short-lived headless
programs and long-lived DN execution, while the blocking-operation hook points
at the runtime-owned sink. The bare-ELF entry point supplies an empty runtime.

The `Midi` source now consumes timestamped MPU events inside its own render
implementation immediately before synthesizing the requested PCM span. The
runtime therefore owns the complete sequence: timer opportunity, logical-time
service, event replay, source rendering, canonical mixing, and sink feeding.
The direct HDA QEMU smoke test still reaches MPU initialization, HDA stream
start, and first-frame playback after this final source-boundary move.

### Important validation-scope distinction

The runtime/source/sink wiring completed above is not yet the MIDI-only
validation configuration described by the later pass criteria. The current
transitional build still registers the fixed SB16, GUS, MIDI, and PC-speaker
PCM sources, and per-slice SB/GUS device servicing remains active for their
guest-visible protocols. The intended deterministic MIDI validation stage must
keep those emulated devices available only where needed for detection and
protocol tests, while disabling their PCM contribution so the sink receives
audio exclusively from the MIDI source. This isolation step remains pending;
it must not be mistaken for a completed general-audio migration.

The isolation switch is implemented as the DOS environment setting
`AUDIO_VALIDATION=MIDI`. It is intentionally absent from the normal
`CONFIG.SYS`, so ordinary boots retain the existing SB/GUS/speaker mix. When
present, each DOS machine keeps SB, GUS, MPU, and speaker protocol state, but
the canonical source array renders silence for SB/GUS/speaker and only the
MIDI source contributes PCM. A temporary QEMU ISO boot with this setting
verified HDA sink initialization, MPU initialization, stream start, and first
frame playback; the default configuration was restored afterward.

With `AUDIO_VALIDATION=MIDI` left enabled for this validation branch, the
virtual SB16 and GUS devices remain present on the DOS address bus and their
guest-visible protocol servicing remains available. Their PCM render steps,
however, are replaced by silent source slots, so they do not contribute to
the canonical mixer or HDA sink. The GUS probe's `GDRAM-OK`, `GREG-OK`,
`GTIMER-OK`, and `GDMA-OK` markers remain valid protocol checks; `GVOICE-OK`
is expected to fail because it verifies audible GUS voice output, which this
MIDI-only validation configuration intentionally disables. SB PCM assertions
must be interpreted similarly when they specifically require audible sample
output rather than DSP, DMA, or IRQ protocol behavior.

### QEMU validation findings from the timer-gated implementation

The reliable headless QEMU smoke-test configuration must explicitly provide
the HDA controller, duplex codec, and an audio backend:

```text
-audiodev driver=none,id=snd0
-device intel-hda
-device hda-duplex,audiodev=snd0
```

Without these devices, QEMU correctly boots the kernel but reports
`Audio: EmulatedSilent`; that run does not exercise HDA initialization or
playback. The direct QEMU command with `-debugcon stdio` also provides a more
reliable validation log than the general `run.sh` wrapper when its image-build
step or stdout capture fails. The current short boot smoke test confirms HDA
route detection, GM-bank loading, sink initialization, and DN startup. It
does not by itself prove MPU guest writes, sustained MIDI rendering, or
long-running playback continuity; those require the later deterministic test
phases.

Removing the elapsed-gap preroll heuristic did not alter initialization: the
same HDA route, 48 kHz sink, and 1440-frame preroll were observed in QEMU.
This confirms that the change is limited to delayed-service continuity and
does not replace genuine cursor/headroom underrun recovery.

### Phase 24 instrumentation progress

The existing HDA census remains trace-gated and reports aggregate service,
timing, produced-frame, drained-frame, and rate information without doing work
in IRQ context. The MPU path now also keeps fixed counters for queue depth,
high-water mark, overflow, data and command writes, consumed events, accepted
and ignored MIDI bytes, maximum event age, and rendered frames. These values
are exposed through device state rather than printed for every event, so
instrumentation cannot flood the kernel log. Periodic presentation of the
remaining counters is still part of the later validation work. The sink-side
headroom, preroll-start, recovery, and underrun counters are now included in
the existing trace-gated periodic census. The sink counters are deliberately
backend-neutral because the same canonical ring path is shared by HDA, AC'97,
and any future adopted PCM device.

Scheduler service timing is now measured only while the existing trace mode is
enabled. The normal audio path does not read TSC for diagnostics. Trace mode
periodically reports the service count, maximum logical audio-time gap,
average service cost, and maximum service cost; this preserves the timing
being investigated on slow hardware while still providing targeted debugging
data when requested.

### QEMU test audio must explicitly expose a sink

A Multiboot QEMU invocation without an audio device reports:

```text
Audio: EmulatedSilent (SB_AUDIO=native)
```

This means that QEMU exposed neither a Sound Blaster nor a supported codec;
the `native` suffix is only the default `SB_AUDIO` policy and does not mean a
native Sound Blaster was detected. In that configuration, SB protocol tests
can still execute, but they do not prove audible playback.

For HDA-backed validation, QEMU must use the repository's existing device
pair:

```text
-device intel-hda
-device hda-duplex,audiodev=snd0
```

With that setup the kernel reports `Audio: EmulatedHda`, loads the resident GM
bank, and exposes the emulated MPU-401 at `0x330`.

### Fixed-capacity state must be constructed in its final storage

The intended MPU queue capacity is 4096 events. Returning that queue or the
containing MPU value by value temporarily materialized a large backing array
on the small kernel stack and caused a page fault during DOS personality
construction. The queue is therefore allocated in place in its final heap
slot. This still satisfies the no-runtime-allocation requirement and keeps the
capacity fixed.

The same constraint applies to future large source, mixer, or runtime state:
prefer in-place initialization when a value contains a substantial fixed
buffer.

### Synth preinitialization has a safe placement boundary

Constructing the MIDI synth directly inside `Mpu::new()` was too early: that
constructor runs while the large DOS machine object is being assembled. It
faulted before the personality was fully initialized. The synth must instead
be initialized at the existing post-construction/configuration boundary, with
the resident bank already available, before guest execution and real-time
audio servicing begin.

This preserves the plan's requirement that synthesis initialization never occur
on the first real-time MIDI event, while respecting the kernel's construction
and stack constraints.

### Current tests have deliberately different proof scopes

The completed tests establish different facts:

- queue and timeline unit tests prove ordering, equal-timestamp FIFO behavior,
  and explicit overflow handling;
- the Multiboot ISO test proves that base and games modules are mounted and
  that representative programs start;
- the QEMU HDA run proves HDA discovery, GM-bank availability, MPU `0x330`
  configuration, synth startup, and sink/preroll activity;
- SB protocol tests prove guest-visible SB behavior, but do not by themselves
  prove physical or audible SB output;
- DOOM startup alone does not prove that DOOM emitted MIDI events or that the
  synth rendered audible music.

The later deterministic MIDI validation must therefore add explicit evidence
for MPU event production, queue consumption, synth rendering, and PCM sink
submission.

### Source registration remains fixed and explicit for this phase

The current source set is a fixed array of `AudioSource` implementations
behind the canonical mixer. A dynamic source registry would add storage and
lifetime complexity without enabling another source in this validation phase.
`AudioRuntime` therefore exposes the reusable `RenderMode` boundary while the
DOS personality supplies the fixed source set. Future SB/OPL/GUS sources can
join that same array and trait boundary when their source lifetimes are ready.

### The first runtime boundary does not remove sink recovery behavior

The initial `AudioRuntime` integration now owns the logical producer clock and
derives render intervals from `Arch::audio_time_micros()`. The existing sink,
mixer, preroll, and recovery code remain below it. Therefore a steady-state
fixture may still report startup or mode-switch underruns at this stage. Those
events are not evidence that the logical-time boundary failed; they belong to
the later work that moves PCM servicing fully out of the guest/event-loop path.

For this stage, the relevant QEMU HDA evidence is successful initialization,
GM-bank loading, MPU discovery, stream start, and first-frame consumption.

### Audio-time conversion must retain sub-millisecond remainder

`AudioTime` is expressed in microseconds while the legacy renderer currently
accepts millisecond intervals. Converting each service interval independently
with integer division loses the fractional remainder and makes the producer
systematically fall behind the sink. `AudioRuntime` now carries that
sub-millisecond remainder while adapting to the legacy millisecond renderer.
This prevents systematic time loss without changing the sink, preroll, or
underrun policy. The final runtime should preferably advance directly in
logical microseconds or sample frames.

### Timer wakeup ownership is separate from IRQ-safe rendering

The timer path now records 500 Hz audio-service opportunities in a counter
separate from guest `PENDING_TICKS`. The interrupt handler performs only the
counter update. The event loop consumes the wakeup count and invokes the
already-initialized runtime in normal kernel context. Hosted backends retain
the divider fallback until they expose an equivalent timer-owned wakeup.

This is an intermediate §35–§36 bridge: it removes audio-service scheduling
from guest tick semantics without claiming that PCM rendering is safe inside a
hardware interrupt. Heap allocation, filesystem access, synth construction,
mixer work, and sink access remain outside IRQ context.

---

# 4. Target Final-Class Architecture

Do not create a MIDI-specific audio architecture merely because MIDI is the first validation source.

Build the validation using the intended general layers.

Conceptually:

```text
                   DOS PERSONALITY

                  Emulated devices
                         |
              +----------+----------+
              |                     |
          MPU-401              future devices
              |                 SB / OPL / GUS
              |
      timestamped device queue
              |
              v

                   AUDIO RUNTIME

                    AudioTime
                        |
                        v
                  Audio sources
                        |
                 +------+------+
                 |             |
             MidiSource      future
                            sources
                 |
                 v

                CanonicalMixer
                        |
                        v

                   SinkTransport
                        |
                        v
                       HDA
```

The validation-specific fact is:

```text
registered source count = 1
```

not:

```text
audio runtime = MIDI-specific prototype
```

---

# 5. Core Reusable Types

Introduce reusable concepts now where their role is already clear.

## 5.1 `AudioTime`

Conceptually:

```rust
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct AudioTime(u64);
```

Requirements:

- monotonic;
- integer or fixed-point;
- cheap from VM86 I/O context;
- cheap from timer IRQ context;
- independent of mixer cadence;
- independent of output sink position.

Do not use floating point as the fundamental representation.

---

## 5.2 `TimedEvent<T>`

Use a generic timestamp wrapper:

```rust
pub struct TimedEvent<T> {
    pub at: AudioTime,
    pub event: T,
}
```

This should later support:

```rust
TimedEvent<MpuEvent>
TimedEvent<OpLEvent>
TimedEvent<SbEvent>
TimedEvent<GusEvent>
```

Do not create one giant global `AudioEvent` enum.

---

## 5.3 Fixed event queue

Implement a reusable fixed-capacity queue:

```rust
FixedEventQueue<T, const N: usize>
```

Requirements:

- preallocated;
- no allocation after initialization;
- FIFO;
- explicit full condition;
- no silent overwrite;
- suitable for guest-side producer and audio-side consumer;
- preserves insertion order for identical timestamps;
- high-water instrumentation.

Do not make the queue MPU-specific.

The MPU-specific event type remains separate.

---

## 5.4 Render mode

Introduce the final-model distinction now if practical:

```rust
enum RenderMode {
    ProducePcm,
    AdvanceOnly,
}
```

The MIDI validation will primarily use `ProducePcm`.

`AdvanceOnly` may not be needed immediately for normal MIDI validation but establishing the API now avoids redesign when physical deadlines and SB/GUS are added.

---

## 5.5 Source abstraction

Use a source abstraction suitable for future devices.

Illustrative only:

```rust
trait AudioSource {
    fn advance_to(
        &mut self,
        time: AudioTime,
        mode: RenderMode,
        output: &mut [Frame],
    );
}
```

The exact interface may need to reflect existing mixer APIs.

Do not over-engineer dynamic registration if a fixed source list is simpler.

The important property is:

```text
MidiSource
    implements the same conceptual interface
that future SB / OPL / GUS sources will implement.
```

---

# 6. Architectural Decisions Discovered During Validation Design

This section records decisions that should later be considered for folding back into the full authoritative audio architecture document.

These are not merely validation hacks.

## 6.1 Emulated audio hardware belongs to the personality lifetime

An MPU-401 is hardware.

It should not be created and destroyed per DOS executable.

The correct lifecycle is:

```text
RetroOS boot
    |
DOS personality created
    |
create virtual MPU-401
create MIDI synthesizer
create event queue
    |
COMMAND.COM
    |
DOOM
    |
DOOM exits
    |
another program
    |
another program
    |
...
    |
DOS personality destroyed/reset
    |
destroy virtual audio hardware
```

Program exit is not a hardware reset event.

---

## 6.2 Remove program-exit MPU reset semantics

Do not reset MPU state merely because a DOS program terminates.

On real hardware:

```text
game exits
```

does not physically power-cycle the MPU-401 or MIDI module.

Only actual guest hardware operations should reset it.

For example:

```text
OUT 331h, FFh
```

is a real MPU reset command and should reset MPU state.

A process exit should not.

---

## 6.3 Preinitialize MPU-401 at DOS personality startup

Create the MPU frontend when the DOS personality starts, regardless of whether the first DOS program uses it.

Do not lazily create the emulated MPU when the first MIDI write occurs.

The hardware is present from the beginning.

---

## 6.4 Preinitialize MIDI synthesis outside the real-time path

Load and initialize everything required for synthesis before deterministic audio servicing can use it.

This includes:

- GM bank / SoundFont data;
- synthesizer object;
- lookup tables;
- voice storage;
- patch mappings;
- mixer buffers.

The deterministic audio renderer must never perform:

```text
GM bank loading
SoundFont parsing
filesystem access
synth construction
large initialization
```

---

## 6.5 MIDI synth lifetime follows the DOS audio hardware lifetime

The MIDI synthesizer should remain alive across DOS executable boundaries.

Do not destroy it when DOOM exits.

If a broken DOS program leaves a note sounding and exits without sending appropriate MIDI messages, the persistent hardware model may legitimately leave that note sounding.

Do not silently clean up musical state simply because RetroOS knows a process exited.

---

## 6.6 Guest-visible protocol state and deferred audio history may both process the same write

An MPU command may require:

```text
immediate synchronous effect
```

and:

```text
timestamped historical replay
```

simultaneously.

These are not conflicting responsibilities.

For example:

```text
OUT 331h, FFh
```

should immediately update guest-visible reset/ACK state while also entering the ordered audio history so the deferred renderer knows that a reset occurred at that exact `AudioTime`.

This pattern will likely apply to other emulated hardware later.

---

## 6.7 Interacting device ports belong to one ordered device history

For MPU-401:

```text
330h data
331h command
```

are not independent channels.

Their interaction must be reconstructable.

Therefore both port-write types belong to the same MPU event queue.

General rule:

> All audio-relevant operations that interact through one emulated device state machine must share an ordering domain.

This does not imply that all sound devices share one global queue.

---

## 6.8 Queue raw device operations when protocol interaction matters

For MPU validation, queue:

```text
raw DataWrite
raw CommandWrite
```

rather than only already-decoded `NoteOn` / `NoteOff` events.

This allows the audio side to reconstruct:

```text
data
reset
UART enable
data
```

correctly.

For another device, the optimal queue semantic may be different.

The general rule should be:

> Queue the lowest-level semantic operation required to reconstruct audio-relevant historical device behavior without unnecessarily moving guest-visible protocol parsing into the renderer.

---

## 6.9 Hardware reset is not necessarily synthesizer reset

An MPU-401 interface reset does not automatically mean the external MIDI synthesizer receives a General MIDI reset.

Therefore:

```text
MPU reset
    !=
kill every MIDI voice
```

The audio-side MPU replay state resets its UART/protocol interpretation.

Synth state changes only when corresponding MIDI data reaches it.

---

## 6.10 Empty event queue does not mean inactive source

A MIDI source may have:

```text
zero pending events
```

while continuing to generate substantial PCM.

Previously received events may have created:

- sustained notes;
- envelopes;
- LFOs;
- sample playback;
- effects tails.

Therefore source advancement is independent of event arrival.

This principle applies generally to continuously evolving emulated hardware.

---

# 7. DOS Personality Initialization

When the DOS personality is initialized:

1. create the emulated MPU-401 frontend;
2. initialize its base address, initially `0x330`;
3. create its fixed event queue;
4. create its audio-side replay state;
5. create the MIDI synthesizer;
6. attach already-loaded GM patch/bank data;
7. initialize synthesizer internals;
8. register `MidiSource` with `AudioRuntime`;
9. initialize mixer working buffers;
10. initialize or attach the HDA sink;
11. only then allow deterministic audio servicing to access the runtime;
12. only then begin normal DOS guest execution.

The entire runtime must be fully published before the timer IRQ can touch it.

---

# 8. GM Bank Lifetime

If the current kernel loads the GM bank before DOS personality initialization, retain that model.

Preferred lifetime:

```text
kernel boot
    |
load / parse GM bank
    |
publish immutable resident bank
    |
DOS personality creation
    |
create MIDI synth using resident bank
```

The audio renderer should see the bank as immutable.

If the GM bank cannot be loaded:

- MPU-401 hardware may still exist;
- guest-visible MPU protocol should still work;
- MIDI playback may be silent;
- do not pretend the MPU itself is absent merely because synthesis resources are unavailable unless current system policy intentionally ties them together.

---

# 9. DOS Personality Destruction

When the DOS personality itself is destroyed or explicitly reset:

1. stop deterministic audio servicing from accessing DOS audio sources;
2. synchronize with any currently executing audio service;
3. stop/pause associated real-time sink playback as required;
4. discard queued DOS audio events;
5. destroy MIDI source;
6. destroy MPU replay state;
7. destroy MPU frontend;
8. release personality-specific audio resources.

Do not perform these steps on ordinary executable exit.

---

# 10. Guest-Visible MPU Frontend

The synchronous MPU frontend owns state visible immediately to DOS.

Responsibilities:

```text
port address decoding
UART mode
reset command
ACK state
status reads
data reads
unknown command behavior
```

The current MPU-401 model should be refactored so this frontend no longer owns the deferred MIDI output FIFO.

---

# 11. Audio-Side MPU Replay State

Create a separate replay state owned exclusively by the audio source.

Minimal example:

```rust
struct MpuReplay {
    uart: bool,
}
```

The replay receives timestamped raw writes.

It reconstructs the historical audio-relevant MPU state.

It does not need to reproduce:

```text
guest status reads
ACK delivery to DOS
```

Those already happened synchronously.

---

# 12. MPU Event Type

Use:

```rust
enum MpuEvent {
    DataWrite(u8),
    CommandWrite(u8),
}
```

Queue:

```rust
TimedEvent<MpuEvent>
```

Do not queue reads.

Reads are observations, not audio-producing historical changes.

---

# 13. Why Both Ports Must Enter One Queue

Consider:

```text
100.000  OUT 330h, 90h
100.010  OUT 330h, 3Ch
100.020  OUT 330h, 7Fh

100.100  OUT 331h, FFh

100.200  OUT 331h, 3Fh

100.300  OUT 330h, 90h
100.310  OUT 330h, 40h
100.320  OUT 330h, 7Fh
```

The queue must contain:

```text
100.000 DataWrite(90)
100.010 DataWrite(3C)
100.020 DataWrite(7F)

100.100 CommandWrite(FF)

100.200 CommandWrite(3F)

100.300 DataWrite(90)
100.310 DataWrite(40)
100.320 DataWrite(7F)
```

If the renderer only runs at:

```text
100
102
104
106 ms
```

it still reconstructs:

```text
old MIDI bytes
then MPU reset
then UART re-entry
then new MIDI bytes
```

in their original order.

This prevents deferred pre-reset data from accidentally being interpreted using post-reset MPU state.

---

# 14. Equal-Timestamp Ordering

`AudioTime` may not have enough resolution to distinguish consecutive x86 `OUT` instructions.

This is acceptable.

Example:

```text
T DataWrite(90)
T DataWrite(3C)
T DataWrite(7F)
T CommandWrite(FF)
```

The queue's FIFO insertion order is authoritative.

For equal timestamps:

```text
guest instruction order
    =
event processing order
```

Do not sort events solely by timestamp.

Do not invent synthetic sub-timestamps.

---

# 15. Synchronous Guest Write Path

On every guest MPU `OUT`:

```text
1. read current AudioTime
2. mutate synchronous MPU frontend
3. publish raw write to MPU event queue
```

Conceptually:

```rust
fn mpu_io_write(port: u16, value: u8) {
    let now = audio_time_now();

    mpu_frontend.port_out(port, value);

    let event = match port {
        MPU_DATA => MpuEvent::DataWrite(value),
        MPU_COMMAND => MpuEvent::CommandWrite(value),
        _ => return,
    };

    publish(TimedEvent {
        at: now,
        event,
    });
}
```

The exact API should follow current architecture boundaries.

---

# 16. Queue Publication Critical Section

Do not keep physical IRQs disabled while executing complete MPU protocol handling.

Preferred shape:

```text
read AudioTime

apply synchronous MPU frontend state

construct event

briefly disable physical IRQ
    |
publish event
    |
restore IRQ
```

If a suitable SPSC mechanism already exists, it may be used instead.

Do not design an unnecessarily complex lock-free structure solely for this phase.

The requirements are:

```text
correctness
bounded publication
no allocation
no event loss
```

---

# 17. Queue Overflow Policy

Start with a generous capacity such as:

```text
4096 events
```

Measure actual DOOM high-water usage.

Overflow must never silently overwrite old events.

Track:

```text
current depth
maximum depth
overflow count
```

For validation:

```text
overflow means test failure
```

Debug builds may panic or print an unmistakable diagnostic.

---

# 18. Remove the Old MPU Deferred FIFO

Current MPU code contains an internal byte FIFO used to defer MIDI data until later host draining.

That queue becomes redundant and harmful once the timestamp queue exists.

Remove or bypass:

```text
output byte FIFO
head
length
push
take
drop-oldest behavior
```

The timestamp queue becomes the only authoritative deferred MPU write history.

Keep synchronous guest-visible state.

---

# 19. Remove Event-Loop MIDI Draining

Current `Mpu::tick()` drains pending MPU bytes and forwards them to the synthesizer.

That must stop.

After conversion:

```text
event loop
    X
    |
    X
MIDI data transfer
```

The only MIDI history consumer is the deterministic audio source.

If `Mpu::tick()` remains for temporary compatibility, its MIDI transfer portion must do nothing.

---

# 20. MIDI Source Ownership

Create a real `MidiSource` rather than a validation-only renderer.

Conceptually:

```rust
struct MidiSource {
    events: EventQueueConsumer<MpuEvent>,
    replay: MpuReplay,
    synth: Synth,
    rendered_until: AudioTime,
}
```

The exact queue ownership representation may differ.

`MidiSource` owns:

```text
audio-side MPU state
MIDI parser state
running status
MIDI synth
voices
envelopes
sample playback state
render frontier
```

The VM86 side owns none of this mutable synthesis state.

---

# 21. MIDI Source Advancement

The source must be able to advance even if the event queue is empty.

Example:

```text
100 ms    NoteOn

102 ms    no event
104 ms    no event
106 ms    no event
108 ms    no event
```

The source still advances:

```text
oscillators
samples
envelopes
controllers
LFOs
voices
```

through each interval.

An empty queue means:

```text
no new hardware change
```

not:

```text
generate silence
```

---

# 22. Processing MPU Commands on the Audio Side

Replay command writes in chronological order.

For the initial validation:

```text
0xFF    MPU reset
0x3F    enter UART
```

must at least affect replay state.

Illustrative:

```rust
fn replay_command(&mut self, value: u8) {
    match value {
        0xFF => {
            self.uart = false;
        }

        0x3F => {
            self.uart = true;
        }

        _ => {}
    }
}
```

Use shared pure command-transition logic between frontend and replay where practical.

Share code.

Do not share mutable state.

---

# 23. Processing MPU Data Writes

When replaying:

```rust
MpuEvent::DataWrite(byte)
```

if historical replay state says:

```text
UART active
```

then deliver the byte to the MIDI parser/synth at that event's logical time.

If UART was inactive:

```text
do not deliver as MIDI
```

This is why command and data writes must share one queue.

---

# 24. MPU Reset Does Not Reset the MIDI Synth

When audio replay encounters:

```text
CommandWrite(0xFF)
```

reset MPU replay protocol state.

Do not automatically:

```text
kill every synth voice
reset all controllers
reset all patches
```

unless an actual MIDI message instructing the synthesizer to do so was sent.

The MPU interface and connected MIDI synthesizer are distinct devices conceptually.

---

# 25. MIDI Byte Timing Model

For this validation, define:

> A UART-mode MPU data byte is considered delivered to the MIDI synthesizer at the `AudioTime` of the guest `OUT 330h` instruction.

Do not yet emulate:

- 31.25 kbit/s transmission;
- serial framing;
- transmit FIFO delay;
- cable delay.

This timing model is intentionally simpler than physical UART serialization but is sufficient for validating deterministic architecture.

---

# 26. `AudioTime` to Sample Frame Mapping

The existing synth API may use logical frame positions.

Create one explicit conversion:

```rust
fn audio_time_to_frame(
    time: AudioTime,
    sample_rate: u32,
) -> u64
```

Use integer/fixed-point math.

Do not derive event frame from:

```text
current PCM production frontier
```

The event's logical sample position comes from its timestamp.

---

# 27. Preserve Event Placement Within Service Intervals

Suppose:

```text
last rendered = 100.000 ms
now           = 102.000 ms
```

and queue contains:

```text
100.300 DataWrite(90)
100.310 DataWrite(3C)
100.320 DataWrite(7F)

101.200 DataWrite(80)
101.210 DataWrite(3C)
101.220 DataWrite(00)
```

The renderer must preserve those times.

If the synth supports future timestamped events through `write_at(frame, byte)`, use that facility.

Do not collapse all events to:

```text
102.000 ms
```

merely because that is when service happens.

---

# 28. Architecture-Neutral `AudioRuntime`

Do not create:

```text
ValidationAudioRuntime
```

unless unavoidable.

Create the intended runtime:

```rust
struct AudioRuntime {
    timeline: AudioTimeline,
    sources: ...,
    mixer: Mixer,
    sink: Sink,
}
```

The exact storage mechanism for sources may remain simple.

For this phase:

```text
sources:
    MidiSource
```

Later:

```text
sources:
    MidiSource
    OplSource
    SbSource
    GusSource
```

The runtime must not know DOS-specific MPU semantics beyond invoking the registered source.

---

# 29. `AudioTimeline`

Introduce a small timeline object if useful.

Possible responsibilities:

```text
last serviced AudioTime
logical render frontier
frame conversion
```

Do not put HDA cursor state into it.

Logical timeline and sink timeline remain distinct.

---

# 30. Canonical Mixer

Use the existing canonical mixer concept rather than bypassing it and sending MIDI PCM directly to HDA.

For this validation:

```text
MidiSource
    |
    v
CanonicalMixer
    |
    v
HDA Sink
```

Even with one source, keep the mixer boundary.

This validates the final layering.

---

# 31. Audio Sink Remains a Separate Layer

Reuse the experimental HDA sink.

Do not make `MidiSource` know:

```text
HDA cursor
BDL
preroll
hardware reset
```

The source produces logical PCM.

The sink manages real-time transport.

---

# 32. AudioTime on `arch-metal`

Expose architecture-provided monotonic `AudioTime`.

Reuse the HPET infrastructure from:

```text
arch-metal/src/irq.rs
```

Prefer:

```text
HPET-derived monotonic time
```

where available.

Provide a reasonable fallback.

Do not derive MIDI timestamps from:

```text
delivered timer IRQ count
```

---

# 33. Preserve Existing `take_pending_ticks()`

Do not remove the existing corrected pending-tick mechanism yet.

It may still drive:

```text
DOS timers
virtual PIT
other world advancement
```

Separate it from audio timing.

```text
take_pending_ticks()
    |
guest/world timing


AudioTime::now()
    |
audio timestamps
audio renderer logical time
```

---

# 34. Deterministic Audio Service

Use the existing physical 1 kHz system timer.

Initial service cadence:

```text
500 Hz
```

meaning approximately every second timer interrupt.

This is a wakeup cadence only.

The service must do:

```rust
let now = AudioTime::now();
```

and determine actual elapsed logical time.

Never assume:

```text
one service call = exactly 2 ms
```

---

# 35. Timer IRQ Audio Flow

Conceptually:

```text
physical timer IRQ
       |
       v
500 Hz divider says service
       |
       v
AudioRuntime::service()
       |
       +-- read AudioTime
       +-- determine logical interval
       +-- advance MidiSource
       +-- mix PCM
       +-- submit to HDA
       +-- service sink state
```

The ordinary kernel event loop is not part of this PCM continuity path.

---

# 36. Hard IRQ Restrictions

Everything required by normal service must already exist.

Do not perform:

- heap allocation;
- filesystem access;
- SoundFont parsing;
- GM bank loading;
- synthesizer construction;
- paging/mapping work;
- BIOS calls;
- sleeping;
- blocking locks.

Required data should already be initialized and resident.

---

# 37. Existing HDA Preroll

Retain the existing preroll mechanism where compatible.

Deterministic audio scheduling does not eliminate preroll.

The sink still needs safe startup headroom.

---

# 38. Remove Elapsed-Gap Preroll Invalidations

Disable or replace logic equivalent to:

```rust
if elapsed_ms > MAX_PREROLL_GAP_MS {
    discard_preroll();
}
```

A delayed service interval does not itself imply discontinuity.

Ask instead:

```text
Can the complete required MIDI/source interval be reconstructed?
```

If yes and HDA has not exhausted valid PCM:

```text
continuity remains valid
```

---

# 39. Preserve True Underrun Recovery

Do not weaken actual HDA underrun handling.

Distinguish:

```text
renderer temporarily late
but HDA still buffered
```

from:

```text
HDA consumed beyond valid queued PCM
```

Only the second means physical continuity was lost.

---

# 40. Blocking Operations

Retain the experimental blocking-operation transport handling.

Adapt ownership so blocking hooks can access the sink through `AudioRuntime` or a proper sink control interface.

Do not make the DOS MPU source responsible for this.

---

# 41. Make Optional Audio Hardware Absent

For this validation kernel:

```text
MPU-401 present
SB absent
GUS absent
```

Do not implement dummy SB IRQs.

Do not expose fake SB hardware just to satisfy DOOM.

Configure DOOM for:

```text
Music:
    General MIDI
    port 330h

Sound effects:
    None
```

If the current environment automatically advertises SB/GUS, adjust validation composition so these devices are not installed.

---

# 42. Keep Core PC Hardware Normal

Do not disable:

```text
PIT
PIC
keyboard
mouse
VM86 interrupt virtualization
ordinary DOS timing
```

Only optional expansion audio hardware is absent.

---

# 43. Concrete Coding Plan

## Phase 1: Baseline branch

1. Create validation branch from `experiment/audio-preroll-resume-gate`.
2. Build and boot it unchanged.
3. Verify current DOOM MIDI behavior.
4. Record current HDA/preroll diagnostics.
5. Record current USB/SMM timing behavior where reproducible.

Do not change behavior before obtaining baseline data.

---

## Phase 2: Introduce general timing types

Add:

```text
AudioTime
TimedEvent<T>
RenderMode
```

in an architecture-neutral module.

Keep APIs minimal.

Compile without changing existing behavior.

---

## Phase 3: Add reusable fixed event queue

Implement:

```rust
FixedEventQueue<T, const N: usize>
```

Requirements:

- fixed storage;
- FIFO;
- explicit full;
- peek;
- pop;
- depth;
- high-water;
- overflow count.

Add unit tests.

Test equal-timestamp insertion ordering indirectly through FIFO semantics.

---

## Phase 4: Expose `arch-metal` monotonic audio time

In or near:

```text
arch-metal/src/irq.rs
```

reuse existing retained HPET state.

Expose an inexpensive monotonic read.

Verify:

```text
same function usable from VM86 I/O handling
same function usable from timer IRQ
```

Do not modify guest timer behavior yet.

---

## Phase 5: Introduce the final `AudioRuntime` skeleton

Create the intended runtime structure rather than a MIDI-only validation runtime.

Initial responsibilities:

```text
logical audio timeline
source advancement
canonical mixer
sink
```

For now it contains one registered source.

Compile without moving rendering yet.

---

## Phase 6: Define `AudioSource`

Create the common source contract.

Adapt the shape to existing mixer APIs.

Do not yet add SB/GUS implementations.

Create only:

```text
MidiSource
```

---

## Phase 7: Change DOS audio hardware lifetime

Locate DOS personality/machine initialization.

Move MPU creation to:

```text
DOS personality startup
```

if it is currently tied to program launch or lazy first use.

Ensure the MPU remains alive across program exits.

Remove program-exit logic that destroys or resets it.

---

## Phase 8: Preinitialize the MIDI synth

At DOS personality initialization:

1. obtain resident GM bank;
2. create MIDI synth;
3. initialize it fully;
4. create MIDI source;
5. publish source into `AudioRuntime`.

Do not initialize the synth in the timer service.

Remove lazy initialization from runtime MIDI processing.

---

## Phase 9: Refactor `lib/sound/src/mpu401.rs`

Separate:

```text
synchronous guest protocol
```

from:

```text
deferred MIDI history
```

Retain:

- UART state;
- reset;
- ACK;
- status;
- command processing;
- port ownership.

Remove internal deferred output MIDI FIFO.

Update tests.

---

## Phase 10: Add `MpuEvent`

Define:

```rust
enum MpuEvent {
    DataWrite(u8),
    CommandWrite(u8),
}
```

Create one:

```text
FixedEventQueue<TimedEvent<MpuEvent>, N>
```

for the MPU device.

---

## Phase 11: Queue both output ports

Modify MPU guest I/O dispatch.

For `330h`:

```text
read AudioTime
synchronously apply frontend Data write
queue DataWrite
```

For `331h`:

```text
read AudioTime
synchronously apply frontend Command write
queue CommandWrite
```

Do not queue reads.

---

## Phase 12: Keep queue publication bounded

Use:

```text
frontend operation
construct event
brief publication critical section
```

Do not hold interrupts disabled while running large protocol operations.

Instrument overflow.

---

## Phase 13: Remove old `Mpu::tick()` MIDI delivery

Stop draining MPU data from the event loop.

Delete or bypass:

```text
Mpu401::take()
Mpu::tick() -> Synth::write_at()
```

The new MIDI source becomes the only deferred MIDI consumer.

---

## Phase 14: Implement `MpuReplay`

Create audio-side MPU replay state.

At minimum:

```rust
struct MpuReplay {
    uart: bool,
}
```

Implement command transitions.

Prefer sharing a pure helper for command-state transitions with the synchronous frontend where reasonable.

Do not share actual runtime state.

---

## Phase 15: Implement `MidiSource`

`MidiSource` owns:

```text
MpuReplay
Synth
event queue consumer
logical render frontier
```

It consumes events only when their timestamp belongs within the interval being advanced.

---

## Phase 16: Implement timestamp-correct MIDI delivery

Convert each MPU event timestamp to logical synth frame position.

Feed MIDI bytes using the existing synth's timed-write facility where possible.

Verify:

```text
multiple MIDI writes received between two timer services
```

retain their individual logical positions.

---

## Phase 17: Keep synthesis running without events

Test source advancement with:

```text
NoteOn
then no MPU writes for hundreds of milliseconds
```

PCM must continue.

Add a focused unit/integration test if practical.

---

## Phase 18: Connect `MidiSource` to canonical mixer

Do not send synth PCM directly to HDA.

Use:

```text
MidiSource
    |
CanonicalMixer
    |
Sink
```

even with only one source.

---

## Phase 19: Move audio sink ownership into `AudioRuntime`

Refactor existing sink ownership away from event-loop local state where needed.

The timer service must be able to safely access:

```text
mixer
source
sink
timeline
```

Use existing kernel ownership conventions.

Avoid unrestricted global mutable aliases.

---

## Phase 20: Preserve blocking-operation sink access

Refactor the existing blocking hook to use the new sink/runtime ownership.

Verify:

```text
pause
blocking operation
re-preroll
resume
```

still works.

---

## Phase 21: Add 500 Hz timer-driven service

Modify the physical 1 kHz timer path.

Every second service opportunity:

```rust
audio_runtime.service(AudioTime::now());
```

Do not pass fixed `2 ms`.

Do not derive `now` from service-count increments.

---

## Phase 22: Remove event-loop audio dependency

Disable event-loop MIDI rendering/HDA feeding in the validation configuration.

Retain event-loop work for:

```text
guest timers
other devices
display
kernel work
```

Verify HDA continuity no longer depends on event-loop frequency.

---

## Phase 23: Remove elapsed-gap preroll reset

Disable the experimental gap heuristic.

Retain actual cursor/headroom-based underrun detection.

---

## Phase 24: Add instrumentation

Track:

### MPU queue

```text
events pushed
data writes
command writes
current depth
high-water mark
overflow
```

### MIDI source

```text
events consumed
MIDI bytes accepted
MIDI bytes ignored because UART inactive
maximum event age
frames rendered
```

### Scheduler

```text
service count
maximum AudioTime gap
average service cost
maximum service cost
```

### HDA

```text
written frames
consumed frames
minimum headroom
maximum headroom
preroll starts
underruns
recoveries
```

Avoid expensive logging in the IRQ.

Use fixed counters and optional trace rings.

---

# 44. Unit Tests

## 44.1 Queue ordering

Input:

```text
Data
Data
Reset
UART
Data
```

Output order must match exactly.

---

## 44.2 Equal timestamps

Push:

```text
T Data(90)
T Data(3C)
T Data(7F)
T Command(FF)
```

Pop in exactly that order.

---

## 44.3 Frontend UART state

Verify:

```text
Reset -> UART false
UART command -> UART true
Reset again -> UART false
```

---

## 44.4 Replay UART state

Apply identical command sequence to `MpuReplay`.

State transitions must match the frontend's audio-relevant UART state.

---

## 44.5 Frontend/replay consistency

Feed identical output-write sequences to both models.

After every command event:

```text
frontend UART state
    ==
replay UART state
```

ACK state is intentionally frontend-only.

---

## 44.6 Historical reset ordering

Input:

```text
UART
Data 90
Data 3C
Data 7F
Reset
Data 80
UART
Data 90
```

Expected:

```text
first note bytes accepted
reset disables UART
post-reset data before UART ignored
new data after UART accepted
```

---

# 45. Pre-DOOM Runtime Tests

Before running DOOM:

1. boot kernel;
2. verify `AudioRuntime` initialized before timer servicing;
3. verify MIDI source registered;
4. verify synth already initialized;
5. verify event queue empty;
6. verify HDA starts correctly when PCM begins;
7. verify no allocation occurs from timer audio path;
8. verify no SB/GUS hardware is exposed;
9. verify MPU ports remain present across multiple DOS program launches;
10. verify exiting one DOS program does not reset MPU hardware.

---

# 46. MPU Detection Test

Use a small utility or DOOM setup.

Verify synchronous:

```text
OUT reset
read ACK
OUT UART
read ACK
```

Temporarily disable deterministic audio rendering and verify detection still works.

This proves:

```text
guest-visible MPU protocol
    !=
audio renderer
```

---

# 47. DOOM Configuration

Configure:

```text
Music:
    General MIDI

MPU port:
    330h

Sound effects:
    None
```

Do not add fake Sound Blaster support merely to get through setup if another configuration route is available.

The intended validation machine really has no SB installed.

---

# 48. First DOOM Validation

Use familiar music such as:

```text
menu/title music
E1M1
```

Listen for:

- tempo instability;
- pitch instability;
- missing notes;
- stuck notes;
- duplicated fragments;
- MIDI parser corruption;
- reset-related corruption;
- periodic glitches tied to event-loop cadence;
- HDA startup truncation.

---

# 49. VM86 Workload Variation

While music plays:

```text
move through complex scenes
trigger screen transitions
enter/leave menus
generate keyboard activity
vary game workload
```

The music should not change merely because VM86/kernel event-loop cadence changes.

---

# 50. USB/SMM Reproduction

On affected hardware:

1. reproduce USB legacy keyboard-induced stalls;
2. run DOOM music;
3. generate keyboard activity;
4. inspect `AudioTime` gaps;
5. inspect HDA headroom;
6. inspect underruns.

If HDA retains sufficient queued PCM:

```text
larger timer-service gap
    |
MIDI reconstructs elapsed interval
    |
no audible break
```

If HDA actually exhausts valid PCM:

```text
true underrun
    |
recovery
```

---

# 51. Deliberate Service-Skip Test

Add a debug control:

```text
skip next N audio service opportunities
```

Do not stop:

```text
AudioTime
HDA consumption
guest execution
```

Example:

```text
100 ms service
102 ms service
skip
skip
skip
skip
skip
114 ms service
```

The renderer must discover:

```text
12 ms logical interval
```

not:

```text
2 ms
```

If enough HDA headroom exists, the reconstructed interval should remain continuous.

---

# 52. Validate Persistent Hardware Lifetime

Run:

```text
program A
exit
program B
exit
DOOM
exit
another MIDI program
```

Verify the same emulated MPU instance remains present.

Do not perform hidden reset at executable boundaries.

Optionally test a program that leaves MIDI state active and verify that process exit itself does not magically send reset/all-notes-off behavior.

---

# 53. Validation Pass Criteria

The phase passes when:

- [ ] `AudioTime` exists independently of event-loop tick counts.
- [ ] `TimedEvent<T>` is reusable.
- [ ] `FixedEventQueue<T, N>` is reusable.
- [ ] `AudioRuntime` is not MIDI-specific.
- [ ] `AudioSource` is suitable for future devices.
- [ ] MPU-401 exists for the entire DOS personality lifetime.
- [ ] MIDI synth exists for the DOS personality lifetime.
- [ ] GM bank loading occurs outside deterministic audio service.
- [ ] synth initialization occurs before deterministic service can access it.
- [ ] ordinary DOS program exit does not reset MPU hardware.
- [ ] both `330h` and `331h` writes enter one MPU event queue.
- [ ] synchronous guest-visible MPU protocol remains functional.
- [ ] frontend and replay UART states remain consistent.
- [ ] equal-timestamp event ordering is FIFO.
- [ ] old MPU internal MIDI FIFO is removed or bypassed.
- [ ] event-loop `Mpu::tick()` no longer delivers MIDI.
- [ ] MIDI source continues rendering when its event queue is empty.
- [ ] canonical mixer remains between source and sink.
- [ ] physical timer drives deterministic audio service.
- [ ] actual `AudioTime` determines elapsed logical interval.
- [ ] long scheduler gap alone does not discard valid preroll.
- [ ] true HDA underrun remains separately detected.
- [ ] queue overflow does not occur under DOOM.
- [ ] DOOM General MIDI works without SB/GUS.
- [ ] DOOM music remains stable under VM86 workload variation.
- [ ] USB/SMM disturbance does not directly modulate MIDI timing while sink headroom survives.

---

# 54. What May Remain Temporary

It is acceptable for this phase to contain temporary composition such as:

```text
only MidiSource registered
validation build flag disabling SB/GUS
debug service-skip controls
extra tracing
```

It should not contain temporary architectural substitutions such as:

```text
MidiValidationRuntime instead of AudioRuntime
MidiOnlyClock instead of AudioTime
MpuOnlyQueue implementation instead of reusable queue
direct MidiSource -> HDA bypass
program-owned MPU hardware
lazy IRQ-side synth construction
```

---

# 55. Implementation Restraint

Do not generalize beyond what is already reasonably clear.

Good generalization now:

```text
AudioTime
TimedEvent<T>
fixed event queue
AudioSource
RenderMode
AudioRuntime
canonical mixer boundary
sink boundary
personality-lifetime hardware ownership
```

Premature generalization now:

```text
one universal enum for every future sound event
dynamic plugin framework for audio sources
complex generic device graph
global cross-device scheduler before a second device exists
generic mutable-memory history framework before SB/GUS
```

The objective is:

> build the correct foundation once, but implement only one actual device source.

---

# 56. Likely Next Phase After Validation

If the MIDI/DOOM validation succeeds, preserve the infrastructure and add the next source.

Two sensible next steps are:

```text
OPL
```

because it has no mutable DMA-memory problem,

or:

```text
Sound Blaster
```

because it provides the most important DOS digital-audio compatibility milestone.

SB will additionally require:

```text
timestamped SB state changes
virtual DMA timing
staging FIFO
guest IRQ semantics
AdvanceOnly
```

Those should be built on the architecture proven here.

---

# 57. Decisions to Fold Back Into the Main Architecture Document

After successful validation, review the master deterministic audio architecture and incorporate these conclusions explicitly.

## 57.1 Personality-lifetime device ownership

State clearly that emulated hardware generally belongs to the active personality/machine lifetime rather than individual program lifetime.

---

## 57.2 No implicit program-exit hardware reset

Document that process exit must not silently reset emulated sound cards unless the personality deliberately models such a platform-level action.

---

## 57.3 Preinitialization of real-time dependencies

Strengthen the rule that every renderer dependency must be initialized before entering real-time service, including synthesizers and immutable patch resources.

---

## 57.4 Synchronous plus deferred handling

Document explicitly that one guest operation may:

```text
mutate synchronous guest-visible state
+
emit a timestamped renderer event
```

at the same logical time.

---

## 57.5 Per-device ordering domains

Add the rule that interacting operations of one device must share an ordered historical stream.

For MPU-401 this includes both command and data ports.

---

## 57.6 Raw versus semantic queued events

Clarify that each device should queue the lowest semantic level needed to faithfully reconstruct audio-relevant historical behavior.

This may differ by device.

For MPU-401, raw command/data writes are appropriate.

For MIDI synthesis itself, the resulting MIDI byte stream may then be parsed on the audio side.

---

## 57.7 Persistent autonomous source evolution

Strengthen the distinction:

```text
event queue supplies changes
source engine supplies continuous evolution
```

An empty queue never inherently means the source is silent.

---

## 57.8 Interface reset versus downstream-device reset

Document that reset commands must be interpreted at the correct hardware layer.

Resetting an interface does not automatically imply resetting every downstream emulated component.

---

## 57.9 Validation-first source migration

Consider documenting MPU-401/MIDI as the recommended first implementation source because it validates:

- timestamping;
- device event ordering;
- deterministic service;
- autonomous rendering;
- source/mixer/sink separation;

without requiring mutable DMA history.

---

# 58. Final Validation Data Flow

At completion:

```text
RetroOS boot
    |
load immutable GM bank
    |
DOS personality starts
    |
    +-- create MPU frontend
    +-- create MPU event queue
    +-- create MpuReplay
    +-- create MIDI synth
    +-- create MidiSource
    +-- register source in AudioRuntime
    +-- initialize canonical mixer
    +-- attach HDA sink
    |
    v

DOOM
 |
 | OUT 331h / OUT 330h
 |
 v
synchronous MPU frontend
 |
 | immediate ACK/status/UART state
 |
 +-----------------------------------+
                                     |
                               timestamp raw write
                                     |
                                     v
                          FixedEventQueue<MpuEvent>
                                     |
                        - - timer boundary - -
                                     |
                                     v
                              AudioRuntime
                                     |
                                     v
                                MidiSource
                                     |
                           replay MPU history
                                     |
                              MIDI byte stream
                                     |
                              persistent Synth
                                     |
                      continues between all events
                                     |
                                     v
                              canonical PCM
                                     |
                                     v
                            CanonicalMixer
                                     |
                                     v
                                HDA sink
                                     |
                      preroll / running / recovery
                                     |
                                     v
                                    DAC
```

The architecture is validated when the following remains true even during irregular VM86/event-loop behavior:

```text
guest writes determine WHAT changed

AudioTime determines WHEN it changed

the device queue preserves ORDER

the source reconstructs HISTORY

the source evolves between events

the mixer produces PCM

the sink independently manages real-time playback
```

That is the foundation on which the remaining RetroOS audio devices should be implemented.
