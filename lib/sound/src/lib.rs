//! `//lib:sound` — emulated sound cards as passive, host-agnostic state
//! machines, plus the voice engine they share.
//!
//! Nothing in this crate reaches out. A card has exactly four ports, and the
//! host drives every one of them:
//!
//!  - **registers** — `owns` / `port_in` / `port_out`, pure functions of card
//!    state.
//!  - **clock** — passed *as an argument* to `tick`, never read. The same
//!    discipline [`Engine::mix_frame`] already uses for its rate.
//!  - **IRQ** — the card reports that it wants service; the host owns the
//!    interrupt controller and decides what that means.
//!  - **sample bytes** — a card names its *own* memory and the DMA registers
//!    the guest programmed into it, and nothing else. No guest physical
//!    address, no 8237, no page register: it knows a transfer is armed, never
//!    where the bytes live. The host moves them.
//!
//! That is the whole contract. A host with a completely different memory
//! model, clock, or interrupt path hooks a card up by calling these and
//! supplying bytes — there is no trait to implement and no callback to
//! register. See `SOUND_LIB_DESIGN.md` at the repo root for why each of those
//! lines sits where it does.
//!
//! The same discipline covers the OUTPUT side ([`sink`]): a ring of PCM plus
//! its counters, driven by the host with "here are frames" and "a block
//! played". A ring buffer and some arithmetic are no more machine-specific
//! than a card's register file is.
//!
//! What deliberately stays *outside*: WHICH sink to play into, what a DMA
//! channel points at, and how loud one card should be against another.
//! Hosts that want a reusable latency controller can use [`pacer`]; choosing
//! whether to use it and what latency to target is still host policy.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod sink;
pub mod event_queue;
pub mod timeline;
pub mod pacer;
pub mod engine;
pub mod gus;
pub mod mpu401;
pub mod opl;
pub mod midi;
pub mod pat;
pub mod sb;
pub mod speaker;

pub use engine::{
    Addressing, Engine, Events, LoopMode, MAX_VOICES, Ramp, Voice, VoiceFilter, voice,
    volume,
};
pub use pacer::{Pacer, RATE_FP_SHIFT};
