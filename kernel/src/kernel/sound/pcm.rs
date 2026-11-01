//! Buffered PCM sources, mixed by the existing audio service on its owning core.
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use crate::kernel::media::Shared;

const CAPACITY: usize = 32768;
const INVALID: u32 = 0xc000000d;
struct Stream {
    frames: VecDeque<(i16,i16)>,
    rate: u32,
    channels: u32,
    bits: u32,
    phase: u64,
    consumed: u64,
    last_frame: u64,
    output_rate: u32,
    paused: bool,
    volume: u32,
}
static STREAMS: Shared<Vec<Arc<Shared<Stream>>>> = Shared::new(Vec::new());
#[derive(Default)]
pub(crate) struct Handles(Vec<Option<Arc<Shared<Stream>>>>);
impl Handles {
    pub(crate) fn clear(&mut self) {
        let mut streams = STREAMS.lock();
        streams.retain(|s| !self.0.iter().flatten().any(|owner| Arc::ptr_eq(s,owner)));
        self.0.clear();
    }
}
impl Drop for Handles { fn drop(&mut self) { self.clear(); } }
impl Stream {
    fn played(&self, frontier: u64) -> u64 {
        let ahead = self.last_frame.saturating_sub(frontier);
        self.consumed.saturating_sub(ahead * u64::from(self.rate) / u64::from(self.output_rate.max(1)))
    }
    fn mix(&mut self, frames: &mut [(i32,i32)], rate: u32, base: u64) {
        if self.paused { return; }
        self.output_rate = rate;
        let step = (u64::from(self.rate) << 32) / u64::from(rate.max(1));
        for (i, frame) in frames.iter_mut().enumerate() {
            let Some(&(l,r)) = self.frames.front() else { self.phase = 0; break; };
            frame.0 += i32::from(l) * (self.volume & 65535) as i32 / 65535;
            frame.1 += i32::from(r) * (self.volume >> 16) as i32 / 65535;
            self.phase += step;
            let count = (self.phase >> 32) as usize;
            self.phase &= 0xffff_ffff;
            let count = count.min(self.frames.len());
            self.frames.drain(..count);
            self.consumed += count as u64;
            self.last_frame = base + i as u64 + 1;
        }
    }
}
pub(super) fn mix(frames: &mut [(i32,i32)], rate: u32, base: u64) {
    // Registration/removal happens on the kernel core, never on the media core.
    // Holding the registry keeps every allocation alive until mixing finishes.
    let Some(streams) = STREAMS.try_lock() else { return; };
    for stream in streams.iter() {
        if let Some(mut stream) = stream.try_lock() { stream.mix(frames,rate,base); }
    }
}
pub(crate) fn call<A: crate::Arch>(machine: &mut A, handles: &mut Handles, args: [u32;6]) -> u32 {
    let [op,handle,data,size,_,out] = args;
    if op == 0 {
        if data == 0 || out == 0 { return INVALID; }
        let rate = machine.read::<u32>(data as usize);
        let channels = machine.read::<u32>(data as usize+4);
        let bits = machine.read::<u32>(data as usize+8);
        if !(4000..=192000).contains(&rate) || !matches!(channels,1|2) || !matches!(bits,8|16) { return INVALID; }
        if handles.0.iter().flatten().count() >= 16 { return 0xc000009a; }
        let stream = Arc::new(Shared::new(Stream { frames:VecDeque::with_capacity(CAPACITY),rate,channels,bits,
            phase:0,consumed:0,last_frame:0,output_rate:rate,paused:false,volume:u32::MAX }));
        STREAMS.lock().push(stream.clone());
        let i = handles.0.iter().position(Option::is_none).unwrap_or(handles.0.len());
        if i == handles.0.len() { handles.0.push(None); }
        handles.0[i] = Some(stream);
        machine.write::<u32>(out as usize,i as u32+1);
        return 0;
    }
    if op == 6 && handle == 0 {
        for owner in handles.0.iter().flatten() { owner.lock().volume = data; }
        return 0;
    }
    let Some(i) = handle.checked_sub(1).map(|i|i as usize) else { return 0xc0000008; };
    let Some(Some(owner)) = handles.0.get(i) else { return 0xc0000008; };
    if op == 5 {
        STREAMS.lock().retain(|s|!Arc::ptr_eq(s,owner));
        handles.0[i] = None;
        return 0;
    }
    let mut stream = owner.lock();
    match op {
        1 => {
            if out == 0 || data == 0 && size != 0 { return INVALID; }
            let stride = stream.channels * stream.bits / 8;
            if size % stride != 0 { return INVALID; }
            let count = (size/stride).min((CAPACITY-stream.frames.len()) as u32);
            for n in 0..count {
                let address = data as usize+(n*stride) as usize;
                let sample = |address| if stream.bits == 8 {
                    (i16::from(machine.read::<u8>(address))-128)*256
                } else { machine.read::<i16>(address) };
                let l = sample(address);
                let r = if stream.channels == 1 {l} else {sample(address+(stream.bits/8) as usize)};
                stream.frames.push_back((l,r));
            }
            machine.write::<u32>(out as usize,count*stride);
        },
        2 => {
            if out == 0 { return INVALID; }
            let bytes = stream.played(super::played_frames()) * u64::from(stream.channels*stream.bits/8);
            machine.write::<u64>(out as usize,bytes);
        },
        3 => { stream.frames.clear();stream.phase=0;stream.consumed=0;stream.last_frame=0; },
        4 => stream.paused = data != 0,
        6 => stream.volume = data,
        _ => return INVALID,
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_waits_for_play_cursor_and_pause_retains_samples() {
        let mut s = Stream {frames: [(100,-100);100].into_iter().collect(),rate:1000,channels:2,bits:16,
            phase:0,consumed:0,last_frame:0,output_rate:1000,paused:true,volume:u32::MAX};
        s.mix(&mut [(0,0);10],1000,0);
        assert_eq!(s.frames.len(),100);
        s.paused=false;
        let mut frames=[(0,0);100];s.mix(&mut frames,1000,200);
        assert_eq!(frames,[(100,-100);100]);
        assert_eq!(s.played(200),0);
        assert_eq!(s.played(250),50);
        assert_eq!(s.played(300),100);
        assert_eq!(s.played(400),100);
    }
    #[test]
    fn resampling_consumes_source_frames_at_the_source_rate() {
        let mut s = Stream {frames: [(100,100);100].into_iter().collect(),rate:1000,channels:1,bits:8,
            phase:0,consumed:0,last_frame:0,output_rate:2000,paused:false,volume:u32::MAX};
        s.mix(&mut [(0,0);100],2000,0);
        assert_eq!(s.consumed,50);
        assert_eq!(s.played(50),25);
    }
}
