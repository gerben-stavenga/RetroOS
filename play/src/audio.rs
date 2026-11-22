//! SDL playback for the kernel mixer. The audio callback advances the cursor.
use kernel::kernel::sound::{self, Device, Frame};
use sdl2::audio::{AudioCallback, AudioDevice, AudioSpecDesired};
use std::sync::{Arc, Mutex};

struct Playback {
    ring: Vec<Frame>,
    played: u64,
    written: u64,
    active: bool,
}

struct Callback(Arc<Mutex<Playback>>);

impl AudioCallback for Callback {
    type Channel = i16;
    fn callback(&mut self, samples: &mut [i16]) {
        samples.fill(0);
        let mut playback = self.0.lock().unwrap();
        if !playback.active { return; }
        let count = samples.len() / 2;
        let ready = playback.written.saturating_sub(playback.played).min(count as u64);
        for (i, pair) in samples.chunks_exact_mut(2).take(ready as usize).enumerate() {
            let index = (playback.played + i as u64) % playback.ring.len() as u64;
            pair.copy_from_slice(&playback.ring[index as usize]);
        }
        playback.played += count as u64;
    }
}

struct Output {
    playback: Arc<Mutex<Playback>>,
    rate: u32,
    period: usize,
    sampled: u64,
}

impl Device for Output {
    fn rate(&self) -> u32 { self.rate }
    fn block_frames(&self) -> usize { self.period }

    fn start(&mut self) {
        let mut playback = self.playback.lock().unwrap();
        playback.played = 0;
        playback.written = 0;
        playback.active = true;
        self.sampled = 0;
    }

    fn halt(&mut self) {
        self.playback.lock().unwrap().active = false;
    }

    fn frames_played(&mut self) -> u64 {
        let played = self.playback.lock().unwrap().played;
        let frames = played - self.sampled;
        self.sampled = played;
        frames
    }

    fn discard(&mut self) {
        let mut playback = self.playback.lock().unwrap();
        playback.written = playback.played;
    }

    fn submit(&mut self, first_frame: u64, frames: &[Frame]) {
        let mut playback = self.playback.lock().unwrap();
        let end = first_frame + frames.len() as u64;
        // SDL may have consumed silence since the last kernel cursor sample.
        let first = first_frame.max(playback.played);
        if first >= end { return; }
        let capacity = playback.ring.len() as u64;
        for frame in playback.written.max(playback.played)..first {
            playback.ring[(frame % capacity) as usize] = [0; 2];
        }
        for (i, &frame) in frames[(first - first_frame) as usize..].iter().enumerate() {
            let at = (first + i as u64) % capacity;
            playback.ring[at as usize] = frame;
        }
        playback.written = end;
    }
}

pub fn open(sdl: &sdl2::Sdl) -> Result<AudioDevice<impl AudioCallback<Channel = i16>>, String> {
    let audio = sdl.audio()?;
    let desired = AudioSpecDesired { freq: Some(48_000), channels: Some(2), samples: Some(512) };
    let mut device = audio.open_playback(None, &desired, |spec| Callback(Arc::new(Mutex::new(Playback {
        ring: vec![[0; 2]; usize::from(spec.samples) * sound::HOST_BUFFER_BLOCKS],
        played: 0,
        written: 0,
        active: false,
    }))))?;
    let rate = device.spec().freq as u32;
    let period = usize::from(device.spec().samples);
    let playback = device.lock().0.clone();
    sound::install_host_output(Box::new(Output { playback, rate, period, sampled: 0 }));
    device.resume();
    Ok(device)
}
