//! Read-only ISO 9660 filesystem and CD image normalization.
//!
//! The UI/device layer is intentionally absent here.  A future media slot owns
//! insertion and ejection, supplies a [`RandomAccess`] image, and calls
//! [`mount`].  Both cooked `.iso` files and the data track of a single-file
//! CUE/BIN image become the same seekable stream of 2048-byte ISO sectors.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use hadris_iso::sync::read::{DirEntry as IsoDirEntry, Extent, IsoImage};
use hadris_iso::sync::{ErrorKind, Read, Seek, SeekFrom};
use spin::Mutex;

use crate::kernel::vfs::{self, DirEntry, Filesystem, Vnode};

const COOKED_SECTOR: u64 = 2048;
const RAW_SECTOR: u64 = 2352;
const MODE1_PAYLOAD_OFFSET: u64 = 16;

/// A byte-addressable image source.  Device and hosted implementations can
/// satisfy this without copying an entire CD image into RAM.
pub trait RandomAccess: Send + Sync {
    fn len(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, MediaError>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The container presented by an insert operation.
#[derive(Clone, Copy)]
pub enum DiscFormat<'a> {
    /// A concatenation of cooked 2048-byte sectors.
    Iso,
    /// CUE metadata for the accompanying BIN source.
    Cue(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    InvalidCue,
    UnsupportedCue,
    NoDataTrack,
    InvalidImage,
    OutOfBounds,
    Io,
}

impl compact_fmt::Format for MediaError {
    fn format(&self, out: &mut dyn compact_fmt::Write, _: compact_fmt::FormatSpec) -> compact_fmt::Result {
        out.write_str(match self {
            Self::InvalidCue => "InvalidCue",
            Self::UnsupportedCue => "UnsupportedCue",
            Self::NoDataTrack => "NoDataTrack",
            Self::InvalidImage => "InvalidImage",
            Self::OutOfBounds => "OutOfBounds",
            Self::Io => "Io",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackMode {
    Audio,
    Mode1_2048,
    Mode1_2352,
}

impl TrackMode {
    fn stored_sector_size(self) -> u64 {
        match self {
            Self::Mode1_2048 => COOKED_SECTOR,
            Self::Audio | Self::Mode1_2352 => RAW_SECTOR,
        }
    }

    fn is_data(self) -> bool {
        !matches!(self, Self::Audio)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CueTrack {
    pub number: u8,
    pub mode: TrackMode,
    /// File-relative frame of INDEX 00, when present.
    pub index00: Option<u32>,
    /// File-relative frame of INDEX 01.
    pub index01: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CueSheet {
    pub bin_file: Vec<u8>,
    pub tracks: Vec<CueTrack>,
}

impl CueSheet {
    /// Parse the useful subset of CDRWIN CUE syntax.  Metadata commands are
    /// ignored; one `FILE ... BINARY` and AUDIO/MODE1 tracks are supported.
    pub fn parse(bytes: &[u8]) -> Result<Self, MediaError> {
        let text = core::str::from_utf8(bytes).map_err(|_| MediaError::InvalidCue)?;
        let mut bin_file = None;
        let mut tracks: Vec<PartialTrack> = Vec::new();

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            let mut words = line.split_ascii_whitespace();
            let Some(command) = words.next() else {
                continue;
            };
            if command.eq_ignore_ascii_case("FILE") {
                if bin_file.is_some() {
                    return Err(MediaError::UnsupportedCue);
                }
                let (name, kind) = parse_file_line(&line[command.len()..])?;
                if !kind.eq_ignore_ascii_case("BINARY") {
                    return Err(MediaError::UnsupportedCue);
                }
                bin_file = Some(name.as_bytes().to_vec());
            } else if command.eq_ignore_ascii_case("TRACK") {
                let number = words
                    .next()
                    .and_then(|word| word.parse::<u8>().ok())
                    .ok_or(MediaError::InvalidCue)?;
                let mode = match words.next() {
                    Some(word) if word.eq_ignore_ascii_case("AUDIO") => TrackMode::Audio,
                    Some(word) if word.eq_ignore_ascii_case("MODE1/2048") => TrackMode::Mode1_2048,
                    Some(word) if word.eq_ignore_ascii_case("MODE1/2352") => TrackMode::Mode1_2352,
                    _ => return Err(MediaError::UnsupportedCue),
                };
                tracks.push(PartialTrack {
                    number,
                    mode,
                    index00: None,
                    index01: None,
                });
            } else if command.eq_ignore_ascii_case("INDEX") {
                let track = tracks.last_mut().ok_or(MediaError::InvalidCue)?;
                let index = words
                    .next()
                    .and_then(|word| word.parse::<u8>().ok())
                    .ok_or(MediaError::InvalidCue)?;
                let frame = parse_msf(words.next().ok_or(MediaError::InvalidCue)?)?;
                match index {
                    0 => track.index00 = Some(frame),
                    1 => track.index01 = Some(frame),
                    _ => {}
                }
            }
        }

        let bin_file = bin_file.ok_or(MediaError::InvalidCue)?;
        if tracks.is_empty() {
            return Err(MediaError::InvalidCue);
        }
        let mut complete = Vec::with_capacity(tracks.len());
        let mut last_frame = None;
        for track in tracks {
            let index01 = track.index01.ok_or(MediaError::InvalidCue)?;
            if last_frame.is_some_and(|last| index01 <= last) {
                return Err(MediaError::InvalidCue);
            }
            last_frame = Some(index01);
            complete.push(CueTrack {
                number: track.number,
                mode: track.mode,
                index00: track.index00,
                index01,
            });
        }
        Ok(Self {
            bin_file,
            tracks: complete,
        })
    }
}

struct PartialTrack {
    number: u8,
    mode: TrackMode,
    index00: Option<u32>,
    index01: Option<u32>,
}

fn parse_file_line(rest: &str) -> Result<(&str, &str), MediaError> {
    let rest = rest.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"').ok_or(MediaError::InvalidCue)?;
        let name = &quoted[..end];
        let kind = quoted[end + 1..].trim();
        if name.is_empty() || kind.is_empty() {
            return Err(MediaError::InvalidCue);
        }
        Ok((name, kind))
    } else {
        let mut words = rest.split_ascii_whitespace();
        let name = words.next().ok_or(MediaError::InvalidCue)?;
        let kind = words.next().ok_or(MediaError::InvalidCue)?;
        Ok((name, kind))
    }
}

fn parse_msf(value: &str) -> Result<u32, MediaError> {
    let mut fields = value.split(':');
    let minutes = fields
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(MediaError::InvalidCue)?;
    let seconds = fields
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(MediaError::InvalidCue)?;
    let frames = fields
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(MediaError::InvalidCue)?;
    if fields.next().is_some() || seconds >= 60 || frames >= 75 {
        return Err(MediaError::InvalidCue);
    }
    minutes
        .checked_mul(60)
        .and_then(|v| v.checked_add(seconds))
        .and_then(|v| v.checked_mul(75))
        .and_then(|v| v.checked_add(frames))
        .ok_or(MediaError::InvalidCue)
}

/// A seekable, cooked view of one ISO data track.
pub struct DataTrackReader {
    source: Box<dyn RandomAccess>,
    file_offset: u64,
    sectors: u64,
    stored_sector: u64,
    payload_offset: u64,
    position: u64,
}

impl fmt::Debug for DataTrackReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataTrackReader")
            .field("file_offset", &self.file_offset)
            .field("sectors", &self.sectors)
            .field("stored_sector", &self.stored_sector)
            .field("position", &self.position)
            .finish()
    }
}

impl DataTrackReader {
    pub fn open(source: Box<dyn RandomAccess>, format: DiscFormat<'_>) -> Result<Self, MediaError> {
        match format {
            DiscFormat::Iso => {
                if !source.len().is_multiple_of(COOKED_SECTOR) {
                    return Err(MediaError::InvalidImage);
                }
                Ok(Self {
                    sectors: source.len() / COOKED_SECTOR,
                    source,
                    file_offset: 0,
                    stored_sector: COOKED_SECTOR,
                    payload_offset: 0,
                    position: 0,
                })
            }
            DiscFormat::Cue(cue) => Self::open_cue_bin(source, &CueSheet::parse(cue)?),
        }
    }

    fn open_cue_bin(source: Box<dyn RandomAccess>, cue: &CueSheet) -> Result<Self, MediaError> {
        let data_index = cue
            .tracks
            .iter()
            .position(|track| track.mode.is_data())
            .ok_or(MediaError::NoDataTrack)?;
        let track = &cue.tracks[data_index];
        let stored_sector = track.mode.stored_sector_size();

        // A single BIN whose tracks use different stored sector sizes needs a
        // per-span byte map.  Reject that uncommon layout explicitly; mixed
        // mode AUDIO + MODE1/2352 (the usual raw BIN) is fully supported.
        if cue
            .tracks
            .iter()
            .any(|candidate| candidate.mode.stored_sector_size() != stored_sector)
        {
            return Err(MediaError::UnsupportedCue);
        }

        let start_frame = track.index01 as u64;
        let end_frame = if let Some(next) = cue.tracks.get(data_index + 1) {
            next.index00.unwrap_or(next.index01) as u64
        } else {
            source.len() / stored_sector
        };
        if end_frame <= start_frame || !source.len().is_multiple_of(stored_sector) {
            return Err(MediaError::InvalidImage);
        }
        let file_offset = start_frame
            .checked_mul(stored_sector)
            .ok_or(MediaError::InvalidImage)?;
        let sectors = end_frame - start_frame;
        let end = file_offset
            .checked_add(
                sectors
                    .checked_mul(stored_sector)
                    .ok_or(MediaError::InvalidImage)?,
            )
            .ok_or(MediaError::InvalidImage)?;
        if end > source.len() {
            return Err(MediaError::InvalidImage);
        }
        Ok(Self {
            source,
            file_offset,
            sectors,
            stored_sector,
            payload_offset: if track.mode == TrackMode::Mode1_2352 {
                MODE1_PAYLOAD_OFFSET
            } else {
                0
            },
            position: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.sectors * COOKED_SECTOR
    }

    pub fn is_empty(&self) -> bool {
        self.sectors == 0
    }

    fn read_source_exact(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), ErrorKind> {
        while !buf.is_empty() {
            let n = self
                .source
                .read_at(offset, buf)
                .map_err(|_| ErrorKind::Other)?;
            if n == 0 || n > buf.len() {
                return Err(ErrorKind::UnexpectedEof);
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }
}

impl Read for DataTrackReader {
    type Error = ErrorKind;

    fn read(&mut self, buf: &mut [u8]) -> hadris_iso::sync::IoResult<usize, Self::Error> {
        let available = self.len().saturating_sub(self.position);
        let wanted = (buf.len() as u64).min(available) as usize;
        let mut done = 0;
        while done < wanted {
            let logical = self.position;
            let sector = logical / COOKED_SECTOR;
            let within = logical % COOKED_SECTOR;
            let chunk = (wanted - done).min((COOKED_SECTOR - within) as usize);
            let physical =
                self.file_offset + sector * self.stored_sector + self.payload_offset + within;
            self.read_source_exact(physical, &mut buf[done..done + chunk])
                .map_err(hadris_iso::sync::Error::from_source)?;
            self.position += chunk as u64;
            done += chunk;
        }
        Ok(done)
    }
}

impl Seek for DataTrackReader {
    type Error = ErrorKind;

    fn seek(&mut self, pos: SeekFrom) -> hadris_iso::sync::IoResult<u64, Self::Error> {
        let next = match pos {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(delta) => i128::from(self.len()) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if next < 0 || next > i128::from(self.len()) {
            return Err(hadris_iso::sync::Error::from_source(
                ErrorKind::InvalidInput,
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

#[derive(Clone)]
struct OpenFile {
    size: u32,
    extents: Vec<Extent>,
}

struct OpenState {
    next_handle: u64,
    files: BTreeMap<u64, OpenFile>,
}

/// Hadris-backed, read-only filesystem over the normalized data track.
pub struct Iso9660Fs {
    image: IsoImage<DataTrackReader>,
    opens: Mutex<OpenState>,
}

impl Iso9660Fs {
    pub fn open(source: Box<dyn RandomAccess>, format: DiscFormat<'_>) -> Result<Self, MediaError> {
        let reader = DataTrackReader::open(source, format)?;
        let image = IsoImage::open(reader).map_err(|_| MediaError::InvalidImage)?;
        Ok(Self {
            image,
            opens: Mutex::new(OpenState {
                next_handle: 1,
                files: BTreeMap::new(),
            }),
        })
    }

    fn find(&self, path: &[u8]) -> Option<IsoDirEntry> {
        let path = core::str::from_utf8(path).ok()?;
        self.image.find_path(path).ok().flatten()
    }

    fn directory_entries(&self, path: &[u8]) -> Option<Vec<IsoDirEntry>> {
        let dir_ref = if path.is_empty() {
            self.image.root_dir().dir_ref()
        } else {
            let entry = self.find(path)?;
            if !entry.is_directory() {
                return None;
            }
            entry.as_dir_ref(&self.image).ok()?
        };
        self.image
            .open_dir(dir_ref)
            .entries()
            .collect::<Result<Vec<_>, _>>()
            .ok()
    }
}

impl Filesystem for Iso9660Fs {
    fn open(&self, path: &[u8]) -> Option<Vnode> {
        let entry = self.find(path)?;
        if !entry.is_file() || entry.total_size() > u32::MAX as u64 {
            return None;
        }
        let mut state = self.opens.lock();
        let handle = state.next_handle;
        state.next_handle = state.next_handle.checked_add(1).unwrap_or(1);
        let size = entry.total_size() as u32;
        state.files.insert(
            handle,
            OpenFile {
                size,
                extents: entry.extents().collect(),
            },
        );
        Some(Vnode {
            handle,
            size,
            mode: 0o444,
        })
    }

    fn read(&self, handle: u64, offset: u32, buf: &mut [u8], _size: u32) -> i32 {
        let file = match self.opens.lock().files.get(&handle).cloned() {
            Some(file) => file,
            None => return -9,
        };
        if offset >= file.size {
            return 0;
        }
        let wanted = buf.len().min((file.size - offset) as usize);
        let mut logical = offset as u64;
        let mut done = 0;
        for extent in file.extents {
            let extent_len = extent.length as u64;
            if logical >= extent_len {
                logical -= extent_len;
                continue;
            }
            let n = (wanted - done).min((extent_len - logical) as usize);
            let image_offset = extent.sector.0 as u64 * COOKED_SECTOR + logical;
            if self
                .image
                .read_bytes_at(image_offset, &mut buf[done..done + n])
                .is_err()
            {
                return if done == 0 { -5 } else { done as i32 };
            }
            done += n;
            logical = 0;
            if done == wanted {
                break;
            }
        }
        done as i32
    }

    fn readdir(&self, dir: &[u8], cookie: u64, out: &mut Vec<DirEntry>, max: usize) -> Option<u64> {
        let entries = self.directory_entries(dir)?;
        let mut visible = 0_u64;
        for entry in entries {
            if entry.is_special() {
                continue;
            }
            if visible < cookie {
                visible += 1;
                continue;
            }
            if out.len() >= max {
                return Some(visible);
            }
            let display = entry.display_name();
            let display = strip_iso_version(display.as_ref());
            let bytes = display.as_bytes();
            let name_len = bytes.len().min(100);
            let mut result = DirEntry {
                name: [0; 100],
                name_len,
                size: entry.total_size().min(u32::MAX as u64) as u32,
                is_dir: entry.is_directory(),
                is_symlink: false,
                mode: if entry.is_directory() { 0o555 } else { 0o444 },
                mtime: 0,
                node: 0,
                mount_idx: 0,
            };
            result.name[..name_len].copy_from_slice(&bytes[..name_len]);
            out.push(result);
            visible += 1;
        }
        None
    }

    fn dir_exists(&self, path: &[u8]) -> bool {
        path.is_empty() || self.find(path).is_some_and(|entry| entry.is_directory())
    }

    fn clunk(&self, handle: u64) {
        self.opens.lock().files.remove(&handle);
    }

    fn write(&self, _handle: u64, _offset: u32, _data: &[u8]) -> i32 {
        -1
    }
}

fn strip_iso_version(name: &str) -> &str {
    match name.rsplit_once(';') {
        Some((base, version))
            if !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            base
        }
        _ => name,
    }
}

/// Construct and mount a boot-lifetime optical filesystem.  Replacing/ejecting
/// a live VFS mount is intentionally left to the future media-slot lifecycle.
pub fn mount(
    prefix: &'static [u8],
    source: Box<dyn RandomAccess>,
    format: DiscFormat<'_>,
) -> Result<(), MediaError> {
    let filesystem = Box::leak(Box::new(Iso9660Fs::open(source, format)?));
    vfs::mount(prefix, filesystem);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct Bytes(Vec<u8>);

    impl RandomAccess for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, MediaError> {
            let offset = offset as usize;
            if offset > self.0.len() {
                return Err(MediaError::OutOfBounds);
            }
            let n = buf.len().min(self.0.len() - offset);
            buf[..n].copy_from_slice(&self.0[offset..offset + n]);
            Ok(n)
        }
    }

    #[test]
    fn parses_mixed_mode_cue() {
        let cue = CueSheet::parse(
            br#"
            FILE "game.bin" BINARY
              TRACK 01 MODE1/2352
                INDEX 01 00:00:00
              TRACK 02 AUDIO
                INDEX 00 00:10:00
                INDEX 01 00:12:00
        "#,
        )
        .unwrap();
        assert_eq!(cue.bin_file, b"game.bin");
        assert_eq!(cue.tracks.len(), 2);
        assert_eq!(cue.tracks[0].mode, TrackMode::Mode1_2352);
        assert_eq!(cue.tracks[1].index00, Some(750));
    }

    #[test]
    fn raw_mode1_exposes_only_2048_byte_payloads() {
        let mut bin = vec![0_u8; RAW_SECTOR as usize * 2];
        bin[16..16 + 2048].fill(0x11);
        let second = RAW_SECTOR as usize + 16;
        bin[second..second + 2048].fill(0x22);
        let cue = b"FILE \"disc.bin\" BINARY\nTRACK 01 MODE1/2352\nINDEX 01 00:00:00\n";
        let mut reader = DataTrackReader::open(Box::new(Bytes(bin)), DiscFormat::Cue(cue)).unwrap();
        let mut crossing = [0_u8; 4];
        reader.seek(SeekFrom::Start(2046)).unwrap();
        reader.read(&mut crossing).unwrap();
        assert_eq!(crossing, [0x11, 0x11, 0x22, 0x22]);
    }

    #[test]
    fn audio_only_cue_has_no_iso_track() {
        let cue = b"FILE \"music.bin\" BINARY\nTRACK 01 AUDIO\nINDEX 01 00:00:00\n";
        let error = DataTrackReader::open(
            Box::new(Bytes(vec![0; RAW_SECTOR as usize])),
            DiscFormat::Cue(cue),
        )
        .unwrap_err();
        assert_eq!(error, MediaError::NoDataTrack);
    }

    #[test]
    fn rejects_mixed_stored_sector_sizes() {
        let cue = b"FILE \"odd.bin\" BINARY\nTRACK 01 AUDIO\nINDEX 01 00:00:00\nTRACK 02 MODE1/2048\nINDEX 01 00:01:00\n";
        let error = DataTrackReader::open(
            Box::new(Bytes(vec![
                0;
                RAW_SECTOR as usize * 75 + COOKED_SECTOR as usize
            ])),
            DiscFormat::Cue(cue),
        )
        .unwrap_err();
        assert_eq!(error, MediaError::UnsupportedCue);
    }

    fn both_u16(dst: &mut [u8], value: u16) {
        dst[..2].copy_from_slice(&value.to_le_bytes());
        dst[2..4].copy_from_slice(&value.to_be_bytes());
    }

    fn both_u32(dst: &mut [u8], value: u32) {
        dst[..4].copy_from_slice(&value.to_le_bytes());
        dst[4..8].copy_from_slice(&value.to_be_bytes());
    }

    fn directory_record(dst: &mut [u8], extent: u32, size: u32, flags: u8, name: &[u8]) -> usize {
        let length = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
        dst[..length].fill(0);
        dst[0] = length as u8;
        both_u32(&mut dst[2..10], extent);
        both_u32(&mut dst[10..18], size);
        dst[25] = flags;
        both_u16(&mut dst[28..32], 1);
        dst[32] = name.len() as u8;
        dst[33..33 + name.len()].copy_from_slice(name);
        length
    }

    /// Small ECMA-119 image: PVD, both path tables, root directory, one file.
    fn minimal_iso() -> Vec<u8> {
        const SECTORS: usize = 22;
        let mut iso = vec![0_u8; SECTORS * COOKED_SECTOR as usize];

        let pvd = &mut iso[16 * 2048..17 * 2048];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 1;
        pvd[40..45].copy_from_slice(b"TEST ");
        both_u32(&mut pvd[80..88], SECTORS as u32);
        both_u16(&mut pvd[120..124], 1);
        both_u16(&mut pvd[124..128], 1);
        both_u16(&mut pvd[128..132], 2048);
        both_u32(&mut pvd[132..140], 10);
        pvd[140..144].copy_from_slice(&18_u32.to_le_bytes());
        pvd[148..152].copy_from_slice(&19_u32.to_be_bytes());
        directory_record(&mut pvd[156..190], 20, 2048, 2, &[0]);
        pvd[881] = 1;

        let terminator = &mut iso[17 * 2048..18 * 2048];
        terminator[0] = 255;
        terminator[1..6].copy_from_slice(b"CD001");
        terminator[6] = 1;

        let lpt = &mut iso[18 * 2048..19 * 2048];
        lpt[0] = 1;
        lpt[2..6].copy_from_slice(&20_u32.to_le_bytes());
        lpt[6..8].copy_from_slice(&1_u16.to_le_bytes());
        let mpt = &mut iso[19 * 2048..20 * 2048];
        mpt[0] = 1;
        mpt[2..6].copy_from_slice(&20_u32.to_be_bytes());
        mpt[6..8].copy_from_slice(&1_u16.to_be_bytes());

        let root = &mut iso[20 * 2048..21 * 2048];
        let mut offset = directory_record(root, 20, 2048, 2, &[0]);
        offset += directory_record(&mut root[offset..], 20, 2048, 2, &[1]);
        directory_record(&mut root[offset..], 21, 5, 0, b"HELLO.TXT;1");
        iso[21 * 2048..21 * 2048 + 5].copy_from_slice(b"hello");
        iso
    }

    #[test]
    fn hadris_iso_stream_serves_the_vfs() {
        let filesystem = Iso9660Fs::open(Box::new(Bytes(minimal_iso())), DiscFormat::Iso).unwrap();

        let vnode = Filesystem::open(&filesystem, b"hello.txt").unwrap();
        assert_eq!(vnode.size, 5);
        let mut contents = [0_u8; 8];
        assert_eq!(
            Filesystem::read(&filesystem, vnode.handle, 0, &mut contents, vnode.size),
            5
        );
        assert_eq!(&contents[..5], b"hello");

        let mut entries = Vec::new();
        assert_eq!(
            Filesystem::readdir(&filesystem, b"", 0, &mut entries, 8),
            None
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(&entries[0].name[..entries[0].name_len], b"HELLO.TXT");
        Filesystem::clunk(&filesystem, vnode.handle);
    }
}
