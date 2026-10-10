//! Boot-bundle configuration and declarative filesystem composition.
//! Filesystem images use the same block interface on metal and hosted builds.

use crate::kernel::{
    block::{self, Disk, Volume},
    fs::disk::FilesystemVolume,
    vfs,
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Ro,
    Rw,
    Ram,
}

#[derive(Clone, Debug)]
pub struct Mount {
    pub name: String,
    pub source: String,
    pub path: String,
    pub drive: Option<u8>,
    pub access: Access,
    pub format: String,
    pub partition: Option<usize>,
    pub subdir: String,
    pub grant: String,
}

#[derive(Clone, Debug)]
pub struct Bundle {
    pub source: String,
    pub subdir: String,
}

#[derive(Clone, Default, Debug)]
pub struct Config {
    pub bundle: Option<Bundle>,
    pub mounts: Vec<Mount>,
    pub environment: Vec<u8>,
    pub launch: Vec<(String, String)>,
}

fn canonical(path: &str) -> bool {
    path.starts_with('/')
        && !path.as_bytes().contains(&0)
        && (path == "/"
            || path[1..]
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != ".."))
}

pub fn uuid(value: &str) -> Result<arch_abi::VolumeUuid, &'static str> {
    let mut hex = Vec::new();
    let expected: &[usize] = match value.len() {
        9 => &[4],
        36 => &[8, 13, 18, 23],
        _ => return Err("invalid UUID"),
    };
    for (i, byte) in value.bytes().enumerate() {
        if expected.contains(&i) {
            if byte != b'-' {
                return Err("invalid UUID");
            }
        } else {
            hex.push((byte as char).to_digit(16).ok_or("invalid UUID")? as u8);
        }
    }
    let bytes: Vec<_> = hex.chunks_exact(2).map(|s| s[0] * 16 + s[1]).collect();
    Ok(if bytes.len() == 4 {
        arch_abi::VolumeUuid::Fat(bytes.try_into().unwrap())
    } else {
        arch_abi::VolumeUuid::Ext4(bytes.try_into().unwrap())
    })
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let text = core::str::from_utf8(bytes).map_err(|_| "configuration must be UTF-8")?;
        let mut config = Self::default();
        let mut section = "";
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if line.starts_with('[') {
                section = line
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .ok_or("invalid section")?
                    .trim();
                if section == "bundle" {
                    if config.bundle.is_some() { return Err("duplicate bundle section"); }
                    config.bundle = Some(Bundle { source: String::new(), subdir: "/".into() });
                } else if let Some(name) = section.strip_prefix("mount ") {
                    let name = name
                        .strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .ok_or("mount name must be quoted")?;
                    if name.is_empty() || config.mounts.iter().any(|m| m.name == name) {
                        return Err("duplicate or empty mount name");
                    }
                    if config.mounts.len() == 24 {
                        return Err("too many mounts");
                    }
                    config.mounts.push(Mount {
                        name: name.to_string(),
                        source: String::new(),
                        path: String::new(),
                        drive: None,
                        access: Access::Ro,
                        format: "auto".to_string(),
                        partition: None,
                        subdir: "/".to_string(),
                        grant: "/".to_string(),
                    });
                } else if !section.eq_ignore_ascii_case("launch")
                    && !matches!(section, "system" | "locale" | "sound" | "environment") {
                    return Err("unknown section");
                }
                continue;
            }
            let (key, value) = line.split_once('=').ok_or("expected key=value")?;
            let (key, value) = (key.trim(), value.trim());
            if key.is_empty() || value.as_bytes().contains(&0) {
                return Err("invalid key/value");
            }
            if section == "bundle" {
                let bundle = config.bundle.as_mut().ok_or("missing bundle section")?;
                match key {
                    "source" => bundle.source = value.into(),
                    "subdir" => bundle.subdir = value.into(),
                    _ => return Err("unknown bundle key"),
                }
            } else if section.eq_ignore_ascii_case("launch") {
                if key.len() >= 16 || key.contains([' ', '\t', '/', '\\', ':']) {
                    return Err("launch key must be a DOS basename under 16 bytes");
                }
                if line.len() > 78 {
                    return Err("launch entry too long");
                }
                if value.split_ascii_whitespace().any(|flag|
                    !["loadfix", "dos32a", "repair", "iopl3", "xms32k"]
                        .iter().any(|known| flag.eq_ignore_ascii_case(known))) {
                    return Err("unknown launch flag");
                }
                if config.launch.len() == 32 {
                    return Err("too many launch entries");
                }
                config.launch.push((key.to_string(), value.to_string()));
            } else if section.starts_with("mount ") {
                let mount = config.mounts.last_mut().ok_or("missing mount section")?;
                match key {
                    "source" => mount.source = value.to_string(),
                    "path" => mount.path = value.to_string(),
                    "drive" => {
                        let bytes = value.as_bytes();
                        if bytes.len() != 1 || !bytes[0].is_ascii_alphabetic() {
                            return Err("drive must be one letter");
                        }
                        let drive = bytes[0].to_ascii_uppercase();
                        if matches!(drive, b'A' | b'B' | b'H') {
                            return Err("A/B/H are reserved drives");
                        }
                        mount.drive = Some(drive);
                    }
                    "access" => {
                        mount.access = match value {
                            "ro" => Access::Ro,
                            "rw" => Access::Rw,
                            "ram" => Access::Ram,
                            _ => return Err("access must be ro, rw or ram"),
                        }
                    }
                    "format" => mount.format = value.to_string(),
                    "partition" => {
                        let n = value.parse().map_err(|_| "invalid partition number")?;
                        if n == 0 {
                            return Err("partition numbers start at 1");
                        }
                        mount.partition = Some(n);
                    }
                    "subdir" => mount.subdir = value.to_string(),
                    "grant" => mount.grant = value.to_string(),
                    _ => return Err("unknown mount key"),
                }
            } else {
                let key = match (section, key) {
                    ("system", "start") => "START".to_string(),
                    ("locale", "language") => "LOCALE".to_string(),
                    ("locale", "keyboard") => "KEYBOARD".to_string(),
                    ("locale", "codepage") => "CODEPAGE".to_string(),
                    ("sound", "sb_audio") => "SB_AUDIO".to_string(),
                    ("sound", "hda_output") => "HDA_OUTPUT".to_string(),
                    ("sound", "volume") => "AUDIO_VOLUME".to_string(),
                    ("environment", _) => key.to_ascii_uppercase(),
                    _ => return Err("unknown setting"),
                };
                config.environment.extend_from_slice(key.as_bytes());
                config.environment.push(b'=');
                config.environment.extend_from_slice(value.as_bytes());
                config.environment.push(0);
            }
        }
        config.environment.push(0);
        if let Some(bundle) = &mut config.bundle {
            if !canonical(&bundle.subdir) { return Err("bundle subdir must be canonical"); }
            if let Some(id) = bundle.source.strip_prefix("UUID=") {
                bundle.source = alloc::format!("UUID={}", uuid_text(uuid(id)?));
            } else if bundle.source != "module" {
                return Err("bundle source must be module or UUID=...");
            }
        }
        for mount in &mut config.mounts {
            if let Some(id) = mount.source.strip_prefix("UUID=") {
                mount.source = alloc::format!("UUID={}", uuid_text(uuid(id)?));
            }
        }
        for (i, mount) in config.mounts.iter().enumerate() {
            if !canonical(&mount.path) || !canonical(&mount.subdir) || !canonical(&mount.grant) {
                return Err("mount paths must be canonical absolute paths");
            }
            if ["/bootbundle", "/mountfs", "/sessionfs", "/userconfig", "/mount-export", "/dos-root"]
                .iter().any(|path| contains(path, &mount.path)) {
                return Err("internal mount path is reserved");
            }
            if mount.path == "/" && mount.drive.is_some_and(|d| d != b'C') {
                return Err("only C: can expose the namespace root");
            }
            if mount.drive == Some(b'D') && mount.path != "/cdrom" {
                return Err("D: must mount at /cdrom");
            }
            if !matches!(mount.format.as_str(), "auto" | "fat" | "ext4" | "iso9660") {
                return Err("unsupported format");
            }
            if let Some(id) = mount.source.strip_prefix("UUID=") {
                uuid(id)?;
            } else if let Some(file) = mount.source.strip_prefix("file:") {
                if !canonical(file) {
                    return Err("image source must be an absolute path");
                }
                if config.mounts[..i].iter().any(|m| m.source == mount.source) {
                    return Err("duplicate image source");
                }
            } else if mount.source != "bundle" {
                return Err("source must be bundle, UUID=..., or file:/...");
            }
            if mount.format == "iso9660" && mount.access != Access::Ro {
                return Err("ISO9660 supports ro only");
            }
            if config.mounts[..i]
                .iter()
                .any(|m| m.path == mount.path || (mount.drive.is_some() && m.drive == mount.drive))
            {
                return Err("duplicate mount path or drive");
            }
        }
        // A file depends on the most specific configured mount containing it.
        // Reject cycles before any filesystem is opened writable.
        config.order()?;
        Ok(config)
    }

    /// BOOT.INI owns storage policy; RETROOS.INI owns user settings.
    pub fn parse_boot(bytes: &[u8]) -> Result<Self, &'static str> {
        let config = Self::parse(bytes)?;
        if config.bundle.is_none() { return Err("BOOT.INI requires [bundle]"); }
        if config.environment.iter().any(|b| *b != 0) || !config.launch.is_empty() {
            return Err("user settings belong in RETROOS.INI");
        }
        Ok(config)
    }

    pub fn parse_user(bytes: &[u8]) -> Result<Self, &'static str> {
        let config = Self::parse(bytes)?;
        if config.bundle.is_some() || !config.mounts.is_empty() {
            return Err("bundle and mounts belong in BOOT.INI");
        }
        Ok(config)
    }

    pub fn select_bundle(&self, module: Option<FilesystemVolume>, volumes: &[FilesystemVolume])
        -> Result<(FilesystemVolume, &'static [u8]), &'static str>
    {
        let bundle = self.bundle.as_ref().ok_or("missing bundle configuration")?;
        let volume = if bundle.source == "module" {
            module.ok_or("BOOT.INI requires a bundle module")?
        } else {
            let id = uuid(bundle.source.strip_prefix("UUID=").ok_or("invalid bundle source")?)?;
            let mut matches = volumes.iter().filter(|v| v.c_uuid() == Some(id));
            let selected = *matches.next().ok_or("bundle UUID not found")?;
            if matches.next().is_some() { return Err("bundle UUID is ambiguous"); }
            selected
        };
        Ok((volume, prefix(&bundle.subdir)))
    }

    fn dependency(&self, index: usize) -> Option<usize> {
        let path = self.mounts[index].source.strip_prefix("file:")?;
        self.mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| contains(&m.path, path))
            .max_by_key(|(_, m)| m.path.len())
            .map(|(i, _)| i)
    }

    pub fn order(&self) -> Result<Vec<usize>, &'static str> {
        let mut order = Vec::new();
        while order.len() < self.mounts.len() {
            let next = (0..self.mounts.len()).find(|i| {
                !order.contains(i) && self.dependency(*i).is_none_or(|d| order.contains(&d))
            });
            order.push(next.ok_or("image mount dependency cycle")?);
        }
        Ok(order)
    }
}

fn prefix_bytes(path: &str) -> Vec<u8> {
    let mut bytes = path.trim_start_matches('/').as_bytes().to_vec();
    if !bytes.is_empty() {
        bytes.push(b'/');
    }
    bytes
}

fn contains(parent: &str, path: &str) -> bool {
    parent == "/"
        || path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|s| s.starts_with('/'))
}

pub fn prefix(path: &str) -> &'static [u8] {
    let mut bytes = path.trim_start_matches('/').as_bytes().to_vec();
    if !bytes.is_empty() {
        bytes.push(b'/');
    }
    Box::leak(bytes.into_boxed_slice())
}

/// Read before namespace composition, directly on the supplied boot filesystem.
pub fn read(fs: &dyn vfs::Filesystem, path: &[u8]) -> Result<Option<Config>, &'static str> {
    let Some(node) = fs.open(path) else {
        return Ok(None);
    };
    if node.size > 64 * 1024 {
        fs.clunk(node.handle);
        return Err("BOOT.INI exceeds 64 KiB");
    }
    let mut bytes = alloc::vec![0; node.size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let size = (bytes.len() - offset) as u32;
        let n = fs.read(node.handle, offset as u32, &mut bytes[offset..], size);
        if n <= 0 {
            fs.clunk(node.handle);
            return Err("cannot read BOOT.INI");
        }
        offset += n as usize;
    }
    fs.clunk(node.handle);
    Config::parse_boot(&bytes).map(Some)
}

/// Keep a sector overlay above a partition, rather than duplicating a whole disk.
pub fn open(
    volume: FilesystemVolume,
    access: Access,
    protected: bool,
) -> Result<Box<dyn vfs::Filesystem>, &'static str> {
    let volume = if access == Access::Ram || (protected && access == Access::Rw) {
        let disk = Box::leak(Box::new(ExtentDisk(volume.volume))) as &'static dyn Disk;
        let overlay =
            Box::leak(Box::new(block::overlay::RamOverlay::wrap(disk))) as &'static dyn Disk;
        FilesystemVolume {
            volume: block::cache::volume(Volume::whole(overlay)),
            ..volume
        }
    } else {
        volume
    };
    volume.open(access != Access::Ro)
}

struct ExtentDisk(Volume);
impl Disk for ExtentDisk {
    fn read(&self, lba: u64, buf: &mut [u8]) -> u32 {
        self.0.read(lba, buf)
    }
    fn write(&self, lba: u64, buf: &[u8]) -> u32 {
        self.0.write(lba, buf)
    }
    fn flush(&self) -> Result<(), block::FlushError> {
        self.0.flush()
    }
    fn sectors(&self) -> u64 {
        self.0.sectors
    }
    fn name(&self) -> &str {
        self.0.disk().name()
    }
}

pub fn read_bundle(
    volume: FilesystemVolume,
) -> Result<Option<(Config, &'static [u8])>, &'static str> {
    let source = volume.open(false)?;
    for home in [b"".as_slice(), b"home/retroos/"] {
        if let Some(config) = read(source.as_ref(), &[home, b"RETROOS/BOOT.INI"].concat())? {
            return Ok(Some((config, home)));
        }
    }
    Ok(None)
}

/// Build the configured namespace. Unlisted physical partitions are untouched.
pub fn apply(
    config: &Config,
    bundle: FilesystemVolume,
    bundle_home: &[u8],
    volumes: &[FilesystemVolume],
    protected: bool,
    extras: Vec<(arch_abi::BootModule, FilesystemVolume)>,
) -> Result<(), &'static str> {
    for mount in &config.mounts {
        if let Some(id) = mount.source.strip_prefix("UUID=") {
            let id = uuid(id)?;
            let candidates: Vec<_> = volumes
                .iter()
                .enumerate()
                .filter(|(_, v)| v.c_uuid() == Some(id))
                .collect();
            if candidates.len() != 1 {
                return Err("configured UUID missing or ambiguous");
            }
            let other: Vec<_> = config
                .mounts
                .iter()
                .filter(|m| m.source == mount.source)
                .collect();
            if other.iter().any(|m| m.access == Access::Ram)
                && other.iter().any(|m| m.access == Access::Rw)
                && !protected
            {
                return Err("one filesystem cannot have both persistent and RAM views");
            }
        }
    }
    // The boot bundle is always writable session content. For disk boot its
    // sector overlay protects the source; for GRUB this also preserves the
    // original module bytes for multiple views of the same filesystem.
    let bootfs: &'static dyn vfs::Filesystem = Box::leak(open(bundle, Access::Ram, true)?);
    vfs::mount(b"bootbundle/", bootfs);
    vfs::hide_mount(b"bootbundle/");
    // A self-contained root remains if configuration only names data mounts.
    vfs::mount(b"", bootfs);
    crate::kernel::dos::configure_drive(b'C', b"");
    let mut c_mounted = false;
    let mut opened: Vec<(usize, &'static dyn vfs::Filesystem)> = Vec::new();
    for index in config.order()? {
        let mount = &config.mounts[index];
        let target = prefix(&mount.path);
        let fs: &'static dyn vfs::Filesystem;
        let mut volume = None;
        if mount.source == "bundle" {
            fs = bootfs;
        } else if let Some(id) = mount.source.strip_prefix("UUID=") {
            let id = uuid(id)?;
            let mut matches = volumes
                .iter()
                .enumerate()
                .filter(|(_, v)| v.c_uuid() == Some(id));
            let (index, selected) = matches.next().ok_or("configured UUID not found")?;
            if matches.next().is_some() {
                return Err("configured UUID is ambiguous");
            }
            volume = Some(*selected);
            fs = if let Some((_, fs)) = opened.iter().find(|(i, _)| *i == index) {
                *fs
            } else {
                let access = if config
                    .mounts
                    .iter()
                    .any(|m| m.source == mount.source && m.access == Access::Ram)
                {
                    Access::Ram
                } else if config
                    .mounts
                    .iter()
                    .any(|m| m.source == mount.source && m.access == Access::Rw)
                {
                    Access::Rw
                } else {
                    Access::Ro
                };
                let fs =
                    Box::leak(open(*selected, access, protected)?) as &'static dyn vfs::Filesystem;
                opened.push((index, fs));
                fs
            };
        } else {
            let path = mount.source.strip_prefix("file:").ok_or("invalid source")?;
            let backing = vfs::open_backing(path.trim_start_matches('/').as_bytes())
                .ok_or("image source not found")?;
            if mount.format == "iso9660"
                || (mount.format == "auto" && path.to_ascii_lowercase().ends_with(".iso"))
            {
                if mount.access != Access::Ro {
                    backing.close();
                    return Err("ISO9660 supports ro only");
                }
                fs = match crate::kernel::fs::iso9660::Iso9660Fs::open(
                    Box::new(IsoFile(backing)),
                    crate::kernel::fs::iso9660::DiscFormat::Iso,
                ) {
                    Ok(fs) => Box::leak(Box::new(fs)),
                    Err(_) => {
                        backing.close();
                        return Err("invalid ISO9660 image");
                    }
                };
            } else {
                let writable = mount.access == Access::Rw && !protected;
                let disk = block::file::FileDisk::new(backing, mount.name.clone(), writable)?;
                let disk: &'static dyn Disk = Box::leak(Box::new(disk));
                let whole = Volume::whole(disk);
                let parts = block::partition::scan(whole);
                let chosen = if let Some(n) = mount.partition {
                    parts.get(n - 1).ok_or("image partition not found")?.volume
                } else if parts.is_empty() {
                    whole
                } else {
                    let supported: Vec<_> = parts
                        .iter()
                        .filter_map(|p| FilesystemVolume::probe(p.volume))
                        .collect();
                    if supported.len() != 1 {
                        return Err("partitioned image needs an explicit partition number");
                    }
                    supported[0].volume
                };
                let selected =
                    FilesystemVolume::probe(chosen).ok_or("image has no supported filesystem")?;
                volume = Some(selected);
                fs = Box::leak(open(selected, mount.access, protected)?);
            }
        }
        if mount.format != "auto" && !fs.format_name().eq_ignore_ascii_case(&mount.format) {
            return Err("filesystem does not match configured format");
        }
        // Mount the full filesystem privately; expose only the requested
        // subtree. This also keeps grant paths relative to their filesystem.
        let private = prefix(&alloc::format!("/mountfs/{}", index));
        if mount.access == Access::Ro {
            vfs::mount_readonly(private, fs);
        } else if mount.source == "bundle" || mount.access == Access::Ram || protected {
            vfs::mount(private, fs);
        } else if let Some(volume) = volume {
            volume.mount_writable(private, fs, mount.grant.trim_start_matches('/').as_bytes());
        } else {
            vfs::mount_readonly(private, fs);
        }
        if let Some(id) = mount.source.strip_prefix("UUID=") {
            let id = uuid(id)?;
            crate::kernel::mount_editor::record_mount(
                id,
                private,
                mount.access == Access::Ram || protected,
            );
        }
        vfs::hide_mount(private);
        let subdir = mount.subdir.trim_start_matches('/').as_bytes();
        let bundle_subdir;
        let subdir = if mount.source == "bundle" {
            bundle_subdir = [bundle_home, subdir].concat();
            bundle_subdir.as_slice()
        } else { subdir };
        if !subdir.is_empty() && !fs.dir_exists(subdir) {
            return Err("configured subdirectory not found");
        }
        let mut source = private.to_vec();
        source.extend_from_slice(subdir);
        if !source.ends_with(b"/") {
            source.push(b'/');
        }
        vfs::bind(target, Box::leak(source.into_boxed_slice()));
        if let Some(drive) = mount.drive {
            crate::kernel::dos::configure_drive(drive, target);
            c_mounted |= drive == b'C';
        }
        crate::compact_println!(
            "Mount: {} -> {} ({})",
            mount.name.as_str(),
            mount.path.as_str(),
            match mount.access {
                Access::Ro => "ro",
                Access::Ram => "ram",
                Access::Rw if protected => "ram (protected)",
                Access::Rw => "rw",
            }
        );
    }
    if !c_mounted {
        let source = Box::leak([b"bootbundle/".as_slice(), bundle_home].concat().into_boxed_slice());
        vfs::bind(b"dos-root/", source);
        vfs::hide_mount(b"dos-root/");
        crate::kernel::dos::set_c_root(b"dos-root/");
    }
    let c = crate::kernel::dos::c_root();
    let settings_source = config.mounts.iter().position(|m| m.drive == Some(b'C') && m.source != "bundle")
        .map(|index| {
            let mount = &config.mounts[index];
            let mut path = prefix(&alloc::format!("/mountfs/{}", index)).to_vec();
            let subdir = mount.subdir.trim_start_matches('/');
            if !subdir.is_empty() { path.extend_from_slice(subdir.as_bytes()); path.push(b'/'); }
            path.extend_from_slice(b"RETROOS/RETROOS.INI");
            Box::leak(path.into_boxed_slice()) as &'static [u8]
        });
    // An external C: owns its applications and data. Only the matched runtime
    // and default shell come from the boot bundle; edits stay in RAM.
    let external_c = config.mounts.iter().any(|m| m.drive == Some(b'C') && m.source != "bundle");
    let mut entries = Vec::new();
    bootfs.readdir(bundle_home.strip_suffix(b"/").unwrap_or(bundle_home), 0, &mut entries, usize::MAX);
    for entry in entries {
        let name = &entry.name[..entry.name_len];
        if !entry.is_dir || entry.is_symlink || matches!(name, b"." | b".." | b"bin" | b"TEMP" | b"lost+found") { continue; }
        if external_c && !matches!(name, b"RETROOS" | b"DN") { continue; }
        let directory: &'static [u8] = Box::leak([name, b"/"].concat().into_boxed_slice());
        let source = [b"bootbundle/".as_slice(), bundle_home, directory].concat();
        let exposed = [c, directory].concat();
        if config
            .mounts
            .iter()
            .any(|m| prefix_bytes(&m.path) == exposed)
        {
            // Unix command aliases must follow an explicitly mounted app
            // directory as well as the default boot copy.
            if !c.is_empty() && !config.mounts.iter().any(|m| prefix_bytes(&m.path) == directory) {
                vfs::bind(directory, Box::leak(exposed.into_boxed_slice()));
            }
            continue;
        }
        if bootfs.dir_exists(&[bundle_home, directory.strip_suffix(b"/").unwrap()].concat()) {
            if !c.is_empty() && !config.mounts.iter().any(|m| prefix_bytes(&m.path) == directory) {
                vfs::bind(directory, Box::leak(source.clone().into_boxed_slice()));
            }
            vfs::bind(
                Box::leak([c, directory].concat().into_boxed_slice()),
                Box::leak(source.into_boxed_slice()),
            );
        }
    }
    if let Some(source) = settings_source {
        vfs::bind(Box::leak([c, b"RETROOS/RETROOS.INI"].concat().into_boxed_slice()), source);
        if !c.is_empty() { vfs::bind(b"RETROOS/RETROOS.INI", source); }
    }
    // /bin/rc points at /COMMANDER/RC/RC.EXE. A persistent C: owns that
    // application tree; expose its Unix spelling only when it exists.
    let commanders = [c, b"COMMANDER/"].concat();
    if external_c && !c.is_empty()
        && (vfs::dir_exists(&commanders)
            || config.mounts.iter().any(|m| prefix_bytes(&m.path).starts_with(&commanders)))
        && !config.mounts.iter().any(|m| m.path == "/COMMANDER")
    {
        vfs::bind(b"COMMANDER/", Box::leak(commanders.into_boxed_slice()));
        // Mirror explicit child mounts so their virtual ancestors are also
        // enumerable through the Unix alias.
        for mount in &config.mounts {
            let target = prefix_bytes(&mount.path);
            if let Some(relative) = target.strip_prefix(c)
                && relative.starts_with(b"COMMANDER/")
            {
                vfs::bind(Box::leak(relative.to_vec().into_boxed_slice()), Box::leak(target.into_boxed_slice()));
            }
        }
    }
    let external_root = config.mounts.iter().any(|m| m.path == "/" && m.source != "bundle");
    let explicit_bin = config.mounts.iter().find(|m| m.path == "/bin");
    let bin = [bundle_home, b"bin"].concat();
    let default_bin = !external_root && explicit_bin.is_none() && bootfs.dir_exists(&bin);
    if default_bin {
        let source = [b"bootbundle/".as_slice(), bin.as_slice(), b"/"].concat();
        vfs::bind(b"bin/", Box::leak(source.into_boxed_slice()));
    }
    // A mounted Linux root owns its /bin and /usr/bin. Bundle tools are
    // available only with the RAM root or an explicitly selected bundle view.
    let selected_bundle_bin = explicit_bin.is_some_and(|m|
        m.source == "bundle" && m.subdir.trim_matches('/') == "bin");
    if default_bin || selected_bundle_bin {
        let links = [bundle_home, b"RETROOS/UNIXLINK.LST"].concat();
        if let Some(links) = crate::kernel::fs::unix_links::UnixLinks::load(bootfs, &links) {
            vfs::mount_union_readonly(b"bin/", Box::leak(Box::new(links)));
        }
    }
    let session = Box::leak(crate::kernel::fs::session::new());
    session.mkdir(b"TEMP");
    vfs::mount(b"sessionfs/", session);
    vfs::hide_mount(b"sessionfs/");
    vfs::bind(
        Box::leak([c, b"TEMP/"].concat().into_boxed_slice()),
        b"sessionfs/TEMP/",
    );
    // Optional showcase modules are standalone mounts. Never union them with
    // a physical GAMES directory. G: is a conventional default, overridable.
    for (module, volume) in extras {
        if config.mounts.iter().any(|m| prefix_bytes(&m.path) == module.mount()) { continue; }
        let fs = Box::leak(open(volume, Access::Ram, false)?);
        let target = Box::leak(module.mount().to_vec().into_boxed_slice());
        vfs::mount(target, fs);
        if module.mount() == b"showcase/" {
            let mut entries = Vec::new();
            fs.readdir(b"", 0, &mut entries, usize::MAX);
            for entry in entries {
                let name = &entry.name[..entry.name_len];
                if !entry.is_dir || entry.is_symlink || matches!(name, b"." | b".." | b"lost+found") { continue; }
                let directory: &'static [u8] = Box::leak([name, b"/"].concat().into_boxed_slice());
                if config.mounts.iter().any(|m| prefix_bytes(&m.path) == [c, directory].concat()) { continue; }
                let source = Box::leak([target, directory].concat().into_boxed_slice());
                vfs::bind(Box::leak([c, directory].concat().into_boxed_slice()), source);
                if !c.is_empty() { vfs::bind(directory, source); }
            }
        }
        crate::compact_println!("Optional module: /{} ({} MiB)",
            core::str::from_utf8(module.mount()).unwrap_or("?"), module.len / (1024 * 1024));
        if crate::kernel::dos::extra_drive_prefix(b'G').is_none() {
            crate::kernel::dos::configure_drive(b'G', target);
        }
    }
    crate::compact_println!(
        "Mounts: configuration applied; unlisted physical partitions unmounted"
    );
    Ok(())
}

struct IsoFile(vfs::BackingFile);
impl crate::kernel::fs::iso9660::RandomAccess for IsoFile {
    fn len(&self) -> u64 {
        self.0.size() as u64
    }
    fn read_at(
        &self,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, crate::kernel::fs::iso9660::MediaError> {
        let offset = u32::try_from(offset)
            .map_err(|_| crate::kernel::fs::iso9660::MediaError::OutOfBounds)?;
        let count = buf.len().min(self.0.size().saturating_sub(offset) as usize);
        let n = self.0.read_at(offset, &mut buf[..count]);
        if n < 0 {
            Err(crate::kernel::fs::iso9660::MediaError::Io)
        } else {
            Ok(n as usize)
        }
    }
}
pub fn uuid_text(id: arch_abi::VolumeUuid) -> String {
    match id {
        arch_abi::VolumeUuid::Fat(bytes) => alloc::format!(
            "{:02X}{:02X}-{:02X}{:02X}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3]
        ),
        arch_abi::VolumeUuid::Ext4(bytes) => {
            let mut out = String::new();
            for (i, b) in bytes.iter().enumerate() {
                if matches!(i, 4 | 6 | 8 | 10) {
                    out.push('-');
                }
                out.push_str(&alloc::format!("{:02x}", b));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_and_user_configuration_have_distinct_responsibilities() {
        let boot = Config::parse_boot(b"[bundle]\nsource=UUID=ABCD-1234\nsubdir=/boot/release\n[mount \"session\"]\nsource=bundle\npath=/\ndrive=C\naccess=ram\n").unwrap();
        assert_eq!(boot.bundle.unwrap().subdir, "/boot/release");
        assert!(Config::parse_boot(b"[bundle]\nsource=module\n[system]\nstart=DN.COM\n").is_err());
        assert!(Config::parse_boot(b"[mount \"session\"]\nsource=bundle\npath=/\n").is_err());
        assert!(Config::parse_user(b"[bundle]\nsource=module\n").is_err());
        assert!(Config::parse_user(b"[mount \"session\"]\nsource=bundle\npath=/\n").is_err());
        let user = Config::parse_user(b"[locale]\nlanguage=it-IT\n[launch]\nALADDIN.EXE=xms32k\n").unwrap();
        assert_eq!(user.launch, [("ALADDIN.EXE".into(), "xms32k".into())]);
    }

    #[test]
    fn orders_image_after_its_container() {
        let c = Config::parse(b"[mount \"data\"]\nsource=file:/home/user/data.bin\npath=/dos\ndrive=C\naccess=rw\n[ mount ]");
        assert!(c.is_err());
        let c = Config::parse(b"[mount \"data\"]\nsource=file:/home/user/data.bin\npath=/dos\ndrive=C\naccess=rw\n[mount \"host\"]\nsource=UUID=ABCD-1234\npath=/\naccess=ro\n").unwrap();
        assert_eq!(c.order().unwrap(), [1, 0]);
    }
    #[test]
    fn rejects_cycles_and_duplicate_drives() {
        assert!(Config::parse(b"[mount \"loop\"]\nsource=file:/loop/a.bin\npath=/loop\n").is_err());
        assert!(Config::parse(b"[mount \"a\"]\nsource=bundle\npath=/a\ndrive=C\n[mount \"b\"]\nsource=bundle\npath=/b\ndrive=C\n").is_err());
    }
    #[test]
    fn settings_become_personality_neutral_policy() {
        let c = Config::parse(
            b"[locale]\nlanguage=it-IT\nkeyboard=us\n[system]\nstart=C:\\DN\\DN.COM\n",
        )
        .unwrap();
        assert_eq!(
            c.environment,
            b"LOCALE=it-IT\0KEYBOARD=us\0START=C:\\DN\\DN.COM\0\0"
        );
        assert!(Config::parse(b"[mount \"bad\"]\nsource=UUID=ABCD-X234\npath=/\n").is_err());
    }

    #[test]
    fn launch_overrides_are_preserved_separately_from_environment() {
        let c = Config::parse(
            b"[environment]\nHOME=C:\\MC\n[launch]\nDOOM.EXE=repair\nALADDIN.EXE=xms32k\nCHESS.EXE=\n[locale]\nlanguage=en-US\n",
        ).unwrap();
        assert_eq!(c.environment, b"HOME=C:\\MC\0LOCALE=en-US\0\0");
        assert_eq!(c.launch, alloc::vec![
            ("DOOM.EXE".to_string(), "repair".to_string()),
            ("ALADDIN.EXE".to_string(), "xms32k".to_string()),
            ("CHESS.EXE".to_string(), "".to_string()),
        ]);
        assert!(Config::parse(b"[launch]\nDOOM.EXE=typo\n").is_err());
        assert!(Config::parse(b"[launch]\nC:\\DOOM.EXE=repair\n").is_err());
    }
}
