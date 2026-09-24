//! Filesystem detection shared by physical partitions and GRUB module images.

use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::kernel::block::Volume;
use crate::kernel::vfs::{self, Filesystem};
use super::{fat, portable_ext4};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format { Ext4, Fat }

#[derive(Clone, Copy)]
pub struct FilesystemVolume {
    pub volume: Volume,
    pub format: Format,
    /// Partition-table role, independent of boot directories and filesystem.
    pub is_esp: bool,
}

impl FilesystemVolume {
    pub fn probe(volume: Volume) -> Option<Self> {
        let format = if portable_ext4::is_ext(&volume) {
            Format::Ext4
        } else if fat::is_fat(&volume) {
            Format::Fat
        } else {
            return None;
        };
        Some(Self { volume, format, is_esp: false })
    }

    /// ext4's on-disk filesystem UUID (superblock + 0x68).
    pub fn uuid(&self) -> Option<[u8; 16]> {
        if self.format != Format::Ext4 { return None; }
        let mut sector = [0; 512];
        if self.volume.read(2, &mut sector) != 1 { return None; }
        Some(sector[104..120].try_into().unwrap())
    }

    pub fn name(&self) -> &'static str {
        match self.format { Format::Ext4 => "ext4", Format::Fat => "FAT" }
    }

    /// A Unix root exposes its DOS home; a FAT root is the actual C: volume.
    /// Explicit mappings (including the build toolchain's C: = /) still win.
    pub fn c_root<'a>(&self, boot: &'a crate::BootConfig) -> &'a [u8] {
        if boot.c_root_explicit() || self.format == Format::Ext4 { boot.c_root() }
        else { b"" }
    }

    pub fn open(&self, writable: bool) -> Result<Box<dyn Filesystem>, &'static str> {
        match self.format {
            Format::Ext4 => portable_ext4::PortableExt4Fs::new(self.volume)
                .map(|fs| Box::new(fs) as Box<dyn Filesystem>)
                .map_err(|_| "ext4 mount failed"),
            Format::Fat => fat::FatFs::new(fat::VolumeIo::new(self.volume, writable))
                .map(|fs| Box::new(fs) as Box<dyn Filesystem>)
                .map_err(|_| "FAT mount failed"),
        }
    }

    /// Prefer an OS root over an EFI system partition or unrelated data disk.
    /// Preserve the legacy ext4 preference when no candidate has root markers.
    pub fn root_score(&self, boot: &crate::BootConfig) -> u8 {
        let Ok(fs) = self.open(false) else { return 0 };
        let home = self.c_root(boot);
        let home = home.strip_suffix(b"/").unwrap_or(home);
        if has_directory(fs.as_ref(), b"etc") && has_directory(fs.as_ref(), b"usr") {
            3
        } else if has_directory(fs.as_ref(), if home.is_empty() { b"RETROOS" } else { home }) {
            2
        } else {
            u8::from(self.format == Format::Ext4)
        }
    }

    /// FAT has no Unix ownership. Explicitly grant access to the selected
    /// FAT root/session; secondary volumes are explicitly mounted read-only.
    pub fn mount_writable(&self, prefix: &'static [u8], fs: &'static dyn Filesystem, home: &[u8]) {
        match self.format {
            Format::Ext4 => vfs::mount_writable(prefix, fs, home),
            Format::Fat => vfs::mount(prefix, fs),
        }
    }
}

/// What a volume is carrying, judged by what is actually on it.
///
/// These are not exclusive and they are not a partition type: one installed
/// ext4 carries both the Unix tree and C:, which is the shape RetroOS has on
/// a real machine.  `startup` decides which volume fills which job; this only
/// reports evidence, the same division drivers and `startup` already keep.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Evidence {
    /// A Unix tree: the Linux personality's `/`.
    pub unix: bool,
    /// C: preference: identified data (3), another Unix home (2), plain FAT (1).
    pub dos: u8,
    /// Directory within the selected volume, empty for a FAT volume root.
    pub dos_home: Vec<u8>,
    /// Root-level runtime files that can supply C:\RETROOS. Independent of
    /// whether this volume also supplies the Linux root or C: data.
    pub boot: bool,
}

impl FilesystemVolume {
    /// Inspect the volume once and record what it holds.
    ///
    /// Marker names are matched by exact bytes, as the VFS resolves them.
    /// Lowercase `bin`/`etc`/`usr` are Unix by construction: a DOS volume
    /// built by mtools stores 8.3 names uppercase, so the case difference is
    /// itself evidence rather than something to fold away.
    pub fn evidence(&self, boot: &crate::BootConfig) -> Evidence {
        let Ok(fs) = self.open(false) else { return Evidence::default() };
        let fs = fs.as_ref();

        let runtime = has_directory(fs, b"RETROOS");

        let preferred = self.c_root(boot);
        let preferred_dir = preferred.strip_suffix(b"/").unwrap_or(preferred);
        let mut dos_home = preferred.to_vec();
        let dos = match self.format {
            Format::Fat => {
                if [b"CONFIG".as_slice(), b"GAMES", b"ULTRAMID"]
                    .iter().any(|path| has_directory(fs, path)) {
                    3
                } else { 1 }
            }
            Format::Ext4 => {
                if has_directory(fs, preferred_dir) {
                    3
                } else if !boot.c_root_explicit() && let Some(home) = other_home(fs) {
                    dos_home = home;
                    2
                } else { 0 }
            }
        };
        Evidence {
            unix: self.format == Format::Ext4 && (has_directory(fs, b"bin")
                || has_directory(fs, b"etc") || has_directory(fs, b"usr")),
            dos: if self.is_esp { 0 } else { dos }, dos_home,
            boot: runtime,
        }
    }
}

/// Choose a stable existing user home without creating directories during
/// discovery. Ignore symlinks and dot entries; write grants use this directory.
fn other_home(fs: &dyn Filesystem) -> Option<Vec<u8>> {
    if !has_directory(fs, b"home") { return None; }
    let mut entries = Vec::new();
    fs.readdir(b"home", 0, &mut entries, usize::MAX);
    let name = entries.iter().filter(|entry| entry.is_dir && !entry.is_symlink)
        .map(|entry| &entry.name[..entry.name_len])
        .filter(|name| !name.starts_with(b"."))
        .min()?;
    Some([b"home/".as_slice(), name, b"/"].concat())
}

/// Root markers use the same exact directory names as the VFS namespace.
/// Do not let a storage library's internal case folding select an unusable root.
fn has_directory(fs: &dyn Filesystem, path: &[u8]) -> bool {
    let mut parent = Vec::new();
    for name in path.split(|&byte| byte == b'/').filter(|name| !name.is_empty()) {
        let mut entries = Vec::new();
        fs.readdir(&parent, 0, &mut entries, usize::MAX);
        if !entries.iter().any(|entry| entry.is_dir && &entry.name[..entry.name_len] == name) {
            return false;
        }
        if !parent.is_empty() { parent.push(b'/'); }
        parent.extend_from_slice(name);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fat::tests::formatted;

    #[test]
    fn c_drive_mapping_depends_on_mount_type_not_directory_presence() {
        let (_, volume) = formatted(fatfs::FatType::Fat12, 2880);
        let fat = FilesystemVolume { volume, format: Format::Fat, is_esp: false };
        // The mapping decision does not read the filesystem.
        let unix = FilesystemVolume { volume, format: Format::Ext4, is_esp: false };
        let mut boot = crate::BootConfig::empty();
        assert_eq!(fat.c_root(&boot), b"");
        assert_eq!(unix.c_root(&boot), b"home/retroos/");
        boot.set_c_root(b"/home/retroos");
        assert_eq!(fat.c_root(&boot), b"home/retroos/");
        boot.set_c_root(b"/");
        assert_eq!(unix.c_root(&boot), b"");
    }

    #[test]
    fn fat_boot_directory_marks_a_dos_root_not_an_efi_partition() {
        let (_, volume) = formatted(fatfs::FatType::Fat12, 2880);
        let fat = FilesystemVolume { volume, format: Format::Fat, is_esp: false };
        let boot = crate::BootConfig::empty();
        assert_eq!(fat.root_score(&boot), 0);
        {
            let fs = fat.open(true).unwrap();
            assert_eq!(fs.mkdir(b"EFI"), 0);
        }
        assert_eq!(fat.root_score(&boot), 0);
        {
            let fs = fat.open(true).unwrap();
            assert_eq!(fs.mkdir(b"RETROOS"), 0);
        }
        assert_eq!(fat.root_score(&boot), 2);
        assert_eq!(fat.c_root(&boot), b"");
    }
    #[test]
    fn fat_boot_directories_do_not_exclude_data_but_esp_type_does() {
        for marker in [None, Some(b"CONFIG".as_slice()), Some(b"GAMES"), Some(b"ULTRAMID")] {
            let (_, volume) = formatted(fatfs::FatType::Fat12, 2880);
            let mut fat = FilesystemVolume { volume, format: Format::Fat, is_esp: false };
            if let Some(marker) = marker {
                assert_eq!(fat.open(true).unwrap().mkdir(marker), 0);
            }
            let evidence = fat.evidence(&crate::BootConfig::empty());
            assert_eq!(evidence.dos, if marker.is_some() { 3 } else { 1 });
            assert!(evidence.dos_home.is_empty());
            assert_eq!(fat.open(true).unwrap().mkdir(b"EFI"), 0);
            assert_eq!(fat.evidence(&crate::BootConfig::empty()).dos, evidence.dos);
            fat.is_esp = true;
            assert_eq!(fat.evidence(&crate::BootConfig::empty()).dos, 0);
        }
    }

}
