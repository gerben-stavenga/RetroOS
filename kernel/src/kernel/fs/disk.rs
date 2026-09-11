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
        Some(Self { volume, format })
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
        } else if has_directory(fs.as_ref(), if home.is_empty() { b"BOOT" } else { home }) {
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
        let fat = FilesystemVolume { volume, format: Format::Fat };
        // The mapping decision does not read the filesystem.
        let unix = FilesystemVolume { volume, format: Format::Ext4 };
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
        let fat = FilesystemVolume { volume, format: Format::Fat };
        let boot = crate::BootConfig::empty();
        assert_eq!(fat.root_score(&boot), 0);
        {
            let fs = fat.open(true).unwrap();
            assert_eq!(fs.mkdir(b"EFI"), 0);
        }
        assert_eq!(fat.root_score(&boot), 0);
        {
            let fs = fat.open(true).unwrap();
            assert_eq!(fs.mkdir(b"BOOT"), 0);
        }
        assert_eq!(fat.root_score(&boot), 2);
        assert_eq!(fat.c_root(&boot), b"");
    }
}
