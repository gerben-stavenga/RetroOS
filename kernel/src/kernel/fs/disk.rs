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
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Evidence {
    /// A Unix tree: the Linux personality's `/`.
    pub unix: bool,
    /// A DOS world: C:.
    pub dos: bool,
    /// A boot volume — GRUB's prefix volume / the ESP. Supplies C:\RETROOS and
    /// is never a root: its `BOOT/` would otherwise outscore the real C:.
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

        // Only a runtime-bearing boot disk fills this role. A Linux root
        // containing /boot/grub is still a root, not exclusively a boot disk.
        if has_directory(fs, b"RETROOS") &&
            (has_directory(fs, b"EFI") || has_directory(fs, b"boot/grub")) {
            return Evidence { boot: true, ..Default::default() };
        }

        let home = boot.c_root();
        let home = home.strip_suffix(b"/").unwrap_or(home);
        Evidence {
            unix: has_directory(fs, b"bin")
                || has_directory(fs, b"etc")
                || has_directory(fs, b"usr"),
            // Either a volume that IS C: (a DOS tree at its root) or one that
            // CONTAINS C: (the installed-machine ext4, C: in a subdirectory).
            dos: has_directory(fs, b"RETROOS")
                || has_directory(fs, b"GAMES")
                || (!home.is_empty() && has_directory(fs, home)),
            boot: false,
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
            assert_eq!(fs.mkdir(b"RETROOS"), 0);
        }
        assert_eq!(fat.root_score(&boot), 2);
        assert_eq!(fat.c_root(&boot), b"");
    }
}
