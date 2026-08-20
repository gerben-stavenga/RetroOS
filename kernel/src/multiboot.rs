//! GRUB Multiboot module transport and filesystem composition.
//!
//! The metal entry owns the unsafe loader handoff.  This capsule owns the
//! policy and the ordinary kernel objects that consume the resulting ranges.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::kernel::block::{Disk, Volume};
use crate::kernel::fs::lwext4::{is_ext, Lwext4Fs, MountMode};
use crate::kernel::{console::Console, vfs};


#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
struct MultibootModule {
    mod_start: u32,
    mod_end: u32,
    string: u32,
    reserved: u32,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub(crate) struct AcceptedModule {
    start: u64,
    len: usize,
    mount: [u8; arch_abi::BOOT_MODULE_MOUNT_MAX],
    mount_len: usize,
}

#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
const MULTIBOOT_INFO_MODULES: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
struct ParsedMount {
    bytes: [u8; arch_abi::BOOT_MODULE_MOUNT_MAX],
    len: usize,
}

/// Parse the sole supported module command. `None` means that the module is
/// unrelated to RetroOS and must not consume a slot or validate its payload.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn parse_mount(command: &[u8]) -> Option<ParsedMount> {
    let (key, path) = arch_abi::cmdline::parse_key_value(command)?;
    if !arch_abi::cmdline::key_eq(key, b"retroos.mount") { return None; }
    assert!(!path.is_empty(), "retroos.mount path must be absolute");
    assert_eq!(path[0], b'/', "retroos.mount path must be absolute");
    assert!(!path.contains(&b' '), "retroos.mount accepts one token only");

    let mut out = [0u8; arch_abi::BOOT_MODULE_MOUNT_MAX];
    let path = &path[1..];
    if path.is_empty() { return Some(ParsedMount { bytes: out, len: 0 }) }
    assert_ne!(*path.last().unwrap(), b'/', "retroos.mount path may not end in '/'");
    let mut len = 0;
    for component in path.split(|&b| b == b'/') {
        assert!(!component.is_empty(), "retroos.mount path has an empty component");
        assert!(component != b"." && component != b"..",
            "retroos.mount path may not contain '.' or '..'");
        for &b in component {
            assert!(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'),
                "retroos.mount path contains an unsupported character");
            assert!(len + 1 < out.len(), "retroos.mount path is too long");
            out[len] = b;
            len += 1;
        }
        assert!(len < out.len(), "retroos.mount path is too long");
        out[len] = b'/';
        len += 1;
    }
    Some(ParsedMount { bytes: out, len })
}

#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub(crate) unsafe fn capture_modules<ReadDescriptor, ReadCommand>(
    flags: u32,
    mods_count: u32,
    mods_addr: u32,
    mut read_descriptor: ReadDescriptor,
    mut read_command: ReadCommand,
) -> [Option<AcceptedModule>; arch_abi::MAX_BOOT_MODULES]
where
    ReadDescriptor: FnMut(u32) -> [u32; 4],
    ReadCommand: FnMut(u32, &mut [u8]) -> Option<usize>,
{
    let mut accepted = [None; arch_abi::MAX_BOOT_MODULES];
    if flags & MULTIBOOT_INFO_MODULES == 0 || mods_addr == 0 { return accepted; }
    for index in 0..(mods_count as usize).min(32) {
        let words = read_descriptor(index as u32);
        let descriptor = MultibootModule {
            mod_start: words[0], mod_end: words[1], string: words[2], reserved: words[3],
        };
        if descriptor.string == 0 { continue; }
        let mut command = [0u8; 256];
        let Some(len_command) = read_command(descriptor.string, &mut command) else { continue };
        let Some(mount) = parse_mount(&command[..len_command]) else { continue };
        assert!(descriptor.mod_end > descriptor.mod_start,
            "Multiboot module has an empty or wrapped range");
        let len = (descriptor.mod_end - descriptor.mod_start) as usize;
        assert!(len != 0 && len.is_multiple_of(512),
            "Multiboot module size is not sector-aligned");
        for prior in accepted.iter().flatten() {
            assert!(prior.mount[..prior.mount_len] != mount.bytes[..mount.len],
                "duplicate retroos.mount path");
        }
        let slot = accepted.iter().position(Option::is_none)
            .expect("too many RetroOS Multiboot modules (maximum 4)");
        accepted[slot] = Some(AcceptedModule {
            start: descriptor.mod_start as u64,
            len,
            mount: mount.bytes,
            mount_len: mount.len,
        });
    }
    accepted
}

#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub(crate) fn reserve_modules(
    modules: &[Option<AcceptedModule>; arch_abi::MAX_BOOT_MODULES],
    mut reserve: impl FnMut(u64, u64),
) {
    for module in modules.iter().flatten() {
        reserve(module.start / arch_abi::PAGE_SIZE as u64,
            (module.start + module.len as u64).div_ceil(arch_abi::PAGE_SIZE as u64));
    }
}

#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub(crate) fn handoff_modules(
    modules: [Option<AcceptedModule>; arch_abi::MAX_BOOT_MODULES],
) -> [Option<arch_abi::BootModule>; arch_abi::MAX_BOOT_MODULES] {
    let mut result = [None; arch_abi::MAX_BOOT_MODULES];
    for (slot, module) in modules.into_iter().enumerate() {
        let Some(module) = module else { continue };
        result[slot] = Some(arch_abi::BootModule::new(
            module.start, module.len, module.mount, module.mount_len));
    }
    result
}

/// Keep physical filesystems available below a module-owned root without
/// allowing them to replace `/`. The mount-table slot and visible disk number
/// are intentionally independent.
pub(crate) fn mount_physical_fallbacks(
    ext: &[Volume],
    first_slot: usize,
    max_slots: usize,
    screen: &mut Console,
) -> usize {
    let mut slot = first_slot;
    for (disk_number, &volume) in (1usize..).zip(ext.iter()) {
        if slot >= max_slots { break; }
        let mut prefix = Vec::new();
        prefix.extend_from_slice(b"disk");
        prefix.extend_from_slice(disk_number.to_string().as_bytes());
        prefix.push(b'/');
        let prefix: &'static [u8] = Box::leak(prefix.into_boxed_slice());
        match Lwext4Fs::new(volume, slot, MountMode::ReadOnly) {
            Ok(fs) => {
                vfs::mount(prefix, Box::leak(Box::new(fs)));
                crate::screenln!(screen, "ext4 partition ({} MB) → /{}",
                    volume.sectors / 2048,
                    core::str::from_utf8(&prefix[..prefix.len() - 1]).unwrap_or("?"));
                slot += 1;
            }
            Err(error) => crate::screenln!(screen, "ext4 partition skipped: {}", error),
        }
    }
    slot
}

pub struct ModuleDisk {
    physical_start: u64,
    len: usize,
    read_physical: arch_abi::BootPhysicalReader,
}

impl ModuleDisk {
    pub fn from_boot_module(
        module: arch_abi::BootModule,
        read_physical: arch_abi::BootPhysicalReader,
    ) -> Option<Self> {
        if module.len == 0 || !module.len.is_multiple_of(512) { return None; }
        Some(Self {
            physical_start: module.physical_start,
            len: module.len,
            read_physical,
        })
    }
}

impl Disk for ModuleDisk {
    fn read(&self, lba: u64, buf: &mut [u8]) -> u32 {
        let want = buf.len().div_ceil(512) as u64;
        let n = self.sectors().saturating_sub(lba).min(want);
        let count = n as usize * 512;
        if count != 0 {
            let offset = lba.checked_mul(512)
                .expect("Multiboot module LBA offset overflow");
            let physical = self.physical_start.checked_add(offset)
                .expect("Multiboot module physical offset overflow");
            assert!((self.read_physical)(physical, &mut buf[..count]),
                "Multiboot module physical read failed");
        }
        buf[count..].fill(0);
        n as u32
    }
    fn write(&self, _: u64, _: &[u8]) -> u32 { 0 }
    fn sectors(&self) -> u64 { (self.len / 512) as u64 }
    fn name(&self) -> &str { "multiboot-module" }
}

pub struct ModuleMountSummary { pub has_root: bool, pub next_ext_slot: usize }

/// Mount each module as an independent volatile writable session. Raw ext4
/// images are treated as whole disks; partition scanning is intentionally not
/// used for this boot-only format.
pub fn mount_modules(
    boot: &crate::BootConfig,
    screen: &mut Console,
    first_slot: usize,
) -> ModuleMountSummary {
    let modules: Vec<_> = boot.boot_modules.iter().flatten().copied().collect();
    for (i, a) in modules.iter().enumerate() {
        for b in modules.iter().skip(i + 1) {
            assert!(a.mount() != b.mount(), "duplicate retroos.mount path");
        }
    }
    let mut slot = first_slot;
    let mut has_root = false;
    let reader = if modules.is_empty() {
        None
    } else {
        Some(boot.boot_physical_reader.expect(
            "Multiboot modules require a physical-memory reader"))
    };
    for module in modules {
        assert!(slot < 8, "too many ext4 mounts (lwext4 allows 8 slots)");
        let disk = ModuleDisk::from_boot_module(module, reader.expect("missing module reader"))
            .expect("invalid Multiboot module");
        let disk: &'static dyn Disk = Box::leak(Box::new(disk));
        let disk: &'static dyn Disk = Box::leak(Box::new(crate::kernel::block::overlay::RamOverlay::wrap(disk)));
        let volume = Volume::whole(disk);
        assert!(is_ext(&volume), "Multiboot module is not a raw ext4 image");
        let fs = Lwext4Fs::new(volume, slot, MountMode::ReadWrite)
            .unwrap_or_else(|e| panic!("Multiboot ext4 mount failed: {}", e));
        let fs: &'static dyn vfs::Filesystem = Box::leak(Box::new(fs));
        let mount = module.mount();
        let mount: &'static [u8] = Box::leak(mount.to_vec().into_boxed_slice());
        vfs::mount_writable(mount, fs, if mount.is_empty() { crate::kernel::dos::c_root() } else { b"" });
        if mount.is_empty() {
            crate::screenln!(screen, "Multiboot ext4 ({} MB, volatile overlay) → /", volume.sectors / 2048);
        } else {
            crate::screenln!(screen, "Multiboot ext4 ({} MB, volatile overlay) → /{}",
                volume.sectors / 2048,
                core::str::from_utf8(&mount[..mount.len() - 1]).unwrap_or("?"));
        }
        has_root |= mount.is_empty();
        slot += 1;
    }
    ModuleMountSummary { has_root, next_ext_slot: slot }
}

#[cfg(test)]
mod tests {
    use super::{capture_modules, handoff_modules, parse_mount, Disk, ModuleDisk};
    #[test] fn root_is_empty() { assert_eq!(parse_mount(b"retroos.mount=/").unwrap().len, 0); }
    #[test] fn nested_is_normalized() { let p = parse_mount(b"retroos.mount=/home/retroos/GAMES").unwrap(); assert_eq!(&p.bytes[..p.len], b"home/retroos/GAMES/"); }
    #[test] fn unrelated_is_ignored() { assert!(parse_mount(b"initrd /boot/initrd").is_none()); }
    #[test] #[should_panic] fn extra_token_is_rejected() { parse_mount(b"retroos.mount=/ x"); }
    #[test] #[should_panic] fn traversal_is_rejected() { parse_mount(b"retroos.mount=/a/../b"); }

    #[test]
    fn unrelated_modules_do_not_consume_accepted_slots() {
        let descriptors = [
            [1, 0, 1, 0], [0, 0, 2, 0], [3, 2, 3, 0],
            [4, 5, 4, 0], [4096, 4608, 5, 0],
        ];
        let accepted = unsafe {
            capture_modules(1 << 3, 5, 1,
                |index| descriptors[index as usize],
                |string, out| {
                    let command: &[u8] = if string == 5 { b"retroos.mount=/" } else { b"initrd" };
                    out[..command.len()].copy_from_slice(command);
                    Some(command.len())
                })
        };
        assert_eq!(accepted.iter().flatten().count(), 1);
    }

    #[test]
    #[should_panic(expected = "duplicate retroos.mount path")]
    fn duplicate_mounts_fail_before_acceptance_completes() {
        let descriptors = [[0, 512, 1, 0], [1024, 1536, 2, 0]];
        let _ = unsafe {
            capture_modules(1 << 3, 2, 1,
                |index| descriptors[index as usize],
                |_string, out| {
                    let command = b"retroos.mount=/";
                    out[..command.len()].copy_from_slice(command);
                    Some(command.len())
                })
        };
    }

    #[test]
    #[should_panic(expected = "too many RetroOS Multiboot modules")]
    fn fifth_accepted_module_is_rejected() {
        let descriptors = [
            [0, 512, 1, 0], [512, 1024, 2, 0], [1024, 1536, 3, 0],
            [1536, 2048, 4, 0], [2048, 2560, 5, 0],
        ];
        let _ = unsafe {
            capture_modules(1 << 3, 5, 1,
                |index| descriptors[index as usize],
                |string, out| {
                    let mut command = [0u8; 32];
                    command[..16].copy_from_slice(b"retroos.mount=/a");
                    command[15] = b'a' + (string as u8 - 1);
                    out[..16].copy_from_slice(&command[..16]);
                    Some(16)
                })
        };
    }

    #[test]
    fn reservation_rounds_outward_and_handoff_preserves_physical_order() {
        let descriptors = [[0x123, 0x323, 1, 0], [0x1000, 0x1200, 2, 0]];
        let modules = unsafe {
            capture_modules(1 << 3, 2, 1,
                |index| descriptors[index as usize],
                |string, out| {
                    let command: &[u8] = if string == 1 {
                        b"retroos.mount=/base"
                    } else {
                        b"retroos.mount=/games"
                    };
                    out[..command.len()].copy_from_slice(command);
                    Some(command.len())
                })
        };
        let mut ranges = [(99, 99); 2];
        let mut range_count = 0;
        super::reserve_modules(&modules, |start, end| {
            ranges[range_count] = (start, end);
            range_count += 1;
        });
        assert_eq!(&ranges[..range_count], &[(0, 1), (1, 2)]);

        let handed_off = handoff_modules(modules);
        assert_eq!(handed_off[0].unwrap().physical_start, 0x123);
        assert_eq!(handed_off[1].unwrap().physical_start, 0x1000);
        assert_eq!(handed_off[0].unwrap().mount(), b"base/");
        assert_eq!(handed_off[1].unwrap().mount(), b"games/");
    }

    fn read_host_physical(physical: u64, destination: &mut [u8]) -> bool {
        unsafe {
            core::ptr::copy_nonoverlapping(
                physical as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        true
    }

    fn fail_physical_read(_: u64, _: &mut [u8]) -> bool { false }

    #[test]
    fn module_disk_reads_and_zero_fills() {
        static IMAGE: [u8; 1024] = [0x11; 1024];
        let mount = [0u8; arch_abi::BOOT_MODULE_MOUNT_MAX];
        let module = arch_abi::BootModule::new(
            IMAGE.as_ptr() as u64, IMAGE.len(), mount, 0);
        let disk = ModuleDisk::from_boot_module(module, read_host_physical).unwrap();
        let mut output = [0xff; 1024];
        assert_eq!(disk.read(1, &mut output), 1);
        assert_eq!(output[0], 0x11);
        assert!(output[512..].iter().all(|&byte| byte == 0));
        assert_eq!(disk.write(0, &output), 0);
    }

    #[test]
    fn module_disk_reads_from_physical_offset() {
        static IMAGE: [u8; 2048] = [0x22; 2048];
        let mount = [0u8; arch_abi::BOOT_MODULE_MOUNT_MAX];
        let module = arch_abi::BootModule::new(
            IMAGE.as_ptr() as u64 - 512, IMAGE.len(), mount, 0);
        let disk = ModuleDisk::from_boot_module(module, read_host_physical).unwrap();
        let mut output = [0xff; 512];
        assert_eq!(disk.read(1, &mut output), 1);
        assert!(output.iter().all(|&byte| byte == 0x22));
    }

    #[test]
    #[should_panic(expected = "Multiboot module physical read failed")]
    fn module_disk_reports_reader_failure() {
        let mount = [0u8; arch_abi::BOOT_MODULE_MOUNT_MAX];
        let module = arch_abi::BootModule::new(0x1000, 512, mount, 0);
        let disk = ModuleDisk::from_boot_module(module, fail_physical_read).unwrap();
        let mut output = [0u8; 512];
        let _ = disk.read(0, &mut output);
    }

    #[test]
    #[should_panic(expected = "Multiboot module physical offset overflow")]
    fn module_disk_rejects_physical_offset_overflow() {
        let mount = [0u8; arch_abi::BOOT_MODULE_MOUNT_MAX];
        let module = arch_abi::BootModule::new(u64::MAX, 1024, mount, 0);
        let disk = ModuleDisk::from_boot_module(module, read_host_physical).unwrap();
        let mut output = [0u8; 512];
        let _ = disk.read(1, &mut output);
    }
}
