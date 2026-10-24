#![allow(dead_code)]
mod paging2 {
    pub static MEMORY: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
    pub fn read_boot_physical(address: u64, out: &mut [u8]) -> bool {
        // Give the fixture aliases above 4 GiB to exercise XSDT pointers.
        let address = if address >= 0x1_0000_0000 {
            address - 0x1_0000_0000
        } else {
            address
        };
        let memory = MEMORY.lock().unwrap();
        let Some(bytes) = memory.get(address as usize..address as usize + out.len()) else {
            return false;
        };
        out.copy_from_slice(bytes);
        true
    }
}
#[path = "src/acpi.rs"]
mod acpi;

#[test]
fn rsdp_roots_checksums_and_high_addresses() {
    fn checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        bytes[at] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)));
    }
    let mut memory = vec![0; 256];
    memory[64..68].copy_from_slice(b"RSDT");
    memory[68..72].copy_from_slice(&40u32.to_le_bytes());
    memory[100..104].copy_from_slice(&128u32.to_le_bytes());
    memory[128..132].copy_from_slice(b"APIC");
    memory[132..136].copy_from_slice(&52u32.to_le_bytes());
    memory[172..180].copy_from_slice(&[0, 8, 0, 7, 1, 0, 0, 0]);
    checksum(&mut memory[64..104], 9);
    checksum(&mut memory[128..180], 9);
    let mut rsdp = [0u8; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[16..20].copy_from_slice(&64u32.to_le_bytes());
    checksum(&mut rsdp[..20], 8);
    *paging2::MEMORY.lock().unwrap() = memory.clone();
    let mut ids = [0; 4];
    assert_eq!(acpi::processor_ids(&rsdp[..20], &mut ids), Some(1));
    assert_eq!(ids[0], 7);
    // Bad MADT checksum must not publish any boot targets.
    paging2::MEMORY.lock().unwrap()[137] ^= 1;
    assert_eq!(acpi::processor_ids(&rsdp[..20], &mut ids), None);
    // ACPI 2.0, XSDT and MADT both above 4 GiB.
    memory[64..68].copy_from_slice(b"XSDT");
    memory[68..72].copy_from_slice(&44u32.to_le_bytes());
    memory[100..108].copy_from_slice(&0x1_0000_0080u64.to_le_bytes());
    checksum(&mut memory[64..108], 9);
    *paging2::MEMORY.lock().unwrap() = memory;
    rsdp[15] = 2;
    rsdp[16..20].fill(0);
    rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&0x1_0000_0040u64.to_le_bytes());
    checksum(&mut rsdp[..20], 8);
    checksum(&mut rsdp, 32);
    assert_eq!(acpi::processor_ids(&rsdp, &mut ids), Some(1));
    rsdp[32] ^= 1;
    assert_eq!(acpi::processor_ids(&rsdp, &mut ids), None);
}
