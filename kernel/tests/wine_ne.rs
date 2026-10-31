//! Verify the actual bundled Wine descriptors, not a second invented NE format.
#[path = "../src/kernel/windows/pe.rs"]
mod pe;
#[path = "../src/kernel/windows/ne.rs"]
mod ne;

const MODULES: &[&[u8]] = &[
    include_bytes!(env!("WINE_BUILT_KERNEL16")),
    include_bytes!(env!("WINE_KERNEL16")),
    include_bytes!(env!("WINE_USER16")),
    include_bytes!(env!("WINE_GDI16")),
    include_bytes!(env!("WINE_MM16")),
    include_bytes!(env!("WINE_DIALOG16")),
    include_bytes!(env!("WINE_FPU16")),
];

#[test]
fn bundled_wine_ne_interfaces_have_real_code_data_and_exports() {
    for bytes in MODULES {
        let pe = pe::Image::parse(bytes).unwrap();
        let (rva, bytes) = pe.embedded_ne().unwrap().unwrap();
        assert!(rva > 0);
        let image = ne::Image::parse(bytes).unwrap();
        assert_eq!(image.header.segment_count, 2);
        let code = image.segment(1).unwrap();
        assert!(code.is_code() && code.is_32bit());
        assert!(!image.segment(2).unwrap().is_code());
        assert!(image.modules().unwrap().is_empty());
        assert!((1..700).any(|ordinal| image.entry(ordinal).is_ok()));
        // Wine's unpatched CALLFROM16 records begin with push imm32; far call.
        let thunk = image.segment_bytes(code).unwrap();
        assert_eq!(thunk[0], 0x68);
        assert_eq!(thunk[5], 0x9a);
    }
}

#[test]
fn corrupt_descriptor_extent_is_rejected() {
    let mut bytes = MODULES[0].to_vec();
    let image = pe::Image::parse(&bytes).unwrap();
    let (_, descriptor) = image.embedded_ne().unwrap().unwrap();
    let offset = descriptor.as_ptr() as usize - bytes.as_ptr() as usize;
    for size in [0u32, 63, u32::MAX] {
        bytes[offset + 40..offset + 44].copy_from_slice(&size.to_le_bytes());
        assert!(pe::Image::parse(&bytes).unwrap().embedded_ne().is_err());
    }
}

#[test]
fn source_built_kernel_exposes_wines_existing_relays() {
    let image = pe::Image::parse(MODULES[0]).unwrap();
    for name in [b"RetroWineCallFrom16".as_slice(), b"RetroWineCallFrom16Regs", b"RetroWineConfigureSelectors", b"RetroWineImportSelectors"] {
        assert!(image.export_rva(&pe::ImportSymbol::Name(name.to_vec())).unwrap().is_some());
    }
}
