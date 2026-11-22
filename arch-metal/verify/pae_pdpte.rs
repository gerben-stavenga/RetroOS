#[kani::proof]
fn hardware_pdpte_contract() {
    let raw: u64 = kani::any();
    let physical_bits: u32 = kani::any();
    let result = encode_pae_pdpte(raw, physical_bits);

    if !(32..=52).contains(&physical_bits) {
        assert!(result.is_none());
    } else if raw.trailing_zeros() != 0 {
        assert_eq!(result, Some(0));
    } else {
        let frame = (raw >> 12) % (1u64 << 40);
        if frame >= 1u64 << (physical_bits - 12) {
            assert!(result.is_none());
        } else {
            let entry = result.unwrap();
            // Check each bit independently of the encoder's masks.
            let bit: u32 = kani::any();
            kani::assume(bit < 64);
            let allowed = matches!(bit, 0 | 3 | 4) || (12..physical_bits).contains(&bit);
            let expected = allowed && (raw >> bit) & 1 == 1;
            assert_eq!((entry >> bit) & 1 == 1, expected);
            assert_eq!(encode_pae_pdpte(entry, physical_bits), Some(entry));
        }
    }
}
