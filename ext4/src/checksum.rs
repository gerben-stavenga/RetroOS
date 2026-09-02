//! ext4's CRC32C conventions.

#[derive(Clone)]
pub(crate) struct Checksum {
    digest: crc::Digest<'static, u32>,
}

impl Checksum {
    const ALGORITHM: crc::Algorithm<u32> = crc::CRC_32_ISCSI;

    pub(crate) fn new() -> Self {
        Self::with_seed(Self::ALGORITHM.init)
    }

    pub(crate) fn with_seed(seed: u32) -> Self {
        const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&Checksum::ALGORITHM);
        Self {
            digest: CRC32C.digest_with_initial(seed.reverse_bits()),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.digest.update(bytes);
    }

    pub(crate) fn update_u32_le(&mut self, value: u32) {
        self.update(&value.to_le_bytes());
    }

    pub(crate) fn finalize(self) -> u32 {
        self.digest.finalize() ^ u32::MAX
    }
}
