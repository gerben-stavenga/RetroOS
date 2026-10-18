//! Private boot credentials, kept outside every guest environment block.
use alloc::vec::Vec;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Profile {
    pub ssid: Vec<u8>,
    pub password: Zeroizing<Vec<u8>>,
    pub auto_connect: bool,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            ssid: Vec::new(),
            password: Zeroizing::new(Vec::new()),
            auto_connect: true,
        }
    }
}
impl core::fmt::Debug for Profile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiProfile")
            .field("auto_connect", &self.auto_connect)
            .finish_non_exhaustive()
    }
}
impl Profile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ssid.is_empty() || self.ssid.len() > 32 || self.ssid.contains(&0) {
            return Err("Wi-Fi SSID must contain 1 through 32 bytes");
        }
        let p = &self.password;
        if !(p.len() == 64 && p.iter().all(u8::is_ascii_hexdigit)
            || (8..=63).contains(&p.len()) && p.iter().all(|b| (0x20..=0x7e).contains(b)))
        {
            return Err("Wi-Fi password must be 8 through 63 ASCII bytes or a 64-digit PSK");
        }
        Ok(())
    }
    pub fn pmk(&self) -> Result<Zeroizing<[u8; 32]>, &'static str> {
        self.validate()?;
        let mut out = Zeroizing::new([0; 32]);
        if self.password.len() == 64 {
            for (byte, hex) in out.iter_mut().zip(self.password.chunks_exact(2)) {
                let nibble = |c: u8| (c as char).to_digit(16).unwrap() as u8;
                *byte = nibble(hex[0]) * 16 + nibble(hex[1]);
            }
        } else {
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&self.password, &self.ssid, 4096, &mut *out);
        }
        Ok(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ieee_wpa_psk_vector_and_debug_redaction() {
        let p = Profile {
            ssid: b"IEEE".to_vec(),
            password: Zeroizing::new(b"password".to_vec()),
            auto_connect: true,
        };
        let expected = [
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
            0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
            0x97, 0x10, 0xa1, 0x2e,
        ];
        assert_eq!(*p.pmk().unwrap(), expected);
        let text = alloc::format!("{p:?}");
        assert!(!text.contains("password"));
        assert!(
            Profile {
                password: Zeroizing::new(b"short".to_vec()),
                ..p.clone()
            }
            .validate()
            .is_err()
        );
    }
}
