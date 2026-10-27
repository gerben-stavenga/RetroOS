extern crate alloc;
use alloc::vec::Vec;
/// SZDD mode A: 4 KiB space-filled dictionary, low-bit-first tokens.
pub fn expand(data: &[u8]) -> Result<Vec<u8>, i32> {
    if !data.starts_with(b"SZDD") {
        return Ok(data.to_vec());
    }
    if data.len() < 14 || &data[..8] != b"SZDD\x88\xf0\x27\x33" {
        return Err(-3);
    }
    if data[8] != b'A' {
        return Err(-8);
    }
    let size = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
    if size > 64 * 1024 * 1024 {
        return Err(-5);
    }
    let mut result = Vec::with_capacity(size);
    let mut ring = [b' '; 4096];
    let mut write = 4096 - 16;
    let mut pos = 14;
    while result.len() < size {
        let flags = *data.get(pos).ok_or(-3)?;
        pos += 1;
        for bit in 0..8 {
            if result.len() == size {
                break;
            }
            if flags & (1 << bit) != 0 {
                let c = *data.get(pos).ok_or(-3)?;
                pos += 1;
                result.push(c);
                ring[write] = c;
                write = (write + 1) & 4095;
            } else {
                let lo = *data.get(pos).ok_or(-3)? as usize;
                let hi = *data.get(pos + 1).ok_or(-3)? as usize;
                pos += 2;
                let mut read = lo | ((hi & 0xf0) << 4);
                let length = (hi & 15) + 3;
                if result.len() + length > size {
                    return Err(-3);
                }
                for _ in 0..length {
                    let c = ring[read];
                    read = (read + 1) & 4095;
                    result.push(c);
                    ring[write] = c;
                    write = (write + 1) & 4095;
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stream(size: u32, tokens: &[u8]) -> Vec<u8> {
        let mut d = b"SZDD\x88\xf0\x27\x33A\0".to_vec();
        d.extend_from_slice(&size.to_le_bytes());
        d.extend_from_slice(tokens);
        d
    }
    #[test]
    fn literal_overlap_and_dictionary_spaces() {
        assert_eq!(
            expand(&stream(9, &[7, b'a', b'b', b'c', 0xf0, 0xf3])).unwrap(),
            b"abcabcabc"
        );
        assert_eq!(expand(&stream(3, &[0, 0, 0])).unwrap(), b"   ");
        assert_eq!(expand(b"plain").unwrap(), b"plain");
    }
    #[test]
    fn rejects_truncation_and_overrun() {
        assert!(expand(&stream(1, &[1])).is_err());
        assert!(expand(&stream(2, &[0, 0, 0])).is_err());
        assert!(expand(b"SZDD").is_err());
        let mut d = stream(0, &[]);
        d[8] = b'B';
        assert_eq!(expand(&d), Err(-8));
    }
}
