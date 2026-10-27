//! Bounded Windows DIB decoding, shared by PE and NE resources.
extern crate alloc;
use alloc::{vec, vec::Vec};

fn word(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
fn dword(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}
pub fn decode(data: &[u8], wanted_width: i32, wanted_height: i32) -> Option<(i32, i32, Vec<u8>)> {
    let header = dword(data, 0)? as usize;
    let (width, height, depth, palette_stride) = if header == 12 {
        (
            word(data, 4)? as i32,
            word(data, 6)? as i32,
            word(data, 10)?,
            3,
        )
    } else if header >= 40 {
        (
            dword(data, 4)? as i32,
            dword(data, 8)? as i32,
            word(data, 14)?,
            4,
        )
    } else {
        return None;
    };
    if width <= 0
        || width > 2048
        || height == 0
        || height.unsigned_abs() > 2048
        || !matches!(depth, 1 | 4 | 8 | 24 | 32)
    {
        return None;
    }
    let compression = if header >= 40 { dword(data, 16)? } else { 0 };
    if !matches!((compression, depth), (0, _) | (1, 8) | (2, 4)) || (compression != 0 && height < 0)
    {
        return None;
    }
    let colors = if depth <= 8 {
        if header >= 40 && dword(data, 32)? != 0 {
            dword(data, 32)? as usize
        } else {
            1usize << depth
        }
    } else {
        0
    };
    let offset = header.checked_add(colors.checked_mul(palette_stride)?)?;
    let stride = (width as usize * depth as usize).div_ceil(32) * 4;
    if depth <= 8 && colors > 1usize << depth {
        return None;
    }
    data.get(header..offset)?;
    let indices;
    let source = if compression == 0 {
        data.get(offset..offset.checked_add(stride * height.unsigned_abs() as usize)?)?
    } else {
        let length = dword(data, 20)? as usize;
        let stream = if length == 0 {
            data.get(offset..)?
        } else {
            data.get(offset..offset.checked_add(length)?)?
        };
        indices = rle(stream, width as usize, height as usize, depth)?;
        &indices
    };
    let out_width = if wanted_width > 0 {
        wanted_width
    } else {
        width
    };
    let out_height = if wanted_height > 0 {
        wanted_height
    } else {
        height.abs()
    };
    if out_width > 2048 || out_height > 2048 {
        return None;
    }
    let mut bits = vec![0u8; out_width as usize * out_height as usize * 4];
    for y in 0..out_height as usize {
        let sy = y * height.unsigned_abs() as usize / out_height as usize;
        let row = if height > 0 {
            height as usize - 1 - sy
        } else {
            sy
        } * if compression == 0 {
            stride
        } else {
            width as usize
        };
        for x in 0..out_width as usize {
            let sx = x * width as usize / out_width as usize;
            let pixel = if depth <= 8 {
                let bit = sx * depth as usize;
                let index = if compression == 0 {
                    ((source[row + bit / 8] >> (8 - depth as usize - bit % 8))
                        & ((1u16 << depth) - 1) as u8) as usize
                } else {
                    source[row + sx] as usize
                };
                if index >= colors {
                    return None;
                }
                data.get(header + index * palette_stride..header + index * palette_stride + 3)?
            } else {
                &source[row + sx * (depth as usize / 8)..][..3]
            };
            let at = (y * out_width as usize + x) * 4;
            bits[at..at + 3].copy_from_slice(pixel);
        }
    }
    Some((out_width, out_height, bits))
}

// Microsoft GDI bitmap compression: encoded runs, word-aligned absolute
// packets, EOL/EOB, and relative cursor movement. Keep palette indices in
// bottom-up row order until the common scaling/color conversion pass.
// https://learn.microsoft.com/en-us/windows/win32/gdi/bitmap-compression
fn rle(data: &[u8], width: usize, height: usize, depth: u16) -> Option<Vec<u8>> {
    let mut pixels = vec![0; width.checked_mul(height)?];
    let (mut at, mut x, mut y) = (0usize, 0usize, 0usize);
    loop {
        let count = *data.get(at)? as usize;
        let value = *data.get(at + 1)?;
        at += 2;
        if count == 0 {
            match value {
                0 => {
                    x = 0;
                    y = y.checked_add(1)?;
                    if y > height {
                        return None;
                    }
                    continue;
                }
                1 => return Some(pixels),
                2 => {
                    x = x.checked_add(*data.get(at)? as usize)?;
                    y = y.checked_add(*data.get(at + 1)? as usize)?;
                    at += 2;
                    if x > width || y >= height {
                        return None;
                    }
                    continue;
                }
                _ => {}
            }
        }
        let n = if count == 0 { value as usize } else { count };
        if y >= height || x.checked_add(n)? > width {
            return None;
        }
        let bytes = if depth == 4 { n.div_ceil(2) } else { n };
        let literal = if count == 0 {
            let padded = (bytes + 1) & !1;
            let packet = data.get(at..at.checked_add(padded)?)?;
            at += padded;
            packet
        } else {
            &[]
        };
        for i in 0..n {
            pixels[y * width + x + i] = if depth == 4 {
                let byte = if count == 0 { literal[i / 2] } else { value };
                if i & 1 == 0 { byte >> 4 } else { byte & 15 }
            } else if count == 0 {
                literal[i]
            } else {
                value
            };
        }
        x += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dib(width: i32, height: i32, depth: u16, compression: u32, stream: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 40 + (1usize << depth) * 4];
        data[..4].copy_from_slice(&40u32.to_le_bytes());
        data[4..8].copy_from_slice(&width.to_le_bytes());
        data[8..12].copy_from_slice(&height.to_le_bytes());
        data[12..14].copy_from_slice(&1u16.to_le_bytes());
        data[14..16].copy_from_slice(&depth.to_le_bytes());
        data[16..20].copy_from_slice(&compression.to_le_bytes());
        data[20..24].copy_from_slice(&(stream.len() as u32).to_le_bytes());
        for i in 0..1usize << depth {
            data[40 + i * 4..43 + i * 4].fill(i as u8);
        }
        data.extend_from_slice(stream);
        data
    }
    #[test]
    fn rle4_runs_literals_padding_delta_and_bottom_up() {
        // Bottom: 1 2 1 2 1 0 0 0; middle: 3 4 5 6 7 0 0 0;
        // top: 0 0 8 9 8 0 0 0. Five literal nibbles need a pad byte.
        let stream = [
            5, 0x12, 0, 0, 0, 5, 0x34, 0x56, 0x70, 0, 0, 0, 0, 2, 2, 0, 3, 0x89, 0, 1,
        ];
        let (_, _, bits) = decode(&dib(8, 3, 4, 2, &stream), 0, 0).unwrap();
        let actual: Vec<_> = bits.chunks_exact(4).map(|p| p[0]).collect();
        assert_eq!(
            actual,
            [
                0, 0, 8, 9, 8, 0, 0, 0, 3, 4, 5, 6, 7, 0, 0, 0, 1, 2, 1, 2, 1, 0, 0, 0
            ]
        );
    }
    #[test]
    fn rle8_literals_delta_and_scaling() {
        let stream = [0, 3, 1, 2, 3, 0, 0, 0, 0, 2, 1, 0, 2, 4, 0, 1];
        let (_, _, bits) = decode(&dib(3, 2, 8, 1, &stream), 6, 2).unwrap();
        let actual: Vec<_> = bits.chunks_exact(4).map(|p| p[0]).collect();
        assert_eq!(actual, [0, 0, 4, 4, 4, 4, 1, 1, 2, 2, 3, 3]);
    }
    #[test]
    fn rejects_truncation_overflow_invalid_palette_and_top_down_rle() {
        for stream in [
            &[0][..],
            &[4, 0x12, 0, 1],
            &[0, 3, 0x12],
            &[0, 2, 4, 0, 0, 1],
            &[3, 0x12],
        ] {
            assert!(decode(&dib(3, 1, 4, 2, stream), 0, 0).is_none());
        }
        assert!(decode(&dib(3, -1, 4, 2, &[3, 0x12, 0, 1]), 0, 0).is_none());
        let mut data = dib(3, 1, 4, 2, &[3, 0x12, 0, 1]);
        data[32..36].copy_from_slice(&17u32.to_le_bytes());
        assert!(decode(&data, 0, 0).is_none());
    }
    #[test]
    fn uncompressed_indexed_rows_still_work() {
        let data = dib(3, 2, 4, 0, &[0x12, 0x30, 0, 0, 0x45, 0x60, 0, 0]);
        let (_, _, bits) = decode(&data, 0, 0).unwrap();
        assert_eq!(
            bits.chunks_exact(4).map(|p| p[0]).collect::<Vec<_>>(),
            [4, 5, 6, 1, 2, 3]
        );
    }
}
