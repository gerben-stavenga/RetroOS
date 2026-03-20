//! MD5 hash implementation

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn left_rotate(x: u32, c: u32) -> u32 {
    (x << c) | (x >> (32 - c))
}

fn process_block(block: &[u8; 64], a0: &mut u32, b0: &mut u32, c0: &mut u32, d0: &mut u32) {
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut a = *a0;
    let mut b = *b0;
    let mut c = *c0;
    let mut d = *d0;

    for i in 0..64 {
        let (f, g) = if i < 16 {
            ((b & c) | ((!b) & d), i)
        } else if i < 32 {
            ((d & b) | ((!d) & c), (5 * i + 1) % 16)
        } else if i < 48 {
            (b ^ c ^ d, (3 * i + 5) % 16)
        } else {
            (c ^ (b | (!d)), (7 * i) % 16)
        };

        let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(left_rotate(f, S[i]));
    }

    *a0 = a0.wrapping_add(a);
    *b0 = b0.wrapping_add(b);
    *c0 = c0.wrapping_add(c);
    *d0 = d0.wrapping_add(d);
}

/// Compute MD5 hash of data
pub fn compute(data: &[u8], out: &mut [u8; 16]) {
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let orig_len_bits = data.len() as u64 * 8;

    // Process complete 64-byte blocks
    let mut offset = 0usize;
    while offset + 64 <= data.len() {
        let mut block = [0u8; 64];
        block.copy_from_slice(&data[offset..offset + 64]);
        process_block(&block, &mut a0, &mut b0, &mut c0, &mut d0);
        offset += 64;
    }

    // Final block(s) with padding
    let remaining = data.len() - offset;
    let mut block = [0u8; 64];
    block[..remaining].copy_from_slice(&data[offset..]);
    block[remaining] = 0x80;

    if remaining < 56 {
        // Room for length in this block
        block[56..64].copy_from_slice(&orig_len_bits.to_le_bytes());
        process_block(&block, &mut a0, &mut b0, &mut c0, &mut d0);
    } else {
        // Need an extra block for length
        process_block(&block, &mut a0, &mut b0, &mut c0, &mut d0);
        block = [0u8; 64];
        block[56..64].copy_from_slice(&orig_len_bits.to_le_bytes());
        process_block(&block, &mut a0, &mut b0, &mut c0, &mut d0);
    }

    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
}
