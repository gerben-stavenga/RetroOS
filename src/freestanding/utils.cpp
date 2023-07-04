//
// Created by gerben stavenga on 6/25/23.
//

#include "utils.h"

void panic_assert(OutputStream& out, string_view cond_str, string_view file, int line) {
    print(out, "Kernel assert: Condition \"{}\" failed at {}:{}.\n", cond_str, file, line);
    terminate();
}

NOINLINE void PrintImpl(OutputStream& out, string_view format, const ValuePrinter* printers, size_t n) {
    BufferedOStreamN<100> buf(&out);
    print_buf(buf, format, printers, n);
}

NOINLINE void print_buf(BufferedOStream& out, string_view format, const ValuePrinter* printers, size_t n) {
    size_t k = 0;
    for (size_t i = 0; i < format.size(); i++) {
        if (format[i] == '{') {
            if (i + 1 < format.size() && format[i + 1] == '{') {
                out.put('{');
                i++;
            } else {
                size_t j = i + 1;
                while (j < format.size() && format[j] != '}') {
                    j++;
                }
                if (j == format.size()) {
                    terminate();
                }
                if (k >= n) {
                    terminate();
                }
                printers[k].print(out, printers[k].value, printers[k].extra);
                k++;
                i = j;
            }
        } else {
            out.put(format[i]);
        }
    }
    if (k < n) {
        terminate();
    }
}

NOINLINE void print_char(BufferedOStream& out, uint64_t x, uint64_t) {
    out.put(x);
}

NOINLINE void print_val_u(BufferedOStream& out, uint64_t x, uint64_t) {
    char buf[20];
    int n = 0;
    do {
        buf[n++] = x % 10;
        x /= 10;
    } while (x);
    for (int i = n - 1; i >= 0; i--) {
        out.put(buf[i] + '0');
    }
}

void print_val_s(BufferedOStream& out, uint64_t x, uint64_t) {
    if (int64_t(x) < 0) {
        out.put('-');
        x = (~x) + 1;
    }
    print_val_u(out, uint64_t (x), 0);
}

inline char HexDigit(int x) {
    return x < 10 ? '0' + x : 'a' + x - 10;
}

void print_val_hex(BufferedOStream& out, uint64_t x, uint64_t ndigits) {
    out.put('0'); out.put('x');
    for (int i = ndigits - 1; i >= 0; i--) {
        int digit = (x >> (i * 4)) & 0xf;
        out.put(HexDigit(digit));
    }
}

void print_val_str(BufferedOStream& out, uint64_t data, uint64_t size) {
    string_view str(reinterpret_cast<const char*>(data), size);
    for (size_t i = 0; i < str.size(); i++) {
        out.put(str[i]);
    }
}

void print_val_hexbuf(BufferedOStream& out, uint64_t data, uint64_t size) {
    string_view str(reinterpret_cast<const char*>(data), size);
    for (size_t i = 0; i < str.size(); i++) {
        out.put(HexDigit(uint8_t(str[i]) >> 4));
        out.put(HexDigit(str[i] & 0xF));
    }
}

struct USTARRawHeader {
    char filename[100];
    char filemode[8];
    char uid[8];
    char gid[8];
    char filesize[12];
    char mtime[12];
    char checksum[8];
    char typeflag[1];
    char link_target[100];
    char magic[6];
    char version[2];
    char username[32];
    char groupname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
};

static_assert(sizeof(USTARRawHeader) == 512);

struct USTARHeader {
    string_view filename;
    uint32_t filemode;
    uint32_t uid;
    uint32_t gid;
    uint64_t filesize;
    uint64_t mtime;
    uint8_t typeflag;
    string_view link_target;
    char checksum[8];

    char filename_[256];
    char link_target_[256];
};

uint64_t ReadOctal(string_view buf) {
    uint64_t result = 0;
    for (size_t i = 0; i < buf.size(); i++) {
        char c = buf[i];
        if (c < '0' || c > '7') {
            break;
        }
        result = result * 8 + (c - '0');
    }
    return result;
}

USTARHeader Convert(const USTARRawHeader& h) {
    USTARHeader result;

    bool extended = false;
    if (h.magic[0] == 'u' && h.magic[1] == 's' && h.magic[2] == 't' && h.magic[3] == 'a' && h.magic[4] == 'r'  && h.magic[5] == '\0') {
        extended = true;
    }
    auto p = extended ? strncpy(result.filename_, h.prefix, sizeof(h.prefix)) : result.filename_;
    strncpy(p, h.filename, sizeof(h.filename));

    strncpy(result.link_target_, h.link_target, sizeof(h.link_target));

    result.filename = string_view(result.filename_, strnlen(result.filename_, sizeof(result.filename_)));
    result.link_target = string_view(result.link_target_, strnlen(result.link_target_, sizeof(result.link_target_)));

    result.filemode = ReadOctal(string_view(h.filemode, sizeof(h.filemode)));
    result.uid = ReadOctal(string_view(h.uid, sizeof(h.uid)));
    result.gid = ReadOctal(string_view(h.gid, sizeof(h.gid)));
    result.filesize = ReadOctal(string_view(h.filesize, sizeof(h.filesize)));
    result.mtime = ReadOctal(string_view(h.mtime, sizeof(h.mtime)));
    result.typeflag = h.typeflag[0];
    result.link_target = string_view(h.link_target, sizeof(h.link_target));
    memcpy(result.checksum, h.checksum, sizeof(h.checksum));
    return result;
}

constexpr int kUSTARBlockSize = 512;

size_t USTARReader::FindFile(string_view filename) {
    USTARRawHeader raw_header;
    while (ReadBlocks(1, &raw_header)) {
        USTARHeader header = Convert(raw_header);
        if (header.filename == filename) {
            return header.filesize;
        }
        int nblocks = (header.filesize + kUSTARBlockSize - 1) / kUSTARBlockSize;
        SkipBlocks(nblocks);
    }
    return SIZE_MAX;
}

size_t USTARReader::ReadHeader(void* buf) {
    USTARRawHeader* raw_header = static_cast<USTARRawHeader*>(buf);
    if (!ReadBlocks(1, raw_header)) {
        return SIZE_MAX;
    }
    if (raw_header->filename[0] == '\0') {
        return SIZE_MAX;
    }
    USTARHeader header = Convert(*raw_header);
    return header.filesize;
}

bool USTARReader::ReadFile(void* buf, size_t bufsize) {
    char tmp_buf[kUSTARBlockSize];

    if (!ReadBlocks(bufsize / kUSTARBlockSize, buf)) {
        return false;
    }
    auto left_over = bufsize % kUSTARBlockSize;
    if (left_over != 0) {
        if (!ReadBlocks(1, tmp_buf)) {
            return false;
        }
        memcpy((char*)buf + bufsize - left_over, tmp_buf, left_over);
    }
    return true;
}

inline uint32_t LeftRotate(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

// All variables are unsigned 32 bit and wrap modulo 2^32 when calculating
static void ChunkMD5(const char* chunk, uint32_t md5_hash[4]) {
    static const uint32_t kShifts[4][4] = {
            7, 12, 17, 22,
            5, 9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21,
    };

    static const uint32_t kConsts[4][16] = {
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
    };

    uint32_t A = md5_hash[0];
    uint32_t B = md5_hash[1];
    uint32_t C = md5_hash[2];
    uint32_t D = md5_hash[3];

    uint32_t block_data[16];
    memcpy(block_data, chunk, 64);
    for (int group = 0; group < 4; group++) {
        static const int base[4] = {0, 1, 5, 0};
        static const int stride[4] = {1, 5, 3, 7};
        for (int j = 0, g = base[group]; j < 16; j++, g += stride[group]) {
            auto func = [group](uint32_t x, uint32_t y, uint32_t z) {
                switch (group) {
                    case 0:
                        return (x & y) | ((~x) & z);
                    case 1:
                        return (x & z) | (y & (~z));
                    case 2:
                        return x ^ y ^ z;
                    case 3:
                        return y ^ (x | (~z));
                    default:
                        __builtin_unreachable();
                }
            };
            uint32_t F = A + func(B, C, D) + kConsts[group][j] + block_data[g & 0xf];
            A = D;
            D = C;
            C = B;
            B = B + LeftRotate(F, kShifts[group][j & 3]);
        }
    }

    md5_hash[0] += A;
    md5_hash[1] += B;
    md5_hash[2] += C;
    md5_hash[3] += D;
}

void md5(string_view buf, char out[16]) {
    // Initialize variables:
    uint32_t md5_hash[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};   // A, B, C, D

    uint64_t len = buf.size() * 8;
    while (buf.size() >= 64) {
        ChunkMD5(buf.data(), md5_hash);
        buf.remove_prefix(64);
    }
    char padding[64];
    memcpy(padding, buf.data(), buf.size());
    padding[buf.size()] = 0x80;
    auto p = buf.size() + 1;
    if (p <= 56) {
        memset(padding + p, 0, 56 - p);
    } else {
        memset(padding + p, 0, 64 - p);
        ChunkMD5(padding, md5_hash);
        memset(padding, 0, 56);
    }
    memcpy(padding + 56, &len, sizeof(uint64_t));
    ChunkMD5(padding, md5_hash);

    memcpy(out, md5_hash, 16);
}
