//
// Created by gerben stavenga on 6/25/23.
//

#include "utils.h"

extern "C" {

void *memcpy(void *dst, const void *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        static_cast<char *>(dst)[i] = static_cast<const char *>(src)[i];
    }
    return dst;
    //return __builtin_memcpy(dst, src, n);
}

void *memset(void *dst, int value, size_t n) {
    for (size_t i = 0; i < n; i++) {
        static_cast<char *>(dst)[i] = value;
    }
    return dst;
    //return __builtin_memset(dst, value, n);
}

void *memmove(void *dst, const void *src, size_t n) {
    auto d = static_cast<char *>(dst);
    auto s = static_cast<const char *>(src);
    if (reinterpret_cast<uintptr_t>(dst) < reinterpret_cast<uintptr_t>(src)) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return dst;
}

void *memchr(const void *ptr, int value, size_t n) {
    auto p = static_cast<const char *>(ptr);
    while (n--) {
        if (*p == value) {
            return const_cast<char *>(p);
        }
        p++;
    }
    return nullptr;
}

int memcmp(const void *lhs, const void *rhs, size_t n) {
    auto l = static_cast<const char *>(lhs);
    auto r = static_cast<const char *>(rhs);
    while (n--) {
        if (*l != *r) {
            return *l - *r;
        }
        l++;
        r++;
    }
    return 0;
}

size_t strlen(const char *str) {
    size_t i = 0;
    while (str[i]) i++;
    return i;
}

size_t strnlen(const char *str, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (str[i] == 0) return i;
    }
    return n;
}

const char *strchr(const char *str, int c) {
    for (size_t i = 0; str[i]; i++) {
        if (str[i] == c) {
            return str + i;
        }
    }
    return nullptr;
}

const char *strrchr(const char *str, int c) {
    const char *last = nullptr;
    for (size_t i = 0; str[i]; i++) {
        if (str[i] == c) {
            last = str + i;
        }
    }
    return last;
}

int strcmp(const char *lhs, const char *rhs) {
    auto l = reinterpret_cast<const uint8_t *>(lhs);
    auto r = reinterpret_cast<const uint8_t *>(rhs);
    while (*l && *l == *r) {
        l++;
        r++;
    }
    return *l - *r;
}

int strncmp(const char *lhs, const char *rhs, size_t n) {
    auto l = reinterpret_cast<const uint8_t *>(lhs);
    auto r = reinterpret_cast<const uint8_t *>(rhs);
    while (n-- && *l && *l == *r) {
        l++;
        r++;
    }
    return n ? *l - *r : 0;
}

char *strcpy(char *dst, const char *src) {
    auto d = dst;
    do {
        *d++ = *src;
    } while (*src++);
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
    auto d = dst;
    while (n--) {
        *d++ = *src;
        if (*src) {
            src++;
        }
    }
    return dst;
}

char *strcat(char *dst, const char *src) {
    strcpy(dst + strlen(dst), src);
    return dst;
}

char *strncat(char *dst, const char *src, size_t n) {
    strncpy(dst + strlen(dst), src, n);
    return dst;
}

const char* strstr(const char *haystack, const char *needle) {
    size_t len = 0;
    while (needle[len]) {
        if (haystack[len] == needle[len]) {
            len++;
        } else {
            if (!haystack[len]) return nullptr;
            len = 0;
            haystack++;
        }
    }
    return haystack;
}

}  // extern "C"

void panic_assert(OutputStream& out, string_view cond_str, string_view file, int line) {
    print(out, "Kernel assert: Condition \"{}\" failed at {}:{}.\n", cond_str, file, line);
    terminate(-1);
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
                if (j == format.size() || k >= n) {
                    goto error;
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
error:
        print(out, "\n\nInvalid format string: \"{}\" with {} arguments.\n", format, n);
        terminate(-1);
    }
}

NOINLINE void print_char(BufferedOStream& out, uintptr_t x, uintptr_t) {
    out.put(x);
}

NOINLINE void print_val_u(BufferedOStream& out, uintptr_t x, uintptr_t y) {
    auto z = uint64_t(x) | (uint64_t(y) << 32);
    char buf[20];
    int n = 0;
    do {
        buf[n++] = z % 10;
        z /= 10;
    } while (z);
    for (int i = n - 1; i >= 0; i--) {
        out.put(buf[i] + '0');
    }
}

void print_val_s(BufferedOStream& out, uintptr_t x, uintptr_t y) {
    auto z = uint64_t(x) | (uint64_t(y) << 32);
    if (int64_t(z) < 0) {
        out.put('-');
        z = (~z) + 1;
    }
    print_val_u(out, z, z >> 32);
}

inline char HexDigit(int x) {
    return x < 10 ? '0' + x : 'a' + x - 10;
}

NOINLINE static void print_hex(BufferedOStream& out, uintptr_t x, uintptr_t ndigits) {
    for (int i = ndigits - 1; i >= 0; i--) {
        int digit = (x >> (i * 4)) & 0xf;
        out.put(HexDigit(digit));
    }
}

void print_val_hex(BufferedOStream& out, uintptr_t x, uintptr_t ndigits) {
    out.put('0'); out.put('x');
    print_hex(out, x, ndigits);
}

void print_val_hex64(BufferedOStream& out, uintptr_t x, uintptr_t y) {
    out.put('0'); out.put('x');
    print_hex(out, y, sizeof(uintptr_t) * 2);
    print_hex(out, x, sizeof(uintptr_t) * 2);
}

void print_val_str(BufferedOStream& out, uintptr_t data, uintptr_t size) {
    string_view str(reinterpret_cast<const char*>(data), size);
    for (size_t i = 0; i < str.size(); i++) {
        out.put(str[i]);
    }
}

void print_val_hexbuf(BufferedOStream& out, uintptr_t data, uintptr_t size) {
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
    char _version[2];
    char _username[32];
    char _groupname[32];
    char _devmajor[8];
    char _devminor[8];
    char prefix[155];
    char _pad[12];
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
    static const uint8_t kShifts[4][4] = {
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

    auto hash_group = [&A, &B, &C, &D, block_data](int group, auto func) {
        constexpr uint8_t base[4] = {0, 1, 5, 0};
        constexpr uint8_t stride[4] = {1, 5, 3, 7};
        for (int i = 0, g = base[group]; i < 16; i++, g += stride[group]) {
            uint32_t F = A + func(B, C, D) + kConsts[group][i] + block_data[g & 0xf];
            A = D;
            D = C;
            C = B;
            B = B + LeftRotate(F, kShifts[group][i & 3]);
        }
    };

    hash_group(0, [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((~x) & z); });
    hash_group(1, [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & (~z)); });
    hash_group(2, [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; });
    hash_group(3, [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | (~z)); });

    md5_hash[0] += A;
    md5_hash[1] += B;
    md5_hash[2] += C;
    md5_hash[3] += D;
}

void md5(string_view buf, char out[16]) {
    // Initialize variables:
    uint32_t md5_hash[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };   // A, B, C, D

    uint64_t len = buf.size() * 8;
    while (buf.size() >= 64) {
        ChunkMD5(buf.data(), md5_hash);
        buf.remove_prefix(64);
    }
    char padding[64] = {};
    memcpy(padding, buf.data(), buf.size());
    padding[buf.size()] = 0x80;
    auto p = buf.size() + 1;
    if (p > 56) {
        ChunkMD5(padding, md5_hash);
        memset(padding, 0, 56);
    }
    memcpy(padding + 56, &len, sizeof(uint64_t));
    ChunkMD5(padding, md5_hash);

    memcpy(out, md5_hash, 16);
}
