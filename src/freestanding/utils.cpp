//
// Created by gerben stavenga on 6/25/23.
//

#include "utils.h"

#include "demangle.h"

constinit StdOutStream std_out;

extern "C" {

void *memcpy(void *dst, const void *src, std::size_t n) {
    for (std::size_t i = 0; i < n; i++) {
        static_cast<char *>(dst)[i] = static_cast<const char *>(src)[i];
    }
    return dst;
}

void *memset(void *dst, int value, std::size_t n) {
    for (std::size_t i = 0; i < n; i++) {
        static_cast<char *>(dst)[i] = value;
    }
    return dst;
}

void *memmove(void *dst, const void *src, std::size_t n) {
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

void *memchr(const void *ptr, int value, std::size_t n) {
    auto p = static_cast<const char *>(ptr);
    while (n--) {
        if (*p == value) {
            return const_cast<char *>(p);
        }
        p++;
    }
    return nullptr;
}

int memcmp(const void *lhs, const void *rhs, std::size_t n) {
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

std::size_t strlen(const char *str) {
    std::size_t i = 0;
    while (str[i]) i++;
    return i;
}

std::size_t strnlen(const char *str, std::size_t n) {
    for (std::size_t i = 0; i < n; i++) {
        if (str[i] == 0) return i;
    }
    return n;
}

char *strchr(const char *str, int c) {
    for (std::size_t i = 0; str[i]; i++) {
        if (str[i] == c) {
            return const_cast<char*>(str + i);
        }
    }
    return nullptr;
}

char *strrchr(const char *str, int c) {
    const char *last = nullptr;
    for (std::size_t i = 0; str[i]; i++) {
        if (str[i] == c) {
            last = str + i;
        }
    }
    return const_cast<char*>(last);
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

int strncmp(const char *lhs, const char *rhs, std::size_t n) {
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

char *strncpy(char *dst, const char *src, std::size_t n) {
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

char *strncat(char *dst, const char *src, std::size_t n) {
    strncpy(dst + strlen(dst), src, n);
    return dst;
}

char* strstr(const char *haystack, const char *needle) {
    std::size_t len = 0;
    while (needle[len]) {
        if (haystack[len] == needle[len]) {
            len++;
        } else {
            if (!haystack[len]) return nullptr;
            len = 0;
            haystack++;
        }
    }
    return const_cast<char*>(haystack);
}

}  // extern "C"

PanicStream::~PanicStream() {
    print(std_out, "\n");
    Exit(-1);
}

PanicStream GetPanicStream(const char* cond_str, const char* file, int line) {
    print(std_out, "assert: Condition \"{}\" failed at {}:{}.", cond_str, file, line);
    return PanicStream();
}

NOINLINE void PrintImpl(OutputStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n) {
    char* pos;
    BufferedOStream buf(&out, &pos);
    buf.Flush(print_buf(pos, buf, format, printers, n));
}

NOINLINE char* print_buf(char* pos, BufferedOStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n) {
    std::size_t k = 0;
    for (std::size_t i = 0; i < format.size(); i++) {
        if (PREDICT_FALSE(format[i] == '{')) {
            if (i + 1 < format.size() && format[i + 1] == '{') {
                pos = out.put(pos, '{');
                i++;
            } else {
                std::size_t j = i + 1;
                while (j < format.size() && format  [j] != '}') {
                    j++;
                }
                if (j == format.size() || k >= n) {
                    goto error;
                }
                pos = printers[k].print(pos, out, printers[k]);
                k++;
                i = j;
            }
        } else if (PREDICT_FALSE(format[i] == '}')) {
            if (i + 1 < format.size() && format[i + 1] == '}') {
                pos = out.put(pos, format[i]);
                i++;
            } else {
                goto error;
            }
        } else {
            pos = out.put(pos, format[i]);
        }
    }
    if (k < n) {
error:
        pos = print(pos, out, "\n\nInvalid format string: \"{}\" with {} arguments.\n", format, n);
        Exit(-1);
    }
    return pos;
}

NOINLINE char* print_char(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    return out.put(pos, value.n);
}

NOINLINE char* print_decimal(char* pos, BufferedOStream& out, uint64_t z) {
    char buf[20];
    int n = 0;
    do {
        buf[n++] = z % 10;
        z /= 10;
    } while (z);
    for (int i = n - 1; i >= 0; i--) {
        pos = out.put(pos, buf[i] + '0');
    }
    return pos;
}

NOINLINE char* print_val_u(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    auto z = value.n;
    return print_decimal(pos, out, z);
}

char* print_val_s(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    auto z = value.n;
    if (int64_t(z) < 0) {
        pos = out.put(pos, '-');
        z = -z;
    }
    return print_decimal(pos, out, z);
}

inline char HexDigit(int x) {
    return x < 10 ? '0' + x : 'a' + x - 10;
}

NOINLINE static char* print_hex(char* pos, BufferedOStream& out, uintptr_t x, uintptr_t ndigits) {
    for (int i = ndigits - 1; i >= 0; i--) {
        int digit = (x >> (i * 4)) & 0xf;
        pos = out.put(pos, HexDigit(digit));
    }
    return pos;
}

char* print_val_hex(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    auto x = value.hex_num.x;
    auto ndigits = value.hex_num.size;
    pos = out.put(pos, '0'); pos = out.put(pos, 'x');
    return print_hex(pos, out, x, ndigits);
}

char* print_val_hex64(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    uintptr_t x = value.n & 0xFFFFFFFF;
    uintptr_t y = value.n >> 32;
    pos = out.put(pos, '0'); pos = out.put(pos, 'x');
    pos = print_hex(pos, out, y, sizeof(uintptr_t) * 2);
    return print_hex(pos, out, x, sizeof(uintptr_t) * 2);
}

char* print_val_str(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    std::string_view str(value.s);
    for (std::size_t i = 0; i < str.size(); i++) {
        pos = out.put(pos, str[i]);
    }
    return pos;
}

char* print_val_hexbuf(char* pos, BufferedOStream& out, const ValuePrinter& value) {
    std::string_view str(value.s);
    for (std::size_t i = 0; i < str.size(); i++) {
        pos = out.put(pos, HexDigit(uint8_t(str[i]) >> 4));
        pos = out.put(pos, HexDigit(str[i] & 0xF));
    }
    return pos;
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
    std::string_view filename;
    uint32_t filemode;
    uint32_t uid;
    uint32_t gid;
    uint64_t filesize;
    uint64_t mtime;
    uint8_t typeflag;
    std::string_view link_target;
    char checksum[8];

    char filename_[256];
    char link_target_[256];
};

uint64_t ReadOctal(std::string_view buf) {
    uint64_t result = 0;
    for (std::size_t i = 0; i < buf.size(); i++) {
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

    result.filename = std::string_view(result.filename_, strnlen(result.filename_, sizeof(result.filename_)));
    result.link_target = std::string_view(result.link_target_, strnlen(result.link_target_, sizeof(result.link_target_)));

    result.filemode = ReadOctal(std::string_view(h.filemode, sizeof(h.filemode)));
    result.uid = ReadOctal(std::string_view(h.uid, sizeof(h.uid)));
    result.gid = ReadOctal(std::string_view(h.gid, sizeof(h.gid)));
    result.filesize = ReadOctal(std::string_view(h.filesize, sizeof(h.filesize)));
    result.mtime = ReadOctal(std::string_view(h.mtime, sizeof(h.mtime)));
    result.typeflag = h.typeflag[0];
    result.link_target = std::string_view(h.link_target, sizeof(h.link_target));
    memcpy(result.checksum, h.checksum, sizeof(h.checksum));
    return result;
}

constexpr int kUSTARBlockSize = 512;

std::size_t USTARReader::FindFile(std::string_view filename) {
    USTARRawHeader raw_header;
    block_ = 0;
    while (ReadBlocks(1, &raw_header)) {
        if (raw_header.filename[0] == '\0') break;
        USTARHeader header = Convert(raw_header);
        if (header.filename == filename) {
            return header.filesize;
        }
        int nblocks = (header.filesize + kUSTARBlockSize - 1) / kUSTARBlockSize;
        SkipBlocks(nblocks);
    }
    return SIZE_MAX;
}

std::size_t USTARReader::ReadHeader(void* buf) {
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

bool USTARReader::ReadFile(void* buf, std::size_t bufsize) {
    if (!ReadBlocks(bufsize / kUSTARBlockSize, buf)) {
        return false;
    }
    auto left_over = bufsize % kUSTARBlockSize;
    if (left_over != 0) {
        char tmp_buf[kUSTARBlockSize];
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
            {7, 12, 17, 22},
            {5, 9, 14, 20},
            {4, 11, 16, 23},
            {6, 10, 15, 21},
    };

    static const uint32_t kConsts[4][16] = {
            {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821},
            {0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a},
            {0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665},
            {0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391},
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

void md5(std::string_view buf, char out[16]) {
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

constexpr std::uint64_t kUsedMarker = 0xA110CEDDA110CEDDul;
constexpr std::uint64_t kFreeMarker = 0xFEE59ACEFEE59ACEul;

struct MemBlock {
    uint64_t marker;
    MemBlock* next;
    MemBlock* prev;
};

MemBlock* head;

void InitializeAllocator(void* ptr, std::size_t size) {
    auto start = static_cast<MemBlock*>(ptr);
    auto end = reinterpret_cast<MemBlock*>(GetAddress(ptr) + size - sizeof(MemBlock));
    *start = MemBlock{kFreeMarker, end, end};
    *end = MemBlock{kUsedMarker, start, start};  // sentinel
    head = start;
}

extern "C" {

void* malloc(std::size_t size) {
    auto p = head;
    size = (size + 7) & -8;
    do {
        assert(p->marker == kUsedMarker || p->marker == kFreeMarker);
        auto next = p->next;
        if (next < p) break;
        
        if (p->marker == kFreeMarker) {
            auto s = GetAddress(next) - GetAddress(p + 1);
            if (s >= size) {
                constexpr std::size_t kMinFreeBlock = 64;
                if (s >= size + sizeof(MemBlock) + kMinFreeBlock) {
                    auto n = GetAddress(p + 1) + size;                    
                    auto split = reinterpret_cast<MemBlock*>(n);
                    *split = MemBlock{kFreeMarker, next, p};
                    p->next = split;
                    next->prev = split;
                }
                p->marker = kUsedMarker;
                return p + 1;
            }
        }
        p = next;
    } while (true);
    return nullptr;
}

void* calloc(std::size_t size) {
    auto p = malloc(size);
    memset(p, 0, size);
    return p;
}

void* realloc(void* p, std::size_t size) {
    auto ret = malloc(size);
    memcpy(ret, p, size);
    free(p);
    return ret;
}

void free(void* ptr) {
    auto block = static_cast<MemBlock*>(ptr) - 1;
    assert(block->marker == kUsedMarker);
    block->marker = kFreeMarker;
    if (block->prev->marker == kFreeMarker) {
        block->prev->next = block->next;
        block->next->prev = block->prev;
    } else if (block->next->marker == kFreeMarker) {
        block->next->next->prev = block;
        block->next = block->next->next;
    }
}

}  // extern "C"

// Format of an ELF executable file

constexpr uint32_t kElfMagic = 0x464C457FU;  // "\x7FELF" in little endian

// File header
struct ElfHeader {
    uint32_t magic;  // must equal ELF_MAGIC
    uint8_t elf[12];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

// Program section header
struct ProgramHeader {
    uint32_t type;
    uint32_t off;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
};

struct SectionHeader {
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint32_t	sh_flags;
	uint32_t	sh_addr;
	uint32_t	sh_offset;
	uint32_t	sh_size;
	uint32_t	sh_link;
	uint32_t	sh_info;
	uint32_t	sh_addralign;
	uint32_t	sh_entsize;
};

enum ShT_Types {
	SHT_NULL	= 0,   // Null section
	SHT_PROGBITS	= 1,   // Program information
	SHT_SYMTAB	= 2,   // Symbol table
	SHT_STRTAB	= 3,   // String table
	SHT_RELA	= 4,   // Relocation (w/ addend)
	SHT_NOBITS	= 8,   // Not present in file
	SHT_REL		= 9,   // Relocation (no addend)
};

enum ShT_Attributes {
	SHF_WRITE	= 0x01, // Writable section
	SHF_ALLOC	= 0x02  // Exists in memory
};

struct Symbol {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
};

// Values for Proghdr type
enum {
    kElfProgLoad = 1,

    // Flag bits for Proghdr flags
    kElfProgFlagExec = 1,
    kElfProgFlagWrite = 2,
    kElfProgFlagRead = 4,
};

const void* LoadElf(std::string_view elf_buf, void* (*mmap)(uintptr_t, std::size_t, int)) {
    auto elf = reinterpret_cast<const ElfHeader*>(elf_buf.data());  // scratch space

    if (elf->magic != kElfMagic) return nullptr;
    if (elf->elf[0] != 1) return nullptr;
    if (elf->elf[1] != 1) return nullptr;
    if (elf->elf[3] != 0) return nullptr;
    if (elf->type != 2) return nullptr;  // executable
    if (elf->machine != 3) return nullptr;  // x86

    // Load each program segment (ignores ph flags).
    auto phs = reinterpret_cast<const ProgramHeader*>(&elf_buf[elf->phoff]);
    for (const auto& ph : Range(phs, elf->phnum)) {
        if (ph.type != kElfProgLoad) continue;
        auto buf = mmap(ph.vaddr, ph.memsz, ph.flags);
        memcpy(buf, &elf_buf[ph.off], ph.filesz);
    }
/*
    auto shs = reinterpret_cast<const SectionHeader*>(&elf_buf[elf->shoff]);
    auto strtab_sh = shs[elf->shstrndx];

    for (const auto& sh : Range(shs, elf->shnum)) {
        if (sh.sh_type != SHT_SYMTAB) continue;
        auto symtab = reinterpret_cast<const Symbol*>(reinterpret_cast<uintptr_t>(&sh) + sh.sh_offset);
        int nsyms = sh.sh_size / sh.sh_entsize;

        auto nsyms = symtab->st_size;
        for (const auto& sym : Range(symtab, nsyms)) {

        }
    }
*/
    return reinterpret_cast<const void*>(elf->entry);
}

struct Out : BufferedOStream {
    Out(char* buf, std::size_t size) : BufferedOStream(buf, size, &pos_) {}

    static void callback(const char* str, std::size_t len, void* opaque) {
        auto out = static_cast<Out*>(opaque);
        out->pos_ = out->Push(out->pos_, {str, len});
    }

    char* pos_;
};

void StackTrace(OutputStream& out, std::string_view symbol_map) {
    void* bp;
    asm ("movl %%ebp, %0": "=r" (bp));
    void** frame = static_cast<void**>(bp);
    bp = frame[0];
    char demangle_buf[256];
    char cstr[256];
    while (bp) {
        auto ip = frame[1];
        std::string_view name;
        for (auto p = symbol_map.begin(); p < symbol_map.end();) {
            uintptr_t x = 0;
            for (int i = 0; i < 8; i++) {
                x *= 16;
                if (p[i] >= 'a' && p[i] <= 'f') x += p[i] - 'a' + 10;
                else x += p[i] - '0'; 
            }
            if (x > reinterpret_cast<std::uintptr_t>(ip)) break;
            p += 11;
            auto tmp = p;
            while (*p != '\n') p++;
            memcpy(cstr, tmp, p - tmp);
            cstr[p - tmp] = 0;
            Out out(demangle_buf, sizeof(demangle_buf));
            if (true && cplus_demangle_v3_callback (cstr, 0, Out::callback, &out)) {
                name = {demangle_buf, out.Flush(out.pos_)};
            } else {
                out.Flush(out.pos_);
                name = {tmp, static_cast<std::size_t>(p - tmp)};
            }
            p++;
        }
        print(out, "{} at {} (sp = {})\n", ip, name, bp);
        frame = static_cast<void**>(bp);
        bp = frame[0];
    }
}
