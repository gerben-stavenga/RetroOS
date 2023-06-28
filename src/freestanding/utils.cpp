//
// Created by gerben stavenga on 6/25/23.
//

#include "utils.h"

void print_val_u(BufferedOStream& out, uint64_t x) {
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

void print_val_s(BufferedOStream& out, int64_t x) {
    if (x < 0) {
        out.put('-');
        x = (~x) + 1;
    }
    print_val_u(out, uint64_t (x));
}

void print_val_hex(BufferedOStream& out, uint64_t x, int ndigits) {
    out.put('0'); out.put('x');
    for (int i = ndigits - 1; i >= 0; i--) {
        int digit = (x >> (i * 4)) & 0xf;
        out.put(digit < 10 ? '0' + digit : 'a' + digit - 10);
    }
}

void print_val_str(BufferedOStream& out, string_view buf) {
    for (size_t i = 0; i < buf.size; i++) {
        out.put(buf[i]);
    }
}

string_view print_buf(BufferedOStream& out, string_view format) {
    int bracket = 0;
    for (size_t i = 0; i < format.size; i++) {
        char c = format.p[i];
        if (bracket == 1) {
            if (c == '}') {
                bracket--;
                return format.consume(i + 1);
            } else if (c == '{') {
                bracket = 0;
            } else {
                return string_view();
            }
        } else if (bracket == -1) {
            if (c == '}') {
                bracket = 0;
            } else {
                return string_view();
            }
        } else if (c == '{') {
            bracket++;
            continue;
        } else if (c == '}') {
            bracket--;
            continue;
        }
        out.put(c);
    }
    return string_view();
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

    char filename_[256];
    char link_target_[256];
};

uint64_t ReadOctal(string_view buf) {
    uint64_t result = 0;
    for (size_t i = 0; i < buf.size; i++) {
        char c = buf.p[i];
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
    if (bufsize % kUSTARBlockSize != 0) {
        if (!ReadBlocks(1, tmp_buf)) {
            return false;
        }
        memcpy((char*)buf + bufsize - bufsize % kUSTARBlockSize, tmp_buf, bufsize % kUSTARBlockSize);
    }
    return true;
}
