//
// Created by gerben stavenga on 6/10/23.
//

#ifndef OS_UTILS_H
#define OS_UTILS_H

#include <stdint.h>
#include <stddef.h>

#define NOINLINE __attribute__((noinline))

#ifdef NDEBUG
constexpr bool kDebug = false;
#else
constexpr bool kDebug = true;
#endif

template <typename T, size_t N>
constexpr size_t array_size(const T (&)[N]) {
    return N;
}

inline void memmove(void* dst, const void* src, size_t n) {
    if (reinterpret_cast<uintptr_t>(dst) <= reinterpret_cast<uintptr_t>(src)) {
        for (size_t i = 0; i < n; i++) {
            static_cast<uint8_t*>(dst)[i] = static_cast<const uint8_t*>(src)[i];
        }
    } else {
        for (size_t i = n; i > 0; i--) {
            static_cast<uint8_t*>(dst)[i - 1] = static_cast<const uint8_t*>(src)[i - 1];
        }
    }
}

inline void memcpy(void* dst, const void* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        static_cast<uint8_t*>(dst)[i] = static_cast<const uint8_t*>(src)[i];
    }
}

inline void memset(void* dst, int value, size_t n) {
    for (size_t i = 0; i < n; i++) {
        static_cast<uint8_t*>(dst)[i] = value;
    }
}

inline char* strncpy(char* dst, const char* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
        if (src[i] == 0) {
            return dst;
        }
    }
    return dst;
}

inline constexpr size_t strlen(const char* p) {
    size_t i = 0;
    for (; p[i] != 0; i++);
    return i;
}

inline constexpr size_t strnlen(const char* p, size_t max) {
    for (size_t i = 0; i < max; i++) if (p[i] == 0) return i;
    return max;
}

struct string_view {
    constexpr string_view() = default;
    constexpr string_view(const char* s) : p(s), size_(strlen(s)) {}
    template<int N> constexpr string_view(const char s[N]) : p(s), size_(strlen(s)) {}
    constexpr string_view(const char* s, size_t n) : p(s), size_(n) {}

    string_view consume(size_t i) { return string_view(p + i, size_ - i); }
    char operator[](size_t i) { return p[i]; }

    const char* data() const { return p; }
    size_t size() const { return size_; }
    const char* begin() const { return p; }
    const char* end() const { return p + size_; }

    bool operator==(string_view other) {
        if (size_ != other.size_) return false;
        for (size_t i = 0; i < size_; i++) {
            if (p[i] != other.p[i]) return false;
        }
        return true;
    }
private:
    const char* p = nullptr;
    size_t size_ = 0;
};

class OutputStream {
public:
    virtual void Push(string_view) = 0;
};

class BufferedOStream {
public:
    ~BufferedOStream() {
        char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedOStream);
        if (pos != 0) {
            stream->Push({buffer, pos});
        }
    }

    void put(char c) {
        char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedOStream);
        buffer[pos++] = c;
        if (c == '\n' || pos == buffer_size) {
            stream->Push({buffer, pos});
            pos = 0;
        }
    }

protected:
    constexpr BufferedOStream(OutputStream* stream_, size_t buffer_size_) : stream(stream_), buffer_size(buffer_size_) {}

private:
    OutputStream* stream;
    size_t pos = 0;
    size_t buffer_size;
};

template<int N>
class BufferedOStreamN : public BufferedOStream {
public:
    constexpr BufferedOStreamN(OutputStream* stream_) : BufferedOStream(stream_, N) {}
private:
    char buffer[N];
};

template<typename T>
struct Hex {
    constexpr Hex(T x_) : x(x_) {}
    T x;
};

void print_val_u(BufferedOStream& out, uint64_t x);
void print_val_s(BufferedOStream& out, int64_t x);
void print_val_hex(BufferedOStream& out, uint64_t x, int ndigits);
void print_val_str(BufferedOStream& out, string_view buf);

inline void print_val(BufferedOStream& out, const int& x) {
    print_val_s(out, x);
}

inline void print_val(BufferedOStream& out, const unsigned& x) {
    print_val_s(out, x);
}

inline void print_val(BufferedOStream& out, const long& x) {
    print_val_s(out, x);
}

inline void print_val(BufferedOStream& out, const long unsigned& x) {
    print_val_s(out, x);
}

inline void print_val(BufferedOStream& out, const char& c) {
    out.put(c);
}

inline void print_val(BufferedOStream& out, const void* p) {
    print_val_hex(out, reinterpret_cast<uintptr_t>(p), sizeof(uintptr_t) * 2);
}

inline void print_val(BufferedOStream& out, const string_view& buf) {
    print_val_str(out, buf);
}

inline void print_val(BufferedOStream& out, char const* const& s) {
    print_val(out, string_view(s));
}

template <typename T>
void print_val(BufferedOStream& out, const Hex<T>& x) {
    print_val_hex(out, x.x, sizeof(T) * 2);
}

string_view print_buf(BufferedOStream& out, string_view format);

template <typename Head, typename... Tail>
void print_buf(BufferedOStream& out, string_view format, const Head& head, const Tail&... tail) {
    if (format.size() > 0) {
        format = print_buf(out, format);
    }
    print_val(out, head);
    print_buf(out, format, tail...);
}

template <typename CharOut, typename... Args>
void print(CharOut& out, string_view format, const Args&... args) {
    BufferedOStreamN<100> buf(&out);
    print_buf(buf, format, args...);
}

class USTARReader {
public:
    size_t FindFile(string_view filename);
    size_t ReadHeader(void* buf);
    bool ReadFile(void* buf, size_t size);

private:
    virtual bool ReadBlocks(int n, void *buf) = 0;
    virtual void SkipBlocks(int n) = 0;
};

class RamUSTARReader : public USTARReader {
public:
    constexpr RamUSTARReader(const char* data, size_t size) : data_(data), size_(size) {}

    bool ReadBlocks(int n, void *buf) override {
        if (pos_ + n * 512 > size_) return false;
        memcpy(buf, data_ + pos_, n * 512);
        pos_ += n * 512;
        return true;
    }

    void SkipBlocks(int n) override {
        pos_ += n * 512;
    }

private:
    const char* data_;
    size_t size_;
    size_t pos_ = 0;
};

#endif //OS_UTILS_H
