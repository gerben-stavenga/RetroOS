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
    constexpr string_view(const char* s) : string_view(s, strlen(s)) {}
    template<int N> constexpr string_view(const char s[N]) : string_view(s, N) {}
    constexpr string_view(const char* s, size_t n) : data_(s), size_(n) {}

    void remove_prefix(size_t n) { data_ += n; size_ -= n; }

    char operator[](size_t i) const { return data_[i]; }
    const char* data() const { return data_; }
    size_t size() const { return size_; }
    const char* begin() const { return data_; }
    const char* end() const { return data_ + size_; }
    string_view substr(size_t start, size_t end) const { return string_view(data_ + start, end - start); }

    bool operator==(string_view other) {
        if (size_ != other.size_) return false;
        for (size_t i = 0; i < size_; i++) {
            if (data_[i] != other.data_[i]) return false;
        }
        return true;
    }
private:
    const char* data_ = nullptr;
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

template<typename T>
struct Hex {
    constexpr Hex(T x_) : x(x_) {}
    T x;
};

void print_char(BufferedOStream& out, uint64_t x, uint64_t);
void print_val_u(BufferedOStream& out, uint64_t x, uint64_t);
void print_val_s(BufferedOStream& out, uint64_t x, uint64_t);
void print_val_hex(BufferedOStream& out, uint64_t x, uint64_t ndigits);
void print_val_str(BufferedOStream& out, uint64_t data, uint64_t size);
void print_val_hexbuf(BufferedOStream& out, uint64_t data, uint64_t size);

struct ValuePrinter {
    uint64_t value;
    uint64_t extra;
    void (*print)(BufferedOStream& out, uint64_t value, uint64_t extra);
};

inline ValuePrinter MakeValuePrinter(const bool* x) {
    return {static_cast<uint64_t>(*x), 0, print_val_u };
}
inline ValuePrinter MakeValuePrinter(const char* x) {
    return {static_cast<uint64_t>(*x), 0, print_char };
}
inline ValuePrinter MakeValuePrinter(const int16_t* x) {
    return {static_cast<uint64_t>(*x), 0, print_val_s };
}
inline ValuePrinter MakeValuePrinter(const uint16_t* x) {
    return {static_cast<uintptr_t>(*x), 0, print_val_u };
}
inline ValuePrinter MakeValuePrinter(const int* x) {
    return {static_cast<uint64_t>(*x), 0, print_val_s };
}
inline ValuePrinter MakeValuePrinter(const uint32_t* x) {
    return {static_cast<uintptr_t>(*x), 0, print_val_u };
}
inline ValuePrinter MakeValuePrinter(const long int* x) {
    return {static_cast<uint64_t>(*x), 0, print_val_s };
}
inline ValuePrinter MakeValuePrinter(const uint64_t* x) {
    return {static_cast<uintptr_t>(*x), 0, print_val_u };
}

template <typename T>
ValuePrinter MakeValuePrinter(const Hex<T>* x) {
    return {static_cast<uint64_t>(x->x), sizeof(T) * 2, print_val_hex };
}

template <>
inline ValuePrinter MakeValuePrinter<string_view>(const Hex<string_view>* x) {
    return {reinterpret_cast<uintptr_t>(x->x.data()), x->x.size(), print_val_hexbuf };
}

template <typename T>
inline ValuePrinter MakeValuePrinter(T const* const* x) {
    auto tmp = Hex(reinterpret_cast<uintptr_t>(*x));
    return MakeValuePrinter(&tmp);
}

inline ValuePrinter MakeValuePrinter(const string_view* x) {
    return {reinterpret_cast<uintptr_t>(x->data()), x->size(), print_val_str };
}
inline ValuePrinter MakeValuePrinter(char const* const* x) {
    auto tmp = string_view(*x);
    return MakeValuePrinter(&tmp);
}

void print_buf(BufferedOStream& out, string_view format, const ValuePrinter* printers, size_t n);

template <typename T, size_t N>
struct Array {
    T data[N];
    constexpr size_t size() const { return N; }
    constexpr const T& operator[](size_t i) const { return data[i]; }
    constexpr T& operator[](size_t i) { return data[i]; }
};

void PrintImpl(OutputStream& out, string_view format, const ValuePrinter* printers, size_t n);

template<int N>
class BufferedOStreamN : public BufferedOStream {
public:
    constexpr BufferedOStreamN(OutputStream* stream_) : BufferedOStream(stream_, N) {}
private:
    char buffer[N];
};

template <typename... Args>
void print(OutputStream& out, string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(&args)...};
    PrintImpl(out, format, printers, n);
}

template <typename... Args>
void print(BufferedOStream& out, string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(&args)...};
    print_buf(out, format, printers, n);
}

[[noreturn]] void terminate() __attribute__((weak));

[[noreturn]] void panic_assert(OutputStream& out, string_view str, string_view file, int line);

inline void AssertImpl(bool cond, OutputStream& out, string_view cond_str, string_view file, int line) {
    if (kDebug && !cond) panic_assert(out, cond_str, file, line);
}

class USTARReader {
public:
    USTARReader() = default;
    USTARReader(size_t block) : block_(block) {}

    size_t FindFile(string_view filename);
    size_t ReadHeader(void* buf);
    bool ReadFile(void* buf, size_t size);

protected:
    size_t block_ = 0;
private:
    virtual bool ReadBlocks(int n, void *buf) = 0;

    void SkipBlocks(int n) {
        block_ += n;
    }
};

void md5(string_view buf, char out[16]);

inline uint32_t LoadLE32(const void* p) {
    auto up = static_cast<uint8_t const*>(p);
    return uint32_t(up[0]) | uint32_t(up[1]) << 8 | uint32_t(up[2]) << 16 | uint32_t(up[3]) << 24;
}

#endif //OS_UTILS_H
