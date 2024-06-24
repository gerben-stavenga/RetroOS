//
// Created by gerben stavenga on 6/10/23.
//

#ifndef OS_UTILS_H
#define OS_UTILS_H

#include <cstdint>
#include <cstddef>

#include <string_view>
#include <type_traits>

#define NOINLINE __attribute__((noinline))
#define ALWAYS_INLINE __attribute__((always_inline))
#define PREDICT_TRUE(x) __builtin_expect((x), 1)
#define PREDICT_FALSE(x) __builtin_expect((x), 0)

#ifdef NDEBUG
constexpr bool kDebug = false;
#else
constexpr bool kDebug = true;
#endif

template <typename T, std::size_t N>
constexpr std::size_t array_size(const T (&)[N]) { return N; }

extern "C" {

void *memmove(void *dst, const void *src, std::size_t n);
void *memcpy(void *dst, const void *src, std::size_t n);
void *memset(void *dst, int value, std::size_t n);
char *strncpy(char *dst, const char *src, std::size_t n);
// std::size_t strlen(const char *p);
std::size_t strnlen(const char *p, std::size_t max);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, std::size_t n);
char* strchr(const char *s, int c);
char* strrchr(const char *s, int c);
char* strstr(const char* haystack, const char* needle);

}

class OutputStream {
public:
    virtual void Push(std::string_view) = 0;
};

class BufferedOStream {
public:
    void Finalize(std::size_t pos) {
        if (pos != 0) {
            char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedOStream);
            stream->Push({buffer, pos});
        }
    }

    std::size_t put(std::size_t pos, char c) {
        char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedOStream);
        buffer[pos++] = c;
        if (PREDICT_FALSE(c == '\n' || pos == buffer_size)) {
            stream->Push({buffer, pos});
            pos = 0;
        }
        return pos;
    }

protected:
    constexpr BufferedOStream(OutputStream* stream_, std::size_t buffer_size_) : stream(stream_), buffer_size(buffer_size_) {}

private:
    OutputStream* stream;
    std::size_t buffer_size;
};

struct ValuePrinter {
    ValuePrinter() {};
    union {
        uint64_t n;
        struct {
            uintptr_t x;
            uintptr_t size;
        } hex_num;
        void* p;
        std::string_view s;
    };
    std::size_t (*print)(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
};

std::size_t print_char(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
std::size_t print_val_u(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
std::size_t print_val_s(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
std::size_t print_val_hex(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
std::size_t print_val_hex64(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
std::size_t print_val_str(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);
std::size_t print_val_hexbuf(std::size_t pos, BufferedOStream& out, const ValuePrinter& value);

inline ValuePrinter MakeValuePrinter(const bool& x) {
    ValuePrinter res;
    res.n = x;
    res.print = print_val_u;
    return res;
}
inline ValuePrinter MakeValuePrinter(const char& x) {
    ValuePrinter res;
    res.n = x;
    res.print = print_char;
    return res;
}

inline ValuePrinter MakeValuePrinter(const std::integral auto x) {
    ValuePrinter res;
    res.n = x;
    res.print = std::is_signed<decltype(x)>::value ? print_val_s : print_val_u;
    return res;
}

template<typename T>
struct Hex {
    constexpr Hex(T x_) : x(x_) {}
    T x;
};

template <typename T>
ValuePrinter MakeValuePrinter(const Hex<T>& x) {
    ValuePrinter res;
    if (sizeof(T) > sizeof(uintptr_t)) {
        res.n = x.x;
        res.print = print_val_hex64;
    } else {
        res.hex_num.x = x.x;
        res.hex_num.size = 2 * sizeof(T);
        res.print = print_val_hex;
    }
    return res;
}

template <>
inline ValuePrinter MakeValuePrinter<std::string_view>(const Hex<std::string_view>& x) {
    ValuePrinter res;
    res.s = x.x;
    res.print = print_val_hexbuf;
    return res;
}

inline ValuePrinter MakeValuePrinter(void const* const& x) {
    auto tmp = Hex(reinterpret_cast<uintptr_t>(x));
    return MakeValuePrinter(tmp);
}

inline ValuePrinter MakeValuePrinter(const std::string_view& x) {
    ValuePrinter res;
    res.s = x;
    res.print = print_val_str;
    return res;
}
inline ValuePrinter MakeValuePrinter(char const* const& x) {
    auto tmp = std::string_view(x);
    return MakeValuePrinter(tmp);
}

std::size_t print_buf(std::size_t pos, BufferedOStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n);

void PrintImpl(OutputStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n);

template<int N>
class BufferedOStreamN : public BufferedOStream {
public:
    constexpr BufferedOStreamN(OutputStream* stream_) : BufferedOStream(stream_, N) {}
private:
    char buffer[N];
};

template <typename... Args>
void print(OutputStream& out, std::string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    PrintImpl(out, format, printers, n);
}

template <typename... Args>
std::size_t print(std::size_t pos, BufferedOStream& out, std::string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    return print_buf(pos, out, format, printers, n);
}

class InputStream {
public:
    virtual std::size_t Pull(char* buf, std::size_t max_len) = 0;
};

class BufferedIStream {
public:
    BufferedIStream(InputStream* stream_, std::size_t buffer_size_) : stream(stream_), buffer_size(buffer_size_) {}

    bool get(char& c) {
        char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedIStream);
        if (pos == size) {
            pos = 0;
            size = stream->Pull(buffer, buffer_size);
            if (size == 0) return false;
        }
        c = buffer[pos++];
        return true;
    }

private:
    InputStream* stream;
    std::size_t pos = 0;
    std::size_t size = 0;
    std::size_t buffer_size;
};

template<int N>
class BufferedIStreamN : public BufferedIStream {
public:
    constexpr BufferedIStreamN(InputStream* stream_) : BufferedIStream(stream_, N) {}
private:
    char buffer[N];
};

[[noreturn]] void terminate(int exit_code) __attribute__((weak));

[[noreturn]] void panic_assert(OutputStream& out, std::string_view str, std::string_view file, int line);

inline void AssertImpl(bool cond, OutputStream& out, std::string_view cond_str, std::string_view file, int line) {
    if (kDebug && !cond) panic_assert(out, cond_str, file, line);
}

class USTARReader {
public:
    USTARReader() = default;

    std::size_t FindFile(std::string_view filename);
    std::size_t ReadHeader(void* buf);
    bool ReadFile(void* buf, std::size_t size);

private:
    std::size_t block_ = 0;

    virtual bool ReadBlocks(std::size_t block, int n, void *buf) = 0;
    bool ReadBlocks(int n, void* buf) {
        if (!ReadBlocks(block_, n, buf)) return false;
        block_ += n;
        return true;
    }

    void SkipBlocks(int n) {
        block_ += n;
    }
};

void md5(std::string_view buf, char out[16]);

template <typename T>
void swap(T& a, T& b) {
    T tmp = a;
    a = b;
    b = tmp;
}

template <typename T, typename IsLess>
void sort(T* begin, T* end, IsLess is_less) {
    for (auto i = begin; i != end; ++i) {
        for (auto j = i + 1; j != end; ++j) {
            if (is_less(*j, *i)) {
                swap(*i, *j);
            }
        }
    }
}

template <typename T>
T min(const T& a, const T& b) {
    return a < b ? a : b;
}

#endif //OS_UTILS_H
