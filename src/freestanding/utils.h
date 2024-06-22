//
// Created by gerben stavenga on 6/10/23.
//

#ifndef OS_UTILS_H
#define OS_UTILS_H

#include <stdint.h>
#include <stddef.h>

#define NOINLINE __attribute__((noinline))
#define ALWAYS_INLINE __attribute__((always_inline))
#define PREDICT_TRUE(x) __builtin_expect((x), 1)
#define PREDICT_FALSE(x) __builtin_expect((x), 0)

#ifdef NDEBUG
constexpr bool kDebug = false;
#else
constexpr bool kDebug = true;
#endif

template <typename T, size_t N>
constexpr size_t array_size(const T (&)[N]) {
    return N;
}

template<class T, T v>
struct integral_constant
{
    static constexpr T value = v;
    using value_type = T;
    using type = integral_constant; // using injected-class-name
    constexpr operator value_type() const noexcept { return value; }
    constexpr value_type operator()() const noexcept { return value; } // since c++14
};

template< bool B >
using bool_constant = integral_constant<bool, B>;

using true_type = bool_constant<true>;
using false_type = bool_constant<false>;

template<class T>
struct is_integral : bool_constant<
        requires (T t, T* p, void (*f)(T)) // T* parameter excludes reference types
        {
                reinterpret_cast<T>(t); // Exclude class types
        f(0); // Exclude enumeration types
        p + t; // Exclude everything not yet excluded but integral types
        }> {};

template <class T>
inline constexpr bool is_integral_v = is_integral<T>::value;

template <class T>
concept integral = is_integral_v<T>;

template <class T, class U>
struct is_same : false_type {};

template <class T>
struct is_same<T, T> : true_type {};


template <class T> struct remove_cv { typedef T type; };
template <class T> struct remove_cv<const T> { typedef T type; };
template <class T> struct remove_cv<volatile T> { typedef T type; };
template <class T> struct remove_cv<const volatile T> { typedef T type; };

template <class T> struct remove_const { typedef T type; };
template <class T> struct remove_const<const T> { typedef T type; };

template <class T> struct remove_volatile { typedef T type; };
template <class T> struct remove_volatile<volatile T> { typedef T type; };

template <class T >
using remove_cv_t = typename remove_cv<T>::type;
template <class T >
using remove_const_t = typename remove_const<T>::type;
template <class T >
using remove_volatile_t = typename remove_volatile<T>::type;

template <class T>
struct is_floating_point
        : integral_constant<
                bool,
                // Note: standard floating-point types
                is_same<float, typename remove_cv<T>::type>::value
                || is_same<double, typename remove_cv<T>::type>::value
                || is_same<long double, typename remove_cv<T>::type>::value
                // Note: extended floating-point types (C++23, if supported)
/*                || is_same<float16_t, typename remove_cv<T>::type>::value
                || is_same<float32_t, typename remove_cv<T>::type>::value
                || is_same<float64_t, typename remove_cv<T>::type>::value
                || is_same<float128_t, typename remove_cv<T>::type>::value
                || is_same<bfloat16_t, typename remove_cv<T>::type>::value
*/
        > {};

template <class T>
struct is_arithmetic : integral_constant<bool,
        is_integral<T>::value ||
        is_floating_point<T>::value> {};

namespace detail
{
    template <typename T,bool = is_arithmetic<T>::value>
    struct is_signed : integral_constant<bool, T(-1) < T(0)> {};

    template <typename T>
    struct is_signed<T,false> : false_type {};
} // namespace detail

template <typename T>
struct is_signed : detail::is_signed<T>::type {};

extern "C" {

void *memmove(void *dst, const void *src, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
char *strncpy(char *dst, const char *src, size_t n);
size_t strlen(const char *p);
size_t strnlen(const char *p, size_t max);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char* strchr(const char *s, int c);
char* strrchr(const char *s, int c);
char* strstr(const char* haystack, const char* needle);

}

struct string_view {
    constexpr string_view() = default;
    constexpr string_view(const char* s) : string_view(s, strlen(s)) {}
    template<int N> constexpr string_view(const char (&s)[N]) : string_view(s, N) {}
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
    void Finalize(size_t pos) {
        if (pos != 0) {
            char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedOStream);
            stream->Push({buffer, pos});
        }
    }

    size_t put(size_t pos, char c) {
        char* buffer = reinterpret_cast<char*>(this) + sizeof(BufferedOStream);
        buffer[pos++] = c;
        if (PREDICT_FALSE(c == '\n' || pos == buffer_size)) {
            stream->Push({buffer, pos});
            pos = 0;
        }
        return pos;
    }

protected:
    constexpr BufferedOStream(OutputStream* stream_, size_t buffer_size_) : stream(stream_), buffer_size(buffer_size_) {}

private:
    OutputStream* stream;
    size_t buffer_size;
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
        string_view s;
    };
    size_t (*print)(size_t pos, BufferedOStream& out, const ValuePrinter& value);
};

size_t print_char(size_t pos, BufferedOStream& out, const ValuePrinter& value);
size_t print_val_u(size_t pos, BufferedOStream& out, const ValuePrinter& value);
size_t print_val_s(size_t pos, BufferedOStream& out, const ValuePrinter& value);
size_t print_val_hex(size_t pos, BufferedOStream& out, const ValuePrinter& value);
size_t print_val_hex64(size_t pos, BufferedOStream& out, const ValuePrinter& value);
size_t print_val_str(size_t pos, BufferedOStream& out, const ValuePrinter& value);
size_t print_val_hexbuf(size_t pos, BufferedOStream& out, const ValuePrinter& value);

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

inline ValuePrinter MakeValuePrinter(const integral auto x) {
    ValuePrinter res;
    res.n = x;
    res.print = is_signed<decltype(x)>::value ? print_val_s : print_val_u;
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
inline ValuePrinter MakeValuePrinter<string_view>(const Hex<string_view>& x) {
    ValuePrinter res;
    res.s = x.x;
    res.print = print_val_hexbuf;
    return res;
}

inline ValuePrinter MakeValuePrinter(void const* const& x) {
    auto tmp = Hex(reinterpret_cast<uintptr_t>(x));
    return MakeValuePrinter(tmp);
}

inline ValuePrinter MakeValuePrinter(const string_view& x) {
    ValuePrinter res;
    res.s = x;
    res.print = print_val_str;
    return res;
}
inline ValuePrinter MakeValuePrinter(char const* const& x) {
    auto tmp = string_view(x);
    return MakeValuePrinter(tmp);
}

size_t print_buf(size_t pos, BufferedOStream& out, string_view format, const ValuePrinter* printers, size_t n);

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
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    PrintImpl(out, format, printers, n);
}

template <typename... Args>
size_t print(size_t pos, BufferedOStream& out, string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    return print_buf(pos, out, format, printers, n);
}

class InputStream {
public:
    virtual size_t Pull(char* buf, size_t max_len) = 0;
};

class BufferedIStream {
public:
    BufferedIStream(InputStream* stream_, size_t buffer_size_) : stream(stream_), buffer_size(buffer_size_) {}

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
    size_t pos = 0;
    size_t size = 0;
    size_t buffer_size;
};

template<int N>
class BufferedIStreamN : public BufferedIStream {
public:
    constexpr BufferedIStreamN(InputStream* stream_) : BufferedIStream(stream_, N) {}
private:
    char buffer[N];
};

[[noreturn]] void terminate(int exit_code) __attribute__((weak));

[[noreturn]] void panic_assert(OutputStream& out, string_view str, string_view file, int line);

inline void AssertImpl(bool cond, OutputStream& out, string_view cond_str, string_view file, int line) {
    if (kDebug && !cond) panic_assert(out, cond_str, file, line);
}

class USTARReader {
public:
    USTARReader() = default;

    size_t FindFile(string_view filename);
    size_t ReadHeader(void* buf);
    bool ReadFile(void* buf, size_t size);

private:
    size_t block_ = 0;

    virtual bool ReadBlocks(size_t block, int n, void *buf) = 0;
    bool ReadBlocks(int n, void* buf) {
        if (!ReadBlocks(block_, n, buf)) return false;
        block_ += n;
        return true;
    }

    void SkipBlocks(int n) {
        block_ += n;
    }
};

void md5(string_view buf, char out[16]);

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
