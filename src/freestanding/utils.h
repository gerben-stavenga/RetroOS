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

template< class T >
inline constexpr bool is_integral_v = is_integral<T>::value;

template < class T >
concept integral = is_integral_v<T>;

template<class T, class U>
struct is_same : false_type {};

template<class T>
struct is_same<T, T> : true_type {};


template<class T> struct remove_cv { typedef T type; };
template<class T> struct remove_cv<const T> { typedef T type; };
template<class T> struct remove_cv<volatile T> { typedef T type; };
template<class T> struct remove_cv<const volatile T> { typedef T type; };

template<class T> struct remove_const { typedef T type; };
template<class T> struct remove_const<const T> { typedef T type; };

template<class T> struct remove_volatile { typedef T type; };
template<class T> struct remove_volatile<volatile T> { typedef T type; };

template< class T >
using remove_cv_t = typename remove_cv<T>::type;
template< class T >
using remove_const_t = typename remove_const<T>::type;
template< class T >
using remove_volatile_t = typename remove_volatile<T>::type;

template<class T>
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

template<class T>
struct is_arithmetic : integral_constant<bool,
        is_integral<T>::value ||
        is_floating_point<T>::value> {};

namespace detail
{
    template<typename T,bool = is_arithmetic<T>::value>
    struct is_signed : integral_constant<bool, T(-1) < T(0)> {};

    template<typename T>
    struct is_signed<T,false> : false_type {};
} // namespace detail

template<typename T>
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
const char* strchr(const char *s, int c);
const char* strrchr(const char *s, int c);
const char* strstr(const char* haystack, const char* needle);

}

struct string_view {
    constexpr string_view() = default;
    constexpr string_view(const char* s) : string_view(s, __builtin_strlen(s)) {}
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

void print_char(BufferedOStream& out, uintptr_t x, uintptr_t);
void print_val_u(BufferedOStream& out, uintptr_t x, uintptr_t);
void print_val_s(BufferedOStream& out, uintptr_t x, uintptr_t);
void print_val_hex(BufferedOStream& out, uintptr_t x, uintptr_t ndigits);
void print_val_hex64(BufferedOStream& out, uintptr_t x, uintptr_t ndigits);
void print_val_str(BufferedOStream& out, uintptr_t data, uintptr_t size);
void print_val_hexbuf(BufferedOStream& out, uintptr_t data, uintptr_t size);

struct ValuePrinter {
    uintptr_t value;
    uintptr_t extra;
    void (*print)(BufferedOStream& out, uintptr_t value, uintptr_t extra);
};

inline ValuePrinter MakeValuePrinter(const bool& x) {
    return {static_cast<uintptr_t>(x), 0, print_val_u };
}
inline ValuePrinter MakeValuePrinter(const char& x) {
    return {static_cast<uintptr_t>(x), 0, print_char };
}

inline ValuePrinter MakeValuePrinter(const integral auto& x) {
    auto value = static_cast<uint64_t>(x);
    return {static_cast<uintptr_t>(value), static_cast<uintptr_t>(value >> 32), print_val_u };
}

template<typename T>
struct Hex {
    constexpr Hex(T x_) : x(x_) {}
    T x;
};

template <typename T>
ValuePrinter MakeValuePrinter(const Hex<T>& x) {
    if (sizeof(T) > sizeof(uintptr_t)) {
        return {static_cast<uintptr_t>(x.x), static_cast<uintptr_t>(x.x >> 32), print_val_hex64};
    } else {
        return {static_cast<uintptr_t>(x.x), sizeof(T) * 2, print_val_hex};
    }
}

template <>
inline ValuePrinter MakeValuePrinter<string_view>(const Hex<string_view>& x) {
    return {reinterpret_cast<uintptr_t>(x.x.data()), x.x.size(), print_val_hexbuf };
}

inline ValuePrinter MakeValuePrinter(void const* const& x) {
    auto tmp = Hex(reinterpret_cast<uintptr_t>(x));
    return MakeValuePrinter(tmp);
}

inline ValuePrinter MakeValuePrinter(const string_view& x) {
    return {reinterpret_cast<uintptr_t>(x.data()), x.size(), print_val_str };
}
inline ValuePrinter MakeValuePrinter(char const* const& x) {
    auto tmp = string_view(x);
    return MakeValuePrinter(tmp);
}

void print_buf(BufferedOStream& out, string_view format, const ValuePrinter* printers, size_t n);

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
void print(BufferedOStream& out, string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    print_buf(out, format, printers, n);
}

[[noreturn]] void terminate(int exit_code) __attribute__((weak));

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
