//
// Created by gerben stavenga on 6/10/23.
//

#ifndef OS_UTILS_H
#define OS_UTILS_H

#include <stdint.h>
#include <stddef.h>

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

inline constexpr size_t strlen(const char* p) {
    size_t i = 0;
    for (; p[i] != 0; i++);
    return i;
}

struct string_view {
    constexpr string_view() = default;
    constexpr string_view(const char* s) : p(s), size(strlen(s)) {}
    template<int N> constexpr string_view(const char s[N]) : p(s), size(strlen(s)) {}
    constexpr string_view(const char* s, size_t n) : p(s), size(n) {}

    string_view consume(size_t i) { return string_view(p + i, size - i); }
    char operator[](size_t i) { return p[i]; }

    const char* p = nullptr;
    size_t size = 0;
};

template <typename CharOut>
void print_val_u(CharOut& out, uint64_t x) {
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

template <typename CharOut>
void print_val_s(CharOut& out, int64_t x) {
    if (x < 0) {
        out.put('-');
        x = (~x) + 1;
    }
    print_val_u(out, uint64_t (x));
}

template <typename CharOut>
void print_val(CharOut& out, const int& x) {
    print_val_s(out, x);
}

template <typename CharOut>
void print_val(CharOut& out, const char& c) {
    out.put(c);
}

template <typename CharOut>
void print_val(CharOut& out, const void* p) {
    out.put('0'); out.put('x');
    uintptr_t x = reinterpret_cast<uintptr_t>(p);
    int ndigits = sizeof(uintptr_t) * 2;
    for (int i = 0; i < ndigits; i++) {
        int d = (x >> (4 * (ndigits - 1 - i))) & 0xF;
        out.put(d < 10 ? '0' + d : 'A' + d - 10);
    }
}

template <typename CharOut>
void print_val(CharOut& out, string_view buf) {
    for (int i = 0; i < buf.size; i++) {
        out.put(buf[i]);
    }
}

template <typename CharOut>
string_view print(CharOut& out, string_view format) {
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

template <typename CharOut, typename Head, typename... Tail>
void print(CharOut& out, string_view format, const Head& head, const Tail &... tail) {
    if (format.size > 0) {
        format = print(out, format);
    }
    print_val(out, head);
    print(out, format, tail...);
}

#endif //OS_UTILS_H
