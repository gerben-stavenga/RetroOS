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
    constexpr string_view(const char* s) : p(s), size(strlen(s)) {}
    constexpr string_view(const char* s, size_t n) : p(s), size(n) {}

    string_view consume(size_t i) { return string_view(p + i, size - i); }
    char operator[](size_t i) { return p[i]; }

    const char* p;
    size_t size;
};

template <typename CharOut>
void print_val(CharOut out, uint64_t x) {
    char buf[20];
    int n = 0;
    while (x) {
        buf[n++] = x % 10;
        x /= 10;
    }
    for (int i = n - 1; i >= 0; i--) {
        out.put(buf[i]);
    }
}

template <typename CharOut>
void print_val(CharOut out, int64_t x) {
    if (x < 0) {
        out.put('-');
        x = (~x) + 1;
    }
    print_val(out, uint64_t (x));
}

template <typename CharOut>
void print_val(CharOut out, const void* p) {
    out.put('0'); out.put('x');
    uintptr_t x = reinterpret_cast<uintptr_t>(p);
    int ndigits = sizeof(uintptr_t) * 2;
    for (int i = 0; i < ndigits; i++) {
        int d = (x >> (4 * (ndigits - 1 - i))) & 0xF;
        out.put(d < 10 ? '0' + d : 'A' + d);
    }
}

template <typename CharOut>
void print_val(CharOut out, string_view buf) {
    for (int i = 0; i < buf.size; i++) {
        out.put(buf[i]);
    }
}

template <typename CharOut, typename Head, typename... Tail>
void print(CharOut out, string_view format, const Head& head, const Tail &... tail) {
    bool open_bracket = false;
    for (size_t i = 0; i < format.size; i++) {
        char c = format.p[i];
        if (open_bracket && c != '{') {
            if (c != '}') return;  // todo parse options
            print_val(out, head);
            print(out, format.consume(i + 1), tail...);
            return;
        } else if (c == '{') {
            open_bracket = true;
            continue;
        }
        out.put(c);
    }
}

#endif //OS_UTILS_H
