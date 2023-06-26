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
