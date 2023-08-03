//
// Created by gerben stavenga on 7/16/23.
//

#ifndef OS_PIPE_H
#define OS_PIPE_H

class Pipe {
public:
    Pipe(size_t size) : size(size) {}

    int Write(string_view s) volatile {
        int i = 0;
        while (i < s.size() && write_pos < read_pos + size) {
            Buffer()[write_pos++ & (size - 1)] = s[i++];
        }
        return i;
    }

    void Push(char c) volatile {
        if (write_pos == read_pos + size) {
            read_pos++;
        }
        Buffer()[write_pos++ & (size - 1)] = c;
    }

    char Pop() volatile {
        return Buffer()[read_pos++ & (size - 1)];
    }

    bool Empty() volatile {
        return read_pos == write_pos;
    }

    int Read(char* buf, int len) volatile {
        int i = 0;
        while (i < len && read_pos < write_pos) {
            buf[i++] = Buffer()[read_pos++ & (size - 1)];
        }
        return i;
    }

private:
    volatile char* Buffer() volatile {
        return reinterpret_cast<volatile char*>(this + 1);
    }

    uint64_t read_pos = 0;
    uint64_t write_pos = 0;
    size_t size;
};

template <int N>
class PipeN : public Pipe {
public:
    PipeN() : Pipe(N) {
        static_assert((N & (N - 1)) == 0, "N must be a power of 2");
    }

private:
    char buffer[N];
};


#endif //OS_PIPE_H
