//
// Created by gerben stavenga on 7/16/23.
//

#ifndef OS_PIPE_H
#define OS_PIPE_H

class Pipe {
public:
    Pipe(size_t size) : size(size) {}

    int Write(string_view s) {
        int i = 0;
        auto wp = write_pos;
        auto rp = read_pos;
        while (i < s.size() && wp < rp + size) {
            Buffer()[wp++ & (size - 1)] = s[i++];
        }
        write_pos = wp;
        return i;
    }

    void Push(char c) {
        if (write_pos == read_pos + size) {
            read_pos++;
        }
        Buffer()[write_pos++ & (size - 1)] = c;
    }

    char Pop() {
        if (Empty()) return 0;
        return Buffer()[read_pos++ & (size - 1)];
    }

    bool Empty() {
        return read_pos == write_pos;
    }

    int Read(char* buf, int len) {
        int i = 0;
        auto wp = write_pos;
        auto rp = read_pos;
        while (i < len && rp < wp) {
            buf[i++] = Buffer()[rp++ & (size - 1)];
        }
        read_pos = rp;
        return i;
    }

private:
    char* Buffer() {
        return reinterpret_cast<char*>(this + 1);
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
