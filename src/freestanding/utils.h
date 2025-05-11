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

__attribute__((weak))
[[noreturn]] void Exit(int exit_code);
__attribute__((weak))
void StdOutPush(std::string_view str);
    

class OutputStream {
public:
    virtual std::pair<char*, std::size_t> Next() = 0;
    virtual void Flush(std::size_t backup_count) = 0;
};
    
class StdOutStream : public OutputStream {
public:
    std::pair<char*, std::size_t> Next() override {
        if (pos_) StdOutPush(std::string_view(buffer_, sizeof(buffer_)));
        pos_ += sizeof(buffer_);
        return {buffer_, sizeof(buffer_)};
    }

    void Flush(std::size_t backup_count) override {
        auto len = sizeof(buffer_) - backup_count;
        if (len > 0) {
            StdOutPush(std::string_view(buffer_, len));
        }
        pos_ = 0;
    }

private:
    char buffer_[256] = {};
    std::size_t pos_ = 0;
};

extern StdOutStream std_out;
    
class PanicStream {
public:
    ~PanicStream();

    template <typename T>
    PanicStream& operator<<(const T& x) {
        print(std_out, " {}", x);
        return *this;
    }
};

PanicStream GetPanicStream(const char* str, const char* file, int line);

#define assert(cond) if (!kDebug || (cond)) {} else GetPanicStream(#cond, __FILE__, __LINE__)


template <typename T, std::size_t N>
constexpr std::size_t array_size(const T (&)[N]) { return N; }

template <typename T>
struct Range {
    constexpr Range(T* p, std::size_t s) : begin_(p), end_(p + s) {}
    auto begin() { return begin_; }
    auto end() { return end_; }
    T* begin_;
    T* end_;
};

extern "C" {

void *memmove(void *dst, const void *src, std::size_t n);
void *memcpy(void *dst, const void *src, std::size_t n);
void *memset(void *dst, int value, std::size_t n);
char *strncpy(char *dst, const char *src, std::size_t n);
std::size_t strlen(const char *p);
std::size_t strnlen(const char *p, std::size_t max);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, std::size_t n);
char* strchr(const char *s, int c);
char* strrchr(const char *s, int c);
char* strstr(const char* haystack, const char* needle);
void *memchr(const void *ptr, int value, std::size_t n);
int memcmp(const void *lhs, const void *rhs, std::size_t n);


void* malloc(std::size_t size);
void* calloc(std::size_t size);
void* realloc(void* ptr, std::size_t size);
void free(void*);

}  // extern "C"

class BufferedOStream {
public:
    constexpr BufferedOStream(OutputStream* stream, char** pos) : stream_(stream) {
        if (stream == nullptr) {
            *pos = nullptr;
            buffer_end_ = nullptr;
            return;
        }
        auto [buffer, len] = stream->Next();
        if (buffer == nullptr) {
            *pos = nullptr;
            buffer_end_ = nullptr;
            return;
        }
        buffer_end_ = buffer + len;
        *pos = buffer;
    }

    constexpr BufferedOStream(char* buf, std::size_t size, char** pos) : buffer_end_(buf + size) {
        *pos = buf;
        size_ = size;
    }

    ~BufferedOStream() {
        assert(buffer_end_ == nullptr);
    }

    std::size_t Flush(char* pos) {
        auto buffer_end = buffer_end_;
        if (buffer_end == nullptr) return 0;
        buffer_end_ = nullptr;
        assert(pos != nullptr);
        auto backup_count = buffer_end - pos;
        if (stream_ != nullptr) {
            stream_->Flush(backup_count);
        }
        return size_ - backup_count;
    }

    char* put(char* pos, char c) {
        if (pos == nullptr)  return nullptr;
        while (pos >= buffer_end_) pos = Next();
        *pos++ = c;
        return pos;
    }

    char* Push(char* pos, std::string_view str) {
        for (auto c : str) {
            pos = put(pos, c);
            if (pos == nullptr) return nullptr;
        }
        return pos;
    }

private:
    OutputStream* stream_ = nullptr;
    char* buffer_end_ = nullptr;
    size_t size_ = 0;

    char* Next() {
        if (stream_ == nullptr) return Error();
        auto [buffer, len] = stream_->Next();
        if (buffer == nullptr) return Error();
        buffer_end_ = buffer + len;
        size_ += len;
        return buffer;
    }

    char* Error() {
        buffer_end_ = nullptr;
        return nullptr;
    }
};

struct ValuePrinter {
    ValuePrinter() {};
    union {
        uint64_t n;
        struct {
            uintptr_t x;
            uintptr_t size;
        } hex_num;
        const void* p;
        std::string_view s;
    };
    char* (*print)(char* pos, BufferedOStream& out, const ValuePrinter& value);
};

char* print_char(char* pos, BufferedOStream& out, const ValuePrinter& value);
char* print_val_u(char* pos, BufferedOStream& out, const ValuePrinter& value);
char* print_val_s(char* pos, BufferedOStream& out, const ValuePrinter& value);
char* print_val_hex(char* pos, BufferedOStream& out, const ValuePrinter& value);
char* print_val_hex64(char* pos, BufferedOStream& out, const ValuePrinter& value);
char* print_val_str(char* pos, BufferedOStream& out, const ValuePrinter& value);
char* print_val_hexbuf(char* pos, BufferedOStream& out, const ValuePrinter& value);

template <typename T>
concept Printable = requires(const T& v)
{
    {v.MakeValuePrinter()} -> std::same_as<ValuePrinter>;
};

template <Printable T>
ValuePrinter MakeValuePrinter(const T& x) {
    return x.MakeValuePrinter();
}

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

    ValuePrinter MakeValuePrinter() const {
        ValuePrinter res;
        if (sizeof(T) > sizeof(uintptr_t)) {
            res.n = x;
            res.print = print_val_hex64;
        } else {
            res.hex_num.x = x;
            res.hex_num.size = 2 * sizeof(T);
            res.print = print_val_hex;
        }
        return res;
    }
};

inline ValuePrinter MakeValuePrinter(const Hex<std::string_view>& x) {
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

char* print_buf(char* pos, BufferedOStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n);

void PrintImpl(OutputStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n);

template <typename... Args>
void print(OutputStream& out, std::string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    PrintImpl(out, format, printers, n);
}

template <typename... Args>
char* print(char* pos, BufferedOStream& out, std::string_view format, const Args&... args) {
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

template <typename... Args>
void kprint(std::string_view fmt, Args... args) {
    print(std_out, fmt, args...);
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

#if 0
template <typename T, std::size_t N>
class BTree {
    class Node {
        T array[N - 1];
        Node* children;
        int size = 0;
        bool is_leaf = true;

        int insert_in(T x) {
            assert(size < N - 1);
            size++;
            for (auto i = size; i != 0; i--) {
                if (array[i - 1] < x) {
                    if (array[i - 1] == x) {
                        array[i - 1] = std::move(x);
                        size--;
                    } else {
                        array[i] = std::move(x);
                    }
                    return i;
                }
                array[i] = std::move(array[i - 1]);
            }
            array[0] = std::move(x);
            return 0;
        }

        bool insert(T x) {
            if (is_leaf) {
                if (size < N - 1) {
                    insert_in(std::move(x));
                    return false;
                }
                
            } else {
                for (auto i = 0; i < N; i++) {
                    if (x < array[i]) return children[i]->insert(std::move(x));
                    if (x == array[i]) {
                        array[i] = std::move(x);
                        return false;
                    }
                }
                return children[N]->insert(std::move(x));
            }
        }
    }

    Node* root_ = nullptr;

public:
    void insert(T x) {
        if (root_ == nullptr) root_ = new Node;
        if (root->size < N - 1) {
            root_->size++;
            for (auto i = root_->size; i != 0; i--) {
                if (root_->array[i - 1] <= x) {
                    root_->array[i] = std::move(x);
                    return;
                }
                root_->array[i] = std::move(root_->array[i]); 
            }
            root_->array[0] = std::move(x);
            return;
        }
        root_->insert(std::move(x));
    }
};
#endif

const void* LoadElf(std::string_view elf, void* (*mmap)(uintptr_t, std::size_t, int));

inline std::uintptr_t GetAddress(const void* p) { return reinterpret_cast<std::uintptr_t>(p); }

void InitializeAllocator(void* ptr, std::size_t size);

void StackTrace(OutputStream& out, std::string_view symbol_map);

/* Callback typedef for allocation-less demangler interfaces. */
typedef void (*demangle_callbackref) (const char *, size_t, void *);

#endif //OS_UTILS_H
