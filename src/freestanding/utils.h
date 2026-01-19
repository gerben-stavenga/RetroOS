//
// Created by gerben stavenga on 6/10/23.
//
#ifndef OS_UTILS_H
#define OS_UTILS_H

#include "stdlib.h"

#define NOINLINE __attribute__((noinline))
#define ALWAYS_INLINE __attribute__((always_inline))
#define PREDICT_TRUE(x) __builtin_expect((x), 1)
#define PREDICT_FALSE(x) __builtin_expect((x), 0)

#ifdef NDEBUG
constexpr bool kDebug = false;
#else
constexpr bool kDebug = true;
#endif

template <typename T>
inline constexpr bool is_known_relocatable_v = false;

template <>
inline constexpr bool is_known_relocatable_v<std::string> = true;

template <typename T>
inline constexpr bool is_relocatable_v = std::is_trivial_v<T> || is_known_relocatable_v<T>;

[[noreturn]] void ThrowOutOfRange();

class MemResource {
public:
    void* allocate(size_t bytes, size_t alignment) {
        return do_allocate(bytes, alignment);
    }
    void deallocate(void* ptr, size_t bytes, size_t alignment) {
        return do_deallocate(ptr, bytes, alignment);
    }

private:
    virtual void* do_allocate(size_t bytes, size_t alignment) = 0;
    virtual void do_deallocate(void* ptr, size_t bytes, size_t alignment) = 0;
    virtual bool do_is_equal(MemResource const& other) const noexcept = 0;
};

class DefaultAlloc : public MemResource {
    void* do_allocate(size_t bytes, size_t) override {
        return std::malloc(bytes);
    }
    void do_deallocate(void* p, size_t, size_t) override {
        std::free(p);
    }
    bool do_is_equal(MemResource const& other) const noexcept override {
        return this == &other;
    }
};

extern DefaultAlloc def_alloc;

class VecBase {
public:
    constexpr uint32_t size() const noexcept { return size_; }
    constexpr bool empty() const noexcept { return size() == 0; }
    constexpr uint32_t capacity() const noexcept { return cap_; }

protected:
    constexpr VecBase() noexcept = default;
    constexpr VecBase(MemResource* mr) noexcept : base_or_mr_(mr) {};
    VecBase(VecBase&& other) noexcept : VecBase() {
        Swap(other);
    }
    VecBase& operator=(VecBase&& other) noexcept {
        Swap(other);
        return *this;       
    }

    template <typename T>
    void Free() {
        if (cap_ != 0) FreeOutline(base_or_mr_, cap_ * sizeof(T));
    }

    template<typename T>
    T* Base() const { return static_cast<T*>(base_or_mr_); }

    using Relocator = void (*)(void* dst, void *src, uint32_t size) noexcept;

    template <typename T>
    static void Relocate(void* dst, void* src, uint32_t size) noexcept {
        auto d = static_cast<T*>(dst);
        auto s = static_cast<T*>(src);
        for (uint32_t i = 0; i < size; i++) {
            T tmp = std::move(s[i]);
            s[i].~T();
            new (d + i) T(std::move(tmp));
        }
    }

    void Swap(VecBase& other) noexcept {
        std::swap(base_or_mr_, other.base_or_mr_);
        std::swap(size_, other.size_);
        std::swap(cap_, other.cap_);
    }

    template <typename T>
    void AddAlreadyReserved(T x) noexcept {
        auto s = size_;
        new (Base<T>() + s) T(std::move(x));
        size_ = s + 1;
    }

    template <typename T>
    void Add(T x) noexcept {
        auto s = size_;
        auto c = cap_;
        if (s >= c) {
            Grow<T>();
        }
        new (Base<T>() + s) T(std::move(x));
        size_ = s + 1;
    }
    template <typename T>
    T Remove() noexcept {
        auto p = Base<T>();
        auto s = size_ - 1;
        T res = std::move(p[s]);
        p[s].~T();
        size_ = s;
        return res;
    }
    template <typename T>
    void Reserve(uint32_t newcap) noexcept {
        if (newcap > cap_) {
            Grow<T>(newcap);
        }
    }
    constexpr void SetSize(uint32_t s) noexcept { size_ = s; }

    template <typename T>
    void Grow(uint32_t newcap = 0) noexcept {
        Relocator mover = nullptr;
        if constexpr (!is_relocatable_v<T>) {
            mover = &Relocate<T>;
        }
        std::tie(base_or_mr_, cap_) = GrowOutline(base_or_mr_, size_, cap_, sizeof(T), mover, newcap);
    }

private:
    static std::pair<void*, uint32_t> GrowOutline(void* base, uint32_t size, uint32_t cap, uint32_t elem_size, Relocator relocate, uint32_t newcap) noexcept;
    static void FreeOutline(void* base, size_t bytes) noexcept;

    // If cap_ is 0 it's a memory resource otherwise it's pointing to base of buffer
    void* base_or_mr_ = nullptr;
    uint32_t size_ = 0;
    uint32_t cap_ = 0;
};

template <typename T>
concept IsVecCompatible = std::is_nothrow_move_constructible_v<T> && is_relocatable_v<T>;

template <IsVecCompatible T>
struct Vec : public VecBase {
    constexpr Vec() noexcept = default;
    constexpr Vec(MemResource* mr) noexcept : VecBase(mr) {}
    ~Vec() noexcept {
        clear();
        Free<T>();
    }

    constexpr Vec(Vec&&) noexcept = default;
    constexpr Vec& operator=(Vec&& other) noexcept = default;

    template <typename U>
    Vec(const std::initializer_list<U>& list) {
        reserve(list.size());
        for (auto& x : list) AddAlreadyReserved<T>(x);
    }

    template <typename U>
    Vec(uint32_t n, U x) { 
        reserve(n);
        for (uint32_t i = 0; i < n; i++) AddAlreadyReserved<T>(x);
    }

    constexpr T* data() noexcept { return Base<T>(); }
    constexpr T const* data() const noexcept  { return Base<T>(); }

    constexpr T* begin() noexcept  { return data(); }
    constexpr T const* begin() const noexcept  { return data(); }
    constexpr T* end() noexcept { return data() + size(); }
    constexpr T const* end() const noexcept  { return data() + size(); }

    constexpr auto cbegin() const noexcept  { return begin(); }
    constexpr auto cend() noexcept  { return end(); }

    constexpr auto rbegin() noexcept  { return std::reverse_iterator(end()); }
    constexpr auto rbegin() const noexcept  { return std::reverse_iterator(end()); }
    constexpr auto rend() noexcept  { return std::reverse_iterator(begin()); }
    constexpr auto rend() const noexcept  { return std::reverse_iterator(begin()); }
    constexpr auto crbegin() const noexcept  { return rbegin(); }
    constexpr auto crend() const noexcept  { return rend; }


    void reserve(uint32_t newcap) noexcept { return Reserve<T>(newcap); }

    void push_back(const T& x) noexcept { Add<T>(x); }
    void push_back(T&& x) noexcept { Add<T>(std::move(x)); }

    T pop_back() noexcept { return Remove<T>(); }

    void clear() noexcept { for (auto& x : *this) x.~T(); SetSize(0); }
    void swap(Vec& other) noexcept { Swap(other); }
    void resize(uint32_t s) noexcept {
        if (s <= size()) {
            for (auto& x : Postfix(s)) x.~T();            
        } else {
            reserve(s);
            auto p = data();
            for (uint32_t i = size(); i < s; i++) new (p + i) T();
        }
        SetSize(s);
    }
    void resize(uint32_t s, const T& value) {
        if (s <= size()) {
            for (auto& x : Postfix(s)) x.~T();            
        } else {
            reserve(s);
            auto p = data();
            for (uint32_t i = size(); i < s; i++) {
                new (p + i) T(value);
            }
        }
        SetSize(s);
    }

    template <typename It>
    void assign(It first, It last) noexcept {
        uint32_t idx = 0;
        for (auto &x : *this) {
            if (first == last) {
                resize(idx);
                return;
            }
            x = *first;
            ++first; ++idx;
        }
        for (; first != last; ++first) push_back(*first);
    }
    // At is specified to throw
    auto at(uint32_t idx) { if (idx >= size()) ThrowOutOfRange(); return Get(idx); }
    auto at(uint32_t idx) const { if (idx >= size()) ThrowOutOfRange(); return Get(idx); }

    T& operator[](uint32_t idx) noexcept { return data()[idx]; }
    T const& operator[](uint32_t idx) const noexcept { return data()[idx]; }

    auto front() noexcept { return Get(0); }
    auto front() const noexcept { return Get(0); }
    auto back() noexcept { return Get(size() - 1); }
    auto back() const noexcept { return Get(size() - 1); }

    void shrink_to_fit(uint32_t) noexcept {}

    T* erase(T* first) noexcept {
        return erase(first, first + 1);
    }

    T* erase(T* first, T* last) noexcept {
        auto d = last - first;
        auto ret = first;
        if (d == 0) return first;
        auto e = end();
        while (last != e) {
            *first = std::move(*last);
            ++first; ++last;
        }
        while (first != e) {
            first->~T();
            ++first;
        }
        SetSize(size() - d);
        return ret;
    }
    void insert(T* position, T res) noexcept {
        auto i = position - data();
        auto s = size();
        push_back(std::move(res));
        std::rotate(data() + i, data() + s, data() + size());
    }
    void insert(T* position, uint32_t n, const T& res) noexcept {
        auto i = position - data();
        auto s = size();
        reserve(n + s);
        while (n--) AddAlreadyReserved<T>(res);
        std::rotate(data() + i, data() + s, data() + size());
    }
    template <class InputIterator>
    void insert(T* position, InputIterator first, InputIterator last) noexcept {
        auto s = size();
        auto i = position - data();
        while (first != last) { push_back(*first); ++first; }
        std::rotate(data() + i, data() + s, data() + size());
    }
    template <typename... Args>
    void emplace(T* position, Args&&... args) noexcept {
        insert(position, T(std::forward<Args>(args)...));
    }
    template <typename... Args>
    void emplace_back(Args&&... args) noexcept {
        push_back(T(std::forward<Args>(args)...));
    }

    T& Get(uint32_t idx) noexcept { return data()[idx]; }
    T const& Get(uint32_t idx) const noexcept { return data()[idx]; }

    std::span<T> Prefix(uint32_t idx) { return {data(), idx}; }
    std::span<T const> Prefix(uint32_t idx) const { return {data(), idx}; }
    std::span<T> Postfix(uint32_t idx) { return {data() + idx, size() - idx}; }
    std::span<T const> Postfix(uint32_t idx) const { return {data() + idx, size() - idx}; }
};

template <typename T>
inline constexpr bool is_known_relocatable_v<Vec<T>> = true;

template <typename T>
class LocalCapture : public T {
    T* global_;
public:
    __attribute__((always_inline))
    LocalCapture(T* global) noexcept : T(std::move(*global)), global_(global) {
        global->~T();
    }
    __attribute__((always_inline))
    ~LocalCapture() noexcept {
        new (global_) T(std::move(*static_cast<T*>(this)));
    }
};

class InputStream {
public:
    const char* Next() {
        auto [pos, size] = NextBuffer();
        end_ = pos + size;
        return pos;
    }

    const char* end() const { return end_; }

    void Flush(const char* pos) {
        if (pos) FlushBuffer(end_ - pos);
        end_ = pos;
    }

private:
    const char* end_ = nullptr;

    virtual std::pair<const char*, std::size_t> NextBuffer() = 0;
    virtual void FlushBuffer(std::size_t backup_count) = 0;
};

class OutputStream {
public:
    char* Next() {
        auto [pos, size] = NextBuffer();
        end_ = pos + size;
        return pos;
    }

    const char* end() const { return end_; }

    void Flush(const char* pos) {
        if (pos) FlushBuffer(end_ - pos);
        end_ = pos;
    }

private:
    const char* end_;

    virtual std::pair<char*, std::size_t> NextBuffer() = 0;
    virtual void FlushBuffer(std::size_t backup_count) = 0;
};

struct ArrayInputStream : public InputStream {
public:
    ArrayInputStream(std::string_view str) : str_(str) {}

    std::pair<const char*, std::size_t> NextBuffer() override {
        auto p = str_.data();
        auto n = str_.size();
        if (n == 0) {
            str_ = {nullptr, 0};
        } else {
            str_ = {str_.end(), 0};
        }
        return {p, n};
    }

    void FlushBuffer(std::size_t backup_count) override {
        str_ = {end() - backup_count, backup_count};
    }
private:
    std::string_view str_;
};

struct ArrayOutStream : public OutputStream {
public:
    ArrayOutStream(char* buf, std::size_t size) : buf_(buf), size_(size) {}

    std::pair<char*, std::size_t> NextBuffer() override {
        auto p = buf_;
        auto n = size_;
        if (n == 0) {
            buf_ = nullptr;
        } else {
            buf_ = p + n;
            size_ = 0;
        }
        return {p, n};
    }

    void FlushBuffer(std::size_t backup_count) override {
        buf_ -= backup_count;
        size_ += backup_count;
    }

    std::size_t size() const { return size_; }
    
private:
    char* buf_;
    std::size_t size_;
};

struct VecOutStream : public OutputStream {
public:
    VecOutStream(Vec<char>& vec) : vec_(vec) {}

    std::pair<char*, std::size_t> NextBuffer() override {
        auto old_size = vec_.size();
        auto new_size = std::max(old_size + 256, old_size * 2);
        vec_.resize(new_size);
        return {vec_.data() + old_size, new_size - old_size};
    }

    void FlushBuffer(std::size_t backup_count) override {
        vec_.resize(vec_.size() - backup_count);
    }

private:
    Vec<char>& vec_;
};


class Reader {
public:
    constexpr Reader(InputStream* stream) : stream_(stream) {
        pos_ = stream->Next();
    }
    constexpr Reader(Reader&& other) noexcept : stream_(other.stream_), pos_(other.pos_) {
        other.stream_ = nullptr;
        other.pos_ = nullptr;
    }
    ~Reader() {
        if (stream_) stream_->Flush(pos_);
    }

    const char* IntoPos() && {
        auto pos = pos_;
        stream_ = nullptr;
        pos_ = nullptr;
        return pos;
    }

    template <typename Func>
    bool Call(Func func) {
        pos_ = func(Reader(stream_, pos_));
        return pos_ != nullptr;
    }

    bool Read(void* buf, std::size_t n) {
        auto p = static_cast<char*>(buf);
        if (n > stream_->end() - pos_) {
            pos_ = ReadSlow(p, n, stream_, pos_);
            return pos_ != nullptr;
        }
        std::memcpy(p, pos_, n);
        pos_ += n;
        return true;
    }

private:
    InputStream* stream_;
    const char* pos_;

    constexpr Reader(InputStream* stream, const char* pos) : stream_(stream), pos_(pos) { };

    static const char* ReadSlow(char* p, std::size_t n, InputStream* stream, const char* pos);
};

class Writer {
public:
    constexpr Writer(OutputStream* stream) : stream_(stream) {
        pos_ = stream->Next();
    }
    constexpr Writer(Writer&& other) noexcept : stream_(other.stream_), pos_(other.pos_) {
        other.stream_ = nullptr;
        other.pos_ = nullptr;
    }
    ~Writer() {
        if (stream_) stream_->Flush(pos_);
    }

    char* IntoPos() && {
        auto pos = pos_;
        stream_ = nullptr;
        pos_ = nullptr;
        return pos;
    }

    template <typename Func>
    bool Call(Func func) {
        pos_ = func(Writer(stream_, pos_));
        return pos_ != nullptr;
    }

    bool Write(std::string_view str) {
        if (str.size() > stream_->end() - pos_) {
            pos_ = WriteSlow(str, stream_, pos_);
            return pos_ != nullptr;
        }
        std::memcpy(pos_, str.data(), str.size());
        pos_ += str.size();
        return true;
    }

    bool put(char c) {
        return Write(std::string_view(&c, 1));
    }

private:
    OutputStream* stream_;
    char* pos_;

    constexpr Writer(OutputStream* stream, char* pos) : stream_(stream), pos_(pos) { };

    static char* WriteSlow(std::string_view str, OutputStream* stream, char* pos);
};

template <int FD>
class StdOutStream : public OutputStream {
public:
    std::pair<char*, std::size_t> NextBuffer() override {
        if (pos_) StdFlush(FD, std::string_view(buffer_, sizeof(buffer_)));
        pos_ += sizeof(buffer_);
        return {buffer_, sizeof(buffer_)};
    }

    void FlushBuffer(std::size_t backup_count) override {
        auto len = sizeof(buffer_) - backup_count;
        if (len > 0) {
            StdFlush(FD, std::string_view(buffer_, len));
        }
        pos_ = 0;
    }

private:
    char buffer_[256] = {};
    std::size_t pos_ = 0;
};

extern StdOutStream<1> std_out;
extern StdOutStream<2> std_err;
    
class PanicStream {
public:
    ~PanicStream();

    template <typename T>
    PanicStream& operator<<(const T& x) {
        print(std_err, " {}", x);
        return *this;
    }
};

__attribute__((weak))
[[noreturn]] void Exit(int exit_code);
__attribute__((weak))
void StdFlush(int fd, std::string_view str);


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
    char* (*print)(Writer out, const ValuePrinter& value);
};

char* print_char(Writer out, const ValuePrinter& value);
char* print_val_u(Writer out, const ValuePrinter& value);
char* print_val_s(Writer out, const ValuePrinter& value);
char* print_val_hex(Writer out, const ValuePrinter& value);
char* print_val_hex64(Writer out, const ValuePrinter& value);
char* print_val_str(Writer out, const ValuePrinter& value);
char* print_val_hexbuf(Writer out, const ValuePrinter& value);

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

char* print_buf(Writer out, std::string_view format, const ValuePrinter* printers, std::size_t n);

void PrintImpl(OutputStream& out, std::string_view format, const ValuePrinter* printers, std::size_t n);

template <typename... Args>
void print(OutputStream& out, std::string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    PrintImpl(out, format, printers, n);
}

template <typename... Args>
char* print(Writer out, std::string_view format, const Args&... args) {
    constexpr auto n = sizeof...(Args);
    const ValuePrinter printers[n] = {MakeValuePrinter(args)...};
    return print_buf(pos, out, format, printers, n);
}


template <typename... Args>
void kprint(std::string_view fmt, Args... args) {
    print(std_out, fmt, args...);
}

template <typename... Args>
std::size_t sprint(char* buf, std::size_t n, std::string_view fmt, Args... args) {
    ArrayOutStream out(buf, n);
    print(Writer(&out), fmt, args...);
    return n - out.size();
}

template <const std::size_t N, typename... Args>
std::size_t sprint(char (&buf)[N], std::string_view fmt, Args... args) {
    return sprint(buf, N, fmt, args...);
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

#endif // OS_UTILS_H
