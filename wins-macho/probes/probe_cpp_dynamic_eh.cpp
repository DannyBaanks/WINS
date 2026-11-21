/*
 * Dual-compiled Differential Probe #5 (Dynamic libc++abi / __gxx_personality_v0):
 * Uses zero libc++ headers so macOS builds can link with -nostdlib++ -Wl,-undefined,dynamic_lookup,
 * forcing EVERY exception symbol (___cxa_allocate_exception, ___cxa_throw, ___cxa_rethrow,
 * ___cxa_begin_catch, ___cxa_end_catch, ___gxx_personality_v0, __Unwind_Resume,
 * __ZTVN10__cxxabiv117__class_type_infoE, __ZTVN10__cxxabiv120__si_class_type_infoE,
 * __ZTVN10__cxxabiv121__vmi_class_type_infoE, __ZTIi, __ZTIPKc)
 * to resolve dynamically into WINS-MachO's Darwin libcxx.zig + unwind.zig runtime!
 */
#include <stdint.h>
#include <stdio.h>

struct BaseA {
    int a;
    explicit BaseA(int x) : a(x) {}
    virtual ~BaseA() {}
    virtual int tag() const { return a; }
};

struct BaseB {
    int b;
    explicit BaseB(int y) : b(y) {}
    virtual ~BaseB() {}
    virtual int tagB() const { return b * 3; }
};

struct DerivedSingle : public BaseA {
    int extra;
    DerivedSingle(int x, int e) : BaseA(x), extra(e) {}
    int tag() const override { return a * 100 + extra; }
};

struct DerivedMulti : public BaseA, public BaseB {
    int c;
    DerivedMulti(int x, int y, int z) : BaseA(x), BaseB(y), c(z) {}
    int tag() const override { return a + b + c; }
    int tagB() const override { return b * 10 + c; }
};

struct Guard {
    uint64_t* log;
    uint32_t id;
    Guard(uint64_t* l, uint32_t i) : log(l), id(i) {
        *log = (*log * 131ULL) ^ (id * 5ULL + 1ULL);
    }
    ~Guard() {
        *log = (*log * 131ULL) ^ (id * 29ULL + 3ULL);
    }
};

__attribute__((noinline)) static void inner_throw(uint8_t mode, int v, uint64_t* log) {
    Guard g3(log, 3);
    switch (mode % 6) {
        case 0:
            throw DerivedSingle(v, (v * 7) & 0x3f);
        case 1:
            throw DerivedMulti(v, v + 5, v + 9);
        case 2:
            throw static_cast<int>(v * 17 + 3);
        case 3:
            throw "const-char-exc";
        case 4:
            throw BaseA(v + 42);
        default:
            *log ^= static_cast<uint64_t>(v + 77);
            return;
    }
}

__attribute__((noinline)) static int mid_frame(uint8_t mode, int v, uint64_t* log) {
    Guard g2(log, 2);
    volatile int keep = v * 3 + 11;
    try {
        inner_throw(mode, v, log);
        return keep;
    } catch (const BaseB& mb) {
        // Tests VMI multiple-inheritance pointer adjustment (DerivedMulti -> BaseB at non-zero offset!)
        int bonus = 0;
        try {
            Guard gn(log, 8);
            if ((v & 1) != 0) throw int(mb.b + 2);
            bonus = 1;
        } catch (int x) {
            bonus = x;
        }
        if ((v & 2) != 0) throw; // rethrow DerivedMulti to outer
        return mb.tagB() + bonus + keep;
    } catch (const BaseA& ba) {
        if ((v & 2) != 0) throw; // rethrow to outer
        return ba.tag() + keep;
    }
}

__attribute__((noinline)) static int outer_frame(uint8_t mode, int v, uint64_t* log) {
    Guard g1(log, 1);
    int keep_outer = v * 5 + 7;
    try {
        return mid_frame(mode, v, log) + keep_outer;
    } catch (const DerivedSingle& ds) {
        return ds.tag() + 10000 + keep_outer;
    } catch (const DerivedMulti& dm) {
        return dm.tag() + dm.tagB() + 20000 + keep_outer;
    } catch (const BaseA& ba) {
        return ba.tag() + 30000 + keep_outer;
    } catch (int i) {
        return i + 40000 + keep_outer;
    } catch (const char* s) {
        return static_cast<int>(s[0]) + 50000 + keep_outer;
    } catch (...) {
        return 60000 + keep_outer;
    }
}

int main() {
    uint8_t buf[4096];
    uint64_t log = 0xabcdef0123456789ULL;
    uint64_t acc = 0;
    size_t total = 0;
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
        const size_t limit = (total < 128) ? ((128 - total < n) ? (128 - total) : n) : 0;
        for (size_t i = 0; i < limit; ++i) {
            const int r = outer_frame(buf[i], static_cast<int>(buf[i]) + static_cast<int>(total + i), &log);
            acc = (acc * 33ULL) ^ static_cast<uint64_t>(static_cast<int64_t>(r));
        }
        total += n;
    }
    printf("len=%zu acc=%016llx log=%016llx\n",
           total,
           static_cast<unsigned long long>(acc),
           static_cast<unsigned long long>(log));
    return 0;
}
