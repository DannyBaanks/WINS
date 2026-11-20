/*
 * Dual-compiled Differential Probe #4 (C++17 Exceptions & Compact Unwind):
 * - Deep multi-frame RAII stack unwinding with callee-saved register preservation
 * - Exact type catch (int, std::out_of_range) & polymorphic derived->base catch (DerivedErr -> BaseErr, std::exception)
 * - catch (...) catch-all
 * - Rethrow (throw;) across intermediate cleanup frames
 * - Nested exceptions (throw/catch inside an active catch block)
 * - std::uncaught_exceptions() tracking during RAII unwind
 * - Concurrent exception throwing across 2 std::thread workers
 *
 * Compiled BOTH as macOS x86_64 Mach-O (tested under wins_macho)
 * AND as Linux x86_64 ELF (the independent native oracle).
 */
#include <cstdint>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

struct BaseErr {
    int code;
    explicit BaseErr(int c) : code(c) {}
    virtual ~BaseErr() = default;
    virtual int score() const { return code; }
};

struct DerivedErr : public BaseErr {
    int extra;
    DerivedErr(int c, int e) : BaseErr(c), extra(e) {}
    int score() const override { return code * 100 + extra; }
};

struct SecretTag {
    uint64_t magic;
};

struct Guard {
    uint64_t* trace;
    uint32_t id;
    Guard(uint64_t* t, uint32_t i) : trace(t), id(i) {
        *trace = (*trace * 131ULL) ^ (id * 3ULL + 1ULL);
    }
    ~Guard() {
        const int u = std::uncaught_exceptions();
        *trace = (*trace * 131ULL) ^ (id * 17ULL + static_cast<uint64_t>(u) * 5ULL + 7ULL);
    }
};

__attribute__((noinline)) static void level3_throw(uint8_t mode, int val, uint64_t* trace) {
    Guard g3(trace, 3);
    switch (mode % 5) {
        case 0:
            throw DerivedErr(val, (val * 7) & 0x3f);
        case 1:
            throw std::out_of_range("oor_" + std::to_string(val));
        case 2:
            throw SecretTag{0xCAFE0000ULL | static_cast<uint64_t>(val & 0xff)};
        case 3:
            throw static_cast<int>(val * 13 + 5);
        default:
            // No throw path
            *trace ^= static_cast<uint64_t>(val + 99);
            return;
    }
}

__attribute__((noinline)) static int level2_rethrow(uint8_t mode, int val, uint64_t* trace) {
    Guard g2(trace, 2);
    volatile int keep_a = val + 11;
    volatile int keep_b = val * 3 + 7;
    try {
        level3_throw(mode, val, trace);
        return keep_a + keep_b;
    } catch (const BaseErr& e) {
        // Exercise nested throw/catch inside an active catch handler
        int inner_bonus = 0;
        try {
            Guard g_inner(trace, 9);
            if ((val & 1) != 0) throw int(e.code + 1);
            inner_bonus = 2;
        } catch (int x) {
            inner_bonus = x;
        }
        *trace ^= static_cast<uint64_t>(inner_bonus);
        if ((val & 2) != 0) {
            throw; // rethrow to level1!
        }
        return e.score() + inner_bonus + keep_a;
    }
}

__attribute__((noinline)) static int level1_catch_all(uint8_t mode, int val, uint64_t* trace) {
    Guard g1(trace, 1);
    int saved_acc = val * 5 + 3;
    try {
        return level2_rethrow(mode, val, trace) + saved_acc;
    } catch (const DerivedErr& d) {
        return d.score() + 10000 + saved_acc;
    } catch (const std::logic_error& le) {
        return static_cast<int>(std::string(le.what()).size()) + 20000 + saved_acc;
    } catch (int i) {
        return i + 30000 + saved_acc;
    } catch (...) {
        return 40000 + saved_acc;
    }
}

static uint64_t run_slice(const std::vector<uint8_t>& data, size_t start, size_t end) {
    uint64_t trace = 0x123456789abcdef0ULL;
    uint64_t acc = 0;
    const size_t limit = (end - start > 64) ? (start + 64) : end;
    for (size_t i = start; i < limit; ++i) {
        const uint8_t b = data[i];
        const int r = level1_catch_all(b, static_cast<int>(b) + static_cast<int>(i - start), &trace);
        acc = (acc * 33ULL) ^ static_cast<uint64_t>(static_cast<int64_t>(r));
    }
    return acc ^ trace;
}

int main() {
    std::vector<uint8_t> input;
    uint8_t buf[4096];
    while (true) {
        const size_t n = std::fread(buf, 1, sizeof(buf), stdin);
        if (n == 0) break;
        input.insert(input.end(), buf, buf + n);
    }

    const size_t mid = input.size() / 2;
    uint64_t res1 = 0;
    uint64_t res2 = 0;

    std::thread t1([&] { res1 = run_slice(input, 0, mid); });
    std::thread t2([&] { res2 = run_slice(input, mid, input.size()); });
    t1.join();
    t2.join();

    std::printf("len=%zu t1=%016llx t2=%016llx uncaught=%d\n",
                input.size(),
                static_cast<unsigned long long>(res1),
                static_cast<unsigned long long>(res2),
                std::uncaught_exceptions());
    return (std::uncaught_exceptions() == 0) ? 0 : 2;
}
