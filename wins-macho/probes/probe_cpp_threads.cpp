/*
 * Dual-compiled Differential Probe #3 (C++ / libc++):
 * Static C++ ctors/dtors (__init_offsets / __mod_init_func + __cxa_atexit),
 * std::string (SSO <= 22B & long heap > 22B + substr + assign),
 * std::vector, std::deque, std::shared_ptr (__shared_weak_count),
 * std::mutex, std::condition_variable, std::thread (4-worker queue),
 * std::chrono::system_clock, std::system_category / generic_category.
 *
 * Compiled BOTH as macOS x86_64 Mach-O (tested under wins_macho)
 * AND as Linux x86_64 ELF (the independent native oracle).
 */
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

static const std::string g_short_banner = "wins-macho-cpp";
static const std::string g_long_banner = "wins-macho-darwin-libcxx-abi-v1-sso-long-verification-string";

struct Chunk {
    std::vector<uint8_t> bytes;
    uint32_t id;
};

class WorkQueue {
public:
    void push(std::shared_ptr<Chunk> item) {
        std::unique_lock<std::mutex> lk(mtx_);
        q_.push_back(std::move(item));
        cv_.notify_one();
    }

    void finish() {
        std::unique_lock<std::mutex> lk(mtx_);
        done_ = true;
        cv_.notify_all();
    }

    bool pop(std::shared_ptr<Chunk>& out) {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait(lk, [this] { return done_ || !q_.empty(); });
        if (q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop_front();
        return true;
    }

private:
    std::mutex mtx_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<Chunk>> q_;
    bool done_ = false;
};

static uint64_t hashChunk(const Chunk& c) {
    uint64_t h = 14695981039346656037ULL ^ (static_cast<uint64_t>(c.id) * 0x9e3779b97f4a7c15ULL);
    for (uint8_t b : c.bytes) {
        h ^= static_cast<uint64_t>(b);
        h *= 1099511628211ULL;
    }
    return h;
}

int main() {
    const auto t0 = std::chrono::system_clock::now();

    std::vector<uint8_t> input;
    uint8_t tmp[4096];
    while (true) {
        const size_t n = std::fread(tmp, 1, sizeof(tmp), stdin);
        if (n == 0) break;
        input.insert(input.end(), tmp, tmp + n);
    }

    // Exercise std::string short/long, substr, assign
    std::string s_short = g_short_banner.substr(5, 5); // "macho"
    std::string s_long = g_long_banner.substr(11, 28); // "darwin-libcxx-abi-v1-sso-lon"
    std::string s_mut = "initial";
    s_mut.assign(g_long_banner.c_str());
    s_mut.assign("ok");

    // 4-thread parallel WorkQueue over std::shared_ptr<Chunk>
    WorkQueue wq;
    std::mutex out_mtx;
    uint64_t xor_acc = 0;
    uint64_t sum_acc = 0;

    std::vector<std::thread> workers;
    workers.reserve(4);
    for (int w = 0; w < 4; ++w) {
        workers.emplace_back([&] {
            std::shared_ptr<Chunk> item;
            while (wq.pop(item)) {
                const uint64_t h = hashChunk(*item);
                std::unique_lock<std::mutex> lk(out_mtx);
                xor_acc ^= h;
                sum_acc += h;
            }
        });
    }

    const size_t chunk_sz = 257;
    uint32_t cid = 0;
    for (size_t off = 0; off < input.size(); off += chunk_sz) {
        const size_t end = (off + chunk_sz < input.size()) ? (off + chunk_sz) : input.size();
        auto c = std::make_shared<Chunk>();
        c->id = cid++;
        c->bytes.assign(input.begin() + static_cast<ptrdiff_t>(off),
                        input.begin() + static_cast<ptrdiff_t>(end));
        wq.push(std::move(c));
    }
    wq.finish();

    for (auto& th : workers) {
        th.join();
    }

    const auto t1 = std::chrono::system_clock::now();
    const int time_ok = (t1 >= t0) ? 1 : 0;

    std::printf("len=%zu chunks=%u xor=%016llx sum=%016llx s=%s l=%s m=%s cat=%s/%s t=%d\n",
                input.size(),
                cid,
                static_cast<unsigned long long>(xor_acc),
                static_cast<unsigned long long>(sum_acc),
                s_short.c_str(),
                s_long.c_str(),
                s_mut.c_str(),
                std::system_category().name(),
                std::generic_category().name(),
                time_ok);
    return time_ok ? 0 : 2;
}
