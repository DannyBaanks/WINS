#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <dlfcn.h>

extern uint64_t mach_absolute_time(void);
struct mach_timebase_info { uint32_t numer; uint32_t denom; };
extern int mach_timebase_info(struct mach_timebase_info *info);
extern int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
extern uint32_t arc4random(void);
extern int _NSGetExecutablePath(char *buf, uint32_t *bufsize);

// Exact Darwin 64-bit struct stat (144 bytes)
struct darwin_timespec { int64_t tv_sec; int64_t tv_nsec; };
struct darwin_stat64 {
    int32_t st_dev;
    uint16_t st_mode;
    uint16_t st_nlink;
    uint64_t st_ino;
    uint32_t st_uid;
    uint32_t st_gid;
    int32_t st_rdev;
    struct darwin_timespec st_atimespec;
    struct darwin_timespec st_mtimespec;
    struct darwin_timespec st_ctimespec;
    struct darwin_timespec st_birthtimespec;
    int64_t st_size;
    int64_t st_blocks;
    int32_t st_blksize;
    uint32_t st_flags;
    uint32_t st_gen;
    int32_t st_lspare;
    int64_t st_qspare[2];
};
extern int stat(const char *path, struct darwin_stat64 *buf);

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

int main(void) {
    struct mach_timebase_info tb = {0, 0};
    mach_timebase_info(&tb);
    uint64_t t0 = mach_absolute_time();

    uint32_t ncpu = 0;
    size_t sz = sizeof(ncpu);
    sysctlbyname("hw.ncpu", &ncpu, &sz, NULL, 0);

    uint32_t pagesz = 0;
    sz = sizeof(pagesz);
    sysctlbyname("hw.pagesize", &pagesz, &sz, NULL, 0);

    char exe_path[256];
    uint32_t exe_len = sizeof(exe_path);
    _NSGetExecutablePath(exe_path, &exe_len);

    struct darwin_stat64 st;
    if (stat(exe_path, &st) != 0) return 10;

    pthread_mutex_lock(&g_mtx);
    uint32_t rnd = arc4random();
    pthread_mutex_unlock(&g_mtx);

    void *h = dlopen(NULL, 0);
    int (*fn_getpid)(void) = (int (*)(void))dlsym(h, "getpid");
    int pid = fn_getpid ? fn_getpid() : -1;

    uint64_t t1 = mach_absolute_time();
    printf("tb=%u/%u dt=%llu ncpu=%u pagesz=%u size=%lld rnd=0x%x pid=%d exe=%s\n",
           tb.numer, tb.denom, (unsigned long long)(t1 - t0),
           ncpu, pagesz, (long long)st.st_size, rnd, pid, exe_path);
    return (tb.numer == 1 && ncpu >= 1 && pagesz == 4096 && st.st_size > 1000 && pid > 0) ? 0 : 1;
}
