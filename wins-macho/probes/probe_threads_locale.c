/*
 * Dual-compiled Differential Probe #2: Pthreads, Static Mutex, Locale, Getpwuid, Strings
 * Compiled BOTH as macOS x86_64 Mach-O (tested under wins_macho)
 * AND as Linux x86_64 ELF (the independent native oracle).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <pwd.h>
#include <pthread.h>
#include <time.h>

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_shared_sum = 0;

struct WorkerArg {
    const unsigned char *data;
    size_t start;
    size_t end;
};

static void *worker_fn(void *raw) {
    struct WorkerArg *wa = (struct WorkerArg *)raw;
    uint64_t local = 0;
    for (size_t i = wa->start; i < wa->end; i++) {
        unsigned char c = wa->data[i];
        local += (uint64_t)tolower((int)c) * 31ULL + (isalpha((int)c) ? 7ULL : (isdigit((int)c) ? 3ULL : 1ULL));
    }
    pthread_mutex_lock(&g_mtx);
    g_shared_sum += local;
    pthread_mutex_unlock(&g_mtx);
    return NULL;
}

int main(void) {
    setlocale(LC_ALL, "C");

    struct timespec t0, t1;
    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) return 2;

    unsigned char buf[16384];
    size_t len = fread(buf, 1, sizeof(buf), stdin);

    /* 2-thread deterministic reduction using static PTHREAD_MUTEX_INITIALIZER */
    g_shared_sum = 0;
    size_t mid = len / 2;
    struct WorkerArg a1 = { buf, 0, mid };
    struct WorkerArg a2 = { buf, mid, len };
    pthread_t th1, th2;
    if (pthread_create(&th1, NULL, worker_fn, &a1) != 0) return 3;
    if (pthread_create(&th2, NULL, worker_fn, &a2) != 0) return 4;
    pthread_join(th1, NULL);
    pthread_join(th2, NULL);

    /* Verify DarwinPasswd struct layout via getpwuid(0) */
    struct passwd *pw = getpwuid(0);
    const char *root_name = (pw && pw->pw_name) ? pw->pw_name : "(null)";
    const char *root_dir = (pw && pw->pw_dir) ? pw->pw_dir : "(null)";

    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) return 5;
    int mono_ok = (t1.tv_sec > t0.tv_sec || (t1.tv_sec == t0.tv_sec && t1.tv_nsec >= t0.tv_nsec)) ? 1 : 0;

    printf("len=%zu sum=%016llx root=%s dir=%s mono=%d\n",
           len, (unsigned long long)g_shared_sum, root_name, root_dir, mono_ok);
    return mono_ok ? 0 : 6;
}
