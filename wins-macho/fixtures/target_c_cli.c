#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

static void *worker(void *arg) {
    int *val = (int *)arg;
    *val = (*val) * 3 + 1;
    return NULL;
}

int main(void) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int x = 7;
    pthread_t th;
    if (pthread_create(&th, NULL, worker, &x) != 0) {
        return 2;
    }
    pthread_join(th, NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    long dt_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
    printf("pid=%d worker_result=%d elapsed_ns=%ld\n", getpid(), x, dt_ns);
    return x == 22 ? 0 : 1;
}
