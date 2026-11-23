typedef unsigned long size_t;
typedef long dispatch_once_t;
typedef void *dispatch_queue_t;
typedef void *dispatch_group_t;
typedef void *dispatch_semaphore_t;
typedef void *dispatch_queue_attr_t;
typedef unsigned long long dispatch_time_t;
typedef void (*dispatch_function_t)(void *);

#define DISPATCH_QUEUE_SERIAL ((dispatch_queue_attr_t)0)
#define DISPATCH_TIME_NOW ((dispatch_time_t)0)
#define DISPATCH_TIME_FOREVER (~0ULL)

extern int printf(const char *fmt, ...);
extern int strcmp(const char *s1, const char *s2);

extern int _dispatch_queue_attr_concurrent;
#define DISPATCH_QUEUE_CONCURRENT ((dispatch_queue_attr_t)&_dispatch_queue_attr_concurrent)

extern dispatch_queue_t dispatch_get_global_queue(long identifier, unsigned long flags);
extern dispatch_queue_t dispatch_queue_create(const char *label, dispatch_queue_attr_t attr);
extern const char *dispatch_queue_get_label(dispatch_queue_t queue);
extern void dispatch_async(dispatch_queue_t queue, void (^block)(void));
extern void dispatch_sync(dispatch_queue_t queue, void (^block)(void));
extern void dispatch_apply_f(size_t iterations, dispatch_queue_t queue, void *context, void (*work)(void *, size_t));
extern void dispatch_once(dispatch_once_t *predicate, void (^block)(void));
extern dispatch_group_t dispatch_group_create(void);
extern void dispatch_group_async(dispatch_group_t group, dispatch_queue_t queue, void (^block)(void));
extern void dispatch_group_notify(dispatch_group_t group, dispatch_queue_t queue, void (^block)(void));
extern long dispatch_group_wait(dispatch_group_t group, dispatch_time_t timeout);
extern dispatch_semaphore_t dispatch_semaphore_create(long value);
extern long dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout);
extern long dispatch_semaphore_signal(dispatch_semaphore_t dsema);
extern dispatch_time_t dispatch_time(dispatch_time_t when, long long delta);
extern void dispatch_after(dispatch_time_t when, dispatch_queue_t queue, void (^block)(void));
extern void dispatch_release(void *object);

static void apply_sum(void *ctx, size_t idx) {
    int *sum = (int *)ctx;
    *sum += (int)(idx + 1);
}

int main(void) {
    // 1. Serial queue FIFO ordering
    dispatch_queue_t serial = dispatch_queue_create("com.wins.serial", DISPATCH_QUEUE_SERIAL);
    if (strcmp(dispatch_queue_get_label(serial), "com.wins.serial") != 0) return 10;

    __block int trace_val = 0;
    dispatch_async(serial, ^{
        trace_val = trace_val * 10 + 1;
    });
    dispatch_async(serial, ^{
        trace_val = trace_val * 10 + 2;
    });
    dispatch_sync(serial, ^{
        trace_val = trace_val * 10 + 3;
    });
    if (trace_val != 123) {
        printf("serial order mismatch: %d\n", trace_val);
        return 11;
    }

    // 2. dispatch_once
    static dispatch_once_t once_tok = 0;
    __block int once_count = 0;
    for (int i = 0; i < 4; i++) {
        dispatch_once(&once_tok, ^{
            once_count++;
        });
    }
    if (once_count != 1) return 12;

    // 3. dispatch_group + global concurrent queue + notify + semaphore
    dispatch_queue_t global = dispatch_get_global_queue(0, 0);
    dispatch_group_t grp = dispatch_group_create();
    dispatch_semaphore_t done_sem = dispatch_semaphore_create(0);

    __block int a = 0;
    __block int b = 0;
    __block int notified = 0;

    dispatch_group_async(grp, global, ^{
        __atomic_store_n(&a, 20, __ATOMIC_RELEASE);
    });
    dispatch_group_async(grp, global, ^{
        __atomic_store_n(&b, 22, __ATOMIC_RELEASE);
    });
    dispatch_group_notify(grp, serial, ^{
        notified = __atomic_load_n(&a, __ATOMIC_ACQUIRE) + __atomic_load_n(&b, __ATOMIC_ACQUIRE);
        dispatch_semaphore_signal(done_sem);
    });

    if (dispatch_group_wait(grp, DISPATCH_TIME_FOREVER) != 0) return 13;
    if (dispatch_semaphore_wait(done_sem, DISPATCH_TIME_FOREVER) != 0) return 14;
    if (notified != 42) return 15;

    // 4. dispatch_apply_f
    int apply_acc = 0;
    dispatch_apply_f(5, global, &apply_acc, apply_sum);
    if (apply_acc != 15) return 16;

    // 5. dispatch_after (5ms)
    __block int after_hit = 0;
    dispatch_semaphore_t after_sem = dispatch_semaphore_create(0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5000000LL), serial, ^{
        after_hit = 99;
        dispatch_semaphore_signal(after_sem);
    });
    dispatch_semaphore_wait(after_sem, DISPATCH_TIME_FOREVER);
    if (after_hit != 99) return 17;

    dispatch_release(after_sem);
    dispatch_release(done_sem);
    dispatch_release(grp);
    dispatch_release(serial);

    printf("dispatch_ok fifo=%d once=%d group=%d apply=%d after=%d\n",
           trace_val, once_count, notified, apply_acc, after_hit);
    return 0;
}
