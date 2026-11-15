/* thread_probe: deterministic Win32 threading/synchronization probe (i386, no CRT).
 *
 * Built with: zig cc -target x86-windows-gnu -nostdlib -O1 -Wl,--entry=probe_main
 *             thread_probe.c -lkernel32 -o thread_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the exit
 * code byte for byte (tools/diff_wine.sh). Every line is deterministic: no addresses,
 * no thread ids, no timings. It exercises exactly the kernel32 surface FalloutNV needs
 * for its worker threads: CreateThread (also suspended), ExitThread, GetExitCodeThread,
 * events (manual/auto), semaphores, mutexes, critical sections, WaitForSingleObject
 * and WaitForMultipleObjects (any/all, timeouts), TlsAlloc, interlocked operations.
 */
#include <windows.h>

static HANDLE g_out;

static void put(const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(g_out, s, n, &w, 0);
}
static void putu(unsigned v) {
    char b[16]; int i = 15; b[i] = 0;
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    put(b + i);
}
static void line(const char *tag, unsigned v) { put(tag); put("="); putu(v); put("\n"); }

/* ---- 1: exit code through GetExitCodeThread ---- */
static DWORD WINAPI exit42(LPVOID p) { (void)p; return 42; }

/* ---- 2: ping-pong over two auto-reset events (an I/O worker handshake) ---- */
struct pp { HANDLE ask, answer; volatile LONG count; LONG n; };
static DWORD WINAPI pp_worker(LPVOID p) {
    struct pp *s = (struct pp *)p;
    for (LONG i = 0; i < s->n; i++) {
        WaitForSingleObject(s->ask, INFINITE);
        InterlockedIncrement(&s->count);
        SetEvent(s->answer);
    }
    return 0;
}

/* ---- 3: critical section with four contending threads ---- */
struct cs { CRITICAL_SECTION lock; volatile LONG shared; LONG n; };
static DWORD WINAPI cs_worker(LPVOID p) {
    struct cs *s = (struct cs *)p;
    for (LONG i = 0; i < s->n; i++) {
        EnterCriticalSection(&s->lock);
        LONG v = s->shared;      /* plain read-modify-write: only the lock protects it */
        s->shared = v + 1;
        LeaveCriticalSection(&s->lock);
    }
    return 0;
}

/* ---- 4: semaphore producer/consumer ---- */
struct sem { HANDLE s; volatile LONG got; LONG n; };
static DWORD WINAPI sem_consumer(LPVOID p) {
    struct sem *s = (struct sem *)p;
    for (LONG i = 0; i < s->n; i++) {
        WaitForSingleObject(s->s, INFINITE);
        InterlockedIncrement(&s->got);
    }
    return 0;
}

/* ---- 5: TLS: every thread sees its own slot ---- */
static DWORD g_slot;
static DWORD WINAPI tls_worker(LPVOID p) {
    TlsSetValue(g_slot, p);
    Sleep(5);
    return (DWORD)(ULONG_PTR)TlsGetValue(g_slot);   /* must still be this thread's value */
}

/* ---- 6: suspended creation ---- */
static volatile LONG g_ran;
static DWORD WINAPI mark_ran(LPVOID p) { (void)p; InterlockedIncrement(&g_ran); return 7; }

/* ---- 7: ExitThread ends only the calling thread ---- */
static DWORD WINAPI exit_thread_with_9(LPVOID p) { (void)p; ExitThread(9); return 1; }

/* ---- 8: thread id seen from inside equals the one CreateThread returned ---- */
static DWORD WINAPI report_id(LPVOID p) { *(volatile DWORD *)p = GetCurrentThreadId(); return 0; }

/* ---- 9: last error is per thread ---- */
static DWORD WINAPI set_err(LPVOID p) { (void)p; SetLastError(1234); return GetLastError(); }

/* ---- 10: mutex held by one thread blocks another until released ---- */
struct mx { HANDLE m, held, go; volatile LONG order; };
static DWORD WINAPI mx_holder(LPVOID p) {
    struct mx *s = (struct mx *)p;
    WaitForSingleObject(s->m, INFINITE);
    SetEvent(s->held);
    WaitForSingleObject(s->go, INFINITE);
    InterlockedExchange(&s->order, 1);   /* written while holding the mutex */
    ReleaseMutex(s->m);
    return 0;
}

int __stdcall probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD code = 0;
    HANDLE t = CreateThread(0, 0, exit42, 0, 0, 0);
    line("t1_wait", WaitForSingleObject(t, 5000));
    GetExitCodeThread(t, &code); line("t1_exit", code);
    CloseHandle(t);

    struct pp pp; pp.ask = CreateEventA(0, 0, 0, 0); pp.answer = CreateEventA(0, 0, 0, 0); pp.count = 0; pp.n = 500;
    t = CreateThread(0, 0, pp_worker, &pp, 0, 0);
    LONG lock_step_ok = 1;
    for (LONG i = 0; i < pp.n; i++) {
        SetEvent(pp.ask);
        if (WaitForSingleObject(pp.answer, 5000) != WAIT_OBJECT_0) { lock_step_ok = 0; break; }
        if (pp.count != i + 1) lock_step_ok = 0;
    }
    WaitForSingleObject(t, 5000); CloseHandle(t);
    line("t2_count", (unsigned)pp.count); line("t2_lockstep", (unsigned)lock_step_ok);

    struct cs cs; InitializeCriticalSection(&cs.lock); cs.shared = 0; cs.n = 5000;
    HANDLE ws[4];
    for (int i = 0; i < 4; i++) ws[i] = CreateThread(0, 0, cs_worker, &cs, 0, 0);
    line("t3_wait_all", WaitForMultipleObjects(4, ws, TRUE, 20000));
    line("t3_total", (unsigned)cs.shared);
    for (int i = 0; i < 4; i++) CloseHandle(ws[i]);
    DeleteCriticalSection(&cs.lock);

    struct sem se; se.s = CreateSemaphoreA(0, 0, 1000, 0); se.got = 0; se.n = 100;
    t = CreateThread(0, 0, sem_consumer, &se, 0, 0);
    for (int i = 0; i < 100; i++) ReleaseSemaphore(se.s, 1, 0);
    line("t4_wait", WaitForSingleObject(t, 5000));
    line("t4_got", (unsigned)se.got);
    LONG prev = -1;
    line("t4_over_max", ReleaseSemaphore(CreateSemaphoreA(0, 1, 1, 0), 1, &prev)); line("t4_prev", (unsigned)prev);
    CloseHandle(t); CloseHandle(se.s);

    g_slot = TlsAlloc();
    TlsSetValue(g_slot, (LPVOID)1000);
    HANDLE tl[3];
    for (int i = 0; i < 3; i++) tl[i] = CreateThread(0, 0, tls_worker, (LPVOID)(ULONG_PTR)(100 + i), 0, 0);
    WaitForMultipleObjects(3, tl, TRUE, 5000);
    for (int i = 0; i < 3; i++) { GetExitCodeThread(tl[i], &code); line("t5_tls", code); CloseHandle(tl[i]); }
    line("t5_main_slot", (unsigned)(ULONG_PTR)TlsGetValue(g_slot));

    t = CreateThread(0, 0, mark_ran, 0, CREATE_SUSPENDED, 0);
    Sleep(50);
    line("t6_ran_before_resume", (unsigned)g_ran);
    line("t6_resume_prev", ResumeThread(t));
    WaitForSingleObject(t, 5000);
    line("t6_ran_after_resume", (unsigned)g_ran);
    GetExitCodeThread(t, &code); line("t6_exit", code); CloseHandle(t);

    t = CreateThread(0, 0, exit_thread_with_9, 0, 0, 0);
    WaitForSingleObject(t, 5000);
    GetExitCodeThread(t, &code); line("t7_exit", code); CloseHandle(t);

    volatile DWORD seen = 0; DWORD returned = 0;
    t = CreateThread(0, 0, report_id, (LPVOID)&seen, 0, &returned);
    WaitForSingleObject(t, 5000);
    line("t8_id_matches", seen == returned && seen != 0 && seen != GetCurrentThreadId()); CloseHandle(t);

    SetLastError(0);
    t = CreateThread(0, 0, set_err, 0, 0, 0);
    WaitForSingleObject(t, 5000);
    GetExitCodeThread(t, &code); line("t9_thread_err", code);
    line("t9_main_err", GetLastError()); CloseHandle(t);

    HANDLE e = CreateEventA(0, TRUE, FALSE, 0);
    line("t10_timeout", WaitForSingleObject(e, 30));
    SetEvent(e);
    line("t10_signaled", WaitForSingleObject(e, 0));
    line("t10_still_signaled", WaitForSingleObject(e, 0));   /* manual reset stays set */
    ResetEvent(e);
    line("t10_reset", WaitForSingleObject(e, 0));
    HANDLE a1 = CreateEventA(0, FALSE, FALSE, 0), a2 = CreateEventA(0, FALSE, FALSE, 0);
    HANDLE both[2] = { a1, a2 };
    SetEvent(a2);
    line("t10_any_index", WaitForMultipleObjects(2, both, FALSE, 0));   /* WAIT_OBJECT_0 + 1 */
    line("t10_any_consumed", WaitForMultipleObjects(2, both, FALSE, 0));
    SetEvent(a1);
    line("t10_all_missing", WaitForMultipleObjects(2, both, TRUE, 0));
    SetEvent(a2);
    line("t10_all", WaitForMultipleObjects(2, both, TRUE, 0));

    struct mx mx; mx.m = CreateMutexA(0, FALSE, 0); mx.held = CreateEventA(0, TRUE, FALSE, 0); mx.go = CreateEventA(0, TRUE, FALSE, 0); mx.order = 0;
    t = CreateThread(0, 0, mx_holder, &mx, 0, 0);
    WaitForSingleObject(mx.held, 5000);
    line("t11_blocked_while_held", WaitForSingleObject(mx.m, 40));   /* WAIT_TIMEOUT */
    SetEvent(mx.go);
    line("t11_acquired_after_release", WaitForSingleObject(mx.m, 5000));
    line("t11_holder_wrote_first", (unsigned)mx.order);
    ReleaseMutex(mx.m);
    WaitForSingleObject(t, 5000); CloseHandle(t);

    put("DONE\n");
    return 0;
}
