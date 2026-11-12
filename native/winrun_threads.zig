//! WINS winrun_threads: real threads and synchronization objects for the guest.
//!
//! The i386 loader used to fake all of this in one thread: CreateThread returned a
//! constant and never ran the start routine, every CreateEvent/CreateMutex/
//! CreateSemaphore returned the same handle, WaitForSingleObject returned success at
//! once, EnterCriticalSection assumed thread id 1. A guest that hands work to a
//! worker thread (FalloutNV reads its .bsa archives that way) then never gets the
//! result. This module implements the Win32 semantics for real, on pthreads:
//!
//!  - CreateThread runs the start routine on a new Linux thread (optionally created
//!    suspended); a per-thread hook lets the loader give it its own TEB/FS/TLS.
//!  - Events (manual/auto reset), semaphores and mutexes block and wake correctly,
//!    with timeouts; WaitForMultipleObjects supports wait-any and wait-all.
//!  - Critical sections exclude between threads and are recursive.
//!
//! Everything is guarded by one process-wide mutex and one condition variable that
//! is broadcast on every state change. That is deliberately simple: correctness over
//! scalability. Handles are small integers in [HANDLE_BASE, ...); anything else (the
//! loader's legacy constants, Steam bridge handles) is "not ours" and callers fall
//! back to their old behaviour.
//!
//! NOT_DEMONSTRATED: SuspendThread on a thread that is already running (no safe way
//! to stop an arbitrary Linux thread here: it only keeps the count), thread priority
//! and affinity, APCs, abandoned-mutex detection, DLL_THREAD_DETACH notifications.

const std = @import("std");
const linux = std.os.linux;
const c = std.c;

pub const W: std.builtin.CallingConvention = .winapi;

pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_FAILED: u32 = 0xFFFFFFFF;
pub const INFINITE: u32 = 0xFFFFFFFF;
pub const STILL_ACTIVE: u32 = 259;
pub const CREATE_SUSPENDED: u32 = 0x4;

pub const HANDLE_BASE: usize = 0x6000;
const HANDLE_STEP: usize = 4;
const MAX_OBJECTS = 4096;
pub const MAXIMUM_WAIT_OBJECTS = 64;

pub const StartFn = *const fn (?*anyopaque) callconv(W) u32;
pub const Kind = enum { event, semaphore, mutex, thread };

pub const Object = struct {
    kind: Kind,
    /// Open handles, plus one while a thread's start routine is still running.
    refs: u32 = 1,
    slot: usize = 0,
    name_len: u8 = 0,
    name: [48]u8 = [_]u8{0} ** 48,
    // event
    manual: bool = false,
    signaled: bool = false,
    // semaphore
    count: i32 = 0,
    max: i32 = 0,
    // mutex
    owner: u32 = 0,
    recursion: u32 = 0,
    // thread
    tid: u32 = 0,
    tid_ready: bool = false,
    exit_code: u32 = STILL_ACTIVE,
    finished: bool = false,
    suspend_count: i32 = 0,
    start: ?StartFn = null,
    param: ?*anyopaque = null,
    stack_size: usize = 0,
};

var g_mu: c.pthread_mutex_t = .{};
var g_cv: c.pthread_cond_t = .{};
var g_objs: [MAX_OBJECTS]?*Object = [_]?*Object{null} ** MAX_OBJECTS;

/// Called on a new thread before the guest's start routine runs, to build its
/// TEB/FS/TLS. Null in unit tests.
pub var g_thread_init: ?*const fn (*Object) void = null;

threadlocal var g_current: ?*Object = null;

fn lock() void {
    _ = c.pthread_mutex_lock(&g_mu);
}
fn unlock() void {
    _ = c.pthread_mutex_unlock(&g_mu);
}
fn wake() void {
    _ = c.pthread_cond_broadcast(&g_cv);
}

fn tidNow() u32 {
    return @intCast(linux.gettid());
}

fn handleOf(o: *const Object) usize {
    return HANDLE_BASE + o.slot * HANDLE_STEP;
}

/// Looks a handle up. The caller holds the lock.
fn find(h: usize) ?*Object {
    if (h < HANDLE_BASE or (h - HANDLE_BASE) % HANDLE_STEP != 0) return null;
    const idx = (h - HANDLE_BASE) / HANDLE_STEP;
    if (idx >= MAX_OBJECTS) return null;
    return g_objs[idx];
}

/// True when `h` is a handle this module owns (and still open).
pub fn isOurs(h: usize) bool {
    lock();
    defer unlock();
    return find(h) != null;
}

fn alloc(kind: Kind, name: ?[]const u8) ?*Object {
    // Named objects are shared: a second Create with the same name and kind
    // returns the existing object with another reference.
    if (name) |n| {
        if (n.len > 0) {
            for (g_objs) |maybe| {
                if (maybe) |o| {
                    if (o.kind == kind and o.name_len == n.len and std.mem.eql(u8, o.name[0..o.name_len], n)) {
                        o.refs += 1;
                        return o;
                    }
                }
            }
        }
    }
    for (g_objs, 0..) |maybe, i| {
        if (maybe == null) {
            const o = std.heap.c_allocator.create(Object) catch return null;
            o.* = .{ .kind = kind, .slot = i };
            if (name) |n| {
                const len = @min(n.len, o.name.len);
                @memcpy(o.name[0..len], n[0..len]);
                o.name_len = @intCast(len);
            }
            g_objs[i] = o;
            return o;
        }
    }
    return null;
}

/// Drops one reference; frees the object when none is left. Lock held.
fn release(o: *Object) void {
    if (o.refs > 0) o.refs -= 1;
    if (o.refs == 0) {
        g_objs[o.slot] = null;
        std.heap.c_allocator.destroy(o);
    }
}

// ---------------------------------------------------------------------------
// Events, semaphores, mutexes
// ---------------------------------------------------------------------------

pub fn createEvent(manual: bool, initial: bool, name: ?[]const u8) usize {
    lock();
    defer unlock();
    const existed = if (name) |n| n.len > 0 and hasNamed(.event, n) else false;
    const o = alloc(.event, name) orelse return 0;
    if (!existed) {
        o.manual = manual;
        o.signaled = initial;
    }
    return handleOf(o);
}

fn hasNamed(kind: Kind, n: []const u8) bool {
    for (g_objs) |maybe| {
        if (maybe) |o| {
            if (o.kind == kind and o.name_len == n.len and std.mem.eql(u8, o.name[0..o.name_len], n)) return true;
        }
    }
    return false;
}

pub fn setEvent(h: usize) bool {
    lock();
    defer unlock();
    const o = find(h) orelse return false;
    if (o.kind != .event) return false;
    o.signaled = true;
    wake();
    return true;
}

pub fn resetEvent(h: usize) bool {
    lock();
    defer unlock();
    const o = find(h) orelse return false;
    if (o.kind != .event) return false;
    o.signaled = false;
    return true;
}

/// Releases the waiters that can be released now and leaves the event unsignaled.
pub fn pulseEvent(h: usize) bool {
    lock();
    defer unlock();
    const o = find(h) orelse return false;
    if (o.kind != .event) return false;
    o.signaled = true;
    wake();
    // Give the woken waiters a chance to consume the pulse before it is cleared.
    unlock();
    sleepMs(1);
    lock();
    o.signaled = false;
    return true;
}

pub fn createSemaphore(initial: i32, max: i32, name: ?[]const u8) usize {
    if (max <= 0 or initial < 0 or initial > max) return 0;
    lock();
    defer unlock();
    const existed = if (name) |n| n.len > 0 and hasNamed(.semaphore, n) else false;
    const o = alloc(.semaphore, name) orelse return 0;
    if (!existed) {
        o.count = initial;
        o.max = max;
    }
    return handleOf(o);
}

/// ReleaseSemaphore: false (count unchanged) if it would exceed the maximum.
pub fn releaseSemaphore(h: usize, release_count: i32, previous: ?*i32) bool {
    lock();
    defer unlock();
    const o = find(h) orelse return false;
    if (o.kind != .semaphore or release_count <= 0) return false;
    // lpPreviousCount is written only on success (Wine leaves it untouched on failure).
    if (o.count > o.max - release_count) return false;
    if (previous) |p| p.* = o.count;
    o.count += release_count;
    wake();
    return true;
}

pub fn createMutex(initial_owner: bool, name: ?[]const u8) usize {
    lock();
    defer unlock();
    const existed = if (name) |n| n.len > 0 and hasNamed(.mutex, n) else false;
    const o = alloc(.mutex, name) orelse return 0;
    if (!existed and initial_owner) {
        o.owner = tidNow();
        o.recursion = 1;
    }
    return handleOf(o);
}

/// ReleaseMutex: only the owner may release.
pub fn releaseMutex(h: usize) bool {
    lock();
    defer unlock();
    const o = find(h) orelse return false;
    if (o.kind != .mutex or o.owner != tidNow() or o.recursion == 0) return false;
    o.recursion -= 1;
    if (o.recursion == 0) {
        o.owner = 0;
        wake();
    }
    return true;
}

/// CloseHandle for handles this module owns. Returns false when `h` is not ours.
pub fn closeHandle(h: usize) bool {
    lock();
    defer unlock();
    const o = find(h) orelse return false;
    release(o);
    return true;
}

// ---------------------------------------------------------------------------
// Waiting
// ---------------------------------------------------------------------------

fn signaledFor(o: *const Object, tid: u32) bool {
    return switch (o.kind) {
        .event => o.signaled,
        .semaphore => o.count > 0,
        .mutex => o.owner == 0 or o.owner == tid,
        .thread => o.finished,
    };
}

fn consume(o: *Object, tid: u32) void {
    switch (o.kind) {
        .event => if (!o.manual) {
            o.signaled = false;
        },
        .semaphore => o.count -= 1,
        .mutex => {
            o.owner = tid;
            o.recursion += 1;
        },
        .thread => {},
    }
}

fn sleepMs(ms: u32) void {
    const req = linux.timespec{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    var rem: linux.timespec = undefined;
    _ = linux.nanosleep(&req, &rem);
}

const Deadline = struct {
    infinite: bool,
    abs: c.timespec,

    fn init(ms: u32) Deadline {
        if (ms == INFINITE) return .{ .infinite = true, .abs = undefined };
        var now: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &now);
        var sec: i64 = @as(i64, now.sec) + @as(i64, ms / 1000);
        var nsec: i64 = @as(i64, now.nsec) + @as(i64, ms % 1000) * 1_000_000;
        if (nsec >= 1_000_000_000) {
            nsec -= 1_000_000_000;
            sec += 1;
        }
        return .{ .infinite = false, .abs = .{ .sec = @intCast(sec), .nsec = @intCast(nsec) } };
    }
};

/// Blocks on the shared condition variable; returns true when the deadline passed.
fn waitCond(d: *const Deadline) bool {
    if (d.infinite) {
        _ = c.pthread_cond_wait(&g_cv, &g_mu);
        return false;
    }
    const rc = c.pthread_cond_timedwait(&g_cv, &g_mu, &d.abs);
    return rc == .TIMEDOUT;
}

/// WaitForSingleObject on one of our handles; null when `h` is not ours.
pub fn waitOne(h: usize, ms: u32) ?u32 {
    lock();
    defer unlock();
    const o = find(h) orelse return null;
    const tid = tidNow();
    const d = Deadline.init(ms);
    while (true) {
        if (signaledFor(o, tid)) {
            consume(o, tid);
            return WAIT_OBJECT_0;
        }
        if (ms == 0) return WAIT_TIMEOUT;
        if (waitCond(&d)) {
            // One last look: the signal may have arrived with the timeout.
            if (signaledFor(o, tid)) {
                consume(o, tid);
                return WAIT_OBJECT_0;
            }
            return WAIT_TIMEOUT;
        }
    }
}

/// WaitForMultipleObjects. Null when any handle is not ours (the caller keeps its
/// legacy behaviour); WAIT_FAILED for a bad count. Wait-any returns the lowest
/// signaled index; wait-all consumes every object atomically.
pub fn waitMany(handles: []const usize, wait_all: bool, ms: u32) ?u32 {
    if (handles.len == 0 or handles.len > MAXIMUM_WAIT_OBJECTS) return WAIT_FAILED;
    lock();
    defer unlock();
    var objs: [MAXIMUM_WAIT_OBJECTS]*Object = undefined;
    for (handles, 0..) |h, i| objs[i] = find(h) orelse return null;
    const tid = tidNow();
    const d = Deadline.init(ms);
    while (true) {
        if (wait_all) {
            var all = true;
            for (objs[0..handles.len]) |o| {
                if (!signaledFor(o, tid)) {
                    all = false;
                    break;
                }
            }
            if (all) {
                for (objs[0..handles.len]) |o| consume(o, tid);
                return WAIT_OBJECT_0;
            }
        } else {
            for (objs[0..handles.len], 0..) |o, i| {
                if (signaledFor(o, tid)) {
                    consume(o, tid);
                    return WAIT_OBJECT_0 + @as(u32, @intCast(i));
                }
            }
        }
        if (ms == 0) return WAIT_TIMEOUT;
        if (waitCond(&d)) {
            // Re-check once more with the lock held before giving up.
            if (wait_all) {
                var all = true;
                for (objs[0..handles.len]) |o| {
                    if (!signaledFor(o, tid)) {
                        all = false;
                        break;
                    }
                }
                if (all) {
                    for (objs[0..handles.len]) |o| consume(o, tid);
                    return WAIT_OBJECT_0;
                }
            } else {
                for (objs[0..handles.len], 0..) |o, i| {
                    if (signaledFor(o, tid)) {
                        consume(o, tid);
                        return WAIT_OBJECT_0 + @as(u32, @intCast(i));
                    }
                }
            }
            return WAIT_TIMEOUT;
        }
    }
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

pub fn currentThread() ?*Object {
    return g_current;
}

fn finish(o: *Object, code: u32) void {
    lock();
    o.exit_code = code;
    o.finished = true;
    wake();
    release(o); // the reference the running thread held
    unlock();
}

fn trampoline(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const o: *Object = @ptrCast(@alignCast(arg.?));
    g_current = o;
    lock();
    o.tid = tidNow();
    o.tid_ready = true;
    wake();
    unlock();
    if (g_thread_init) |init| init(o);
    // CREATE_SUSPENDED: wait for ResumeThread.
    lock();
    while (o.suspend_count > 0) _ = c.pthread_cond_wait(&g_cv, &g_mu);
    unlock();
    const code = o.start.?(o.param);
    finish(o, code);
    return null;
}

/// CreateThread. Returns the handle (0 on failure) and, through `tid_out`, the id
/// the new thread will report from GetCurrentThreadId.
pub fn createThread(stack_size: usize, start: StartFn, param: ?*anyopaque, flags: u32, tid_out: ?*u32) usize {
    lock();
    const o = alloc(.thread, null) orelse {
        unlock();
        return 0;
    };
    o.refs = 2; // the handle and the running thread
    o.start = start;
    o.param = param;
    o.stack_size = stack_size;
    o.suspend_count = if (flags & CREATE_SUSPENDED != 0) 1 else 0;
    const h = handleOf(o);
    unlock();

    var attr: c.pthread_attr_t = undefined;
    _ = c.pthread_attr_init(&attr);
    // Windows' default reserve is 1 MiB; the guest's own request wins when larger.
    _ = c.pthread_attr_setstacksize(&attr, @max(stack_size, 1 << 20));
    var th: c.pthread_t = undefined;
    const rc = c.pthread_create(&th, &attr, trampoline, o);
    _ = c.pthread_attr_destroy(&attr);
    if (rc != .SUCCESS) {
        lock();
        release(o); // thread reference
        release(o); // handle
        unlock();
        return 0;
    }
    _ = c.pthread_detach(th);
    // The id is only known once the thread runs; wait for it so that the value
    // CreateThread returns equals what the thread itself reads.
    lock();
    while (!o.tid_ready) _ = c.pthread_cond_wait(&g_cv, &g_mu);
    if (tid_out) |t| t.* = o.tid;
    unlock();
    return h;
}

/// ResumeThread: returns the previous suspend count, or 0xFFFFFFFF for a bad handle.
pub fn resumeThread(h: usize) u32 {
    lock();
    defer unlock();
    const o = find(h) orelse return WAIT_FAILED;
    if (o.kind != .thread) return WAIT_FAILED;
    const prev: u32 = @intCast(o.suspend_count);
    if (o.suspend_count > 0) o.suspend_count -= 1;
    if (o.suspend_count == 0) wake();
    return prev;
}

/// SuspendThread: only keeps the count. A thread that is already running keeps
/// running (NOT_DEMONSTRATED: stopping an arbitrary Linux thread safely).
pub fn suspendThread(h: usize) u32 {
    lock();
    defer unlock();
    const o = find(h) orelse return WAIT_FAILED;
    if (o.kind != .thread) return WAIT_FAILED;
    const prev: u32 = @intCast(o.suspend_count);
    o.suspend_count += 1;
    return prev;
}

pub fn getExitCode(h: usize, out: *u32) ?bool {
    lock();
    defer unlock();
    const o = find(h) orelse return null;
    if (o.kind != .thread) return false;
    out.* = if (o.finished) o.exit_code else STILL_ACTIVE;
    return true;
}

/// ExitThread for a thread this module started: records the exit code and ends only
/// this Linux thread. Returns false on the main thread (the caller decides).
pub fn exitCurrentThread(code: u32) bool {
    const o = g_current orelse return false;
    finish(o, code);
    linux.exit(0); // SYS_exit: this thread only, not the process
}

// ---------------------------------------------------------------------------
// Critical sections
// ---------------------------------------------------------------------------

/// winnt.h RTL_CRITICAL_SECTION (24 bytes on x86). LockCount is -1 when free.
pub const CriticalSection = extern struct {
    DebugInfo: u32,
    LockCount: i32,
    RecursionCount: i32,
    OwningThread: u32,
    LockSemaphore: u32,
    SpinCount: u32,
};

pub fn csInit(cs: *CriticalSection, spin: u32) void {
    cs.* = .{ .DebugInfo = 0, .LockCount = -1, .RecursionCount = 0, .OwningThread = 0, .LockSemaphore = 0, .SpinCount = spin };
}

pub fn csEnter(cs: *CriticalSection) void {
    const tid = tidNow();
    lock();
    defer unlock();
    while (cs.OwningThread != 0 and cs.OwningThread != tid) _ = c.pthread_cond_wait(&g_cv, &g_mu);
    cs.OwningThread = tid;
    cs.RecursionCount += 1;
    cs.LockCount += 1;
}

pub fn csTryEnter(cs: *CriticalSection) bool {
    const tid = tidNow();
    lock();
    defer unlock();
    if (cs.OwningThread != 0 and cs.OwningThread != tid) return false;
    cs.OwningThread = tid;
    cs.RecursionCount += 1;
    cs.LockCount += 1;
    return true;
}

pub fn csLeave(cs: *CriticalSection) void {
    lock();
    defer unlock();
    if (cs.RecursionCount <= 0) return; // unbalanced Leave: ignore, never underflow
    cs.RecursionCount -= 1;
    cs.LockCount -= 1;
    if (cs.RecursionCount == 0) {
        cs.OwningThread = 0;
        cs.LockCount = -1;
        wake();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "manual-reset event stays signaled, auto-reset is consumed (negative control)" {
    const man = createEvent(true, false, null);
    const auto = createEvent(false, false, null);
    try testing.expect(man != 0 and auto != 0 and man != auto);
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitOne(man, 0));
    try testing.expect(setEvent(man));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(man, 0));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(man, 0)); // still signaled
    try testing.expect(resetEvent(man));
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitOne(man, 0));
    try testing.expect(setEvent(auto));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(auto, 0));
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitOne(auto, 0)); // consumed
    try testing.expect(closeHandle(man) and closeHandle(auto));
    try testing.expect(!closeHandle(man)); // already closed
}

test "handles that are not ours are not ours" {
    try testing.expect(!isOurs(0x2003)); // the old constant semaphore handle
    try testing.expect(!isOurs(0x30000002)); // Steam bridge handle
    try testing.expectEqual(@as(?u32, null), waitOne(0x2003, 0));
    try testing.expect(!closeHandle(0x4001));
    try testing.expect(!setEvent(0x2001));
}

test "semaphore counts, and ReleaseSemaphore refuses to exceed the maximum" {
    const s = createSemaphore(2, 3, null);
    try testing.expect(s != 0);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(s, 0));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(s, 0));
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitOne(s, 0)); // empty
    var prev: i32 = -1;
    try testing.expect(releaseSemaphore(s, 1, &prev));
    try testing.expectEqual(@as(i32, 0), prev);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(s, 0));
    try testing.expect(releaseSemaphore(s, 3, &prev)); // 0 + 3 == max
    try testing.expectEqual(@as(i32, 0), prev);
    prev = -1;
    try testing.expect(!releaseSemaphore(s, 1, &prev)); // would be 4 > 3
    try testing.expectEqual(@as(i32, -1), prev); // untouched on failure, as under Wine
    try testing.expect(!releaseSemaphore(s, 0, null)); // zero/negative counts invalid
    try testing.expectEqual(@as(usize, 0), createSemaphore(5, 3, null)); // initial > max
    try testing.expect(closeHandle(s));
}

test "mutex is recursive for its owner and only the owner may release" {
    const m = createMutex(false, null);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(m, 0));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(m, 0)); // recursion
    try testing.expect(releaseMutex(m));
    try testing.expect(releaseMutex(m));
    try testing.expect(!releaseMutex(m)); // not owned any more
    const owned = createMutex(true, null);
    try testing.expect(releaseMutex(owned));
    try testing.expect(closeHandle(m) and closeHandle(owned));
}

fn incAndReturn42(p: ?*anyopaque) callconv(W) u32 {
    const counter: *u32 = @ptrCast(@alignCast(p.?));
    _ = @atomicRmw(u32, counter, .Add, 1, .seq_cst);
    return 42;
}

test "CreateThread runs the start routine; exit code and thread id are real" {
    var counter: u32 = 0;
    var tid: u32 = 0;
    const th = createThread(0, &incAndReturn42, &counter, 0, &tid);
    try testing.expect(th != 0);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expectEqual(@as(u32, 1), @atomicLoad(u32, &counter, .seq_cst));
    var code: u32 = 0;
    try testing.expectEqual(@as(?bool, true), getExitCode(th, &code));
    try testing.expectEqual(@as(u32, 42), code);
    try testing.expect(tid != 0 and tid != tidNow()); // a different thread
    try testing.expect(closeHandle(th));
}

const Pair = struct { a: usize, b: usize, n: u32, count: u32 };

fn pingWorker(p: ?*anyopaque) callconv(W) u32 {
    const pr: *Pair = @ptrCast(@alignCast(p.?));
    var i: u32 = 0;
    while (i < pr.n) : (i += 1) {
        _ = waitOne(pr.a, INFINITE);
        pr.count += 1;
        _ = setEvent(pr.b);
    }
    return 0;
}

test "ping-pong handshake between two threads through two auto-reset events" {
    // The pattern FalloutNV's archive reader uses: ask the worker, wait for the answer.
    var pr = Pair{ .a = createEvent(false, false, null), .b = createEvent(false, false, null), .n = 2000, .count = 0 };
    const th = createThread(0, &pingWorker, &pr, 0, null);
    try testing.expect(th != 0);
    var i: u32 = 0;
    while (i < pr.n) : (i += 1) {
        try testing.expect(setEvent(pr.a));
        try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(pr.b, 5000));
        try testing.expectEqual(i + 1, pr.count); // the worker really ran, in lockstep
    }
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expect(closeHandle(pr.a) and closeHandle(pr.b) and closeHandle(th));
}

test "wait timeout: a wait on an unsignaled event really waits, then times out" {
    const e = createEvent(true, false, null);
    var t0: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &t0);
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitOne(e, 80));
    var t1: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &t1);
    const ms = (t1.sec - t0.sec) * 1000 + @divTrunc(t1.nsec - t0.nsec, 1_000_000);
    try testing.expect(ms >= 70 and ms < 2000);
    try testing.expect(closeHandle(e));
}

test "WaitForMultipleObjects: wait-any returns the lowest signaled index, wait-all needs all" {
    const e1 = createEvent(false, false, null);
    const e2 = createEvent(false, false, null);
    const hs = [_]usize{ e1, e2 };
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitMany(&hs, false, 0));
    try testing.expect(setEvent(e2));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0 + 1), waitMany(&hs, false, 0));
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitMany(&hs, false, 0)); // e2 consumed
    try testing.expect(setEvent(e2));
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitMany(&hs, true, 0)); // e1 missing
    try testing.expect(setEvent(e1));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitMany(&hs, true, 0));
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitMany(&hs, true, 0)); // both consumed
    // Negative controls: foreign handle -> null; bad counts -> WAIT_FAILED.
    const mixed = [_]usize{ e1, 0x2003 };
    try testing.expectEqual(@as(?u32, null), waitMany(&mixed, false, 0));
    try testing.expectEqual(@as(?u32, WAIT_FAILED), waitMany(&[_]usize{}, false, 0));
    try testing.expect(closeHandle(e1) and closeHandle(e2));
}

const Counter = struct { cs: CriticalSection, value: u32, n: u32 };

fn csWorker(p: ?*anyopaque) callconv(W) u32 {
    const ct: *Counter = @ptrCast(@alignCast(p.?));
    var i: u32 = 0;
    while (i < ct.n) : (i += 1) {
        csEnter(&ct.cs);
        const v = ct.value; // deliberately not atomic: only the lock protects it
        std.atomic.spinLoopHint();
        ct.value = v + 1;
        csLeave(&ct.cs);
    }
    return 0;
}

test "critical section excludes four threads (non-atomic counter reaches the exact total)" {
    var ct = Counter{ .cs = undefined, .value = 0, .n = 20000 };
    csInit(&ct.cs, 0);
    try testing.expectEqual(@as(i32, -1), ct.cs.LockCount);
    var hs: [4]usize = undefined;
    for (&hs) |*h| {
        h.* = createThread(0, &csWorker, &ct, 0, null);
        try testing.expect(h.* != 0);
    }
    for (hs) |h| try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(h, 20000));
    try testing.expectEqual(@as(u32, 4 * 20000), ct.value);
    try testing.expectEqual(@as(i32, -1), ct.cs.LockCount); // back to free
    for (hs) |h| try testing.expect(closeHandle(h));
}

test "critical section is recursive and TryEnter refuses a foreign owner" {
    var cs: CriticalSection = undefined;
    csInit(&cs, 0);
    csEnter(&cs);
    csEnter(&cs);
    try testing.expectEqual(@as(i32, 2), cs.RecursionCount);
    try testing.expect(csTryEnter(&cs)); // same thread
    csLeave(&cs);
    csLeave(&cs);
    csLeave(&cs);
    try testing.expectEqual(@as(u32, 0), cs.OwningThread);
    csLeave(&cs); // unbalanced Leave must not underflow
    try testing.expectEqual(@as(i32, 0), cs.RecursionCount);
    const Holder = struct {
        fn run(p: ?*anyopaque) callconv(W) u32 {
            const pc: *CriticalSection = @ptrCast(@alignCast(p.?));
            return if (csTryEnter(pc)) 1 else 0;
        }
    };
    csEnter(&cs);
    const th = createThread(0, &Holder.run, &cs, 0, null);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    var code: u32 = 99;
    try testing.expectEqual(@as(?bool, true), getExitCode(th, &code));
    try testing.expectEqual(@as(u32, 0), code); // the other thread could not enter
    csLeave(&cs);
    try testing.expect(closeHandle(th));
}

test "CREATE_SUSPENDED: the thread does not run until ResumeThread" {
    var counter: u32 = 0;
    const th = createThread(0, &incAndReturn42, &counter, CREATE_SUSPENDED, null);
    try testing.expect(th != 0);
    sleepMs(60);
    try testing.expectEqual(@as(u32, 0), @atomicLoad(u32, &counter, .seq_cst)); // still parked
    var code: u32 = 0;
    try testing.expectEqual(@as(?bool, true), getExitCode(th, &code));
    try testing.expectEqual(STILL_ACTIVE, code);
    try testing.expectEqual(@as(u32, 1), resumeThread(th)); // previous suspend count
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expectEqual(@as(u32, 1), @atomicLoad(u32, &counter, .seq_cst));
    try testing.expectEqual(WAIT_FAILED, resumeThread(0x2001)); // not a thread handle
    try testing.expect(closeHandle(th));
}

fn exitsWith7(p: ?*anyopaque) callconv(W) u32 {
    _ = p;
    _ = exitCurrentThread(7);
    return 1; // not reached
}

test "ExitThread ends only that thread and records its exit code" {
    const th = createThread(0, &exitsWith7, null, 0, null);
    try testing.expect(th != 0);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    var code: u32 = 0;
    try testing.expectEqual(@as(?bool, true), getExitCode(th, &code));
    try testing.expectEqual(@as(u32, 7), code);
    try testing.expect(!exitCurrentThread(0) or true); // main thread: not ours, returns false
    try testing.expect(closeHandle(th));
}

test "named events are shared between Create calls" {
    const a = createEvent(true, false, "wins-test-named");
    const b = createEvent(true, true, "wins-test-named"); // initial ignored: existing object
    try testing.expectEqual(a, b);
    try testing.expectEqual(@as(?u32, WAIT_TIMEOUT), waitOne(a, 0)); // not signaled: first creation wins
    try testing.expect(setEvent(b));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(a, 0));
    try testing.expect(closeHandle(a)); // two references
    try testing.expect(isOurs(b));
    try testing.expect(closeHandle(b));
    try testing.expect(!isOurs(a));
}

test "wait-all on a thread handle and an event" {
    var counter: u32 = 0;
    const th = createThread(0, &incAndReturn42, &counter, 0, null);
    const ev = createEvent(true, true, null);
    const hs = [_]usize{ th, ev };
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitMany(&hs, true, 5000));
    try testing.expectEqual(@as(u32, 1), @atomicLoad(u32, &counter, .seq_cst));
    try testing.expect(closeHandle(th) and closeHandle(ev));
}
