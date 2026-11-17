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
pub const WAIT_IO_COMPLETION: u32 = 0xC0;
pub const WAIT_FAILED: u32 = 0xFFFFFFFF;
pub const INFINITE: u32 = 0xFFFFFFFF;
pub const STILL_ACTIVE: u32 = 259;
pub const CREATE_SUSPENDED: u32 = 0x4;

pub const HANDLE_BASE: usize = 0x6000;
const HANDLE_STEP: usize = 4;
const MAX_OBJECTS = 4096;
pub const MAXIMUM_WAIT_OBJECTS = 64;

pub const StartFn = *const fn (?*anyopaque) callconv(W) u32;
pub const ApcFn = *const fn (usize) callconv(W) void;
pub const Kind = enum { event, semaphore, mutex, thread };

const Apc = struct { next: ?*Apc = null, callback: ApcFn, data: usize };

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
    running: bool = false,
    exit_code: u32 = STILL_ACTIVE,
    finished: bool = false,
    suspend_count: i32 = 0,
    priority: i32 = 0,
    sig_paused: u32 = 0,
    ctx_gregs: [18]u64 = [_]u64{0} ** 18,
    start: ?StartFn = null,
    param: ?*anyopaque = null,
    stack_size: usize = 0,
    apc_head: ?*Apc = null,
    apc_tail: ?*Apc = null,
};

var g_mu: c.pthread_mutex_t = .{};
/// Wait/wake word for every object state change (replaces a pthread condition
/// variable). A waker bumps it and FUTEX_WAKEs everyone; that never blocks. A
/// pthread_cond_broadcast, by contrast, waits for earlier waiters to leave the
/// condvar, and a waiter stopped by SuspendThread (Mono's GC does that) never
/// does: the broadcaster then hangs holding g_mu and the whole process stops.
var g_epoch: u32 = 0;
/// g_mu nesting of this thread. SuspendThread's signal is deferred while it is
/// non-zero, so a suspended thread can never be holding g_mu.
threadlocal var t_lock_depth: u32 = 0;
threadlocal var t_pause_pending: bool = false;
var g_objs: [MAX_OBJECTS]?*Object = [_]?*Object{null} ** MAX_OBJECTS;

/// Called on a new thread before the guest's start routine runs, to build its
/// TEB/FS/TLS. Null in unit tests.
pub var g_thread_init: ?*const fn (*Object) void = null;

threadlocal var g_current: ?*Object = null;

fn lock() void {
    // Count first: a suspend signal that lands while we wait for or hold g_mu is deferred.
    @atomicStore(u32, &t_lock_depth, t_lock_depth + 1, .seq_cst);
    _ = c.pthread_mutex_lock(&g_mu);
}
fn unlock() void {
    _ = c.pthread_mutex_unlock(&g_mu);
    @atomicStore(u32, &t_lock_depth, t_lock_depth - 1, .seq_cst);
    if (t_lock_depth == 0 and @atomicLoad(bool, &t_pause_pending, .seq_cst)) {
        @atomicStore(bool, &t_pause_pending, false, .seq_cst);
        // Take the deferred suspension now, outside g_mu, with a real signal context.
        _ = linux.tgkill(linux.getpid(), @intCast(linux.gettid()), linux.SIG.URG);
    }
}
/// Every waiter re-checks its object after this; it never blocks the caller.
fn wake() void {
    _ = @atomicRmw(u32, &g_epoch, .Add, 1, .seq_cst);
    _ = linux.futex_3arg(&g_epoch, .{ .cmd = .WAKE, .private = true }, std.math.maxInt(i32));
}

threadlocal var t_tid: u32 = 0;

/// This thread's id. Asked once per thread: Windows reads it from the TEB,
/// so guests call GetCurrentThreadId and take critical sections in their
/// hottest paths, where a system call each time is most of the cost.
pub fn tidNow() u32 {
    if (t_tid == 0) t_tid = @intCast(linux.gettid());
    return t_tid;
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
        var apc = o.apc_head;
        while (apc) |node| {
            apc = node.next;
            std.heap.c_allocator.destroy(node);
        }
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

/// Called with g_mu held: releases it, sleeps until the next wake() (or the
/// deadline), re-takes it. Returns true when the deadline passed. Spurious
/// returns are fine: every caller loops and re-checks its condition.
fn waitCond(d: *const Deadline) bool {
    // Read under g_mu: a wake() for a change made after this read bumps the word,
    // so FUTEX_WAIT below returns at once instead of missing it.
    const seen = @atomicLoad(u32, &g_epoch, .seq_cst);
    var rel: linux.timespec = undefined;
    if (!d.infinite) {
        var now: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &now);
        var sec: i64 = @as(i64, d.abs.sec) - @as(i64, now.sec);
        var nsec: i64 = @as(i64, d.abs.nsec) - @as(i64, now.nsec);
        if (nsec < 0) {
            nsec += 1_000_000_000;
            sec -= 1;
        }
        if (sec < 0) return true;
        rel = .{ .sec = @intCast(sec), .nsec = @intCast(nsec) };
    }
    unlock();
    const rc = linux.futex_4arg(&g_epoch, .{ .cmd = .WAIT, .private = true }, seen, if (d.infinite) null else &rel);
    lock();
    return !d.infinite and linux.errno(rc) == .TIMEDOUT;
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

/// Queue a user-mode APC for a live thread object. Only the target's own
/// alertable wait removes and runs this callback.
pub fn queueUserApc(callback: ?*anyopaque, h: usize, data: usize) bool {
    const raw = callback orelse return false;
    const apc = std.heap.c_allocator.create(Apc) catch return false;
    apc.* = .{ .callback = @ptrCast(@alignCast(raw)), .data = data };
    lock();
    const o = if (h == ~@as(usize, 1)) registerCurrentLocked() else find(h);
    if (o == null or o.?.kind != .thread or o.?.finished) {
        unlock();
        std.heap.c_allocator.destroy(apc);
        return false;
    }
    const thread = o.?;
    if (thread.apc_tail) |tail| tail.next = apc else thread.apc_head = apc;
    thread.apc_tail = apc;
    wake();
    unlock();
    return true;
}

/// g_mu is held. Call guest APCs with g_mu released, draining callbacks added
/// by callbacks as well. Only callbacks belonging to the current thread run.
fn runApcsLocked() bool {
    var ran = false;
    const current = registerCurrentLocked() orelse return false;
    while (current.apc_head) |apc| {
        current.apc_head = apc.next;
        if (current.apc_head == null) current.apc_tail = null;
        unlock();
        apc.callback(apc.data);
        std.heap.c_allocator.destroy(apc);
        lock();
        ran = true;
    }
    return ran;
}

/// Alertable wait for one object. APC completion takes precedence over object
/// completion and timeout.
pub fn waitOneEx(h: usize, ms: u32, alertable: bool) ?u32 {
    lock();
    defer unlock();
    const o = find(h) orelse return null;
    const tid = tidNow();
    const d = Deadline.init(ms);
    while (true) {
        if (alertable and runApcsLocked()) return WAIT_IO_COMPLETION;
        if (signaledFor(o, tid)) {
            consume(o, tid);
            return WAIT_OBJECT_0;
        }
        if (ms == 0) return WAIT_TIMEOUT;
        if (waitCond(&d)) {
            if (alertable and runApcsLocked()) return WAIT_IO_COMPLETION;
            if (signaledFor(o, tid)) {
                consume(o, tid);
                return WAIT_OBJECT_0;
            }
            return WAIT_TIMEOUT;
        }
    }
}

pub fn waitManyEx(handles: []const usize, wait_all: bool, ms: u32, alertable: bool) ?u32 {
    if (handles.len == 0 or handles.len > MAXIMUM_WAIT_OBJECTS) return WAIT_FAILED;
    lock();
    defer unlock();
    var objs: [MAXIMUM_WAIT_OBJECTS]*Object = undefined;
    for (handles, 0..) |h, i| objs[i] = find(h) orelse return null;
    const tid = tidNow();
    const d = Deadline.init(ms);
    while (true) {
        if (alertable and runApcsLocked()) return WAIT_IO_COMPLETION;
        if (waitManyReady(objs[0..handles.len], wait_all, tid)) |result| return result;
        if (ms == 0) return WAIT_TIMEOUT;
        if (waitCond(&d)) {
            if (alertable and runApcsLocked()) return WAIT_IO_COMPLETION;
            if (waitManyReady(objs[0..handles.len], wait_all, tid)) |result| return result;
            return WAIT_TIMEOUT;
        }
    }
}

fn waitManyReady(objs: []*Object, wait_all: bool, tid: u32) ?u32 {
    if (wait_all) {
        for (objs) |o| if (!signaledFor(o, tid)) return null;
        for (objs) |o| consume(o, tid);
        return WAIT_OBJECT_0;
    }
    for (objs, 0..) |o, i| if (signaledFor(o, tid)) {
        consume(o, tid);
        return WAIT_OBJECT_0 + @as(u32, @intCast(i));
    };
    return null;
}

/// Alertable SleepEx wakes on queued APC delivery. Non-alertable sleep ignores
/// the APC queue and returns zero once the interval elapses.
pub fn sleepEx(ms: u32, alertable: bool) u32 {
    if (!alertable) {
        if (ms == INFINITE) {
            while (true) sleepMs(60_000);
        }
        sleepMs(ms);
        return 0;
    }
    lock();
    defer unlock();
    const d = Deadline.init(ms);
    while (true) {
        if (runApcsLocked()) return WAIT_IO_COMPLETION;
        if (ms == 0) return 0;
        if (waitCond(&d)) {
            if (runApcsLocked()) return WAIT_IO_COMPLETION;
            return 0;
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

/// Win32 thread priority state. Priority classes are advisory in this runtime;
/// GetThreadPriority returns exactly the last accepted value.
pub fn setThreadPriority(h: usize, priority: i32) bool {
    if (priority < -15 or priority > 15) return false;
    lock(); defer unlock();
    const o = if (h == ~@as(usize, 1)) registerCurrentLocked() else find(h);
    const thread = o orelse return false;
    if (thread.kind != .thread) return false;
    thread.priority = priority;
    return true;
}

pub fn getThreadPriority(h: usize) ?i32 {
    lock(); defer unlock();
    const o = if (h == ~@as(usize, 1)) registerCurrentLocked() else find(h);
    const thread = o orelse return null;
    if (thread.kind != .thread) return null;
    return thread.priority;
}

/// Returns the host tid for a validated WINS thread handle, including the
/// current-thread pseudo handle. No lookup result means the handle is invalid.
pub fn threadTid(h: usize) ?u32 {
    if (h == ~@as(usize, 1)) return tidNow();
    lock(); defer unlock();
    const o = find(h) orelse return null;
    if (o.kind != .thread or !o.tid_ready) return null;
    return o.tid;
}

var g_sig_init = std.atomic.Value(u32).init(0);

fn onSuspendSignal(_: linux.SIG, _: *const linux.siginfo_t, ctx_raw: ?*anyopaque) callconv(.c) void {
    const o = g_current orelse return;
    if (@atomicLoad(u32, &t_lock_depth, .seq_cst) != 0) {
        // Inside WINS with (or about to take) g_mu: pausing here would freeze
        // every other thread. unlock() re-raises this signal once g_mu is free.
        @atomicStore(bool, &t_pause_pending, true, .seq_cst);
        return;
    }
    // A deferred pause can arrive after the suspender already gave up and resumed us.
    if (@atomicLoad(i32, &o.suspend_count, .seq_cst) <= 0) return;
    if (ctx_raw) |raw| {
        const g: [*]const u64 = @ptrFromInt(@intFromPtr(raw) + 40); // ucontext.uc_mcontext.gregs
        for (0..18) |i| o.ctx_gregs[i] = g[i];
    }
    @atomicStore(u32, &o.sig_paused, 1, .seq_cst);
    // ResumeThread may have run between the check above and the store: it cleared
    // sig_paused before we set it, so nobody would ever wake us. Re-check.
    if (@atomicLoad(i32, &o.suspend_count, .seq_cst) <= 0) {
        @atomicStore(u32, &o.sig_paused, 0, .seq_cst);
        return;
    }
    _ = linux.syscall3(.futex, @intFromPtr(&o.sig_paused), 1, 1);
    while (@atomicLoad(u32, &o.sig_paused, .acquire) == 1) {
        _ = linux.syscall4(.futex, @intFromPtr(&o.sig_paused), 0, 1, 0);
    }
}

fn ensureSuspendHandler() void {
    if (g_sig_init.load(.acquire) == 2) return;
    if (g_sig_init.cmpxchgStrong(0, 1, .acq_rel, .monotonic) == null) {
        var sa: linux.Sigaction = .{
            .handler = .{ .sigaction = onSuspendSignal },
            .mask = linux.sigemptyset(),
            .flags = linux.SA.SIGINFO | linux.SA.RESTART,
        };
        _ = linux.sigaction(linux.SIG.URG, &sa, null);
        g_sig_init.store(2, .release);
    } else {
        while (g_sig_init.load(.acquire) != 2) std.atomic.spinLoopHint();
    }
}

fn registerCurrentLocked() ?*Object {
    if (g_current) |o| return o;
    const tid = tidNow();
    for (g_objs) |maybe| {
        if (maybe) |o| {
            if (o.kind == .thread and o.tid == tid and !o.finished) {
                g_current = o;
                return o;
            }
        }
    }
    const o = alloc(.thread, null) orelse return null;
    o.refs = 2; // stays alive in table while thread lives + handle
    o.tid = tid;
    o.tid_ready = true;
    o.running = true;
    g_current = o;
    return o;
}

pub fn dupCurrentThread() usize {
    ensureSuspendHandler();
    lock();
    defer unlock();
    const o = registerCurrentLocked() orelse return 0;
    o.refs += 1;
    return handleOf(o);
}

pub fn dupHandle(h: usize) usize {
    lock();
    defer unlock();
    const o = find(h) orelse return 0;
    o.refs += 1;
    return handleOf(o);
}

pub fn openThreadByTid(tid: u32) usize {
    ensureSuspendHandler();
    lock();
    defer unlock();
    for (g_objs) |maybe| {
        if (maybe) |o| {
            if (o.kind == .thread and o.tid == tid and !o.finished) {
                o.refs += 1;
                return handleOf(o);
            }
        }
    }
    return 0;
}

fn finish(o: *Object, code: u32) void {
    lock();
    o.exit_code = code;
    @atomicStore(bool, &o.finished, true, .release);
    wake();
    release(o); // the reference the running thread held
    unlock();
}

fn trampoline(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const o: *Object = @ptrCast(@alignCast(arg.?));
    g_current = o;
    ensureSuspendHandler();
    if (g_thread_init) |init_fn| init_fn(o);
    lock();
    o.tid = tidNow();
    o.tid_ready = true;
    wake();
    // CREATE_SUSPENDED: wait for ResumeThread.
    while (o.suspend_count > 0) _ = waitCond(&Deadline.init(INFINITE));
    o.running = true;
    unlock();
    const code = o.start.?(o.param);
    finish(o, code);
    return null;
}

/// CreateThread. Returns the handle (0 on failure) and, through `tid_out`, the id
/// the new thread will report from GetCurrentThreadId.
pub fn createThread(stack_size: usize, start: StartFn, param: ?*anyopaque, flags: u32, tid_out: ?*u32) usize {
    ensureSuspendHandler();
    const alloc_stack = @max(stack_size, 4 * 1024 * 1024);
    lock();
    const o = alloc(.thread, null) orelse {
        unlock();
        return 0;
    };
    o.refs = 2; // the handle and the running thread
    o.start = start;
    o.param = param;
    o.stack_size = alloc_stack;
    o.suspend_count = if (flags & CREATE_SUSPENDED != 0) 1 else 0;
    const h = handleOf(o);
    unlock();

    var attr: c.pthread_attr_t = undefined;
    _ = c.pthread_attr_init(&attr);
    // Reserve at least 4 MiB per guest worker thread so Mono/Unity stacks never clip TEB.StackLimit.
    _ = c.pthread_attr_setstacksize(&attr, alloc_stack);
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
    while (!o.tid_ready) _ = waitCond(&Deadline.init(INFINITE));
    if (tid_out) |t| t.* = o.tid;
    unlock();
    return h;
}

/// ResumeThread: returns the previous suspend count, or 0xFFFFFFFF for a bad handle.
pub fn resumeThread(h: usize) u32 {
    lock();
    defer unlock();
    const o = if (h == ~@as(usize, 1)) registerCurrentLocked() else find(h);
    if (o == null or o.?.kind != .thread) return WAIT_FAILED;
    const obj = o.?;
    const prev: u32 = @intCast(obj.suspend_count);
    if (obj.suspend_count > 0) @atomicStore(i32, &obj.suspend_count, obj.suspend_count - 1, .seq_cst);
    if (obj.suspend_count == 0) {
        @atomicStore(u32, &obj.sig_paused, 0, .release);
        _ = linux.syscall3(.futex, @intFromPtr(&obj.sig_paused), 1, 1);
        wake();
    }
    return prev;
}

/// SuspendThread: pauses a live thread via SIGURG and captures its registers/RSP.
pub fn suspendThread(h: usize) u32 {
    ensureSuspendHandler();
    lock();
    const o = (if (h == ~@as(usize, 1)) registerCurrentLocked() else find(h)) orelse {
        unlock();
        return WAIT_FAILED;
    };
    if (o.kind != .thread) {
        unlock();
        return WAIT_FAILED;
    }
    const prev: u32 = @intCast(o.suspend_count);
    @atomicStore(i32, &o.suspend_count, o.suspend_count + 1, .seq_cst);
    const my_tid = tidNow();
    const should_pause = (prev == 0 and o.running and !o.finished and o.tid != 0 and o.tid != my_tid);
    const target_tid = o.tid;
    if (should_pause) {
        o.refs += 1;
        @atomicStore(u32, &o.sig_paused, 0, .release);
    }
    unlock();

    if (should_pause) {
        _ = linux.tgkill(@intCast(linux.getpid()), @intCast(target_tid), linux.SIG.URG);
        var tries: u32 = 0;
        while (@atomicLoad(u32, &o.sig_paused, .acquire) == 0 and !@atomicLoad(bool, &o.finished, .acquire) and tries < 20) : (tries += 1) {
            var ts: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
            _ = linux.syscall4(.futex, @intFromPtr(&o.sig_paused), 0, 0, @intFromPtr(&ts));
        }
        lock();
        release(o);
        unlock();
    }
    return prev;
}

/// GetThreadContext: fills a Win64 CONTEXT struct (1232 bytes) from the thread's
/// captured signal state (when suspended) or current frame (when querying self).
pub fn getThreadContext(h: usize, lp_ctx: ?*anyopaque) bool {
    const out_ptr: [*]u8 = @ptrCast(lp_ctx orelse return false);
    lock();
    const o = (if (h == ~@as(usize, 1)) registerCurrentLocked() else find(h)) orelse {
        unlock();
        return false;
    };
    if (o.kind != .thread) {
        unlock();
        return false;
    }
    const is_self = (o.tid == tidNow());
    const gregs = o.ctx_gregs;
    const paused = (@atomicLoad(u32, &o.sig_paused, .acquire) == 1);
    unlock();

    const existing_flags = std.mem.readInt(u32, out_ptr[0x30..][0..4], .little);
    std.mem.writeInt(u32, out_ptr[0x30..][0..4], existing_flags | 0x10000F, .little);
    if (is_self and !paused) {
        const sp = @frameAddress();
        std.mem.writeInt(u64, out_ptr[0x78 + 4 * 8 ..][0..8], sp, .little); // Rsp
        std.mem.writeInt(u64, out_ptr[0x78 + 5 * 8 ..][0..8], sp, .little); // Rbp
        std.mem.writeInt(u64, out_ptr[0xf8..][0..8], @returnAddress(), .little); // Rip
        return true;
    }
    std.mem.writeInt(u32, out_ptr[0x44..][0..4], @truncate(gregs[17]), .little); // EFlags
    const map_from_greg = [16]usize{ 13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7 };
    for (0..16) |wreg| {
        std.mem.writeInt(u64, out_ptr[0x78 + wreg * 8 ..][0..8], gregs[map_from_greg[wreg]], .little);
    }
    std.mem.writeInt(u64, out_ptr[0xf8..][0..8], gregs[16], .little); // Rip
    return true;
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

// A critical section is its own lock: OwningThread is claimed with a
// compare-and-swap, so the uncontended Enter/Leave pair makes no system call
// and touches nothing shared with other sections. (Before, every Enter and
// Leave took the one module-wide mutex and every release woke every waiter in
// the process; FalloutNV's main thread spent most of an exterior frame there.)
// A thread that finds the section taken looks again for a moment, then sleeps
// on OwningThread; LockSemaphore counts the sleepers so Leave knows to wake one.

fn csOwner(cs: *CriticalSection) *std.atomic.Value(u32) {
    return @ptrCast(&cs.OwningThread);
}
fn csWaiters(cs: *CriticalSection) *std.atomic.Value(u32) {
    return @ptrCast(&cs.LockSemaphore);
}

const CS_SPINS: u32 = 2000;

pub fn csEnter(cs: *CriticalSection) void {
    const tid = tidNow();
    const owner = csOwner(cs);
    if (owner.load(.monotonic) == tid) {
        cs.RecursionCount += 1;
        cs.LockCount += 1;
        return;
    }
    var spins: u32 = 0;
    while (true) {
        if (owner.cmpxchgWeak(0, tid, .acquire, .monotonic) == null) break;
        if (spins < CS_SPINS) {
            spins += 1;
            std.atomic.spinLoopHint();
            continue;
        }
        const waiters = csWaiters(cs);
        _ = waiters.fetchAdd(1, .seq_cst);
        const seen = owner.load(.seq_cst);
        if (seen != 0) _ = linux.syscall4(.futex, @intFromPtr(owner), 0, seen, 0); // FUTEX_WAIT
        _ = waiters.fetchSub(1, .seq_cst);
    }
    cs.RecursionCount = 1;
    cs.LockCount = 0;
}

pub fn csTryEnter(cs: *CriticalSection) bool {
    const tid = tidNow();
    const owner = csOwner(cs);
    if (owner.load(.monotonic) == tid) {
        cs.RecursionCount += 1;
        cs.LockCount += 1;
        return true;
    }
    if (owner.cmpxchgStrong(0, tid, .acquire, .monotonic) != null) return false;
    cs.RecursionCount = 1;
    cs.LockCount = 0;
    return true;
}

pub fn csLeave(cs: *CriticalSection) void {
    const owner = csOwner(cs);
    // Only the owner may release; an unbalanced or foreign Leave is ignored.
    if (owner.load(.monotonic) != tidNow() or cs.RecursionCount <= 0) return;
    cs.RecursionCount -= 1;
    if (cs.RecursionCount > 0) {
        cs.LockCount -= 1;
        return;
    }
    cs.LockCount = -1;
    owner.store(0, .seq_cst);
    if (csWaiters(cs).load(.seq_cst) != 0) _ = linux.syscall3(.futex, @intFromPtr(owner), 1, 1); // FUTEX_WAKE one
}

test "a critical section excludes other threads and is recursive for its owner" {
    const Ctx = struct {
        cs: CriticalSection = undefined,
        counter: u64 = 0,
        fn work(self: *@This()) void {
            var i: u32 = 0;
            while (i < 200_000) : (i += 1) {
                csEnter(&self.cs);
                csEnter(&self.cs); // recursion
                self.counter += 1; // not atomic: only correct under the lock
                csLeave(&self.cs);
                csLeave(&self.cs);
            }
        }
    };
    var ctx: Ctx = .{};
    csInit(&ctx.cs, 0);
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Ctx.work, .{&ctx});
    for (threads) |t| t.join();
    try testing.expectEqual(@as(u64, 800_000), ctx.counter);
    try testing.expectEqual(@as(i32, -1), ctx.cs.LockCount);
    try testing.expectEqual(@as(u32, 0), ctx.cs.OwningThread);
    try testing.expect(csTryEnter(&ctx.cs));
    csLeave(&ctx.cs);
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

test "thread priority validates handles and preserves the configured value" {
    const pseudo = ~@as(usize, 1);
    try testing.expect(setThreadPriority(pseudo, 3));
    try testing.expectEqual(@as(?i32, 3), getThreadPriority(pseudo));
    try testing.expect(!setThreadPriority(0x1234, 2));
    try testing.expectEqual(@as(?i32, null), getThreadPriority(0x1234));
    try testing.expect(!setThreadPriority(pseudo, 16));
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

const SuspendProbe = struct { go: usize, counter: u32 = 0, stop: u32 = 0, other: usize = 0 };

fn waitGoThenCount(p: ?*anyopaque) callconv(W) u32 {
    const sp: *SuspendProbe = @ptrCast(@alignCast(p.?));
    _ = waitOne(sp.go, INFINITE);
    _ = @atomicRmw(u32, &sp.counter, .Add, 1, .seq_cst);
    return 0;
}

test "SetEvent does not block while a waiter is suspended (Mono GC suspend pattern)" {
    // Mono's GC suspends threads that may be blocked in a wait, then signals
    // objects and resumes them. With a pthread condvar the broadcast waited for
    // the suspended waiter and the process hung holding the global lock.
    var sp: SuspendProbe = .{ .go = createEvent(false, false, null) };
    const th = createThread(0, &waitGoThenCount, &sp, 0, null);
    try testing.expect(th != 0);
    sleepMs(80); // the thread is now inside waitOne
    try testing.expectEqual(@as(u32, 0), suspendThread(th));
    var t0: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &t0);
    try testing.expect(setEvent(sp.go)); // must return at once
    const other = createEvent(true, false, null);
    try testing.expect(setEvent(other)); // any other wake() as well
    var t1: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &t1);
    try testing.expect(t1.sec - t0.sec < 1);
    sleepMs(100);
    try testing.expectEqual(@as(u32, 0), @atomicLoad(u32, &sp.counter, .seq_cst)); // still suspended
    try testing.expectEqual(@as(u32, 1), resumeThread(th));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expectEqual(@as(u32, 1), @atomicLoad(u32, &sp.counter, .seq_cst));
    try testing.expect(closeHandle(th));
    try testing.expect(closeHandle(other));
    try testing.expect(closeHandle(sp.go));
}

fn churnLock(p: ?*anyopaque) callconv(W) u32 {
    const sp: *SuspendProbe = @ptrCast(@alignCast(p.?));
    while (@atomicLoad(u32, &sp.stop, .seq_cst) == 0) {
        _ = setEvent(sp.other);
        _ = resetEvent(sp.other);
        _ = waitOne(sp.other, 0);
        _ = @atomicRmw(u32, &sp.counter, .Add, 1, .seq_cst);
    }
    return 0;
}

test "suspending a thread that keeps taking the global lock never freezes the others" {
    var sp: SuspendProbe = .{ .go = 0, .other = createEvent(true, false, null) };
    const th = createThread(0, &churnLock, &sp, 0, null);
    try testing.expect(th != 0);
    sleepMs(10); // give the worker a scheduling turn before the rapid suspend loop
    const ev = createEvent(false, false, null);
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        _ = suspendThread(th);
        // With the thread paused, the lock must be free for everyone else.
        try testing.expect(setEvent(ev));
        try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(ev, 2000));
        _ = resumeThread(th);
    }
    @atomicStore(u32, &sp.stop, 1, .seq_cst);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expect(@atomicLoad(u32, &sp.counter, .seq_cst) > 0);
    try testing.expect(closeHandle(th));
    try testing.expect(closeHandle(ev));
    try testing.expect(closeHandle(sp.other));
}

const ApcTestState = struct {
    ready: u32 = 0,
    ran: u32 = 0,
    callback_tid: u32 = 0,
    worker_tid: u32 = 0,
    ran_after_nonalert: u32 = 99,
    wait_result: u32 = WAIT_FAILED,
    event: usize,
    event2: usize = 0,
    alertable: bool,
};

fn apcTestCallback(raw: usize) callconv(W) void {
    const state: *ApcTestState = @ptrFromInt(raw);
    state.callback_tid = tidNow();
    _ = @atomicRmw(u32, &state.ran, .Add, 1, .seq_cst);
}

fn apcWaitWorker(raw: ?*anyopaque) callconv(W) u32 {
    const state: *ApcTestState = @ptrCast(@alignCast(raw.?));
    state.worker_tid = tidNow();
    @atomicStore(u32, &state.ready, 1, .seq_cst);
    state.wait_result = waitOneEx(state.event, if (state.alertable) 5000 else 50, state.alertable) orelse WAIT_FAILED;
    if (!state.alertable) {
        state.ran_after_nonalert = @atomicLoad(u32, &state.ran, .seq_cst);
        state.wait_result = waitOneEx(state.event, 5000, true) orelse WAIT_FAILED;
    }
    return 0;
}

fn apcWaitManyWorker(raw: ?*anyopaque) callconv(W) u32 {
    const state: *ApcTestState = @ptrCast(@alignCast(raw.?));
    state.worker_tid = tidNow();
    @atomicStore(u32, &state.ready, 1, .seq_cst);
    const handles = [_]usize{ state.event, state.event2 };
    state.wait_result = waitManyEx(&handles, false, 5000, true) orelse WAIT_FAILED;
    return 0;
}

test "APC queued to a thread in an alertable wait runs there and returns WAIT_IO_COMPLETION" {
    const event = createEvent(false, false, null);
    var state = ApcTestState{ .event = event, .alertable = true };
    const th = createThread(0, &apcWaitWorker, &state, 0, null);
    try testing.expect(th != 0);
    while (@atomicLoad(u32, &state.ready, .seq_cst) == 0) std.atomic.spinLoopHint();
    sleepMs(10); // let the target enter its alertable wait before delivery
    const target_tid = state.worker_tid;
    try testing.expect(target_tid != 0);
    try testing.expect(queueUserApc(@constCast(@ptrCast(&apcTestCallback)), th, @intFromPtr(&state)));
    try testing.expectEqual(@as(u32, 0), @atomicLoad(u32, &state.ran, .seq_cst));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expectEqual(WAIT_IO_COMPLETION, state.wait_result);
    try testing.expectEqual(@as(u32, 1), state.ran);
    try testing.expectEqual(target_tid, state.callback_tid);
    try testing.expect(closeHandle(th) and closeHandle(event));
}

test "APC queued during a non-alertable wait waits for the next alertable wait" {
    const event = createEvent(false, false, null);
    var state = ApcTestState{ .event = event, .alertable = false };
    const th = createThread(0, &apcWaitWorker, &state, 0, null);
    try testing.expect(th != 0);
    while (@atomicLoad(u32, &state.ready, .seq_cst) == 0) std.atomic.spinLoopHint();
    sleepMs(10); // ensure this APC arrives while the target is blocked non-alertably
    try testing.expect(queueUserApc(@constCast(@ptrCast(&apcTestCallback)), th, @intFromPtr(&state)));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expectEqual(WAIT_IO_COMPLETION, state.wait_result);
    try testing.expectEqual(@as(u32, 1), state.ran);
    try testing.expectEqual(state.worker_tid, state.callback_tid);
    try testing.expect(closeHandle(th) and closeHandle(event));
}

test "WaitForMultipleObjectsEx alertable wakes for and dispatches an APC" {
    const event1 = createEvent(false, false, null);
    const event2 = createEvent(false, false, null);
    var state = ApcTestState{ .event = event1, .event2 = event2, .alertable = true };
    const th = createThread(0, &apcWaitManyWorker, &state, 0, null);
    try testing.expect(th != 0);
    while (@atomicLoad(u32, &state.ready, .seq_cst) == 0) std.atomic.spinLoopHint();
    sleepMs(10);
    try testing.expect(queueUserApc(@constCast(@ptrCast(&apcTestCallback)), th, @intFromPtr(&state)));
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expectEqual(WAIT_IO_COMPLETION, state.wait_result);
    try testing.expectEqual(@as(u32, 1), state.ran);
    try testing.expectEqual(state.worker_tid, state.callback_tid);
    try testing.expect(closeHandle(th) and closeHandle(event1) and closeHandle(event2));
}

const SleepQueue = struct { target: usize, state: *ApcTestState };
fn queueSleepApc(raw: ?*anyopaque) callconv(W) u32 {
    const q: *SleepQueue = @ptrCast(@alignCast(raw.?));
    sleepMs(20);
    _ = queueUserApc(@constCast(@ptrCast(&apcTestCallback)), q.target, @intFromPtr(q.state));
    return 0;
}

test "SleepEx alertable returns WAIT_IO_COMPLETION early on a queued APC" {
    const current = dupCurrentThread();
    var state = ApcTestState{ .event = 0, .alertable = true };
    var q = SleepQueue{ .target = current, .state = &state };
    const th = createThread(0, &queueSleepApc, &q, 0, null);
    try testing.expect(th != 0);
    try testing.expectEqual(WAIT_IO_COMPLETION, sleepEx(5000, true));
    try testing.expectEqual(@as(u32, 1), state.ran);
    try testing.expectEqual(tidNow(), state.callback_tid);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expect(closeHandle(th) and closeHandle(current));
}

test "QueueUserAPC rejects a thread that has already finished" {
    var counter: u32 = 0;
    const th = createThread(0, &incAndReturn42, &counter, 0, null);
    try testing.expect(th != 0);
    try testing.expectEqual(@as(?u32, WAIT_OBJECT_0), waitOne(th, 5000));
    try testing.expect(!queueUserApc(@constCast(@ptrCast(&apcTestCallback)), th, 0));
    try testing.expectEqual(@as(u32, 1), @atomicLoad(u32, &counter, .seq_cst));
    try testing.expect(closeHandle(th));
}
