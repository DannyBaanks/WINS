const std = @import("std");
const trace = @import("../runtime/trace.zig");
const objc = @import("objc.zig");

extern "c" fn calloc(nmemb: usize, size: usize) ?*anyopaque;
extern "c" fn malloc(size: usize) ?*anyopaque;
extern "c" fn memcpy(dst: *anyopaque, src: *const anyopaque, n: usize) *anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;
extern "c" fn clock_gettime(clk_id: c_int, tp: *std.c.timespec) c_int;
extern "c" fn nanosleep(req: *const std.c.timespec, rem: ?*std.c.timespec) c_int;

extern "c" fn pthread_create(thread: *usize, attr: ?*const anyopaque, start_routine: *const anyopaque, arg: ?*anyopaque) c_int;
extern "c" fn pthread_detach(thread: usize) c_int;
extern "c" fn pthread_join(thread: usize, retval: ?*?*anyopaque) c_int;
extern "c" fn pthread_mutex_init(mutex: *anyopaque, attr: ?*const anyopaque) c_int;
extern "c" fn pthread_mutex_lock(mutex: *anyopaque) c_int;
extern "c" fn pthread_mutex_unlock(mutex: *anyopaque) c_int;
extern "c" fn pthread_mutex_destroy(mutex: *anyopaque) c_int;
extern "c" fn pthread_cond_init(cond: *anyopaque, attr: ?*const anyopaque) c_int;
extern "c" fn pthread_cond_wait(cond: *anyopaque, mutex: *anyopaque) c_int;
extern "c" fn pthread_cond_timedwait(cond: *anyopaque, mutex: *anyopaque, abstime: *const std.c.timespec) c_int;
extern "c" fn pthread_cond_signal(cond: *anyopaque) c_int;
extern "c" fn pthread_cond_broadcast(cond: *anyopaque) c_int;
extern "c" fn pthread_cond_destroy(cond: *anyopaque) c_int;

pub const DISPATCH_TIME_NOW: u64 = 0;
pub const DISPATCH_TIME_FOREVER: u64 = ~@as(u64, 0);

// ============================================================================
// Clang / Darwin Blocks ABI
// ============================================================================

pub const BlockDescriptor = extern struct {
    reserved: usize,
    size: usize,
    copy_helper: ?*const fn (*anyopaque, *const anyopaque) callconv(.c) void = null,
    dispose_helper: ?*const fn (*anyopaque) callconv(.c) void = null,
};

pub const BlockLiteral = extern struct {
    isa: usize,
    flags: c_int,
    reserved: c_int,
    invoke: *const fn (*anyopaque) callconv(.c) void,
    descriptor: ?*const BlockDescriptor,
};

const BLOCK_IS_NOESCAPE: c_int = 1 << 23;
const BLOCK_HAS_COPY_DISPOSE: c_int = 1 << 25;
const BLOCK_IS_GLOBAL: c_int = 1 << 28;
const BLOCK_NEEDS_FREE: c_int = 1 << 24;

pub var NSConcreteStackBlock: [32]usize = .{0} ** 32;
pub var NSConcreteGlobalBlock: [32]usize = .{0} ** 32;
pub var NSConcreteMallocBlock: [32]usize = .{0} ** 32;

pub fn shim_Block_copy(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (trace.active_tracer) |t| t.recordExternalCall("__Block_copy");
    const ptr = arg orelse return null;
    const blk: *BlockLiteral = @ptrCast(@alignCast(ptr));
    if ((blk.flags & BLOCK_IS_GLOBAL) != 0) return ptr;
    if ((blk.flags & BLOCK_NEEDS_FREE) != 0) {
        // Already heap-allocated; bump refcount in low bits (simplified: keep alive)
        return ptr;
    }
    const size: usize = if (blk.descriptor) |d| @max(d.size, @sizeOf(BlockLiteral)) else @sizeOf(BlockLiteral);
    const copy = malloc(size) orelse return null;
    _ = memcpy(copy, ptr, size);
    const copy_blk: *BlockLiteral = @ptrCast(@alignCast(copy));
    copy_blk.isa = @intFromPtr(&NSConcreteMallocBlock);
    copy_blk.flags = (blk.flags & ~BLOCK_IS_NOESCAPE) | BLOCK_NEEDS_FREE | 2;
    if ((blk.flags & BLOCK_HAS_COPY_DISPOSE) != 0) {
        if (blk.descriptor) |d| {
            if (d.copy_helper) |helper| helper(copy, ptr);
        }
    }
    return copy;
}

pub fn shim_Block_release(arg: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__Block_release");
    const ptr = arg orelse return;
    const blk: *BlockLiteral = @ptrCast(@alignCast(ptr));
    if ((blk.flags & BLOCK_IS_GLOBAL) != 0) return;
    if ((blk.flags & BLOCK_NEEDS_FREE) == 0) return;
    if ((blk.flags & BLOCK_HAS_COPY_DISPOSE) != 0) {
        if (blk.descriptor) |d| {
            if (d.dispose_helper) |helper| helper(ptr);
        }
    }
    free(ptr);
}

const BlockByref = extern struct {
    isa: usize,
    forwarding: *BlockByref,
    flags: c_int,
    size: c_int,
};

const BLOCK_FIELD_IS_OBJECT: c_int = 3;
const BLOCK_FIELD_IS_BLOCK: c_int = 7;
const BLOCK_FIELD_IS_BYREF: c_int = 8;
const BLOCK_BYREF_NEEDS_FREE: c_int = 1 << 24;

pub fn shim_Block_object_assign(dest: *?*anyopaque, src: ?*anyopaque, flags: c_int) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__Block_object_assign");
    const kind = flags & 0x1f;
    if (kind == BLOCK_FIELD_IS_BYREF) {
        const s = src orelse return;
        var byref: *BlockByref = @ptrCast(@alignCast(s));
        byref = byref.forwarding;
        if ((byref.flags & BLOCK_BYREF_NEEDS_FREE) == 0) {
            const sz: usize = @intCast(@max(byref.size, @as(c_int, @sizeOf(BlockByref))));
            const copy_raw = malloc(sz) orelse return;
            _ = memcpy(copy_raw, @ptrCast(byref), sz);
            const copy: *BlockByref = @ptrCast(@alignCast(copy_raw));
            copy.forwarding = copy;
            copy.flags = (byref.flags & ~@as(c_int, 0xffff)) | BLOCK_BYREF_NEEDS_FREE | 2;
            byref.forwarding = copy;
            dest.* = copy_raw;
        } else {
            dest.* = @ptrCast(byref);
        }
    } else if (kind == BLOCK_FIELD_IS_BLOCK) {
        dest.* = shim_Block_copy(src);
    } else if (kind == BLOCK_FIELD_IS_OBJECT) {
        dest.* = objc.shim_objc_retain(src);
    }
}

pub fn shim_Block_object_dispose(obj: ?*anyopaque, flags: c_int) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("__Block_object_dispose");
    const ptr = obj orelse return;
    const kind = flags & 0x1f;
    if (kind == BLOCK_FIELD_IS_BYREF) {
        var byref: *BlockByref = @ptrCast(@alignCast(ptr));
        byref = byref.forwarding;
        if ((byref.flags & BLOCK_BYREF_NEEDS_FREE) != 0) {
            // Keep alive if still referenced by original stack frame/other blocks
        }
    } else if (kind == BLOCK_FIELD_IS_BLOCK) {
        shim_Block_release(ptr);
    } else if (kind == BLOCK_FIELD_IS_OBJECT) {
        objc.shim_objc_release(ptr);
    }
}

fn invokeAndReleaseBlock(blk_ptr: ?*anyopaque) callconv(.c) void {
    const ptr = blk_ptr orelse return;
    const blk: *BlockLiteral = @ptrCast(@alignCast(ptr));
    blk.invoke(ptr);
    shim_Block_release(ptr);
}

// ============================================================================
// Dispatch Queue
// ============================================================================

const MutexBuf = [64]u8;
const CondBuf = [64]u8;

const WorkItem = struct {
    func: *const fn (?*anyopaque) callconv(.c) void,
    context: ?*anyopaque,
    done_flag: ?*bool = null,
    done_cond: ?*CondBuf = null,
    next: ?*WorkItem = null,
};

pub const DispatchQueue = extern struct {
    magic: u32,
    is_concurrent: bool,
    is_static: bool,
    refcount: usize,
    stopped: bool = false,
    worker_started: bool = false,
    worker_tid: usize = 0,
    label: [64]u8,
    mutex: MutexBuf align(8),
    cond: CondBuf align(8),
    head: ?*WorkItem,
    tail: ?*WorkItem,
};

const QUEUE_MAGIC: u32 = 0x4451_5545; // 'DQUE'
pub var dispatch_queue_attr_concurrent: usize = 1;

pub var dispatch_main_q: DispatchQueue = .{
    .magic = QUEUE_MAGIC,
    .is_concurrent = false,
    .is_static = true,
    .refcount = 1,
    .stopped = false,
    .worker_started = false,
    .worker_tid = 0,
    .label = initLabel("com.apple.main-thread"),
    .mutex = .{0} ** 64,
    .cond = .{0} ** 64,
    .head = null,
    .tail = null,
};

var dispatch_global_q: DispatchQueue = .{
    .magic = QUEUE_MAGIC,
    .is_concurrent = true,
    .is_static = true,
    .refcount = 1,
    .stopped = false,
    .worker_started = false,
    .worker_tid = 0,
    .label = initLabel("com.apple.root.default-qos"),
    .mutex = .{0} ** 64,
    .cond = .{0} ** 64,
    .head = null,
    .tail = null,
};

var static_queues_init: bool = false;

fn initLabel(src: []const u8) [64]u8 {
    var buf: [64]u8 = .{0} ** 64;
    const n = @min(src.len, 63);
    @memcpy(buf[0..n], src[0..n]);
    return buf;
}

fn ensureStaticQueues() void {
    if (static_queues_init) return;
    static_queues_init = true;
    _ = pthread_mutex_init(&dispatch_main_q.mutex, null);
    _ = pthread_cond_init(&dispatch_main_q.cond, null);
    _ = pthread_mutex_init(&dispatch_global_q.mutex, null);
    _ = pthread_cond_init(&dispatch_global_q.cond, null);
}

fn serialWorkerThread(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const q: *DispatchQueue = @ptrCast(@alignCast(arg.?));
    while (true) {
        _ = pthread_mutex_lock(&q.mutex);
        while (q.head == null and !q.stopped) {
            _ = pthread_cond_wait(&q.cond, &q.mutex);
        }
        if (q.head == null and q.stopped) {
            _ = pthread_mutex_unlock(&q.mutex);
            break;
        }
        const item = q.head.?;
        q.head = item.next;
        if (q.head == null) q.tail = null;
        _ = pthread_mutex_unlock(&q.mutex);

        item.func(item.context);

        if (item.done_flag) |flag| {
            _ = pthread_mutex_lock(&q.mutex);
            flag.* = true;
            if (item.done_cond) |dc| _ = pthread_cond_broadcast(dc);
            _ = pthread_mutex_unlock(&q.mutex);
        } else {
            free(@ptrCast(item));
        }
    }
    return null;
}

const ConcurrentArg = struct {
    func: *const fn (?*anyopaque) callconv(.c) void,
    context: ?*anyopaque,
};

fn concurrentWorkerThread(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const ca: *ConcurrentArg = @ptrCast(@alignCast(arg.?));
    const func = ca.func;
    const ctx = ca.context;
    free(@ptrCast(ca));
    func(ctx);
    return null;
}

pub fn shim_dispatch_get_global_queue(identifier: isize, flags: usize) callconv(.c) ?*DispatchQueue {
    _ = identifier;
    _ = flags;
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_get_global_queue");
    ensureStaticQueues();
    return &dispatch_global_q;
}

pub fn shim_dispatch_queue_create(label: ?[*:0]const u8, attr: ?*anyopaque) callconv(.c) ?*DispatchQueue {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_queue_create");
    ensureStaticQueues();
    const raw = calloc(1, @sizeOf(DispatchQueue)) orelse return null;
    const q: *DispatchQueue = @ptrCast(@alignCast(raw));
    q.magic = QUEUE_MAGIC;
    q.is_concurrent = (attr == @as(?*anyopaque, @ptrCast(&dispatch_queue_attr_concurrent)));
    q.is_static = false;
    q.refcount = 1;
    if (label) |lbl| {
        q.label = initLabel(std.mem.span(lbl));
    } else {
        q.label = initLabel("com.wins.macho.queue");
    }
    _ = pthread_mutex_init(&q.mutex, null);
    _ = pthread_cond_init(&q.cond, null);
    return q;
}

pub fn shim_dispatch_queue_get_label(queue: ?*DispatchQueue) callconv(.c) [*:0]const u8 {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_queue_get_label");
    const q = queue orelse return "";
    return @ptrCast(&q.label);
}

pub fn shim_dispatch_async_f(queue: ?*DispatchQueue, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_async_f");
    ensureStaticQueues();
    const q = queue orelse return;
    if (q.is_concurrent) {
        const raw = malloc(@sizeOf(ConcurrentArg)) orelse {
            work(context);
            return;
        };
        const ca: *ConcurrentArg = @ptrCast(@alignCast(raw));
        ca.* = .{ .func = work, .context = context };
        var tid: usize = 0;
        if (pthread_create(&tid, null, &concurrentWorkerThread, raw) == 0) {
            _ = pthread_detach(tid);
        } else {
            free(raw);
            work(context);
        }
        return;
    }

    const raw = calloc(1, @sizeOf(WorkItem)) orelse {
        work(context);
        return;
    };
    const item: *WorkItem = @ptrCast(@alignCast(raw));
    item.* = .{ .func = work, .context = context };

    _ = pthread_mutex_lock(&q.mutex);
    if (q.tail) |t| {
        t.next = item;
        q.tail = item;
    } else {
        q.head = item;
        q.tail = item;
    }
    if (!q.worker_started) {
        q.worker_started = true;
        var tid: usize = 0;
        if (pthread_create(&tid, null, &serialWorkerThread, @ptrCast(q)) == 0) {
            q.worker_tid = tid;
        }
    }
    _ = pthread_cond_signal(&q.cond);
    _ = pthread_mutex_unlock(&q.mutex);
}

pub fn shim_dispatch_sync_f(queue: ?*DispatchQueue, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_sync_f");
    ensureStaticQueues();
    const q = queue orelse return;
    if (q.is_concurrent) {
        work(context);
        return;
    }

    var done: bool = false;
    var done_cond: CondBuf align(8) = .{0} ** 64;
    _ = pthread_cond_init(&done_cond, null);
    defer _ = pthread_cond_destroy(&done_cond);

    var item: WorkItem = .{
        .func = work,
        .context = context,
        .done_flag = &done,
        .done_cond = &done_cond,
    };

    _ = pthread_mutex_lock(&q.mutex);
    if (q.tail) |t| {
        t.next = &item;
        q.tail = &item;
    } else {
        q.head = &item;
        q.tail = &item;
    }
    if (!q.worker_started) {
        q.worker_started = true;
        var tid: usize = 0;
        if (pthread_create(&tid, null, &serialWorkerThread, @ptrCast(q)) == 0) {
            q.worker_tid = tid;
        }
    }
    _ = pthread_cond_signal(&q.cond);
    while (!done) {
        _ = pthread_cond_wait(&done_cond, &q.mutex);
    }
    _ = pthread_mutex_unlock(&q.mutex);
}

pub fn shim_dispatch_async(queue: ?*DispatchQueue, block: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_async");
    const copied = shim_Block_copy(block) orelse return;
    shim_dispatch_async_f(queue, copied, &invokeAndReleaseBlock);
}

pub fn shim_dispatch_sync(queue: ?*DispatchQueue, block: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_sync");
    const blk: *BlockLiteral = @ptrCast(@alignCast(block orelse return));
    const S = struct {
        fn run(ctx: ?*anyopaque) callconv(.c) void {
            const b: *BlockLiteral = @ptrCast(@alignCast(ctx.?));
            b.invoke(ctx.?);
        }
    };
    shim_dispatch_sync_f(queue, @ptrCast(blk), &S.run);
}

pub fn shim_dispatch_apply_f(iterations: usize, queue: ?*DispatchQueue, context: ?*anyopaque, work: *const fn (?*anyopaque, usize) callconv(.c) void) callconv(.c) void {
    _ = queue;
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_apply_f");
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        work(context, i);
    }
}

pub fn shim_dispatch_once_f(predicate: *isize, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_once_f");
    if (@atomicLoad(isize, predicate, .acquire) == -1) return;
    if (@cmpxchgStrong(isize, predicate, 0, -1, .seq_cst, .acquire) == null) {
        work(context);
    }
}

pub fn shim_dispatch_once(predicate: *isize, block: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_once");
    const blk: *BlockLiteral = @ptrCast(@alignCast(block orelse return));
    if (@atomicLoad(isize, predicate, .acquire) == -1) return;
    if (@cmpxchgStrong(isize, predicate, 0, -1, .seq_cst, .acquire) == null) {
        blk.invoke(@ptrCast(blk));
    }
}

// ============================================================================
// Dispatch Group
// ============================================================================

const NotifyNode = struct {
    queue: ?*DispatchQueue,
    func: *const fn (?*anyopaque) callconv(.c) void,
    context: ?*anyopaque,
    next: ?*NotifyNode = null,
};

pub const DispatchGroup = extern struct {
    magic: u32,
    refcount: usize,
    pending: usize,
    mutex: MutexBuf align(8),
    cond: CondBuf align(8),
    notify_head: ?*NotifyNode,
};

const GROUP_MAGIC: u32 = 0x4447_5250; // 'DGRP'

pub fn shim_dispatch_group_create() callconv(.c) ?*DispatchGroup {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_create");
    const raw = calloc(1, @sizeOf(DispatchGroup)) orelse return null;
    const g: *DispatchGroup = @ptrCast(@alignCast(raw));
    g.magic = GROUP_MAGIC;
    g.refcount = 1;
    _ = pthread_mutex_init(&g.mutex, null);
    _ = pthread_cond_init(&g.cond, null);
    return g;
}

pub fn shim_dispatch_group_enter(group: ?*DispatchGroup) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_enter");
    const g = group orelse return;
    _ = pthread_mutex_lock(&g.mutex);
    g.pending += 1;
    _ = pthread_mutex_unlock(&g.mutex);
}

pub fn shim_dispatch_group_leave(group: ?*DispatchGroup) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_leave");
    const g = group orelse return;
    _ = pthread_mutex_lock(&g.mutex);
    if (g.pending > 0) g.pending -= 1;
    var notifications: ?*NotifyNode = null;
    if (g.pending == 0) {
        notifications = g.notify_head;
        g.notify_head = null;
        _ = pthread_cond_broadcast(&g.cond);
    }
    _ = pthread_mutex_unlock(&g.mutex);

    while (notifications) |n| {
        const next = n.next;
        shim_dispatch_async_f(n.queue, n.context, n.func);
        free(@ptrCast(n));
        notifications = next;
    }
}

pub fn shim_dispatch_group_wait(group: ?*DispatchGroup, timeout: u64) callconv(.c) isize {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_wait");
    const g = group orelse return 0;
    _ = pthread_mutex_lock(&g.mutex);
    defer _ = pthread_mutex_unlock(&g.mutex);

    if (g.pending == 0) return 0;
    if (timeout == DISPATCH_TIME_NOW) return 1;

    if (timeout == DISPATCH_TIME_FOREVER) {
        while (g.pending > 0) {
            _ = pthread_cond_wait(&g.cond, &g.mutex);
        }
        return 0;
    }

    var ts: std.c.timespec = undefined;
    nsToAbsTimespec(timeout, &ts);
    while (g.pending > 0) {
        const rc = pthread_cond_timedwait(&g.cond, &g.mutex, &ts);
        if (rc != 0) break;
    }
    return if (g.pending == 0) 0 else 1;
}

const GroupAsyncCtx = struct {
    group: *DispatchGroup,
    func: *const fn (?*anyopaque) callconv(.c) void,
    context: ?*anyopaque,
};

fn groupAsyncRunner(raw: ?*anyopaque) callconv(.c) void {
    const ctx: *GroupAsyncCtx = @ptrCast(@alignCast(raw.?));
    const g = ctx.group;
    const func = ctx.func;
    const inner = ctx.context;
    free(@ptrCast(ctx));
    func(inner);
    shim_dispatch_group_leave(g);
}

pub fn shim_dispatch_group_async_f(group: ?*DispatchGroup, queue: ?*DispatchQueue, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_async_f");
    const g = group orelse return;
    shim_dispatch_group_enter(g);
    const raw = malloc(@sizeOf(GroupAsyncCtx)) orelse {
        work(context);
        shim_dispatch_group_leave(g);
        return;
    };
    const ctx: *GroupAsyncCtx = @ptrCast(@alignCast(raw));
    ctx.* = .{ .group = g, .func = work, .context = context };
    shim_dispatch_async_f(queue, raw, &groupAsyncRunner);
}

pub fn shim_dispatch_group_async(group: ?*DispatchGroup, queue: ?*DispatchQueue, block: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_async");
    const copied = shim_Block_copy(block) orelse return;
    shim_dispatch_group_async_f(group, queue, copied, &invokeAndReleaseBlock);
}

pub fn shim_dispatch_group_notify_f(group: ?*DispatchGroup, queue: ?*DispatchQueue, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_notify_f");
    const g = group orelse return;
    _ = pthread_mutex_lock(&g.mutex);
    if (g.pending == 0) {
        _ = pthread_mutex_unlock(&g.mutex);
        shim_dispatch_async_f(queue, context, work);
        return;
    }
    const raw = malloc(@sizeOf(NotifyNode)) orelse {
        _ = pthread_mutex_unlock(&g.mutex);
        return;
    };
    const node: *NotifyNode = @ptrCast(@alignCast(raw));
    node.* = .{ .queue = queue, .func = work, .context = context, .next = g.notify_head };
    g.notify_head = node;
    _ = pthread_mutex_unlock(&g.mutex);
}

pub fn shim_dispatch_group_notify(group: ?*DispatchGroup, queue: ?*DispatchQueue, block: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_group_notify");
    const copied = shim_Block_copy(block) orelse return;
    shim_dispatch_group_notify_f(group, queue, copied, &invokeAndReleaseBlock);
}

// ============================================================================
// Dispatch Semaphore
// ============================================================================

pub const DispatchSemaphore = extern struct {
    magic: u32,
    refcount: usize,
    value: isize,
    mutex: MutexBuf align(8),
    cond: CondBuf align(8),
};

const SEM_MAGIC: u32 = 0x4453_454D; // 'DSEM'

pub fn shim_dispatch_semaphore_create(value: isize) callconv(.c) ?*DispatchSemaphore {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_semaphore_create");
    if (value < 0) return null;
    const raw = calloc(1, @sizeOf(DispatchSemaphore)) orelse return null;
    const s: *DispatchSemaphore = @ptrCast(@alignCast(raw));
    s.magic = SEM_MAGIC;
    s.refcount = 1;
    s.value = value;
    _ = pthread_mutex_init(&s.mutex, null);
    _ = pthread_cond_init(&s.cond, null);
    return s;
}

pub fn shim_dispatch_semaphore_wait(sem: ?*DispatchSemaphore, timeout: u64) callconv(.c) isize {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_semaphore_wait");
    const s = sem orelse return 0;
    _ = pthread_mutex_lock(&s.mutex);
    defer _ = pthread_mutex_unlock(&s.mutex);

    if (s.value > 0) {
        s.value -= 1;
        return 0;
    }
    if (timeout == DISPATCH_TIME_NOW) return 1;
    if (timeout == DISPATCH_TIME_FOREVER) {
        while (s.value <= 0) {
            _ = pthread_cond_wait(&s.cond, &s.mutex);
        }
        s.value -= 1;
        return 0;
    }

    var ts: std.c.timespec = undefined;
    nsToAbsTimespec(timeout, &ts);
    while (s.value <= 0) {
        const rc = pthread_cond_timedwait(&s.cond, &s.mutex, &ts);
        if (rc != 0) break;
    }
    if (s.value > 0) {
        s.value -= 1;
        return 0;
    }
    return 1;
}

pub fn shim_dispatch_semaphore_signal(sem: ?*DispatchSemaphore) callconv(.c) isize {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_semaphore_signal");
    const s = sem orelse return 0;
    _ = pthread_mutex_lock(&s.mutex);
    s.value += 1;
    const woken: isize = if (s.value <= 0) 1 else 0;
    _ = pthread_cond_signal(&s.cond);
    _ = pthread_mutex_unlock(&s.mutex);
    return woken;
}

// ============================================================================
// Retain / Release / Time / After
// ============================================================================

pub fn shim_dispatch_retain(obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_retain");
    const ptr = obj orelse return;
    const magic = @as(*const u32, @ptrCast(@alignCast(ptr))).*;
    switch (magic) {
        QUEUE_MAGIC => @as(*DispatchQueue, @ptrCast(@alignCast(ptr))).refcount +|= 1,
        GROUP_MAGIC => @as(*DispatchGroup, @ptrCast(@alignCast(ptr))).refcount +|= 1,
        SEM_MAGIC => @as(*DispatchSemaphore, @ptrCast(@alignCast(ptr))).refcount +|= 1,
        else => {},
    }
}

pub fn shim_dispatch_release(obj: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_release");
    const ptr = obj orelse return;
    const magic = @as(*const u32, @ptrCast(@alignCast(ptr))).*;
    switch (magic) {
        QUEUE_MAGIC => {
            const q: *DispatchQueue = @ptrCast(@alignCast(ptr));
            if (q.is_static) return;
            if (q.refcount > 1) {
                q.refcount -= 1;
                return;
            }
            if (q.worker_started and q.worker_tid != 0) {
                _ = pthread_mutex_lock(&q.mutex);
                q.stopped = true;
                _ = pthread_cond_broadcast(&q.cond);
                _ = pthread_mutex_unlock(&q.mutex);
                _ = pthread_join(q.worker_tid, null);
            }
            _ = pthread_mutex_destroy(&q.mutex);
            _ = pthread_cond_destroy(&q.cond);
            free(ptr);
        },
        GROUP_MAGIC => {
            const g: *DispatchGroup = @ptrCast(@alignCast(ptr));
            if (g.refcount > 1) {
                g.refcount -= 1;
                return;
            }
            _ = pthread_mutex_destroy(&g.mutex);
            _ = pthread_cond_destroy(&g.cond);
            free(ptr);
        },
        SEM_MAGIC => {
            const s: *DispatchSemaphore = @ptrCast(@alignCast(ptr));
            if (s.refcount > 1) {
                s.refcount -= 1;
                return;
            }
            _ = pthread_mutex_destroy(&s.mutex);
            _ = pthread_cond_destroy(&s.cond);
            free(ptr);
        },
        else => {},
    }
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = clock_gettime(0, &ts); // CLOCK_REALTIME
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn nsToAbsTimespec(abs_ns: u64, ts: *std.c.timespec) void {
    ts.sec = @intCast(abs_ns / 1_000_000_000);
    ts.nsec = @intCast(abs_ns % 1_000_000_000);
}

pub fn shim_dispatch_time(when: u64, delta: i64) callconv(.c) u64 {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_time");
    if (when == DISPATCH_TIME_FOREVER) return DISPATCH_TIME_FOREVER;
    const base: u64 = if (when == DISPATCH_TIME_NOW) nowNs() else when;
    if (delta >= 0) {
        return base +| @as(u64, @intCast(delta));
    } else {
        const sub: u64 = @intCast(-delta);
        return if (base > sub) base - sub else 0;
    }
}

const AfterCtx = struct {
    when: u64,
    queue: ?*DispatchQueue,
    func: *const fn (?*anyopaque) callconv(.c) void,
    context: ?*anyopaque,
};

fn afterThread(raw: ?*anyopaque) callconv(.c) ?*anyopaque {
    const ctx: *AfterCtx = @ptrCast(@alignCast(raw.?));
    const when = ctx.when;
    const q = ctx.queue;
    const func = ctx.func;
    const inner = ctx.context;
    free(@ptrCast(ctx));

    const now = nowNs();
    if (when > now and when != DISPATCH_TIME_FOREVER) {
        const diff = when - now;
        var req: std.c.timespec = .{
            .sec = @intCast(diff / 1_000_000_000),
            .nsec = @intCast(diff % 1_000_000_000),
        };
        _ = nanosleep(&req, null);
    }
    shim_dispatch_async_f(q, inner, func);
    return null;
}

pub fn shim_dispatch_after_f(when: u64, queue: ?*DispatchQueue, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_after_f");
    const raw = malloc(@sizeOf(AfterCtx)) orelse return;
    const ctx: *AfterCtx = @ptrCast(@alignCast(raw));
    ctx.* = .{ .when = when, .queue = queue, .func = work, .context = context };
    var tid: usize = 0;
    if (pthread_create(&tid, null, &afterThread, raw) == 0) {
        _ = pthread_detach(tid);
    } else {
        free(raw);
    }
}

pub fn shim_dispatch_after(when: u64, queue: ?*DispatchQueue, block: ?*anyopaque) callconv(.c) void {
    if (trace.active_tracer) |t| t.recordExternalCall("_dispatch_after");
    const copied = shim_Block_copy(block) orelse return;
    shim_dispatch_after_f(when, queue, copied, &invokeAndReleaseBlock);
}
