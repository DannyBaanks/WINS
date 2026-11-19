const std = @import("std");

pub const EventKind = enum {
    START,
    IMAGE_MAPPED,
    ENTRYPOINT_RESOLVED,
    DYLIB_GRAPH_READY,
    FIXUPS_APPLIED,
    IMPORTS_RESOLVED,
    TRANSFER_CONTROL,
    FIRST_EXTERNAL_CALL,
    FIRST_UNSUPPORTED_CALL,
    FIRST_UNSUPPORTED_KERNEL_BOUNDARY,
    EXIT,
    SIGNAL,
};

pub const TraceEvent = struct {
    ts_ns: i64,
    rel_us: i64,
    kind: EventKind,
    detail: []const u8,
};

pub const Tracer = struct {
    allocator: std.mem.Allocator,
    start_ns: i64,
    events: std.ArrayList(TraceEvent),
    last_event: ?EventKind = null,
    last_shim: ?[]const u8 = null,
    saw_first_external_call: bool = false,
    saw_first_unsupported: bool = false,

    pub fn init(allocator: std.mem.Allocator) Tracer {
        return .{
            .allocator = allocator,
            .start_ns = nowNs(),
            .events = .empty,
        };
    }

    pub fn deinit(self: *Tracer) void {
        for (self.events.items) |ev| {
            self.allocator.free(ev.detail);
        }
        self.events.deinit(self.allocator);
    }

    pub fn nowNs() i64 {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
        return @as(i64, ts.sec) * 1_000_000_000 + @as(i64, ts.nsec);
    }

    pub fn record(self: *Tracer, kind: EventKind, comptime fmt: []const u8, args: anytype) void {
        const ts = nowNs();
        const rel_us = @divFloor(ts - self.start_ns, 1000);
        const detail = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        self.events.append(self.allocator, .{
            .ts_ns = ts,
            .rel_us = rel_us,
            .kind = kind,
            .detail = detail,
        }) catch {
            self.allocator.free(detail);
            return;
        };
        self.last_event = kind;
    }

    pub fn recordExternalCall(self: *Tracer, symbol: []const u8) void {
        self.last_shim = symbol;
        if (!self.saw_first_external_call) {
            self.saw_first_external_call = true;
            self.record(.FIRST_EXTERNAL_CALL, "symbol={s}", .{symbol});
        }
    }

    pub fn recordUnsupportedCall(self: *Tracer, symbol: []const u8) void {
        if (!self.saw_first_unsupported) {
            self.saw_first_unsupported = true;
            self.record(.FIRST_UNSUPPORTED_CALL, "symbol={s}", .{symbol});
        }
    }
};

// Global pointer for C-ABI shims and signal handlers to report back to the active tracer
pub var active_tracer: ?*Tracer = null;
