const std = @import("std");
const trace = @import("trace.zig");
const c_uctx = @cImport({
    @cInclude("ucontext.h");
});

pub var active_evidence_dir: ?[]const u8 = null;
pub var active_target_path: ?[]const u8 = null;

pub const CrashInfo = struct {
    signal: i32,
    si_addr: usize,
    rip: usize,
    rsp: usize,
    rax: usize,
    rdi: usize,
    rsi: usize,
    rdx: usize,
};

pub fn handleDarwinSyscallOrCrash(sig: std.os.linux.SIG, info: *const std.posix.siginfo_t, uctx_raw: ?*anyopaque) callconv(.c) void {
    const linux = std.os.linux;
    const sig_num: i32 = @intCast(@intFromEnum(sig));
    var rip: usize = 0;
    var rsp: usize = 0;
    var rax: usize = 0;
    var rdi: usize = 0;
    var rsi: usize = 0;
    var rdx: usize = 0;
    const si_addr: usize = @intFromPtr(info.fields.sigfault.addr);

    if (uctx_raw) |raw| {
        const REG_RDI = 8;
        const REG_RSI = 9;
        const REG_RDX = 12;
        const REG_RAX = 13;
        const REG_RSP = 15;
        const REG_RIP = 16;
        const REG_EFL = 17;
        const uc: *c_uctx.ucontext_t = @ptrCast(@alignCast(raw));
        rip = @bitCast(uc.uc_mcontext.gregs[REG_RIP]);
        rsp = @bitCast(uc.uc_mcontext.gregs[REG_RSP]);
        rax = @bitCast(uc.uc_mcontext.gregs[REG_RAX]);
        rdi = @bitCast(uc.uc_mcontext.gregs[REG_RDI]);
        rsi = @bitCast(uc.uc_mcontext.gregs[REG_RSI]);
        rdx = @bitCast(uc.uc_mcontext.gregs[REG_RDX]);

        if (sig == linux.SIG.SYS) {
            // Check Darwin BSD syscall (0x2000000 | num) or Mach trap (0x1000000 | num)
            if (rax == 0x2000004) {
                // Darwin BSD SYS_write(fd, buf, count): CF=1 + positive errno on error, CF=0 on success
                const res = linux.write(@intCast(rdi), @ptrFromInt(rsi), rdx);
                const sres: isize = @bitCast(res);
                if (sres < 0 and sres >= -4095) {
                    uc.uc_mcontext.gregs[REG_RAX] = @intCast(-sres);
                    uc.uc_mcontext.gregs[REG_EFL] |= 1; // Set CF
                } else {
                    uc.uc_mcontext.gregs[REG_RAX] = @bitCast(res);
                    uc.uc_mcontext.gregs[REG_EFL] &= ~@as(@TypeOf(uc.uc_mcontext.gregs[REG_EFL]), 1); // Clear CF
                }
                if (trace.active_tracer) |t| {
                    t.recordExternalCall("syscall:darwin_bsd_write(0x2000004)");
                }
                return;
            }
            if (trace.active_tracer) |t| {
                const kind_str: []const u8 = if ((rax & 0xFF000000) == 0x1000000)
                    "MACH_TRAP"
                else if ((rax & 0xFF000000) == 0x2000000)
                    "DARWIN_BSD_SYSCALL"
                else
                    "UNKNOWN_SYSCALL";
                t.record(.FIRST_UNSUPPORTED_KERNEL_BOUNDARY, "class={s} rax=0x{x} rip=0x{x}", .{ kind_str, rax, rip });
            }
        }
    }

    if (trace.active_tracer) |t| {
        t.record(.SIGNAL, "sig={d} rip=0x{x} addr=0x{x} rax=0x{x}", .{ sig_num, rip, si_addr, rax });
    }

    std.debug.print(
        "\n=== WINS-MACHO CRASH / BOUNDARY ===\nsignal={d} rip=0x{x} rsp=0x{x} addr=0x{x}\nrax=0x{x} rdi=0x{x} rsi=0x{x} rdx=0x{x}\n",
        .{ sig_num, rip, rsp, si_addr, rax, rdi, rsi, rdx },
    );
    if (trace.active_tracer) |t| {
        std.debug.print("last_event={s} last_shim={s}\n", .{
            if (t.last_event) |e| @tagName(e) else "none",
            t.last_shim orelse "none",
        });
    }

    if (active_evidence_dir) |dir| {
        var path_buf: [512]u8 = undefined;
        const crash_path = std.fmt.bufPrint(&path_buf, "{s}/crash.json\x00", .{dir}) catch null;
        if (crash_path) |cp| {
            const fd = std.c.open(@ptrCast(cp.ptr), .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
            if (fd >= 0) {
                var json_buf: [1024]u8 = undefined;
                const last_ev = if (trace.active_tracer) |t| (if (t.last_event) |e| @tagName(e) else "none") else "none";
                const last_sh = if (trace.active_tracer) |t| (t.last_shim orelse "none") else "none";
                const msg = std.fmt.bufPrint(&json_buf,
                    "{{\n  \"signal\": {d},\n  \"si_addr\": \"0x{x}\",\n  \"rip\": \"0x{x}\",\n  \"rsp\": \"0x{x}\",\n  \"rax\": \"0x{x}\",\n  \"rdi\": \"0x{x}\",\n  \"rsi\": \"0x{x}\",\n  \"rdx\": \"0x{x}\",\n  \"last_event\": \"{s}\",\n  \"last_shim\": \"{s}\"\n}}\n",
                    .{ sig_num, si_addr, rip, rsp, rax, rdi, rsi, rdx, last_ev, last_sh },
                ) catch "";
                _ = linux.write(fd, msg.ptr, msg.len);
                _ = linux.close(fd);
            }
        }
    }

    linux.exit_group(@intCast(128 + @as(u8, @truncate(@as(u32, @bitCast(sig_num))))));
}

pub fn installSignalHandlers() void {
    const linux = std.os.linux;
    var act: linux.Sigaction = .{
        .handler = .{ .sigaction = &handleDarwinSyscallOrCrash },
        .mask = linux.sigemptyset(),
        .flags = linux.SA.SIGINFO,
    };
    _ = linux.sigaction(linux.SIG.SEGV, &act, null);
    _ = linux.sigaction(linux.SIG.ILL, &act, null);
    _ = linux.sigaction(linux.SIG.BUS, &act, null);
    _ = linux.sigaction(linux.SIG.SYS, &act, null);
    _ = linux.sigaction(linux.SIG.ABRT, &act, null);
}

// Install seccomp-bpf filter that traps syscalls with nr >= 0x1000000 (Darwin BSD / Mach traps)
// while allowing all normal Linux syscalls (< 0x1000000).
pub fn installDarwinSyscallTrap() bool {
    const linux = std.os.linux;
    const PR_SET_NO_NEW_PRIVS = 38;
    const PR_SET_SECCOMP = 22;
    const SECCOMP_MODE_FILTER = 2;

    if (linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;

    const SockFilter = extern struct {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    };
    const SockFprog = extern struct {
        len: u16,
        filter: [*]const SockFilter,
    };

    // seccomp_data.nr is at offset 0 (u32)
    // BPF_LD|BPF_W|BPF_ABS = 0x20
    // BPF_JMP|BPF_JGE|BPF_K = 0x35
    // BPF_RET|BPF_K = 0x06
    // SECCOMP_RET_ALLOW = 0x7fff0000
    // SECCOMP_RET_TRAP = 0x00030000
    const filter = [_]SockFilter{
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 0 }, // ld [0] (nr)
        .{ .code = 0x35, .jt = 0, .jf = 1, .k = 0x01000000 }, // jge 0x1000000 -> next, else skip
        .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0x00030000 }, // ret SECCOMP_RET_TRAP
        .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0x7fff0000 }, // ret SECCOMP_RET_ALLOW
    };
    const prog = SockFprog{
        .len = filter.len,
        .filter = &filter,
    };
    return linux.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, @intFromPtr(&prog), 0, 0) == 0;
}
