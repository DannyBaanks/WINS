#!/usr/bin/env python3
"""Probe patch: catch SIGABRT too, walk the frame-pointer chain, dump the map.

Measurement only. glibc detects the corrupted chunk at pop time, long after the
write that broke it, so the only way to name the write is to (a) know which
chunk was bad and (b) put a watchpoint on it. This gives (a): the abort's
registers name the bad tcache entry, and the EBP chain names the client call
that popped it.

The map dump answers a separate question: EIP came back "(unmapped)", which
means the code that was executing had already been unmapped underneath it. The
map says what is still there and what is not.

The handler is re-entrancy safe: a fault while reading the chain would
re-enter it, so a flag makes the second entry exit immediately.

Run only by tools/build_probe.sh, against native/probe/ (gitignored).
"""
import sys
import pathlib

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

NL = chr(92) + "n"

s = target.read_text()

# 1. Re-entrancy guard, right after the handler's opening line.
lines = s.split("\n")
for idx, line in enumerate(lines):
    if line.startswith("fn sigHandler(sig: linux.SIG,"):
        guard = [
            "    if (g_in_handler) {",
            "        linux.exit_group(134);",
            "    }",
            "    g_in_handler = true;",
        ]
        lines[idx + 1:idx + 1] = guard
        # The flag itself goes before the function, at file scope.
        lines[idx:idx] = ["var g_in_handler: bool = false;", ""]
        break
else:
    raise SystemExit("sigHandler not found")

s = "\n".join(lines)

# 2. Frame-pointer backtrace, printed from the saved context.
anchor2 = "        const esp_val = uctx.uc_mcontext.esp;"
assert anchor2 in s, "esp_val anchor not found"
bt = [
    '        std.debug.print("  Frame-pointer backtrace (EBP chain):' + NL + '", .{});',
    "        var fp: usize = uctx.uc_mcontext.ebp;",
    "        var depth: usize = 0;",
    "        while (depth < 28 and fp > 0x1000 and fp + 8 < 0xFFFFF000) : (depth += 1) {",
    "            const ret: u32 = @as(*const u32, @ptrFromInt(fp + 4)).*;",
    "            const next: u32 = @as(*const u32, @ptrFromInt(fp)).*;",
    '            std.debug.print("    #{d} fp=0x{x:0>8} ret=0x{x:0>8}' + NL + '", .{ depth, fp, ret });',
    "            if (next <= fp or next - fp > 0x200000) break;",
    "            fp = next;",
    "        }",
]
s = s.replace(anchor2, "\n".join(bt) + "\n" + anchor2, 1)

# 3. Dump the whole map at crash time.
anchor_map = "        describeAddr(uctx.uc_mcontext.eip);"
assert anchor_map in s, "describeAddr anchor not found"
mapcode = [
    anchor_map,
    "        {",
    '            const fd2 = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);',
    "            if (linux.errno(fd2) == .SUCCESS) {",
    "                defer _ = linux.close(@intCast(fd2));",
    "                var b2: [16 * 1024]u8 = undefined;",
    "                const rn2 = linux.read(@intCast(fd2), &b2, b2.len);",
    "                if (rn2 <= b2.len) {",
    '                    std.debug.print("  --- maps at crash ---' + NL + '", .{});',
    "                    var it2 = std.mem.splitScalar(u8, b2[0..@intCast(rn2)], '" + chr(92) + "n');",
    '                    while (it2.next()) |l2| std.debug.print("    {s}' + NL + '", .{l2});',
    "                }",
    "            }",
    "        }",
]
s = s.replace(anchor_map, "\n".join(mapcode), 1)

# 4. Register SIGABRT as well: glibc's malloc_printerr aborts, and that abort is
#    the only place the corrupted chunk is named.
anchor3 = "    _ = linux.sigaction(linux.SIG.ILL, &sa, null);"
assert anchor3 in s, "sigaction anchor not found"
s = s.replace(
    anchor3,
    anchor3 + "\n    _ = linux.sigaction(linux.SIG.ABRT, &sa, null);",
    1,
)

# 5. Dump the map right before the guest image is mapped at its PE base. The
#    crash-time map showed the guest's image VMA carrying the name "[heap]"
#    and no other heap anywhere, which means the heap was inside the window
#    the image mapping claims. This shows what was there before.
anchor_img = "    const mapped_ptr = linux.mmap(\n        @ptrFromInt(image_base),"
assert anchor_img in s, "image mmap anchor not found"
pre = [
    "    {",
    '        std.debug.print("  --- maps before guest image mapping ---' + NL + '", .{});',
    '        const fd3 = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);',
    "        if (linux.errno(fd3) == .SUCCESS) {",
    "            defer _ = linux.close(@intCast(fd3));",
    "            var b3: [16 * 1024]u8 = undefined;",
    "            const rn3 = linux.read(@intCast(fd3), &b3, b3.len);",
    "            if (rn3 <= b3.len) {",
    "                var it3 = std.mem.splitScalar(u8, b3[0..@intCast(rn3)], '" + chr(92) + "n');",
    '                while (it3.next()) |l3| std.debug.print("    {s}' + NL + '", .{l3});',
    "            }",
    "        }",
    "    }",
]
s = s.replace(anchor_img, "\n".join(pre) + "\n" + anchor_img, 1)

# 6. Dump the map at the very top of main: the state before the loader has
#    allocated anything. If a brk heap already exists there, the guest's image
#    window has to be reserved before anything can grow into it.
anchor_main = "pub fn main(init: std.process.Init) !void {"
assert anchor_main in s, "main anchor not found"
premain = [
    anchor_main,
    "    {",
    '        std.debug.print("  --- maps at main entry ---' + NL + '", .{});',
    '        const fd4 = linux.open("/proc/self/maps", .{ .ACCMODE = .RDONLY }, 0);',
    "        if (linux.errno(fd4) == .SUCCESS) {",
    "            defer _ = linux.close(@intCast(fd4));",
    "            var b4: [16 * 1024]u8 = undefined;",
    "            const rn4 = linux.read(@intCast(fd4), &b4, b4.len);",
    "            if (rn4 <= b4.len) {",
    "                var it4 = std.mem.splitScalar(u8, b4[0..@intCast(rn4)], '" + chr(92) + "n');",
    '                while (it4.next()) |l4| std.debug.print("    {s}' + NL + '", .{l4});',
    "            }",
    "        }",
    "    }",
]
s = s.replace(anchor_main, "\n".join(premain), 1)

target.write_text(s)
print("probe: SIGABRT capture + frame-pointer backtrace + map dumps patched in")
