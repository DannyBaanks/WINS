#!/usr/bin/env python3
"""Patch the local probe copy so steamclient_CreateInterface calls the REAL
Steam client instead of refusing.

Laboratory only. Measured: with a dynamic glibc i386 build, dlopen of the real
linux32/steamclient.so succeeds and its CreateInterface answers "SteamClient010"
with a real interface object (rc=0). That is the honest bridge -- the client
answers for itself -- and this patch exists to observe how far the guest gets
with the real object before any of it is designed into the published loader.

The returned pointer is handed to the guest RAW. That is the point of the
measurement: whatever the guest does with it next -- which vtable slot it calls,
with what -- is the specification the adapter has to satisfy. The Linux C++ ABI
and the Win32 ABI differ (this in ecx vs on the stack, callee vs caller cleanup),
so a raw hand-off is expected to misbehave; where it misbehishes tells us which
slots matter.

Run only by tools/build_probe.sh, against native/probe/ (gitignored).
"""
import pathlib
import sys

probe_dir = pathlib.Path(sys.argv[1])
target = probe_dir / "winrun32.zig"

s = target.read_text()

# dlopen/dlsym declarations, inserted once, right before the function.
decls = (
    "extern fn dlopen(path: [*:0]const u8, flags: c_int) ?*anyopaque;\n"
    "extern fn dlsym(handle: ?*anyopaque, sym: [*:0]const u8) ?*anyopaque;\n"
    "extern fn dlerror() [*:0]const u8;\n\n"
)
anchor = "fn steamclient_CreateInterface("
assert anchor in s, "steamclient_CreateInterface not found"
if "extern fn dlopen(" not in s:
    s = s.replace(anchor, decls + anchor, 1)

start = s.index(anchor)
end = s.index("\n}\n", start) + len("\n}\n")

body = '''fn steamclient_CreateInterface(pName: ?[*:0]const u8, pReturnCode: ?*i32) callconv(.c) ?*anyopaque {
    if (pReturnCode) |rc| rc.* = -1;
    const name = if (pName) |n| std.mem.sliceTo(n, 0) else "";
    std.debug.print("[WINS:Steam] CreateInterface(\\"{s}\\")\\n", .{name});
    // PROBE: the real client, loaded for real. It is the only thing that can
    // answer for itself; the loader does not speak for it.
    const CLIENT_PATH = "/home/danny/.local/share/Steam/linux32/steamclient.so";
    const handle = dlopen(CLIENT_PATH, 2) orelse {
        std.debug.print("  -> dlopen of the real client FAILED: {s}\\n", .{std.mem.sliceTo(dlerror(), 0)});
        return null;
    };
    const sym = dlsym(handle, "CreateInterface") orelse {
        std.debug.print("  -> real client has no CreateInterface export\\n", .{});
        return null;
    };
    const real: *const fn ([*:0]const u8, ?*i32) callconv(.c) ?*anyopaque = @ptrCast(sym);
    const iface = real(name, pReturnCode);
    const rc = if (pReturnCode) |r| r.* else -999;
    if (iface) |i| {
        std.debug.print("  -> REAL client returned 0x{x} (rc={d})\\n", .{ @intFromPtr(i), rc });
        // Dump the vtable so the next crash's EIP can be matched to a slot: that
        // is what tells us which method the guest called, which is the spec the
        // ABI adapter has to satisfy. Without this, the slot is a guess.
        const vt: [*]const usize = @ptrCast(@alignCast(i));
        var k: usize = 0;
        while (k < 14) : (k += 1) {
            std.debug.print("  [probe] iface vtable[{d}] = 0x{x}\\n", .{ k, vt[k] });
        }
        return i;
    }
    std.debug.print("  -> REAL client returned null (rc={d})\\n", .{rc});
    return null;
}
'''

s = s[:start] + body + s[end:]

# Localisation: load and call the client at STARTUP, before any guest code runs.
# If it aborts here too, the library alone is the problem. If it succeeds and
# only aborts later, the guest's execution under our shims corrupted the heap
# first -- which is a loader defect, not something the real client did.
startup = (
    "    // PROBE (localisation): real client at startup, before any guest code.\n"
    "    {\n"
    "        const h = dlopen(\"/home/danny/.local/share/Steam/linux32/steamclient.so\", 2);\n"
    "        if (h) |hh| {\n"
    "            std.debug.print(\"[probe] startup dlopen OK\\n\", .{});\n"
    "            if (dlsym(hh, \"CreateInterface\")) |sy| {\n"
    "                const f: *const fn ([*:0]const u8, ?*i32) callconv(.c) ?*anyopaque = @ptrCast(sy);\n"
    "                var code: i32 = -1;\n"
    "                const r = f(\"SteamClient010\", &code);\n"
    "                std.debug.print(\"[probe] startup CreateInterface -> {s} (rc={d})\\n\", .{ if (r != null) \"non-null\" else \"null\", code });\n"
    "            }\n"
    "        } else {\n"
    "            std.debug.print(\"[probe] startup dlopen FAILED\\n\", .{});\n"
    "        }\n"
    "    }\n"
)
anchor = "pub fn main(init: std.process.Init) !void {"
if "[probe] startup dlopen" not in s:
    assert anchor in s, "main not found"
    s = s.replace(anchor, anchor + "\n" + startup, 1)

target.write_text(s)
print("probe: CreateInterface now calls the real client")
