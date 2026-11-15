//! WINS library registry: the Windows DLLs WINS stands in for, as versioned units.
//!
//! WINS does not run Windows DLLs; each one a program imports is answered by a
//! piece of native code. This file names those pieces, the way a distribution
//! names its packages, so that a user, a model or a bug report can say
//! "wins-dsound 0.2.0" instead of "the sound code", and so that the DLLs WINS
//! does NOT stand in for are visible as gaps (`winrun32 --imports <exe>`).
//!
//! This is metadata. It does not decide what resolves: `resolveImport` in
//! winrun32.zig does, and `--imports` reports its answers. Whether an import
//! resolves says nothing about whether the program then behaves like it does on
//! Windows -- `status` and `evidence` carry that, and say so honestly.
//!
//! Versioning (details in libs/README.md): MAJOR when behaviour a working
//! program relied on changes, MINOR when exports are added or a feature is
//! implemented, PATCH for fixes. 0.x while no library claims full coverage.
//! Bump the version in the same commit that changes the library.

const std = @import("std");

/// How much is known about a library. `exercised` needs a recorded run of a real
/// program through it (named in `evidence`); everything else is `unexercised`.
/// There is no "complete": WINS has not implemented the whole of any DLL.
pub const Status = enum { exercised, unexercised };

pub const Library = struct {
    /// Stable identifier, `wins-<dll>`.
    name: []const u8,
    /// MAJOR.MINOR.PATCH.
    version: []const u8,
    /// Windows DLL names this library answers for: lowercase, with ".dll".
    dlls: []const []const u8,
    /// Loaders that bind it: "winrun32" (i386 PE32) and/or "winrun" (x86-64 PE32+).
    loaders: []const []const u8,
    /// Files that implement it, relative to the repository root.
    sources: []const []const u8,
    status: Status,
    /// What it does, and what it knowingly does not.
    summary: []const u8,
    /// The recorded runs behind `exercised`; empty when `unexercised`.
    evidence: []const u8,
};

const I386 = [_][]const u8{"winrun32"};
const BOTH = [_][]const u8{ "winrun32", "winrun" };

/// The recorded run that exercised the libraries marked below: the Steam build of
/// FalloutNV.exe played through the menu, New Game and the Mojave exterior; every
/// listed library appears in that run's loader log (WINS 8c50dda, 2026-11-15).
const FNV = "FalloutNV.exe (Steam build, i386) played through the menu, New Game and the Mojave exterior; the library appears in that run's loader log (WINS 8c50dda, 2026-11-15)";
const X64 = [_][]const u8{"winrun"};

pub const libraries = [_]Library{
    .{
        .name = "wins-kernel32",
        .version = "0.1.0",
        .dlls = &.{"kernel32.dll"},
        .loaders = &BOTH,
        .sources = &.{ "native/winrun32.zig", "native/winrun_kernel32.zig", "native/winrun_threads.zig" },
        .status = .exercised,
        .summary = "Files, memory, threads and synchronisation (real threads, lock-free critical sections), time, ini files, console. Many of the ~900 kernel32 exports are not implemented.",
        .evidence = FNV,
    },
    .{
        .name = "wins-ntdll",
        .version = "0.1.0",
        .dlls = &.{"ntdll.dll"},
        .loaders = &I386,
        .sources = &.{"native/winrun32.zig"},
        .status = .unexercised,
        .summary = "A handful of Nt*/Rtl* calls used by anti-debug and loader code.",
        .evidence = "",
    },
    .{
        .name = "wins-psapi",
        .version = "0.1.0",
        .dlls = &.{"psapi.dll"},
        .loaders = &I386,
        .sources = &.{"native/winrun32.zig"},
        .status = .unexercised,
        .summary = "Process and module enumeration.",
        .evidence = "",
    },
    .{
        .name = "wins-version",
        .version = "0.1.0",
        .dlls = &.{"version.dll"},
        .loaders = &I386,
        .sources = &.{"native/winrun32.zig"},
        .status = .unexercised,
        .summary = "File version resources (GetFileVersionInfo, VerQueryValue).",
        .evidence = "",
    },
    .{
        .name = "wins-dbghelp",
        .version = "0.1.0",
        .dlls = &.{"dbghelp.dll"},
        .loaders = &I386,
        .sources = &.{ "native/winrun32.zig", "native/winrun_extra_dlls.zig" },
        .status = .unexercised,
        .summary = "Stack walking entry points, answered without symbols.",
        .evidence = "",
    },
    .{
        .name = "wins-msvcrt",
        .version = "0.1.0",
        .dlls = &.{ "msvcrt.dll", "ucrtbase.dll" },
        .loaders = &BOTH,
        .sources = &.{"native/winrun_msvcrt.zig"},
        .status = .unexercised,
        .summary = "The C runtime a program imports instead of linking statically.",
        .evidence = "",
    },
    .{
        .name = "wins-user32",
        .version = "0.1.0",
        .dlls = &.{"user32.dll"},
        .loaders = &BOTH,
        .sources = &.{ "native/wins_user32.zig", "native/winrun_gui_support.zig", "native/winrun_extra_dlls.zig" },
        .status = .exercised,
        .summary = "Window classes, windows, message queues, activation and input messages over a host X11 window. i386 uses wins_user32.zig; the x86-64 GUI loader uses winrun_gui_support.zig.",
        .evidence = FNV,
    },
    .{
        .name = "wins-gdi32",
        .version = "0.1.0",
        .dlls = &.{"gdi32.dll"},
        .loaders = &BOTH,
        .sources = &.{ "native/winrun32.zig", "native/winrun_gui_support.zig" },
        .status = .unexercised,
        .summary = "i386: GetStockObject only. x86-64 GUI loader: a larger drawing surface.",
        .evidence = "",
    },
    .{
        .name = "wins-winmm",
        .version = "0.1.0",
        .dlls = &.{"winmm.dll"},
        .loaders = &I386,
        .sources = &.{ "native/winrun32.zig", "native/winrun_msvcrt.zig" },
        .status = .exercised,
        .summary = "timeGetTime and mmio* (RIFF files read through the caller's own I/O procedure, with the I/O buffer). No waveOut/midi on i386.",
        .evidence = FNV,
    },
    .{
        .name = "wins-xinput",
        .version = "0.2.0",
        .dlls = &.{ "xinput1_3.dll", "xinput1_4.dll", "xinput1_2.dll", "xinput9_1_0.dll" },
        .loaders = &I386,
        .sources = &.{ "native/wins_xinput.zig", "native/winrun_ordinals.zig", "native/winrun32.zig", "native/winrun_directx.zig" },
        .status = .unexercised,
        .summary = "XInput 1.3/1.4/9.1.0 over host SDL2 GameController (via dlopen, with GetStateEx ordinal 100, vibration, capabilities, audio/battery queries); returns not connected when no gamepad or libSDL2 is present.",
        .evidence = "",
    },
    .{
        .name = "wins-d3d9",
        .version = "0.3.0",
        .dlls = &.{"d3d9.dll"},
        .loaders = &I386,
        .sources = &.{ "native/wins_d3d9.zig", "native/wins_d3d9_gl.zig", "native/wins_d3d9_shader.zig", "native/wins_gl.zig" },
        .status = .exercised,
        .summary = "Direct3D 9 on the host GPU through OpenGL: devices, Reset (pool/backbuffer validation and host resize), 2D/cube/volume textures, UpdateSurface and UpdateTexture, render targets, state blocks (Create/Begin/End/Capture/Apply), shader-model 3 translated to GLSL, fixed-function transform and vertex lighting (directional/point/spot, materials, ambient), clip planes, occlusion queries. Renders on the NVIDIA GPU when present.",
        .evidence = FNV,
    },
    .{
        .name = "wins-d3dx9",
        .version = "0.2.0",
        .dlls = &.{"d3dx9_38.dll"},
        .loaders = &I386,
        .sources = &.{"native/wins_d3d9.zig"},
        .status = .unexercised,
        .summary = "Matrix/vector math, shader and DDS 2D/cube/volume texture helpers; only the exports a measured program needed.",
        .evidence = "",
    },
    .{
        .name = "wins-dsound",
        .version = "0.2.0",
        .dlls = &.{"dsound.dll"},
        .loaders = &I386,
        .sources = &.{ "native/wins_dsound.zig", "native/wins_audio.zig" },
        .status = .exercised,
        .summary = "DirectSound 8: buffers, DuplicateSoundBuffer, IDirectSoundNotify position notifications, a software mixer with 3D positioning to PipeWire/PulseAudio. No EAX, no capture.",
        .evidence = FNV,
    },
    .{
        .name = "wins-dinput8",
        .version = "0.2.0",
        .dlls = &.{"dinput8.dll"},
        .loaders = &I386,
        .sources = &.{ "native/wins_dinput.zig", "native/wins_xinput.zig" },
        .status = .exercised,
        .summary = "DirectInput 8 keyboard and mouse fed by the host window, plus gamepads/joysticks backed by XInput/SDL2. No force feedback or action mapping.",
        .evidence = FNV,
    },
    .{
        .name = "wins-quartz",
        .version = "0.1.0",
        .dlls = &.{"quartz.dll"},
        .loaders = &I386,
        .sources = &.{ "native/wins_dshow.zig", "native/wins_audio.zig" },
        .status = .exercised,
        .summary = "DirectShow filter graph for pull-mode MPEG audio, reached through ole32!CoCreateInstance (CLSID_FilterGraph), not imported by name. No video renderer.",
        .evidence = FNV,
    },
    .{
        .name = "wins-binkw32",
        .version = "0.2.0",
        .dlls = &.{"binkw32.dll"},
        .loaders = &I386,
        .sources = &.{ "native/wins_bink.zig", "native/wins_audio.zig" },
        .status = .exercised,
        .summary = "Bink video and audio decoding through the host i386 libavcodec (binkvideo, binkaudio_dct/binkaudio_rdft) and wins_audio.zig; nine exports.",
        .evidence = "FalloutNV.exe played FNVIntro.bik through this library in a run on 2026-11-14 (WINS ea7773f); no live Bink audio run recorded",
    },
    .{
        .name = "wins-vorbisfile",
        .version = "0.1.0",
        .dlls = &.{"libvorbisfile.dll"},
        .loaders = &I386,
        .sources = &.{"native/winrun_vorbis.zig"},
        .status = .exercised,
        .summary = "A bridge to the host's real i386 libvorbisfile (needs libvorbisfile3:i386), not a decoder written here.",
        .evidence = FNV,
    },
    .{
        .name = "wins-steam-api",
        .version = "0.2.0",
        .dlls = &.{ "steam_api.dll", "steamclient.dll" },
        .loaders = &I386,
        .sources = &.{"native/winrun32.zig"},
        .status = .exercised,
        .summary = "A bridge to the real running Steam client (ISteamClient, ISteamUser, ISteamUtils, ISteamAppTicket, ISteamUserStats007, ISteamApps003, ISteamFriends005 answered by it). Needs Steam running.",
        .evidence = FNV,
    },
    .{
        .name = "wins-advapi32",
        .version = "0.1.0",
        .dlls = &.{"advapi32.dll"},
        .loaders = &BOTH,
        .sources = &.{ "native/winrun32.zig", "native/winrun_extra_dlls.zig" },
        .status = .exercised,
        .summary = "Registry (in-memory), crypto random, tokens. Not persistent.",
        .evidence = FNV,
    },
    .{
        .name = "wins-ole32",
        .version = "0.1.0",
        .dlls = &.{"ole32.dll"},
        .loaders = &BOTH,
        .sources = &.{ "native/winrun32.zig", "native/winrun_extra_dlls.zig" },
        .status = .exercised,
        .summary = "COM initialisation and CoCreateInstance for the classes WINS implements (DirectShow filter graph).",
        .evidence = FNV,
    },
    .{
        .name = "wins-oleaut32",
        .version = "0.1.0",
        .dlls = &.{"oleaut32.dll"},
        .loaders = &BOTH,
        .sources = &.{"native/winrun_extra_dlls.zig"},
        .status = .unexercised,
        .summary = "BSTR and variant helpers.",
        .evidence = "",
    },
    .{
        .name = "wins-shell32",
        .version = "0.1.0",
        .dlls = &.{"shell32.dll"},
        .loaders = &BOTH,
        .sources = &.{ "native/winrun32.zig", "native/winrun_extra_dlls.zig" },
        .status = .unexercised,
        .summary = "Known folders mapped to the WINS profile, ShellExecute, CommandLineToArgv.",
        .evidence = "",
    },
    .{
        .name = "wins-shlwapi",
        .version = "0.1.0",
        .dlls = &.{"shlwapi.dll"},
        .loaders = &BOTH,
        .sources = &.{"native/winrun_extra_dlls.zig"},
        .status = .unexercised,
        .summary = "Path and string helpers.",
        .evidence = "",
    },
    .{
        .name = "wins-comctl32",
        .version = "0.1.0",
        .dlls = &.{"comctl32.dll"},
        .loaders = &I386,
        .sources = &.{ "native/winrun32.zig", "native/winrun_extra_dlls.zig" },
        .status = .unexercised,
        .summary = "InitCommonControls; no common-control windows.",
        .evidence = "",
    },
    .{
        .name = "wins-ws2-32",
        .version = "0.1.0",
        .dlls = &.{ "ws2_32.dll", "wsock32.dll" },
        .loaders = &BOTH,
        .sources = &.{"native/winrun_extra_dlls.zig"},
        .status = .unexercised,
        .summary = "Winsock entry points.",
        .evidence = "",
    },
    .{
        .name = "wins-crypto",
        .version = "0.1.0",
        .dlls = &.{ "crypt32.dll", "ncrypt.dll", "bcrypt.dll" },
        .loaders = &BOTH,
        .sources = &.{"native/winrun_extra_dlls.zig"},
        .status = .unexercised,
        .summary = "Crypto API entry points; certificate and key stores are not real.",
        .evidence = "",
    },
    .{
        .name = "wins-ldap",
        .version = "0.1.0",
        .dlls = &.{"wldap32.dll"},
        .loaders = &BOTH,
        .sources = &.{"native/winrun_extra_dlls.zig"},
        .status = .unexercised,
        .summary = "LDAP entry points.",
        .evidence = "",
    },
    .{
        .name = "wins-netmisc",
        .version = "0.1.0",
        .dlls = &.{ "sensapi.dll", "secur32.dll", "wintrust.dll", "iphlpapi.dll", "dnsapi.dll", "winhttp.dll" },
        .loaders = &BOTH,
        .sources = &.{"native/winrun_extra_dlls.zig"},
        .status = .unexercised,
        .summary = "Network and trust helpers; a few entry points each.",
        .evidence = "",
    },
    .{
        .name = "wins-directx-x64",
        .version = "0.1.0",
        .dlls = &.{ "d3d11.dll", "dxgi.dll", "d3dcompiler_47.dll" },
        .loaders = &X64,
        .sources = &.{"native/winrun_directx.zig"},
        .status = .unexercised,
        .summary = "x86-64 loader only: Direct3D 11 / DXGI / HLSL compiler shims. Not a rendering implementation.",
        .evidence = "",
    },
};

fn stripDll(name: []const u8) []const u8 {
    return if (std.ascii.endsWithIgnoreCase(name, ".dll")) name[0 .. name.len - 4] else name;
}

/// The library that answers for `dll` (with or without ".dll", any case), or null
/// when WINS has no library for it.
pub fn libraryFor(dll: []const u8) ?*const Library {
    const want = stripDll(dll);
    for (&libraries) |*lib| {
        for (lib.dlls) |d| {
            if (std.ascii.eqlIgnoreCase(stripDll(d), want)) return lib;
        }
    }
    return null;
}

/// Index of `lib` in `libraries`.
pub fn indexOf(lib: *const Library) usize {
    return (@intFromPtr(lib) - @intFromPtr(&libraries[0])) / @sizeOf(Library);
}

fn appendStrings(out: *std.ArrayList(u8), a: std.mem.Allocator, items: []const []const u8) !void {
    try out.append(a, '[');
    for (items, 0..) |s, i| {
        if (i != 0) try out.append(a, ',');
        const piece = try std.fmt.allocPrint(a, "\"{s}\"", .{s});
        try out.appendSlice(a, piece);
    }
    try out.append(a, ']');
}

/// The registry as JSON (what `winrun32 --libs` prints). Strings in it never
/// contain quotes, backslashes or control characters; a test enforces that.
/// Pass an arena: the pieces it builds along the way are not freed one by one.
pub fn jsonAlloc(a: std.mem.Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, "{\"libraries\":[\n");
    for (&libraries, 0..) |lib, i| {
        if (i != 0) try out.appendSlice(a, ",\n");
        const head = try std.fmt.allocPrint(a, "{{\"name\":\"{s}\",\"version\":\"{s}\",\"status\":\"{s}\",\"dlls\":", .{ lib.name, lib.version, @tagName(lib.status) });
        try out.appendSlice(a, head);
        try appendStrings(&out, a, lib.dlls);
        try out.appendSlice(a, ",\"loaders\":");
        try appendStrings(&out, a, lib.loaders);
        try out.appendSlice(a, ",\"sources\":");
        try appendStrings(&out, a, lib.sources);
        const tail = try std.fmt.allocPrint(a, ",\"summary\":\"{s}\",\"evidence\":\"{s}\"}}", .{ lib.summary, lib.evidence });
        try out.appendSlice(a, tail);
    }
    try out.appendSlice(a, "\n]}\n");
    return out.items;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn isSemver(v: []const u8) bool {
    var parts = std.mem.splitScalar(u8, v, '.');
    var n: usize = 0;
    while (parts.next()) |p| : (n += 1) {
        if (p.len == 0) return false;
        for (p) |c| if (!std.ascii.isDigit(c)) return false;
        if (p.len > 1 and p[0] == '0') return false;
    }
    return n == 3;
}

test "every library has a semver version, a unique name and at least one source" {
    for (&libraries, 0..) |lib, i| {
        try testing.expect(isSemver(lib.version));
        try testing.expect(std.mem.startsWith(u8, lib.name, "wins-"));
        try testing.expect(lib.sources.len > 0 and lib.dlls.len > 0 and lib.loaders.len > 0);
        try testing.expect(lib.summary.len > 0);
        for (libraries[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, lib.name, other.name));
        // An exercised library must say what exercised it; an unexercised one must not claim a run.
        try testing.expect((lib.status == .exercised) == (lib.evidence.len > 0));
    }
}

test "a DLL belongs to one library, spelled lowercase with .dll" {
    for (&libraries, 0..) |lib, i| {
        for (lib.dlls) |d| {
            try testing.expect(std.ascii.endsWithIgnoreCase(d, ".dll"));
            for (d) |c| try testing.expect(!std.ascii.isUpper(c));
            // Another library claiming the same DLL would make attribution ambiguous.
            for (libraries[i + 1 ..]) |other| {
                for (other.dlls) |od| try testing.expect(!std.mem.eql(u8, d, od));
            }
        }
    }
}

test "libraryFor ignores case and the .dll suffix, and says no for a DLL WINS lacks" {
    try testing.expectEqualStrings("wins-kernel32", libraryFor("KERNEL32.DLL").?.name);
    try testing.expectEqualStrings("wins-kernel32", libraryFor("kernel32").?.name);
    try testing.expectEqualStrings("wins-xinput", libraryFor("XINPUT1_3.dll").?.name);
    try testing.expect(libraryFor("opengl32.dll") == null); // negative control
    try testing.expect(libraryFor("") == null);
}

test "registry strings cannot break the JSON they are printed in" {
    for (&libraries) |lib| {
        const all = [_][]const u8{ lib.name, lib.version, lib.summary, lib.evidence };
        for (all) |s| for (s) |c| try testing.expect(c != '"' and c != '\\' and c >= 0x20);
        for (lib.dlls) |s| for (s) |c| try testing.expect(c != '"' and c != '\\' and c >= 0x20);
        for (lib.sources) |s| for (s) |c| try testing.expect(c != '"' and c != '\\' and c >= 0x20);
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const json = try jsonAlloc(arena.allocator());
    // It parses, and carries every library.
    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json, .{});
    try testing.expectEqual(libraries.len, parsed.value.object.get("libraries").?.array.items.len);
}
