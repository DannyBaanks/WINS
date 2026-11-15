// WINS — wins_graph.zig
// Semantic Bipartite Windows <-> Linux Mapping Graph & Subprocess Transmutation Engine.
// Provides 1:1 translations for Windows commands, system processes, and FHS paths
// to power autonomous differential fuzzing and execution in cleanrooms.

const std = @import("std");
const linux = std.os.linux;

// ---------------------------------------------------------------------------
// 1. Path Normalization & FHS Bipartite Translation
// ---------------------------------------------------------------------------

pub const PathMapping = struct {
    win_prefix: []const u8,
    lin_prefix: []const u8,
};

pub const CANONICAL_PATH_MAPPINGS = [_]PathMapping{
    // Special Windows Devices
    .{ .win_prefix = "NUL", .lin_prefix = "/dev/null" },
    .{ .win_prefix = "CON", .lin_prefix = "/dev/tty" },
    .{ .win_prefix = "PRN", .lin_prefix = "/dev/lp0" },
    .{ .win_prefix = "AUX", .lin_prefix = "/dev/ttyS0" },

    // Named Pipes IPC
    .{ .win_prefix = "\\\\.\\pipe\\", .lin_prefix = "/tmp/" },
    .{ .win_prefix = "//./pipe/", .lin_prefix = "/tmp/" },

    // Environment Variables
    .{ .win_prefix = "%APPDATA%", .lin_prefix = "/home/user/.config" },
    .{ .win_prefix = "%LOCALAPPDATA%\\Temp", .lin_prefix = "/tmp" },
    .{ .win_prefix = "%LOCALAPPDATA%", .lin_prefix = "/home/user/.local/share" },
    .{ .win_prefix = "%TEMP%", .lin_prefix = "/tmp" },
    .{ .win_prefix = "%TMP%", .lin_prefix = "/tmp" },
    .{ .win_prefix = "%USERPROFILE%", .lin_prefix = "/home/user" },
    .{ .win_prefix = "%WINDIR%", .lin_prefix = "/usr" },
    .{ .win_prefix = "%SYSTEMROOT%", .lin_prefix = "/usr" },

    // System Directories
    .{ .win_prefix = "C:\\Windows\\System32", .lin_prefix = "/usr/lib" },
    .{ .win_prefix = "C:\\Windows\\SysWOW64", .lin_prefix = "/usr/lib32" },
    .{ .win_prefix = "C:\\Windows\\Temp", .lin_prefix = "/var/tmp" },
    .{ .win_prefix = "C:\\Windows", .lin_prefix = "/usr" },
    .{ .win_prefix = "C:\\Program Files (x86)", .lin_prefix = "/opt" },
    .{ .win_prefix = "C:\\Program Files", .lin_prefix = "/opt" },
    .{ .win_prefix = "C:\\ProgramData", .lin_prefix = "/var/lib" },
};

/// Normalizes a Windows path or DOS drive path into a canonical Linux path.
/// Converts backslashes to forward slashes, expands known paths, and strips drive letters.
pub fn normalizePath(out: []u8, win_path: []const u8) []const u8 {
    if (win_path.len == 0) return "";

    var temp_buf: [1024]u8 = undefined;
    if (win_path.len > temp_buf.len) return win_path;

    // First: Normalize backslashes to slashes
    for (win_path, 0..) |c, i| {
        temp_buf[i] = if (c == '\\') '/' else c;
    }
    const current_len: usize = win_path.len;
    var norm_slice = temp_buf[0..current_len];

    // Check special devices case-insensitively
    if (std.ascii.eqlIgnoreCase(win_path, "NUL")) {
        const dst = "/dev/null";
        @memcpy(out[0..dst.len], dst);
        return out[0..dst.len];
    }
    if (std.ascii.eqlIgnoreCase(win_path, "CON")) {
        const dst = "/dev/tty";
        @memcpy(out[0..dst.len], dst);
        return out[0..dst.len];
    }

    // Check named pipe prefix
    if (std.mem.startsWith(u8, norm_slice, "//./pipe/")) {
        const pipe_name = norm_slice["//./pipe/".len..];
        const res = std.fmt.bufPrint(out, "/tmp/{s}.sock", .{pipe_name}) catch return win_path;
        return res;
    }

    // Match and replace canonical prefixes
    for (CANONICAL_PATH_MAPPINGS) |mapping| {
        var win_p_norm: [256]u8 = undefined;
        const mlen = mapping.win_prefix.len;
        if (mlen <= win_p_norm.len) {
            for (mapping.win_prefix, 0..) |mc, mi| {
                win_p_norm[mi] = if (mc == '\\') '/' else mc;
            }
            const norm_prefix = win_p_norm[0..mlen];
            if (current_len >= mlen and std.ascii.eqlIgnoreCase(norm_slice[0..mlen], norm_prefix)) {
                const rest = norm_slice[mlen..];
                const res = std.fmt.bufPrint(out, "{s}{s}", .{ mapping.lin_prefix, rest }) catch return win_path;
                return cleanSlashes(res);
            }
        }
    }

    // Check AppData under C:/Users/<user>/AppData/...
    if (std.mem.startsWith(u8, norm_slice, "C:/Users/") or std.mem.startsWith(u8, norm_slice, "c:/Users/")) {
        const after_users = norm_slice["C:/Users/".len..];
        if (std.mem.indexOfScalar(u8, after_users, '/')) |slash_idx| {
            const user = after_users[0..slash_idx];
            const sub = after_users[slash_idx..];
            if (std.mem.startsWith(u8, sub, "/AppData/Roaming")) {
                const rest = sub["/AppData/Roaming".len..];
                const res = std.fmt.bufPrint(out, "/home/{s}/.config{s}", .{ user, rest }) catch return win_path;
                return cleanSlashes(res);
            } else if (std.mem.startsWith(u8, sub, "/AppData/Local")) {
                const rest = sub["/AppData/Local".len..];
                const res = std.fmt.bufPrint(out, "/home/{s}/.local/share{s}", .{ user, rest }) catch return win_path;
                return cleanSlashes(res);
            } else {
                const res = std.fmt.bufPrint(out, "/home/{s}{s}", .{ user, sub }) catch return win_path;
                return cleanSlashes(res);
            }
        }
    }

    // Strip generic drive letter like C:/, D:/, Z:/
    if (norm_slice.len >= 2 and norm_slice[1] == ':') {
        const rest = if (norm_slice.len >= 3 and norm_slice[2] == '/') norm_slice[2..] else norm_slice[2..];
        if (rest.len == 0) {
            out[0] = '/';
            return out[0..1];
        }
        @memcpy(out[0..rest.len], rest);
        return cleanSlashes(out[0..rest.len]);
    }

    // General relative or unix path: copy and normalize slashes
    @memcpy(out[0..norm_slice.len], norm_slice);
    return cleanSlashes(out[0..norm_slice.len]);
}

fn cleanSlashes(path: []u8) []u8 {
    if (path.len == 0) return path;
    var w: usize = 0;
    var prev_slash = false;
    for (path) |c| {
        if (c == '/') {
            if (!prev_slash) {
                path[w] = '/';
                w += 1;
                prev_slash = true;
            }
        } else {
            path[w] = c;
            w += 1;
            prev_slash = false;
        }
    }
    return path[0..w];
}

// ---------------------------------------------------------------------------
// 2. Command Translation & CLI De-layering
// ---------------------------------------------------------------------------

pub const MAX_ARGS = 32;

pub const TranslatedCommand = struct {
    args_storage: [MAX_ARGS][256]u8 = undefined,
    argv: [MAX_ARGS + 1]?[*:0]const u8 = .{null} ** (MAX_ARGS + 1),
    argc: usize = 0,
    matched_rule: []const u8 = "passthrough",

    pub fn addArg(self: *TranslatedCommand, arg: []const u8) bool {
        if (self.argc >= MAX_ARGS) return false;
        const copy_len = @min(arg.len, 255);
        @memcpy(self.args_storage[self.argc][0..copy_len], arg[0..copy_len]);
        self.args_storage[self.argc][copy_len] = 0;
        self.argv[self.argc] = @ptrCast(&self.args_storage[self.argc]);
        self.argc += 1;
        self.argv[self.argc] = null;
        return true;
    }
};

/// Translates a Windows command-line string into an equivalent Linux command vector.
/// De-layers "cmd.exe /c", maps utilities (dir -> ls, copy -> cp, tasklist -> ps, etc.),
/// and normalizes any path arguments embedded in the invocation.
pub fn translateCommandLine(cmdline: []const u8) TranslatedCommand {
    var result = TranslatedCommand{};
    const trimmed = std.mem.trim(u8, cmdline, " \t\r\n");
    if (trimmed.len == 0) return result;

    // Tokenize arguments while respecting quoted strings
    var tokens: [MAX_ARGS][]const u8 = undefined;
    var n_tokens: usize = 0;

    var i: usize = 0;
    while (i < trimmed.len and n_tokens < MAX_ARGS) {
        while (i < trimmed.len and (trimmed[i] == ' ' or trimmed[i] == '\t')) : (i += 1) {}
        if (i >= trimmed.len) break;

        var start = i;
        var in_quote = false;
        if (trimmed[i] == '"') {
            in_quote = true;
            start += 1;
            i += 1;
        }
        while (i < trimmed.len) {
            if (in_quote) {
                if (trimmed[i] == '"') {
                    break;
                }
            } else {
                if (trimmed[i] == ' ' or trimmed[i] == '\t') break;
            }
            i += 1;
        }
        const token = trimmed[start..i];
        tokens[n_tokens] = token;
        n_tokens += 1;
        if (in_quote and i < trimmed.len and trimmed[i] == '"') {
            i += 1;
        }
    }

    if (n_tokens == 0) return result;

    // Step 1: Strip "cmd.exe /c" or "cmd /c" wrapper if present
    var cur_idx: usize = 0;
    const first = tokens[0];
    const is_cmd = std.ascii.eqlIgnoreCase(first, "cmd.exe") or std.ascii.eqlIgnoreCase(first, "cmd");
    if (is_cmd and n_tokens > 1) {
        if (std.ascii.eqlIgnoreCase(tokens[1], "/c") or std.ascii.eqlIgnoreCase(tokens[1], "/k")) {
            cur_idx = 2;
        }
    }

    if (cur_idx >= n_tokens) {
        _ = result.addArg("sh");
        result.matched_rule = "cmd_interactive_shell";
        return result;
    }

    const verb = tokens[cur_idx];
    cur_idx += 1;
    const remaining = tokens[cur_idx..n_tokens];

    // Step 2: Match against the 1:1 Command Rulebook
    if (std.ascii.eqlIgnoreCase(verb, "dir")) {
        result.matched_rule = "dir_to_ls";
        _ = result.addArg("ls");
        var has_one = false;
        for (remaining) |arg| {
            if (std.ascii.eqlIgnoreCase(arg, "/b")) {
                if (!has_one) {
                    _ = result.addArg("-1");
                    has_one = true;
                }
            } else if (std.ascii.eqlIgnoreCase(arg, "/s")) {
                _ = result.addArg("-R");
            } else if (std.ascii.eqlIgnoreCase(arg, "/a")) {
                _ = result.addArg("-a");
            } else if (!std.mem.startsWith(u8, arg, "/")) {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "copy")) {
        result.matched_rule = "copy_to_cp";
        _ = result.addArg("cp");
        for (remaining) |arg| {
            if (std.ascii.eqlIgnoreCase(arg, "/y") or std.ascii.eqlIgnoreCase(arg, "/b")) {
                // Ignore Windows binary/overwrite flags
            } else {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "xcopy") or std.ascii.eqlIgnoreCase(verb, "robocopy")) {
        result.matched_rule = "xcopy_to_cp_r";
        _ = result.addArg("cp");
        _ = result.addArg("-r");
        for (remaining) |arg| {
            if (!std.mem.startsWith(u8, arg, "/")) {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "move")) {
        result.matched_rule = "move_to_mv";
        _ = result.addArg("mv");
        for (remaining) |arg| {
            if (!std.ascii.eqlIgnoreCase(arg, "/y")) {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "del") or std.ascii.eqlIgnoreCase(verb, "erase")) {
        result.matched_rule = "del_to_rm";
        _ = result.addArg("rm");
        _ = result.addArg("-f");
        for (remaining) |arg| {
            if (!std.mem.startsWith(u8, arg, "/")) {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "type")) {
        result.matched_rule = "type_to_cat";
        _ = result.addArg("cat");
        for (remaining) |arg| {
            var norm_buf: [512]u8 = undefined;
            _ = result.addArg(normalizePath(&norm_buf, arg));
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "md") or std.ascii.eqlIgnoreCase(verb, "mkdir")) {
        result.matched_rule = "mkdir_to_mkdir_p";
        _ = result.addArg("mkdir");
        _ = result.addArg("-p");
        for (remaining) |arg| {
            var norm_buf: [512]u8 = undefined;
            _ = result.addArg(normalizePath(&norm_buf, arg));
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "rd") or std.ascii.eqlIgnoreCase(verb, "rmdir")) {
        result.matched_rule = "rmdir_to_rm_rf";
        _ = result.addArg("rm");
        _ = result.addArg("-rf");
        for (remaining) |arg| {
            if (!std.mem.startsWith(u8, arg, "/")) {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "echo")) {
        result.matched_rule = "echo_to_echo";
        _ = result.addArg("echo");
        for (remaining) |arg| {
            _ = result.addArg(arg);
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "where")) {
        result.matched_rule = "where_to_which";
        _ = result.addArg("which");
        for (remaining) |arg| {
            _ = result.addArg(arg);
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "findstr")) {
        result.matched_rule = "findstr_to_grep";
        _ = result.addArg("grep");
        for (remaining) |arg| {
            if (std.ascii.eqlIgnoreCase(arg, "/i")) {
                _ = result.addArg("-i");
            } else if (std.ascii.eqlIgnoreCase(arg, "/s")) {
                _ = result.addArg("-r");
            } else {
                var norm_buf: [512]u8 = undefined;
                _ = result.addArg(normalizePath(&norm_buf, arg));
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "tasklist")) {
        result.matched_rule = "tasklist_to_ps";
        _ = result.addArg("ps");
        _ = result.addArg("aux");
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "taskkill")) {
        result.matched_rule = "taskkill_to_kill";
        var has_im = false;
        var target: []const u8 = "";
        for (remaining, 0..) |arg, idx| {
            if (std.ascii.eqlIgnoreCase(arg, "/im") and idx + 1 < remaining.len) {
                has_im = true;
                target = remaining[idx + 1];
            } else if (std.ascii.eqlIgnoreCase(arg, "/pid") and idx + 1 < remaining.len) {
                target = remaining[idx + 1];
            }
        }
        if (has_im) {
            _ = result.addArg("pkill");
            _ = result.addArg("-f");
            _ = result.addArg(target);
        } else {
            _ = result.addArg("kill");
            _ = result.addArg("-9");
            _ = result.addArg(target);
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "ipconfig")) {
        result.matched_rule = "ipconfig_to_ip_addr";
        _ = result.addArg("ip");
        _ = result.addArg("addr");
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "netstat")) {
        result.matched_rule = "netstat_to_ss";
        _ = result.addArg("ss");
        _ = result.addArg("-tulpn");
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "ping")) {
        result.matched_rule = "ping_to_ping";
        _ = result.addArg("ping");
        var pidx: usize = 0;
        while (pidx < remaining.len) : (pidx += 1) {
            if (std.ascii.eqlIgnoreCase(remaining[pidx], "-n") and pidx + 1 < remaining.len) {
                _ = result.addArg("-c");
                _ = result.addArg(remaining[pidx + 1]);
                pidx += 1;
            } else {
                _ = result.addArg(remaining[pidx]);
            }
        }
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "whoami")) {
        result.matched_rule = "whoami_to_whoami";
        _ = result.addArg("whoami");
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "hostname")) {
        result.matched_rule = "hostname_to_hostname";
        _ = result.addArg("hostname");
        return result;
    }

    if (std.ascii.eqlIgnoreCase(verb, "ver")) {
        result.matched_rule = "ver_to_uname";
        _ = result.addArg("uname");
        _ = result.addArg("-a");
        return result;
    }

    // Default Passthrough: normalize any paths in the command
    result.matched_rule = "passthrough_normalized";
    var base_buf: [512]u8 = undefined;
    _ = result.addArg(normalizePath(&base_buf, verb));
    for (remaining) |arg| {
        var norm_buf: [512]u8 = undefined;
        _ = result.addArg(normalizePath(&norm_buf, arg));
    }
    return result;
}

// ---------------------------------------------------------------------------
// 3. Automated Subprocess Execution & Oracle Capturing
// ---------------------------------------------------------------------------

pub const ExecutionResult = struct {
    exit_code: u32 = 0,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
};

/// Executes a translated command vector inside the current Linux cleanroom
/// and returns its captured stdout, stderr, and exit code.
pub fn executeTranslated(
    allocator: std.mem.Allocator,
    cmd: *const TranslatedCommand,
) !ExecutionResult {
    if (cmd.argc == 0) return ExecutionResult{ .exit_code = 0 };

    var slice_args = try allocator.alloc([]const u8, cmd.argc);
    defer allocator.free(slice_args);

    for (0..cmd.argc) |idx| {
        const c_str = cmd.argv[idx].?;
        slice_args[idx] = std.mem.span(c_str);
    }

    var child = std.process.Child.init(slice_args, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    const stdout = try child.stdout.?.readToEndAlloc(allocator, 1024 * 1024);
    const stderr = try child.stderr.?.readToEndAlloc(allocator, 1024 * 1024);

    const term = try child.wait();
    const code: u32 = switch (term) {
        .Exited => |c| c,
        else => 1,
    };

    return ExecutionResult{
        .exit_code = code,
        .stdout = stdout,
        .stderr = stderr,
    };
}

// ---------------------------------------------------------------------------
// 4. Embedded Verification Unit Tests
// ---------------------------------------------------------------------------

test "wins_graph: normalizePath canonical mappings" {
    var buf: [512]u8 = undefined;

    // Special Devices
    try std.testing.expectEqualStrings("/dev/null", normalizePath(&buf, "NUL"));
    try std.testing.expectEqualStrings("/dev/null", normalizePath(&buf, "nul"));
    try std.testing.expectEqualStrings("/dev/tty", normalizePath(&buf, "CON"));

    // Named Pipes
    try std.testing.expectEqualStrings("/tmp/mypipe.sock", normalizePath(&buf, "\\\\.\\pipe\\mypipe"));
    try std.testing.expectEqualStrings("/tmp/socket2.sock", normalizePath(&buf, "//./pipe/socket2"));

    // System32 and Windows
    try std.testing.expectEqualStrings("/usr/lib/kernel32.dll", normalizePath(&buf, "C:\\Windows\\System32\\kernel32.dll"));
    try std.testing.expectEqualStrings("/usr/notepad.exe", normalizePath(&buf, "C:\\Windows\\notepad.exe"));

    // Temp & Environment
    try std.testing.expectEqualStrings("/tmp/test.tmp", normalizePath(&buf, "%TEMP%\\test.tmp"));
    try std.testing.expectEqualStrings("/home/user/.config/app/cfg.ini", normalizePath(&buf, "%APPDATA%\\app\\cfg.ini"));
    try std.testing.expectEqualStrings("/home/user/.local/share/app/db.sqlite", normalizePath(&buf, "%LOCALAPPDATA%\\app\\db.sqlite"));

    // Users directory
    try std.testing.expectEqualStrings("/home/alice/.config/app.json", normalizePath(&buf, "C:\\Users\\alice\\AppData\\Roaming\\app.json"));
    try std.testing.expectEqualStrings("/home/bob/.local/share/data.bin", normalizePath(&buf, "C:\\Users\\bob\\AppData\\Local\\data.bin"));
    try std.testing.expectEqualStrings("/home/carol/Documents/doc.txt", normalizePath(&buf, "C:\\Users\\carol\\Documents\\doc.txt"));

    // Generic Drive letter
    try std.testing.expectEqualStrings("/opt/vendor/app.exe", normalizePath(&buf, "C:\\Program Files\\vendor\\app.exe"));
    try std.testing.expectEqualStrings("/var/lib/data.dat", normalizePath(&buf, "C:\\ProgramData\\data.dat"));
    try std.testing.expectEqualStrings("/foo/bar/baz.txt", normalizePath(&buf, "D:\\foo\\bar\\baz.txt"));
}

test "wins_graph: translateCommandLine cmd.exe de-layering" {
    // dir /b
    const t1 = translateCommandLine("cmd.exe /c dir /b C:\\Windows");
    try std.testing.expectEqualStrings("dir_to_ls", t1.matched_rule);
    try std.testing.expectEqual(@as(usize, 3), t1.argc);
    try std.testing.expectEqualStrings("ls", std.mem.span(t1.argv[0].?));
    try std.testing.expectEqualStrings("-1", std.mem.span(t1.argv[1].?));
    try std.testing.expectEqualStrings("/usr", std.mem.span(t1.argv[2].?));

    // copy /y
    const t2 = translateCommandLine("cmd /c copy /y \"C:\\Users\\test\\a.txt\" \"C:\\Users\\test\\b.txt\"");
    try std.testing.expectEqualStrings("copy_to_cp", t2.matched_rule);
    try std.testing.expectEqual(@as(usize, 3), t2.argc);
    try std.testing.expectEqualStrings("cp", std.mem.span(t2.argv[0].?));
    try std.testing.expectEqualStrings("/home/test/a.txt", std.mem.span(t2.argv[1].?));
    try std.testing.expectEqualStrings("/home/test/b.txt", std.mem.span(t2.argv[2].?));

    // del /f /q
    const t3 = translateCommandLine("del /f /q C:\\Windows\\Temp\\junk.dat");
    try std.testing.expectEqualStrings("del_to_rm", t3.matched_rule);
    try std.testing.expectEqualStrings("rm", std.mem.span(t3.argv[0].?));
    try std.testing.expectEqualStrings("-f", std.mem.span(t3.argv[1].?));
    try std.testing.expectEqualStrings("/var/tmp/junk.dat", std.mem.span(t3.argv[2].?));

    // type
    const t4 = translateCommandLine("type C:\\Windows\\System32\\drivers\\etc\\hosts");
    try std.testing.expectEqualStrings("type_to_cat", t4.matched_rule);
    try std.testing.expectEqualStrings("cat", std.mem.span(t4.argv[0].?));
    try std.testing.expectEqualStrings("/usr/lib/drivers/etc/hosts", std.mem.span(t4.argv[1].?));

    // taskkill
    const t5 = translateCommandLine("taskkill /f /im test.exe");
    try std.testing.expectEqualStrings("taskkill_to_kill", t5.matched_rule);
    try std.testing.expectEqualStrings("pkill", std.mem.span(t5.argv[0].?));
    try std.testing.expectEqualStrings("-f", std.mem.span(t5.argv[1].?));
    try std.testing.expectEqualStrings("test.exe", std.mem.span(t5.argv[2].?));

    // ping
    const t6 = translateCommandLine("ping -n 4 127.0.0.1");
    try std.testing.expectEqualStrings("ping_to_ping", t6.matched_rule);
    try std.testing.expectEqualStrings("ping", std.mem.span(t6.argv[0].?));
    try std.testing.expectEqualStrings("-c", std.mem.span(t6.argv[1].?));
    try std.testing.expectEqualStrings("4", std.mem.span(t6.argv[2].?));
    try std.testing.expectEqualStrings("127.0.0.1", std.mem.span(t6.argv[3].?));
}
