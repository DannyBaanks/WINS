//! WINS Differential Fuzzer - Windows Path Security & Anomalies Suite
//! Tests handling of DOS device names, Alternate Data Streams (ADS),
//! trailing dots/spaces, and traversal sanitization on Linux.

const std = @import("std");
const generator = @import("../generator.zig");
const FuzzGenerator = generator.FuzzGenerator;

pub const SecuritySuiteResult = struct {
    total_iterations: u64,
    divergences: u64,
    dos_devices_caught: u64 = 0,
    ads_streams_caught: u64 = 0,
    trailing_chars_trimmed: u64 = 0,
};

const DOS_DEVICES = [_][]const u8{
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
};

/// Checks if a segment base name (without extension) matches a DOS reserved device
pub fn isDosDevice(segment: []const u8) bool {
    // Strip extension if present: "CON.txt" -> "CON"
    var base = segment;
    if (std.mem.indexOfScalar(u8, segment, '.')) |dot_idx| {
        base = segment[0..dot_idx];
    }
    // Also trim trailing spaces: "COM1 " -> "COM1"
    while (base.len > 0 and base[base.len - 1] == ' ') {
        base = base[0 .. base.len - 1];
    }

    for (DOS_DEVICES) |dev| {
        if (std.ascii.eqlIgnoreCase(base, dev)) {
            return true;
        }
    }
    return false;
}

/// Candidate Linux Sanitizer & Path Normalizer
pub fn sanitizeWindowsPathForLinux(in_path: []const u8, out_buf: []u8) []const u8 {
    var src = in_path;
    var out_pos: usize = 0;

    // 1. Strip Extended Length / UNC prefixes: \\?\ or \\.\ or \??\
    if (src.len >= 4 and ((src[0] == '\\' and src[1] == '\\' and (src[2] == '?' or src[2] == '.') and src[3] == '\\') or
        (src[0] == '\\' and src[1] == '?' and src[2] == '?' and src[3] == '\\')))
    {
        src = src[4..];
    }

    // 2. Strip Drive Letter (e.g. C:\)
    if (src.len >= 2 and std.ascii.isAlphabetic(src[0]) and src[1] == ':') {
        src = src[2..];
        if (src.len > 0 and (src[0] == '\\' or src[0] == '/')) {
            src = src[1..];
        }
    }

    // 3. Process path segment by segment
    var start_idx: usize = 0;
    var i: usize = 0;

    while (i <= src.len) : (i += 1) {
        const is_end = (i == src.len);
        const is_sep = if (!is_end) (src[i] == '\\' or src[i] == '/') else false;

        if (is_sep or is_end) {
            var segment = src[start_idx..i];

            if (segment.len > 0 and !std.mem.eql(u8, segment, ".")) {
                // Check Alternate Data Stream (ADS): "file.txt:stream"
                var stream_name: ?[]const u8 = null;
                if (std.mem.indexOfScalar(u8, segment, ':')) |colon_idx| {
                    stream_name = segment[colon_idx + 1 ..];
                    segment = segment[0..colon_idx];
                }

                // Trim trailing dots and spaces (Win32 behavior)
                while (segment.len > 0 and (segment[segment.len - 1] == '.' or segment[segment.len - 1] == ' ')) {
                    segment = segment[0 .. segment.len - 1];
                }

                if (segment.len > 0) {
                    // Check DOS device collision
                    const is_dos = isDosDevice(segment);

                    if (out_pos > 0 and out_buf[out_pos - 1] != '/' and out_pos < out_buf.len) {
                        out_buf[out_pos] = '/';
                        out_pos += 1;
                    }

                    if (is_dos) {
                        const safe_prefix = "_win_";
                        if (out_pos + safe_prefix.len < out_buf.len) {
                            @memcpy(out_buf[out_pos .. out_pos + safe_prefix.len], safe_prefix);
                            out_pos += safe_prefix.len;
                        }
                    }

                    if (out_pos + segment.len < out_buf.len) {
                        @memcpy(out_buf[out_pos .. out_pos + segment.len], segment);
                        out_pos += segment.len;
                    }

                    // If ADS exists, append safe suffix if not Zone.Identifier
                    if (stream_name) |st| {
                        if (!std.ascii.startsWithIgnoreCase(st, "Zone.Identifier") and
                            !std.ascii.startsWithIgnoreCase(st, "$DATA"))
                        {
                            const ads_suffix = ".stream_";
                            if (out_pos + ads_suffix.len + st.len < out_buf.len) {
                                @memcpy(out_buf[out_pos .. out_pos + ads_suffix.len], ads_suffix);
                                out_pos += ads_suffix.len;
                                @memcpy(out_buf[out_pos .. out_pos + st.len], st);
                                out_pos += st.len;
                            }
                        }
                    }
                }
            }
            start_idx = i + 1;
        }
    }

    if (out_pos == 0 and out_buf.len > 0) {
        out_buf[0] = '.';
        out_pos = 1;
    }

    return out_buf[0..out_pos];
}

/// Reference Win32 Validator: Verifies whether the Linux sanitized path conforms to safety invariants:
/// 1. No DOS devices as raw file components.
/// 2. No unescaped colons (ADS streams).
/// 3. No trailing dots or spaces at the end of path segments.
/// 4. No backslashes remaining.
pub fn verifySafetyInvariants(sanitized_path: []const u8) bool {
    var iter = std.mem.splitScalar(u8, sanitized_path, '/');
    while (iter.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;

        // Invariant 1: No raw DOS devices
        for (DOS_DEVICES) |dev| {
            var base = segment;
            if (std.mem.indexOfScalar(u8, segment, '.')) |dot_idx| {
                base = segment[0..dot_idx];
            }
            if (std.ascii.eqlIgnoreCase(base, dev)) {
                return false; // Divergence: raw DOS device slipped through!
            }
        }

        // Invariant 2: No colons (ADS vulnerability on POSIX)
        if (std.mem.indexOfScalar(u8, segment, ':') != null) {
            return false;
        }

        // Invariant 3: No trailing dots or spaces
        if (segment[segment.len - 1] == '.' or segment[segment.len - 1] == ' ') {
            return false;
        }
    }

    // Invariant 4: No backslashes
    if (std.mem.indexOfScalar(u8, sanitized_path, '\\') != null) {
        return false;
    }

    return true;
}

pub fn run(iterations: u64, seed: u64) SecuritySuiteResult {
    var gen = FuzzGenerator.init(seed);
    var res = SecuritySuiteResult{
        .total_iterations = iterations,
        .divergences = 0,
    };

    var in_buf: [512]u8 = undefined;
    var out_buf: [512]u8 = undefined;

    var iter: u64 = 0;
    while (iter < iterations) : (iter += 1) {
        const sec_path = gen.generateSecurityPath(&in_buf);
        const sanitized = sanitizeWindowsPathForLinux(sec_path, &out_buf);

        // Track what was fuzzed
        if (std.mem.indexOf(u8, sec_path, "CON") != null or
            std.mem.indexOf(u8, sec_path, "AUX") != null or
            std.mem.indexOf(u8, sec_path, "PRN") != null or
            std.mem.indexOf(u8, sec_path, "NUL") != null or
            std.mem.indexOf(u8, sec_path, "COM") != null or
            std.mem.indexOf(u8, sec_path, "LPT") != null)
        {
            res.dos_devices_caught += 1;
        }

        if (std.mem.indexOfScalar(u8, sec_path, ':')) |c_idx| {
            if (c_idx > 1) { // ADS colon after drive
                res.ads_streams_caught += 1;
            }
        }

        if (sec_path.len > 0 and (sec_path[sec_path.len - 1] == '.' or sec_path[sec_path.len - 1] == ' ')) {
            res.trailing_chars_trimmed += 1;
        }

        // Check safety invariants
        if (!verifySafetyInvariants(sanitized)) {
            res.divergences += 1;
        }
    }

    return res;
}
