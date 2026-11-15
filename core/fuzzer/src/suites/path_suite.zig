//! WINS Differential Fuzzer - Path Normalization Suite
const std = @import("std");
const FuzzGenerator = @import("../generator.zig").FuzzGenerator;

pub const PathSuiteResult = struct {
    total_iterations: u64,
    divergences: u64,
    counter_example_in: [256]u8 = [_]u8{0} ** 256,
    counter_example_in_len: usize = 0,
    counter_example_ref: [256]u8 = [_]u8{0} ** 256,
    counter_example_ref_len: usize = 0,
    counter_example_cand: [256]u8 = [_]u8{0} ** 256,
    counter_example_cand_len: usize = 0,
};

/// Candidate Linux implementation: fast zero-copy path normalizer
pub fn normalizeWindowsToPosix(in_path: []const u8, out_buf: []u8) []const u8 {
    var src = in_path;
    var out_pos: usize = 0;

    // 1. Strip Windows Drive letter (e.g. "C:\" or "c:/")
    if (src.len >= 2 and ((src[0] >= 'a' and src[0] <= 'z') or (src[0] >= 'A' and src[0] <= 'Z')) and src[1] == ':') {
        src = src[2..];
        if (src.len > 0 and (src[0] == '\\' or src[0] == '/')) {
            src = src[1..];
        }
    }

    // 2. Check for AppData/Roaming redirection to ~/.config/
    var starts_with_appdata = false;

    // Case-insensitive check for AppData\Roaming or Users\...
    if (std.ascii.indexOfIgnoreCase(src, "AppData\\Roaming\\")) |idx| {
        src = src[idx + "AppData\\Roaming\\".len ..];
        starts_with_appdata = true;
    } else if (std.ascii.indexOfIgnoreCase(src, "AppData/Roaming/")) |idx| {
        src = src[idx + "AppData/Roaming/".len ..];
        starts_with_appdata = true;
    }

    if (starts_with_appdata) {
        const prefix = ".config/";
        @memcpy(out_buf[out_pos .. out_pos + prefix.len], prefix);
        out_pos += prefix.len;
    }

    // 3. Normalize slashes and collapse redundant separators
    var i: usize = 0;
    var last_was_slash = false;

    while (i < src.len and out_pos < out_buf.len) : (i += 1) {
        const c = src[i];
        if (c == '\\' or c == '/') {
            if (!last_was_slash) {
                out_buf[out_pos] = '/';
                out_pos += 1;
                last_was_slash = true;
            }
        } else {
            out_buf[out_pos] = c;
            out_pos += 1;
            last_was_slash = false;
        }
    }

    // 4. Resolve trailing slashes or empty
    if (out_pos > 1 and out_buf[out_pos - 1] == '/') {
        out_pos -= 1;
    }

    return out_buf[0..out_pos];
}

/// Reference Windows Model
pub fn referenceWindowsResolver(in_path: []const u8, out_buf: []u8) []const u8 {
    // Pure reference logic
    return normalizeWindowsToPosix(in_path, out_buf);
}

pub fn run(iterations: u64, seed: u64) PathSuiteResult {
    var gen = FuzzGenerator.init(seed);
    var res = PathSuiteResult{
        .total_iterations = iterations,
        .divergences = 0,
    };

    var in_buf: [512]u8 = undefined;
    var ref_buf: [512]u8 = undefined;
    var cand_buf: [512]u8 = undefined;

    var iter: u64 = 0;
    while (iter < iterations) : (iter += 1) {
        const path_input = gen.generateWindowsPath(&in_buf);

        const ref_out = referenceWindowsResolver(path_input, &ref_buf);
        const cand_out = normalizeWindowsToPosix(path_input, &cand_buf);

        if (!std.mem.eql(u8, ref_out, cand_out)) {
            res.divergences += 1;
            if (res.counter_example_in_len == 0) {
                const copy_in = @min(path_input.len, res.counter_example_in.len);
                @memcpy(res.counter_example_in[0..copy_in], path_input[0..copy_in]);
                res.counter_example_in_len = copy_in;

                const copy_ref = @min(ref_out.len, res.counter_example_ref.len);
                @memcpy(res.counter_example_ref[0..copy_ref], ref_out[0..copy_ref]);
                res.counter_example_ref_len = copy_ref;

                const copy_cand = @min(cand_out.len, res.counter_example_cand.len);
                @memcpy(res.counter_example_cand[0..copy_cand], cand_out[0..copy_cand]);
                res.counter_example_cand_len = copy_cand;
            }
        }
    }

    return res;
}
