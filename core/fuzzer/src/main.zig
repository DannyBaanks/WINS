//! WINS High-Performance Differential Fuzzing Engine in Zig
//! Verifies functional equivalence between Windows runtime behaviors and
//! native Linux transpilations with zero operating system emulation.

const std = @import("std");
const path_suite = @import("suites/path_suite.zig");
const encoding_suite = @import("suites/encoding_suite.zig");
const registry_suite = @import("suites/registry_suite.zig");
const pixel_suite = @import("suites/pixel_suite.zig");
const path_security_suite = @import("suites/path_security_suite.zig");
const buffer_suite = @import("suites/buffer_suite.zig");

pub fn getTimestampNs() i128 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + ts.nsec;
}

pub fn printDirect(bytes: []const u8) void {
    _ = std.os.linux.write(1, bytes.ptr, bytes.len);
}

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.vector;

    var suite_name: []const u8 = "all";
    var iterations: u64 = 100_000;
    var seed: u64 = 1337;
    var json_output: bool = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = std.mem.span(args[i]);
        if (std.mem.eql(u8, arg, "--suite") and i + 1 < args.len) {
            i += 1;
            suite_name = std.mem.span(args[i]);
        } else if (std.mem.eql(u8, arg, "--iterations") and i + 1 < args.len) {
            i += 1;
            iterations = std.fmt.parseInt(u64, std.mem.span(args[i]), 10) catch 100_000;
        } else if (std.mem.eql(u8, arg, "--seed") and i + 1 < args.len) {
            i += 1;
            seed = std.fmt.parseInt(u64, std.mem.span(args[i]), 10) catch 1337;
        } else if (std.mem.eql(u8, arg, "--json")) {
            json_output = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printDirect(
                \\WINS High-Performance Differential Fuzzer (Zig Engine)
                \\Usage: wins-fuzz [options]
                \\
                \\Options:
                \\  --suite <all|path|encoding|registry|pixel|security|buffer>
                \\                        Select test suite (default: all)
                \\  --iterations <N>      Number of fuzz iterations per suite (default: 100000)
                \\  --seed <S>            Deterministic PRNG seed (default: 1337)
                \\  --json                Output machine-readable JSON for AI agents
                \\  --help, -h            Show this help message
                \\
            );
            return;
        }
    }

    const t0 = getTimestampNs();

    var path_res = path_suite.PathSuiteResult{ .total_iterations = 0, .divergences = 0 };
    var enc_res = encoding_suite.EncodingSuiteResult{ .total_iterations = 0, .divergences = 0, .transcoded_bytes = 0 };
    var reg_res = registry_suite.RegistrySuiteResult{ .total_iterations = 0, .divergences = 0 };
    var pix_res = pixel_suite.PixelSuiteResult{ .total_iterations = 0, .divergences = 0 };
    var sec_res = path_security_suite.SecuritySuiteResult{ .total_iterations = 0, .divergences = 0 };
    var buf_res = buffer_suite.BufferSuiteResult{ .total_iterations = 0, .divergences = 0 };

    const run_all = std.mem.eql(u8, suite_name, "all");

    if (run_all or std.mem.eql(u8, suite_name, "path")) {
        path_res = path_suite.run(iterations, seed);
    }
    if (run_all or std.mem.eql(u8, suite_name, "encoding")) {
        enc_res = encoding_suite.run(iterations, seed + 1);
    }
    if (run_all or std.mem.eql(u8, suite_name, "registry")) {
        reg_res = registry_suite.run(iterations, seed + 2);
    }
    if (run_all or std.mem.eql(u8, suite_name, "pixel")) {
        pix_res = pixel_suite.run(iterations, seed + 3);
    }
    if (run_all or std.mem.eql(u8, suite_name, "security")) {
        sec_res = path_security_suite.run(iterations, seed + 4);
    }
    if (run_all or std.mem.eql(u8, suite_name, "buffer")) {
        buf_res = buffer_suite.run(iterations, seed + 5);
    }

    const t1 = getTimestampNs();
    const elapsed_ns = t1 - t0;
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const total_ops = path_res.total_iterations + enc_res.total_iterations + reg_res.total_iterations +
        pix_res.total_iterations + sec_res.total_iterations + buf_res.total_iterations;
    const ops_per_sec = if (elapsed_ms > 0) (@as(f64, @floatFromInt(total_ops)) / (elapsed_ms / 1000.0)) else 0;
    const total_divergences = path_res.divergences + enc_res.divergences + reg_res.divergences +
        pix_res.divergences + sec_res.divergences + buf_res.divergences;

    if (json_output) {
        var json_buf: [4096]u8 = undefined;
        const json_slice = std.fmt.bufPrint(&json_buf,
            \\{{
            \\  "engine": "WINS Differential Fuzzer (Zig)",
            \\  "status": "{s}",
            \\  "total_iterations": {d},
            \\  "total_divergences": {d},
            \\  "duration_ms": {d:.2},
            \\  "ops_per_sec": {d:.0},
            \\  "suites": {{
            \\    "path_normalization": {{
            \\      "iterations": {d},
            \\      "divergences": {d}
            \\    }},
            \\    "utf16_utf8_transcoding": {{
            \\      "iterations": {d},
            \\      "divergences": {d},
            \\      "transcoded_bytes": {d}
            \\    }},
            \\    "virtual_registry": {{
            \\      "iterations": {d},
            \\      "divergences": {d}
            \\    }},
            \\    "pixel_graphics_math": {{
            \\      "iterations": {d},
            \\      "divergences": {d},
            \\      "max_delta": {d}
            \\    }},
            \\    "path_security_anomalies": {{
            \\      "iterations": {d},
            \\      "divergences": {d},
            \\      "dos_devices_caught": {d},
            \\      "ads_streams_caught": {d},
            \\      "trailing_trimmed": {d}
            \\    }},
            \\    "scintilla_text_buffer": {{
            \\      "iterations": {d},
            \\      "divergences": {d},
            \\      "lines_indexed": {d},
            \\      "multibyte_queries": {d}
            \\    }}
            \\  }}
            \\}}
            \\
        , .{
            if (total_divergences == 0) "EQUIVALENCE_PROVEN" else "DIVERGENCE_DETECTED",
            total_ops,
            total_divergences,
            elapsed_ms,
            ops_per_sec,
            path_res.total_iterations,
            path_res.divergences,
            enc_res.total_iterations,
            enc_res.divergences,
            enc_res.transcoded_bytes,
            reg_res.total_iterations,
            reg_res.divergences,
            pix_res.total_iterations,
            pix_res.divergences,
            pix_res.max_delta,
            sec_res.total_iterations,
            sec_res.divergences,
            sec_res.dos_devices_caught,
            sec_res.ads_streams_caught,
            sec_res.trailing_chars_trimmed,
            buf_res.total_iterations,
            buf_res.divergences,
            buf_res.lines_indexed,
            buf_res.multibyte_queries,
        }) catch "{}";

        printDirect(json_slice);
        return;
    }

    var term_buf: [4096]u8 = undefined;
    const term_slice = std.fmt.bufPrint(&term_buf,
        \\
        \\⚡ WINS DIFFERENTIAL FUZZER (ZIG ENGINE)
        \\========================================================================
        \\  Status:            {s}
        \\  Total Iterations:  {d}
        \\  Divergences:       {d}
        \\  Execution Time:    {d:.2} ms ({d:.0} ops/sec)
        \\
        \\  [DIFFERENTIAL SUITE BREAKDOWN]
        \\  * Path Normalizer:       {d} iterations, {d} divergences
        \\  * UTF-16/8 Transcoder:   {d} iterations, {d} divergences ({d} bytes)
        \\  * Virtual Registry:      {d} iterations, {d} divergences
        \\  * Pixel Graphics Math:   {d} iterations, {d} divergences (Direct2D/HLSL)
        \\  * Path Security / ADS:   {d} iterations, {d} divergences (DOS/UNC sanitized)
        \\  * Scintilla Text Buffer: {d} iterations, {d} divergences ({d} lines indexed)
        \\========================================================================
        \\
    , .{
        if (total_divergences == 0) "EQUIVALENCE_PROVEN (Zero Divergences)" else "DIVERGENCE_DETECTED",
        total_ops,
        total_divergences,
        elapsed_ms,
        ops_per_sec,
        path_res.total_iterations,
        path_res.divergences,
        enc_res.total_iterations,
        enc_res.divergences,
        enc_res.transcoded_bytes,
        reg_res.total_iterations,
        reg_res.divergences,
        pix_res.total_iterations,
        pix_res.divergences,
        sec_res.total_iterations,
        sec_res.divergences,
        buf_res.total_iterations,
        buf_res.divergences,
        buf_res.lines_indexed,
    }) catch "Error formatting output";

    printDirect(term_slice);
}
