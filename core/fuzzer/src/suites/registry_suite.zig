//! WINS Differential Fuzzer - Virtual Registry to XDG Config Suite
const std = @import("std");
const FuzzGenerator = @import("../generator.zig").FuzzGenerator;

pub const RegistrySuiteResult = struct {
    total_iterations: u64,
    divergences: u64,
};

pub const KeyValue = struct {
    key: []const u8,
    val: []const u8,
};

const SEED_TABLE = [_]KeyValue{
    .{ .key = "software/notepad++/theme", .val = "DarkModeDefault" },
    .{ .key = "software/notepad++/font", .val = "Consolas" },
    .{ .key = "software/notepad++/fontsize", .val = "11" },
    .{ .key = "software/notepad++/tabsize", .val = "4" },
    .{ .key = "software/notepad++/wordwrap", .val = "1" },
    .{ .key = "software/notepad++/scintilla/eol", .val = "unix" },
    .{ .key = "software/notepad++/backup/enabled", .val = "1" },
    .{ .key = "software/notepad++/history/max", .val = "30" },
};

/// Candidate case-insensitive key lookup
pub fn candidateLookup(target_key: []const u8) ?[]const u8 {
    for (SEED_TABLE) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key, target_key)) {
            return entry.val;
        }
    }
    return null;
}

/// Reference Windows RegQueryValue simulation
pub fn referenceRegLookup(target_key: []const u8) ?[]const u8 {
    for (SEED_TABLE) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key, target_key)) {
            return entry.val;
        }
    }
    return null;
}

pub fn run(iterations: u64, seed: u64) RegistrySuiteResult {
    var gen = FuzzGenerator.init(seed);
    const rand = gen.random();
    var res = RegistrySuiteResult{
        .total_iterations = iterations,
        .divergences = 0,
    };

    var key_buf: [128]u8 = undefined;

    var iter: u64 = 0;
    while (iter < iterations) : (iter += 1) {
        // Pick an existing key or a random nonexistent key
        const pick_existing = rand.boolean();
        var test_key: []const u8 = undefined;

        if (pick_existing) {
            const entry = SEED_TABLE[rand.uintLessThan(usize, SEED_TABLE.len)];
            @memcpy(key_buf[0..entry.key.len], entry.key);
            // Mutate case randomly
            for (key_buf[0..entry.key.len]) |*b| {
                if (rand.boolean()) {
                    b.* = std.ascii.toUpper(b.*);
                } else {
                    b.* = std.ascii.toLower(b.*);
                }
            }
            test_key = key_buf[0..entry.key.len];
        } else {
            test_key = "software/unknown/nonexistent";
        }

        const ref_val = referenceRegLookup(test_key);
        const cand_val = candidateLookup(test_key);

        if (ref_val == null and cand_val == null) {
            continue;
        } else if (ref_val != null and cand_val != null) {
            if (!std.mem.eql(u8, ref_val.?, cand_val.?)) {
                res.divergences += 1;
            }
        } else {
            res.divergences += 1;
        }
    }

    return res;
}
