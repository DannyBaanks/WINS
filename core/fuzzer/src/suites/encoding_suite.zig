//! WINS Differential Fuzzer - UTF-16LE <-> UTF-8 Transcoding Suite
const std = @import("std");
const FuzzGenerator = @import("../generator.zig").FuzzGenerator;

pub const EncodingSuiteResult = struct {
    total_iterations: u64,
    divergences: u64,
    transcoded_bytes: u64,
    counter_example_in: [256]u8 = [_]u8{0} ** 256,
    counter_example_in_len: usize = 0,
};

pub fn run(iterations: u64, seed: u64) EncodingSuiteResult {
    var gen = FuzzGenerator.init(seed);
    var res = EncodingSuiteResult{
        .total_iterations = iterations,
        .divergences = 0,
        .transcoded_bytes = 0,
    };

    var in_buf: [512]u8 = undefined;
    var utf16_buf: [512]u16 = undefined;
    var roundtrip_buf: [1024]u8 = undefined;

    var iter: u64 = 0;
    while (iter < iterations) : (iter += 1) {
        const utf8_input = gen.generateUtf8String(&in_buf);
        res.transcoded_bytes += utf8_input.len;

        // 1. Candidate Transcoding to UTF-16LE
        const u16_len = std.unicode.utf8ToUtf16Le(&utf16_buf, utf8_input) catch {
            // Invalid UTF-8 sequence generated
            continue;
        };

        // 2. Candidate Transcoding back to UTF-8
        const u8_len = std.unicode.utf16LeToUtf8(&roundtrip_buf, utf16_buf[0..u16_len]) catch {
            res.divergences += 1;
            continue;
        };

        const roundtrip_slice = roundtrip_buf[0..u8_len];

        // 3. Differential Equivalence Check
        if (!std.mem.eql(u8, utf8_input, roundtrip_slice)) {
            res.divergences += 1;
            if (res.counter_example_in_len == 0) {
                const copy_len = @min(utf8_input.len, res.counter_example_in.len);
                @memcpy(res.counter_example_in[0..copy_len], utf8_input[0..copy_len]);
                res.counter_example_in_len = copy_len;
            }
        }
    }

    return res;
}
