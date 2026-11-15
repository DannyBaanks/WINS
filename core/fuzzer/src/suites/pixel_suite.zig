//! WINS Differential Fuzzer - Direct2D & ComputeSharp Pixel Math Suite
//! Validates graphics math equivalence between Windows Direct2D/HLSL shaders
//! (as used in Paint.NET) and Linux native software/SIMD/shader blitters.

const std = @import("std");
const generator = @import("../generator.zig");
const FuzzGenerator = generator.FuzzGenerator;
const RgbaPixel = generator.RgbaPixel;

pub const PixelSuiteResult = struct {
    total_iterations: u64,
    divergences: u64,
    max_delta: u8 = 0,
};

pub const BlendMode = enum(u8) {
    normal,
    multiply,
    screen,
    overlay,
    darken,
    lighten,
    additive,
    difference,
};

/// Reference Direct2D Straight to Premultiplied Alpha
pub fn refPremultiplyChannel(c: u8, a: u8) u8 {
    const prod: u32 = @as(u32, c) * @as(u32, a) + 127;
    return @as(u8, @intCast(prod / 255));
}

/// Candidate Linux High-Performance Premultiply (Pixman/Cairo fast integer approximation)
/// Formula: (t + (t >> 8)) >> 8 where t = c * a + 128
pub fn candPremultiplyChannel(c: u8, a: u8) u8 {
    const t: u32 = @as(u32, c) * @as(u32, a) + 128;
    return @as(u8, @intCast((t + (t >> 8)) >> 8));
}

/// Reference Direct2D Unpremultiply
pub fn refUnpremultiplyChannel(pr: u8, a: u8) u8 {
    if (a == 0) return 0;
    const num: u32 = @as(u32, pr) * 255 + (@as(u32, a) / 2);
    const res = num / @as(u32, a);
    return @as(u8, @intCast(@min(255, res)));
}

/// Candidate Linux Unpremultiply
pub fn candUnpremultiplyChannel(pr: u8, a: u8) u8 {
    if (a == 0) return 0;
    const num: u32 = @as(u32, pr) * 255 + (@as(u32, a) / 2);
    const res = num / @as(u32, a);
    return @as(u8, @intCast(@min(255, res)));
}

/// Reference Direct2D / Paint.NET Blend Mode (Integer Reference)
pub fn refBlendChannel(src: u8, dst: u8, mode: BlendMode) u8 {
    return switch (mode) {
        .normal => src,
        .multiply => @as(u8, @intCast((@as(u32, src) * @as(u32, dst) + 127) / 255)),
        .screen => blk: {
            const inv_src = 255 - @as(u32, src);
            const inv_dst = 255 - @as(u32, dst);
            const prod = (inv_src * inv_dst + 127) / 255;
            break :blk @as(u8, @intCast(255 - prod));
        },
        .overlay => blk: {
            if (dst < 128) {
                const prod = (2 * @as(u32, src) * @as(u32, dst) + 127) / 255;
                break :blk @as(u8, @intCast(@min(255, prod)));
            } else {
                const inv_src = 255 - @as(u32, src);
                const inv_dst = 255 - @as(u32, dst);
                const prod = (2 * inv_src * inv_dst + 127) / 255;
                break :blk @as(u8, @intCast(255 - @min(255, prod)));
            }
        },
        .darken => @min(src, dst),
        .lighten => @max(src, dst),
        .additive => @as(u8, @intCast(@min(255, @as(u32, src) + @as(u32, dst)))),
        .difference => if (src >= dst) src - dst else dst - src,
    };
}

/// Candidate Linux Blend Mode (SIMD-ready integer arithmetic)
pub fn candBlendChannel(src: u8, dst: u8, mode: BlendMode) u8 {
    return switch (mode) {
        .normal => src,
        .multiply => blk: {
            const t = @as(u32, src) * @as(u32, dst) + 128;
            break :blk @as(u8, @intCast((t + (t >> 8)) >> 8));
        },
        .screen => blk: {
            const inv_s = 255 - @as(u32, src);
            const inv_d = 255 - @as(u32, dst);
            const t = inv_s * inv_d + 128;
            const prod = (t + (t >> 8)) >> 8;
            break :blk @as(u8, @intCast(255 - prod));
        },
        .overlay => blk: {
            if (dst < 128) {
                const t = 2 * @as(u32, src) * @as(u32, dst) + 128;
                const prod = (t + (t >> 8)) >> 8;
                break :blk @as(u8, @intCast(@min(255, prod)));
            } else {
                const inv_s = 255 - @as(u32, src);
                const inv_d = 255 - @as(u32, dst);
                const t = 2 * inv_s * inv_d + 128;
                const prod = (t + (t >> 8)) >> 8;
                break :blk @as(u8, @intCast(255 - @min(255, prod)));
            }
        },
        .darken => @min(src, dst),
        .lighten => @max(src, dst),
        .additive => @as(u8, @intCast(@min(255, @as(u32, src) + @as(u32, dst)))),
        .difference => if (src >= dst) src - dst else dst - src,
    };
}

/// ComputeSharp HLSL Float4 Pixel Shader Simulation
pub fn hlslShaderBlendFloat(src: f32, dst: f32, mode: BlendMode) f32 {
    return switch (mode) {
        .normal => src,
        .multiply => src * dst,
        .screen => 1.0 - (1.0 - src) * (1.0 - dst),
        .overlay => if (dst < 0.5) (2.0 * src * dst) else (1.0 - 2.0 * (1.0 - src) * (1.0 - dst)),
        .darken => @min(src, dst),
        .lighten => @max(src, dst),
        .additive => @min(1.0, src + dst),
        .difference => @abs(src - dst),
    };
}

pub fn run(iterations: u64, seed: u64) PixelSuiteResult {
    var gen = FuzzGenerator.init(seed);
    const rand = gen.random();
    var res = PixelSuiteResult{
        .total_iterations = iterations,
        .divergences = 0,
        .max_delta = 0,
    };

    var iter: u64 = 0;
    while (iter < iterations) : (iter += 1) {
        const test_case = rand.uintLessThan(u8, 4);

        switch (test_case) {
            // Case 0: Premultiply equivalence between Direct2D reference and Pixman candidate
            0 => {
                const c = gen.generateByteWithBoundaries();
                const a = gen.generateByteWithBoundaries();

                const ref_val = refPremultiplyChannel(c, a);
                const cand_val = candPremultiplyChannel(c, a);

                if (ref_val != cand_val) {
                    res.divergences += 1;
                    const delta: u8 = if (ref_val > cand_val) ref_val - cand_val else cand_val - ref_val;
                    if (delta > res.max_delta) res.max_delta = delta;
                }
            },
            // Case 1: Unpremultiply roundtrip equivalence
            1 => {
                const c = gen.generateByteWithBoundaries();
                const a = gen.generateByteWithBoundaries();

                if (a == 255) {
                    // When fully opaque, premultiply then unpremultiply must be an exact identity
                    const pr = candPremultiplyChannel(c, a);
                    const unpr = candUnpremultiplyChannel(pr, a);
                    if (unpr != c) {
                        res.divergences += 1;
                    }
                } else if (a > 0) {
                    const ref_pr = refPremultiplyChannel(c, a);
                    const cand_pr = candPremultiplyChannel(c, a);
                    const ref_unpr = refUnpremultiplyChannel(ref_pr, a);
                    const cand_unpr = candUnpremultiplyChannel(cand_pr, a);

                    if (ref_unpr != cand_unpr) {
                        const delta: u8 = if (ref_unpr > cand_unpr) ref_unpr - cand_unpr else cand_unpr - ref_unpr;
                        if (delta > 1) { // Tolerate at most 1 LSB quantization difference
                            res.divergences += 1;
                        }
                    }
                }
            },
            // Case 2: Blend Modes (Integer Reference vs SIMD Candidate)
            2 => {
                const src = gen.generateByteWithBoundaries();
                const dst = gen.generateByteWithBoundaries();
                const mode_int = rand.uintLessThan(u8, 8);
                const mode: BlendMode = @enumFromInt(mode_int);

                const ref_res = refBlendChannel(src, dst, mode);
                const cand_res = candBlendChannel(src, dst, mode);

                if (ref_res != cand_res) {
                    const delta: u8 = if (ref_res > cand_res) ref_res - cand_res else cand_res - ref_res;
                    if (delta > 1) { // Flag any deviation greater than 1 LSB
                        res.divergences += 1;
                    }
                }
            },
            // Case 3: Direct2D Integer vs ComputeSharp HLSL Float32 Shader
            3 => {
                const src = gen.generateByteWithBoundaries();
                const dst = gen.generateByteWithBoundaries();
                const mode_int = rand.uintLessThan(u8, 8);
                const mode: BlendMode = @enumFromInt(mode_int);

                const int_res = candBlendChannel(src, dst, mode);

                const src_f = @as(f32, @floatFromInt(src)) / 255.0;
                const dst_f = @as(f32, @floatFromInt(dst)) / 255.0;
                const float_res = hlslShaderBlendFloat(src_f, dst_f, mode);
                const float_res_u8 = @as(u8, @intFromFloat(@round(@min(1.0, @max(0.0, float_res)) * 255.0)));

                if (int_res != float_res_u8) {
                    const delta: u8 = if (int_res > float_res_u8) int_res - float_res_u8 else float_res_u8 - int_res;
                    // In real-world GPU shaders, float vs integer rounding can differ by at most 1 unit
                    if (delta > 1) {
                        res.divergences += 1;
                    }
                }
            },
            else => {},
        }
    }

    return res;
}
