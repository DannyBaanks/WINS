//! Software BGRX32 GDI framebuffer, bitmap/DC state, and 8x8->8x16 raster font.
const std = @import("std");

pub const Surface = struct {
    width: u32 = 0,
    height: u32 = 0,
    pixels: []u32 = &.{},

    pub fn ensure(self: *Surface, w_in: i32, h_in: i32, bg_xrgb: u32) bool {
        if (w_in <= 0 or h_in <= 0) return false;
        const w: u32 = @intCast(@min(w_in, 4096));
        const h: u32 = @intCast(@min(h_in, 4096));
        if (self.width == w and self.height == h and self.pixels.len == @as(usize, w) * h) {
            return true;
        }
        const need: usize = @as(usize, w) * h;
        const next = std.heap.page_allocator.alloc(u32, need) catch return false;
        @memset(next, bg_xrgb);
        if (self.pixels.len > 0) {
            const copy_w = @min(w, self.width);
            const copy_h = @min(h, self.height);
            var row: u32 = 0;
            while (row < copy_h) : (row += 1) {
                const dst_off = @as(usize, row) * w;
                const src_off = @as(usize, row) * self.width;
                @memcpy(next[dst_off .. dst_off + copy_w], self.pixels[src_off .. src_off + copy_w]);
            }
            std.heap.page_allocator.free(self.pixels);
        }
        self.width = w;
        self.height = h;
        self.pixels = next;
        return true;
    }

    pub fn deinit(self: *Surface) void {
        if (self.pixels.len > 0) {
            std.heap.page_allocator.free(self.pixels);
        }
        self.* = .{};
    }

    pub fn bytesPtr(self: *const Surface) ?[*]u8 {
        if (self.pixels.len == 0) return null;
        return @ptrCast(self.pixels.ptr);
    }
};

pub const Clip = struct {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
};

pub fn colorrefToXrgb(cr: u32) u32 {
    const r = cr & 0xff;
    const g = (cr >> 8) & 0xff;
    const b = (cr >> 16) & 0xff;
    return (r << 16) | (g << 8) | b;
}

pub fn putPixelClipped(s: *Surface, clip: Clip, x: i32, y: i32, xrgb: u32) void {
    if (s.pixels.len == 0) return;
    const w: i32 = @intCast(s.width);
    const h: i32 = @intCast(s.height);
    if (x < 0 or y < 0 or x >= w or y >= h) return;
    if (x < clip.left or y < clip.top or x >= clip.right or y >= clip.bottom) return;
    s.pixels[@as(usize, @intCast(y)) * s.width + @as(usize, @intCast(x))] = xrgb;
}

pub fn fillRect(s: *Surface, clip: Clip, l: i32, t: i32, r: i32, b: i32, xrgb: u32) void {
    if (s.pixels.len == 0) return;
    const sw: i32 = @intCast(s.width);
    const sh: i32 = @intCast(s.height);
    const x0 = @max(@max(l, clip.left), 0);
    const y0 = @max(@max(t, clip.top), 0);
    const x1 = @min(@min(r, clip.right), sw);
    const y1 = @min(@min(b, clip.bottom), sh);
    if (x0 >= x1 or y0 >= y1) return;
    var y: i32 = y0;
    while (y < y1) : (y += 1) {
        const row = @as(usize, @intCast(y)) * s.width;
        @memset(s.pixels[row + @as(usize, @intCast(x0)) .. row + @as(usize, @intCast(x1))], xrgb);
    }
}

pub fn frameRect(s: *Surface, clip: Clip, l: i32, t: i32, r: i32, b: i32, xrgb: u32) void {
    if (l >= r or t >= b) return;
    fillRect(s, clip, l, t, r, t + 1, xrgb);
    fillRect(s, clip, l, b - 1, r, b, xrgb);
    fillRect(s, clip, l, t, l + 1, b, xrgb);
    fillRect(s, clip, r - 1, t, r, b, xrgb);
}

pub fn drawLine(s: *Surface, clip: Clip, x0_in: i32, y0_in: i32, x1: i32, y1: i32, xrgb: u32) void {
    var x0 = x0_in;
    var y0 = y0_in;
    const dx: i32 = @intCast(@abs(x1 - x0));
    const sx: i32 = if (x0 < x1) 1 else -1;
    const dy: i32 = -@as(i32, @intCast(@abs(y1 - y0)));
    const sy: i32 = if (y0 < y1) 1 else -1;
    var err: i32 = dx + dy;
    var steps: usize = 0;
    while (steps < 16384) : (steps += 1) {
        putPixelClipped(s, clip, x0, y0, xrgb);
        if (x0 == x1 and y0 == y1) break;
        const e2 = 2 * err;
        if (e2 >= dy) {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx) {
            err += dx;
            y0 += sy;
        }
    }
}

pub fn blitCopy(
    dst: *Surface,
    clip: Clip,
    dx: i32,
    dy: i32,
    w: i32,
    h: i32,
    src: *const Surface,
    sx: i32,
    sy: i32,
    rop: u32,
) void {
    if (dst.pixels.len == 0 or w <= 0 or h <= 0) return;
    if (rop == 0x00000042) { // BLACKNESS
        fillRect(dst, clip, dx, dy, dx + w, dy + h, 0x000000);
        return;
    }
    if (rop == 0x00FF0062) { // WHITENESS
        fillRect(dst, clip, dx, dy, dx + w, dy + h, 0xFFFFFF);
        return;
    }
    if (src.pixels.len == 0) return;
    const sw: i32 = @intCast(src.width);
    const sh: i32 = @intCast(src.height);
    const dw: i32 = @intCast(dst.width);
    const dh: i32 = @intCast(dst.height);

    var row: i32 = 0;
    while (row < h) : (row += 1) {
        const py = dy + row;
        const qy = sy + row;
        if (py < clip.top or py >= clip.bottom or py < 0 or py >= dh) continue;
        if (qy < 0 or qy >= sh) continue;
        const x_start = @max(@max(0, clip.left - dx), @max(-dx, -sx));
        const x_end = @min(@min(w, clip.right - dx), @min(dw - dx, sw - sx));
        if (x_start >= x_end) continue;
        const dst_off = @as(usize, @intCast(py)) * dst.width + @as(usize, @intCast(dx + x_start));
        const src_off = @as(usize, @intCast(qy)) * src.width + @as(usize, @intCast(sx + x_start));
        const count: usize = @intCast(x_end - x_start);
        if (rop == 0x00660046) { // SRCINVERT
            for (0..count) |k| dst.pixels[dst_off + k] ^= src.pixels[src_off + k];
        } else if (rop == 0x008800C6) { // SRCAND
            for (0..count) |k| dst.pixels[dst_off + k] &= src.pixels[src_off + k];
        } else if (rop == 0x00EE0086) { // SRCPAINT
            for (0..count) |k| dst.pixels[dst_off + k] |= src.pixels[src_off + k];
        } else {
            @memcpy(dst.pixels[dst_off .. dst_off + count], src.pixels[src_off .. src_off + count]);
        }
    }
}

// Compact 8x8 ASCII bitmap font (printable 0x20..0x7E), MSB = leftmost pixel.
// Drawn vertically doubled into 8x14 / 8x16 cells so text matches tmHeight=16 cleanly.
const FONT8X8: [95][8]u8 = .{
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // ' '
    .{ 0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00 }, // '!'
    .{ 0x6C, 0x6C, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00 }, // '"'
    .{ 0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00 }, // '#'
    .{ 0x18, 0x7E, 0xC0, 0x7C, 0x06, 0xFC, 0x18, 0x00 }, // '$'
    .{ 0x00, 0xC6, 0xCC, 0x18, 0x30, 0x66, 0xC6, 0x00 }, // '%'
    .{ 0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00 }, // '&'
    .{ 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00 }, // '''
    .{ 0x18, 0x30, 0x60, 0x60, 0x60, 0x30, 0x18, 0x00 }, // '('
    .{ 0x60, 0x30, 0x18, 0x18, 0x18, 0x30, 0x60, 0x00 }, // ')'
    .{ 0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00 }, // '*'
    .{ 0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00 }, // '+'
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30 }, // ','
    .{ 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00 }, // '-'
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00 }, // '.'
    .{ 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00 }, // '/'
    .{ 0x7C, 0xC6, 0xCE, 0xDE, 0xF6, 0xE6, 0x7C, 0x00 }, // '0'
    .{ 0x30, 0x70, 0x30, 0x30, 0x30, 0x30, 0xFC, 0x00 }, // '1'
    .{ 0x7C, 0xC6, 0x06, 0x3C, 0x60, 0xC0, 0xFE, 0x00 }, // '2'
    .{ 0x7C, 0xC6, 0x06, 0x3C, 0x06, 0xC6, 0x7C, 0x00 }, // '3'
    .{ 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x0C, 0x00 }, // '4'
    .{ 0xFE, 0xC0, 0xFC, 0x06, 0x06, 0xC6, 0x7C, 0x00 }, // '5'
    .{ 0x38, 0x60, 0xC0, 0xFC, 0xC6, 0xC6, 0x7C, 0x00 }, // '6'
    .{ 0xFE, 0xC6, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00 }, // '7'
    .{ 0x7C, 0xC6, 0xC6, 0x7C, 0xC6, 0xC6, 0x7C, 0x00 }, // '8'
    .{ 0x7C, 0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0x78, 0x00 }, // '9'
    .{ 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00 }, // ':'
    .{ 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30 }, // ';'
    .{ 0x18, 0x30, 0x60, 0xC0, 0x60, 0x30, 0x18, 0x00 }, // '<'
    .{ 0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00 }, // '='
    .{ 0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00 }, // '>'
    .{ 0x7C, 0xC6, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x00 }, // '?'
    .{ 0x7C, 0xC6, 0xDE, 0xDE, 0xDE, 0xC0, 0x7C, 0x00 }, // '@'
    .{ 0x38, 0x6C, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00 }, // 'A'
    .{ 0xFC, 0xC6, 0xC6, 0xFC, 0xC6, 0xC6, 0xFC, 0x00 }, // 'B'
    .{ 0x7C, 0xC6, 0xC0, 0xC0, 0xC0, 0xC6, 0x7C, 0x00 }, // 'C'
    .{ 0xF8, 0xCC, 0xC6, 0xC6, 0xC6, 0xCC, 0xF8, 0x00 }, // 'D'
    .{ 0xFE, 0xC0, 0xC0, 0xFC, 0xC0, 0xC0, 0xFE, 0x00 }, // 'E'
    .{ 0xFE, 0xC0, 0xC0, 0xFC, 0xC0, 0xC0, 0xC0, 0x00 }, // 'F'
    .{ 0x7C, 0xC6, 0xC0, 0xCE, 0xC6, 0xC6, 0x7E, 0x00 }, // 'G'
    .{ 0xC6, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00 }, // 'H'
    .{ 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00 }, // 'I'
    .{ 0x3E, 0x0C, 0x0C, 0x0C, 0xCC, 0xCC, 0x78, 0x00 }, // 'J'
    .{ 0xC6, 0xCC, 0xD8, 0xF0, 0xD8, 0xCC, 0xC6, 0x00 }, // 'K'
    .{ 0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xFE, 0x00 }, // 'L'
    .{ 0xC6, 0xEE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0x00 }, // 'M'
    .{ 0xC6, 0xE6, 0xF6, 0xDE, 0xCE, 0xC6, 0xC6, 0x00 }, // 'N'
    .{ 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00 }, // 'O'
    .{ 0xFC, 0xC6, 0xC6, 0xFC, 0xC0, 0xC0, 0xC0, 0x00 }, // 'P'
    .{ 0x7C, 0xC6, 0xC6, 0xC6, 0xD6, 0xCC, 0x76, 0x00 }, // 'Q'
    .{ 0xFC, 0xC6, 0xC6, 0xFC, 0xD8, 0xCC, 0xC6, 0x00 }, // 'R'
    .{ 0x7C, 0xC6, 0xC0, 0x7C, 0x06, 0xC6, 0x7C, 0x00 }, // 'S'
    .{ 0xFE, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00 }, // 'T'
    .{ 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00 }, // 'U'
    .{ 0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x10, 0x00 }, // 'V'
    .{ 0xC6, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0x00 }, // 'W'
    .{ 0xC6, 0x6C, 0x38, 0x38, 0x6C, 0xC6, 0xC6, 0x00 }, // 'X'
    .{ 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00 }, // 'Y'
    .{ 0xFE, 0x06, 0x0C, 0x38, 0x60, 0xC0, 0xFE, 0x00 }, // 'Z'
    .{ 0x7C, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7C, 0x00 }, // '['
    .{ 0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00 }, // '\'
    .{ 0x7C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x7C, 0x00 }, // ']'
    .{ 0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00 }, // '^'
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00 }, // '_'
    .{ 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00 }, // '`'
    .{ 0x00, 0x00, 0x7C, 0x06, 0x7E, 0xC6, 0x7E, 0x00 }, // 'a'
    .{ 0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xFC, 0x00 }, // 'b'
    .{ 0x00, 0x00, 0x7C, 0xC6, 0xC0, 0xC6, 0x7C, 0x00 }, // 'c'
    .{ 0x06, 0x06, 0x7E, 0xC6, 0xC6, 0xC6, 0x7E, 0x00 }, // 'd'
    .{ 0x00, 0x00, 0x7C, 0xC6, 0xFE, 0xC0, 0x7C, 0x00 }, // 'e'
    .{ 0x1C, 0x36, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x00 }, // 'f'
    .{ 0x00, 0x00, 0x7E, 0xC6, 0xC6, 0x7E, 0x06, 0x7C }, // 'g'
    .{ 0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x00 }, // 'h'
    .{ 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00 }, // 'i'
    .{ 0x0C, 0x00, 0x1C, 0x0C, 0x0C, 0xCC, 0xCC, 0x78 }, // 'j'
    .{ 0xC0, 0xC0, 0xCC, 0xD8, 0xF0, 0xD8, 0xCC, 0x00 }, // 'k'
    .{ 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00 }, // 'l'
    .{ 0x00, 0x00, 0xEC, 0xFE, 0xD6, 0xC6, 0xC6, 0x00 }, // 'm'
    .{ 0x00, 0x00, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x00 }, // 'n'
    .{ 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0x00 }, // 'o'
    .{ 0x00, 0x00, 0xFC, 0xC6, 0xC6, 0xFC, 0xC0, 0xC0 }, // 'p'
    .{ 0x00, 0x00, 0x7E, 0xC6, 0xC6, 0x7E, 0x06, 0x06 }, // 'q'
    .{ 0x00, 0x00, 0xDC, 0xE6, 0xC0, 0xC0, 0xC0, 0x00 }, // 'r'
    .{ 0x00, 0x00, 0x7E, 0xC0, 0x7C, 0x06, 0xFC, 0x00 }, // 's'
    .{ 0x30, 0x30, 0x7C, 0x30, 0x30, 0x36, 0x1C, 0x00 }, // 't'
    .{ 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0x7E, 0x00 }, // 'u'
    .{ 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x00 }, // 'v'
    .{ 0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xFE, 0x6C, 0x00 }, // 'w'
    .{ 0x00, 0x00, 0xC6, 0x6C, 0x38, 0x6C, 0xC6, 0x00 }, // 'x'
    .{ 0x00, 0x00, 0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0x78 }, // 'y'
    .{ 0x00, 0x00, 0xFE, 0x0C, 0x38, 0x60, 0xFE, 0x00 }, // 'z'
    .{ 0x1C, 0x30, 0x30, 0xE0, 0x30, 0x30, 0x1C, 0x00 }, // '{'
    .{ 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00 }, // '|'
    .{ 0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00 }, // '}'
    .{ 0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // '~'
};

fn asciiGlyph(ch: u8) [8]u8 {
    return FONT8X8[(if (ch >= 0x20 and ch <= 0x7e) ch else '?') - 0x20];
}

/// 8x16 cell: the 8x8 ASCII glyph with every row doubled.
fn doubled(g: [8]u8) [16]u8 {
    var out: [16]u8 = undefined;
    for (g, 0..) |r, i| {
        out[2 * i] = r;
        out[2 * i + 1] = r;
    }
    return out;
}

const Mark = enum { none, grave, acute, circ, tilde, diaer, ring, cedilla };

/// Two 1-px rows drawn above the letter.
fn markRows(m: Mark) [2]u8 {
    return switch (m) {
        .grave => .{ 0x30, 0x18 },
        .acute => .{ 0x0C, 0x18 },
        .circ => .{ 0x38, 0x6C },
        .tilde => .{ 0x76, 0xDC },
        .diaer => .{ 0x6C, 0x6C },
        .ring => .{ 0x38, 0x28 },
        .none, .cedilla => .{ 0, 0 },
    };
}

/// Latin-1 letter -> ASCII base + diacritic.
fn decompose(c: u16) ?struct { base: u8, mark: Mark } {
    const M = Mark;
    const a6 = [_]M{ .grave, .acute, .circ, .tilde, .diaer, .ring };
    const e4 = [_]M{ .grave, .acute, .circ, .diaer };
    const o5 = [_]M{ .grave, .acute, .circ, .tilde, .diaer };
    const lower: u8 = if (c >= 0xE0) 0x20 else 0;
    const u = if (c >= 0xE0) c - 0x20 else c;
    return switch (u) {
        0xC0...0xC5 => .{ .base = 'A' + lower, .mark = a6[u - 0xC0] },
        0xC6 => .{ .base = 'A' + lower, .mark = .none }, // Æ
        0xC7 => .{ .base = 'C' + lower, .mark = .cedilla },
        0xC8...0xCB => .{ .base = 'E' + lower, .mark = e4[u - 0xC8] },
        0xCC...0xCF => .{ .base = 'I' + lower, .mark = e4[u - 0xCC] },
        0xD0 => .{ .base = 'D' + lower, .mark = .none },
        0xD1 => .{ .base = 'N' + lower, .mark = .tilde },
        0xD2...0xD6 => .{ .base = 'O' + lower, .mark = o5[u - 0xD2] },
        0xD8 => .{ .base = 'O' + lower, .mark = .none },
        0xD9...0xDC => .{ .base = 'U' + lower, .mark = e4[u - 0xD9] },
        0xDD => .{ .base = 'Y' + lower, .mark = .acute },
        0xDE => .{ .base = 'P' + lower, .mark = .none },
        0xDF => if (lower != 0) .{ .base = 'y', .mark = .diaer } else .{ .base = 'B', .mark = .none }, // ÿ / ß
        else => null,
    };
}

fn rotated180(g: [8]u8) [8]u8 {
    var out: [8]u8 = undefined;
    for (g, 0..) |r, i| out[7 - i] = @bitReverse(r);
    return out;
}

/// 8x16 glyph for a UTF-16 unit: ASCII, Latin-1 letters composed from base +
/// diacritic (Spanish/Portuguese/French), ¿ ¡ ° €, typographic punctuation
/// folded to ASCII; anything else is '?'.
pub fn glyph16(c: u16) [16]u8 {
    if (c >= 0x20 and c <= 0x7e) return doubled(asciiGlyph(@intCast(c)));
    switch (c) {
        0xA0 => return doubled(asciiGlyph(' ')),
        0xA1 => return doubled(rotated180(asciiGlyph('!'))),
        0xBF => return doubled(rotated180(asciiGlyph('?'))),
        0xB0 => return doubled(.{ 0x38, 0x6C, 0x38, 0, 0, 0, 0, 0 }),
        0xB4 => return doubled(.{ 0x0C, 0x18, 0, 0, 0, 0, 0, 0 }),
        0xA8 => return doubled(.{ 0x6C, 0, 0, 0, 0, 0, 0, 0 }),
        0xAB => return doubled(.{ 0, 0x36, 0x6C, 0xD8, 0x6C, 0x36, 0, 0 }),
        0xBB => return doubled(.{ 0, 0xD8, 0x6C, 0x36, 0x6C, 0xD8, 0, 0 }),
        0xB7 => return doubled(.{ 0, 0, 0, 0x18, 0, 0, 0, 0 }),
        0xD7 => return doubled(asciiGlyph('x')),
        0xF7 => return doubled(.{ 0, 0x18, 0, 0x7E, 0, 0x18, 0, 0 }),
        0x20AC => return doubled(.{ 0x3C, 0x66, 0xF8, 0x60, 0xF8, 0x66, 0x3C, 0 }),
        0x2018, 0x2019, 0x201A => return doubled(asciiGlyph('\'')),
        0x201C, 0x201D, 0x201E => return doubled(asciiGlyph('"')),
        0x2010...0x2015, 0x2212 => return doubled(asciiGlyph('-')),
        0x2026 => return doubled(.{ 0, 0, 0, 0, 0, 0, 0x92, 0 }),
        0x2022 => return doubled(.{ 0, 0, 0x38, 0x7C, 0x38, 0, 0, 0 }),
        else => {},
    }
    const d = decompose(c) orelse return doubled(asciiGlyph('?'));
    var g = asciiGlyph(d.base);
    if ((d.base | 0x20) == 'i' and d.mark != .none and d.base >= 'a') g[0] = 0; // dotless i under the accent
    if (d.mark == .cedilla) {
        var out = doubled(g);
        out[14] = 0x18;
        out[15] = 0x30;
        return out;
    }
    const mr = markRows(d.mark);
    if (g[0] == 0 and g[1] == 0) { // lowercase: two blank rows (4 px) above the x-height
        var out = doubled(g);
        out[1] = mr[0];
        out[2] = mr[1];
        return out;
    }
    if (d.mark == .none) return doubled(g);
    // capital: accent in px 0-1, gap, then rows 0..6 in 13 px (row 3 single height)
    var out: [16]u8 = @splat(0);
    out[0] = mr[0];
    out[1] = mr[1];
    var py: usize = 3;
    for (g[0..7], 0..) |r, i| {
        out[py] = r;
        py += 1;
        if (i != 3) {
            out[py] = r;
            py += 1;
        }
    }
    return out;
}

pub fn drawChar(s: *Surface, clip: Clip, x: i32, y: i32, ch_u16: u16, fg: u32, bg: ?u32) void {
    const glyph = glyph16(ch_u16);
    for (glyph, 0..) |bits, row| {
        var col: i32 = 0;
        while (col < 8) : (col += 1) {
            const on = (bits & (@as(u8, 0x80) >> @intCast(col))) != 0;
            const py = y + @as(i32, @intCast(row));
            if (on) {
                putPixelClipped(s, clip, x + col, py, fg);
            } else if (bg) |bcol| {
                putPixelClipped(s, clip, x + col, py, bcol);
            }
        }
    }
}

test "glyph16: Spanish letters get their accent, unknown stays '?'" {
    const q = glyph16('?');
    try std.testing.expectEqualSlices(u8, &q, &glyph16(0x4E00)); // CJK -> '?'
    const n = glyph16('n');
    const enye = glyph16(0xF1);
    try std.testing.expectEqualSlices(u8, n[3..], enye[3..]); // body unchanged
    try std.testing.expect(enye[1] != 0 and n[1] == 0); // tilde on top
    try std.testing.expect(!std.mem.eql(u8, &glyph16(0xE1), &glyph16(0xE0))); // á != à
    try std.testing.expect(!std.mem.eql(u8, &glyph16(0xC9), &glyph16('E'))); // É has its accent
    try std.testing.expect(!std.mem.eql(u8, &glyph16(0xBF), &q)); // ¿ is not '?'
}

pub fn drawTextU16(
    s: *Surface,
    clip: Clip,
    x: i32,
    y: i32,
    text: []const u16,
    fg: u32,
    bg: ?u32,
) void {
    var cur_x = x;
    for (text) |ch| {
        if (ch == 0) break;
        if (ch == '\t') {
            if (bg) |bcol| fillRect(s, clip, cur_x, y, cur_x + 32, y + 16, bcol);
            cur_x += 32;
            continue;
        }
        drawChar(s, clip, cur_x, y, ch, fg, bg);
        cur_x += 8;
    }
}

test "surface fillRect, line, blitCopy and glyph draw produce real pixels" {
    var dst: Surface = .{};
    defer dst.deinit();
    try std.testing.expect(dst.ensure(64, 32, 0x00F0F0F0));
    const full = Clip{ .left = 0, .top = 0, .right = 64, .bottom = 32 };
    fillRect(&dst, full, 4, 4, 20, 20, colorrefToXrgb(0x00FF0000)); // Win32 COLORREF blue -> XRGB 0x000000FF
    try std.testing.expectEqual(@as(u32, 0x000000FF), dst.pixels[4 * 64 + 4]);
    drawLine(&dst, full, 0, 0, 10, 0, 0x00112233);
    try std.testing.expectEqual(@as(u32, 0x00112233), dst.pixels[5]);
    const txt = [_]u16{ 'A', '!' };
    drawTextU16(&dst, full, 24, 4, &txt, 0x00010203, null);
    var lit: usize = 0;
    for (4..20) |yy| {
        for (24..40) |xx| {
            if (dst.pixels[yy * 64 + xx] == 0x00010203) lit += 1;
        }
    }
    try std.testing.expect(lit > 10);

    var mem: Surface = .{};
    defer mem.deinit();
    try std.testing.expect(mem.ensure(16, 16, 0x00ABCDEF));
    blitCopy(&dst, full, 40, 8, 8, 8, &mem, 0, 0, 0x00CC0020);
    try std.testing.expectEqual(@as(u32, 0x00ABCDEF), dst.pixels[8 * 64 + 40]);
}
