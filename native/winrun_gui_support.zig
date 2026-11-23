//! Experimental USER32 subset for synthetic Win32 GUI windows.
//! Supports class registration, WndProc dispatch, window creation, show/update,
//! message queueing, Translate/Dispatch, DefWindowProcW and PostQuitMessage.
const std = @import("std");
const x11 = @import("x11_window.zig");
const gdi = @import("winrun_gdi_fb.zig");
const gl64 = @import("wins_gl_win64.zig");
const kbd = @import("wins_input64_kbd.zig");
const dxmod = @import("winrun_directx.zig");
const dinput = @import("wins_dinput.zig");
const threads = @import("winrun_threads.zig");
const clipboard = @import("winrun_clipboard.zig");
const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

const Rect = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
const Point = extern struct { x: i32, y: i32 };

const WndProcFn = *const fn (usize, u32, usize, usize) callconv(W) usize;

const WNDCLASSEXW = extern struct {
    cbSize: u32,
    style: u32,
    lpfnWndProc: ?WndProcFn,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: ?[*:0]const u16,
    hIconSm: usize,
};

const WNDCLASSW = extern struct {
    style: u32,
    lpfnWndProc: ?WndProcFn,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: usize,
    hIcon: usize,
    hCursor: usize,
    hbrBackground: usize,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: ?[*:0]const u16,
};

const CREATESTRUCTW = extern struct {
    lpCreateParams: usize,
    hInstance: usize,
    hMenu: usize,
    hwndParent: usize,
    cy: i32,
    cx: i32,
    y: i32,
    x: i32,
    style: i32,
    lpszName: ?[*:0]const u16,
    lpszClass: ?[*:0]const u16,
    dwExStyle: u32,
};

const MSG = extern struct {
    hwnd: usize,
    message: u32,
    _pad: u32 = 0,
    wParam: usize,
    lParam: usize,
    time: u32,
    pt: Point,
    lPrivate: u32 = 0,
};

const WM_NULL: u32 = 0x0000;
const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_MOVE: u32 = 0x0003;
const WM_SIZE: u32 = 0x0005;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;
const WM_SHOWWINDOW: u32 = 0x0018;
const WM_ACTIVATE: u32 = 0x0006;
const WM_SETFOCUS: u32 = 0x0007;
const WM_KILLFOCUS: u32 = 0x0008;
const WM_ACTIVATEAPP: u32 = 0x001C;
const WM_NCACTIVATE: u32 = 0x0086;
const WM_NCDESTROY: u32 = 0x0082;

const CW_USEDEFAULT: i32 = @bitCast(@as(u32, 0x80000000));
const WS_POPUP: u32 = 0x80000000;
const WS_CHILD: u32 = 0x40000000;
const WS_VISIBLE: u32 = 0x10000000;
const WS_CAPTION: u32 = 0x00C00000;
const WM_NCCREATE: u32 = 0x0081;
const WM_NCCALCSIZE: u32 = 0x0083;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_SYSCHAR: u32 = 0x0106;
const WM_INPUT: u32 = 0x00FF;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_MBUTTONUP: u32 = 0x0208;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_XBUTTONDOWN: u32 = 0x020B;
const WM_XBUTTONUP: u32 = 0x020C;
const WM_MOUSEHWHEEL: u32 = 0x020E;
const WM_CAPTURECHANGED: u32 = 0x0215;
const WM_GETTEXT: u32 = 0x000D;
const WM_GETTEXTLENGTH: u32 = 0x000E;
const WM_SETTEXT: u32 = 0x000C;

const GWLP_WNDPROC: i32 = -4;
const GWLP_HINSTANCE: i32 = -6;
const GWLP_HWNDPARENT: i32 = -8;
const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const GWLP_USERDATA: i32 = -21;
const GWLP_ID: i32 = -12;

const MAX_WINDOWS = 256;
const WinObj = struct {
    in_use: bool = false,
    hwnd: usize = 0,
    x11_win: x11.Window = 0,
    parent: usize = 0,
    wndproc: ?WndProcFn = null,
    style: u32 = 0,
    ex_style: u32 = 0,
    x: i32 = 0,
    y: i32 = 0,
    width: i32 = 0,
    height: i32 = 0,
    visible: bool = false,
    needs_paint: bool = false,
    has_gl: bool = false,
    fullscreen: bool = false,
    x11_mapped: bool = false,
    x11_fs_applied: bool = false,
    hinstance: usize = 0,
    hmenu: usize = 0,
    userdata: isize = 0,
    id: isize = 0,
    extra: [16]isize = [_]isize{0} ** 16,
    title: [256]u16 = [_]u16{0} ** 256,
    title_len: usize = 0,
    class_name: [64]u16 = [_]u16{0} ** 64,
    class_len: usize = 0,
    tab_lparam: usize = 0,
    tab_item_w: i32 = 80,
    tab_item_h: i32 = 24,
    tab_count: u32 = 0,
    tb_btn_count: u32 = 0,
    /// Toolbar buttons from TB_ADDBUTTONSW: command id and whether it is a separator.
    tb_ids: [64]i32 = [_]i32{0} ** 64,
    tb_sep: [64]bool = [_]bool{false} ** 64,
    tb_known: u32 = 0,
    tb_owner: usize = 0,
    tb_pressed: i32 = -1,
    sb_parts_n: usize = 0,
    sb_parts_right: [8]i32 = [_]i32{0} ** 8,
    sb_text: [8][64]u16 = [_][64]u16{[_]u16{0} ** 64} ** 8,
    sb_text_len: [8]usize = [_]usize{0} ** 8,
};

fn winClassEqAscii(w: *const WinObj, ascii: []const u8) bool {
    if (w.class_len != ascii.len) return false;
    for (0..ascii.len) |i| {
        const c1 = w.class_name[i];
        const c2 = ascii[i];
        const l1 = if (c1 >= 'A' and c1 <= 'Z') c1 + 32 else c1;
        const l2 = if (c2 >= 'A' and c2 <= 'Z') @as(u16, c2) + 32 else @as(u16, c2);
        if (l1 != l2) return false;
    }
    return true;
}

fn winScreenPos(hwnd: usize) Point {
    var cur = findWin(hwnd) orelse return .{ .x = 0, .y = 0 };
    var ox: i32 = cur.x;
    var oy: i32 = cur.y;
    var hops: usize = 0;
    while (hops < 16 and (cur.style & WS_CHILD) != 0 and cur.parent != 0) : (hops += 1) {
        const p = findWin(cur.parent) orelse break;
        ox += p.x;
        oy += p.y;
        cur = p;
    }
    return .{ .x = ox, .y = oy };
}

var connection: ?x11.Connection = null;
var wm_delete_atom: c_ulong = 0;
var windows: [MAX_WINDOWS]WinObj = [_]WinObj{.{}} ** MAX_WINDOWS;
var next_synth_hwnd: usize = 0x200010;

const SubclassProcFn = *const fn (usize, u32, usize, usize, usize, usize) callconv(W) usize;
const MAX_SUBCLASSES = 128;
const SubclassEntry = struct {
    in_use: bool = false,
    hwnd: usize = 0,
    proc: SubclassProcFn = undefined,
    id: usize = 0,
    ref_data: usize = 0,
};
var subclasses: [MAX_SUBCLASSES]SubclassEntry = [_]SubclassEntry{.{}} ** MAX_SUBCLASSES;
var active_subclass_idx: ?usize = null;

var win_surfaces: [MAX_WINDOWS]gdi.Surface = [_]gdi.Surface{.{}} ** MAX_WINDOWS;

const HBRUSH_BASE: usize = 0xB1000000;
const HPEN_BASE: usize = 0xB2000000;
const HBITMAP_BASE: usize = 0xB3000000;
const HDC_BASE: usize = 0xD0000000;

const HRGN_BASE: usize = 0xB4000000;

const GdiBrush = struct { in_use: bool = false, xrgb: u32 = 0xFFFFFF, is_null: bool = false, sticky: bool = false };
const GdiPen = struct { in_use: bool = false, xrgb: u32 = 0x000000, width: i32 = 1, is_null: bool = false, sticky: bool = false };
const GdiBitmap = struct {
    in_use: bool = false,
    sticky: bool = false,
    bottom_up: bool = false,
    bpp: u16 = 32,
    surface: gdi.Surface = .{},
    /// Bits handed to the application for non-32bpp DIB sections. Their pixels are
    /// NOT modelled by the software rasterizer (blits from them draw nothing).
    raw: []u8 = &.{},
};
const GdiRegion = struct { in_use: bool = false, rect: gdi.Clip = .{ .left = 0, .top = 0, .right = 0, .bottom = 0 } };
const GdiDC = struct {
    in_use: bool = false,
    hwnd: usize = 0,
    is_mem: bool = false,
    is_screen: bool = false,
    hbitmap: usize = 0,
    hbrush: usize = 0,
    hpen: usize = 0,
    hfont: usize = 0,
    bk_xrgb: u32 = 0xFFFFFF,
    text_xrgb: u32 = 0x000000,
    bk_mode: i32 = 2, // OPAQUE
    text_align: u32 = 0,
    cur_x: i32 = 0,
    cur_y: i32 = 0,
    org_x: i32 = 0,
    org_y: i32 = 0,
    has_clip: bool = false,
    clip: gdi.Clip = .{ .left = 0, .top = 0, .right = 4096, .bottom = 4096 },
    rop2: i32 = 13,
};
const SavedDCState = struct { in_use: bool = false, hdc: usize = 0, level: i32 = 0, dc: GdiDC = .{} };

var gdi_brushes: [1024]GdiBrush = [_]GdiBrush{.{}} ** 1024;
var gdi_pens: [1024]GdiPen = [_]GdiPen{.{}} ** 1024;
var gdi_bitmaps: [512]GdiBitmap = [_]GdiBitmap{.{}} ** 512;
var gdi_regions: [512]GdiRegion = [_]GdiRegion{.{}} ** 512;
var gdi_dcs: [512]GdiDC = [_]GdiDC{.{}} ** 512;
var saved_dcs: [128]SavedDCState = [_]SavedDCState{.{}} ** 128;
var stock_objects: [20]usize = [_]usize{0} ** 20;
var default_bitmap: usize = 0;
var screen_hdc: usize = 0;
var fb_dirty: [MAX_WINDOWS]bool = [_]bool{false} ** MAX_WINDOWS;

const WinProp = struct { in_use: bool = false, hwnd: usize = 0, key_hash: u64 = 0, val: usize = 0 };
var win_props: [128]WinProp = [_]WinProp{.{}} ** 128;

const PAINTSTRUCT = extern struct {
    hdc: usize,
    fErase: i32,
    rcPaint: Rect,
    fRestore: i32,
    fIncUpdate: i32,
    rgbReserved: [32]u8,
};

fn allocGdiBrush(xrgb: u32, is_null: bool, sticky: bool) usize {
    for (&gdi_brushes, 0..) |*b, idx| {
        if (!b.in_use) {
            b.* = .{ .in_use = true, .xrgb = xrgb, .is_null = is_null, .sticky = sticky };
            return HBRUSH_BASE + idx;
        }
    }
    return 0;
}

fn allocGdiPen(xrgb: u32, width: i32, is_null: bool, sticky: bool) usize {
    for (&gdi_pens, 0..) |*p, idx| {
        if (!p.in_use) {
            p.* = .{ .in_use = true, .xrgb = xrgb, .width = width, .is_null = is_null, .sticky = sticky };
            return HPEN_BASE + idx;
        }
    }
    return 0;
}

fn brushFromHandle(hbr: usize) ?GdiBrush {
    if (hbr >= HBRUSH_BASE and hbr < HBRUSH_BASE + gdi_brushes.len) {
        const b = gdi_brushes[hbr - HBRUSH_BASE];
        if (b.in_use) return b;
    }
    if (hbr >= 1 and hbr <= 31) {
        return .{ .in_use = true, .xrgb = gdi.colorrefToXrgb(GetSysColor(@intCast(hbr - 1))), .is_null = false };
    }
    return null;
}

fn penFromHandle(hpen: usize) ?GdiPen {
    if (hpen >= HPEN_BASE and hpen < HPEN_BASE + gdi_pens.len) {
        const p = gdi_pens[hpen - HPEN_BASE];
        if (p.in_use) return p;
    }
    return null;
}

fn bitmapFromHandle(hbmp: usize) ?*GdiBitmap {
    if (hbmp >= HBITMAP_BASE and hbmp < HBITMAP_BASE + gdi_bitmaps.len) {
        const bm = &gdi_bitmaps[hbmp - HBITMAP_BASE];
        if (bm.in_use) return bm;
    }
    return null;
}

fn dcFromHandle(hdc: usize) ?*GdiDC {
    if (hdc >= HDC_BASE and hdc < HDC_BASE + gdi_dcs.len) {
        const dc = &gdi_dcs[hdc - HDC_BASE];
        if (dc.in_use) return dc;
    }
    return null;
}

fn allocDC(hwnd: usize, is_mem: bool) usize {
    for (&gdi_dcs, 0..) |*dc, idx| {
        if (!dc.in_use) {
            dc.* = .{ .in_use = true, .hwnd = hwnd, .is_mem = is_mem };
            return HDC_BASE + idx;
        }
    }
    return 0;
}

fn findWinSlot(hwnd: usize) ?usize {
    if (hwnd == 0) return null;
    for (&windows, 0..) |*w, idx| {
        if (w.in_use and w.hwnd == hwnd) return idx;
    }
    return null;
}

const DrawTarget = struct {
    surface: *gdi.Surface,
    clip: gdi.Clip,
    ox: i32,
    oy: i32,
};

fn winRootAndOffset(hwnd: usize) ?struct { root_idx: usize, ox: i32, oy: i32, clip: gdi.Clip } {
    const start_idx = findWinSlot(hwnd) orelse return null;
    var cur_idx = start_idx;
    var ox: i32 = 0;
    var oy: i32 = 0;
    var hops: usize = 0;
    var clip = gdi.Clip{ .left = 0, .top = 0, .right = windows[start_idx].width, .bottom = windows[start_idx].height };
    while (hops < 16) : (hops += 1) {
        const w = &windows[cur_idx];
        if ((w.style & WS_CHILD) == 0 or w.parent == 0) break;
        const p_idx = findWinSlot(w.parent) orelse break;
        ox += w.x;
        oy += w.y;
        clip.left += w.x;
        clip.right += w.x;
        clip.top += w.y;
        clip.bottom += w.y;
        clip.left = @max(clip.left, 0);
        clip.top = @max(clip.top, 0);
        clip.right = @min(clip.right, windows[p_idx].width);
        clip.bottom = @min(clip.bottom, windows[p_idx].height);
        cur_idx = p_idx;
    }
    const root = &windows[cur_idx];
    if (!win_surfaces[cur_idx].ensure(root.width, root.height, 0x00F0F0F0)) return null;
    return .{ .root_idx = cur_idx, .ox = ox, .oy = oy, .clip = clip };
}

fn intersectClip(a: gdi.Clip, b: gdi.Clip) gdi.Clip {
    return .{
        .left = @max(a.left, b.left),
        .top = @max(a.top, b.top),
        .right = @min(a.right, b.right),
        .bottom = @min(a.bottom, b.bottom),
    };
}

fn dcTarget(dc: *const GdiDC) ?DrawTarget {
    if (dc.is_mem) {
        const bm = bitmapFromHandle(dc.hbitmap) orelse return null;
        if (bm.surface.pixels.len == 0) return null;
        var clip = gdi.Clip{ .left = 0, .top = 0, .right = @intCast(bm.surface.width), .bottom = @intCast(bm.surface.height) };
        if (dc.has_clip) clip = intersectClip(clip, dc.clip);
        return .{ .surface = &bm.surface, .clip = clip, .ox = -dc.org_x, .oy = -dc.org_y };
    }
    const wr = winRootAndOffset(dc.hwnd) orelse return null;
    var clip = wr.clip;
    if (dc.has_clip) {
        const shifted = gdi.Clip{
            .left = dc.clip.left + wr.ox,
            .top = dc.clip.top + wr.oy,
            .right = dc.clip.right + wr.ox,
            .bottom = dc.clip.bottom + wr.oy,
        };
        clip = intersectClip(clip, shifted);
    }
    return .{ .surface = &win_surfaces[wr.root_idx], .clip = clip, .ox = wr.ox - dc.org_x, .oy = wr.oy - dc.org_y };
}

fn markFbDirty(hwnd: usize) void {
    const wr = winRootAndOffset(hwnd) orelse return;
    fb_dirty[wr.root_idx] = true;
}

fn flushDirtyBlits() void {
    const conn = connection orelse return;
    for (&windows, 0..) |*w, idx| {
        if (!fb_dirty[idx]) continue;
        fb_dirty[idx] = false;
        if (!w.in_use or w.x11_win == 0 or !w.visible or w.has_gl) continue;
        const surf = &win_surfaces[idx];
        const ptr = surf.bytesPtr() orelse continue;
        conn.blitBgrx32(w.x11_win, surf.width, surf.height, ptr);
    }
}

/// Marks `hwnd` and every descendant for repaint. All windows of one top-level
/// share a single software surface, so a parent repaint must be followed by its
/// children or they would be painted over.
fn markTreeDirty(hwnd: usize) void {
    for (&windows) |*w| {
        if (!w.in_use) continue;
        var cur: *const WinObj = w;
        var hops: usize = 0;
        while (hops < 16) : (hops += 1) {
            if (cur.hwnd == hwnd) {
                w.needs_paint = true;
                break;
            }
            if ((cur.style & WS_CHILD) == 0 or cur.parent == 0) break;
            cur = findWin(cur.parent) orelse break;
        }
    }
}

fn xrgbToColorref(x: u32) u32 {
    return ((x >> 16) & 0xff) | (x & 0xff00) | ((x & 0xff) << 16);
}

fn allocBitmap(w_in: i32, h_in: i32, fill: u32) usize {
    const w = if (w_in <= 0) 1 else w_in;
    const h = if (h_in <= 0) 1 else h_in;
    for (&gdi_bitmaps, 0..) |*bm, idx| {
        if (!bm.in_use) {
            bm.* = .{ .in_use = true };
            if (!bm.surface.ensure(w, h, fill)) {
                bm.* = .{};
                return 0;
            }
            return HBITMAP_BASE + idx;
        }
    }
    return 0;
}

fn getDefaultBitmap() usize {
    if (default_bitmap == 0) {
        default_bitmap = allocBitmap(1, 1, 0);
        if (bitmapFromHandle(default_bitmap)) |bm| bm.sticky = true;
    }
    return default_bitmap;
}

fn regionFromHandle(h: usize) ?*GdiRegion {
    if (h >= HRGN_BASE and h < HRGN_BASE + gdi_regions.len) {
        const r = &gdi_regions[h - HRGN_BASE];
        if (r.in_use) return r;
    }
    return null;
}

fn allocRegion(rect: gdi.Clip) usize {
    for (&gdi_regions, 0..) |*r, idx| {
        if (!r.in_use) {
            r.* = .{ .in_use = true, .rect = rect };
            return HRGN_BASE + idx;
        }
    }
    return 0;
}

fn dcPenColor(dc: *const GdiDC) ?u32 {
    if (dc.hpen == 0) return 0x000000;
    const p = penFromHandle(dc.hpen) orelse return 0x000000;
    if (p.is_null) return null;
    return p.xrgb;
}

fn dcBrushColor(dc: *const GdiDC) ?u32 {
    if (dc.hbrush == 0) return 0xFFFFFF;
    const b = brushFromHandle(dc.hbrush) orelse return 0xFFFFFF;
    if (b.is_null) return null;
    return b.xrgb;
}

fn applyRop(d: u32, s: u32, rop: u32) u32 {
    const r: u32 = switch (rop & 0x00FFFFFF) {
        0x008800C6 => d & s, // SRCAND
        0x00EE0086 => d | s, // SRCPAINT
        0x00660046 => d ^ s, // SRCINVERT
        0x00440328 => s & ~d, // SRCERASE
        0x00330008 => ~s, // NOTSRCCOPY
        0x00BB0226 => d | ~s, // MERGEPAINT
        else => s, // SRCCOPY and unmodelled ROPs copy the source
    };
    return r & 0x00FFFFFF;
}

/// Nearest-neighbour copy between two draw targets (BitBlt / StretchBlt /
/// StretchDIBits). Coordinates are logical; the targets carry the device offset.
fn stretchCopy(dst: DrawTarget, dx: i32, dy: i32, dw: i32, dh: i32, src_in: DrawTarget, sx: i32, sy: i32, sw: i32, sh: i32, src_flip: bool, rop: u32) void {
    if (dw == 0 or dh == 0 or sw == 0 or sh == 0) return;
    if (dst.surface.pixels.len == 0 or src_in.surface.pixels.len == 0) return;
    var src = src_in;
    var tmp: gdi.Surface = .{};
    defer if (tmp.pixels.len != 0) std.heap.page_allocator.free(tmp.pixels);
    if (src.surface == dst.surface) {
        const copy = std.heap.page_allocator.dupe(u32, src.surface.pixels) catch return;
        tmp = .{ .width = src.surface.width, .height = src.surface.height, .pixels = copy };
        src.surface = &tmp;
    }
    const adw: i32 = @intCast(@abs(dw));
    const adh: i32 = @intCast(@abs(dh));
    const asw: i32 = @intCast(@abs(sw));
    const ash: i32 = @intCast(@abs(sh));
    const sW: i32 = @intCast(src.surface.width);
    const sH: i32 = @intCast(src.surface.height);
    const dW: i32 = @intCast(dst.surface.width);
    const dH: i32 = @intCast(dst.surface.height);
    var row: i32 = 0;
    while (row < adh) : (row += 1) {
        const py = dst.oy + dy + row;
        if (py < dst.clip.top or py >= dst.clip.bottom or py < 0 or py >= dH) continue;
        var qy = src.oy + sy + @divTrunc(row * ash, adh);
        if (src_flip) qy = sH - 1 - qy;
        if (qy < 0 or qy >= sH) continue;
        const drow = @as(usize, @intCast(py)) * dst.surface.width;
        const srow = @as(usize, @intCast(qy)) * src.surface.width;
        var col: i32 = 0;
        while (col < adw) : (col += 1) {
            const px = dst.ox + dx + col;
            if (px < dst.clip.left or px >= dst.clip.right or px < 0 or px >= dW) continue;
            const qx = src.ox + sx + @divTrunc(col * asw, adw);
            if (qx < 0 or qx >= sW) continue;
            const di = drow + @as(usize, @intCast(px));
            dst.surface.pixels[di] = applyRop(dst.surface.pixels[di], src.surface.pixels[srow + @as(usize, @intCast(qx))], rop);
        }
    }
}

fn xorRect(tgt: DrawTarget, l: i32, t: i32, r: i32, b: i32, mask: u32) void {
    const s = tgt.surface;
    if (s.pixels.len == 0) return;
    const x0 = @max(@max(l, tgt.clip.left), 0);
    const y0 = @max(@max(t, tgt.clip.top), 0);
    const x1 = @min(@min(r, tgt.clip.right), @as(i32, @intCast(s.width)));
    const y1 = @min(@min(b, tgt.clip.bottom), @as(i32, @intCast(s.height)));
    var y = y0;
    while (y < y1) : (y += 1) {
        var x = x0;
        while (x < x1) : (x += 1) {
            const i = @as(usize, @intCast(y)) * s.width + @as(usize, @intCast(x));
            s.pixels[i] = (s.pixels[i] ^ mask) & 0x00FFFFFF;
        }
    }
}

fn patBltTarget(dc: *const GdiDC, tgt: DrawTarget, x: i32, y: i32, w: i32, h: i32, rop: u32) void {
    const l = tgt.ox + @min(x, x + w);
    const r = tgt.ox + @max(x, x + w);
    const t = tgt.oy + @min(y, y + h);
    const b = tgt.oy + @max(y, y + h);
    switch (rop & 0x00FFFFFF) {
        0x00000042 => gdi.fillRect(tgt.surface, tgt.clip, l, t, r, b, 0x000000), // BLACKNESS
        0x00FF0062 => gdi.fillRect(tgt.surface, tgt.clip, l, t, r, b, 0xFFFFFF), // WHITENESS
        0x00550009 => xorRect(tgt, l, t, r, b, 0x00FFFFFF), // DSTINVERT
        0x005A0049 => if (dcBrushColor(dc)) |c| xorRect(tgt, l, t, r, b, c), // PATINVERT
        else => if (dcBrushColor(dc)) |c| gdi.fillRect(tgt.surface, tgt.clip, l, t, r, b, c), // PATCOPY
    }
}

fn textWidth(n: usize) i32 {
    return @intCast(n * 8);
}

fn drawTextAt(dc: *const GdiDC, tgt: DrawTarget, x_in: i32, y_in: i32, text: []const u16, dx: ?[*]const i32) void {
    var x = x_in;
    var y = y_in;
    const width = textWidth(text.len);
    const ta = dc.text_align;
    if ((ta & 24) == 24) {
        y -= 13; // TA_BASELINE: fixed 8x16 cell, ascent 13
    } else if ((ta & 8) != 0) {
        y -= 16; // TA_BOTTOM
    }
    if ((ta & 6) == 6) {
        x -= @divTrunc(width, 2); // TA_CENTER
    } else if ((ta & 2) != 0) {
        x -= width; // TA_RIGHT
    }
    const bg: ?u32 = if (dc.bk_mode == 2) dc.bk_xrgb else null;
    if (dx) |advances| {
        var cx = tgt.ox + x;
        for (text, 0..) |ch, i| {
            const adv = advances[i];
            if (bg) |bcol| gdi.fillRect(tgt.surface, tgt.clip, cx, tgt.oy + y, cx + @max(adv, 0), tgt.oy + y + 16, bcol);
            if (ch != ' ' and ch != '\t') gdi.drawChar(tgt.surface, tgt.clip, cx, tgt.oy + y, ch, dc.text_xrgb, null);
            cx += adv;
        }
    } else {
        gdi.drawTextU16(tgt.surface, tgt.clip, tgt.ox + x, tgt.oy + y, text, dc.text_xrgb, bg);
    }
}

fn readRectPtr(p: ?*const anyopaque) ?Rect {
    const ptr = p orelse return null;
    const r: *const Rect = @ptrCast(@alignCast(ptr));
    return r.*;
}

const RegisteredClass = struct {
    name: [64]u16,
    name_len: usize,
    wndproc: WndProcFn,
    instance: usize,
    atom: u16,
    style: u32 = 0,
    hicon: usize = 0,
    hcursor: usize = 0,
    hbr_bg: usize = 0,
    cb_wnd_extra: i32 = 0,
};
var registered_classes: [128]RegisteredClass = undefined;
var num_registered_classes: usize = 0;

const MAX_QUEUE = 256;
var msg_queue: [MAX_QUEUE]MSG = undefined;
var queue_head: usize = 0;
var queue_tail: usize = 0;
var queue_count: usize = 0;
var quit_posted: bool = false;
var quit_exit_code: i32 = 0;

fn pushMsg(msg: MSG) bool {
    if (queue_count >= MAX_QUEUE) return false;
    msg_queue[queue_tail] = msg;
    queue_tail = (queue_tail + 1) % MAX_QUEUE;
    queue_count += 1;
    return true;
}

fn popMsg() ?MSG {
    if (queue_count == 0) return null;
    const m = msg_queue[queue_head];
    queue_head = (queue_head + 1) % MAX_QUEUE;
    queue_count -= 1;
    return m;
}

fn getDisplayName() [*:0]const u8 {
    if (std.c.getenv("DISPLAY")) |d| {
        if (d[0] != 0) return d;
    }
    return ":91";
}

fn ensureX11() ?x11.Connection {
    if (connection) |c| return c;
    const conn = x11.Connection.open(getDisplayName()) catch return null;
    wm_delete_atom = conn.wmDeleteAtom();
    connection = conn;
    return conn;
}

fn findWin(hwnd: usize) ?*WinObj {
    if (hwnd == 0) return null;
    for (&windows) |*w| {
        if (w.in_use and w.hwnd == hwnd) return w;
    }
    return null;
}

fn findWinByX11(xwin: x11.Window) ?*WinObj {
    if (xwin == 0) return null;
    for (&windows) |*w| {
        if (w.in_use and w.x11_win == xwin) return w;
    }
    return null;
}

fn countTopLevelWindows() usize {
    var n: usize = 0;
    for (&windows) |*w| {
        if (w.in_use and w.x11_win != 0) n += 1;
    }
    return n;
}

fn eqlIgnoreCaseU16(a: []const u16, b: []const u16) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

fn isBuiltinClassName(name: []const u16) bool {
    const builtins = [_][]const u8{
        "STATIC",
        "BUTTON",
        "EDIT",
        "LISTBOX",
        "COMBOBOX",
        "SCROLLBAR",
        "MDICLIENT",
        "ToolbarWindow32",
        "msctls_statusbar32",
        "msctls_progress32",
        "msctls_trackbar32",
        "msctls_updown32",
        "SysTabControl32",
        "SysTreeView32",
        "SysListView32",
        "SysHeader32",
        "SysAnimate32",
        "SysLink",
        "ReBarWindow32",
        "tooltips_class32",
        "ComboBoxEx32",
        "RichEdit20W",
        "RichEdit50W",
        "#32770",
        "#32768",
        "IME",
    };
    for (builtins) |b| {
        if (name.len == b.len) {
            var ok = true;
            for (name, b) |cu, cb| {
                const la = if (cu >= 'A' and cu <= 'Z') cu + 32 else cu;
                const lb: u16 = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
                if (la != lb) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
    }
    return false;
}

fn copyTitleU16(dst: []u16, src_opt: ?[*:0]const u16) usize {
    const src = src_opt orelse {
        dst[0] = 0;
        return 0;
    };
    var i: usize = 0;
    while (i + 1 < dst.len and src[i] != 0) : (i += 1) {
        dst[i] = src[i];
    }
    dst[i] = 0;
    return i;
}

fn encodeTitleUtf8(src: []const u16, out: []u8) usize {
    var i: usize = 0;
    for (src) |c| {
        if (c == 0 or i + 1 >= out.len) break;
        out[i] = if (c < 128) @truncate(c) else '?';
        i += 1;
    }
    out[i] = 0;
    return i;
}

fn registerClassExW(wcex: ?*const WNDCLASSEXW) callconv(W) u16 {
    if (wcex == null) return 0;
    if (wcex.?.cbSize != @sizeOf(WNDCLASSEXW) and wcex.?.cbSize != @sizeOf(WNDCLASSW)) return 0;
    if (wcex.?.lpszClassName == null or wcex.?.lpfnWndProc == null) return 0;
    if (num_registered_classes >= registered_classes.len) return 0;
    if (@intFromPtr(wcex.?.lpszClassName.?) < 65536) return 0;

    var len: usize = 0;
    while (len < 64 and wcex.?.lpszClassName.?[len] != 0) : (len += 1) {}
    if (len == 0 or len >= 64) return 0;

    for (registered_classes[0..num_registered_classes]) |*rc| {
        if (eqlIgnoreCaseU16(rc.name[0..rc.name_len], wcex.?.lpszClassName.?[0..len])) {
            rc.wndproc = wcex.?.lpfnWndProc.?;
            rc.style = wcex.?.style;
            rc.hicon = wcex.?.hIcon;
            rc.hcursor = wcex.?.hCursor;
            rc.hbr_bg = wcex.?.hbrBackground;
            rc.cb_wnd_extra = wcex.?.cbWndExtra;
            return rc.atom;
        }
    }

    const atom: u16 = @intCast(0xC001 + num_registered_classes);
    var reg = &registered_classes[num_registered_classes];
    @memcpy(reg.name[0..len], wcex.?.lpszClassName.?[0..len]);
    reg.name[len] = 0;
    reg.name_len = len;
    reg.wndproc = wcex.?.lpfnWndProc.?;
    reg.instance = wcex.?.hInstance;
    reg.atom = atom;
    reg.style = wcex.?.style;
    reg.hicon = wcex.?.hIcon;
    reg.hcursor = wcex.?.hCursor;
    reg.hbr_bg = wcex.?.hbrBackground;
    reg.cb_wnd_extra = wcex.?.cbWndExtra;
    num_registered_classes += 1;
    if (std.c.getenv("WINS_TRACE") != null) {
        var u8buf: [64]u8 = undefined;
        const n = encodeTitleUtf8(reg.name[0..len], &u8buf);
        std.debug.print("[WINS:USER32] RegisterClassExW \"{s}\" atom=0x{x} proc=0x{x}\n", .{ u8buf[0..n], atom, @intFromPtr(reg.wndproc) });
    }
    return atom;
}

fn registerClassW(wc: ?*const WNDCLASSW) callconv(W) u16 {
    if (wc == null or wc.?.lpszClassName == null or wc.?.lpfnWndProc == null) return 0;
    const wcex = WNDCLASSEXW{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = wc.?.style,
        .lpfnWndProc = wc.?.lpfnWndProc,
        .cbClsExtra = wc.?.cbClsExtra,
        .cbWndExtra = wc.?.cbWndExtra,
        .hInstance = wc.?.hInstance,
        .hIcon = wc.?.hIcon,
        .hCursor = wc.?.hCursor,
        .hbrBackground = wc.?.hbrBackground,
        .lpszMenuName = wc.?.lpszMenuName,
        .lpszClassName = wc.?.lpszClassName,
        .hIconSm = 0,
    };
    return registerClassExW(&wcex);
}

fn createWindowExW(ex_style: u32, class: ?[*:0]const u16, title: ?[*:0]const u16, style: u32, raw_x: i32, raw_y: i32, raw_w: i32, raw_h: i32, parent: usize, menu: usize, instance: usize, param: usize) callconv(W) usize {
    if (class == null) return 0;

    var target_wndproc: ?WndProcFn = null;
    const is_atom = @intFromPtr(class.?) < 65536;
    var cls_buf: [64]u16 = [_]u16{0} ** 64;
    var cls_len: usize = 0;

    if (!is_atom) {
        while (cls_len < 64 and class.?[cls_len] != 0) : (cls_len += 1) {
            cls_buf[cls_len] = class.?[cls_len];
        }
        var found: ?RegisteredClass = null;
        for (registered_classes[0..num_registered_classes]) |rc| {
            if (eqlIgnoreCaseU16(rc.name[0..rc.name_len], cls_buf[0..cls_len])) {
                found = rc;
                break;
            }
        }
        if (found) |f| {
            target_wndproc = f.wndproc;
        } else if (isBuiltinClassName(cls_buf[0..cls_len])) {
            target_wndproc = &defWindowProcW;
        } else {
            if (std.c.getenv("WINS_TRACE") != null) {
                var u8buf: [64]u8 = undefined;
                const n = encodeTitleUtf8(cls_buf[0..cls_len], &u8buf);
                std.debug.print("[WINS:USER32] CreateWindowExW unknown class \"{s}\"\n", .{u8buf[0..n]});
            }
            return 0;
        }
    } else {
        const atom_val: u16 = @intCast(@intFromPtr(class.?));
        if (atom_val == 0x8002) {
            target_wndproc = &defWindowProcW; // #32770 dialog
        } else {
            var found: ?RegisteredClass = null;
            for (registered_classes[0..num_registered_classes]) |rc| {
                if (rc.atom == atom_val) {
                    found = rc;
                    break;
                }
            }
            if (found) |f| {
                target_wndproc = f.wndproc;
                cls_len = f.name_len;
                @memcpy(cls_buf[0..cls_len], f.name[0..cls_len]);
            } else {
                if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:USER32] CreateWindowExW unknown atom=0x{x}\n", .{atom_val});
                return 0;
            }
        }
    }

    const is_child = (style & WS_CHILD) != 0;
    if (!is_child and ensureX11() == null) {
        if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:USER32] CreateWindowExW failed: ensureX11() == null\n", .{});
        return 0;
    }
    const x: i32 = if (raw_x == CW_USEDEFAULT) (if (is_child) @as(i32, 0) else 60) else raw_x;
    const y: i32 = if (raw_y == CW_USEDEFAULT) (if (is_child) @as(i32, 0) else 60) else raw_y;
    const width: i32 = if (raw_w == CW_USEDEFAULT) (if (is_child) @as(i32, 0) else 1024) else @max(0, raw_w);
    const height: i32 = if (raw_h == CW_USEDEFAULT) (if (is_child) @as(i32, 0) else 720) else @max(0, raw_h);

    var slot_opt: ?*WinObj = null;
    for (&windows) |*w| {
        if (!w.in_use) {
            slot_opt = w;
            break;
        }
    }
    const slot = slot_opt orelse return 0;

    const hwnd = next_synth_hwnd;
    next_synth_hwnd += 1;

    slot.* = .{
        .in_use = true,
        .hwnd = hwnd,
        .x11_win = 0,
        .parent = parent,
        .wndproc = target_wndproc,
        .style = style,
        .ex_style = ex_style,
        .x = x,
        .y = y,
        .width = width,
        .height = height,
        .visible = (style & WS_VISIBLE) != 0,
        .needs_paint = (style & WS_VISIBLE) != 0,
        .hinstance = instance,
        .hmenu = menu,
        .id = if (is_child) @intCast(menu) else 0,
    };
    slot.title_len = copyTitleU16(&slot.title, title);
    slot.class_len = cls_len;
    @memcpy(slot.class_name[0..cls_len], cls_buf[0..cls_len]);
    if (winClassEqAscii(slot, "msctls_statusbar32")) {
        if (slot.height <= 0) slot.height = 24;
        if (slot.width <= 0) slot.width = 1024;
    } else if (winClassEqAscii(slot, "ToolbarWindow32")) {
        slot.tb_owner = parent;
        if (slot.height <= 0) slot.height = 28;
        if (slot.width <= 0) slot.width = 1024;
    }

    ensureX11Window(slot);
    if (slot.x11_win != 0 and slot.visible) {
        if (connection) |conn| {
            conn.map(slot.x11_win);
            conn.flush();
        }
    }

    if (std.c.getenv("WINS_TRACE") != null) {
        var c8: [64]u8 = undefined;
        var t8: [256]u8 = undefined;
        const cn = encodeTitleUtf8(cls_buf[0..cls_len], &c8);
        const tn = encodeTitleUtf8(slot.title[0..slot.title_len], &t8);
        std.debug.print("[WINS:USER32] CreateWindowExW class=\"{s}\" title=\"{s}\" style=0x{x} {d}x{d} parent=0x{x} -> hwnd=0x{x}\n", .{
            c8[0..cn], t8[0..tn], style, width, height, parent, hwnd,
        });
    }

    if (target_wndproc) |proc| {
        const cs = CREATESTRUCTW{
            .lpCreateParams = param,
            .hInstance = instance,
            .hMenu = menu,
            .hwndParent = parent,
            .cy = height,
            .cx = width,
            .y = y,
            .x = x,
            .style = @bitCast(style),
            .lpszName = title,
            .lpszClass = class,
            .dwExStyle = ex_style,
        };
        const nc_res = proc(hwnd, WM_NCCREATE, 0, @intFromPtr(&cs));
        if (nc_res == 0) {
            _ = destroyWindow(hwnd);
            return 0;
        }
        const cr_res = proc(hwnd, WM_CREATE, 0, @intFromPtr(&cs));
        if (cr_res == @as(usize, @bitCast(@as(isize, -1)))) {
            _ = destroyWindow(hwnd);
            return 0;
        }
        if (slot.in_use) {
            const lp_size: usize = (@as(usize, @intCast(@max(0, height))) << 16) | @as(usize, @intCast(@max(0, width) & 0xffff));
            _ = proc(hwnd, WM_SIZE, 0, lp_size);
        }
    }
    return hwnd;
}

fn getClientRect(window: usize, rect: ?*Rect) callconv(W) i32 {
    const r = rect orelse return 0;
    const w = findWin(window) orelse {
        if (window == 0 or window == 0x10000) {
            r.* = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
            return 1;
        }
        return 0;
    };
    if (w.x11_win != 0) {
        if (connection) |conn| {
            if (conn.geometry(w.x11_win)) |geom| {
                w.width = @intCast(geom.width);
                w.height = @intCast(geom.height);
            } else |_| {}
        }
    }
    r.* = .{ .left = 0, .top = 0, .right = w.width, .bottom = w.height };
    return 1;
}

fn isFullscreenPopupStyle(style: u32, width: i32, height: i32) bool {
    return (style & WS_CHILD) == 0 and (style & WS_POPUP) != 0 and (style & WS_CAPTION) == 0 and width >= 640 and height >= 480;
}

pub fn setWindowFullscreen(hwnd: usize, fullscreen: bool, width: u32, height: u32) void {
    const w = findWin(hwnd) orelse return;
    const nw: i32 = @intCast(@max(1, width));
    const nh: i32 = @intCast(@max(1, height));
    const eff_fs = fullscreen or w.fullscreen or (nw >= 1920 and nh >= 1080);
    w.fullscreen = eff_fs;
    const size_changed = (w.width != nw or w.height != nh);
    if (eff_fs) {
        w.x = 0;
        w.y = 0;
    }
    w.width = nw;
    w.height = nh;
    ensureX11Window(w);
    if (w.x11_win != 0) {
        if (connection) |conn| {
            if (size_changed or !w.x11_mapped) {
                conn.moveResize(w.x11_win, w.x, w.y, @intCast(nw), @intCast(nh));
            }
            if (w.visible and !w.x11_mapped) {
                conn.map(w.x11_win);
                w.x11_mapped = true;
            }
            if (w.x11_mapped and eff_fs != w.x11_fs_applied) {
                conn.setFullscreen(w.x11_win, eff_fs);
                w.x11_fs_applied = eff_fs;
            }
            if (g_cursor_count.load(.monotonic) < 0) conn.setCursorVisible(w.x11_win, false);
            conn.flush();
        }
    }
    if (size_changed) {
        const lp: usize = (@as(usize, @intCast(nh)) << 16) | @as(usize, @intCast(nw & 0xffff));
        _ = pushMsg(.{ .hwnd = hwnd, .message = WM_SIZE, .wParam = 0, .lParam = lp, .time = 0, .pt = .{ .x = 0, .y = 0 } });
    }
}

fn destroyWindow(window: usize) callconv(W) i32 {
    const w = findWin(window) orelse return 0;
    if (w.wndproc) |proc| {
        _ = proc(window, WM_DESTROY, 0, 0);
        _ = proc(window, WM_NCDESTROY, 0, 0);
    }
    if (w.x11_win != 0) {
        gl64.invalidateWindow(w.x11_win);
        if (connection) |conn| {
            conn.destroy(w.x11_win);
        }
    }
    w.* = .{};
    if (g_focus == window) g_focus = 0;
    if (g_capture == window) g_capture = 0;
    if (countTopLevelWindows() == 0) {
        if (connection) |conn| {
            conn.close();
            connection = null;
        }
    }
    return 1;
}

fn ensureX11Window(w: *WinObj) void {
    if (!w.in_use or w.x11_win != 0) return;
    if ((w.style & WS_CHILD) != 0) return;
    if (w.width <= 0 or w.height <= 0) return;
    if (ensureX11()) |conn| {
        const x11_win = conn.createUnmapped(w.x, w.y, @intCast(w.width), @intCast(w.height)) catch 0;
        if (x11_win != 0) {
            w.x11_win = x11_win;
            var tbuf: [256]u8 = undefined;
            const tn = encodeTitleUtf8(w.title[0..w.title_len], &tbuf);
            if (tn > 0) conn.setTitle(x11_win, @ptrCast(&tbuf));
            if (w.fullscreen or isFullscreenPopupStyle(w.style, w.width, w.height)) {
                w.fullscreen = true;
            }
            if (g_cursor_count.load(.monotonic) < 0) {
                conn.setCursorVisible(x11_win, false);
            }
            if (std.c.getenv("WINS_TRACE") != null) {
                std.debug.print("[WINS:USER32] Created X11 window 0x{x} for hwnd=0x{x} ({d}x{d})\n", .{
                    x11_win, w.hwnd, w.width, w.height,
                });
            }
        }
    }
}

/// The top-level window Windows considers active (it got WM_ACTIVATE). Games
/// (FromSoftware's among them) ignore input until their window procedure has
/// seen WM_ACTIVATEAPP/WM_ACTIVATE, so these follow X11 focus and the first
/// ShowWindow of a top-level window, as on Windows.
var g_activated_hwnd: usize = 0;

fn setActivation(hwnd: usize, on: bool, sync: bool) void {
    if (on and g_activated_hwnd == hwnd) return;
    if (!on and g_activated_hwnd != hwnd) return;
    g_activated_hwnd = if (on) hwnd else 0;
    const seq = if (on)
        [_][3]usize{ .{ WM_ACTIVATEAPP, 1, 0 }, .{ WM_NCACTIVATE, 1, 0 }, .{ WM_ACTIVATE, 1, 0 }, .{ WM_SETFOCUS, 0, 0 } }
    else
        [_][3]usize{ .{ WM_KILLFOCUS, 0, 0 }, .{ WM_NCACTIVATE, 0, 0 }, .{ WM_ACTIVATE, 0, 0 }, .{ WM_ACTIVATEAPP, 0, 0 } };
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:USER32] {s} hwnd=0x{x}\n", .{ if (on) "activate" else "deactivate", hwnd });
    for (seq) |m| {
        if (sync) {
            _ = dispatchSubclassFrom(hwnd, @intCast(m[0]), m[1], @bitCast(m[2]), null);
        } else {
            _ = pushMsg(.{ .hwnd = hwnd, .message = @intCast(m[0]), .wParam = m[1], .lParam = @bitCast(m[2]), .time = 0, .pt = .{ .x = 0, .y = 0 } });
        }
    }
}

fn showWindow(window: usize, cmd_show: i32) callconv(W) i32 {
    const w = findWin(window) orelse return 0;
    const was_visible: i32 = if (w.visible) 1 else 0;
    if (cmd_show != 0) {
        w.visible = true;
        w.needs_paint = true;
        w.style |= WS_VISIBLE;
        var resized = false;
        if ((w.style & WS_CHILD) == 0 and (w.width <= 0 or w.height <= 0)) {
            w.width = 1024;
            w.height = 720;
            resized = true;
        }
        ensureX11Window(w);
        if (w.x11_win != 0) {
            if (connection) |conn| {
                if (!w.x11_mapped) {
                    conn.map(w.x11_win);
                    w.x11_mapped = true;
                }
                if (w.fullscreen or isFullscreenPopupStyle(w.style, w.width, w.height)) {
                    w.fullscreen = true;
                    if (!w.x11_fs_applied) {
                        conn.setFullscreen(w.x11_win, true);
                        w.x11_fs_applied = true;
                    }
                }
                if (g_cursor_count.load(.monotonic) < 0) {
                    conn.setCursorVisible(w.x11_win, false);
                }
                conn.flush();
            }
        }
        markTreeDirty(window);
        if (resized) {
            _ = dispatchSubclassFrom(window, WM_SIZE, 0, (@as(usize, @intCast(w.height)) << 16) | @as(usize, @intCast(w.width & 0xffff)), null);
        }
        // Showing a top-level window activates it (SW_SHOWNA/SW_SHOWNOACTIVATE/
        // SW_SHOWMINNOACTIVE = 8/4/7 do not).
        if ((w.style & WS_CHILD) == 0 and w.parent == 0 and was_visible == 0 and g_activated_hwnd == 0 and !g_focus_lost and cmd_show != 4 and cmd_show != 7 and cmd_show != 8)
            setActivation(window, true, true);
    } else if (!w.fullscreen and !w.has_gl) {
        w.visible = false;
        w.style &= ~WS_VISIBLE;
        if (w.x11_win != 0) {
            if (connection) |conn| {
                conn.unmap(w.x11_win);
                w.x11_mapped = false;
                w.x11_fs_applied = false;
                conn.flush();
            }
        }
    }
    return was_visible;
}

fn updateWindow(window: usize) callconv(W) i32 {
    const w = findWin(window) orelse return 0;
    if (w.wndproc) |proc| {
        w.needs_paint = false;
        _ = proc(window, WM_PAINT, 0, 0);
    }
    return 1;
}

fn paintCommonControlOverlay(w: *const WinObj, tgt: DrawTarget) void {
    if (winClassEqAscii(w, "SysTabControl32")) {
        const th = @max(22, w.tab_item_h) + 2;
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + th, 0x00E3E6EB);
        gdi.frameRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy + th, tgt.ox + w.width, tgt.oy + w.height, 0x00C6CBD1);
        const tw = @max(84, w.tab_item_w + 16);
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + 4, tgt.oy + 2, tgt.ox + 4 + tw, tgt.oy + th + 1, 0x00FFFFFF);
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + 4, tgt.oy + 2, tgt.ox + 4 + tw, tgt.oy + 5, 0x000078D7);
        gdi.frameRect(tgt.surface, tgt.clip, tgt.ox + 4, tgt.oy + 2, tgt.ox + 4 + tw, tgt.oy + th + 1, 0x00B8BFC6);
        const label = if (w.title_len > 0) w.title[0..w.title_len] else &[_]u16{ 'n', 'e', 'w', ' ', '1' };
        gdi.drawTextU16(tgt.surface, tgt.clip, tgt.ox + 14, tgt.oy + 6, label, 0x00181C20, null);
    } else if (winClassEqAscii(w, "msctls_statusbar32")) {
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00EAECEF);
        gdi.drawLine(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy, 0x00BFC4CA);
        var left_x: i32 = 0;
        const nparts = if (w.sb_parts_n > 0) w.sb_parts_n else 1;
        for (0..nparts) |pi| {
            const right_x = if (w.sb_parts_n > 0 and w.sb_parts_right[pi] > left_x) w.sb_parts_right[pi] else w.width;
            if (pi > 0) {
                gdi.drawLine(tgt.surface, tgt.clip, tgt.ox + left_x, tgt.oy + 3, tgt.ox + left_x, tgt.oy + w.height - 3, 0x00C4C9D0);
            }
            const tlen = w.sb_text_len[pi];
            if (tlen > 0) {
                const pclip = intersectClip(tgt.clip, .{
                    .left = tgt.ox + left_x,
                    .top = tgt.oy,
                    .right = tgt.ox + right_x - 4,
                    .bottom = tgt.oy + w.height,
                });
                gdi.drawTextU16(tgt.surface, pclip, tgt.ox + left_x + 8, tgt.oy + @max(1, @divFloor(w.height - 16, 2)), w.sb_text[pi][0..tlen], 0x0024282E, null);
            }
            left_x = right_x;
        }
    } else if (winClassEqAscii(w, "ToolbarWindow32")) {
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00EEF0F3);
        gdi.drawLine(tgt.surface, tgt.clip, tgt.ox, tgt.oy + w.height - 1, tgt.ox + w.width, tgt.oy + w.height - 1, 0x00CFD4DA);
        const nb: usize = @min(if (w.tb_btn_count > 0) @as(usize, w.tb_btn_count) else 24, w.tb_ids.len);
        for (0..nb) |bi| {
            const bx = tgt.ox + tbButtonX(w, bi);
            const by = tgt.oy + 3;
            if (bx + 20 > tgt.ox + w.width) break;
            if (bi < w.tb_known and w.tb_sep[bi]) {
                gdi.drawLine(tgt.surface, tgt.clip, bx + 3, by + 2, bx + 3, by + 18, 0x00C4C9D0);
                continue;
            }
            gdi.fillRect(tgt.surface, tgt.clip, bx, by, bx + 20, by + 20, 0x00FAFBFC);
            gdi.frameRect(tgt.surface, tgt.clip, bx, by, bx + 20, by + 20, 0x00B8C0C8);
            const col: u32 = switch (bi % 4) {
                0 => 0x002B6CB0,
                1 => 0x002F855A,
                2 => 0x00C05621,
                else => 0x004A5568,
            };
            gdi.fillRect(tgt.surface, tgt.clip, bx + 5, by + 5, bx + 15, by + 15, col);
        }
    } else if (winClassEqAscii(w, "ReBarWindow32")) {
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00EEF0F3);
        gdi.drawLine(tgt.surface, tgt.clip, tgt.ox, tgt.oy + w.height - 1, tgt.ox + w.width, tgt.oy + w.height - 1, 0x00CFD4DA);
    }
}

fn defWindowProcW(window: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) usize {
    if (msg == WM_NCCREATE) return 1;
    if (msg == WM_NCCALCSIZE) return 0;
    if (msg == WM_CLOSE) {
        _ = destroyWindow(window);
        return 0;
    }
    if (findWin(window)) |w| {
        if (winClassEqAscii(w, "SysTabControl32")) {
            switch (msg) {
                0x1304 => return @max(1, w.tab_count), // TCM_GETITEMCOUNT
                0x130b, 0x130c => return 0, // TCM_GETCURSEL / TCM_SETCURSEL
                0x132c => return if (w.tab_count > 0) 1 else 0, // TCM_GETROWCOUNT
                0x1329 => { // TCM_SETITEMSIZE
                    const old = (@as(usize, @intCast(@max(0, w.tab_item_h))) << 16) | @as(usize, @intCast(@max(0, w.tab_item_w) & 0xffff));
                    w.tab_item_w = @intCast(lparam & 0xffff);
                    w.tab_item_h = @intCast((lparam >> 16) & 0xffff);
                    return old;
                },
                0x130a => { // TCM_GETITEMRECT
                    if (lparam >= 0x10000) {
                        const rc: *Rect = @ptrFromInt(lparam);
                        const idx: i32 = @intCast(wparam & 0xff);
                        const tw = @max(60, w.tab_item_w);
                        const th = @max(22, w.tab_item_h);
                        rc.* = .{ .left = 2 + idx * tw, .top = 2, .right = 2 + (idx + 1) * tw, .bottom = 2 + th };
                        return 1;
                    }
                    return 0;
                },
                0x1328 => { // TCM_ADJUSTRECT
                    if (lparam >= 0x10000) {
                        const rc: *Rect = @ptrFromInt(lparam);
                        const th = @max(22, w.tab_item_h) + 4;
                        if (wparam == 0) {
                            rc.top += th;
                            rc.left += 2;
                            rc.right -= 2;
                            rc.bottom -= 2;
                        } else {
                            rc.top -= th;
                            rc.left -= 2;
                            rc.right += 2;
                            rc.bottom += 2;
                        }
                    }
                    return 0;
                },
                0x133e, 0x133d => { // TCM_INSERTITEMW / TCM_SETITEMW
                    if (lparam >= 0x10000) {
                        const mask = std.mem.readInt(u32, @as(*const [4]u8, @ptrFromInt(lparam)), .little);
                        if ((mask & 1) != 0) {
                            const ptext_addr = std.mem.readInt(usize, @as(*const [8]u8, @ptrFromInt(lparam + 16)), .little);
                            if (ptext_addr >= 0x10000) {
                                w.title_len = copyTitleU16(&w.title, @ptrFromInt(ptext_addr));
                            }
                        }
                        if ((mask & 8) != 0) {
                            w.tab_lparam = std.mem.readInt(usize, @as(*const [8]u8, @ptrFromInt(lparam + 32)), .little);
                        }
                    }
                    if (msg == 0x133e) w.tab_count = @max(1, w.tab_count + 1);
                    w.needs_paint = true;
                    return if (msg == 0x133e) 0 else 1;
                },
                0x133c => { // TCM_GETITEMW
                    if (lparam >= 0x10000) {
                        const mask = std.mem.readInt(u32, @as(*const [4]u8, @ptrFromInt(lparam)), .little);
                        if ((mask & 8) != 0) {
                            std.mem.writeInt(usize, @as(*[8]u8, @ptrFromInt(lparam + 32)), w.tab_lparam, .little);
                        }
                        if ((mask & 1) != 0) {
                            const ptext_addr = std.mem.readInt(usize, @as(*const [8]u8, @ptrFromInt(lparam + 16)), .little);
                            const cch_max = std.mem.readInt(i32, @as(*const [4]u8, @ptrFromInt(lparam + 24)), .little);
                            if (ptext_addr >= 0x10000 and cch_max > 0) {
                                const dst: [*]u16 = @ptrFromInt(ptext_addr);
                                const n = @min(w.title_len, @as(usize, @intCast(cch_max - 1)));
                                @memcpy(dst[0..n], w.title[0..n]);
                                dst[n] = 0;
                            }
                        }
                        return 1;
                    }
                    return 0;
                },
                else => {},
            }
        } else if (winClassEqAscii(w, "msctls_statusbar32")) {
            switch (msg) {
                0x0005 => { // WM_SIZE
                    var pw: i32 = @intCast(lparam & 0xffff);
                    var ph: i32 = @intCast((lparam >> 16) & 0xffff);
                    if ((pw <= 0 or ph <= 0) and w.parent != 0) {
                        if (findWin(w.parent)) |p| {
                            pw = p.width;
                            ph = p.height;
                        }
                    }
                    if (pw > 0 and ph >= 24) {
                        w.x = 0;
                        w.y = ph - 24;
                        w.width = pw;
                        w.height = 24;
                        w.needs_paint = true;
                    }
                    return 0;
                },
                0x0404 => { // SB_SETPARTS
                    const n = @min(wparam, 8);
                    w.sb_parts_n = n;
                    if (lparam >= 0x10000) {
                        const edges: [*]const i32 = @ptrFromInt(lparam);
                        for (0..n) |i| w.sb_parts_right[i] = edges[i];
                    }
                    w.needs_paint = true;
                    return 1;
                },
                0x040b => { // SB_SETTEXTW
                    const part = wparam & 0xff;
                    if (part < 8 and lparam >= 0x10000) {
                        w.sb_text_len[part] = copyTitleU16(&w.sb_text[part], @ptrFromInt(lparam));
                        w.needs_paint = true;
                    }
                    return 1;
                },
                0x040a => { // SB_GETRECT
                    if (lparam >= 0x10000) {
                        const rc: *Rect = @ptrFromInt(lparam);
                        rc.* = .{ .left = 0, .top = 0, .right = 120, .bottom = @max(22, w.height) };
                        return 1;
                    }
                    return 0;
                },
                else => {},
            }
        } else if (winClassEqAscii(w, "ToolbarWindow32")) {
            switch (msg) {
                0x041d => { // TB_GETITEMRECT
                    if (lparam >= 0x10000) {
                        const rc: *Rect = @ptrFromInt(lparam);
                        const idx: usize = wparam & 0xff;
                        const bx = tbButtonX(w, idx);
                        const bw: i32 = if (idx < w.tb_known and w.tb_sep[idx]) 8 else 24;
                        rc.* = .{ .left = bx, .top = 0, .right = bx + bw, .bottom = 26 };
                        return 1;
                    }
                    return 0;
                },
                0x0425 => { // TB_SETPARENT: later notifications go to wParam
                    const old = w.tb_owner;
                    w.tb_owner = wparam;
                    return old;
                },
                WM_LBUTTONDOWN => {
                    w.tb_pressed = tbButtonAt(w, @as(i16, @bitCast(@as(u16, @truncate(lparam)))));
                    return 0;
                },
                WM_LBUTTONUP => {
                    const idx = tbButtonAt(w, @as(i16, @bitCast(@as(u16, @truncate(lparam)))));
                    const pressed = w.tb_pressed;
                    w.tb_pressed = -1;
                    if (idx >= 0 and idx == pressed) {
                        const k: usize = @intCast(idx);
                        const id: usize = @as(u32, @bitCast(w.tb_ids[k])) & 0xffff;
                        const owner = if (w.tb_owner != 0) w.tb_owner else w.parent;
                        if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:TOOLBAR] button {d} -> WM_COMMAND id={d} to 0x{x}\n", .{ k, id, owner });
                        _ = sendMessageW(owner, 0x0111, id, window); // WM_COMMAND, BN_CLICKED
                    }
                    return 0;
                },
                0x043a => return (26 << 16) | 24, // TB_GETBUTTONSIZE
                0x0444 => { // TB_ADDBUTTONSW: wParam buttons, lParam TBBUTTON[] (32 bytes each on x64)
                    if (lparam >= 0x10000) {
                        const base: [*]const u8 = @ptrFromInt(lparam);
                        for (0..@min(wparam, 256)) |bi| {
                            const k = w.tb_known;
                            if (k >= w.tb_ids.len) break;
                            const b = base + bi * 32;
                            w.tb_ids[k] = std.mem.readInt(i32, b[4..8], .little);
                            w.tb_sep[k] = (b[9] & 0x01) != 0; // fsStyle & BTNS_SEP
                            w.tb_known += 1;
                        }
                    }
                    w.tb_btn_count +%= @truncate(wparam);
                    if (w.height < 26) w.height = 28;
                    if (w.width < 240) w.width = 1024;
                    w.needs_paint = true;
                    return 1;
                },
                0x0421 => { // TB_AUTOSIZE
                    if (w.height < 26) w.height = 28;
                    if (w.width <= 0) w.width = 1024;
                    return 0;
                },
                else => {},
            }
        } else if (winClassEqAscii(w, "ReBarWindow32")) {
            switch (msg) {
                0x040a, 0x0401 => { // RB_INSERTBANDW / RB_INSERTBANDA
                    if (w.hwnd == 0x200022) {
                        w.tb_btn_count = 1;
                        w.height = 28;
                        if (w.width <= 0) w.width = 1024;
                    }
                    w.needs_paint = true;
                    return 1;
                },
                0x0410 => return if (wparam == 0) 0 else @bitCast(@as(isize, -1)), // RB_IDTOINDEX
                0x040c, 0x040d => return if (w.tb_btn_count > 0) 1 else 0, // RB_GETBANDCOUNT / RB_GETROWCOUNT
                0x040e, 0x041b => return if (w.tb_btn_count > 0) 28 else 0, // RB_GETROWHEIGHT / RB_GETBARHEIGHT
                0x0409 => { // RB_GETRECT
                    if (lparam >= 0x10000) {
                        const rc: *Rect = @ptrFromInt(lparam);
                        rc.* = .{ .left = 0, .top = 0, .right = @max(200, w.width), .bottom = if (w.tb_btn_count > 0) 28 else 0 };
                        return 1;
                    }
                    return 0;
                },
                else => {},
            }
        }
    }
    if (msg == WM_GETTEXT) {
        const dst: [*]u16 = if (lparam != 0) @ptrFromInt(lparam) else return 0;
        const max_c = @min(wparam, 256);
        if (max_c == 0) return 0;
        const w = findWin(window) orelse {
            dst[0] = 0;
            return 0;
        };
        const n = @min(w.title_len, max_c - 1);
        @memcpy(dst[0..n], w.title[0..n]);
        dst[n] = 0;
        return n;
    }
    if (msg == WM_GETTEXTLENGTH) {
        const w = findWin(window) orelse return 0;
        return w.title_len;
    }
    if (msg == WM_PAINT or msg == 0x0318) { // WM_PAINT or WM_PRINTCLIENT
        if (findWin(window)) |w| {
            if (w.width > 0 and w.height > 0) {
                var ps: PAINTSTRUCT = undefined;
                const use_passed_dc = (wparam != 0 and dcFromHandle(wparam) != null);
                const hdc = if (use_passed_dc) wparam else BeginPaint(window, &ps);
                if (hdc != 0) {
                    if (dcFromHandle(hdc)) |dc| {
                        if (dcTarget(dc)) |tgt| {
                            if ((w.style & WS_CHILD) == 0) {
                                gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00F0F0F0);
                            } else if (winClassEqAscii(w, "SysTabControl32") or winClassEqAscii(w, "msctls_statusbar32") or winClassEqAscii(w, "ToolbarWindow32") or winClassEqAscii(w, "ReBarWindow32")) {
                                paintCommonControlOverlay(w, tgt);
                            } else {
                                gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00F5F5F5);
                                if (w.width >= 4 and w.height >= 4) {
                                    gdi.frameRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00C8C8C8);
                                    if (w.title_len > 0) {
                                        gdi.drawTextU16(tgt.surface, tgt.clip, tgt.ox + 6, tgt.oy + @max(0, @divFloor(w.height - 16, 2)), w.title[0..w.title_len], 0x00202020, null);
                                    }
                                }
                            }
                        }
                    }
                    if (!use_passed_dc) {
                        _ = EndPaint(window, &ps);
                    }
                }
            }
        }
        return 0;
    }
    if (msg == 0x0014) { // WM_ERASEBKGND
        if (findWin(window)) |w| {
            if (wparam != 0) {
                if (dcFromHandle(wparam)) |dc| {
                    if (dcTarget(dc)) |tgt| {
                        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox, tgt.oy, tgt.ox + w.width, tgt.oy + w.height, 0x00F0F0F0);
                    }
                }
            }
        }
        return 1;
    }
    if (msg == WM_SETTEXT and lparam != 0) {
        _ = SetWindowTextW(window, @ptrFromInt(lparam));
        return 1;
    }
    return 0;
}

fn postQuitMessage(exit_code: i32) callconv(W) void {
    quit_posted = true;
    quit_exit_code = exit_code;
}

fn postMessageW(window: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) i32 {
    const m = MSG{
        .hwnd = window,
        .message = msg,
        .wParam = wparam,
        .lParam = lparam,
        .time = 0,
        .pt = .{ .x = 0, .y = 0 },
    };
    return if (pushMsg(m)) 1 else 0;
}

fn callBaseWndProc(window: usize, msg: u32, wparam: usize, lparam: usize) usize {
    if (findWin(window)) |w| {
        if (w.wndproc) |proc| return proc(window, msg, wparam, lparam);
        return defWindowProcW(window, msg, wparam, lparam);
    }
    return 0;
}

fn dispatchSubclassFrom(window: usize, msg: u32, wparam: usize, lparam: usize, below_idx: ?usize) usize {
    var i: usize = below_idx orelse subclasses.len;
    while (i > 0) {
        i -= 1;
        const sc = subclasses[i];
        if (sc.in_use and sc.hwnd == window) {
            const prev = active_subclass_idx;
            active_subclass_idx = i;
            defer active_subclass_idx = prev;
            return sc.proc(window, msg, wparam, lparam, sc.id, sc.ref_data);
        }
    }
    return callBaseWndProc(window, msg, wparam, lparam);
}

fn sendMessageW(window: usize, msg: u32, wparam: usize, lparam: usize) callconv(W) usize {
    return dispatchSubclassFrom(window, msg, wparam, lparam, null);
}

fn isWindowVisibleTree(w: *const WinObj) bool {
    if (!w.in_use or !w.visible) return false;
    var cur: *const WinObj = w;
    var hops: usize = 0;
    while (hops < 16 and (cur.style & WS_CHILD) != 0 and cur.parent != 0) : (hops += 1) {
        const p = findWin(cur.parent) orelse return false;
        if (!p.in_use or !p.visible) return false;
        cur = p;
    }
    return true;
}

/// x of toolbar button `idx` (separators are 8 px wide, buttons 24 px).
fn tbButtonX(w: *const WinObj, idx: usize) i32 {
    var x: i32 = 6;
    for (0..idx) |i| x += if (i < w.tb_known and w.tb_sep[i]) 8 else 24;
    return x;
}

/// Index of the (non-separator) toolbar button at client x, or -1.
fn tbButtonAt(w: *const WinObj, x: i32) i32 {
    const n: usize = @min(@as(usize, w.tb_known), w.tb_ids.len);
    for (0..n) |i| {
        const bx = tbButtonX(w, i);
        if (w.tb_sep[i]) continue;
        if (x >= bx and x < bx + 20) return @intCast(i);
    }
    return -1;
}

fn rectsOverlap(a: *const WinObj, b: *const WinObj) bool {
    return a.x < b.x + b.width and b.x < a.x + a.width and a.y < b.y + b.height and b.y < a.y + a.height;
}

/// Siblings share one software surface and WINS does not clip them against each
/// other (WS_CLIPSIBLINGS), so when a window repaints, every visible sibling above
/// it in Z order (created earlier = lower hwnd) that overlaps it must repaint too,
/// after it. Without this Notepad++'s tab control, repainted alone when the
/// document becomes modified, erased the Scintilla view lying on top of it.
fn propagateOverlapDirt() void {
    var changed = true;
    var rounds: usize = 0;
    while (changed and rounds < 8) : (rounds += 1) {
        changed = false;
        for (&windows) |*w| {
            if (!w.in_use or !w.needs_paint or (w.style & WS_CHILD) == 0 or !isWindowVisibleTree(w)) continue;
            for (&windows) |*o| {
                if (!o.in_use or o.needs_paint or o.parent != w.parent or o.hwnd >= w.hwnd) continue;
                if ((o.style & WS_CHILD) == 0 or !o.visible or o.width <= 0 or o.height <= 0) continue;
                if (!rectsOverlap(w, o)) continue;
                markTreeDirty(o.hwnd);
                changed = true;
            }
        }
    }
}

/// WM_PAINT for `w` (if dirty) then its children bottom-to-top: highest hwnd
/// (created last = lowest in Z order) first, so windows on top paint last.
fn enqueuePaintTree(w: *WinObj, depth: usize) void {
    if (depth > 16) return;
    if (w.needs_paint) {
        w.needs_paint = false;
        _ = pushMsg(.{ .hwnd = w.hwnd, .message = WM_PAINT, .wParam = 0, .lParam = 0, .time = 0, .pt = .{ .x = 0, .y = 0 } });
    }
    var upper: usize = std.math.maxInt(usize);
    while (true) {
        var next: ?*WinObj = null;
        for (&windows) |*c| {
            if (!c.in_use or !c.visible or c.parent != w.hwnd or (c.style & WS_CHILD) == 0 or c.hwnd >= upper) continue;
            if (next == null or c.hwnd > next.?.hwnd) next = c;
        }
        const c = next orelse break;
        upper = c.hwnd;
        enqueuePaintTree(c, depth + 1);
    }
}

fn enqueueDirtyPaints() void {
    propagateOverlapDirt();
    for (&windows) |*w| {
        if (w.in_use and (w.style & WS_CHILD) == 0 and isWindowVisibleTree(w)) enqueuePaintTree(w, 0);
    }
    // Anything still dirty (e.g. a child whose parent is not a WINS window).
    for (&windows) |*w| {
        if (w.in_use and w.needs_paint and isWindowVisibleTree(w)) {
            w.needs_paint = false;
            _ = pushMsg(.{ .hwnd = w.hwnd, .message = WM_PAINT, .wParam = 0, .lParam = 0, .time = 0, .pt = .{ .x = 0, .y = 0 } });
        }
    }
}

var g_last_mouse_x: i32 = 0;
var g_last_mouse_y: i32 = 0;
// DirectInput relative motion (separate from the RawInput deltas above).
var g_dinput_last_x: i32 = 0;
var g_dinput_last_y: i32 = 0;
var g_have_dinput_last = false;
var g_cursor_x: i32 = 960;
var g_cursor_y: i32 = 540;
var g_warp_target_x: i32 = -1;
var g_warp_target_y: i32 = -1;
var g_warp_pending = false;

fn mouseKeyStateMask() usize {
    var mk: usize = 0;
    if (kbd.getKeyState(0x01) < 0) mk |= 0x0001; // MK_LBUTTON
    if (kbd.getKeyState(0x02) < 0) mk |= 0x0002; // MK_RBUTTON
    if (kbd.getKeyState(kbd.VK_SHIFT) < 0) mk |= 0x0004; // MK_SHIFT
    if (kbd.getKeyState(kbd.VK_CONTROL) < 0) mk |= 0x0008; // MK_CONTROL
    if (kbd.getKeyState(0x04) < 0) mk |= 0x0010; // MK_MBUTTON
    if (kbd.getKeyState(0x05) < 0) mk |= 0x0020; // MK_XBUTTON1
    if (kbd.getKeyState(0x06) < 0) mk |= 0x0040; // MK_XBUTTON2
    return mk;
}

/// One X11 key event -> Win32: VK in wParam, VK-state table (shared with
/// GetKeyState/GetAsyncKeyState via winrun_directx.feedKeyState), WM_INPUT
/// when RawInput keyboard is registered, and WM_KEYDOWN/WM_KEYUP (or the
/// WM_SYSKEY* variants while Alt is held).
fn postKeyEvent(w: *WinObj, conn: *const x11.Connection, ke: *const x11.XKeyEvent, down: bool) void {
    const vk = kbd.handleKeyEvent(conn, ke, down);
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:KBD] keycode={d} vk=0x{x} down={} hwnd=0x{x}\n", .{ ke.keycode, vk, down, w.hwnd });
    if (vk != 0) dxmod.feedKeyState(vk, down);
    dinput.keyEvent(dinput.dikFromX11(ke.keycode), down);
    if (vk != 0 and std.c.getenv("WINS_KBD_NO_RAW") == null) {
        if (dxmod.getRegisteredRawInputTarget(1, 6)) |hwnd| { // HID usage page 1, usage 6 = keyboard
            const h = dxmod.pushRawKeyEvent(vk, @intCast(ke.keycode), kbd.isExtendedVk(vk), down);
            _ = pushMsg(.{ .hwnd = hwnd, .message = WM_INPUT, .wParam = 0, .lParam = h, .time = 0, .pt = .{ .x = ke.x, .y = ke.y } });
        }
    }
    // AltGr (X Mod5, or the ISO_Level3_Shift key itself = VK_RMENU) is Ctrl+Alt on
    // Windows: plain WM_KEYDOWN/WM_CHAR, so latam/es AltGr+Q still types '@'.
    const altgr = (ke.state & 0x80) != 0 or vk == 0xA5;
    const alt = kbd.getKeyState(kbd.VK_MENU) < 0 and kbd.getKeyState(kbd.VK_CONTROL) >= 0 and !altgr;
    const msg: u32 = if (down) (if (alt) WM_SYSKEYDOWN else WM_KEYDOWN) else (if (alt) WM_SYSKEYUP else WM_KEYUP);
    // Keyboard input goes to the focus window (e.g. the Scintilla child of an
    // editor), as on Windows; with no focus inside this top-level, to the top-level.
    const target = keyboardTarget(w);
    if (down) rememberChar(@truncate(ke.time), if (vk != 0) vk else @truncate(ke.keycode), kbd.charForKeyEvent(ke));
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:KBD] -> hwnd=0x{x}\n", .{target});
    // Key messages carry the generic VK_SHIFT/VK_CONTROL/VK_MENU, as on Windows
    // (the left/right VKs only exist in GetKeyState and raw input).
    const msg_vk: usize = switch (vk) {
        0xA0, 0xA1 => kbd.VK_SHIFT,
        0xA2, 0xA3 => kbd.VK_CONTROL,
        0xA4, 0xA5 => kbd.VK_MENU,
        0 => ke.keycode,
        else => vk,
    };
    _ = pushMsg(.{ .hwnd = target, .message = msg, .wParam = msg_vk, .lParam = if (down) 1 else 0xC0000001, .time = @truncate(ke.time), .pt = g_cursor });
}

/// Post a RawInput mouse packet (if registered) + WM_INPUT, and the classic
/// WM_*BUTTON*/WM_MOUSEWHEEL messages, plus VK mouse button state.
fn postMouseButton(w: *WinObj, be: *const x11.XButtonEvent, down: bool) void {
    const sp = winScreenPos(w.hwnd);
    g_cursor_x = sp.x + be.x;
    g_cursor_y = sp.y + be.y;
    // Keep the struct cursor (MSG.pt / GetCursorPos space) in sync with the
    // scalars: mouseTarget refreshes it on motion, but buttons and warp echoes
    // do not always pass through it.
    g_cursor = .{ .x = g_cursor_x, .y = g_cursor_y };
    const vk: u8 = switch (be.button) {
        1 => 0x01, // VK_LBUTTON
        2 => 0x04, // VK_MBUTTON
        3 => 0x02, // VK_RBUTTON
        8 => 0x05, // VK_XBUTTON1
        9 => 0x06, // VK_XBUTTON2
        else => 0,
    };
    if (vk != 0) {
        kbd.feedKey(vk, down);
        dxmod.feedKeyState(vk, down);
    }
    const ri_flags: u16 = switch (be.button) {
        1 => if (down) dxmod.RI_MOUSE_LEFT_BUTTON_DOWN else dxmod.RI_MOUSE_LEFT_BUTTON_UP,
        2 => if (down) dxmod.RI_MOUSE_MIDDLE_BUTTON_DOWN else dxmod.RI_MOUSE_MIDDLE_BUTTON_UP,
        3 => if (down) dxmod.RI_MOUSE_RIGHT_BUTTON_DOWN else dxmod.RI_MOUSE_RIGHT_BUTTON_UP,
        4, 5 => if (down) 0x0400 else 0, // RI_MOUSE_WHEEL
        else => 0,
    };
    const ri_wheel: i16 = if (be.button == 4 and down) 120 else if (be.button == 5 and down) -120 else 0;
    switch (be.button) {
        1 => dinput.mouseButton(0, down),
        2 => dinput.mouseButton(2, down),
        3 => dinput.mouseButton(1, down),
        4 => if (down) dinput.mouseWheel(120),
        5 => if (down) dinput.mouseWheel(-120),
        8 => dinput.mouseButton(3, down),
        9 => dinput.mouseButton(4, down),
        else => {},
    }
    const lp: usize = (@as(usize, @intCast(@max(0, be.y))) << 16) | @as(usize, @intCast(@max(0, be.x) & 0xffff));
    if (ri_flags != 0) {
        if (dxmod.getRegisteredRawInputTarget(1, 2)) |hwnd| { // usage page 1, usage 2 = mouse
            const h = dxmod.pushRawMouseEvent(0, 0, ri_flags, @bitCast(ri_wheel));
            _ = pushMsg(.{ .hwnd = hwnd, .message = WM_INPUT, .wParam = 0, .lParam = h, .time = 0, .pt = .{ .x = g_cursor_x, .y = g_cursor_y } });
        }
    }
    _ = lp;
    const t = mouseTarget(w, be.x, be.y);
    const keys = mouseKeys(be.state, be.button, down);
    const time: u32 = @truncate(be.time);
    const msg: u32 = switch (be.button) {
        1 => if (down) WM_LBUTTONDOWN else WM_LBUTTONUP,
        2 => if (down) WM_MBUTTONDOWN else WM_MBUTTONUP,
        3 => if (down) WM_RBUTTONDOWN else WM_RBUTTONUP,
        4, 5, 6, 7 => {
            // X11 wheel = buttons 4-7, one press per notch. Windows sends the wheel to
            // the focus window with screen coordinates in lParam.
            if (!down) return;
            const delta: i16 = if (be.button == 4 or be.button == 7) 120 else -120;
            const wp: usize = (@as(usize, @as(u16, @bitCast(delta))) << 16) | (keys & 0xffff);
            const wheel_target = if (findWin(g_focus) != null) g_focus else t.hwnd;
            _ = pushMsg(.{ .hwnd = wheel_target, .message = if (be.button <= 5) WM_MOUSEWHEEL else WM_MOUSEHWHEEL, .wParam = wp, .lParam = packXY(g_cursor.x, g_cursor.y), .time = time, .pt = g_cursor });
            return;
        },
        8, 9 => {
            // X11 buttons 8/9 = XBUTTON1/2 (extra mouse buttons); their VK and
            // DirectInput state were already fed by the prologue above.
            const xbtn: usize = if (be.button == 8) 0x0001 else 0x0002;
            const wp: usize = (xbtn << 16) | (keys & 0xffff);
            _ = pushMsg(.{ .hwnd = t.hwnd, .message = if (down) WM_XBUTTONDOWN else WM_XBUTTONUP, .wParam = wp, .lParam = packXY(t.x, t.y), .time = time, .pt = g_cursor });
            return;
        },
        else => return,
    };
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:MOUSE] button={d} down={} -> hwnd=0x{x} ({d},{d})\n", .{ be.button, down, t.hwnd, t.x, t.y });
    _ = pushMsg(.{ .hwnd = t.hwnd, .message = msg, .wParam = keys, .lParam = packXY(t.x, t.y), .time = time, .pt = g_cursor });
}

// ---- characters decided at key-event time, consumed by TranslateMessage ----
const PendingChar = struct { time: u32 = 0, vk: u8 = 0, ch: u16 = 0, live: bool = false };
var g_pending_chars: [64]PendingChar = [_]PendingChar{.{}} ** 64;
var g_pending_next: usize = 0;

fn rememberChar(time: u32, vk: u8, ch: u16) void {
    g_pending_chars[g_pending_next] = .{ .time = time, .vk = vk, .ch = ch, .live = true };
    g_pending_next = (g_pending_next + 1) % g_pending_chars.len;
}

/// The character recorded for this key-down (same X time and VK), if the
/// message came from the X keyboard; null for messages a program posted itself.
fn takeChar(time: u32, vk: u8) ?u16 {
    var i: usize = 0;
    while (i < g_pending_chars.len) : (i += 1) {
        const k = (g_pending_next + g_pending_chars.len - 1 - i) % g_pending_chars.len;
        const p = &g_pending_chars[k];
        if (p.live and p.time == time and p.vk == vk) {
            p.live = false;
            return p.ch;
        }
    }
    return null;
}

// ---- focus, capture and pointer routing (desktop programs) ----
var g_focus: usize = 0;
var g_capture: usize = 0;
/// Last pointer position in WINS screen coordinates (the coordinate space of
/// winScreenPos / ClientToScreen), for GetCursorPos and MSG.pt.
var g_cursor: Point = .{ .x = 640, .y = 360 };
/// Time of the last input message retrieved, for GetMessageTime (Scintilla
/// measures double clicks with it).
var g_msg_time: u32 = 1000;

fn topLevelOf(hwnd: usize) usize {
    var cur = findWin(hwnd) orelse return 0;
    var hops: usize = 0;
    while (hops < 16 and (cur.style & WS_CHILD) != 0 and cur.parent != 0) : (hops += 1) {
        cur = findWin(cur.parent) orelse break;
    }
    return cur.hwnd;
}

fn keyboardTarget(w: *const WinObj) usize {
    if (g_focus != 0 and findWin(g_focus) != null and topLevelOf(g_focus) == w.hwnd) return g_focus;
    return w.hwnd;
}

/// Deepest visible child of `root` under (x, y), given in root's client coordinates.
/// Among overlapping siblings the one created first wins: Windows links a new child
/// window at the bottom of its siblings' Z order (Notepad++ relies on this: its tab
/// control, created after the Scintilla views, covers them and must not take their
/// clicks). hwnds are handed out in creation order, so the lowest hwnd is on top.
fn hitTestChild(root: usize, x: i32, y: i32) usize {
    var cur = root;
    var cx = x;
    var cy = y;
    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        var best: ?*const WinObj = null;
        for (&windows) |*c| {
            if (!c.in_use or !c.visible or c.parent != cur or (c.style & WS_CHILD) == 0) continue;
            if (c.width <= 0 or c.height <= 0) continue;
            if (cx >= c.x and cx < c.x + c.width and cy >= c.y and cy < c.y + c.height) {
                if (best == null or c.hwnd < best.?.hwnd) best = c;
            }
        }
        const b = best orelse break;
        cx -= b.x;
        cy -= b.y;
        cur = b.hwnd;
    }
    return cur;
}

const MouseTarget = struct { hwnd: usize, x: i32, y: i32 };

/// Records the pointer position and picks the window a pointer message goes to:
/// the capture window if one is set, else the deepest child under the pointer.
/// x, y are relative to `w`'s X11 window (its client area).
fn mouseTarget(w: *const WinObj, x: i32, y: i32) MouseTarget {
    const top = winScreenPos(w.hwnd);
    g_cursor = .{ .x = top.x + x, .y = top.y + y };
    const target = if (g_capture != 0 and findWin(g_capture) != null) g_capture else hitTestChild(w.hwnd, x, y);
    const o = winScreenPos(target);
    return .{ .hwnd = target, .x = g_cursor.x - o.x, .y = g_cursor.y - o.y };
}

/// MK_* flags from an X11 modifier/button state. X reports the state before the
/// event; Windows includes the button that just went down and drops the one released.
fn mouseKeys(state: c_uint, button: c_uint, down: bool) usize {
    var k: usize = 0;
    if (state & 1 != 0) k |= 0x04; // ShiftMask -> MK_SHIFT
    if (state & 4 != 0) k |= 0x08; // ControlMask -> MK_CONTROL
    if (state & (1 << 8) != 0) k |= 0x01; // Button1 -> MK_LBUTTON
    if (state & (1 << 9) != 0) k |= 0x10; // Button2 -> MK_MBUTTON
    if (state & (1 << 10) != 0) k |= 0x02; // Button3 -> MK_RBUTTON
    const bit: usize = switch (button) {
        1 => 0x01,
        2 => 0x10,
        3 => 0x02,
        else => 0,
    };
    if (down) k |= bit else k &= ~bit;
    return k;
}

/// Client coordinates are signed 16-bit in lParam (negative while captured).
fn packXY(x: i32, y: i32) usize {
    const ux: u16 = @truncate(@as(u32, @bitCast(x)));
    const uy: u16 = @truncate(@as(u32, @bitCast(y)));
    return (@as(usize, uy) << 16) | ux;
}

fn pumpX11Events(wait_ms: i32) void {
    enqueueDirtyPaints();
    flushDirtyBlits();
    const conn = connection orelse return;
    if (std.c.getenv("WINS_TRACE") != null) {
        const n = @atomicRmw(u32, &g_pump_calls, .Add, 1, .monotonic);
        if (n < 5 or n % 500 == 0) std.debug.print("[WINS:MSG] pumpX11Events #{d} pending={d}\n", .{ n, conn.pending() });
    }
    if (conn.pending() == 0 and wait_ms != 0 and queue_count == 0 and !quit_posted) {
        var pfd = [1]std.posix.pollfd{.{
            .fd = conn.fd(),
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        _ = std.posix.poll(&pfd, wait_ms) catch {};
    }
    var limit: usize = 0;
    while (conn.pending() > 0 and limit < 32) : (limit += 1) {
        var ev: x11.XEvent = undefined;
        conn.nextEvent(&ev);
        const any: *const x11.XAnyEvent = @ptrCast(&ev);
        if (std.c.getenv("WINS_XEV") != null) std.debug.print("[WINS:XEV] type={d} win=0x{x} send={d}\n", .{ ev.type, any.window, any.send_event });
        switch (ev.type) {
            x11.SelectionRequest => {
                clipboard.handleSelectionRequest(conn, @ptrCast(&ev));
                continue;
            },
            x11.SelectionClear => {
                const se: *const x11.XSelectionEvent = @ptrCast(&ev); // selection at the same offset
                clipboard.handleSelectionClear(conn, se.selection);
                continue;
            },
            else => {},
        }
        const w = findWinByX11(any.window) orelse continue;
        switch (ev.type) {
            12 => { // Expose
                markTreeDirty(w.hwnd);
                enqueueDirtyPaints();
            },
            22 => { // ConfigureNotify
                const ce: *const x11.XConfigureEvent = @ptrCast(&ev);
                if (!w.fullscreen and ce.width > 0 and ce.height > 0 and (ce.width != w.width or ce.height != w.height)) {
                    w.width = ce.width;
                    w.height = ce.height;
                    const lp: usize = (@as(usize, @intCast(ce.height)) << 16) | @as(usize, @intCast(ce.width & 0xffff));
                    _ = pushMsg(.{ .hwnd = w.hwnd, .message = WM_SIZE, .wParam = 0, .lParam = lp, .time = 0, .pt = .{ .x = 0, .y = 0 } });
                }
            },
            33 => { // ClientMessage
                const cm: *const x11.XClientMessageEvent = @ptrCast(&ev);
                if (@as(c_ulong, @bitCast(cm.data[0])) == wm_delete_atom) {
                    _ = pushMsg(.{ .hwnd = w.hwnd, .message = WM_CLOSE, .wParam = 0, .lParam = 0, .time = 0, .pt = .{ .x = 0, .y = 0 } });
                }
            },
            4 => postMouseButton(w, @ptrCast(&ev), true), // ButtonPress
            5 => postMouseButton(w, @ptrCast(&ev), false), // ButtonRelease
            6 => { // MotionNotify -> WM_MOUSEMOVE (+ raw mouse if registered)
                const me: *const x11.XButtonEvent = @ptrCast(&ev); // same prefix layout as XMotionEvent
                const sp = winScreenPos(w.hwnd);
                g_cursor_x = sp.x + me.x;
                g_cursor_y = sp.y + me.y;
                g_cursor = .{ .x = g_cursor_x, .y = g_cursor_y };
                const is_warp = g_warp_pending and (@abs(me.x - g_warp_target_x) <= 2 and @abs(me.y - g_warp_target_y) <= 2);
                if (is_warp) {
                    g_warp_pending = false;
                    g_dinput_last_x = me.x;
                    g_dinput_last_y = me.y;
                    g_last_mouse_x = me.x;
                    g_last_mouse_y = me.y;
                    g_have_dinput_last = true;
                } else {
                    if (g_warp_pending and (@abs(me.x - g_dinput_last_x) > 300 or @abs(me.y - g_dinput_last_y) > 250)) {
                        g_warp_pending = false;
                        g_dinput_last_x = g_warp_target_x;
                        g_dinput_last_y = g_warp_target_y;
                        g_last_mouse_x = g_warp_target_x;
                        g_last_mouse_y = g_warp_target_y;
                    }
                    // Route to the capture/focus window under the pointer, as on
                    // Windows; mouseTarget also refreshes g_cursor for MSG.pt.
                    const t = mouseTarget(w, me.x, me.y);
                    _ = pushMsg(.{ .hwnd = t.hwnd, .message = WM_MOUSEMOVE, .wParam = mouseKeys(me.state, 0, false), .lParam = packXY(t.x, t.y), .time = @truncate(me.time), .pt = g_cursor });
                    if (g_have_dinput_last) dinput.mouseMove(me.x - g_dinput_last_x, me.y - g_dinput_last_y);
                    g_dinput_last_x = me.x;
                    g_dinput_last_y = me.y;
                    g_have_dinput_last = true;
                    if (dxmod.getRegisteredRawInputTarget(1, 2)) |hwnd| {
                        const rx = me.x - g_last_mouse_x;
                        const ry = me.y - g_last_mouse_y;
                        g_last_mouse_x = me.x;
                        g_last_mouse_y = me.y;
                        const h = dxmod.pushRawMouseEvent(rx, ry, 0, 0);
                        _ = pushMsg(.{ .hwnd = hwnd, .message = WM_INPUT, .wParam = 0, .lParam = h, .time = 0, .pt = .{ .x = g_cursor_x, .y = g_cursor_y } });
                    }
                    if (g_cursor_count.load(.monotonic) < 0 and !g_focus_lost and w.width >= 200 and w.height >= 200) {
                        const margin: i32 = 64;
                        if (me.x < margin or me.y < margin or me.x >= w.width - margin or me.y >= w.height - margin) {
                            const cx = @divTrunc(w.width, 2);
                            const cy = @divTrunc(w.height, 2);
                            g_warp_target_x = cx;
                            g_warp_target_y = cy;
                            g_warp_pending = true;
                            conn.warpPointer(w.x11_win, cx, cy);
                        }
                    }
                }
            },
            9 => { // FocusIn
                g_focus_hwnd = w.hwnd;
                g_focus_lost = false;
                dinput.focus(true);
                setActivation(w.hwnd, true, false);
            },
            10 => { // FocusOut: release keys, but keep fullscreen GL games activated so they do not self-minimize
                if (g_focus_hwnd == w.hwnd or g_focus_hwnd == 0) {
                    g_focus_hwnd = 0;
                    g_focus_lost = true;
                    if (!w.fullscreen and !w.has_gl) {
                        setActivation(w.hwnd, false, false);
                    }
                }
                dinput.focus(false);
                g_have_dinput_last = false;
            },
            2 => postKeyEvent(w, &conn, @ptrCast(&ev), true), // KeyPress
            3 => postKeyEvent(w, &conn, @ptrCast(&ev), false), // KeyRelease
            else => {},
        }
    }
}

var g_msg_calls: u32 = 0;
var g_pump_calls: u32 = 0;

fn getMessageW(lp_msg: ?*MSG, window: usize, min_filter: u32, max_filter: u32) callconv(W) i32 {
    _ = window;
    _ = min_filter;
    _ = max_filter;
    if (lp_msg == null) return -1;
    if (std.c.getenv("WINS_TRACE") != null) {
        const n = @atomicRmw(u32, &g_msg_calls, .Add, 1, .monotonic);
        if (n < 5 or n % 1000 == 0) std.debug.print("[WINS:MSG] GetMessageW call #{d}\n", .{n});
    }

    while (true) {
        if (popMsg()) |m| {
            lp_msg.?.* = m;
            if (m.time != 0) g_msg_time = m.time;
            if (m.message == WM_QUIT) return 0;
            return 1;
        }
        if (quit_posted) {
            lp_msg.?.* = .{
                .hwnd = 0,
                .message = WM_QUIT,
                .wParam = @bitCast(@as(isize, quit_exit_code)),
                .lParam = 0,
                .time = 0,
                .pt = .{ .x = 0, .y = 0 },
            };
            quit_posted = false;
            return 0;
        }
        if (countTopLevelWindows() == 0) {
            lp_msg.?.* = .{
                .hwnd = 0,
                .message = WM_QUIT,
                .wParam = 0,
                .lParam = 0,
                .time = 0,
                .pt = .{ .x = 0, .y = 0 },
            };
            return 0;
        }
        pumpX11Events(100);
    }
}

fn peekMessageW(lp_msg: ?*MSG, window: usize, min_filter: u32, max_filter: u32, remove_msg: u32) callconv(W) i32 {
    _ = window;
    _ = min_filter;
    _ = max_filter;
    if (lp_msg == null) return 0;
    if (std.c.getenv("WINS_TRACE") != null) {
        const n = @atomicRmw(u32, &g_msg_calls, .Add, 1, .monotonic);
        if (n < 5 or n % 1000 == 0) std.debug.print("[WINS:MSG] PeekMessageW call #{d} rm={d}\n", .{ n, remove_msg });
    }
    if (queue_count == 0) pumpX11Events(0);
    if (queue_count > 0) {
        if (remove_msg != 0) {
            lp_msg.?.* = popMsg().?;
            if (lp_msg.?.time != 0) g_msg_time = lp_msg.?.time;
        } else {
            lp_msg.?.* = msg_queue[queue_head];
        }
        return 1;
    }
    if (quit_posted) {
        lp_msg.?.* = .{
            .hwnd = 0,
            .message = WM_QUIT,
            .wParam = @bitCast(@as(isize, quit_exit_code)),
            .lParam = 0,
            .time = 0,
            .pt = .{ .x = 0, .y = 0 },
        };
        if (remove_msg != 0) quit_posted = false;
        return 1;
    }
    return 0;
}

fn translateMessage(lp_msg: ?*const MSG) callconv(W) i32 {
    const m = lp_msg orelse return 0;
    // WM_KEYDOWN/WM_SYSKEYDOWN -> WM_CHAR/WM_SYSCHAR with the character the
    // key produces (shift/caps aware), as the real TranslateMessage does.
    if (m.message == WM_KEYDOWN or m.message == WM_SYSKEYDOWN) {
        if (std.c.getenv("WINS_KBD_NO_CHAR") != null) return 0;
        const vk = @as(u8, @truncate(m.wParam));
        const caps = kbd.getKeyState(0x14) & 1 != 0;
        const ch = takeChar(m.time, vk) orelse kbd.charForVk(vk, kbd.isShiftDown(), caps);
        if (ch != 0) {
            const posted = pushMsg(.{
                .hwnd = m.hwnd,
                .message = if (m.message == WM_SYSKEYDOWN) WM_SYSCHAR else WM_CHAR,
                .wParam = ch,
                .lParam = m.lParam,
                .time = m.time,
                .pt = m.pt,
            });
            return if (posted) 1 else 0;
        }
    }
    return 0;
}

fn dispatchMessageW(lp_msg: ?*const MSG) callconv(W) usize {
    if (lp_msg == null) return 0;
    const m = lp_msg.?.*;
    return dispatchSubclassFrom(m.hwnd, m.message, m.wParam, m.lParam, null);
}

fn MessageBoxW(hwnd: usize, lpText: ?[*:0]const u16, lpCaption: ?[*:0]const u16, uType: u32) callconv(W) i32 {
    _ = hwnd;
    _ = uType;
    if (std.c.getenv("WINS_TRACE") != null) {
        var c8: [128]u8 = undefined;
        var t8: [256]u8 = undefined;
        var cw: [256]u16 = undefined;
        var tw: [256]u16 = undefined;
        const cl = copyTitleU16(&cw, lpCaption);
        const tl = copyTitleU16(&tw, lpText);
        const cn = encodeTitleUtf8(cw[0..cl], &c8);
        const tn = encodeTitleUtf8(tw[0..tl], &t8);
        std.debug.print("[WINS:USER32] MessageBoxW caption=\"{s}\" text=\"{s}\"\n", .{ c8[0..cn], t8[0..tn] });
    }
    return 1;
}

fn MessageBoxA(hwnd: usize, lpText: ?[*:0]const u8, lpCaption: ?[*:0]const u8, uType: u32) callconv(W) i32 {
    _ = hwnd; _ = lpText; _ = lpCaption; _ = uType;
    return 1;
}

fn GetDC(hwnd: usize) callconv(W) usize {
    if (hwnd == 0) {
        if (screen_hdc == 0) {
            screen_hdc = allocDC(0, true);
            if (dcFromHandle(screen_hdc)) |dc| {
                dc.is_screen = true;
                dc.hbitmap = getDefaultBitmap();
            }
        }
        return screen_hdc;
    }
    const hdc = allocDC(hwnd, false);
    if (hdc != 0) return hdc;
    return 0xDC0001;
}

fn ReleaseDC(hwnd: usize, hdc: usize) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (dc.is_screen) return 1;
        const target_hwnd = if (hwnd != 0) hwnd else dc.hwnd;
        dc.* = .{};
        if (target_hwnd != 0) {
            markFbDirty(target_hwnd);
            flushDirtyBlits();
        }
    }
    return 1;
}

fn GetSystemMetrics(nIndex: i32) callconv(W) i32 {
    return switch (nIndex) {
        0 => 1920,
        1 => 1080,
        else => 0,
    };
}

fn SetWindowPos(hwnd: usize, hwndInsertAfter: usize, x: i32, y: i32, cx: i32, cy: i32, uFlags: u32) callconv(W) i32 {
    _ = hwndInsertAfter;
    const w = findWin(hwnd) orelse return 0;
    const SWP_NOSIZE: u32 = 0x0001;
    const SWP_NOMOVE: u32 = 0x0002;
    const SWP_SHOWWINDOW: u32 = 0x0040;
    const SWP_HIDEWINDOW: u32 = 0x0080;
    if ((uFlags & SWP_NOMOVE) == 0) {
        w.x = x;
        w.y = y;
    }
    var size_changed = false;
    if ((uFlags & SWP_NOSIZE) == 0) {
        const nw = @max(0, cx);
        var nh = @max(0, cy);
        if (winClassEqAscii(w, "ReBarWindow32") and w.tb_btn_count > 0 and nh < 28) {
            nh = 28;
        }
        if (nw != w.width or nh != w.height) size_changed = true;
        w.width = nw;
        w.height = nh;
        if (winClassEqAscii(w, "ReBarWindow32") and w.tb_btn_count > 0) {
            for (&windows) |*cw| {
                if (cw.in_use and winClassEqAscii(cw, "ToolbarWindow32")) {
                    cw.x = w.x;
                    cw.y = w.y;
                    if (nw > 0) cw.width = nw;
                    cw.height = nh;
                    cw.needs_paint = true;
                }
            }
        }
    }
    if ((uFlags & SWP_SHOWWINDOW) != 0) {
        w.visible = true;
        w.needs_paint = true;
        w.style |= WS_VISIBLE;
    } else if ((uFlags & SWP_HIDEWINDOW) != 0) {
        w.visible = false;
        w.style &= ~WS_VISIBLE;
    }
    ensureX11Window(w);
    if (w.x11_win != 0) {
        if (connection) |conn| {
            if ((uFlags & (SWP_NOMOVE | SWP_NOSIZE)) != (SWP_NOMOVE | SWP_NOSIZE) and (!w.fullscreen or size_changed)) {
                conn.moveResize(w.x11_win, if (w.fullscreen) 0 else w.x, if (w.fullscreen) 0 else w.y, @intCast(@max(1, w.width)), @intCast(@max(1, w.height)));
            }
            if ((uFlags & SWP_SHOWWINDOW) != 0 or w.visible) {
                if (!w.x11_mapped) {
                    conn.map(w.x11_win);
                    w.x11_mapped = true;
                }
                if (w.fullscreen or isFullscreenPopupStyle(w.style, w.width, w.height)) {
                    w.fullscreen = true;
                    if (!w.x11_fs_applied) {
                        conn.setFullscreen(w.x11_win, true);
                        w.x11_fs_applied = true;
                    }
                }
                if (g_cursor_count.load(.monotonic) < 0) {
                    conn.setCursorVisible(w.x11_win, false);
                }
            } else if ((uFlags & SWP_HIDEWINDOW) != 0 and !w.fullscreen and !w.has_gl) {
                conn.unmap(w.x11_win);
                w.x11_mapped = false;
                w.x11_fs_applied = false;
            }
            conn.flush();
        }
    }
    if (size_changed) {
        if (w.visible) w.needs_paint = true;
        _ = dispatchSubclassFrom(hwnd, WM_SIZE, 0, (@as(usize, @intCast(@max(0, w.height))) << 16) | @as(usize, @intCast(@max(0, w.width) & 0xffff)), null);
    }
    return 1;
}

fn GetWindowRect(hwnd: usize, lpRect: ?*Rect) callconv(W) i32 {
    const r = lpRect orelse return 0;
    if (findWin(hwnd)) |w| {
        const sp = winScreenPos(hwnd);
        r.* = .{ .left = sp.x, .top = sp.y, .right = sp.x + w.width, .bottom = sp.y + w.height };
        return 1;
    }
    r.* = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
    return 1;
}

fn SetWindowTextW(hwnd: usize, lpString: ?[*:0]const u16) callconv(W) i32 {
    const w = findWin(hwnd) orelse return 0;
    w.title_len = copyTitleU16(&w.title, lpString);
    if (w.x11_win != 0) {
        if (connection) |conn| {
            var tbuf: [256]u8 = undefined;
            _ = encodeTitleUtf8(w.title[0..w.title_len], &tbuf);
            conn.setTitle(w.x11_win, @ptrCast(&tbuf));
        }
    }
    return 1;
}

fn SetDlgItemTextW(hDlg: usize, nIDDlgItem: i32, lpString: ?[*:0]const u16) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem; _ = lpString;
    return 1;
}

fn GetDlgItemTextW(hDlg: usize, nIDDlgItem: i32, lpString: ?[*]u16, cchMax: i32) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem;
    if (lpString != null and cchMax > 0) lpString.?[0] = 0;
    return 0;
}

fn GetDlgItemTextA(hDlg: usize, nIDDlgItem: i32, lpString: ?[*]u8, cchMax: i32) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem;
    if (lpString != null and cchMax > 0) lpString.?[0] = 0;
    return 0;
}

fn SendDlgItemMessageW(hDlg: usize, nIDDlgItem: i32, msg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    _ = hDlg; _ = nIDDlgItem; _ = msg; _ = wParam; _ = lParam;
    return 0;
}

fn GetDlgItem(hDlg: usize, nIDDlgItem: i32) callconv(W) usize {
    _ = hDlg;
    return 0xDD0000 + @as(usize, @intCast(@max(nIDDlgItem, 0)));
}

fn GetDlgItemInt(hDlg: usize, nIDDlgItem: i32, lpTranslated: ?*i32, bSigned: i32) callconv(W) u32 {
    _ = hDlg; _ = nIDDlgItem; _ = bSigned;
    if (lpTranslated) |p| p.* = 1;
    return 0;
}

fn SetDlgItemInt(hDlg: usize, nIDDlgItem: i32, uValue: u32, bSigned: i32) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem; _ = uValue; _ = bSigned;
    return 1;
}

fn DialogBoxParamW(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*const anyopaque, dwInitParam: usize) callconv(W) isize {
    _ = hInstance; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    if (std.c.getenv("WINS_TRACE") != null) {
        std.debug.print("[WINS:USER32] DialogBoxParamW tmpl=0x{x}\n", .{@intFromPtr(lpTemplateName)});
    }
    return 1;
}

fn EndDialog(hDlg: usize, nResult: isize) callconv(W) i32 {
    _ = hDlg; _ = nResult;
    return 1;
}

fn EnableWindow(hWnd: usize, bEnable: i32) callconv(W) i32 {
    _ = hWnd; _ = bEnable;
    return 0;
}

fn LoadImageW(hInst: usize, name: ?*const anyopaque, uType: u32, cx: i32, cy: i32, fuLoad: u32) callconv(W) usize {
    _ = hInst; _ = name; _ = uType; _ = cx; _ = cy; _ = fuLoad;
    return 0x770001;
}

fn SystemParametersInfoW(uiAction: u32, uiParam: u32, pvParam: ?*anyopaque, fWinIni: u32) callconv(W) i32 {
    _ = uiParam;
    _ = fWinIni;
    if (uiAction == 0x0030) { // SPI_GETWORKAREA
        if (pvParam) |p| {
            const rc: *Rect = @ptrCast(@alignCast(p));
            rc.* = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
        }
    }
    return 1;
}

fn FindWindowExW(hWndParent: usize, hWndChildAfter: usize, lpszClass: ?*const anyopaque, lpszWindow: ?*const anyopaque) callconv(W) usize {
    _ = hWndParent; _ = hWndChildAfter; _ = lpszClass; _ = lpszWindow;
    return 0;
}

fn SetWindowsHookExW(idHook: i32, lpfn: ?*const anyopaque, hmod: usize, dwThreadId: u32) callconv(W) usize {
    _ = idHook; _ = lpfn; _ = hmod; _ = dwThreadId;
    return 0x880001;
}

fn UnhookWindowsHookEx(hhk: usize) callconv(W) i32 {
    _ = hhk;
    return 1;
}

fn CallNextHookEx(hhk: usize, nCode: i32, wParam: usize, lParam: usize) callconv(W) isize {
    _ = hhk; _ = nCode; _ = wParam; _ = lParam;
    return 0;
}

// GDI32.dll
fn GetDeviceCaps(hdc: usize, nIndex: i32) callconv(W) i32 {
    _ = hdc;
    return switch (nIndex) {
        2 => 1, // TECHNOLOGY = DT_RASDISPLAY
        8 => 1920, // HORZRES
        10 => 1080, // VERTRES
        12 => 32, // BITSPIXEL
        14 => 1, // PLANES
        38 => 0x7E99, // RASTERCAPS
        88 => 96, // LOGPIXELSX
        90 => 96, // LOGPIXELSY
        else => 0,
    };
}

fn CreateFontW(cHeight: i32, cWidth: i32, cEscapement: i32, cOrientation: i32, cWeight: i32, bItalic: u32, bUnderline: u32, bStrikeOut: u32, iCharSet: u32, iOutPrecision: u32, iClipPrecision: u32, iQuality: u32, iPitchAndFamily: u32, pszFaceName: ?[*:0]const u16) callconv(W) usize {
    _ = cHeight; _ = cWidth; _ = cEscapement; _ = cOrientation; _ = cWeight; _ = bItalic; _ = bUnderline; _ = bStrikeOut; _ = iCharSet; _ = iOutPrecision; _ = iClipPrecision; _ = iQuality; _ = iPitchAndFamily; _ = pszFaceName;
    return 0xF0001;
}

fn DeleteObject(ho: usize) callconv(W) i32 {
    if (ho >= HBRUSH_BASE and ho < HBRUSH_BASE + gdi_brushes.len) {
        const b = &gdi_brushes[ho - HBRUSH_BASE];
        if (!b.sticky) b.* = .{};
        return 1;
    }
    if (ho >= HPEN_BASE and ho < HPEN_BASE + gdi_pens.len) {
        const p = &gdi_pens[ho - HPEN_BASE];
        if (!p.sticky) p.* = .{};
        return 1;
    }
    if (ho >= HBITMAP_BASE and ho < HBITMAP_BASE + gdi_bitmaps.len) {
        const bm = &gdi_bitmaps[ho - HBITMAP_BASE];
        if (!bm.sticky) {
            bm.surface.deinit();
            if (bm.raw.len > 0) std.heap.page_allocator.free(bm.raw);
            bm.* = .{};
        }
        return 1;
    }
    if (ho >= HRGN_BASE and ho < HRGN_BASE + gdi_regions.len) {
        gdi_regions[ho - HRGN_BASE] = .{};
        return 1;
    }
    return 1;
}

fn CreateDIBSection(hdc: usize, pbmi: ?*const anyopaque, usage: u32, ppvBits: ?*?*anyopaque, hSection: usize, offset: u32) callconv(W) usize {
    _ = hdc;
    _ = usage;
    _ = hSection;
    _ = offset;
    var w: i32 = 64;
    var h: i32 = 64;
    var bottom_up = true;
    if (pbmi) |ptr| {
        const hdr: *const [10]i32 = @ptrCast(@alignCast(ptr));
        w = @max(1, @min(4096, hdr[1]));
        const raw_h = hdr[2];
        bottom_up = raw_h >= 0;
        h = @max(1, @min(4096, @as(i32, @intCast(@abs(raw_h)))));
    }
    const hbmp = allocBitmap(w, h, 0);
    if (bitmapFromHandle(hbmp)) |bm| {
        bm.bottom_up = bottom_up;
        if (ppvBits) |p| p.* = @ptrCast(bm.surface.pixels.ptr);
        return hbmp;
    }
    if (ppvBits) |p| p.* = @ptrFromInt(0x800000);
    return 0xB001;
}

var gl_dummy_xwin: x11.Window = 0;

pub const GlSurface = struct {
    display: *anyopaque,
    window: c_ulong,
    width: u32,
    height: u32,
};

pub fn ensureGlSurfaceForHwnd(hwnd: usize) ?GlSurface {
    const conn = ensureX11() orelse return null;
    if (findWin(hwnd)) |w| {
        w.has_gl = true;
        if (w.x11_win == 0) {
            if (w.width <= 0) w.width = 1920;
            if (w.height <= 0) w.height = 1080;
            ensureX11Window(w);
            if (w.x11_win != 0 and w.visible) {
                conn.map(w.x11_win);
                if (w.fullscreen or isFullscreenPopupStyle(w.style, w.width, w.height)) {
                    w.fullscreen = true;
                    conn.setFullscreen(w.x11_win, true);
                }
                conn.flush();
            }
        }
        if (w.x11_win != 0) {
            return .{
                .display = @ptrCast(conn.display),
                .window = w.x11_win,
                .width = @intCast(@max(1, w.width)),
                .height = @intCast(@max(1, w.height)),
            };
        }
    }
    if (gl_dummy_xwin == 0) {
        gl_dummy_xwin = conn.createUnmapped(0, 0, 1, 1) catch 0;
    }
    if (gl_dummy_xwin == 0) return null;
    return .{ .display = @ptrCast(conn.display), .window = gl_dummy_xwin, .width = 1, .height = 1 };
}

pub fn getWindowClientSize(hwnd: usize) struct { w: u32, h: u32 } {
    if (findWin(hwnd)) |w| {
        return .{ .w = @intCast(@max(1, w.width)), .h = @intCast(@max(1, w.height)) };
    }
    return .{ .w = 1920, .h = 1080 };
}

pub fn ensureGlSurfaceForDc(hdc: usize) ?GlSurface {
    if (dcFromHandle(hdc)) |dc| {
        return ensureGlSurfaceForHwnd(dc.hwnd);
    }
    return ensureGlSurfaceForHwnd(0);
}

fn SwapBuffers(hdc: usize) callconv(W) i32 {
    return gl64.swapBuffers(hdc);
}

fn ChoosePixelFormat(hdc: usize, ppfd: ?*const anyopaque) callconv(W) i32 {
    return gl64.choosePixelFormat(hdc, ppfd);
}

fn SetPixelFormat(hdc: usize, format: i32, ppfd: ?*const anyopaque) callconv(W) i32 {
    return gl64.setPixelFormat(hdc, format, ppfd);
}

fn DescribePixelFormat(hdc: usize, format: i32, nbytes: u32, ppfd: ?[*]u8) callconv(W) i32 {
    return gl64.describePixelFormat(hdc, format, nbytes, ppfd);
}

fn BitBlt(hdc: usize, x: i32, y: i32, cx: i32, cy: i32, hdcSrc: usize, x1: i32, y1: i32, rop: u32) callconv(W) i32 {
    const dc_dst = dcFromHandle(hdc) orelse return 1;
    const tgt_dst = dcTarget(dc_dst) orelse return 1;
    if (rop == 0x00000042 or rop == 0x00FF0062 or rop == 0x00550009 or rop == 0x005A0049 or rop == 0x00F00021) {
        patBltTarget(dc_dst, tgt_dst, x, y, cx, cy, rop);
        if (!dc_dst.is_mem) markFbDirty(dc_dst.hwnd);
        return 1;
    }
    const dc_src = dcFromHandle(hdcSrc) orelse return 1;
    const tgt_src = dcTarget(dc_src) orelse return 1;
    var flip = false;
    if (dc_src.is_mem) {
        if (bitmapFromHandle(dc_src.hbitmap)) |bm| flip = bm.bottom_up;
    }
    stretchCopy(tgt_dst, x, y, cx, cy, tgt_src, x1, y1, cx, cy, flip, rop);
    if (!dc_dst.is_mem) markFbDirty(dc_dst.hwnd);
    return 1;
}

fn SelectObject(hdc: usize, h: usize) callconv(W) usize {
    const dc = dcFromHandle(hdc) orelse return h;
    if (h >= HBRUSH_BASE and h < HBRUSH_BASE + gdi_brushes.len or (h >= 1 and h <= 31)) {
        const prev = if (dc.hbrush != 0) dc.hbrush else h;
        dc.hbrush = h;
        return prev;
    }
    if (h >= HPEN_BASE and h < HPEN_BASE + gdi_pens.len) {
        const prev = if (dc.hpen != 0) dc.hpen else h;
        dc.hpen = h;
        return prev;
    }
    if (h >= HBITMAP_BASE and h < HBITMAP_BASE + gdi_bitmaps.len) {
        const prev = if (dc.hbitmap != 0) dc.hbitmap else getDefaultBitmap();
        dc.hbitmap = h;
        return prev;
    }
    if (h >= HRGN_BASE and h < HRGN_BASE + gdi_regions.len) {
        if (regionFromHandle(h)) |r| {
            dc.has_clip = true;
            dc.clip = r.rect;
        }
        return 2; // COMPLEXREGION
    }
    const prev_f = if (dc.hfont != 0) dc.hfont else h;
    dc.hfont = h;
    return prev_f;
}

fn CreateCompatibleDC(hdc: usize) callconv(W) usize {
    _ = hdc;
    const m = allocDC(0, true);
    if (dcFromHandle(m)) |dc| {
        dc.hbitmap = getDefaultBitmap();
        return m;
    }
    return 0xB002;
}

fn CreateCompatibleBitmap(hdc: usize, cx: i32, cy: i32) callconv(W) usize {
    _ = hdc;
    const hbmp = allocBitmap(cx, cy, 0x00FFFFFF);
    return if (hbmp != 0) hbmp else 0xB003;
}

const Win32BitmapStruct = extern struct {
    bmType: i32 = 0,
    bmWidth: i32 = 16,
    bmHeight: i32 = 16,
    bmWidthBytes: i32 = 64,
    bmPlanes: u16 = 1,
    bmBitsPixel: u16 = 32,
    _pad: u32 = 0,
    bmBits: ?*anyopaque = null,
};

fn GetObjectA(h: usize, c: i32, pv: ?*anyopaque) callconv(W) i32 {
    return GetObjectW(h, c, pv);
}

fn GetObjectW(h: usize, c: i32, pv: ?*anyopaque) callconv(W) i32 {
    if (bitmapFromHandle(h)) |bm| {
        if (pv == null) return @sizeOf(Win32BitmapStruct);
        if (c >= @as(i32, @sizeOf(Win32BitmapStruct))) {
            const out: *Win32BitmapStruct = @ptrCast(@alignCast(pv.?));
            const w: i32 = @intCast(@max(1, bm.surface.width));
            const ht: i32 = @intCast(@max(1, bm.surface.height));
            out.* = .{
                .bmType = 0,
                .bmWidth = w,
                .bmHeight = ht,
                .bmWidthBytes = w * 4,
                .bmPlanes = 1,
                .bmBitsPixel = 32,
                .bmBits = if (bm.surface.pixels.len > 0) @ptrCast(bm.surface.pixels.ptr) else null,
            };
            return @sizeOf(Win32BitmapStruct);
        }
    }
    if (pv) |p| {
        if (c > 0) {
            const bytes: [*]u8 = @ptrCast(p);
            @memset(bytes[0..@intCast(@min(c, 92))], 0);
        }
        return c;
    }
    return 0;
}

fn CreateBitmap(nWidth: i32, nHeight: i32, nPlanes: u32, nBitCount: u32, lpBits: ?*const anyopaque) callconv(W) usize {
    _ = nPlanes;
    _ = nBitCount;
    _ = lpBits;
    const hbmp = allocBitmap(nWidth, nHeight, 0);
    return if (hbmp != 0) hbmp else 0xB004;
}

fn GetStockObject(i: i32) callconv(W) usize {
    if (i >= 0 and i < @as(i32, stock_objects.len)) {
        const idx: usize = @intCast(i);
        if (stock_objects[idx] != 0) return stock_objects[idx];
        const h: usize = switch (i) {
            0 => allocGdiBrush(0xFFFFFF, false, true), // WHITE_BRUSH
            1 => allocGdiBrush(0xC0C0C0, false, true), // LTGRAY_BRUSH
            2 => allocGdiBrush(0x808080, false, true), // GRAY_BRUSH
            3 => allocGdiBrush(0x404040, false, true), // DKGRAY_BRUSH
            4 => allocGdiBrush(0x000000, false, true), // BLACK_BRUSH
            5 => allocGdiBrush(0, true, true), // NULL_BRUSH / HOLLOW_BRUSH
            6 => allocGdiPen(0xFFFFFF, 1, false, true), // WHITE_PEN
            7 => allocGdiPen(0x000000, 1, false, true), // BLACK_PEN
            8 => allocGdiPen(0, 1, true, true), // NULL_PEN
            18 => allocGdiBrush(0xFFFFFF, false, true), // DC_BRUSH
            19 => allocGdiPen(0x000000, 1, false, true), // DC_PEN
            else => 0xF0001 + idx,
        };
        stock_objects[idx] = h;
        return h;
    }
    return 0xB005;
}

fn CreateFontIndirectW(lplf: ?*const anyopaque) callconv(W) usize {
    _ = lplf;
    return 0xF0002;
}

fn CreateSolidBrush(color: u32) callconv(W) usize {
    const h = allocGdiBrush(gdi.colorrefToXrgb(color), false, false);
    return if (h != 0) h else 0xB006;
}

fn CreatePen(iStyle: i32, cWidth: i32, color: u32) callconv(W) usize {
    const is_null = (iStyle == 5); // PS_NULL
    const h = allocGdiPen(gdi.colorrefToXrgb(color), @max(1, cWidth), is_null, false);
    return if (h != 0) h else 0xB007;
}

fn CreatePatternBrush(hbm: usize) callconv(W) usize {
    _ = hbm;
    const h = allocGdiBrush(0x00E8E8E8, false, false);
    return if (h != 0) h else 0xB008;
}

fn CreateHatchBrush(iHatch: i32, color: u32) callconv(W) usize {
    _ = iHatch;
    const h = allocGdiBrush(gdi.colorrefToXrgb(color), false, false);
    return if (h != 0) h else 0xB009;
}

fn ExtCreatePen(iPenStyle: u32, cWidth: u32, plbrush: ?*const anyopaque, cStyle: u32, pstyle: ?*const anyopaque) callconv(W) usize {
    _ = cStyle;
    _ = pstyle;
    var color: u32 = 0x000000;
    if (plbrush) |ptr| {
        const words: *const [2]u32 = @ptrCast(@alignCast(ptr));
        color = gdi.colorrefToXrgb(words[1]);
    }
    const is_null = (iPenStyle & 0xF) == 5;
    const h = allocGdiPen(color, @intCast(@max(1, cWidth)), is_null, false);
    return if (h != 0) h else 0xB00A;
}

fn DeleteDC(hdc: usize) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (!dc.is_screen) dc.* = .{};
    }
    return 1;
}

fn SaveDC(hdc: usize) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    var max_lvl: i32 = 0;
    for (saved_dcs) |s| {
        if (s.in_use and s.hdc == hdc and s.level > max_lvl) max_lvl = s.level;
    }
    for (&saved_dcs) |*s| {
        if (!s.in_use) {
            s.* = .{ .in_use = true, .hdc = hdc, .level = max_lvl + 1, .dc = dc.* };
            return max_lvl + 1;
        }
    }
    return 1;
}

fn RestoreDC(hdc: usize, nSavedDC: i32) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    var target_idx: ?usize = null;
    var best_lvl: i32 = -1;
    for (saved_dcs, 0..) |s, idx| {
        if (!s.in_use or s.hdc != hdc) continue;
        if (nSavedDC < 0) {
            if (s.level > best_lvl) {
                best_lvl = s.level;
                target_idx = idx;
            }
        } else if (s.level == nSavedDC) {
            target_idx = idx;
            break;
        }
    }
    if (target_idx) |idx| {
        dc.* = saved_dcs[idx].dc;
        saved_dcs[idx] = .{};
    }
    return 1;
}

fn GetROP2(hdc: usize) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| return dc.rop2;
    return 13;
}

fn SetROP2(hdc: usize, rop2: i32) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        const prev = dc.rop2;
        dc.rop2 = rop2;
        return prev;
    }
    return 13;
}

fn SetBkColor(hdc: usize, color: u32) callconv(W) u32 {
    if (dcFromHandle(hdc)) |dc| {
        const prev = xrgbToColorref(dc.bk_xrgb);
        dc.bk_xrgb = gdi.colorrefToXrgb(color);
        return prev;
    }
    return color;
}

fn SetBkMode(hdc: usize, mode: i32) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        const prev = dc.bk_mode;
        dc.bk_mode = mode;
        return prev;
    }
    return mode;
}

fn SetTextColor(hdc: usize, color: u32) callconv(W) u32 {
    if (dcFromHandle(hdc)) |dc| {
        const prev = xrgbToColorref(dc.text_xrgb);
        dc.text_xrgb = gdi.colorrefToXrgb(color);
        return prev;
    }
    return color;
}

fn CreateRectRgn(x1: i32, y1: i32, x2: i32, y2: i32) callconv(W) usize {
    const h = allocRegion(.{ .left = x1, .top = y1, .right = x2, .bottom = y2 });
    return if (h != 0) h else 0xB00B;
}

fn CreateRectRgnIndirect(lprect: ?*const anyopaque) callconv(W) usize {
    if (readRectPtr(lprect)) |r| {
        const h = allocRegion(.{ .left = r.left, .top = r.top, .right = r.right, .bottom = r.bottom });
        if (h != 0) return h;
    }
    return 0xB00C;
}

fn CombineRgn(hrgnDst: usize, hrgnSrc1: usize, hrgnSrc2: usize, iMode: i32) callconv(W) i32 {
    _ = hrgnSrc2;
    _ = iMode;
    if (regionFromHandle(hrgnDst)) |dst| {
        if (regionFromHandle(hrgnSrc1)) |s1| dst.rect = s1.rect;
    }
    return 2;
}

fn SelectClipRgn(hdc: usize, hrgn: usize) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (hrgn == 0) {
            dc.has_clip = false;
        } else if (regionFromHandle(hrgn)) |r| {
            dc.has_clip = true;
            dc.clip = r.rect;
        }
    }
    return 2;
}

fn ExcludeClipRect(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    _ = hdc; _ = left; _ = top; _ = right; _ = bottom;
    return 2;
}

fn IntersectClipRect(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        const incoming = gdi.Clip{ .left = left - dc.org_x, .top = top - dc.org_y, .right = right - dc.org_x, .bottom = bottom - dc.org_y };
        if (dc.has_clip) {
            dc.clip = intersectClip(dc.clip, incoming);
        } else {
            dc.has_clip = true;
            dc.clip = incoming;
        }
    }
    return 2;
}

fn GetClipRgn(hdc: usize, hrgn: usize) callconv(W) i32 {
    _ = hdc; _ = hrgn;
    return 0;
}

fn MoveToEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (lppt) |p| {
            const pt: *Point = @ptrCast(@alignCast(p));
            pt.* = .{ .x = dc.cur_x, .y = dc.cur_y };
        }
        dc.cur_x = x;
        dc.cur_y = y;
    }
    return 1;
}

fn LineTo(hdc: usize, x: i32, y: i32) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (dcTarget(dc)) |tgt| {
            if (dcPenColor(dc)) |col| {
                gdi.drawLine(tgt.surface, tgt.clip, tgt.ox + dc.cur_x, tgt.oy + dc.cur_y, tgt.ox + x, tgt.oy + y, col);
                if (!dc.is_mem) markFbDirty(dc.hwnd);
            }
        }
        dc.cur_x = x;
        dc.cur_y = y;
    }
    return 1;
}

fn Polyline(hdc: usize, apt: ?*const anyopaque, cpt: i32) callconv(W) i32 {
    const pts_ptr = apt orelse return 1;
    if (cpt < 2) return 1;
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const col = dcPenColor(dc) orelse return 1;
    const pts: [*]const Point = @ptrCast(@alignCast(pts_ptr));
    const n: usize = @intCast(@min(cpt, 4096));
    for (0 .. n - 1) |i| {
        gdi.drawLine(tgt.surface, tgt.clip, tgt.ox + pts[i].x, tgt.oy + pts[i].y, tgt.ox + pts[i + 1].x, tgt.oy + pts[i + 1].y, col);
    }
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn Polygon(hdc: usize, apt: ?*const anyopaque, cpt: i32) callconv(W) i32 {
    const pts_ptr = apt orelse return 1;
    if (cpt < 2) return 1;
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const pts: [*]const Point = @ptrCast(@alignCast(pts_ptr));
    const n: usize = @intCast(@min(cpt, 4096));
    if (dcBrushColor(dc)) |bcol| {
        var min_x = pts[0].x;
        var max_x = pts[0].x;
        var min_y = pts[0].y;
        var max_y = pts[0].y;
        for (pts[0..n]) |pt| {
            min_x = @min(min_x, pt.x);
            max_x = @max(max_x, pt.x);
            min_y = @min(min_y, pt.y);
            max_y = @max(max_y, pt.y);
        }
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + min_x, tgt.oy + min_y, tgt.ox + max_x + 1, tgt.oy + max_y + 1, bcol);
    }
    if (dcPenColor(dc)) |pcol| {
        for (0..n) |i| {
            const j = (i + 1) % n;
            gdi.drawLine(tgt.surface, tgt.clip, tgt.ox + pts[i].x, tgt.oy + pts[i].y, tgt.ox + pts[j].x, tgt.oy + pts[j].y, pcol);
        }
    }
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn Rectangle(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    if (dcBrushColor(dc)) |bcol| {
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + left, tgt.oy + top, tgt.ox + right, tgt.oy + bottom, bcol);
    }
    if (dcPenColor(dc)) |pcol| {
        gdi.frameRect(tgt.surface, tgt.clip, tgt.ox + left, tgt.oy + top, tgt.ox + right, tgt.oy + bottom, pcol);
    }
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn RoundRect(hdc: usize, left: i32, top: i32, right: i32, bottom: i32, width: i32, height: i32) callconv(W) i32 {
    _ = width; _ = height;
    return Rectangle(hdc, left, top, right, bottom);
}

fn Ellipse(hdc: usize, left: i32, top: i32, right: i32, bottom: i32) callconv(W) i32 {
    return Rectangle(hdc, left, top, right, bottom);
}

fn PatBlt(hdc: usize, x: i32, y: i32, w: i32, h: i32, rop: u32) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    patBltTarget(dc, tgt, x, y, w, h, rop);
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn StretchBlt(hdcDest: usize, xDest: i32, yDest: i32, wDest: i32, hDest: i32, hdcSrc: usize, xSrc: i32, ySrc: i32, wSrc: i32, hSrc: i32, rop: u32) callconv(W) i32 {
    const dc_dst = dcFromHandle(hdcDest) orelse return 1;
    const tgt_dst = dcTarget(dc_dst) orelse return 1;
    const dc_src = dcFromHandle(hdcSrc) orelse return 1;
    const tgt_src = dcTarget(dc_src) orelse return 1;
    var flip = false;
    if (dc_src.is_mem) {
        if (bitmapFromHandle(dc_src.hbitmap)) |bm| flip = bm.bottom_up;
    }
    stretchCopy(tgt_dst, xDest, yDest, wDest, hDest, tgt_src, xSrc, ySrc, wSrc, hSrc, flip, rop);
    if (!dc_dst.is_mem) markFbDirty(dc_dst.hwnd);
    return 1;
}

fn GdiAlphaBlend(hdcDest: usize, xDest: i32, yDest: i32, wDest: i32, hDest: i32, hdcSrc: usize, xSrc: i32, ySrc: i32, wSrc: i32, hSrc: i32, ftn: usize) callconv(W) i32 {
    _ = ftn;
    return StretchBlt(hdcDest, xDest, yDest, wDest, hDest, hdcSrc, xSrc, ySrc, wSrc, hSrc, 0x00CC0020);
}

fn GetTextExtentPoint32W(hdc: usize, lpString: ?[*:0]const u16, c: i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpString;
    if (lpSize) |s| {
        const ptr: *[2]i32 = @ptrCast(@alignCast(s));
        ptr[0] = @max(0, c) * 8;
        ptr[1] = 16;
    }
    return 1;
}

fn GetTextExtentPoint32A(hdc: usize, lpString: ?[*:0]const u8, c: i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpString;
    if (lpSize) |s| {
        const ptr: *[2]i32 = @ptrCast(@alignCast(s));
        ptr[0] = @max(0, c) * 8;
        ptr[1] = 16;
    }
    return 1;
}

fn GetTextExtentPointW(hdc: usize, lpString: ?[*:0]const u16, c: i32, lpSize: ?*anyopaque) callconv(W) i32 {
    return GetTextExtentPoint32W(hdc, lpString, c, lpSize);
}

fn GetTextExtentExPointA(hdc: usize, lpszStr: ?[*:0]const u8, cchString: i32, nMaxExtent: i32, lpnFit: ?*i32, alpDx: ?*i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = nMaxExtent;
    const n: usize = @intCast(@max(0, @min(cchString, 4096)));
    if (lpnFit) |fit| fit.* = @intCast(n);
    if (alpDx) |dx_ptr| {
        const arr: [*]i32 = @ptrCast(dx_ptr);
        for (0..n) |i| arr[i] = @as(i32, @intCast(i + 1)) * 8;
    }
    return GetTextExtentPoint32A(hdc, lpszStr, @intCast(n), lpSize);
}

fn GetTextExtentExPointW(hdc: usize, lpszStr: ?[*:0]const u16, cchString: i32, nMaxExtent: i32, lpnFit: ?*i32, alpDx: ?*i32, lpSize: ?*anyopaque) callconv(W) i32 {
    _ = nMaxExtent;
    const n: usize = @intCast(@max(0, @min(cchString, 4096)));
    if (lpnFit) |fit| fit.* = @intCast(n);
    if (alpDx) |dx_ptr| {
        const arr: [*]i32 = @ptrCast(dx_ptr);
        for (0..n) |i| arr[i] = @as(i32, @intCast(i + 1)) * 8;
    }
    return GetTextExtentPoint32W(hdc, lpszStr, @intCast(n), lpSize);
}

fn GetTextMetricsW(hdc: usize, lptm: ?*anyopaque) callconv(W) i32 {
    _ = hdc;
    if (lptm) |tm| {
        const bytes: [*]u8 = @ptrCast(tm);
        @memset(bytes[0..60], 0);
        const i32_ptr: *[7]i32 = @ptrCast(@alignCast(tm));
        i32_ptr[0] = 16; // tmHeight
        i32_ptr[1] = 13; // tmAscent
        i32_ptr[2] = 3; // tmDescent
        i32_ptr[5] = 8; // tmAveCharWidth
        i32_ptr[6] = 8; // tmMaxCharWidth
    }
    return 1;
}

fn ExtTextOutW(hdc: usize, x: i32, y: i32, options: u32, lprect: ?*const anyopaque, lpString: ?[*:0]const u16, c: u32, lpDx: ?*const i32) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    var tgt = dcTarget(dc) orelse return 1;
    if (readRectPtr(lprect)) |rc| {
        if ((options & 0x0002) != 0) { // ETO_OPAQUE
            gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + rc.left, tgt.oy + rc.top, tgt.ox + rc.right, tgt.oy + rc.bottom, dc.bk_xrgb);
        }
        if ((options & 0x0004) != 0) { // ETO_CLIPPED
            const rclip = gdi.Clip{ .left = tgt.ox + rc.left, .top = tgt.oy + rc.top, .right = tgt.ox + rc.right, .bottom = tgt.oy + rc.bottom };
            tgt.clip = intersectClip(tgt.clip, rclip);
        }
    }
    if (lpString) |s_ptr| {
        const n: usize = @min(c, 4096);
        if (n > 0) {
            const slice: [*]const u16 = @ptrCast(s_ptr);
            const dx_arr: ?[*]const i32 = if (lpDx) |p| @ptrCast(p) else null;
            drawTextAt(dc, tgt, x, y, slice[0..n], dx_arr);
        }
    }
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn ExtTextOutA(hdc: usize, x: i32, y: i32, options: u32, lprect: ?*const anyopaque, lpString: ?[*:0]const u8, c: u32, lpDx: ?*const i32) callconv(W) i32 {
    var u16_buf: [512]u16 = undefined;
    var n: usize = 0;
    if (lpString) |s_ptr| {
        const slice: [*]const u8 = @ptrCast(s_ptr);
        n = @min(c, u16_buf.len);
        for (0..n) |i| u16_buf[i] = slice[i];
    }
    return ExtTextOutW(hdc, x, y, options, lprect, if (n > 0) @ptrCast(&u16_buf) else null, @intCast(n), lpDx);
}

fn SetTextAlign(hdc: usize, align_flags: u32) callconv(W) u32 {
    if (dcFromHandle(hdc)) |dc| {
        const prev = dc.text_align;
        dc.text_align = align_flags;
        return prev;
    }
    return align_flags;
}

fn SetWindowOrgEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (lppt) |p| {
            const pt: *Point = @ptrCast(@alignCast(p));
            pt.* = .{ .x = dc.org_x, .y = dc.org_y };
        }
        dc.org_x = x;
        dc.org_y = y;
    }
    return 1;
}

fn OffsetWindowOrgEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    if (dcFromHandle(hdc)) |dc| {
        if (lppt) |p| {
            const pt: *Point = @ptrCast(@alignCast(p));
            pt.* = .{ .x = dc.org_x, .y = dc.org_y };
        }
        dc.org_x += x;
        dc.org_y += y;
    }
    return 1;
}

fn SetBrushOrgEx(hdc: usize, x: i32, y: i32, lppt: ?*anyopaque) callconv(W) i32 {
    _ = hdc; _ = x; _ = y; _ = lppt;
    return 1;
}

fn SetDIBits(hdc: usize, hbm: usize, start: u32, cLines: u32, lpBits: ?*const anyopaque, pbmi: ?*const anyopaque, ColorUse: u32) callconv(W) i32 {
    _ = hdc; _ = hbm; _ = start; _ = lpBits; _ = pbmi; _ = ColorUse;
    return @intCast(cLines);
}

fn GetDIBits(hdc: usize, hbm: usize, start: u32, cLines: u32, lpvBits: ?*anyopaque, pbmi: ?*anyopaque, usage: u32) callconv(W) i32 {
    _ = hdc; _ = hbm; _ = start; _ = lpvBits; _ = pbmi; _ = usage;
    return @intCast(cLines);
}

fn StretchDIBits(hdc: usize, xDest: i32, yDest: i32, DestWidth: i32, DestHeight: i32, xSrc: i32, ySrc: i32, SrcWidth: i32, SrcHeight: i32, lpBits: ?*const anyopaque, lpbmi: ?*const anyopaque, iUsage: u32, rop: u32) callconv(W) i32 {
    _ = xSrc; _ = ySrc; _ = SrcWidth; _ = SrcHeight; _ = lpBits; _ = lpbmi; _ = iUsage;
    if (dcFromHandle(hdc)) |dc| {
        if (dcTarget(dc)) |tgt| {
            if (rop == 0x00000042 or rop == 0x00FF0062) {
                patBltTarget(dc, tgt, xDest, yDest, DestWidth, DestHeight, rop);
                if (!dc.is_mem) markFbDirty(dc.hwnd);
            }
        }
    }
    return DestHeight;
}

fn GetPixel(hdc: usize, x: i32, y: i32) callconv(W) u32 {
    if (dcFromHandle(hdc)) |dc| {
        if (dcTarget(dc)) |tgt| {
            const px = tgt.ox + x;
            const py = tgt.oy + y;
            if (px >= 0 and py >= 0 and px < @as(i32, @intCast(tgt.surface.width)) and py < @as(i32, @intCast(tgt.surface.height))) {
                return xrgbToColorref(tgt.surface.pixels[@as(usize, @intCast(py)) * tgt.surface.width + @as(usize, @intCast(px))]);
            }
        }
    }
    return 0;
}

fn SetPixel(hdc: usize, x: i32, y: i32, color: u32) callconv(W) u32 {
    if (dcFromHandle(hdc)) |dc| {
        if (dcTarget(dc)) |tgt| {
            gdi.putPixelClipped(tgt.surface, tgt.clip, tgt.ox + x, tgt.oy + y, gdi.colorrefToXrgb(color));
            if (!dc.is_mem) markFbDirty(dc.hwnd);
        }
    }
    return color;
}

fn SetStretchBltMode(hdc: usize, mode: i32) callconv(W) i32 {
    _ = hdc;
    return mode;
}

fn RectVisible(hdc: usize, lprect: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = lprect;
    return 1;
}

fn DPtoLP(hdc: usize, lppt: ?*anyopaque, c: i32) callconv(W) i32 {
    _ = hdc; _ = lppt; _ = c;
    return 1;
}

fn EnumFontFamiliesExW(hdc: usize, lpLogfont: ?*anyopaque, lpProc: ?*anyopaque, lParam: usize, dwFlags: u32) callconv(W) i32 {
    _ = hdc; _ = lpLogfont; _ = lpProc; _ = lParam; _ = dwFlags;
    return 1;
}

fn StartDocW(hdc: usize, lpdi: ?*const anyopaque) callconv(W) i32 {
    _ = hdc; _ = lpdi;
    return 1;
}

fn EndDoc(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn StartPage(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

fn EndPage(hdc: usize) callconv(W) i32 {
    _ = hdc;
    return 1;
}

pub fn lookupGdi32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "BitBlt")) return @intFromPtr(&BitBlt);
    if (std.mem.eql(u8, name, "SelectObject")) return @intFromPtr(&SelectObject);
    if (std.mem.eql(u8, name, "CreateCompatibleDC")) return @intFromPtr(&CreateCompatibleDC);
    if (std.mem.eql(u8, name, "CreateCompatibleBitmap")) return @intFromPtr(&CreateCompatibleBitmap);
    if (std.mem.eql(u8, name, "GetObjectA")) return @intFromPtr(&GetObjectA);
    if (std.mem.eql(u8, name, "GetObjectW")) return @intFromPtr(&GetObjectW);
    if (std.mem.eql(u8, name, "CreateBitmap")) return @intFromPtr(&CreateBitmap);
    if (std.mem.eql(u8, name, "GetStockObject")) return @intFromPtr(&GetStockObject);
    if (std.mem.eql(u8, name, "GetDeviceCaps")) return @intFromPtr(&GetDeviceCaps);
    if (std.mem.eql(u8, name, "CreateFontW")) return @intFromPtr(&CreateFontW);
    if (std.mem.eql(u8, name, "CreateFontIndirectW")) return @intFromPtr(&CreateFontIndirectW);
    if (std.mem.eql(u8, name, "CreateSolidBrush")) return @intFromPtr(&CreateSolidBrush);
    if (std.mem.eql(u8, name, "CreatePen")) return @intFromPtr(&CreatePen);
    if (std.mem.eql(u8, name, "CreatePatternBrush")) return @intFromPtr(&CreatePatternBrush);
    if (std.mem.eql(u8, name, "CreateHatchBrush")) return @intFromPtr(&CreateHatchBrush);
    if (std.mem.eql(u8, name, "ExtCreatePen")) return @intFromPtr(&ExtCreatePen);
    if (std.mem.eql(u8, name, "DeleteDC")) return @intFromPtr(&DeleteDC);
    if (std.mem.eql(u8, name, "SaveDC")) return @intFromPtr(&SaveDC);
    if (std.mem.eql(u8, name, "RestoreDC")) return @intFromPtr(&RestoreDC);
    if (std.mem.eql(u8, name, "GetROP2")) return @intFromPtr(&GetROP2);
    if (std.mem.eql(u8, name, "SetROP2")) return @intFromPtr(&SetROP2);
    if (std.mem.eql(u8, name, "SetBkColor")) return @intFromPtr(&SetBkColor);
    if (std.mem.eql(u8, name, "SetBkMode")) return @intFromPtr(&SetBkMode);
    if (std.mem.eql(u8, name, "SetTextColor")) return @intFromPtr(&SetTextColor);
    if (std.mem.eql(u8, name, "CreateRectRgn")) return @intFromPtr(&CreateRectRgn);
    if (std.mem.eql(u8, name, "CreateRectRgnIndirect")) return @intFromPtr(&CreateRectRgnIndirect);
    if (std.mem.eql(u8, name, "CombineRgn")) return @intFromPtr(&CombineRgn);
    if (std.mem.eql(u8, name, "SelectClipRgn")) return @intFromPtr(&SelectClipRgn);
    if (std.mem.eql(u8, name, "ExcludeClipRect")) return @intFromPtr(&ExcludeClipRect);
    if (std.mem.eql(u8, name, "IntersectClipRect")) return @intFromPtr(&IntersectClipRect);
    if (std.mem.eql(u8, name, "GetClipRgn")) return @intFromPtr(&GetClipRgn);
    if (std.mem.eql(u8, name, "MoveToEx")) return @intFromPtr(&MoveToEx);
    if (std.mem.eql(u8, name, "LineTo")) return @intFromPtr(&LineTo);
    if (std.mem.eql(u8, name, "Polyline")) return @intFromPtr(&Polyline);
    if (std.mem.eql(u8, name, "Polygon")) return @intFromPtr(&Polygon);
    if (std.mem.eql(u8, name, "Rectangle")) return @intFromPtr(&Rectangle);
    if (std.mem.eql(u8, name, "RoundRect")) return @intFromPtr(&RoundRect);
    if (std.mem.eql(u8, name, "Ellipse")) return @intFromPtr(&Ellipse);
    if (std.mem.eql(u8, name, "PatBlt")) return @intFromPtr(&PatBlt);
    if (std.mem.eql(u8, name, "StretchBlt")) return @intFromPtr(&StretchBlt);
    if (std.mem.eql(u8, name, "GdiAlphaBlend")) return @intFromPtr(&GdiAlphaBlend);
    if (std.mem.eql(u8, name, "GetTextExtentPoint32W")) return @intFromPtr(&GetTextExtentPoint32W);
    if (std.mem.eql(u8, name, "GetTextExtentPoint32A")) return @intFromPtr(&GetTextExtentPoint32A);
    if (std.mem.eql(u8, name, "GetTextExtentPointW")) return @intFromPtr(&GetTextExtentPointW);
    if (std.mem.eql(u8, name, "GetTextExtentExPointA")) return @intFromPtr(&GetTextExtentExPointA);
    if (std.mem.eql(u8, name, "GetTextExtentExPointW")) return @intFromPtr(&GetTextExtentExPointW);
    if (std.mem.eql(u8, name, "GetTextMetricsW")) return @intFromPtr(&GetTextMetricsW);
    if (std.mem.eql(u8, name, "ExtTextOutW")) return @intFromPtr(&ExtTextOutW);
    if (std.mem.eql(u8, name, "ExtTextOutA")) return @intFromPtr(&ExtTextOutA);
    if (std.mem.eql(u8, name, "SetTextAlign")) return @intFromPtr(&SetTextAlign);
    if (std.mem.eql(u8, name, "SetWindowOrgEx")) return @intFromPtr(&SetWindowOrgEx);
    if (std.mem.eql(u8, name, "OffsetWindowOrgEx")) return @intFromPtr(&OffsetWindowOrgEx);
    if (std.mem.eql(u8, name, "SetBrushOrgEx")) return @intFromPtr(&SetBrushOrgEx);
    if (std.mem.eql(u8, name, "SetDIBits")) return @intFromPtr(&SetDIBits);
    if (std.mem.eql(u8, name, "GetDIBits")) return @intFromPtr(&GetDIBits);
    if (std.mem.eql(u8, name, "StretchDIBits")) return @intFromPtr(&StretchDIBits);
    if (std.mem.eql(u8, name, "GetPixel")) return @intFromPtr(&GetPixel);
    if (std.mem.eql(u8, name, "SetPixel")) return @intFromPtr(&SetPixel);
    if (std.mem.eql(u8, name, "SetStretchBltMode")) return @intFromPtr(&SetStretchBltMode);
    if (std.mem.eql(u8, name, "RectVisible")) return @intFromPtr(&RectVisible);
    if (std.mem.eql(u8, name, "DPtoLP")) return @intFromPtr(&DPtoLP);
    if (std.mem.eql(u8, name, "EnumFontFamiliesExW")) return @intFromPtr(&EnumFontFamiliesExW);
    if (std.mem.eql(u8, name, "StartDocW")) return @intFromPtr(&StartDocW);
    if (std.mem.eql(u8, name, "EndDoc")) return @intFromPtr(&EndDoc);
    if (std.mem.eql(u8, name, "StartPage")) return @intFromPtr(&StartPage);
    if (std.mem.eql(u8, name, "EndPage")) return @intFromPtr(&EndPage);
    if (std.mem.eql(u8, name, "DeleteObject")) return @intFromPtr(&DeleteObject);
    if (std.mem.eql(u8, name, "CreateDIBSection")) return @intFromPtr(&CreateDIBSection);
    if (std.mem.eql(u8, name, "SwapBuffers")) return @intFromPtr(&SwapBuffers);
    if (std.mem.eql(u8, name, "ChoosePixelFormat")) return @intFromPtr(&ChoosePixelFormat);
    if (std.mem.eql(u8, name, "SetPixelFormat")) return @intFromPtr(&SetPixelFormat);
    if (std.mem.eql(u8, name, "DescribePixelFormat")) return @intFromPtr(&DescribePixelFormat);
    return null;
}

fn ClientToScreen(hwnd: usize, lpPoint: ?*anyopaque) callconv(W) i32 {
    const p = lpPoint orelse return 0;
    const pt: *Point = @ptrCast(@alignCast(p));
    const sp = winScreenPos(hwnd);
    pt.x += sp.x;
    pt.y += sp.y;
    return 1;
}

/// X window the clipboard owns CLIPBOARD with: any of the app's top-level X windows.
fn clipXWindow() x11.Window {
    for (&windows) |*w| if (w.in_use and w.x11_win != 0) return w.x11_win;
    return 0;
}

fn OpenClipboard(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return if (clipboard.open(connection, clipXWindow())) 1 else 0;
}

fn CloseClipboard() callconv(W) i32 {
    return if (clipboard.close(connection, clipXWindow())) 1 else 0;
}

fn EmptyClipboard() callconv(W) i32 {
    return if (clipboard.empty()) 1 else 0;
}

fn GetClipboardData(uFormat: u32) callconv(W) ?*anyopaque {
    return @ptrFromInt(clipboard.get(uFormat));
}

fn SetClipboardData(uFormat: u32, hMem: ?*anyopaque) callconv(W) ?*anyopaque {
    return @ptrFromInt(clipboard.set(uFormat, @intFromPtr(hMem)));
}

fn CreateDialogParamW(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*const anyopaque, dwInitParam: usize) callconv(W) usize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 0xD001;
}

fn DestroyCursor(hCursor: usize) callconv(W) i32 {
    _ = hCursor;
    return 1;
}

fn DestroyIcon(hIcon: usize) callconv(W) i32 {
    _ = hIcon;
    return 1;
}

/// Keyboard focus as X11 reports it: the HWND of the last FocusIn, or none
/// after a FocusOut. Before any focus event, the first visible top-level
/// window counts as active (a fresh Windows process owns the foreground).
var g_focus_hwnd: usize = 0;
var g_focus_lost = false;

fn activeTopLevel() usize {
    if (g_focus_hwnd != 0) return g_focus_hwnd;
    if (g_focus_lost) return 0;
    for (&windows) |*w| {
        if (w.in_use and w.parent == 0 and w.visible) return w.hwnd;
    }
    for (&windows) |*w| {
        if (w.in_use and w.parent == 0) return w.hwnd;
    }
    return 0;
}

fn GetActiveWindow() callconv(W) usize {
    return activeTopLevel();
}

fn GetForegroundWindow() callconv(W) usize {
    return activeTopLevel();
}

fn GetAncestor(hwnd: usize, gaFlags: u32) callconv(W) usize {
    _ = gaFlags;
    return hwnd;
}

fn GetFocus() callconv(W) usize {
    if (g_focus != 0 and findWin(g_focus) != null) return g_focus;
    return 1; // no focus set yet: the value this loader always returned before focus tracking
}

fn GetKeyState(nVirtKey: i32) callconv(W) i16 {
    return kbd.getKeyState(nVirtKey);
}

fn GetMessageTime() callconv(W) i32 {
    return @bitCast(g_msg_time);
}

fn PtInRect(lprc: ?*const anyopaque, pt_packed: u64) callconv(W) i32 {
    const r = readRectPtr(lprc) orelse return 0;
    const px: i32 = @bitCast(@as(u32, @truncate(pt_packed)));
    const py: i32 = @bitCast(@as(u32, @truncate(pt_packed >> 32)));
    return if (px >= r.left and px < r.right and py >= r.top and py < r.bottom) 1 else 0;
}

fn ReleaseCapture() callconv(W) i32 {
    const old = g_capture;
    g_capture = 0;
    if (old != 0 and findWin(old) != null) _ = sendMessageW(old, WM_CAPTURECHANGED, 0, 0);
    return 1;
}

fn SetCapture(hwnd: usize) callconv(W) usize {
    const old = g_capture;
    g_capture = if (findWin(hwnd) != null) hwnd else 0;
    if (old != 0 and old != g_capture and findWin(old) != null) _ = sendMessageW(old, WM_CAPTURECHANGED, 0, g_capture);
    return old;
}

fn GetCapture() callconv(W) usize {
    return if (findWin(g_capture) != null) g_capture else 0;
}

fn GetCursorPos(lpPoint: ?*anyopaque) callconv(W) i32 {
    if (lpPoint) |p| {
        const pt: *Point = @ptrCast(@alignCast(p));
        pt.* = g_cursor;
    }
    return 1;
}

const MonitorInfo = extern struct {
    cbSize: u32,
    rcMonitor: Rect,
    rcWork: Rect,
    dwFlags: u32,
};

fn GetMonitorInfoW(hMonitor: usize, lpmi: ?*MonitorInfo) callconv(W) i32 {
    _ = hMonitor;
    if (lpmi) |mi| {
        mi.rcMonitor = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
        mi.rcWork = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1040 };
        mi.dwFlags = 1;
    }
    return 1;
}

fn GetMonitorInfoA(hMonitor: usize, lpmi: ?*MonitorInfo) callconv(W) i32 {
    return GetMonitorInfoW(hMonitor, lpmi);
}

fn MonitorFromPoint(pt_x: i32, pt_y: i32, dwFlags: u32) callconv(W) usize {
    _ = pt_x; _ = pt_y; _ = dwFlags;
    return 0x10001;
}

fn MonitorFromRect(lprc: ?*const anyopaque, dwFlags: u32) callconv(W) usize {
    _ = lprc; _ = dwFlags;
    return 0x10001;
}

fn MonitorFromWindow(hwnd: usize, dwFlags: u32) callconv(W) usize {
    _ = hwnd; _ = dwFlags;
    return 0x10001;
}

fn GetParent(hwnd: usize) callconv(W) usize {
    const w = findWin(hwnd) orelse return 0;
    return w.parent;
}

fn GetWindowLongPtrW(hwnd: usize, nIndex: i32) callconv(W) isize {
    const w = findWin(hwnd) orelse {
        if (nIndex == GWL_STYLE) return @bitCast(@as(usize, 0x10cf0000));
        return 0;
    };
    return switch (nIndex) {
        GWLP_WNDPROC => if (w.wndproc) |p| @bitCast(@intFromPtr(p)) else 0,
        GWLP_HINSTANCE => @bitCast(w.hinstance),
        GWLP_HWNDPARENT => @bitCast(w.parent),
        GWL_STYLE => @as(i32, @bitCast(w.style)),
        GWL_EXSTYLE => @as(i32, @bitCast(w.ex_style)),
        GWLP_USERDATA => w.userdata,
        GWLP_ID => w.id,
        else => if (nIndex >= 0 and @mod(nIndex, @sizeOf(isize)) == 0) blk: {
            const slot: usize = @intCast(@divTrunc(nIndex, @sizeOf(isize)));
            break :blk if (slot < w.extra.len) w.extra[slot] else 0;
        } else 0,
    };
}

fn SetWindowLongPtrW(hwnd: usize, nIndex: i32, dwNewLong: isize) callconv(W) isize {
    const w = findWin(hwnd) orelse return 0;
    const prev = GetWindowLongPtrW(hwnd, nIndex);
    switch (nIndex) {
        GWLP_WNDPROC => w.wndproc = if (dwNewLong != 0) @ptrFromInt(@as(usize, @bitCast(dwNewLong))) else null,
        GWLP_HINSTANCE => w.hinstance = @bitCast(dwNewLong),
        GWLP_HWNDPARENT => w.parent = @bitCast(dwNewLong),
        GWL_STYLE => {
            w.style = @truncate(@as(usize, @bitCast(dwNewLong)));
            if ((w.style & WS_CHILD) == 0 and w.x11_win != 0) {
                const want_fs = w.fullscreen or isFullscreenPopupStyle(w.style, w.width, w.height);
                if (want_fs and !w.fullscreen) {
                    w.fullscreen = true;
                    if (connection) |conn| conn.setFullscreen(w.x11_win, true);
                }
            }
        },
        GWL_EXSTYLE => w.ex_style = @truncate(@as(usize, @bitCast(dwNewLong))),
        GWLP_USERDATA => w.userdata = dwNewLong,
        GWLP_ID => w.id = dwNewLong,
        else => {
            if (nIndex >= 0 and @mod(nIndex, @sizeOf(isize)) == 0) {
                const slot: usize = @intCast(@divTrunc(nIndex, @sizeOf(isize)));
                if (slot < w.extra.len) w.extra[slot] = dwNewLong;
            }
        },
    }
    return prev;
}

fn GetWindowLongW(hwnd: usize, nIndex: i32) callconv(W) i32 {
    return @truncate(GetWindowLongPtrW(hwnd, nIndex));
}

fn SetWindowLongW(hwnd: usize, nIndex: i32, dwNewLong: i32) callconv(W) i32 {
    return @truncate(SetWindowLongPtrW(hwnd, nIndex, dwNewLong));
}

fn GetWindowLongPtrA(hwnd: usize, nIndex: i32) callconv(W) isize {
    return GetWindowLongPtrW(hwnd, nIndex);
}

fn SetWindowLongPtrA(hwnd: usize, nIndex: i32, dwNewLong: isize) callconv(W) isize {
    return SetWindowLongPtrW(hwnd, nIndex, dwNewLong);
}

fn GetWindowLongA(hwnd: usize, nIndex: i32) callconv(W) i32 {
    return GetWindowLongW(hwnd, nIndex);
}

fn SetWindowLongA(hwnd: usize, nIndex: i32, dwNewLong: i32) callconv(W) i32 {
    return SetWindowLongW(hwnd, nIndex, dwNewLong);
}

const WindowPlacement = extern struct {
    length: u32,
    flags: u32,
    showCmd: u32,
    ptMinPosition: Point,
    ptMaxPosition: Point,
    rcNormalPosition: Rect,
};

fn GetWindowPlacement(hwnd: usize, lpwndpl: ?*WindowPlacement) callconv(W) i32 {
    _ = hwnd;
    if (lpwndpl) |wp| {
        wp.showCmd = 1;
        wp.rcNormalPosition = .{ .left = 0, .top = 0, .right = 1280, .bottom = 720 };
    }
    return 1;
}

fn SetWindowPlacement(hwnd: usize, lpwndpl: ?*const anyopaque) callconv(W) i32 {
    if (lpwndpl) |p| {
        const wp: *const WindowPlacement = @ptrCast(@alignCast(p));
        const r = wp.rcNormalPosition;
        const w = if (r.right > r.left) r.right - r.left else 1024;
        const h = if (r.bottom > r.top) r.bottom - r.top else 720;
        const show_flag: u32 = if (wp.showCmd != 0) 0x0040 else 0;
        _ = SetWindowPos(hwnd, 0, r.left, r.top, w, h, 0x0004 | 0x0010 | show_flag);
    }
    return 1;
}

fn IsDialogMessageW(hDlg: usize, lpMsg: ?*const anyopaque) callconv(W) i32 {
    _ = hDlg; _ = lpMsg;
    return 0;
}

fn SetTimer(hwnd: usize, nIDEvent: usize, uElapse: u32, lpTimerFunc: ?*const anyopaque) callconv(W) usize {
    _ = hwnd; _ = uElapse; _ = lpTimerFunc;
    return if (nIDEvent != 0) nIDEvent else 1;
}

fn KillTimer(hwnd: usize, uIDEvent: usize) callconv(W) i32 {
    _ = hwnd; _ = uIDEvent;
    return 1;
}

fn OffsetRect(lprc: ?*Rect, dx: i32, dy: i32) callconv(W) i32 {
    if (lprc) |r| {
        r.left += dx;
        r.right += dx;
        r.top += dy;
        r.bottom += dy;
    }
    return 1;
}

fn CopyRect(lprcDst: ?*Rect, lprcSrc: ?*const Rect) callconv(W) i32 {
    if (lprcDst != null and lprcSrc != null) {
        lprcDst.?.* = lprcSrc.?.*;
    }
    return 1;
}

fn ScreenToClient(hwnd: usize, lpPoint: ?*anyopaque) callconv(W) i32 {
    const p = lpPoint orelse return 0;
    const pt: *Point = @ptrCast(@alignCast(p));
    const sp = winScreenPos(hwnd);
    pt.x -= sp.x;
    pt.y -= sp.y;
    return 1;
}

fn SetCursor(hCursor: usize) callconv(W) usize {
    return hCursor;
}

/// Windows keeps a display counter (0 with a mouse attached): ShowCursor adds
/// or subtracts 1 and returns the new value, and the cursor shows while it is
/// >= 0. Games hide it with `while (ShowCursor(FALSE) >= 0) {}`, which spins
/// forever unless the count really moves.
var g_cursor_count = std.atomic.Value(i32).init(0);

fn ShowCursor(bShow: i32) callconv(W) i32 {
    const new_val = if (bShow != 0) g_cursor_count.fetchAdd(1, .monotonic) + 1 else g_cursor_count.fetchSub(1, .monotonic) - 1;
    if (connection) |conn| {
        const hwnd = activeTopLevel();
        if (findWin(hwnd)) |w| {
            if (w.x11_win != 0) conn.setCursorVisible(w.x11_win, new_val >= 0);
        }
    }
    return new_val;
}

fn SetCursorPos(x: i32, y: i32) callconv(W) i32 {
    g_cursor_x = x;
    g_cursor_y = y;
    if (!g_focus_lost) {
        if (connection) |conn| {
            const hwnd = activeTopLevel();
            if (findWin(hwnd)) |w| {
                if (w.x11_win != 0) {
                    const sp = winScreenPos(hwnd);
                    const cx = x - sp.x;
                    const cy = y - sp.y;
                    g_warp_target_x = cx;
                    g_warp_target_y = cy;
                    g_warp_pending = true;
                    conn.warpPointer(w.x11_win, cx, cy);
                }
            }
        }
    }
    return 1;
}

fn ClipCursor(lpRect: ?*const anyopaque) callconv(W) i32 {
    _ = lpRect;
    return 1;
}

/// Moves keyboard focus and sends WM_KILLFOCUS / WM_SETFOCUS synchronously, as
/// Windows does. Returns the previous focus window.
fn SetFocus(hwnd: usize) callconv(W) usize {
    const prev = if (findWin(g_focus) != null) g_focus else 0;
    if (hwnd != 0 and findWin(hwnd) == null) return 0;
    if (hwnd == prev) return prev;
    g_focus = hwnd;
    if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:FOCUS] 0x{x} -> 0x{x}\n", .{ prev, hwnd });
    if (prev != 0) _ = sendMessageW(prev, WM_KILLFOCUS, hwnd, 0);
    if (hwnd != 0 and g_focus == hwnd) _ = sendMessageW(hwnd, WM_SETFOCUS, prev, 0);
    return prev;
}

fn SetForegroundWindow(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn TrackMouseEvent(lpEventTrack: ?*anyopaque) callconv(W) i32 {
    _ = lpEventTrack;
    return 1;
}

fn UnregisterClassW(lpClassName: ?*const u16, hInstance: usize) callconv(W) i32 {
    _ = lpClassName; _ = hInstance;
    return 1;
}

fn ValidateRect(hwnd: usize, lpRect: ?*const anyopaque) callconv(W) i32 {
    _ = hwnd; _ = lpRect;
    return 1;
}

fn RegisterRawInputDevices(pRawInputDevices: ?*const anyopaque, uiNumDevices: u32, cbSize: u32) callconv(W) i32 {
    _ = pRawInputDevices; _ = uiNumDevices; _ = cbSize;
    return 1;
}

fn GetRawInputDeviceInfoW(hDevice: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32) callconv(W) u32 {
    _ = hDevice; _ = uiCommand; _ = pData;
    if (pcbSize) |p| p.* = 0;
    return 0;
}

fn GetRawInputData(hRawInput: usize, uiCommand: u32, pData: ?*anyopaque, pcbSize: ?*u32, cbSizeHeader: u32) callconv(W) u32 {
    _ = hRawInput; _ = uiCommand; _ = pData; _ = cbSizeHeader;
    if (pcbSize) |p| p.* = 0;
    return 0;
}

fn GetRawInputDeviceList(pRawInputDeviceList: ?*anyopaque, puiNumDevices: ?*u32, cbSize: u32) callconv(W) u32 {
    _ = pRawInputDeviceList; _ = cbSize;
    if (puiNumDevices) |p| p.* = 0;
    return 0;
}

fn RegisterDeviceNotificationW(hRecipient: usize, NotificationFilter: ?*anyopaque, Flags: u32) callconv(W) usize {
    _ = hRecipient; _ = NotificationFilter; _ = Flags;
    return 0x20001;
}

fn UnregisterDeviceNotification(Handle: usize) callconv(W) i32 {
    _ = Handle;
    return 1;
}

fn GetKeyNameTextW(lParam: i32, lpString: ?[*]u16, cchSize: i32) callconv(W) i32 {
    _ = lParam; _ = lpString; _ = cchSize;
    return 0;
}

fn GetAsyncKeyState(vKey: i32) callconv(W) i16 {
    return kbd.getAsyncKeyState(vKey);
}

fn GetMessagePos() callconv(W) u32 {
    const x: u16 = @bitCast(@as(i16, @truncate(g_cursor_x)));
    const y: u16 = @bitCast(@as(i16, @truncate(g_cursor_y)));
    return (@as(u32, y) << 16) | @as(u32, x);
}

fn GetMessageExtraInfo() callconv(W) isize {
    return 0;
}

fn DragDetect(hwnd: usize, pt_x: i32, pt_y: i32) callconv(W) i32 {
    _ = hwnd; _ = pt_x; _ = pt_y;
    return 0;
}

var g_msg_a_calls: u32 = 0;

fn GetMessageA(lpMsg: ?*anyopaque, hwnd: usize, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(W) i32 {
    // MSG is layout-identical for A/W on x64; pump the real queue (which reads X11).
    if (std.c.getenv("WINS_TRACE") != null) {
        const n = @atomicRmw(u32, &g_msg_a_calls, .Add, 1, .monotonic);
        if (n < 5 or n % 1000 == 0) std.debug.print("[WINS:MSG] GetMessageA call #{d}\n", .{n});
    }
    return getMessageW(@ptrCast(@alignCast(lpMsg)), hwnd, wMsgFilterMin, wMsgFilterMax);
}

fn PeekMessageA(lpMsg: ?*anyopaque, hwnd: usize, wMsgFilterMin: u32, wMsgFilterMax: u32, wRemoveMsg: u32) callconv(W) i32 {
    if (std.c.getenv("WINS_TRACE") != null) {
        const n = @atomicRmw(u32, &g_msg_a_calls, .Add, 1, .monotonic);
        if (n < 5 or n % 1000 == 0) std.debug.print("[WINS:MSG] PeekMessageA call #{d} rm={d}\n", .{ n, wRemoveMsg });
    }
    return peekMessageW(@ptrCast(@alignCast(lpMsg)), hwnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

fn DispatchMessageA(lpMsg: ?*const anyopaque) callconv(W) isize {
    if (std.c.getenv("WINS_TRACE") != null) {
        const n = @atomicRmw(u32, &g_msg_a_calls, .Add, 1, .monotonic);
        if (n < 5 or n % 1000 == 0) std.debug.print("[WINS:MSG] DispatchMessageA call #{d}\n", .{n});
    }
    return @intCast(dispatchMessageW(@ptrCast(@alignCast(lpMsg))));
}

fn CopyImage(h: usize, uType: u32, cx: i32, cy: i32, uFlags: u32) callconv(W) usize {
    _ = uType; _ = cx; _ = cy; _ = uFlags;
    return h;
}

fn wvsprintfA(lpOut: ?[*]u8, lpFmt: ?[*:0]const u8, arglist: ?*anyopaque) callconv(W) i32 {
    _ = lpFmt; _ = arglist;
    if (lpOut) |p| p[0] = 0;
    return 0;
}

fn wsprintfA(lpOut: ?[*]u8, lpFmt: ?[*:0]const u8) callconv(W) i32 {
    _ = lpFmt;
    if (lpOut) |p| p[0] = 0;
    return 0;
}

const DisplayModeSpec = struct { w: u32, h: u32, hz: u32 };
const display_modes = [_]DisplayModeSpec{
    .{ .w = 800, .h = 600, .hz = 60 },
    .{ .w = 1024, .h = 576, .hz = 60 },
    .{ .w = 1280, .h = 720, .hz = 60 },
    .{ .w = 1366, .h = 768, .hz = 60 },
    .{ .w = 1600, .h = 900, .hz = 60 },
    .{ .w = 1920, .h = 1080, .hz = 60 },
};

fn EnumDisplaySettingsA(lpszDeviceName: ?[*:0]const u8, iModeNum: u32, lpDevMode: ?*anyopaque) callconv(W) i32 {
    _ = lpszDeviceName;
    const raw: [*]u8 = @ptrCast(lpDevMode orelse return 0);
    const idx: usize = if (iModeNum >= 0xFFFFFFFE) (display_modes.len - 1) else if (iModeNum < display_modes.len) iModeNum else return 0;
    const m = display_modes[idx];
    const sz = std.mem.readInt(u16, raw[36..38], .little);
    const clear_len: usize = @max(@as(usize, 156), @min(@as(usize, 256), sz));
    @memset(raw[0..clear_len], 0);
    @memcpy(raw[0..8], "DISPLAY1");
    std.mem.writeInt(u16, raw[32..34], 0x0401, .little);
    std.mem.writeInt(u16, raw[36..38], 156, .little);
    std.mem.writeInt(u32, raw[40..44], 0x005C0000, .little);
    std.mem.writeInt(u32, raw[104..108], 32, .little);
    std.mem.writeInt(u32, raw[108..112], m.w, .little);
    std.mem.writeInt(u32, raw[112..116], m.h, .little);
    std.mem.writeInt(u32, raw[120..124], m.hz, .little);
    return 1;
}

fn EnumDisplaySettingsW(lpszDeviceName: ?*const u16, iModeNum: u32, lpDevMode: ?*anyopaque) callconv(W) i32 {
    _ = lpszDeviceName;
    const raw: [*]u8 = @ptrCast(lpDevMode orelse return 0);
    const idx: usize = if (iModeNum >= 0xFFFFFFFE) (display_modes.len - 1) else if (iModeNum < display_modes.len) iModeNum else return 0;
    const m = display_modes[idx];
    const sz = std.mem.readInt(u16, raw[68..70], .little);
    const clear_len: usize = @max(@as(usize, 220), @min(@as(usize, 320), sz));
    @memset(raw[0..clear_len], 0);
    const dname = "DISPLAY1";
    for (dname, 0..) |c, i| std.mem.writeInt(u16, raw[i * 2 ..][0..2], c, .little);
    std.mem.writeInt(u16, raw[64..66], 0x0401, .little);
    std.mem.writeInt(u16, raw[68..70], 220, .little);
    std.mem.writeInt(u32, raw[72..76], 0x005C0000, .little);
    std.mem.writeInt(u32, raw[168..172], 32, .little);
    std.mem.writeInt(u32, raw[172..176], m.w, .little);
    std.mem.writeInt(u32, raw[176..180], m.h, .little);
    std.mem.writeInt(u32, raw[184..188], m.hz, .little);
    return 1;
}

fn ChangeDisplaySettingsW(lpDevMode: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpDevMode; _ = dwFlags;
    return 0;
}

const MonitorRect = extern struct { left: i32, top: i32, right: i32, bottom: i32 };
const MonitorEnumProc = *const fn (usize, usize, *const MonitorRect, usize) callconv(W) i32;

fn EnumDisplayMonitors(hdc: usize, lprcClip: ?*const anyopaque, lpfnEnum: ?*anyopaque, dwData: usize) callconv(W) i32 {
    _ = lprcClip;
    if (lpfnEnum) |f| {
        const cb: MonitorEnumProc = @ptrCast(@alignCast(f));
        const rc: MonitorRect = .{ .left = 0, .top = 0, .right = 1920, .bottom = 1080 };
        _ = cb(0x10001, hdc, &rc, dwData);
    }
    return 1;
}

fn EnumDisplayDevicesA(lpDevice: ?[*:0]const u8, iDevNum: u32, lpDisplayDevice: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpDevice; _ = dwFlags;
    if (iDevNum != 0) return 0;
    const raw: [*]u8 = @ptrCast(lpDisplayDevice orelse return 0);
    @memset(raw[4..424], 0);
    @memcpy(raw[4..16], "\\\\.\\DISPLAY1");
    @memcpy(raw[36..56], "WINS Primary Display");
    std.mem.writeInt(u32, raw[164..168], 5, .little);
    return 1;
}

fn EnumDisplayDevicesW(lpDevice: ?[*:0]const u16, iDevNum: u32, lpDisplayDevice: ?*anyopaque, dwFlags: u32) callconv(W) i32 {
    _ = lpDevice; _ = dwFlags;
    if (iDevNum != 0) return 0;
    const raw: [*]u8 = @ptrCast(lpDisplayDevice orelse return 0);
    @memset(raw[4..840], 0);
    const dn = "\\\\.\\DISPLAY1";
    for (dn, 0..) |c, i| std.mem.writeInt(u16, raw[4 + i * 2 ..][0..2], c, .little);
    const ds = "WINS Primary Display";
    for (ds, 0..) |c, i| std.mem.writeInt(u16, raw[68 + i * 2 ..][0..2], c, .little);
    std.mem.writeInt(u32, raw[324..328], 5, .little);
    return 1;
}

fn GetCaretBlinkTime() callconv(W) u32 {
    return 530;
}

fn IsClipboardFormatAvailable(format: u32) callconv(W) i32 {
    return if (clipboard.available(connection, format)) 1 else 0;
}

fn LoadCursorA(hInstance: usize, lpCursorName: ?*const anyopaque) callconv(W) usize {
    _ = hInstance; _ = lpCursorName;
    return 0x30001;
}

fn LoadIconA(hInstance: usize, lpIconName: ?*const anyopaque) callconv(W) usize {
    _ = hInstance; _ = lpIconName;
    return 0x30002;
}

fn CreateIconIndirect(piconinfo: ?*anyopaque) callconv(W) usize {
    _ = piconinfo;
    return 0x30003;
}

fn GetThreadDesktop(dwThreadId: u32) callconv(W) usize {
    _ = dwThreadId;
    return 0x40001;
}

fn GetUserObjectInformationA(hObj: usize, nIndex: i32, pvInfo: ?*anyopaque, nLength: u32, lpnLengthNeeded: ?*u32) callconv(W) i32 {
    _ = hObj; _ = nIndex; _ = pvInfo; _ = nLength;
    if (lpnLengthNeeded) |p| p.* = 0;
    return 1;
}

fn GetUserObjectInformationW(hObj: usize, nIndex: i32, pvInfo: ?*anyopaque, nLength: u32, lpnLengthNeeded: ?*u32) callconv(W) i32 {
    _ = hObj; _ = nIndex; _ = pvInfo; _ = nLength;
    if (lpnLengthNeeded) |p| p.* = 0;
    return 1;
}

fn GetProcessWindowStation() callconv(W) usize {
    return 0x40002;
}

fn RegisterWindowMessageA(lpString: ?[*:0]const u8) callconv(W) u32 {
    _ = lpString;
    return 0xC001;
}

fn SendMessageA(hwnd: usize, msg: u32, wparam: usize, lparam: isize) callconv(W) isize {
    return @bitCast(sendMessageW(hwnd, msg, wparam, @bitCast(lparam)));
}

fn SendMessageTimeoutA(hwnd: usize, msg: u32, wparam: usize, lparam: isize, fuFlags: u32, uTimeout: u32, lpdwResult: ?*usize) callconv(W) isize {
    _ = hwnd; _ = msg; _ = wparam; _ = lparam; _ = fuFlags; _ = uTimeout;
    if (lpdwResult) |p| p.* = 0;
    return 1;
}

fn EnumWindows(lpEnumFunc: ?*anyopaque, lParam: isize) callconv(W) i32 {
    _ = lpEnumFunc; _ = lParam;
    return 1;
}

fn CreateDialogParamA(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: isize) callconv(W) usize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 0x50001;
}

fn DialogBoxParamA(hInstance: usize, lpTemplateName: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: isize) callconv(W) isize {
    _ = hInstance; _ = lpTemplateName; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 1;
}

fn AdjustWindowRectEx(lpRect: ?*Rect, dwStyle: u32, bMenu: i32, dwExStyle: u32) callconv(W) i32 {
    _ = lpRect; _ = dwStyle; _ = bMenu; _ = dwExStyle;
    return 1;
}

fn SetDlgItemTextA(hDlg: usize, nIDDlgItem: i32, lpString: ?[*:0]const u8) callconv(W) i32 {
    _ = hDlg; _ = nIDDlgItem; _ = lpString;
    return 1;
}

fn CheckDlgButton(hDlg: usize, nIDButton: i32, uCheck: u32) callconv(W) i32 {
    _ = hDlg; _ = nIDButton; _ = uCheck;
    return 1;
}

fn IsDlgButtonChecked(hDlg: usize, nIDButton: i32) callconv(W) u32 {
    _ = hDlg; _ = nIDButton;
    return 0;
}

fn GetDesktopWindow() callconv(W) usize {
    return 0x10000;
}

fn BeginPaint(hwnd: usize, lpPaint: ?*anyopaque) callconv(W) usize {
    const hdc = allocDC(hwnd, false);
    var w_width: i32 = 1024;
    var w_height: i32 = 720;
    if (findWin(hwnd)) |w| {
        w.needs_paint = false;
        w_width = @max(1, w.width);
        w_height = @max(1, w.height);
    }
    if (lpPaint) |ptr| {
        const ps: *PAINTSTRUCT = @ptrCast(@alignCast(ptr));
        ps.* = .{
            .hdc = if (hdc != 0) hdc else 0xB001,
            .fErase = 1,
            .rcPaint = .{ .left = 0, .top = 0, .right = w_width, .bottom = w_height },
            .fRestore = 0,
            .fIncUpdate = 0,
            .rgbReserved = [_]u8{0} ** 32,
        };
    }
    return if (hdc != 0) hdc else 0xB001;
}

fn EndPaint(hwnd: usize, lpPaint: ?*const anyopaque) callconv(W) i32 {
    if (lpPaint) |ptr| {
        const ps: *const PAINTSTRUCT = @ptrCast(@alignCast(ptr));
        if (dcFromHandle(ps.hdc)) |dc| {
            if (findWin(hwnd)) |w| {
                if (winClassEqAscii(w, "SysTabControl32") or winClassEqAscii(w, "msctls_statusbar32")) {
                    if (dcTarget(dc)) |tgt| {
                        paintCommonControlOverlay(w, tgt);
                    }
                }
            }
            dc.* = .{};
        }
    }
    markFbDirty(hwnd);
    flushDirtyBlits();
    return 1;
}

fn InvalidateRect(hwnd: usize, lpRect: ?*const anyopaque, bErase: i32) callconv(W) i32 {
    _ = lpRect;
    _ = bErase;
    if (hwnd == 0) {
        for (&windows) |*w| {
            if (w.in_use) w.needs_paint = true;
        }
    } else {
        markTreeDirty(hwnd);
    }
    return 1;
}

fn RedrawWindow(hwnd: usize, lprcUpdate: ?*const anyopaque, hrgnUpdate: usize, flags: u32) callconv(W) i32 {
    _ = lprcUpdate;
    _ = hrgnUpdate;
    _ = flags;
    if (hwnd != 0) markTreeDirty(hwnd);
    return 1;
}

fn FillRect(hdc: usize, lprc: ?*const anyopaque, hbr: usize) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const r = readRectPtr(lprc) orelse return 1;
    const b = brushFromHandle(hbr) orelse GdiBrush{ .in_use = true, .xrgb = 0x00F0F0F0 };
    if (!b.is_null) {
        gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + r.left, tgt.oy + r.top, tgt.ox + r.right, tgt.oy + r.bottom, b.xrgb);
        if (!dc.is_mem) markFbDirty(dc.hwnd);
    }
    return 1;
}

fn FrameRect(hdc: usize, lprc: ?*const anyopaque, hbr: usize) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const r = readRectPtr(lprc) orelse return 1;
    const b = brushFromHandle(hbr) orelse GdiBrush{ .in_use = true, .xrgb = 0x00808080 };
    if (!b.is_null) {
        gdi.frameRect(tgt.surface, tgt.clip, tgt.ox + r.left, tgt.oy + r.top, tgt.ox + r.right, tgt.oy + r.bottom, b.xrgb);
        if (!dc.is_mem) markFbDirty(dc.hwnd);
    }
    return 1;
}

fn DrawEdge(hdc: usize, qrc: ?*anyopaque, edge: u32, grfFlags: u32) callconv(W) i32 {
    _ = edge;
    _ = grfFlags;
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const r = readRectPtr(qrc) orelse return 1;
    gdi.frameRect(tgt.surface, tgt.clip, tgt.ox + r.left, tgt.oy + r.top, tgt.ox + r.right, tgt.oy + r.bottom, 0x00A0A0A0);
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn DrawFrameControl(hdc: usize, lprc: ?*anyopaque, uType: u32, uState: u32) callconv(W) i32 {
    _ = uType;
    _ = uState;
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const r = readRectPtr(lprc) orelse return 1;
    gdi.fillRect(tgt.surface, tgt.clip, tgt.ox + r.left, tgt.oy + r.top, tgt.ox + r.right, tgt.oy + r.bottom, 0x00E1E1E1);
    gdi.frameRect(tgt.surface, tgt.clip, tgt.ox + r.left, tgt.oy + r.top, tgt.ox + r.right, tgt.oy + r.bottom, 0x00A0A0A0);
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn DrawFocusRect(hdc: usize, lprc: ?*const anyopaque) callconv(W) i32 {
    const dc = dcFromHandle(hdc) orelse return 1;
    const tgt = dcTarget(dc) orelse return 1;
    const r = readRectPtr(lprc) orelse return 1;
    gdi.frameRect(tgt.surface, tgt.clip, tgt.ox + r.left, tgt.oy + r.top, tgt.ox + r.right, tgt.oy + r.bottom, 0x00606060);
    if (!dc.is_mem) markFbDirty(dc.hwnd);
    return 1;
}

fn DrawIconEx(hdc: usize, xLeft: i32, yTop: i32, hIcon: usize, cxWidth: i32, cyWidth: i32, istepIfAniCur: u32, hbrFlickerFreeDraw: usize, diFlags: u32) callconv(W) i32 {
    _ = hdc; _ = xLeft; _ = yTop; _ = hIcon; _ = cxWidth; _ = cyWidth; _ = istepIfAniCur; _ = hbrFlickerFreeDraw; _ = diFlags;
    return 1;
}

fn DrawTextW(hdc: usize, lpchText: ?[*:0]const u16, cchText: i32, lprc: ?*anyopaque, format: u32) callconv(W) i32 {
    const str = lpchText orelse return 0;
    var len: usize = 0;
    if (cchText < 0) {
        while (len < 1024 and str[len] != 0) : (len += 1) {}
    } else {
        len = @intCast(@min(cchText, 1024));
    }
    const rc_ptr: *Rect = if (lprc) |p| @ptrCast(@alignCast(p)) else return 16;
    const tw = textWidth(len);
    if ((format & 0x00000400) != 0) { // DT_CALCRECT
        rc_ptr.right = rc_ptr.left + tw;
        rc_ptr.bottom = rc_ptr.top + 16;
        return 16;
    }
    if (dcFromHandle(hdc)) |dc| {
        if (dcTarget(dc)) |tgt| {
            var x = rc_ptr.left;
            var y = rc_ptr.top;
            if ((format & 0x00000001) != 0) { // DT_CENTER
                x = rc_ptr.left + @divTrunc((rc_ptr.right - rc_ptr.left) - tw, 2);
            } else if ((format & 0x00000002) != 0) { // DT_RIGHT
                x = rc_ptr.right - tw;
            }
            if ((format & 0x00000004) != 0) { // DT_VCENTER
                y = rc_ptr.top + @divTrunc((rc_ptr.bottom - rc_ptr.top) - 16, 2);
            }
            const bg: ?u32 = if (dc.bk_mode == 2) dc.bk_xrgb else null;
            gdi.drawTextU16(tgt.surface, tgt.clip, tgt.ox + x, tgt.oy + y, str[0..len], dc.text_xrgb, bg);
            if (!dc.is_mem) markFbDirty(dc.hwnd);
        }
    }
    return 16;
}

fn DrawTextExW(hdc: usize, lpchText: ?[*:0]const u16, cchText: i32, lprc: ?*anyopaque, format: u32, lpdtp: ?*anyopaque) callconv(W) i32 {
    _ = lpdtp;
    return DrawTextW(hdc, lpchText, cchText, lprc, format);
}

fn CreateMenu() callconv(W) usize {
    return 0x90001;
}

fn CreatePopupMenu() callconv(W) usize {
    return 0x90002;
}

fn DestroyMenu(hMenu: usize) callconv(W) i32 {
    _ = hMenu;
    return 1;
}

fn GetMenu(hWnd: usize) callconv(W) usize {
    _ = hWnd;
    return 0x90001;
}

fn SetMenu(hWnd: usize, hMenu: usize) callconv(W) i32 {
    _ = hWnd; _ = hMenu;
    return 1;
}

fn DrawMenuBar(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn GetSubMenu(hMenu: usize, nPos: i32) callconv(W) usize {
    _ = hMenu; _ = nPos;
    return 0x90002;
}

fn GetMenuItemCount(hMenu: usize) callconv(W) i32 {
    _ = hMenu;
    return 1;
}

fn GetMenuItemID(hMenu: usize, nPos: i32) callconv(W) u32 {
    _ = hMenu;
    return @intCast(nPos);
}

fn GetMenuItemInfoW(hmenu: usize, item: u32, fByPosition: i32, lpmii: ?*anyopaque) callconv(W) i32 {
    _ = hmenu; _ = item; _ = fByPosition; _ = lpmii;
    return 1;
}

fn SetMenuItemInfoW(hmenu: usize, item: u32, fByPosition: i32, lpmii: ?*const anyopaque) callconv(W) i32 {
    _ = hmenu; _ = item; _ = fByPosition; _ = lpmii;
    return 1;
}

fn GetMenuStringW(hMenu: usize, uIDItem: u32, lpString: ?[*:0]u16, cchMax: i32, flags: u32) callconv(W) i32 {
    _ = hMenu; _ = uIDItem; _ = flags;
    if (lpString) |s| {
        if (cchMax > 0) s[0] = 0;
    }
    return 0;
}

fn GetMenuState(hMenu: usize, uId: u32, uFlags: u32) callconv(W) u32 {
    _ = hMenu; _ = uId; _ = uFlags;
    return 0;
}

fn InsertMenuW(hMenu: usize, uPosition: u32, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn InsertMenuItemW(hmenu: usize, item: u32, fByPosition: i32, lpmi: ?*const anyopaque) callconv(W) i32 {
    _ = hmenu; _ = item; _ = fByPosition; _ = lpmi;
    return 1;
}

fn AppendMenuW(hMenu: usize, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn AppendMenuA(hMenu: usize, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn ModifyMenuW(hMnu: usize, uPosition: u32, uFlags: u32, uIDNewItem: usize, lpNewItem: ?*const anyopaque) callconv(W) i32 {
    _ = hMnu; _ = uPosition; _ = uFlags; _ = uIDNewItem; _ = lpNewItem;
    return 1;
}

fn DeleteMenu(hMenu: usize, uPosition: u32, uFlags: u32) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags;
    return 1;
}

fn RemoveMenu(hMenu: usize, uPosition: u32, uFlags: u32) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags;
    return 1;
}

fn EnableMenuItem(hMenu: usize, uIDEnableItem: u32, uEnable: u32) callconv(W) i32 {
    _ = hMenu; _ = uIDEnableItem; _ = uEnable;
    return 0;
}

fn CheckMenuItem(hMenu: usize, uIDCheckItem: u32, uCheck: u32) callconv(W) i32 {
    _ = hMenu; _ = uIDCheckItem; _ = uCheck;
    return 0;
}

fn CheckMenuRadioItem(hmenu: usize, first: u32, last: u32, check: u32, flags: u32) callconv(W) i32 {
    _ = hmenu; _ = first; _ = last; _ = check; _ = flags;
    return 1;
}

fn SetMenuItemBitmaps(hMenu: usize, uPosition: u32, uFlags: u32, hBitmapUnchecked: usize, hBitmapChecked: usize) callconv(W) i32 {
    _ = hMenu; _ = uPosition; _ = uFlags; _ = hBitmapUnchecked; _ = hBitmapChecked;
    return 1;
}

fn TrackPopupMenu(hMenu: usize, uFlags: u32, x: i32, y: i32, nReserved: i32, hWnd: usize, prcRect: ?*const anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = x; _ = y; _ = nReserved; _ = hWnd; _ = prcRect;
    return 1;
}

fn TrackPopupMenuEx(hMenu: usize, uFlags: u32, x: i32, y: i32, hwnd: usize, lptpm: ?*anyopaque) callconv(W) i32 {
    _ = hMenu; _ = uFlags; _ = x; _ = y; _ = hwnd; _ = lptpm;
    return 1;
}

fn GetMenuBarInfo(hwnd: usize, idObject: i32, idItem: i32, pmbi: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = idObject; _ = idItem; _ = pmbi;
    return 1;
}

fn CreateCaret(hWnd: usize, hBitmap: usize, nWidth: i32, nHeight: i32) callconv(W) i32 {
    _ = hWnd; _ = hBitmap; _ = nWidth; _ = nHeight;
    return 1;
}

fn DestroyCaret() callconv(W) i32 {
    return 1;
}

fn ShowCaret(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn HideCaret(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn SetCaretPos(X: i32, Y: i32) callconv(W) i32 {
    _ = X; _ = Y;
    return 1;
}

fn GetWindowTextW(hWnd: usize, lpString: ?[*:0]u16, nMaxCount: i32) callconv(W) i32 {
    const dst = lpString orelse return 0;
    if (nMaxCount <= 0) return 0;
    const w = findWin(hWnd) orelse {
        dst[0] = 0;
        return 0;
    };
    const cap: usize = @intCast(nMaxCount);
    const n = @min(w.title_len, cap - 1);
    @memcpy(dst[0..n], w.title[0..n]);
    dst[n] = 0;
    return @intCast(n);
}

fn GetWindowTextA(hWnd: usize, lpString: ?[*:0]u8, nMaxCount: i32) callconv(W) i32 {
    const dst = lpString orelse return 0;
    if (nMaxCount <= 0) return 0;
    const w = findWin(hWnd) orelse {
        dst[0] = 0;
        return 0;
    };
    const cap: usize = @intCast(nMaxCount);
    const n = encodeTitleUtf8(w.title[0..w.title_len], dst[0..cap]);
    return @intCast(n);
}

fn GetWindowTextLengthW(hWnd: usize) callconv(W) i32 {
    const w = findWin(hWnd) orelse return 0;
    return @intCast(w.title_len);
}

fn IsWindow(hWnd: usize) callconv(W) i32 {
    return if (findWin(hWnd) != null) 1 else 0;
}

fn IsWindowEnabled(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn IsWindowVisible(hWnd: usize) callconv(W) i32 {
    if (findWin(hWnd)) |w| return if (isWindowVisibleTree(w)) 1 else 0;
    return 0;
}

fn IsIconic(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 0;
}

fn IsZoomed(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 0;
}

fn IsChild(hWndParent: usize, hWnd: usize) callconv(W) i32 {
    var cur = findWin(hWnd) orelse return 0;
    var hops: usize = 0;
    while (hops < 16 and cur.parent != 0) : (hops += 1) {
        if (cur.parent == hWndParent) return 1;
        cur = findWin(cur.parent) orelse return 0;
    }
    return 0;
}

fn SetParent(hWndChild: usize, hWndNewParent: usize) callconv(W) usize {
    if (findWin(hWndChild)) |w| {
        const old = w.parent;
        w.parent = hWndNewParent;
        return old;
    }
    return hWndNewParent;
}

fn MoveWindow(hWnd: usize, X: i32, Y: i32, nWidth: i32, nHeight: i32, bRepaint: i32) callconv(W) i32 {
    const res = SetWindowPos(hWnd, 0, X, Y, nWidth, nHeight, 0x0004 | 0x0010);
    if (res != 0 and bRepaint != 0) {
        _ = InvalidateRect(hWnd, null, 1);
    }
    return res;
}

fn BringWindowToTop(hWnd: usize) callconv(W) i32 {
    _ = hWnd;
    return 1;
}

fn GetLastActivePopup(hWnd: usize) callconv(W) usize {
    return hWnd;
}

fn FindWindowW(lpClassName: ?[*:0]const u16, lpWindowName: ?[*:0]const u16) callconv(W) usize {
    _ = lpClassName; _ = lpWindowName;
    return 0;
}

fn GetWindowThreadProcessId(hWnd: usize, lpdwProcessId: ?*u32) callconv(W) u32 {
    _ = hWnd;
    if (lpdwProcessId) |pid| pid.* = 1000;
    return 1001;
}

fn GetClassNameW(hWnd: usize, lpClassName: ?[*:0]u16, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpClassName) |s| {
        if (nMaxCount > 0) s[0] = 0;
    }
    return 0;
}

fn GetClassNameA(hWnd: usize, lpClassName: ?[*:0]u8, nMaxCount: i32) callconv(W) i32 {
    _ = hWnd;
    if (lpClassName) |s| {
        if (nMaxCount > 0) s[0] = 0;
    }
    return 0;
}

fn GetDlgCtrlID(hWnd: usize) callconv(W) i32 {
    if (findWin(hWnd)) |w| return @truncate(w.id);
    return 1;
}

fn GetSysColor(nIndex: i32) callconv(W) u32 {
    return switch (nIndex) {
        0 => 0xC8C8C8, // COLOR_SCROLLBAR
        1 => 0x000000, // COLOR_BACKGROUND
        2 => 0xD1B499, // COLOR_ACTIVECAPTION
        3 => 0xDBCDBF, // COLOR_INACTIVECAPTION
        4 => 0xF0F0F0, // COLOR_MENU
        5 => 0xFFFFFF, // COLOR_WINDOW
        6 => 0x646464, // COLOR_WINDOWFRAME
        7 => 0x000000, // COLOR_MENUTEXT
        8 => 0x000000, // COLOR_WINDOWTEXT
        9 => 0x000000, // COLOR_CAPTIONTEXT
        12 => 0xABABAB, // COLOR_APPWORKSPACE
        13 => 0xD77800, // COLOR_HIGHLIGHT
        14 => 0xFFFFFF, // COLOR_HIGHLIGHTTEXT
        15 => 0xF0F0F0, // COLOR_BTNFACE
        16 => 0xA0A0A0, // COLOR_BTNSHADOW
        17 => 0x6D6D6D, // COLOR_GRAYTEXT
        18 => 0x000000, // COLOR_BTNTEXT
        20 => 0xFFFFFF, // COLOR_BTNHIGHLIGHT
        21 => 0x696969, // COLOR_3DDKSHADOW
        22 => 0xE3E3E3, // COLOR_3DLIGHT
        23 => 0x000000, // COLOR_INFOTEXT
        24 => 0xE1FFFF, // COLOR_INFOBK
        else => 0xF0F0F0,
    };
}

fn GetSysColorBrush(nIndex: i32) callconv(W) usize {
    if (nIndex >= 0 and nIndex <= 30) {
        return @intCast(nIndex + 1);
    }
    return GetStockObject(0);
}

fn propKeyHash(lpString: ?[*:0]const u16) u64 {
    const p = lpString orelse return 0;
    const addr = @intFromPtr(p);
    if (addr < 0x10000) return addr;
    var h: u64 = 0xcbf29ce484222325;
    var i: usize = 0;
    while (i < 128 and p[i] != 0) : (i += 1) {
        h = (h ^ p[i]) *% 0x100000001b3;
    }
    return h;
}

fn SetPropW(hWnd: usize, lpString: ?[*:0]const u16, hData: usize) callconv(W) i32 {
    const kh = propKeyHash(lpString);
    if (kh == 0) return 0;
    for (&win_props) |*wp| {
        if (wp.in_use and wp.hwnd == hWnd and wp.key_hash == kh) {
            wp.val = hData;
            return 1;
        }
    }
    for (&win_props) |*wp| {
        if (!wp.in_use) {
            wp.* = .{ .in_use = true, .hwnd = hWnd, .key_hash = kh, .val = hData };
            return 1;
        }
    }
    return 1;
}

fn GetPropW(hWnd: usize, lpString: ?[*:0]const u16) callconv(W) usize {
    const kh = propKeyHash(lpString);
    if (kh == 0) return 0;
    for (win_props) |wp| {
        if (wp.in_use and wp.hwnd == hWnd and wp.key_hash == kh) return wp.val;
    }
    return 0;
}

fn RemovePropW(hWnd: usize, lpString: ?[*:0]const u16) callconv(W) usize {
    const kh = propKeyHash(lpString);
    if (kh == 0) return 0;
    for (&win_props) |*wp| {
        if (wp.in_use and wp.hwnd == hWnd and wp.key_hash == kh) {
            const v = wp.val;
            wp.* = .{};
            return v;
        }
    }
    return 0;
}

fn SetLayeredWindowAttributes(hwnd: usize, crKey: u32, bAlpha: u8, dwFlags: u32) callconv(W) i32 {
    _ = hwnd; _ = crKey; _ = bAlpha; _ = dwFlags;
    return 1;
}

fn GetWindowDC(hWnd: usize) callconv(W) usize {
    return GetDC(hWnd);
}

fn GetDCEx(hWnd: usize, hrgnClip: usize, flags: u32) callconv(W) usize {
    _ = hrgnClip; _ = flags;
    return GetDC(hWnd);
}

fn MapWindowPoints(hWndFrom: usize, hWndTo: usize, lpPoints: ?*anyopaque, cPoints: u32) callconv(W) i32 {
    const p = lpPoints orelse return 0;
    const pts: [*]Point = @ptrCast(@alignCast(p));
    const from_sp = if (hWndFrom != 0) winScreenPos(hWndFrom) else Point{ .x = 0, .y = 0 };
    const to_sp = if (hWndTo != 0) winScreenPos(hWndTo) else Point{ .x = 0, .y = 0 };
    const dx = from_sp.x - to_sp.x;
    const dy = from_sp.y - to_sp.y;
    for (0..cPoints) |i| {
        pts[i].x += dx;
        pts[i].y += dy;
    }
    return (@as(i32, dy & 0xffff) << 16) | (dx & 0xffff);
}

fn InflateRect(lprc: ?*anyopaque, dx: i32, dy: i32) callconv(W) i32 {
    const ptr = lprc orelse return 0;
    const r: *Rect = @ptrCast(@alignCast(ptr));
    r.left -= dx;
    r.top -= dy;
    r.right += dx;
    r.bottom += dy;
    return 1;
}

fn EqualRect(lprc1: ?*const anyopaque, lprc2: ?*const anyopaque) callconv(W) i32 {
    const r1 = readRectPtr(lprc1) orelse return 0;
    const r2 = readRectPtr(lprc2) orelse return 0;
    return if (r1.left == r2.left and r1.top == r2.top and r1.right == r2.right and r1.bottom == r2.bottom) 1 else 0;
}

fn IntersectRect(lprcDst: ?*anyopaque, lprcSrc1: ?*const anyopaque, lprcSrc2: ?*const anyopaque) callconv(W) i32 {
    const dst_ptr = lprcDst orelse return 0;
    const dst: *Rect = @ptrCast(@alignCast(dst_ptr));
    const r1 = readRectPtr(lprcSrc1) orelse {
        dst.* = .{ .left = 0, .top = 0, .right = 0, .bottom = 0 };
        return 0;
    };
    const r2 = readRectPtr(lprcSrc2) orelse {
        dst.* = .{ .left = 0, .top = 0, .right = 0, .bottom = 0 };
        return 0;
    };
    const l = @max(r1.left, r2.left);
    const t = @max(r1.top, r2.top);
    const r = @min(r1.right, r2.right);
    const b = @min(r1.bottom, r2.bottom);
    if (l < r and t < b) {
        dst.* = .{ .left = l, .top = t, .right = r, .bottom = b };
        return 1;
    }
    dst.* = .{ .left = 0, .top = 0, .right = 0, .bottom = 0 };
    return 0;
}

fn SetRectEmpty(lprc: ?*anyopaque) callconv(W) i32 {
    if (lprc) |r| {
        const ptr: *[4]i32 = @ptrCast(@alignCast(r));
        ptr.* = .{ 0, 0, 0, 0 };
    }
    return 1;
}

fn EnumChildWindows(hWndParent: usize, lpEnumFunc: ?*anyopaque, lParam: usize) callconv(W) i32 {
    _ = hWndParent; _ = lpEnumFunc; _ = lParam;
    return 1;
}

fn EnumThreadWindows(dwThreadId: u32, lpfn: ?*anyopaque, lParam: usize) callconv(W) i32 {
    _ = dwThreadId; _ = lpfn; _ = lParam;
    return 1;
}

fn GetComboBoxInfo(hwndCombo: usize, pcbi: ?*anyopaque) callconv(W) i32 {
    _ = hwndCombo; _ = pcbi;
    return 1;
}

fn GetIconInfo(hIcon: usize, piconinfo: ?*anyopaque) callconv(W) i32 {
    _ = hIcon; _ = piconinfo;
    return 1;
}

fn wsprintfW(buf: ?[*:0]u16, fmt: ?[*:0]const u16, a1: usize, a2: usize, a3: usize, a4: usize) callconv(W) i32 {
    const dst = buf orelse return 0;
    const f = fmt orelse {
        dst[0] = 0;
        return 0;
    };
    const args = [4]usize{ a1, a2, a3, a4 };
    var ai: usize = 0;
    var fi: usize = 0;
    var di: usize = 0;
    while (f[fi] != 0 and di < 500) {
        if (f[fi] != '%') {
            dst[di] = f[fi];
            di += 1;
            fi += 1;
            continue;
        }
        fi += 1;
        if (f[fi] == '%') {
            dst[di] = '%';
            di += 1;
            fi += 1;
            continue;
        }
        while (f[fi] == '0' or f[fi] == '-' or f[fi] == '+' or f[fi] == ' ' or (f[fi] >= '1' and f[fi] <= '9') or f[fi] == '.' or f[fi] == 'l' or f[fi] == 'h' or f[fi] == 'I') {
            fi += 1;
        }
        const spec = f[fi];
        if (spec == 0) break;
        fi += 1;
        const val: usize = if (ai < args.len) args[ai] else 0;
        ai += 1;
        if (spec == 'd' or spec == 'i') {
            var tmp: [32]u8 = undefined;
            const sval: i32 = @bitCast(@as(u32, @truncate(val)));
            const s = std.fmt.bufPrint(&tmp, "{d}", .{sval}) catch "";
            for (s) |ch| {
                if (di < 500) {
                    dst[di] = ch;
                    di += 1;
                }
            }
        } else if (spec == 'u') {
            var tmp: [32]u8 = undefined;
            const uval: u32 = @truncate(val);
            const s = std.fmt.bufPrint(&tmp, "{d}", .{uval}) catch "";
            for (s) |ch| {
                if (di < 500) {
                    dst[di] = ch;
                    di += 1;
                }
            }
        } else if (spec == 'x' or spec == 'X') {
            var tmp: [32]u8 = undefined;
            const uval: u32 = @truncate(val);
            const s = std.fmt.bufPrint(&tmp, "{x}", .{uval}) catch "";
            for (s) |ch| {
                if (di < 500) {
                    dst[di] = if (spec == 'X' and ch >= 'a' and ch <= 'f') ch - 32 else ch;
                    di += 1;
                }
            }
        } else if (spec == 's' or spec == 'S') {
            if (val >= 0x10000) {
                const wstr: [*:0]const u16 = @ptrFromInt(val);
                var si: usize = 0;
                while (wstr[si] != 0 and di < 500) : (si += 1) {
                    dst[di] = wstr[si];
                    di += 1;
                }
            }
        } else if (spec == 'c') {
            dst[di] = @truncate(val);
            di += 1;
        }
    }
    dst[di] = 0;
    return @intCast(di);
}

fn GetScrollPos(hWnd: usize, nBar: i32) callconv(W) i32 {
    _ = hWnd; _ = nBar;
    return 0;
}

fn SetScrollPos(hWnd: usize, nBar: i32, nPos: i32, bRedraw: i32) callconv(W) i32 {
    _ = hWnd; _ = nBar; _ = bRedraw;
    return nPos;
}

fn GetScrollRange(hWnd: usize, nBar: i32, lpMinPos: ?*i32, lpMaxPos: ?*i32) callconv(W) i32 {
    _ = hWnd; _ = nBar;
    if (lpMinPos) |min| min.* = 0;
    if (lpMaxPos) |max| max.* = 100;
    return 1;
}

fn SetScrollRange(hWnd: usize, nBar: i32, nMinPos: i32, nMaxPos: i32, bRedraw: i32) callconv(W) i32 {
    _ = hWnd; _ = nBar; _ = nMinPos; _ = nMaxPos; _ = bRedraw;
    return 1;
}

fn GetScrollInfo(hwnd: usize, nBar: i32, lpsi: ?*anyopaque) callconv(W) i32 {
    _ = hwnd; _ = nBar; _ = lpsi;
    return 1;
}

fn SetScrollInfo(hwnd: usize, nBar: i32, lpsi: ?*const anyopaque, redraw: i32) callconv(W) i32 {
    _ = hwnd; _ = nBar; _ = lpsi; _ = redraw;
    return 0;
}

fn ScrollWindow(hWnd: usize, XAmount: i32, YAmount: i32, lpRect: ?*const anyopaque, lpClipRect: ?*const anyopaque) callconv(W) i32 {
    _ = hWnd; _ = XAmount; _ = YAmount; _ = lpRect; _ = lpClipRect;
    return 1;
}

fn ShowScrollBar(hWnd: usize, wBar: i32, bShow: i32) callconv(W) i32 {
    _ = hWnd; _ = wBar; _ = bShow;
    return 1;
}

fn RegisterClipboardFormatW(lpszFormat: ?[*:0]const u16) callconv(W) u32 {
    return clipboard.registerFormat(lpszFormat);
}

fn AddClipboardFormatListener(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn RemoveClipboardFormatListener(hwnd: usize) callconv(W) i32 {
    _ = hwnd;
    return 1;
}

fn SetClipboardViewer(hWndNewViewer: usize) callconv(W) usize {
    _ = hWndNewViewer;
    return 0;
}

fn ChangeClipboardChain(hWndRemove: usize, hWndNewNext: usize) callconv(W) i32 {
    _ = hWndRemove; _ = hWndNewNext;
    return 1;
}

/// ACCEL as laid out by Windows (6 bytes: fVirt, pad, key, cmd).
const Accel = extern struct { fVirt: u8, pad: u8, key: u16, cmd: u16 };
const ACCEL_TABLE_MAX = 1024;
const AccelTable = struct { used: bool = false, n: usize = 0, items: [ACCEL_TABLE_MAX]Accel = undefined };
var accel_tables: [8]AccelTable = [_]AccelTable{.{}} ** 8;
const HACCEL_BASE: usize = 0xA000;

fn accelTable(h: usize) ?*AccelTable {
    if (h <= HACCEL_BASE or h > HACCEL_BASE + accel_tables.len) return null;
    const t = &accel_tables[h - HACCEL_BASE - 1];
    return if (t.used) t else null;
}

fn CreateAcceleratorTableW(paccel: ?*anyopaque, cAccel: i32) callconv(W) usize {
    const p = paccel orelse return 0;
    if (cAccel <= 0) return 0;
    const src: [*]const Accel = @ptrCast(@alignCast(p));
    for (&accel_tables, 0..) |*t, i| {
        if (t.used) continue;
        t.used = true;
        t.n = @min(@as(usize, @intCast(cAccel)), ACCEL_TABLE_MAX);
        @memcpy(t.items[0..t.n], src[0..t.n]);
        return HACCEL_BASE + i + 1;
    }
    return 0;
}

fn DestroyAcceleratorTable(hAccel: usize) callconv(W) i32 {
    const t = accelTable(hAccel) orelse return 0;
    t.used = false;
    return 1;
}

/// WM_KEYDOWN/WM_SYSKEYDOWN (FVIRTKEY entries, modifiers must match exactly) or
/// WM_CHAR/WM_SYSCHAR (character entries) -> WM_COMMAND(1, cmd) to hWnd, and the
/// key message is consumed so TranslateMessage never turns Ctrl+S into a ^S char.
fn TranslateAcceleratorW(hWnd: usize, hAccTable: usize, lpMsg: ?*anyopaque) callconv(W) i32 {
    const t = accelTable(hAccTable) orelse return 0;
    const m: *const MSG = @ptrCast(@alignCast(lpMsg orelse return 0));
    if (hWnd == 0) return 0;
    const is_key = m.message == WM_KEYDOWN or m.message == WM_SYSKEYDOWN;
    const is_char = m.message == WM_CHAR or m.message == WM_SYSCHAR;
    if (!is_key and !is_char) return 0;
    var mods: u8 = 0;
    if (kbd.getKeyState(kbd.VK_SHIFT) < 0) mods |= 0x04; // FSHIFT
    if (kbd.getKeyState(kbd.VK_CONTROL) < 0) mods |= 0x08; // FCONTROL
    if (kbd.getKeyState(kbd.VK_MENU) < 0) mods |= 0x10; // FALT
    const key: u16 = @truncate(m.wParam);
    for (t.items[0..t.n]) |a| {
        const virt = (a.fVirt & 0x01) != 0; // FVIRTKEY
        const hit = if (virt)
            is_key and a.key == key and (a.fVirt & 0x1c) == mods
        else
            is_char and a.key == key and (((a.fVirt & 0x10) != 0) == (m.message == WM_SYSCHAR));
        if (!hit) continue;
        if (std.c.getenv("WINS_TRACE") != null) std.debug.print("[WINS:ACCEL] key=0x{x} mods=0x{x} -> WM_COMMAND id={d} to 0x{x}\n", .{ key, mods, a.cmd, hWnd });
        _ = sendMessageW(hWnd, 0x0111, (@as(usize, 1) << 16) | a.cmd, 0); // WM_COMMAND, from accelerator
        return 1;
    }
    return 0;
}

fn RegisterWindowMessageW(lpString: ?[*:0]const u16) callconv(W) u32 {
    _ = lpString;
    return 0xC002;
}

fn FlashWindowEx(pfwi: ?*anyopaque) callconv(W) i32 {
    _ = pfwi;
    return 1;
}

fn LockWindowUpdate(hWndLock: usize) callconv(W) i32 {
    _ = hWndLock;
    return 1;
}

fn BeginDeferWindowPos(nNumWindows: i32) callconv(W) usize {
    _ = nNumWindows;
    return 0xD001;
}

fn DeferWindowPos(hWinPosInfo: usize, hWnd: usize, hWndInsertAfter: usize, x: i32, y: i32, cx: i32, cy: i32, uFlags: u32) callconv(W) usize {
    _ = SetWindowPos(hWnd, hWndInsertAfter, x, y, cx, cy, uFlags);
    return hWinPosInfo;
}

fn EndDeferWindowPos(hWinPosInfo: usize) callconv(W) i32 {
    _ = hWinPosInfo;
    return 1;
}

fn unpackPoint(pt: usize) Point {
    return .{ .x = @bitCast(@as(u32, @truncate(pt))), .y = @bitCast(@as(u32, @truncate(pt >> 32))) };
}

/// POINT by value (x low 32 bits, y high 32), WINS screen coordinates.
fn WindowFromPoint(point: usize) callconv(W) usize {
    const p = unpackPoint(point);
    var hit: usize = 0;
    for (&windows) |*w| {
        if (!w.in_use or w.x11_win == 0 or !w.visible) continue;
        const o = winScreenPos(w.hwnd);
        if (p.x >= o.x and p.x < o.x + w.width and p.y >= o.y and p.y < o.y + w.height)
            hit = hitTestChild(w.hwnd, p.x - o.x, p.y - o.y);
    }
    return hit;
}

/// Direct child of `hwnd` containing `pt` (hwnd's client coordinates); `hwnd`
/// itself when no child does; 0 outside hwnd. CWP_SKIPINVISIBLE = 1.
fn ChildWindowFromPointEx(hwnd: usize, pt: usize, flags: u32) callconv(W) usize {
    const self = findWin(hwnd) orelse return 0;
    const p = unpackPoint(pt);
    if (p.x < 0 or p.y < 0 or p.x >= self.width or p.y >= self.height) return 0;
    var best: usize = hwnd;
    for (&windows) |*c| {
        if (!c.in_use or c.parent != hwnd or (c.style & WS_CHILD) == 0) continue;
        if (flags & 1 != 0 and !c.visible) continue;
        if (p.x >= c.x and p.x < c.x + c.width and p.y >= c.y and p.y < c.y + c.height) {
            if (best == hwnd or c.hwnd < best) best = c.hwnd; // first-created sibling is on top
        }
    }
    return best;
}

fn CreateDialogIndirectParamW(hInstance: usize, lpTemplate: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: usize) callconv(W) usize {
    _ = hInstance; _ = lpTemplate; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 0x10001;
}

fn DialogBoxIndirectParamW(hInstance: usize, hDialogTemplate: ?*const anyopaque, hWndParent: usize, lpDialogFunc: ?*anyopaque, dwInitParam: usize) callconv(W) isize {
    _ = hInstance; _ = hDialogTemplate; _ = hWndParent; _ = lpDialogFunc; _ = dwInitParam;
    return 1;
}

fn mouse_event(dwFlags: u32, dx: u32, dy: u32, dwData: u32, dwExtraInfo: usize) callconv(W) void {
    _ = dwFlags; _ = dx; _ = dy; _ = dwData; _ = dwExtraInfo;
}

fn GetKeyboardState(lpKeyState: ?[*]u8) callconv(W) i32 {
    const out = lpKeyState orelse return 0;
    // Per VK: 0x80 = down, 0x01 = toggled, the same table GetKeyState reads.
    for (0..256) |vk| {
        const st: u16 = @bitCast(kbd.getKeyState(@intCast(vk)));
        out[vk] = (if ((st & 0x8000) != 0) @as(u8, 0x80) else 0) | @as(u8, @intCast(st & 1));
    }
    return 1;
}

fn MapVirtualKeyW(uCode: u32, uMapType: u32) callconv(W) u32 {
    _ = uMapType;
    return uCode;
}

fn GetKeyboardLayout(idThread: u32) callconv(W) usize {
    _ = idThread;
    return 0x04090409;
}

fn ToAscii(uVirtKey: u32, uScanCode: u32, lpKeyState: ?*const u8, lpChar: ?*u16, uFlags: u32) callconv(W) i32 {
    _ = uScanCode; _ = lpKeyState; _ = uFlags;
    if (lpChar) |c| c.* = @intCast(uVirtKey & 0xFF);
    return 1;
}

fn IsCharLowerW(ch: u16) callconv(W) i32 {
    return if (ch >= 'a' and ch <= 'z') 1 else 0;
}

fn CharUpperW(lpsz: ?[*:0]u16) callconv(W) ?[*:0]u16 {
    if (lpsz) |s| {
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            if (s[i] >= 'a' and s[i] <= 'z') s[i] -= 32;
        }
    }
    return lpsz;
}

fn CharLowerW(lpsz: ?[*:0]u16) callconv(W) ?[*:0]u16 {
    if (lpsz) |s| {
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            if (s[i] >= 'A' and s[i] <= 'Z') s[i] += 32;
        }
    }
    return lpsz;
}

fn IsCharAlphaNumericW(ch: u16) callconv(W) i32 {
    return if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9')) 1 else 0;
}

fn IsCharAlphaW(ch: u16) callconv(W) i32 {
    return if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z')) 1 else 0;
}

fn LoadCursorW(hInstance: usize, lpCursorName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpCursorName;
    return 0x50001;
}

fn LoadMenuW(hInstance: usize, lpMenuName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpMenuName;
    return 0x90001;
}

fn LoadBitmapW(hInstance: usize, lpBitmapName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpBitmapName;
    return 0xB003;
}

fn LoadIconW(hInstance: usize, lpIconName: ?[*:0]const u16) callconv(W) usize {
    _ = hInstance; _ = lpIconName;
    return 0x40001;
}

fn LoadStringA(hInstance: usize, uID: u32, lpBuffer: ?[*:0]u8, cchBufferMax: i32) callconv(W) i32 {
    _ = hInstance; _ = uID;
    if (lpBuffer) |b| {
        if (cchBufferMax > 0) b[0] = 0;
    }
    return 0;
}

fn LoadStringW(hInstance: usize, uID: u32, lpBuffer: ?[*:0]u16, cchBufferMax: i32) callconv(W) i32 {
    const buf = lpBuffer orelse return 0;
    if (cchBufferMax <= 0) return 0;
    buf[0] = 0;
    const k32 = @import("winrun_kernel32.zig");
    const block_id: usize = (uID >> 4) + 1;
    const raw = k32.findResourceBytes(hInstance, @ptrFromInt(block_id), @ptrFromInt(6)) orelse return 0; // RT_STRING=6
    var off: usize = 0;
    const idx_in_block = uID & 15;
    for (0..16) |i| {
        if (off + 2 > raw.len) return 0;
        const nchars = std.mem.readInt(u16, raw[off..][0..2], .little);
        off += 2;
        if (off + @as(usize, nchars) * 2 > raw.len) return 0;
        if (i == idx_in_block) {
            const copy_n = @min(@as(usize, nchars), @as(usize, @intCast(cchBufferMax)) - 1);
            for (0..copy_n) |j| {
                buf[j] = std.mem.readInt(u16, raw[off + j * 2 ..][0..2], .little);
            }
            buf[copy_n] = 0;
            return @intCast(copy_n);
        }
        off += @as(usize, nchars) * 2;
    }
    return 0;
}

fn MessageBeep(uType: u32) callconv(W) i32 {
    _ = uType;
    return 1;
}

fn GetUpdateRgn(hWnd: usize, hRgn: usize, bErase: i32) callconv(W) i32 {
    _ = bErase;
    if (regionFromHandle(hRgn)) |r| {
        if (findWin(hWnd)) |w| {
            r.rect = .{ .left = 0, .top = 0, .right = @max(1, w.width), .bottom = @max(1, w.height) };
            return 2; // SIMPLEREGION
        }
    }
    return 1; // NULLREGION
}

fn GetWindow(hWnd: usize, uCmd: u32) callconv(W) usize {
    _ = hWnd; _ = uCmd;
    return 0;
}

fn sleepMs(ms: u32) void {
    const req = std.os.linux.timespec{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    var rem: std.os.linux.timespec = undefined;
    _ = std.os.linux.nanosleep(&req, &rem);
}

const QS_KEY: u32 = 0x0001;
const QS_MOUSEMOVE: u32 = 0x0002;
const QS_MOUSEBUTTON: u32 = 0x0004;
const QS_POSTMESSAGE: u32 = 0x0008;
const QS_TIMER: u32 = 0x0010;
const QS_PAINT: u32 = 0x0080;
const QS_SENDMESSAGE: u32 = 0x0040;
const QS_HOTKEY: u32 = 0x0100;
const QS_RAWINPUT: u32 = 0x0400;
const QS_ALLINPUT: u32 = 0x04FF;
const QS_ALLEVENTS: u32 = 0x0BF7;

fn msgMatchesWake(msg: u32, mask: u32) bool {
    if (mask & QS_KEY != 0 and msg >= 0x0100 and msg <= 0x0109) return true; // WM_KEYFIRST..KEYLAST + WM_CHAR
    if (mask & QS_MOUSEMOVE != 0 and msg == 0x0200) return true;
    if (mask & QS_MOUSEBUTTON != 0 and msg >= 0x0201 and msg <= 0x020E) return true;
    if (mask & QS_RAWINPUT != 0 and msg == WM_INPUT) return true;
    if (mask & QS_PAINT != 0 and msg == WM_PAINT) return true;
    if (mask & QS_TIMER != 0 and msg == 0x0113) return true;
    if (mask & QS_HOTKEY != 0 and msg == 0x0401) return true;
    if (mask & (QS_POSTMESSAGE | QS_SENDMESSAGE) != 0) return true;
    if (mask & QS_ALLINPUT != 0 and msg != WM_NULL and msg != WM_QUIT) return true;
    if (mask & QS_ALLEVENTS != 0 and msg != WM_NULL) return true;
    return false;
}

fn queueHasInput(wake_mask: u32) bool {
    if (queue_count == 0) return false;
    var i = queue_head;
    var n: usize = 0;
    while (n < queue_count) : (n += 1) {
        if (msgMatchesWake(msg_queue[i].message, wake_mask)) return true;
        i = (i + 1) % MAX_QUEUE;
    }
    return false;
}

/// MsgWaitForMultipleObjects: pump X11, return WAIT_OBJECT_0+nCount when a
/// queued message matches dwWakeMask, otherwise wait on the handles (in
/// slices so X11 input is still noticed) until the timeout elapses.
fn MsgWaitForMultipleObjects(nCount: u32, pHandles: ?*const usize, fWaitAll: i32, dwMilliseconds: u32, dwWakeMask: u32) callconv(W) u32 {
    const INFINITE: u32 = 0xFFFFFFFF;
    var remaining = dwMilliseconds;
    const infinite = dwMilliseconds == INFINITE;
    const handles = if (nCount >= 1 and nCount <= threads.MAXIMUM_WAIT_OBJECTS) pHandles else null;
    while (true) {
        pumpX11Events(0);
        if (queueHasInput(dwWakeMask)) return threads.WAIT_OBJECT_0 + nCount;
        const slice: u32 = if (infinite) 50 else @min(remaining, 20);
        if (handles) |hs| {
            if (threads.waitMany(@as([*]const usize, @ptrCast(hs))[0..nCount], fWaitAll != 0, slice)) |r| {
                if (r != threads.WAIT_TIMEOUT) return r;
            } else {
                // at least one handle is not ours: just sleep the slice
                if (slice > 0) sleepMs(slice);
            }
        } else if (slice > 0) {
            sleepMs(slice);
        }
        if (!infinite) {
            if (remaining <= slice) return threads.WAIT_TIMEOUT;
            remaining -= slice;
        }
    }
}

fn NotifyWinEvent(event: u32, hwnd: usize, idObject: i32, idChild: i32) callconv(W) void {
    _ = event; _ = hwnd; _ = idObject; _ = idChild;
}

fn CallWindowProcW(lpPrevWndFunc: ?*anyopaque, hWnd: usize, Msg: u32, wParam: usize, lParam: usize) callconv(W) isize {
    const f_ptr = lpPrevWndFunc orelse return @bitCast(defWindowProcW(hWnd, Msg, wParam, lParam));
    if (@intFromPtr(f_ptr) < 0x10000) return @bitCast(defWindowProcW(hWnd, Msg, wParam, lParam));
    const proc: WndProcFn = @ptrCast(@alignCast(f_ptr));
    return @bitCast(proc(hWnd, Msg, wParam, lParam));
}

fn GetDoubleClickTime() callconv(W) u32 {
    return 500;
}

fn SystemParametersInfoA(uiAction: u32, uiParam: u32, pvParam: ?*anyopaque, fWinIni: u32) callconv(W) i32 {
    return SystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
}

fn WaitForInputIdle(hProcess: usize, dwMilliseconds: u32) callconv(W) u32 {
    _ = hProcess;
    _ = dwMilliseconds;
    return 0;
}

fn SendMessageTimeoutW(
    hWnd: usize,
    Msg: u32,
    wParam: usize,
    lParam: usize,
    fuFlags: u32,
    uTimeout: u32,
    lpdwResult: ?*usize,
) callconv(W) isize {
    _ = fuFlags;
    _ = uTimeout;
    const res: usize = @bitCast(sendMessageW(hWnd, Msg, wParam, lParam));
    if (lpdwResult) |out| out.* = res;
    return 1;
}

pub fn lookup(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "GetCursorPos")) return @intFromPtr(&GetCursorPos);
    if (std.mem.eql(u8, name, "GetMonitorInfoW")) return @intFromPtr(&GetMonitorInfoW);
    if (std.mem.eql(u8, name, "GetMonitorInfoA")) return @intFromPtr(&GetMonitorInfoA);
    if (std.mem.eql(u8, name, "MonitorFromPoint")) return @intFromPtr(&MonitorFromPoint);
    if (std.mem.eql(u8, name, "MonitorFromRect")) return @intFromPtr(&MonitorFromRect);
    if (std.mem.eql(u8, name, "MonitorFromWindow")) return @intFromPtr(&MonitorFromWindow);
    if (std.mem.eql(u8, name, "GetParent")) return @intFromPtr(&GetParent);
    if (std.mem.eql(u8, name, "GetWindowLongPtrW")) return @intFromPtr(&GetWindowLongPtrW);
    if (std.mem.eql(u8, name, "SetWindowLongPtrW")) return @intFromPtr(&SetWindowLongPtrW);
    if (std.mem.eql(u8, name, "GetWindowLongW")) return @intFromPtr(&GetWindowLongW);
    if (std.mem.eql(u8, name, "SetWindowLongW")) return @intFromPtr(&SetWindowLongW);
    if (std.mem.eql(u8, name, "GetWindowLongPtrA")) return @intFromPtr(&GetWindowLongPtrA);
    if (std.mem.eql(u8, name, "SetWindowLongPtrA")) return @intFromPtr(&SetWindowLongPtrA);
    if (std.mem.eql(u8, name, "GetWindowLongA")) return @intFromPtr(&GetWindowLongA);
    if (std.mem.eql(u8, name, "SetWindowLongA")) return @intFromPtr(&SetWindowLongA);
    if (std.mem.eql(u8, name, "GetWindowPlacement")) return @intFromPtr(&GetWindowPlacement);
    if (std.mem.eql(u8, name, "SetWindowPlacement")) return @intFromPtr(&SetWindowPlacement);
    if (std.mem.eql(u8, name, "IsDialogMessageW")) return @intFromPtr(&IsDialogMessageW);
    if (std.mem.eql(u8, name, "SetTimer")) return @intFromPtr(&SetTimer);
    if (std.mem.eql(u8, name, "KillTimer")) return @intFromPtr(&KillTimer);
    if (std.mem.eql(u8, name, "OffsetRect")) return @intFromPtr(&OffsetRect);
    if (std.mem.eql(u8, name, "CopyRect")) return @intFromPtr(&CopyRect);
    if (std.mem.eql(u8, name, "ScreenToClient")) return @intFromPtr(&ScreenToClient);
    if (std.mem.eql(u8, name, "SetCursor")) return @intFromPtr(&SetCursor);
    if (std.mem.eql(u8, name, "ShowCursor")) return @intFromPtr(&ShowCursor);
    if (std.mem.eql(u8, name, "SetCursorPos")) return @intFromPtr(&SetCursorPos);
    if (std.mem.eql(u8, name, "ClipCursor")) return @intFromPtr(&ClipCursor);
    if (std.mem.eql(u8, name, "SetFocus")) return @intFromPtr(&SetFocus);
    if (std.mem.eql(u8, name, "SetForegroundWindow")) return @intFromPtr(&SetForegroundWindow);
    if (std.mem.eql(u8, name, "GetForegroundWindow")) return @intFromPtr(&GetForegroundWindow);
    if (std.mem.eql(u8, name, "TrackMouseEvent")) return @intFromPtr(&TrackMouseEvent);
    if (std.mem.eql(u8, name, "UnregisterClassW")) return @intFromPtr(&UnregisterClassW);
    if (std.mem.eql(u8, name, "ValidateRect")) return @intFromPtr(&ValidateRect);
    if (std.mem.eql(u8, name, "RegisterRawInputDevices")) return @intFromPtr(&RegisterRawInputDevices);
    if (std.mem.eql(u8, name, "GetRawInputDeviceInfoW")) return @intFromPtr(&GetRawInputDeviceInfoW);
    if (std.mem.eql(u8, name, "GetRawInputData")) return @intFromPtr(&GetRawInputData);
    if (std.mem.eql(u8, name, "GetRawInputDeviceList")) return @intFromPtr(&GetRawInputDeviceList);
    if (std.mem.eql(u8, name, "RegisterDeviceNotificationW")) return @intFromPtr(&RegisterDeviceNotificationW);
    if (std.mem.eql(u8, name, "UnregisterDeviceNotification")) return @intFromPtr(&UnregisterDeviceNotification);
    if (std.mem.eql(u8, name, "GetKeyNameTextW")) return @intFromPtr(&GetKeyNameTextW);
    if (std.mem.eql(u8, name, "GetAsyncKeyState")) return @intFromPtr(&GetAsyncKeyState);
    if (std.mem.eql(u8, name, "GetMessagePos")) return @intFromPtr(&GetMessagePos);
    if (std.mem.eql(u8, name, "GetMessageExtraInfo")) return @intFromPtr(&GetMessageExtraInfo);
    if (std.mem.eql(u8, name, "DragDetect")) return @intFromPtr(&DragDetect);
    if (std.mem.eql(u8, name, "GetMessageA")) return @intFromPtr(&GetMessageA);
    if (std.mem.eql(u8, name, "PeekMessageA")) return @intFromPtr(&PeekMessageA);
    if (std.mem.eql(u8, name, "DispatchMessageA")) return @intFromPtr(&DispatchMessageA);
    if (std.mem.eql(u8, name, "CopyImage")) return @intFromPtr(&CopyImage);
    if (std.mem.eql(u8, name, "wvsprintfA")) return @intFromPtr(&wvsprintfA);
    if (std.mem.eql(u8, name, "wsprintfA")) return @intFromPtr(&wsprintfA);
    if (std.mem.eql(u8, name, "EnumDisplaySettingsA")) return @intFromPtr(&EnumDisplaySettingsA);
    if (std.mem.eql(u8, name, "EnumDisplaySettingsW")) return @intFromPtr(&EnumDisplaySettingsW);
    if (std.mem.eql(u8, name, "ChangeDisplaySettingsW")) return @intFromPtr(&ChangeDisplaySettingsW);
    if (std.mem.eql(u8, name, "EnumDisplayMonitors")) return @intFromPtr(&EnumDisplayMonitors);
    if (std.mem.eql(u8, name, "EnumDisplayDevicesA")) return @intFromPtr(&EnumDisplayDevicesA);
    if (std.mem.eql(u8, name, "EnumDisplayDevicesW")) return @intFromPtr(&EnumDisplayDevicesW);
    if (std.mem.eql(u8, name, "GetCaretBlinkTime")) return @intFromPtr(&GetCaretBlinkTime);
    if (std.mem.eql(u8, name, "IsClipboardFormatAvailable")) return @intFromPtr(&IsClipboardFormatAvailable);
    if (std.mem.eql(u8, name, "LoadCursorA")) return @intFromPtr(&LoadCursorA);
    if (std.mem.eql(u8, name, "LoadIconA")) return @intFromPtr(&LoadIconA);
    if (std.mem.eql(u8, name, "CreateIconIndirect")) return @intFromPtr(&CreateIconIndirect);
    if (std.mem.eql(u8, name, "GetThreadDesktop")) return @intFromPtr(&GetThreadDesktop);
    if (std.mem.eql(u8, name, "GetUserObjectInformationA")) return @intFromPtr(&GetUserObjectInformationA);
    if (std.mem.eql(u8, name, "GetUserObjectInformationW")) return @intFromPtr(&GetUserObjectInformationW);
    if (std.mem.eql(u8, name, "GetProcessWindowStation")) return @intFromPtr(&GetProcessWindowStation);
    if (std.mem.eql(u8, name, "RegisterWindowMessageA")) return @intFromPtr(&RegisterWindowMessageA);
    if (std.mem.eql(u8, name, "SendMessageA")) return @intFromPtr(&SendMessageA);
    if (std.mem.eql(u8, name, "SendMessageTimeoutA")) return @intFromPtr(&SendMessageTimeoutA);
    if (std.mem.eql(u8, name, "EnumWindows")) return @intFromPtr(&EnumWindows);
    if (std.mem.eql(u8, name, "CreateDialogParamA")) return @intFromPtr(&CreateDialogParamA);
    if (std.mem.eql(u8, name, "DialogBoxParamA")) return @intFromPtr(&DialogBoxParamA);
    if (std.mem.eql(u8, name, "AdjustWindowRectEx")) return @intFromPtr(&AdjustWindowRectEx);
    if (std.mem.eql(u8, name, "SetDlgItemTextA")) return @intFromPtr(&SetDlgItemTextA);
    if (std.mem.eql(u8, name, "CheckDlgButton")) return @intFromPtr(&CheckDlgButton);
    if (std.mem.eql(u8, name, "IsDlgButtonChecked")) return @intFromPtr(&IsDlgButtonChecked);
    if (std.mem.eql(u8, name, "GetDesktopWindow")) return @intFromPtr(&GetDesktopWindow);
    if (std.mem.eql(u8, name, "ClientToScreen")) return @intFromPtr(&ClientToScreen);
    if (std.mem.eql(u8, name, "OpenClipboard")) return @intFromPtr(&OpenClipboard);
    if (std.mem.eql(u8, name, "CloseClipboard")) return @intFromPtr(&CloseClipboard);
    if (std.mem.eql(u8, name, "EmptyClipboard")) return @intFromPtr(&EmptyClipboard);
    if (std.mem.eql(u8, name, "GetClipboardData")) return @intFromPtr(&GetClipboardData);
    if (std.mem.eql(u8, name, "SetClipboardData")) return @intFromPtr(&SetClipboardData);
    if (std.mem.eql(u8, name, "CreateDialogParamW")) return @intFromPtr(&CreateDialogParamW);
    if (std.mem.eql(u8, name, "DestroyCursor")) return @intFromPtr(&DestroyCursor);
    if (std.mem.eql(u8, name, "DestroyIcon")) return @intFromPtr(&DestroyIcon);
    if (std.mem.eql(u8, name, "GetActiveWindow")) return @intFromPtr(&GetActiveWindow);
    if (std.mem.eql(u8, name, "GetAncestor")) return @intFromPtr(&GetAncestor);
    if (std.mem.eql(u8, name, "GetFocus")) return @intFromPtr(&GetFocus);
    if (std.mem.eql(u8, name, "GetKeyState")) return @intFromPtr(&GetKeyState);
    if (std.mem.eql(u8, name, "GetMessageTime")) return @intFromPtr(&GetMessageTime);
    if (std.mem.eql(u8, name, "PtInRect")) return @intFromPtr(&PtInRect);
    if (std.mem.eql(u8, name, "ReleaseCapture")) return @intFromPtr(&ReleaseCapture);
    if (std.mem.eql(u8, name, "SetCapture")) return @intFromPtr(&SetCapture);
    if (std.mem.eql(u8, name, "GetCapture")) return @intFromPtr(&GetCapture);
    if (std.mem.eql(u8, name, "CreateWindowExW")) return @intFromPtr(&createWindowExW);
    if (std.mem.eql(u8, name, "GetClientRect")) return @intFromPtr(&getClientRect);
    if (std.mem.eql(u8, name, "DestroyWindow")) return @intFromPtr(&destroyWindow);
    if (std.mem.eql(u8, name, "RegisterClassExW")) return @intFromPtr(&registerClassExW);
    if (std.mem.eql(u8, name, "RegisterClassW")) return @intFromPtr(&registerClassW);
    if (std.mem.eql(u8, name, "DefWindowProcW")) return @intFromPtr(&defWindowProcW);
    if (std.mem.eql(u8, name, "ShowWindow")) return @intFromPtr(&showWindow);
    if (std.mem.eql(u8, name, "UpdateWindow")) return @intFromPtr(&updateWindow);
    if (std.mem.eql(u8, name, "GetMessageW")) return @intFromPtr(&getMessageW);
    if (std.mem.eql(u8, name, "PeekMessageW")) return @intFromPtr(&peekMessageW);
    if (std.mem.eql(u8, name, "TranslateMessage")) return @intFromPtr(&translateMessage);
    if (std.mem.eql(u8, name, "DispatchMessageW")) return @intFromPtr(&dispatchMessageW);
    if (std.mem.eql(u8, name, "PostQuitMessage")) return @intFromPtr(&postQuitMessage);
    if (std.mem.eql(u8, name, "PostMessageW")) return @intFromPtr(&postMessageW);
    if (std.mem.eql(u8, name, "SendMessageW")) return @intFromPtr(&sendMessageW);
    if (std.mem.eql(u8, name, "MessageBoxW")) return @intFromPtr(&MessageBoxW);
    if (std.mem.eql(u8, name, "MessageBoxA")) return @intFromPtr(&MessageBoxA);
    if (std.mem.eql(u8, name, "GetDC")) return @intFromPtr(&GetDC);
    if (std.mem.eql(u8, name, "ReleaseDC")) return @intFromPtr(&ReleaseDC);
    if (std.mem.eql(u8, name, "GetSystemMetrics")) return @intFromPtr(&GetSystemMetrics);
    if (std.mem.eql(u8, name, "SetWindowPos")) return @intFromPtr(&SetWindowPos);
    if (std.mem.eql(u8, name, "GetWindowRect")) return @intFromPtr(&GetWindowRect);
    if (std.mem.eql(u8, name, "SetWindowTextW")) return @intFromPtr(&SetWindowTextW);
    if (std.mem.eql(u8, name, "SetDlgItemTextW")) return @intFromPtr(&SetDlgItemTextW);
    if (std.mem.eql(u8, name, "GetDlgItemTextW")) return @intFromPtr(&GetDlgItemTextW);
    if (std.mem.eql(u8, name, "GetDlgItemTextA")) return @intFromPtr(&GetDlgItemTextA);
    if (std.mem.eql(u8, name, "SendDlgItemMessageW")) return @intFromPtr(&SendDlgItemMessageW);
    if (std.mem.eql(u8, name, "GetDlgItem")) return @intFromPtr(&GetDlgItem);
    if (std.mem.eql(u8, name, "GetDlgItemInt")) return @intFromPtr(&GetDlgItemInt);
    if (std.mem.eql(u8, name, "SetDlgItemInt")) return @intFromPtr(&SetDlgItemInt);
    if (std.mem.eql(u8, name, "DialogBoxParamW")) return @intFromPtr(&DialogBoxParamW);
    if (std.mem.eql(u8, name, "EndDialog")) return @intFromPtr(&EndDialog);
    if (std.mem.eql(u8, name, "EnableWindow")) return @intFromPtr(&EnableWindow);
    if (std.mem.eql(u8, name, "LoadImageW")) return @intFromPtr(&LoadImageW);
    if (std.mem.eql(u8, name, "SystemParametersInfoW")) return @intFromPtr(&SystemParametersInfoW);
    if (std.mem.eql(u8, name, "FindWindowExW")) return @intFromPtr(&FindWindowExW);
    if (std.mem.eql(u8, name, "SetWindowsHookExW")) return @intFromPtr(&SetWindowsHookExW);
    if (std.mem.eql(u8, name, "UnhookWindowsHookEx")) return @intFromPtr(&UnhookWindowsHookEx);
    if (std.mem.eql(u8, name, "CallNextHookEx")) return @intFromPtr(&CallNextHookEx);
    if (std.mem.eql(u8, name, "BeginPaint")) return @intFromPtr(&BeginPaint);
    if (std.mem.eql(u8, name, "EndPaint")) return @intFromPtr(&EndPaint);
    if (std.mem.eql(u8, name, "InvalidateRect")) return @intFromPtr(&InvalidateRect);
    if (std.mem.eql(u8, name, "RedrawWindow")) return @intFromPtr(&RedrawWindow);
    if (std.mem.eql(u8, name, "FillRect")) return @intFromPtr(&FillRect);
    if (std.mem.eql(u8, name, "FrameRect")) return @intFromPtr(&FrameRect);
    if (std.mem.eql(u8, name, "DrawEdge")) return @intFromPtr(&DrawEdge);
    if (std.mem.eql(u8, name, "DrawFrameControl")) return @intFromPtr(&DrawFrameControl);
    if (std.mem.eql(u8, name, "DrawFocusRect")) return @intFromPtr(&DrawFocusRect);
    if (std.mem.eql(u8, name, "DrawIconEx")) return @intFromPtr(&DrawIconEx);
    if (std.mem.eql(u8, name, "DrawTextW")) return @intFromPtr(&DrawTextW);
    if (std.mem.eql(u8, name, "DrawTextExW")) return @intFromPtr(&DrawTextExW);
    if (std.mem.eql(u8, name, "CreateMenu")) return @intFromPtr(&CreateMenu);
    if (std.mem.eql(u8, name, "CreatePopupMenu")) return @intFromPtr(&CreatePopupMenu);
    if (std.mem.eql(u8, name, "DestroyMenu")) return @intFromPtr(&DestroyMenu);
    if (std.mem.eql(u8, name, "GetMenu")) return @intFromPtr(&GetMenu);
    if (std.mem.eql(u8, name, "SetMenu")) return @intFromPtr(&SetMenu);
    if (std.mem.eql(u8, name, "DrawMenuBar")) return @intFromPtr(&DrawMenuBar);
    if (std.mem.eql(u8, name, "GetSubMenu")) return @intFromPtr(&GetSubMenu);
    if (std.mem.eql(u8, name, "GetMenuItemCount")) return @intFromPtr(&GetMenuItemCount);
    if (std.mem.eql(u8, name, "GetMenuItemID")) return @intFromPtr(&GetMenuItemID);
    if (std.mem.eql(u8, name, "GetMenuItemInfoW")) return @intFromPtr(&GetMenuItemInfoW);
    if (std.mem.eql(u8, name, "SetMenuItemInfoW")) return @intFromPtr(&SetMenuItemInfoW);
    if (std.mem.eql(u8, name, "GetMenuStringW")) return @intFromPtr(&GetMenuStringW);
    if (std.mem.eql(u8, name, "GetMenuState")) return @intFromPtr(&GetMenuState);
    if (std.mem.eql(u8, name, "InsertMenuW")) return @intFromPtr(&InsertMenuW);
    if (std.mem.eql(u8, name, "InsertMenuItemW")) return @intFromPtr(&InsertMenuItemW);
    if (std.mem.eql(u8, name, "AppendMenuW")) return @intFromPtr(&AppendMenuW);
    if (std.mem.eql(u8, name, "AppendMenuA")) return @intFromPtr(&AppendMenuA);
    if (std.mem.eql(u8, name, "ModifyMenuW")) return @intFromPtr(&ModifyMenuW);
    if (std.mem.eql(u8, name, "DeleteMenu")) return @intFromPtr(&DeleteMenu);
    if (std.mem.eql(u8, name, "RemoveMenu")) return @intFromPtr(&RemoveMenu);
    if (std.mem.eql(u8, name, "EnableMenuItem")) return @intFromPtr(&EnableMenuItem);
    if (std.mem.eql(u8, name, "CheckMenuItem")) return @intFromPtr(&CheckMenuItem);
    if (std.mem.eql(u8, name, "CheckMenuRadioItem")) return @intFromPtr(&CheckMenuRadioItem);
    if (std.mem.eql(u8, name, "SetMenuItemBitmaps")) return @intFromPtr(&SetMenuItemBitmaps);
    if (std.mem.eql(u8, name, "TrackPopupMenu")) return @intFromPtr(&TrackPopupMenu);
    if (std.mem.eql(u8, name, "TrackPopupMenuEx")) return @intFromPtr(&TrackPopupMenuEx);
    if (std.mem.eql(u8, name, "GetMenuBarInfo")) return @intFromPtr(&GetMenuBarInfo);
    if (std.mem.eql(u8, name, "CreateCaret")) return @intFromPtr(&CreateCaret);
    if (std.mem.eql(u8, name, "DestroyCaret")) return @intFromPtr(&DestroyCaret);
    if (std.mem.eql(u8, name, "ShowCaret")) return @intFromPtr(&ShowCaret);
    if (std.mem.eql(u8, name, "HideCaret")) return @intFromPtr(&HideCaret);
    if (std.mem.eql(u8, name, "SetCaretPos")) return @intFromPtr(&SetCaretPos);
    if (std.mem.eql(u8, name, "GetWindowTextW")) return @intFromPtr(&GetWindowTextW);
    if (std.mem.eql(u8, name, "GetWindowTextA")) return @intFromPtr(&GetWindowTextA);
    if (std.mem.eql(u8, name, "GetWindowTextLengthW")) return @intFromPtr(&GetWindowTextLengthW);
    if (std.mem.eql(u8, name, "IsWindow")) return @intFromPtr(&IsWindow);
    if (std.mem.eql(u8, name, "IsWindowEnabled")) return @intFromPtr(&IsWindowEnabled);
    if (std.mem.eql(u8, name, "IsWindowVisible")) return @intFromPtr(&IsWindowVisible);
    if (std.mem.eql(u8, name, "IsIconic")) return @intFromPtr(&IsIconic);
    if (std.mem.eql(u8, name, "IsZoomed")) return @intFromPtr(&IsZoomed);
    if (std.mem.eql(u8, name, "IsChild")) return @intFromPtr(&IsChild);
    if (std.mem.eql(u8, name, "SetParent")) return @intFromPtr(&SetParent);
    if (std.mem.eql(u8, name, "MoveWindow")) return @intFromPtr(&MoveWindow);
    if (std.mem.eql(u8, name, "BringWindowToTop")) return @intFromPtr(&BringWindowToTop);
    if (std.mem.eql(u8, name, "GetLastActivePopup")) return @intFromPtr(&GetLastActivePopup);
    if (std.mem.eql(u8, name, "FindWindowW")) return @intFromPtr(&FindWindowW);
    if (std.mem.eql(u8, name, "GetWindowThreadProcessId")) return @intFromPtr(&GetWindowThreadProcessId);
    if (std.mem.eql(u8, name, "GetClassNameW")) return @intFromPtr(&GetClassNameW);
    if (std.mem.eql(u8, name, "GetClassNameA")) return @intFromPtr(&GetClassNameA);
    if (std.mem.eql(u8, name, "GetDlgCtrlID")) return @intFromPtr(&GetDlgCtrlID);
    if (std.mem.eql(u8, name, "GetSysColor")) return @intFromPtr(&GetSysColor);
    if (std.mem.eql(u8, name, "GetSysColorBrush")) return @intFromPtr(&GetSysColorBrush);
    if (std.mem.eql(u8, name, "SetPropW")) return @intFromPtr(&SetPropW);
    if (std.mem.eql(u8, name, "GetPropW")) return @intFromPtr(&GetPropW);
    if (std.mem.eql(u8, name, "RemovePropW")) return @intFromPtr(&RemovePropW);
    if (std.mem.eql(u8, name, "SetLayeredWindowAttributes")) return @intFromPtr(&SetLayeredWindowAttributes);
    if (std.mem.eql(u8, name, "GetWindowDC")) return @intFromPtr(&GetWindowDC);
    if (std.mem.eql(u8, name, "GetDCEx")) return @intFromPtr(&GetDCEx);
    if (std.mem.eql(u8, name, "MapWindowPoints")) return @intFromPtr(&MapWindowPoints);
    if (std.mem.eql(u8, name, "InflateRect")) return @intFromPtr(&InflateRect);
    if (std.mem.eql(u8, name, "EqualRect")) return @intFromPtr(&EqualRect);
    if (std.mem.eql(u8, name, "IntersectRect")) return @intFromPtr(&IntersectRect);
    if (std.mem.eql(u8, name, "SetRectEmpty")) return @intFromPtr(&SetRectEmpty);
    if (std.mem.eql(u8, name, "EnumChildWindows")) return @intFromPtr(&EnumChildWindows);
    if (std.mem.eql(u8, name, "EnumThreadWindows")) return @intFromPtr(&EnumThreadWindows);
    if (std.mem.eql(u8, name, "GetComboBoxInfo")) return @intFromPtr(&GetComboBoxInfo);
    if (std.mem.eql(u8, name, "GetIconInfo")) return @intFromPtr(&GetIconInfo);
    if (std.mem.eql(u8, name, "wsprintfW")) return @intFromPtr(&wsprintfW);
    if (std.mem.eql(u8, name, "GetScrollPos")) return @intFromPtr(&GetScrollPos);
    if (std.mem.eql(u8, name, "SetScrollPos")) return @intFromPtr(&SetScrollPos);
    if (std.mem.eql(u8, name, "GetScrollRange")) return @intFromPtr(&GetScrollRange);
    if (std.mem.eql(u8, name, "SetScrollRange")) return @intFromPtr(&SetScrollRange);
    if (std.mem.eql(u8, name, "GetScrollInfo")) return @intFromPtr(&GetScrollInfo);
    if (std.mem.eql(u8, name, "SetScrollInfo")) return @intFromPtr(&SetScrollInfo);
    if (std.mem.eql(u8, name, "ScrollWindow")) return @intFromPtr(&ScrollWindow);
    if (std.mem.eql(u8, name, "ShowScrollBar")) return @intFromPtr(&ShowScrollBar);
    if (std.mem.eql(u8, name, "RegisterClipboardFormatW")) return @intFromPtr(&RegisterClipboardFormatW);
    if (std.mem.eql(u8, name, "AddClipboardFormatListener")) return @intFromPtr(&AddClipboardFormatListener);
    if (std.mem.eql(u8, name, "RemoveClipboardFormatListener")) return @intFromPtr(&RemoveClipboardFormatListener);
    if (std.mem.eql(u8, name, "SetClipboardViewer")) return @intFromPtr(&SetClipboardViewer);
    if (std.mem.eql(u8, name, "ChangeClipboardChain")) return @intFromPtr(&ChangeClipboardChain);
    if (std.mem.eql(u8, name, "CreateAcceleratorTableW")) return @intFromPtr(&CreateAcceleratorTableW);
    if (std.mem.eql(u8, name, "DestroyAcceleratorTable")) return @intFromPtr(&DestroyAcceleratorTable);
    if (std.mem.eql(u8, name, "TranslateAcceleratorW")) return @intFromPtr(&TranslateAcceleratorW);
    if (std.mem.eql(u8, name, "RegisterWindowMessageW")) return @intFromPtr(&RegisterWindowMessageW);
    if (std.mem.eql(u8, name, "FlashWindowEx")) return @intFromPtr(&FlashWindowEx);
    if (std.mem.eql(u8, name, "LockWindowUpdate")) return @intFromPtr(&LockWindowUpdate);
    if (std.mem.eql(u8, name, "BeginDeferWindowPos")) return @intFromPtr(&BeginDeferWindowPos);
    if (std.mem.eql(u8, name, "DeferWindowPos")) return @intFromPtr(&DeferWindowPos);
    if (std.mem.eql(u8, name, "EndDeferWindowPos")) return @intFromPtr(&EndDeferWindowPos);
    if (std.mem.eql(u8, name, "WindowFromPoint")) return @intFromPtr(&WindowFromPoint);
    if (std.mem.eql(u8, name, "ChildWindowFromPointEx")) return @intFromPtr(&ChildWindowFromPointEx);
    if (std.mem.eql(u8, name, "CreateDialogIndirectParamW")) return @intFromPtr(&CreateDialogIndirectParamW);
    if (std.mem.eql(u8, name, "DialogBoxIndirectParamW")) return @intFromPtr(&DialogBoxIndirectParamW);
    if (std.mem.eql(u8, name, "mouse_event")) return @intFromPtr(&mouse_event);
    if (std.mem.eql(u8, name, "GetKeyboardState")) return @intFromPtr(&GetKeyboardState);
    if (std.mem.eql(u8, name, "MapVirtualKeyW")) return @intFromPtr(&MapVirtualKeyW);
    if (std.mem.eql(u8, name, "GetKeyboardLayout")) return @intFromPtr(&GetKeyboardLayout);
    if (std.mem.eql(u8, name, "ToAscii")) return @intFromPtr(&ToAscii);
    if (std.mem.eql(u8, name, "IsCharLowerW")) return @intFromPtr(&IsCharLowerW);
    if (std.mem.eql(u8, name, "CharUpperW")) return @intFromPtr(&CharUpperW);
    if (std.mem.eql(u8, name, "CharLowerW")) return @intFromPtr(&CharLowerW);
    if (std.mem.eql(u8, name, "IsCharAlphaNumericW")) return @intFromPtr(&IsCharAlphaNumericW);
    if (std.mem.eql(u8, name, "IsCharAlphaW")) return @intFromPtr(&IsCharAlphaW);
    if (std.mem.eql(u8, name, "LoadCursorW")) return @intFromPtr(&LoadCursorW);
    if (std.mem.eql(u8, name, "LoadMenuW")) return @intFromPtr(&LoadMenuW);
    if (std.mem.eql(u8, name, "LoadBitmapW")) return @intFromPtr(&LoadBitmapW);
    if (std.mem.eql(u8, name, "LoadIconW")) return @intFromPtr(&LoadIconW);
    if (std.mem.eql(u8, name, "LoadStringA")) return @intFromPtr(&LoadStringA);
    if (std.mem.eql(u8, name, "LoadStringW")) return @intFromPtr(&LoadStringW);
    if (std.mem.eql(u8, name, "MessageBeep")) return @intFromPtr(&MessageBeep);
    if (std.mem.eql(u8, name, "GetUpdateRgn")) return @intFromPtr(&GetUpdateRgn);
    if (std.mem.eql(u8, name, "GetWindow")) return @intFromPtr(&GetWindow);
    if (std.mem.eql(u8, name, "MsgWaitForMultipleObjects")) return @intFromPtr(&MsgWaitForMultipleObjects);
    if (std.mem.eql(u8, name, "NotifyWinEvent")) return @intFromPtr(&NotifyWinEvent);
    if (std.mem.eql(u8, name, "CallWindowProcW")) return @intFromPtr(&CallWindowProcW);
    if (std.mem.eql(u8, name, "GetDoubleClickTime")) return @intFromPtr(&GetDoubleClickTime);
    if (std.mem.eql(u8, name, "SystemParametersInfoA")) return @intFromPtr(&SystemParametersInfoA);
    if (std.mem.eql(u8, name, "WaitForInputIdle")) return @intFromPtr(&WaitForInputIdle);
    if (std.mem.eql(u8, name, "SendMessageTimeoutW")) return @intFromPtr(&SendMessageTimeoutW);
    return null;
}

fn comctlInitCommonControls() callconv(W) void {}

fn comctlSetWindowSubclass(hWnd: usize, pfnSubclass: ?SubclassProcFn, uIdSubclass: usize, dwRefData: usize) callconv(W) i32 {
    const proc = pfnSubclass orelse return 0;
    if (findWin(hWnd) == null) return 0;
    for (&subclasses) |*sc| {
        if (sc.in_use and sc.hwnd == hWnd and sc.proc == proc and sc.id == uIdSubclass) {
            sc.ref_data = dwRefData;
            return 1;
        }
    }
    for (&subclasses) |*sc| {
        if (!sc.in_use) {
            sc.* = .{
                .in_use = true,
                .hwnd = hWnd,
                .proc = proc,
                .id = uIdSubclass,
                .ref_data = dwRefData,
            };
            return 1;
        }
    }
    return 0;
}

fn comctlGetWindowSubclass(hWnd: usize, pfnSubclass: ?SubclassProcFn, uIdSubclass: usize, pdwRefData: ?*usize) callconv(W) i32 {
    const proc = pfnSubclass orelse return 0;
    for (subclasses) |sc| {
        if (sc.in_use and sc.hwnd == hWnd and sc.proc == proc and sc.id == uIdSubclass) {
            if (pdwRefData) |out| out.* = sc.ref_data;
            return 1;
        }
    }
    return 0;
}

fn comctlRemoveWindowSubclass(hWnd: usize, pfnSubclass: ?SubclassProcFn, uIdSubclass: usize) callconv(W) i32 {
    const proc = pfnSubclass orelse return 0;
    for (&subclasses) |*sc| {
        if (sc.in_use and sc.hwnd == hWnd and sc.proc == proc and sc.id == uIdSubclass) {
            sc.* = .{};
            return 1;
        }
    }
    return 0;
}

fn comctlDefSubclassProc(hWnd: usize, uMsg: u32, wParam: usize, lParam: usize) callconv(W) usize {
    return dispatchSubclassFrom(hWnd, uMsg, wParam, lParam, active_subclass_idx);
}

fn comctlLoadIconMetric(hinst: usize, pszName: ?*const anyopaque, lims: i32, phico: ?*usize) callconv(W) i32 {
    _ = hinst;
    _ = pszName;
    _ = lims;
    if (phico) |p| p.* = 0x40001;
    return 0;
}

fn comctlLoadIconWithScaleDown(hinst: usize, pszName: ?*const anyopaque, cx: i32, cy: i32, phico: ?*usize) callconv(W) i32 {
    _ = hinst;
    _ = pszName;
    _ = cx;
    _ = cy;
    if (phico) |p| p.* = 0x40001;
    return 0;
}

pub fn lookupComctl32(name: []const u8) ?usize {
    if (std.mem.eql(u8, name, "InitCommonControls")) return @intFromPtr(&comctlInitCommonControls);
    if (std.mem.eql(u8, name, "SetWindowSubclass")) return @intFromPtr(&comctlSetWindowSubclass);
    if (std.mem.eql(u8, name, "GetWindowSubclass")) return @intFromPtr(&comctlGetWindowSubclass);
    if (std.mem.eql(u8, name, "RemoveWindowSubclass")) return @intFromPtr(&comctlRemoveWindowSubclass);
    if (std.mem.eql(u8, name, "DefSubclassProc")) return @intFromPtr(&comctlDefSubclassProc);
    if (std.mem.eql(u8, name, "LoadIconMetric")) return @intFromPtr(&comctlLoadIconMetric);
    if (std.mem.eql(u8, name, "LoadIconWithScaleDown")) return @intFromPtr(&comctlLoadIconWithScaleDown);
    return null;
}
