//! WINS Differential Fuzzer - Random Input & Mutation Generator
const std = @import("std");

pub const RgbaPixel = struct {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
};

pub const FuzzGenerator = struct {
    prng: std.Random.DefaultPrng,

    pub fn init(seed: u64) FuzzGenerator {
        return .{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn random(self: *FuzzGenerator) std.Random {
        return self.prng.random();
    }

    /// Generates boundary and random u8 values for pixel/channel math
    pub fn generateByteWithBoundaries(self: *FuzzGenerator) u8 {
        const rand = self.random();
        const boundaries = [_]u8{ 0, 1, 2, 126, 127, 128, 129, 253, 254, 255 };
        if (rand.uintLessThan(u8, 10) < 4) {
            return boundaries[rand.uintLessThan(usize, boundaries.len)];
        }
        return rand.int(u8);
    }

    /// Generates an RGBA pixel with stress on edge-case alphas and colors
    pub fn generatePixel(self: *FuzzGenerator) RgbaPixel {
        const rand = self.random();
        const alpha_mode = rand.uintLessThan(u8, 5);
        const a: u8 = switch (alpha_mode) {
            0 => 0,   // fully transparent
            1 => 255, // fully opaque
            2 => 1,   // minimum non-zero alpha
            3 => 128, // mid alpha
            else => self.generateByteWithBoundaries(),
        };

        return .{
            .r = self.generateByteWithBoundaries(),
            .g = self.generateByteWithBoundaries(),
            .b = self.generateByteWithBoundaries(),
            .a = a,
        };
    }

    /// Generates a normalized float in [0.0, 1.0] with edge cases (0.0, 1.0, subnormals)
    pub fn generateNormalizedFloat(self: *FuzzGenerator) f32 {
        const rand = self.random();
        const mode = rand.uintLessThan(u8, 6);
        return switch (mode) {
            0 => 0.0,
            1 => 1.0,
            2 => 0.5,
            3 => 1.0 / 255.0,
            4 => 254.0 / 255.0,
            else => @as(f32, @floatFromInt(rand.uintLessThan(u16, 256))) / 255.0,
        };
    }

    /// Generates a random simulated Windows path with typical Windows anomalies
    pub fn generateWindowsPath(self: *FuzzGenerator, buf: []u8) []const u8 {
        const rand = self.random();
        const drives = [_][]const u8{ "C:\\", "D:\\", "E:\\", "c:\\", "", "", "" };
        const base_dirs = [_][]const u8{
            "Users\\User\\AppData\\Roaming\\Notepad++\\",
            "Program Files\\Notepad++\\",
            "Windows\\System32\\",
            "temp\\",
            "plugins\\Config\\",
            "userDefineLangs\\",
            "themes\\",
        };
        const sub_names = [_][]const u8{
            "config", "stylers.model", "langs.model", "session",
            "pluginsAdmin", "nppLog", "doLocalConf", "change",
        };
        const exts = [_][]const u8{ ".xml", ".ini", ".log", ".txt", ".dll", ".tmp" };

        var pos: usize = 0;

        // 1. Optional Drive
        const drive = drives[rand.uintLessThan(usize, drives.len)];
        if (pos + drive.len < buf.len) {
            @memcpy(buf[pos .. pos + drive.len], drive);
            pos += drive.len;
        }

        // 2. Traversal injection
        const mode = rand.uintLessThan(u8, 5);
        if (mode == 0) {
            const trav = "..\\..\\";
            if (pos + trav.len < buf.len) {
                @memcpy(buf[pos .. pos + trav.len], trav);
                pos += trav.len;
            }
        } else if (mode == 1) {
            const trav = ".\\sub\\..\\";
            if (pos + trav.len < buf.len) {
                @memcpy(buf[pos .. pos + trav.len], trav);
                pos += trav.len;
            }
        }

        const base = base_dirs[rand.uintLessThan(usize, base_dirs.len)];
        if (pos + base.len < buf.len) {
            @memcpy(buf[pos .. pos + base.len], base);
            pos += base.len;
        }

        // 3. Name and Ext
        const name = sub_names[rand.uintLessThan(usize, sub_names.len)];
        if (pos + name.len < buf.len) {
            @memcpy(buf[pos .. pos + name.len], name);
            pos += name.len;
        }

        const ext = exts[rand.uintLessThan(usize, exts.len)];
        if (pos + ext.len < buf.len) {
            @memcpy(buf[pos .. pos + ext.len], ext);
            pos += ext.len;
        }

        // 4. Occasional mixed slashes
        if (rand.boolean() and pos > 0) {
            const idx = rand.uintLessThan(usize, pos);
            if (buf[idx] == '\\') {
                buf[idx] = '/';
            }
        }

        return buf[0..pos];
    }

    /// Generates Windows security and anomaly paths (DOS devices, ADS, UNC, trailing dots/spaces)
    pub fn generateSecurityPath(self: *FuzzGenerator, buf: []u8) []const u8 {
        const rand = self.random();
        const devices = [_][]const u8{
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4",
            "LPT1", "LPT2", "LPT3",
            "con", "prn", "aux", "nul", "com1",
        };
        const streams = [_][]const u8{
            ":Zone.Identifier", ":$DATA", ":hidden_stream", ":metadata",
        };
        const unc_prefixes = [_][]const u8{
            "\\\\?\\C:\\", "\\\\.\\", "\\\\server\\share\\", "C:\\", "",
        };

        var pos: usize = 0;
        const test_kind = rand.uintLessThan(u8, 5);

        switch (test_kind) {
            // Case 0: DOS Device (e.g. C:\temp\CON.txt or AUX)
            0 => {
                const unc = unc_prefixes[rand.uintLessThan(usize, unc_prefixes.len)];
                if (pos + unc.len < buf.len) {
                    @memcpy(buf[pos .. pos + unc.len], unc);
                    pos += unc.len;
                }
                if (rand.boolean()) {
                    const dir = "data\\sub\\";
                    if (pos + dir.len < buf.len) {
                        @memcpy(buf[pos .. pos + dir.len], dir);
                        pos += dir.len;
                    }
                }
                const dev = devices[rand.uintLessThan(usize, devices.len)];
                if (pos + dev.len < buf.len) {
                    @memcpy(buf[pos .. pos + dev.len], dev);
                    pos += dev.len;
                }
                if (rand.boolean()) {
                    const ext = ".txt";
                    if (pos + ext.len < buf.len) {
                        @memcpy(buf[pos .. pos + ext.len], ext);
                        pos += ext.len;
                    }
                }
            },
            // Case 1: Alternate Data Stream (ADS)
            1 => {
                const prefix = "C:\\Users\\User\\Documents\\document.txt";
                if (pos + prefix.len < buf.len) {
                    @memcpy(buf[pos .. pos + prefix.len], prefix);
                    pos += prefix.len;
                }
                const stream = streams[rand.uintLessThan(usize, streams.len)];
                if (pos + stream.len < buf.len) {
                    @memcpy(buf[pos .. pos + stream.len], stream);
                    pos += stream.len;
                }
            },
            // Case 2: Trailing dots and spaces (Windows auto-trims them)
            2 => {
                const base = "C:\\Projects\\file_test";
                if (pos + base.len < buf.len) {
                    @memcpy(buf[pos .. pos + base.len], base);
                    pos += base.len;
                }
                const dot_count = rand.uintAtMost(usize, 3) + 1;
                var d: usize = 0;
                while (d < dot_count and pos < buf.len) : (d += 1) {
                    buf[pos] = '.';
                    pos += 1;
                }
                const space_count = rand.uintAtMost(usize, 3);
                var s: usize = 0;
                while (s < space_count and pos < buf.len) : (s += 1) {
                    buf[pos] = ' ';
                    pos += 1;
                }
            },
            // Case 3: Deep directory traversal
            3 => {
                const trav_roots = [_][]const u8{
                    "C:\\Users\\User\\AppData\\Roaming\\..\\..\\..\\..\\..\\windows\\system32\\calc.exe",
                    "..\\..\\..\\..\\etc\\passwd",
                    "C:\\temp\\.\\..\\.\\..\\secret.key",
                };
                const chosen = trav_roots[rand.uintLessThan(usize, trav_roots.len)];
                if (pos + chosen.len < buf.len) {
                    @memcpy(buf[pos .. pos + chosen.len], chosen);
                    pos += chosen.len;
                }
            },
            // Case 4: Extended UNC Paths (MAX_PATH bypass)
            else => {
                const unc = "\\\\?\\C:\\VeryLongPath\\";
                if (pos + unc.len < buf.len) {
                    @memcpy(buf[pos .. pos + unc.len], unc);
                    pos += unc.len;
                }
                var segs: usize = 0;
                while (segs < 6 and pos + 12 < buf.len) : (segs += 1) {
                    const seg = "directory\\";
                    @memcpy(buf[pos .. pos + seg.len], seg);
                    pos += seg.len;
                }
                const leaf = "target_payload.ini";
                if (pos + leaf.len < buf.len) {
                    @memcpy(buf[pos .. pos + leaf.len], leaf);
                    pos += leaf.len;
                }
            },
        }

        return buf[0..pos];
    }

    /// Generates multi-line text buffers with mixed line endings (\r\n, \n, \r) and multibyte characters
    pub fn generateTextBuffer(self: *FuzzGenerator, buf: []u8) []const u8 {
        const rand = self.random();
        const line_contents = [_][]const u8{
            "fn main() void {",
            "    const val: u32 = 42;",
            "    // Español: línea con tildes áéíóú y eñe ñ",
            "    // 日本語: 漢字とひらがなとカタカナ",
            "    // Emojis: 🚀 💻 🦀 ✨ 🔥",
            "    return;",
            "}",
            "",
            "    ",
            "\t\tindented with tabs",
            "End of file line without trailing newline",
        };
        const eols = [_][]const u8{ "\r\n", "\n", "\r" };

        var pos: usize = 0;
        const line_count = rand.uintAtMost(usize, 8) + 2;

        var l: usize = 0;
        while (l < line_count) : (l += 1) {
            const line = line_contents[rand.uintLessThan(usize, line_contents.len)];
            if (pos + line.len < buf.len) {
                @memcpy(buf[pos .. pos + line.len], line);
                pos += line.len;
            }

            // Don't always add EOL to the very last line (tests EOF edge cases)
            if (l + 1 < line_count or rand.boolean()) {
                const eol = eols[rand.uintLessThan(usize, eols.len)];
                if (pos + eol.len < buf.len) {
                    @memcpy(buf[pos .. pos + eol.len], eol);
                    pos += eol.len;
                }
            }
        }

        return buf[0..pos];
    }

    /// Generates UTF-8 strings including multibyte characters, emojis, and edge cases
    pub fn generateUtf8String(self: *FuzzGenerator, buf: []u8) []const u8 {
        const rand = self.random();
        const snippets = [_][]const u8{
            "Notepad++", "Scintilla", "Editor", "Line: 42",
            "Español ñ á é í ó ú", "日本語 テキスト", "中文 文本 简体",
            "Русский текст", "Emoji 🚀 💻 🦀 ✨",
            "Path/with/symbols!@#$%^&*()",
            "\t\r\n", "zero\x00term",
        };

        var pos: usize = 0;
        const count = rand.uintAtMost(usize, 3) + 1;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const snip = snippets[rand.uintLessThan(usize, snippets.len)];
            if (pos + snip.len < buf.len) {
                @memcpy(buf[pos .. pos + snip.len], snip);
                pos += snip.len;
            }
            if (i + 1 < count and pos + 3 < buf.len) {
                @memcpy(buf[pos .. pos + 3], " - ");
                pos += 3;
            }
        }

        return buf[0..pos];
    }
};