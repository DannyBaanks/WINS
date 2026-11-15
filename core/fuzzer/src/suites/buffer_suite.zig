//! WINS Differential Fuzzer - Scintilla Text Buffer Navigation Suite
//! Validates line indexing, byte-to-line/column mapping, and mixed EOL handling
//! between Scintilla reference model (used in Notepad++) and candidate Linux editors.

const std = @import("std");
const generator = @import("../generator.zig");
const FuzzGenerator = generator.FuzzGenerator;

pub const BufferSuiteResult = struct {
    total_iterations: u64,
    divergences: u64,
    lines_indexed: u64 = 0,
    multibyte_queries: u64 = 0,
};

pub const LineSpan = struct {
    start: usize,
    end: usize, // Excludes \r and \n
    eol_len: usize,
};

/// Reference Scintilla Character Scanner Model
pub const ReferenceScintillaBuffer = struct {
    lines: [128]LineSpan = undefined,
    line_count: usize = 0,

    pub fn indexDocument(self: *ReferenceScintillaBuffer, doc: []const u8) void {
        self.line_count = 0;
        var start: usize = 0;
        var i: usize = 0;

        while (i < doc.len and self.line_count < self.lines.len) {
            const b = doc[i];
            if (b == '\r') {
                const line_end = i;
                var eol_len: usize = 1;
                if (i + 1 < doc.len and doc[i + 1] == '\n') {
                    eol_len = 2;
                    i += 1;
                }
                self.lines[self.line_count] = .{
                    .start = start,
                    .end = line_end,
                    .eol_len = eol_len,
                };
                self.line_count += 1;
                i += 1;
                start = i;
            } else if (b == '\n') {
                self.lines[self.line_count] = .{
                    .start = start,
                    .end = i,
                    .eol_len = 1,
                };
                self.line_count += 1;
                i += 1;
                start = i;
            } else {
                i += 1;
            }
        }

        // Final line without newline
        if (start <= doc.len and self.line_count < self.lines.len) {
            self.lines[self.line_count] = .{
                .start = start,
                .end = doc.len,
                .eol_len = 0,
            };
            self.line_count += 1;
        }
    }

    pub fn lineFromOffset(self: *const ReferenceScintillaBuffer, offset: usize) usize {
        if (self.line_count == 0) return 0;
        var l: usize = 0;
        while (l < self.line_count) : (l += 1) {
            const span = self.lines[l];
            const full_end = span.end + span.eol_len;
            if (offset >= span.start and offset < full_end) {
                return l;
            }
        }
        return self.line_count - 1;
    }

    pub fn columnFromOffset(self: *const ReferenceScintillaBuffer, doc: []const u8, offset: usize) usize {
        const line_idx = self.lineFromOffset(offset);
        const line_start = self.lines[line_idx].start;
        if (offset <= line_start) return 0;

        // Count Unicode code points (characters) rather than raw bytes
        var col: usize = 0;
        var pos = line_start;
        const target = @min(offset, doc.len);

        while (pos < target) {
            const byte = doc[pos];
            // UTF-8 leading byte detection
            if ((byte & 0x80) == 0) {
                if (byte == '\t') {
                    col += 4 - (col % 4); // Standard 4-space tab stop
                } else {
                    col += 1;
                }
                pos += 1;
            } else if ((byte & 0xE0) == 0xC0) {
                col += 1;
                pos += @min(2, target - pos);
            } else if ((byte & 0xF0) == 0xE0) {
                col += 1;
                pos += @min(3, target - pos);
            } else if ((byte & 0xF8) == 0xF0) {
                col += 1;
                pos += @min(4, target - pos);
            } else {
                col += 1;
                pos += 1;
            }
        }
        return col;
    }
};

/// Candidate Linux Fast Line Indexer
pub const CandidateLinuxBuffer = struct {
    line_starts: [128]usize = undefined,
    line_ends: [128]usize = undefined,
    line_count: usize = 0,

    pub fn indexDocument(self: *CandidateLinuxBuffer, doc: []const u8) void {
        self.line_count = 0;
        var start: usize = 0;
        self.line_starts[0] = 0;

        var i: usize = 0;
        while (i < doc.len and self.line_count + 1 < self.line_starts.len) : (i += 1) {
            const b = doc[i];
            if (b == '\r') {
                self.line_ends[self.line_count] = i;
                self.line_count += 1;
                if (i + 1 < doc.len and doc[i + 1] == '\n') {
                    i += 1;
                }
                start = i + 1;
                self.line_starts[self.line_count] = start;
            } else if (b == '\n') {
                self.line_ends[self.line_count] = i;
                self.line_count += 1;
                start = i + 1;
                self.line_starts[self.line_count] = start;
            }
        }

        if (self.line_count < self.line_starts.len) {
            self.line_ends[self.line_count] = doc.len;
            self.line_count += 1;
        }
    }

    /// Binary search line from byte offset
    pub fn lineFromOffset(self: *const CandidateLinuxBuffer, offset: usize) usize {
        if (self.line_count <= 1) return 0;
        var low: usize = 0;
        var high: usize = self.line_count;

        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.line_starts[mid] <= offset) {
                if (mid + 1 == self.line_count or self.line_starts[mid + 1] > offset) {
                    return mid;
                }
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return self.line_count - 1;
    }

    pub fn columnFromOffset(self: *const CandidateLinuxBuffer, doc: []const u8, offset: usize) usize {
        const line_idx = self.lineFromOffset(offset);
        const line_start = self.line_starts[line_idx];
        if (offset <= line_start) return 0;

        var col: usize = 0;
        var pos = line_start;
        const target = @min(offset, doc.len);

        while (pos < target) {
            const byte = doc[pos];
            if ((byte & 0x80) == 0) {
                if (byte == '\t') {
                    col += 4 - (col % 4);
                } else {
                    col += 1;
                }
                pos += 1;
            } else if ((byte & 0xE0) == 0xC0) {
                col += 1;
                pos += @min(2, target - pos);
            } else if ((byte & 0xF0) == 0xE0) {
                col += 1;
                pos += @min(3, target - pos);
            } else if ((byte & 0xF8) == 0xF0) {
                col += 1;
                pos += @min(4, target - pos);
            } else {
                col += 1;
                pos += 1;
            }
        }
        return col;
    }
};

pub fn run(iterations: u64, seed: u64) BufferSuiteResult {
    var gen = FuzzGenerator.init(seed);
    const rand = gen.random();
    var res = BufferSuiteResult{
        .total_iterations = iterations,
        .divergences = 0,
    };

    var doc_buf: [2048]u8 = undefined;
    var ref_buf = ReferenceScintillaBuffer{};
    var cand_buf = CandidateLinuxBuffer{};

    var iter: u64 = 0;
    while (iter < iterations) : (iter += 1) {
        const doc = gen.generateTextBuffer(&doc_buf);
        if (doc.len == 0) continue;

        ref_buf.indexDocument(doc);
        cand_buf.indexDocument(doc);

        res.lines_indexed += ref_buf.line_count;

        // Differential 1: Line counts must match exactly
        if (ref_buf.line_count != cand_buf.line_count) {
            res.divergences += 1;
            continue;
        }

        // Differential 2: Sample random offsets across document
        const queries = rand.uintLessThan(u8, 5) + 1;
        var q: usize = 0;
        while (q < queries) : (q += 1) {
            const offset = rand.uintLessThan(usize, doc.len + 1);

            const ref_line = ref_buf.lineFromOffset(offset);
            const cand_line = cand_buf.lineFromOffset(offset);

            if (ref_line != cand_line) {
                res.divergences += 1;
            }

            const ref_col = ref_buf.columnFromOffset(doc, offset);
            const cand_col = cand_buf.columnFromOffset(doc, offset);

            if (ref_col != cand_col) {
                res.divergences += 1;
            }

            // Track multibyte checks
            if (offset < doc.len and (doc[offset] & 0x80) != 0) {
                res.multibyte_queries += 1;
            }
        }
    }

    return res;
}
