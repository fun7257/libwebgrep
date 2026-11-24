//! [Module] codec/encoding.zig
//! [Layer] Layer 3 — Stream Codec & Character Transcoding
//! [Role] Leading BOM sniffing, WHATWG/HTTP charset resolution, and streaming/slice transcoding
//!        for UTF-8, UTF-16LE, UTF-16BE, GBK (CP936), and ISO-8859-1 (Latin-1) into searchable UTF-8.
//! [Invariants]
//!   1. Without a leading BOM or explicit caller encoding/charset hint, raw bytes pass through untouched.
//!   2. Ill-formed sequences in decoded modes map deterministically to U+FFFD (`\xEF\xBF\xBD`).
//! [HotPath] `convertIntoMode`, `convertedLenMode`, `Decoder.decodeInto`, and `encodeCp`.

const std = @import("std");
const unicode = std.unicode;
const decompress = @import("decompress.zig");
const gbk_table = @import("../tables/gbk_table.zig");
const legacy_tables = @import("../tables/legacy_encodings.zig");
const memchr = @import("../finder/memchr.zig");

pub const Encoding = enum {
    /// Only sniff for a BOM at the start of the stream (if no BOM is present, transcode using the `charset` hint if given, otherwise search raw bytes).
    auto,
    /// Do not sniff or transcode. Invalid bytes enter matching as-is.
    none,
    /// Process as UTF-8 (strip leading BOM, replace invalid bytes with U+FFFD).
    utf8,
    /// Transcode from UTF-16LE to UTF-8.
    utf16le,
    /// Transcode from UTF-16BE to UTF-8.
    utf16be,
    /// Transcode from GBK / GB2312 / CP936 to UTF-8.
    gbk,
    /// Transcode from ISO-8859-1 / Latin-1 to UTF-8.
    latin1,
    /// Transcode from exact Windows-1252 / CP1252 (with 0x80..0x9F punctuation/Euro) to UTF-8.
    windows1252,
    /// Transcode from full GB18030 (2-byte + 4-byte BMP & supplementary) to UTF-8.
    gb18030,
    /// Transcode from Shift_JIS / CP932 to UTF-8.
    shift_jis,
    /// Transcode from EUC-JP (JIS X 0208 + halfwidth katakana) to UTF-8.
    euc_jp,
    /// Transcode from Big5 / CP950 to UTF-8.
    big5,
    /// Transcode from EUC-KR / CP949 to UTF-8.
    euc_kr,
    /// Transcode from Windows-1251 / CP1251 (Cyrillic) to UTF-8.
    windows1251,
    /// Transcode from UTF-32LE to UTF-8.
    utf32le,
    /// Transcode from UTF-32BE to UTF-8.
    utf32be,
    /// Heuristic auto-detection when no BOM or explicit `charset` hint is present.
    detect,
};

pub const Sniff = enum {
    need_more,
    raw,
    utf8,
    utf16le,
    utf16be,
    gbk,
    latin1,
    windows1252,
    gb18030,
    shift_jis,
    euc_jp,
    big5,
    euc_kr,
    windows1251,
    utf32le,
    utf32be,
};

const coded_mode = enum {
    utf8,
    utf16le,
    utf16be,
    gbk,
    latin1,
    windows1252,
    gb18030,
    shift_jis,
    euc_jp,
    big5,
    euc_kr,
    windows1251,
    utf32le,
    utf32be,
};

const Step = struct {
    n: usize,
    cp: u21,
};

pub const Utf16Span = struct {
    start: usize,
    end: usize,
};

pub const Pull = struct {
    n: usize,
    eof: bool,
};

/// Inspects only the beginning of the stream. When `eof` is true, an incomplete BOM prefix is treated as raw bytes.
pub fn sniff(bytes: []const u8, eof: bool) Sniff {
    if (bytes.len >= 4 and bytes[0] == 0xff and bytes[1] == 0xfe and bytes[2] == 0x00 and bytes[3] == 0x00) return .utf32le;
    if (bytes.len >= 4 and bytes[0] == 0x00 and bytes[1] == 0x00 and bytes[2] == 0xfe and bytes[3] == 0xff) return .utf32be;
    if (bytes.len >= 3 and std.mem.eql(u8, bytes[0..3], "\xef\xbb\xbf")) return .utf8;
    if (bytes.len >= 2 and bytes[0] == 0xff and bytes[1] == 0xfe) {
        if (!eof and (bytes.len == 2 or (bytes.len == 3 and bytes[2] == 0x00))) return .need_more;
        return .utf16le;
    }
    if (bytes.len >= 2 and bytes[0] == 0xfe and bytes[1] == 0xff) return .utf16be;
    if (eof or bytes.len >= 4) return .raw;
    if (bytes.len == 0) return .need_more;
    if (bytes.len == 1) {
        return switch (bytes[0]) {
            0xef, 0xff, 0xfe, 0x00 => .need_more,
            else => .raw,
        };
    }
    if (bytes[0] == 0xef and bytes[1] == 0xbb) return .need_more;
    if (bytes[0] == 0x00 and bytes[1] == 0x00 and (bytes.len == 2 or bytes[2] == 0xfe)) return .need_more;
    return .raw;
}

/// Parse a WHATWG charset label or HTTP Content-Type header (such as `text/plain; charset=gbk`) into an `Encoding`.
pub fn fromCharset(label_or_header: []const u8) ?Encoding {
    var token = label_or_header;
    if (std.ascii.findIgnoreCase(token, "charset=")) |idx| {
        token = token[idx + "charset=".len ..];
        if (std.mem.findAny(u8, token, "; \t\r\n")) |end| {
            token = token[0..end];
        }
    }
    token = std.mem.trim(u8, token, " \t\r\n\"'");
    if (token.len == 0) return null;

    if (std.ascii.eqlIgnoreCase(token, "utf-8") or std.ascii.eqlIgnoreCase(token, "utf8")) return .utf8;
    if (std.ascii.eqlIgnoreCase(token, "utf-16le") or std.ascii.eqlIgnoreCase(token, "utf16le") or std.ascii.eqlIgnoreCase(token, "utf-16")) return .utf16le;
    if (std.ascii.eqlIgnoreCase(token, "utf-16be") or std.ascii.eqlIgnoreCase(token, "utf16be")) return .utf16be;
    if (std.ascii.eqlIgnoreCase(token, "utf-32le") or std.ascii.eqlIgnoreCase(token, "utf32le") or std.ascii.eqlIgnoreCase(token, "utf-32") or std.ascii.eqlIgnoreCase(token, "utf32")) return .utf32le;
    if (std.ascii.eqlIgnoreCase(token, "utf-32be") or std.ascii.eqlIgnoreCase(token, "utf32be")) return .utf32be;
    if (std.ascii.eqlIgnoreCase(token, "gb18030")) return .gb18030;
    if (std.ascii.eqlIgnoreCase(token, "gbk") or
        std.ascii.eqlIgnoreCase(token, "gb2312") or
        std.ascii.eqlIgnoreCase(token, "gb_2312") or
        std.ascii.eqlIgnoreCase(token, "cp936") or
        std.ascii.eqlIgnoreCase(token, "ms936") or
        std.ascii.eqlIgnoreCase(token, "windows-936") or
        std.ascii.eqlIgnoreCase(token, "chinese") or
        std.ascii.eqlIgnoreCase(token, "csgb2312")) return .gbk;
    if (std.ascii.eqlIgnoreCase(token, "windows-1252") or
        std.ascii.eqlIgnoreCase(token, "cp1252") or
        std.ascii.eqlIgnoreCase(token, "x-cp1252")) return .windows1252;
    if (std.ascii.eqlIgnoreCase(token, "iso-8859-1") or
        std.ascii.eqlIgnoreCase(token, "iso8859-1") or
        std.ascii.eqlIgnoreCase(token, "latin1") or
        std.ascii.eqlIgnoreCase(token, "latin-1")) return .latin1;
    if (std.ascii.eqlIgnoreCase(token, "shift_jis") or
        std.ascii.eqlIgnoreCase(token, "shift-jis") or
        std.ascii.eqlIgnoreCase(token, "sjis") or
        std.ascii.eqlIgnoreCase(token, "cp932") or
        std.ascii.eqlIgnoreCase(token, "ms932") or
        std.ascii.eqlIgnoreCase(token, "windows-31j")) return .shift_jis;
    if (std.ascii.eqlIgnoreCase(token, "euc-jp") or std.ascii.eqlIgnoreCase(token, "eucjp")) return .euc_jp;
    if (std.ascii.eqlIgnoreCase(token, "big5") or std.ascii.eqlIgnoreCase(token, "big5-hkscs") or std.ascii.eqlIgnoreCase(token, "cp950")) return .big5;
    if (std.ascii.eqlIgnoreCase(token, "euc-kr") or std.ascii.eqlIgnoreCase(token, "euckr") or std.ascii.eqlIgnoreCase(token, "cp949") or std.ascii.eqlIgnoreCase(token, "ks_c_5601-1987")) return .euc_kr;
    if (std.ascii.eqlIgnoreCase(token, "windows-1251") or std.ascii.eqlIgnoreCase(token, "cp1251") or std.ascii.eqlIgnoreCase(token, "x-cp1251")) return .windows1251;
    return null;
}

/// Heuristic character encoding detector for BOM-less, hint-less text samples (inspects up to 8 KiB).
pub fn detectEncoding(sample: []const u8) Encoding {
    if (sample.len == 0) return .utf8;
    switch (sniff(sample, true)) {
        .utf8 => return .utf8,
        .utf32le => return .utf32le,
        .utf32be => return .utf32be,
        .utf16le => return .utf16le,
        .utf16be => return .utf16be,
        else => {},
    }

    const head = sample[0..@min(sample.len, 8192)];

    // Check UTF-32LE / UTF-32BE null-byte cadence
    if (head.len >= 8 and (head.len % 4) == 0) {
        var le32_hits: usize = 0;
        var be32_hits: usize = 0;
        var i: usize = 0;
        while (i + 4 <= head.len) : (i += 4) {
            if (head[i] > 0 and head[i] < 0x80 and head[i + 1] == 0 and head[i + 2] == 0 and head[i + 3] == 0) le32_hits += 1;
            if (head[i] == 0 and head[i + 1] == 0 and head[i + 2] == 0 and head[i + 3] > 0 and head[i + 3] < 0x80) be32_hits += 1;
        }
        const units = head.len / 4;
        if (le32_hits * 2 >= units and le32_hits >= 2) return .utf32le;
        if (be32_hits * 2 >= units and be32_hits >= 2) return .utf32be;
    }

    // Check UTF-16LE / UTF-16BE null-byte cadence
    if (head.len >= 4 and (head.len % 2) == 0) {
        var le16_hits: usize = 0;
        var be16_hits: usize = 0;
        var i: usize = 0;
        while (i + 2 <= head.len) : (i += 2) {
            if (head[i] > 0 and head[i] < 0x80 and head[i + 1] == 0) le16_hits += 1;
            if (head[i] == 0 and head[i + 1] > 0 and head[i + 1] < 0x80) be16_hits += 1;
        }
        const units = head.len / 2;
        if (le16_hits * 2 >= units and le16_hits >= 2) return .utf16le;
        if (be16_hits * 2 >= units and be16_hits >= 2) return .utf16be;
    }

    if (isAsciiSlice(head) or validUtf8(head)) return .utf8;

    // Score multi-byte legacy CJK encodings
    const candidates = [_]struct { enc: Encoding, mode: coded_mode }{
        .{ .enc = .gb18030, .mode = .gb18030 },
        .{ .enc = .shift_jis, .mode = .shift_jis },
        .{ .enc = .euc_jp, .mode = .euc_jp },
        .{ .enc = .big5, .mode = .big5 },
        .{ .enc = .euc_kr, .mode = .euc_kr },
    };
    var best_enc: ?Encoding = null;
    var best_score: i64 = 0;
    for (candidates) |cand| {
        var i: usize = 0;
        var valid_mb: i64 = 0;
        var bad: i64 = 0;
        var script_bonus: i64 = 0;
        while (i < head.len) {
            const st = decodeMode(cand.mode, head[i..], true) orelse break;
            if (st.cp == unicode.replacement_character) {
                bad += 1;
            } else if (st.n >= 2) {
                valid_mb += 1;
                if (cand.enc == .shift_jis or cand.enc == .euc_jp) {
                    if ((st.cp >= 0x3040 and st.cp <= 0x30FF) or (st.cp >= 0xFF61 and st.cp <= 0xFF9F)) script_bonus += 4;
                } else if (cand.enc == .euc_kr) {
                    if (st.cp >= 0xAC00 and st.cp <= 0xD7A3) script_bonus += 4;
                } else if (cand.enc == .gb18030 and st.n == 4) {
                    script_bonus += 6;
                }
            }
            i += st.n;
        }
        if (valid_mb >= 1 and bad == 0) {
            const score = valid_mb * 4 + script_bonus;
            if (score > best_score) {
                best_score = score;
                best_enc = cand.enc;
            }
        }
    }
    if (best_enc) |enc| return enc;

    // Single-byte high-bit heuristic: Windows-1251 (Cyrillic 0xC0..0xFF) vs Windows-1252
    var high_total: usize = 0;
    var cyr_lower: usize = 0;
    var mid_80_bf: usize = 0;
    for (head) |b| {
        if (b >= 0x80) {
            high_total += 1;
            if (b >= 0xE0) cyr_lower += 1;
            if (b >= 0x80 and b <= 0xBF) mid_80_bf += 1;
        }
    }
    if (high_total >= 4 and cyr_lower * 2 >= high_total and mid_80_bf * 5 <= high_total) {
        return .windows1251;
    }
    return .windows1252;
}

pub fn resolveHint(encoding: Encoding, charset: ?[]const u8) Encoding {
    if (encoding != .auto) return encoding;
    if (charset) |hint| {
        if (fromCharset(hint)) |enc| return enc;
    }
    return .auto;
}

inline fn firstNonAscii(bytes: []const u8) ?usize {
    const V = @Vector(memchr.native_width, u8);
    const msb: V = @splat(0x80);
    const zero: V = @splat(0);
    var i: usize = 0;
    while (i + memchr.native_width <= bytes.len) : (i += memchr.native_width) {
        const v: V = bytes[i..][0..memchr.native_width].*;
        if (@reduce(.Or, (v & msb) != zero)) return i;
    }
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] >= 0x80) return i;
    }
    return null;
}

pub inline fn isAsciiSlice(bytes: []const u8) bool {
    return firstNonAscii(bytes) == null;
}

pub fn validUtf8(bytes: []const u8) bool {
    const off = firstNonAscii(bytes) orelse return true;
    return unicode.utf8ValidateSlice(bytes[off..]);
}

pub fn lossyLen(bytes: []const u8) usize {
    return convertedLen(.utf8, bytes);
}

pub fn writeLossy(bytes: []const u8, out: []u8) usize {
    return convertInto(.utf8, bytes, out);
}

/// `start` and `end` are byte offsets in the raw slice. The returned span is measured in UTF-16 code units on the lossy UTF-8 text.
pub fn utf16Span(bytes: []const u8, start: usize, end: usize) Utf16Span {
    const from = @min(start, bytes.len);
    const to = @min(@max(end, from), bytes.len);
    if (prefixAscii(bytes, to)) return .{ .start = from, .end = to };

    var i: usize = 0;
    var units: usize = 0;
    var u16_start: usize = 0;
    var u16_end: usize = 0;
    var got_start = false;
    var got_end = false;
    while (i < bytes.len and !(got_start and got_end)) {
        const step = decodeUtf8(bytes[i..], true) orelse break;
        const next = i + step.n;
        if (!got_start and from <= i) {
            u16_start = units;
            got_start = true;
        } else if (!got_start and from < next) {
            u16_start = units + convertedUnits(.utf8, bytes[i..from]);
            got_start = true;
        }
        if (!got_end and to <= i) {
            u16_end = units;
            got_end = true;
        } else if (!got_end and to < next) {
            u16_end = units + convertedUnits(.utf8, bytes[i..to]);
            got_end = true;
        }
        units += unitsOf(step.cp);
        i = next;
    }
    if (!got_start) u16_start = units + if (from > i) convertedUnits(.utf8, bytes[i..from]) else 0;
    if (!got_end) u16_end = units + if (to > i) convertedUnits(.utf8, bytes[i..to]) else 0;
    return .{ .start = u16_start, .end = u16_end };
}

pub fn sniffToCodedMode(kind: Sniff) ?coded_mode {
    return switch (kind) {
        .utf8 => .utf8,
        .utf16le => .utf16le,
        .utf16be => .utf16be,
        .gbk => .gbk,
        .latin1 => .latin1,
        .windows1252 => .windows1252,
        .gb18030 => .gb18030,
        .shift_jis => .shift_jis,
        .euc_jp => .euc_jp,
        .big5 => .big5,
        .euc_kr => .euc_kr,
        .windows1251 => .windows1251,
        .utf32le => .utf32le,
        .utf32be => .utf32be,
        .raw, .need_more => null,
    };
}

pub fn encodingToSniff(enc: Encoding) Sniff {
    return switch (enc) {
        .auto, .none, .detect => .raw,
        .utf8 => .utf8,
        .utf16le => .utf16le,
        .utf16be => .utf16be,
        .gbk => .gbk,
        .latin1 => .latin1,
        .windows1252 => .windows1252,
        .gb18030 => .gb18030,
        .shift_jis => .shift_jis,
        .euc_jp => .euc_jp,
        .big5 => .big5,
        .euc_kr => .euc_kr,
        .windows1251 => .windows1251,
        .utf32le => .utf32le,
        .utf32be => .utf32be,
    };
}

/// Byte length after transcoding into searchable bytes. Returns `input.len` unchanged for raw bytes.
pub fn decodedSize(kind: Sniff, input: []const u8) usize {
    const mode = sniffToCodedMode(kind) orelse return input.len;
    return convertedLen(mode, input);
}

pub fn convertAlloc(allocator: std.mem.Allocator, kind: Sniff, input: []const u8) error{OutOfMemory}![]u8 {
    return convertAllocWithMap(allocator, kind, input, 0, null);
}

pub fn convertAllocWithMap(
    allocator: std.mem.Allocator,
    kind: Sniff,
    input: []const u8,
    raw_base: u64,
    offset_map: ?*decompress.OffsetMap,
) error{OutOfMemory}![]u8 {
    const mode = sniffToCodedMode(kind) orelse return allocator.dupe(u8, input);
    const len = convertedLen(mode, input);
    return convertAllocWithMapKnownLen(allocator, kind, input, raw_base, offset_map, len);
}

pub fn convertAllocWithMapKnownLen(
    allocator: std.mem.Allocator,
    kind: Sniff,
    input: []const u8,
    raw_base: u64,
    offset_map: ?*decompress.OffsetMap,
    len: usize,
) error{OutOfMemory}![]u8 {
    const mode = sniffToCodedMode(kind) orelse return allocator.dupe(u8, input);
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    const n = try convertIntoWithMap(allocator, mode, input, buf, raw_base, offset_map);
    std.debug.assert(n == len);
    return buf;
}

pub fn convertScratchWithMapKnownLen(
    buf_alloc: std.mem.Allocator,
    decode_buf: *[]u8,
    map_alloc: std.mem.Allocator,
    kind: Sniff,
    input: []const u8,
    raw_base: u64,
    offset_map: ?*decompress.OffsetMap,
    len: usize,
) error{OutOfMemory}![]u8 {
    const mode = sniffToCodedMode(kind) orelse {
        if (decode_buf.len < input.len) {
            if (decode_buf.len == 0) {
                decode_buf.* = try buf_alloc.alloc(u8, input.len);
            } else {
                decode_buf.* = try buf_alloc.realloc(decode_buf.*, input.len);
            }
        }
        if (input.len > 0) @memcpy(decode_buf.*[0..input.len], input);
        return decode_buf.*[0..input.len];
    };
    if (decode_buf.len < len) {
        if (decode_buf.len == 0) {
            decode_buf.* = try buf_alloc.alloc(u8, len);
        } else {
            decode_buf.* = try buf_alloc.realloc(decode_buf.*, len);
        }
    }
    const n = try convertIntoWithMap(map_alloc, mode, input, decode_buf.*[0..len], raw_base, offset_map);
    std.debug.assert(n == len);
    return decode_buf.*[0..len];
}

/// Converts upstream bytes into searchable bytes.
/// When `encoding == .none` or no BOM is present, the first read length matches reading directly into `dest`.
pub const Decoder = struct {
    mode: Mode = .undecided,
    fallback_mode: Mode = .raw,
    in_len: usize = 0,
    in_i: usize = 0,
    out_hold: [4]u8 = undefined,
    out_len: usize = 0,
    out_i: usize = 0,
    raw_buf: []u8 = &.{},
    saw_eof: bool = false,
    /// Byte limit for the decode input buffer. Returns `DecodeLimit` instead of growing past this cap.
    max_in: usize = std.math.maxInt(usize),
    raw_consumed: u64 = 0,
    out_produced: u64 = 0,
    offset_map: ?*decompress.OffsetMap = null,

    const Mode = enum {
        undecided,
        raw,
        detect,
        utf8,
        utf16le,
        utf16be,
        gbk,
        latin1,
        windows1252,
        gb18030,
        shift_jis,
        euc_jp,
        big5,
        euc_kr,
        windows1251,
        utf32le,
        utf32be,
    };

    pub fn init(encoding: Encoding) Decoder {
        return initWithHint(encoding, null);
    }

    pub fn initWithHint(encoding: Encoding, charset: ?[]const u8) Decoder {
        const resolved = resolveHint(encoding, charset);
        return switch (resolved) {
            .none => .{ .mode = .raw, .fallback_mode = .raw },
            .auto => .{ .mode = .undecided, .fallback_mode = .raw },
            .detect => .{ .mode = .undecided, .fallback_mode = .detect },
            .utf8 => .{ .mode = .undecided, .fallback_mode = .utf8 },
            .utf16le => .{ .mode = .undecided, .fallback_mode = .utf16le },
            .utf16be => .{ .mode = .undecided, .fallback_mode = .utf16be },
            .gbk => .{ .mode = .undecided, .fallback_mode = .gbk },
            .latin1 => .{ .mode = .undecided, .fallback_mode = .latin1 },
            .windows1252 => .{ .mode = .undecided, .fallback_mode = .windows1252 },
            .gb18030 => .{ .mode = .undecided, .fallback_mode = .gb18030 },
            .shift_jis => .{ .mode = .undecided, .fallback_mode = .shift_jis },
            .euc_jp => .{ .mode = .undecided, .fallback_mode = .euc_jp },
            .big5 => .{ .mode = .undecided, .fallback_mode = .big5 },
            .euc_kr => .{ .mode = .undecided, .fallback_mode = .euc_kr },
            .windows1251 => .{ .mode = .undecided, .fallback_mode = .windows1251 },
            .utf32le => .{ .mode = .undecided, .fallback_mode = .utf32le },
            .utf32be => .{ .mode = .undecided, .fallback_mode = .utf32be },
        };
    }

    pub fn deinit(self: *Decoder, allocator: std.mem.Allocator) void {
        if (self.raw_buf.len != 0) allocator.free(self.raw_buf);
        self.* = .{};
    }

    pub fn pull(
        self: *Decoder,
        allocator: std.mem.Allocator,
        comptime readFn: anytype,
        read_ctx: *anyopaque,
        raw_cap: usize,
        dest: []u8,
        bytes_read: *u64,
    ) PullError(readFn)!Pull {
        if (dest.len == 0) return .{ .n = 0, .eof = false };
        if (self.mode == .raw) {
            var filled: usize = 0;
            if (self.out_i < self.out_len or self.in_i < self.in_len) {
                filled = self.drainOut(dest);
                if (filled < dest.len) {
                    const more = self.emitPending(dest[filled..], self.saw_eof);
                    filled += more.n;
                }
                if (filled == dest.len or (self.saw_eof and !self.hasPending())) {
                    return .{ .n = filled, .eof = self.saw_eof and !self.hasPending() };
                }
            }
            const n = try readFn(read_ctx, dest[filled..]);
            bytes_read.* += n;
            if (n == 0) self.saw_eof = true;
            return .{ .n = filled + n, .eof = n == 0 and !self.hasPending() };
        }
        if (self.mode == .undecided) {
            return self.pullUndecided(allocator, readFn, read_ctx, raw_cap, dest, bytes_read);
        }
        return self.pullCoded(allocator, readFn, read_ctx, raw_cap, dest, bytes_read);
    }

    fn hasPending(self: *const Decoder) bool {
        return self.in_i < self.in_len or self.out_i < self.out_len;
    }

    fn pullUndecided(
        self: *Decoder,
        allocator: std.mem.Allocator,
        comptime readFn: anytype,
        read_ctx: *anyopaque,
        raw_cap: usize,
        dest: []u8,
        bytes_read: *u64,
    ) PullError(readFn)!Pull {
        if (self.fallback_mode == .detect) {
            var tmp: [1024]u8 = undefined;
            const pending_len = self.in_len - self.in_i;
            const remain = if (pending_len < tmp.len) tmp.len - pending_len else 0;
            if (remain > 0 and !self.saw_eof) {
                const want = @min(remain, @max(raw_cap, 1));
                const n = try readFn(read_ctx, tmp[0..want]);
                bytes_read.* += n;
                if (n == 0) {
                    self.saw_eof = true;
                } else {
                    try self.appendIn(allocator, tmp[0..n]);
                }
            }
            const cur_len = self.in_len - self.in_i;
            if (!self.saw_eof and cur_len < tmp.len) {
                return .{ .n = 0, .eof = false };
            }
            return self.decide(allocator, dest, self.saw_eof);
        }

        if (self.in_i < self.in_len) {
            var tmp: [4]u8 = undefined;
            const want = @min(tmp.len, @max(raw_cap, 1));
            const n = try readFn(read_ctx, tmp[0..want]);
            bytes_read.* += n;
            if (n == 0) self.saw_eof = true;
            if (n != 0) try self.appendIn(allocator, tmp[0..n]);
            return self.decide(allocator, dest, self.saw_eof);
        }

        const n = try readFn(read_ctx, dest);
        bytes_read.* += n;
        if (n == 0) {
            self.mode = .raw;
            self.saw_eof = true;
            return .{ .n = 0, .eof = true };
        }
        const kind = sniff(dest[0..n], false);
        switch (kind) {
            .need_more => {
                try self.appendIn(allocator, dest[0..n]);
                return .{ .n = 0, .eof = false };
            },
            .raw => {
                if (self.fallback_mode != .raw) {
                    self.mode = self.fallback_mode;
                    self.in_i = 0;
                    self.in_len = 0;
                    try self.appendIn(allocator, dest[0..n]);
                    return self.decodeAvailable(allocator, dest, false);
                }
                self.mode = .raw;
                return .{ .n = n, .eof = false };
            },
            else => {
                const cmode = sniffToCodedMode(kind) orelse .utf8;
                self.mode = codedToMode(cmode);
                const bom = bomLen(cmode);
                self.raw_consumed = bom;
                if (self.offset_map) |m| m.base_raw_offset = bom;
                const payload = if (n >= bom) dest[bom..n] else dest[n..n];
                self.in_i = 0;
                self.in_len = 0;
                if (payload.len != 0) try self.appendIn(allocator, payload);
                return self.decodeAvailable(allocator, dest, false);
            },
        }
    }

    fn decide(self: *Decoder, allocator: std.mem.Allocator, dest: []u8, eof: bool) !Pull {
        const pending = self.raw_buf[self.in_i..self.in_len];
        const kind = sniff(pending, eof);
        switch (kind) {
            .need_more => return .{ .n = 0, .eof = false },
            .raw => {
                if (self.fallback_mode != .raw) {
                    self.mode = if (self.fallback_mode == .detect) encodingToMode(detectEncoding(pending)) else self.fallback_mode;
                    return self.decodeAvailable(allocator, dest, eof);
                }
                self.mode = .raw;
                return self.emitPending(dest, eof);
            },
            else => {
                const cmode = sniffToCodedMode(kind) orelse .utf8;
                self.mode = codedToMode(cmode);
                const bom = bomLen(cmode);
                self.raw_consumed = bom;
                if (self.offset_map) |m| m.base_raw_offset = bom;
                self.in_i += @min(bom, self.in_len - self.in_i);
                return self.decodeAvailable(allocator, dest, eof);
            },
        }
    }

    fn codedToMode(mode: coded_mode) Mode {
        return switch (mode) {
            .utf8 => .utf8,
            .utf16le => .utf16le,
            .utf16be => .utf16be,
            .gbk => .gbk,
            .latin1 => .latin1,
            .windows1252 => .windows1252,
            .gb18030 => .gb18030,
            .shift_jis => .shift_jis,
            .euc_jp => .euc_jp,
            .big5 => .big5,
            .euc_kr => .euc_kr,
            .windows1251 => .windows1251,
            .utf32le => .utf32le,
            .utf32be => .utf32be,
        };
    }

    fn bomLen(mode: coded_mode) usize {
        return switch (mode) {
            .utf8 => 3,
            .utf16le, .utf16be => 2,
            .utf32le, .utf32be => 4,
            else => 0,
        };
    }

    fn encodingToMode(enc: Encoding) Mode {
        return switch (enc) {
            .none, .auto, .detect => .raw,
            .utf8 => .utf8,
            .utf16le => .utf16le,
            .utf16be => .utf16be,
            .gbk => .gbk,
            .latin1 => .latin1,
            .windows1252 => .windows1252,
            .gb18030 => .gb18030,
            .shift_jis => .shift_jis,
            .euc_jp => .euc_jp,
            .big5 => .big5,
            .euc_kr => .euc_kr,
            .windows1251 => .windows1251,
            .utf32le => .utf32le,
            .utf32be => .utf32be,
        };
    }

    fn pullCoded(
        self: *Decoder,
        allocator: std.mem.Allocator,
        comptime readFn: anytype,
        read_ctx: *anyopaque,
        raw_cap: usize,
        dest: []u8,
        bytes_read: *u64,
    ) PullError(readFn)!Pull {
        var filled = self.drainOut(dest);
        if (filled == dest.len) return .{ .n = filled, .eof = false };
        if (!self.saw_eof and self.undecoded() < 4) {
            const n = try self.readRaw(allocator, readFn, read_ctx, raw_cap);
            bytes_read.* += n;
            if (n == 0) self.saw_eof = true;
        }
        filled += try self.decodeInto(allocator, dest[filled..], self.saw_eof);
        const eof = self.saw_eof and !self.hasPending();
        return .{ .n = filled, .eof = eof };
    }

    fn emitPending(self: *Decoder, dest: []u8, eof: bool) Pull {
        const pending = self.raw_buf[self.in_i..self.in_len];
        const n = @min(pending.len, dest.len);
        @memcpy(dest[0..n], pending[0..n]);
        self.in_i += n;
        const done = eof and self.in_i >= self.in_len;
        return .{ .n = n, .eof = done };
    }

    fn decodeAvailable(self: *Decoder, allocator: std.mem.Allocator, dest: []u8, eof: bool) error{OutOfMemory}!Pull {
        const n = try self.decodeInto(allocator, dest, eof);
        const done = eof and !self.hasPending();
        return .{ .n = n, .eof = done };
    }

    fn undecoded(self: *const Decoder) usize {
        return self.in_len - self.in_i;
    }

    fn readRaw(
        self: *Decoder,
        allocator: std.mem.Allocator,
        comptime readFn: anytype,
        read_ctx: *anyopaque,
        raw_cap: usize,
    ) !usize {
        self.compactIn();
        const want = @max(raw_cap, 1);
        if (self.raw_buf.len < want or self.raw_buf.len - self.in_len < @min(want, 4)) {
            const need = @max(self.in_len + want, want + 4);
            const cap = @max(need, if (self.raw_buf.len == 0) need else self.raw_buf.len * 2);
            if (self.raw_buf.len == 0) {
                self.raw_buf = try allocator.alloc(u8, cap);
            } else {
                self.raw_buf = try allocator.realloc(self.raw_buf, cap);
            }
        }
        const avail = self.raw_buf.len - self.in_len;
        const to_read = @min(want, avail);
        const n = try readFn(read_ctx, self.raw_buf[self.in_len..][0..to_read]);
        if (n != 0) {
            if (self.in_len + n > self.max_in) return error.DecodeLimit;
            self.in_len += n;
        }
        return n;
    }

    fn appendIn(self: *Decoder, allocator: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, DecodeLimit }!void {
        if (bytes.len == 0) return;
        self.compactIn();
        const need = self.in_len + bytes.len;
        if (need > self.max_in) return error.DecodeLimit;
        if (self.raw_buf.len < need) {
            const cap = @max(need, if (self.raw_buf.len == 0) need else self.raw_buf.len * 2);
            if (self.raw_buf.len == 0) {
                self.raw_buf = try allocator.alloc(u8, cap);
            } else {
                self.raw_buf = try allocator.realloc(self.raw_buf, cap);
            }
        }
        @memcpy(self.raw_buf[self.in_len..][0..bytes.len], bytes);
        self.in_len += bytes.len;
    }

    fn compactIn(self: *Decoder) void {
        if (self.in_i == 0) return;
        const rest = self.in_len - self.in_i;
        if (rest != 0) @memmove(self.raw_buf[0..rest], self.raw_buf[self.in_i..self.in_len]);
        self.in_len = rest;
        self.in_i = 0;
    }

    fn drainOut(self: *Decoder, dest: []u8) usize {
        const left = self.out_len - self.out_i;
        const n = @min(left, dest.len);
        if (n != 0) @memcpy(dest[0..n], self.out_hold[self.out_i..][0..n]);
        self.out_i += n;
        if (self.out_i >= self.out_len) {
            self.out_i = 0;
            self.out_len = 0;
        }
        return n;
    }

    fn decodeInto(self: *Decoder, allocator: std.mem.Allocator, dest: []u8, eof: bool) error{OutOfMemory}!usize {
        if (self.offset_map) |m| {
            return switch (self.coded()) {
                inline else => |mode| self.decodeIntoModeImpl(mode, true, allocator, dest, eof, m),
            };
        }
        return switch (self.coded()) {
            inline else => |mode| self.decodeIntoModeImpl(mode, false, allocator, dest, eof, undefined),
        };
    }

    fn decodeIntoModeImpl(
        self: *Decoder,
        comptime mode: coded_mode,
        comptime has_map: bool,
        allocator: std.mem.Allocator,
        dest: []u8,
        eof: bool,
        m: if (has_map) *decompress.OffsetMap else void,
    ) error{OutOfMemory}!usize {
        var filled = self.drainOut(dest);
        while (filled < dest.len and self.in_i < self.in_len) {
            const rest = self.raw_buf[self.in_i..self.in_len];
            if (comptime mode == .utf16le) {
                const ascii_units = copyUtf16LeAsciiPrefix(dest[filled..], rest);
                if (ascii_units != 0) {
                    const run_in = ascii_units * 2;
                    if (comptime has_map) {
                        try m.recordRun(allocator, self.out_produced, self.raw_consumed, self.out_produced + ascii_units, self.raw_consumed + run_in);
                    }
                    self.in_i += run_in;
                    self.raw_consumed += run_in;
                    filled += ascii_units;
                    self.out_produced += ascii_units;
                    continue;
                }
                // Tight inline BMP non-ASCII loop (avoids re-entering SIMD or calling utf8Encode per char)
                var si: usize = 0;
                var di: usize = filled;
                const run_out_start = self.out_produced;
                const run_raw_start = self.raw_consumed;
                while (si + 2 <= rest.len and di + 3 <= dest.len) {
                    const u = std.mem.readInt(u16, rest[si..][0..2], .little);
                    if (u < 0x80) break;
                    if (u >= 0x0800) {
                        if (u >= 0xD800 and u <= 0xDFFF) break;
                        dest[di] = @intCast(0xE0 | (u >> 12));
                        dest[di + 1] = @intCast(0x80 | ((u >> 6) & 0x3F));
                        dest[di + 2] = @intCast(0x80 | (u & 0x3F));
                        si += 2;
                        di += 3;
                    } else {
                        if (comptime has_map) break;
                        dest[di] = @intCast(0xC0 | (u >> 6));
                        dest[di + 1] = @intCast(0x80 | (u & 0x3F));
                        si += 2;
                        di += 2;
                    }
                }
                if (si != 0) {
                    const run_out = di - filled;
                    if (comptime has_map) {
                        try m.recordRun(allocator, run_out_start, run_raw_start, run_out_start + run_out, run_raw_start + si);
                    }
                    self.in_i += si;
                    self.raw_consumed += si;
                    filled = di;
                    self.out_produced += run_out;
                    continue;
                }
            } else if (comptime mode == .gbk and !has_map) {
                const fast = decodeGbkFastNoMap(rest, dest[filled..]);
                if (fast.in_n != 0) {
                    self.in_i += fast.in_n;
                    self.raw_consumed += fast.in_n;
                    filled += fast.out_n;
                    self.out_produced += fast.out_n;
                    if (filled >= dest.len or self.in_i >= self.in_len) break;
                }
            } else if (comptime isAsciiCompatible(mode)) {
                const ascii_run = copyAsciiPrefix(dest[filled..], rest);
                if (ascii_run != 0) {
                    if (comptime has_map) {
                        try m.recordRun(allocator, self.out_produced, self.raw_consumed, self.out_produced + ascii_run, self.raw_consumed + ascii_run);
                    }
                    self.in_i += ascii_run;
                    self.raw_consumed += ascii_run;
                    filled += ascii_run;
                    self.out_produced += ascii_run;
                    continue;
                }
                if (comptime mode == .gbk) {
                    var si: usize = 0;
                    var di: usize = filled;
                    const run_out_start = self.out_produced;
                    const run_raw_start = self.raw_consumed;
                    while (si + 2 <= rest.len and di + 3 <= dest.len) {
                        const lead = rest[si] -% 0x81;
                        if (lead >= 0x7E) break;
                        const enc = gbk_table.utf8_direct[(@as(usize, lead) << 8) | rest[si + 1]];
                        if ((enc >> 24) != 3) break;
                        dest[di] = @truncate(enc);
                        dest[di + 1] = @truncate(enc >> 8);
                        dest[di + 2] = @truncate(enc >> 16);
                        di += 3;
                        si += 2;
                    }
                    if (si != 0) {
                        const run_out = di - filled;
                        if (comptime has_map) {
                            try m.recordRun(allocator, run_out_start, run_raw_start, run_out_start + run_out, run_raw_start + si);
                        }
                        self.in_i += si;
                        self.raw_consumed += si;
                        filled = di;
                        self.out_produced += run_out;
                        continue;
                    }
                }
            }
            const step = decodeModeComptime(mode, self.raw_buf[self.in_i..self.in_len], eof) orelse break;
            if (comptime has_map) {
                try m.record(allocator, self.out_produced, self.raw_consumed);
            }
            self.in_i += step.n;
            self.raw_consumed += step.n;
            if (dest.len - filled >= 4) {
                const n_out = encodeCp(step.cp, dest[filled..]);
                filled += n_out;
                self.out_produced += n_out;
            } else {
                self.queueCp(step.cp);
                self.out_produced += self.out_len;
                filled += self.drainOut(dest[filled..]);
            }
            if (comptime has_map) {
                try m.record(allocator, self.out_produced, self.raw_consumed);
            }
        }
        return filled;
    }

    fn coded(self: *const Decoder) coded_mode {
        return switch (self.mode) {
            .utf16le => .utf16le,
            .utf16be => .utf16be,
            .gbk => .gbk,
            .latin1 => .latin1,
            .windows1252 => .windows1252,
            .gb18030 => .gb18030,
            .shift_jis => .shift_jis,
            .euc_jp => .euc_jp,
            .big5 => .big5,
            .euc_kr => .euc_kr,
            .windows1251 => .windows1251,
            .utf32le => .utf32le,
            .utf32be => .utf32be,
            else => .utf8,
        };
    }

    fn queueCp(self: *Decoder, cp: u21) void {
        var tmp: [4]u8 = undefined;
        const n = encodeCp(cp, &tmp);
        @memcpy(self.out_hold[0..n], tmp[0..n]);
        self.out_len = n;
        self.out_i = 0;
    }
};

fn PullError(comptime readFn: anytype) type {
    const ret = @typeInfo(@TypeOf(readFn)).@"fn".return_type.?;
    const set = switch (@typeInfo(ret)) {
        .error_union => |eu| eu.error_set,
        else => error{},
    };
    return set || error{ OutOfMemory, DecodeLimit };
}

fn prefixAscii(bytes: []const u8, end: usize) bool {
    const to = @min(end, bytes.len);
    return isAsciiSlice(bytes[0..to]);
}

fn unitsOf(cp: u21) usize {
    return if (cp > 0xffff) 2 else 1;
}

fn convertedUnits(mode: coded_mode, input: []const u8) usize {
    var i: usize = 0;
    var units: usize = 0;
    while (i < input.len) {
        const step = decodeMode(mode, input[i..], true) orelse break;
        units += unitsOf(step.cp);
        i += step.n;
    }
    return units;
}

fn convertedLen(mode: coded_mode, input: []const u8) usize {
    return switch (mode) {
        inline else => |m| convertedLenMode(m, input),
    };
}

fn isAsciiCompatible(comptime mode: coded_mode) bool {
    return switch (mode) {
        .utf8, .gbk, .gb18030, .shift_jis, .euc_jp, .big5, .euc_kr, .latin1, .windows1252, .windows1251 => true,
        .utf16le, .utf16be, .utf32le, .utf32be => false,
    };
}

/// Returns the length of the leading pure-ASCII prefix (`b < 0x80`) of `src`.
inline fn countAsciiPrefix(src: []const u8) usize {
    const W = memchr.native_width;
    const V = @Vector(W, u8);
    const S = @Vector(W, i8);
    const Mask = @Int(.unsigned, W);
    const zero_s: S = @splat(0);
    var i: usize = 0;
    while (i + W * 2 <= src.len) : (i += W * 2) {
        const v0: V = src[i..][0..W].*;
        const v1: V = src[i + W ..][0..W].*;
        const combined: V = v0 | v1;
        if (@as(Mask, @bitCast(@as(S, @bitCast(combined)) < zero_s)) != 0) {
            const hi0 = @as(S, @bitCast(v0)) < zero_s;
            const m0: Mask = @bitCast(hi0);
            if (m0 != 0) return i + @as(usize, @ctz(m0));
            const hi1 = @as(S, @bitCast(v1)) < zero_s;
            return i + W + @as(usize, @ctz(@as(Mask, @bitCast(hi1))));
        }
    }
    while (i + W <= src.len) : (i += W) {
        const v: V = src[i..][0..W].*;
        const hi = @as(S, @bitCast(v)) < zero_s;
        const m: Mask = @bitCast(hi);
        if (m != 0) return i + @as(usize, @ctz(m));
    }
    while (i < src.len and src[i] < 0x80) : (i += 1) {}
    return i;
}

/// Copies the leading pure-ASCII prefix (`b < 0x80`) of `src` into `dst`.
/// May write up to `W` bytes within `dst[0..@min(dst.len, src.len)]` on a SIMD hit, returning the exact ASCII prefix length.
inline fn copyAsciiPrefix(dst: []u8, src: []const u8) usize {
    const limit = @min(dst.len, src.len);
    const W = memchr.native_width;
    const V = @Vector(W, u8);
    const S = @Vector(W, i8);
    const Mask = @Int(.unsigned, W);
    const zero_s: S = @splat(0);
    var i: usize = 0;
    while (i + W * 2 <= limit) : (i += W * 2) {
        const v0: V = src[i..][0..W].*;
        const v1: V = src[i + W ..][0..W].*;
        const combined: V = v0 | v1;
        if (@as(Mask, @bitCast(@as(S, @bitCast(combined)) < zero_s)) != 0) {
            const hi0 = @as(S, @bitCast(v0)) < zero_s;
            const m0: Mask = @bitCast(hi0);
            dst[i..][0..W].* = v0;
            if (m0 != 0) return i + @as(usize, @ctz(m0));
            const hi1 = @as(S, @bitCast(v1)) < zero_s;
            dst[i + W ..][0..W].* = v1;
            return i + W + @as(usize, @ctz(@as(Mask, @bitCast(hi1))));
        }
        dst[i..][0..W].* = v0;
        dst[i + W ..][0..W].* = v1;
    }
    while (i + W <= limit) : (i += W) {
        const v: V = src[i..][0..W].*;
        const hi = @as(S, @bitCast(v)) < zero_s;
        const m: Mask = @bitCast(hi);
        dst[i..][0..W].* = v;
        if (m != 0) return i + @as(usize, @ctz(m));
    }
    while (i < limit and src[i] < 0x80) : (i += 1) {
        dst[i] = src[i];
    }
    return i;
}

/// Fused register-resident GBK -> UTF-8 fast path without OffsetMap tracking (Variant H).
/// Uses speculative 32B/64B SIMD ASCII copy + `@ctz` falling straight into a 2x unrolled
/// `gbk_table.utf8_direct` CJK loop with inline 1-byte ASCII swallow.
/// May speculatively write within `dst[0..dst.len]` past `out_n`; stops cleanly before
/// Euro (`0x80`), invalid lead/trail bytes, or tight tail slack (`dst.len - di < 4`).
noinline fn decodeGbkFastNoMap(src: []const u8, dst: []u8) struct { in_n: usize, out_n: usize } {
    const W = memchr.native_width;
    const V = @Vector(W, u8);
    const S = @Vector(W, i8);
    const Mask = @Int(.unsigned, W);
    const zero_s: S = @splat(0);

    var si: usize = 0;
    var di: usize = 0;
    const src_len = src.len;
    const dst_len = dst.len;

    outer: while (si < src_len and di < dst_len) {
        ascii_hit: {
            if (si + W <= src_len and di + W <= dst_len) {
                const v: V = src[si..][0..W].*;
                const m: Mask = @bitCast(@as(S, @bitCast(v)) < zero_s);
                dst[di..][0..W].* = v;
                if (m != 0) {
                    const adv: usize = @ctz(m);
                    si += adv;
                    di += adv;
                    break :ascii_hit;
                }
                si += W;
                di += W;

                while (si + W * 2 <= src_len and di + W * 2 <= dst_len) {
                    const v0: V = src[si..][0..W].*;
                    const v1: V = src[si + W ..][0..W].*;
                    const combined: V = v0 | v1;
                    if (@as(Mask, @bitCast(@as(S, @bitCast(combined)) < zero_s)) != 0) {
                        const m0: Mask = @bitCast(@as(S, @bitCast(v0)) < zero_s);
                        dst[di..][0..W].* = v0;
                        if (m0 != 0) {
                            const adv: usize = @ctz(m0);
                            si += adv;
                            di += adv;
                            break :ascii_hit;
                        }
                        const m1: Mask = @bitCast(@as(S, @bitCast(v1)) < zero_s);
                        dst[di + W ..][0..W].* = v1;
                        const adv: usize = W + @as(usize, @ctz(m1));
                        si += adv;
                        di += adv;
                        break :ascii_hit;
                    }
                    dst[di..][0..W].* = v0;
                    dst[di + W ..][0..W].* = v1;
                    si += W * 2;
                    di += W * 2;
                }

                while (si + W <= src_len and di + W <= dst_len) {
                    const v2: V = src[si..][0..W].*;
                    const m2: Mask = @bitCast(@as(S, @bitCast(v2)) < zero_s);
                    dst[di..][0..W].* = v2;
                    if (m2 != 0) {
                        const adv: usize = @ctz(m2);
                        si += adv;
                        di += adv;
                        break :ascii_hit;
                    }
                    si += W;
                    di += W;
                }
            }

            while (si < src_len and di < dst_len and src[si] < 0x80) {
                dst[di] = src[si];
                si += 1;
                di += 1;
            }
            if (si >= src_len or di >= dst_len) break :outer;
        }

        // 2x unrolled CJK loop with inline 1-byte ASCII swallow
        while (si + 6 <= src_len and di + 8 <= dst_len) {
            const b1 = src[si];
            const lead0 = b1 -% 0x81;
            if (lead0 < 0x7E) {
                const enc0 = gbk_table.utf8_direct[(@as(usize, lead0) << 8) | src[si + 1]];
                if (enc0 == 0) return .{ .in_n = si, .out_n = di };
                const b3 = src[si + 2];
                const lead1 = b3 -% 0x81;
                if (lead1 < 0x7E) {
                    const enc1 = gbk_table.utf8_direct[(@as(usize, lead1) << 8) | src[si + 3]];
                    if (enc1 == 0) {
                        std.mem.writeInt(u32, dst[di..][0..4], enc0, .little);
                        return .{ .in_n = si + 2, .out_n = di + @as(usize, enc0 >> 24) };
                    }
                    std.mem.writeInt(u32, dst[di..][0..4], enc0, .little);
                    const len0: usize = enc0 >> 24;
                    std.mem.writeInt(u32, dst[di + len0 ..][0..4], enc1, .little);
                    di += len0 + @as(usize, enc1 >> 24);
                    si += 4;
                    continue;
                }
                std.mem.writeInt(u32, dst[di..][0..4], enc0, .little);
                di += @as(usize, enc0 >> 24);
                si += 2;
                if (b3 < 0x80) {
                    if (src[si + 1] >= 0x80) {
                        dst[di] = b3;
                        di += 1;
                        si += 1;
                        continue;
                    }
                    continue :outer;
                }
                return .{ .in_n = si, .out_n = di };
            } else if (b1 < 0x80) {
                if (src[si + 1] >= 0x80) {
                    dst[di] = b1;
                    di += 1;
                    si += 1;
                    continue;
                }
                continue :outer;
            } else {
                return .{ .in_n = si, .out_n = di };
            }
        }

        // 1x CJK + ASCII tail with safe 4B store slack
        while (si + 2 <= src_len and di + 4 <= dst_len) {
            const b1 = src[si];
            const lead = b1 -% 0x81;
            if (lead >= 0x7E) {
                if (b1 < 0x80) {
                    dst[di] = b1;
                    di += 1;
                    si += 1;
                    continue;
                }
                return .{ .in_n = si, .out_n = di };
            }
            const enc = gbk_table.utf8_direct[(@as(usize, lead) << 8) | src[si + 1]];
            if (enc == 0) return .{ .in_n = si, .out_n = di };
            std.mem.writeInt(u32, dst[di..][0..4], enc, .little);
            di += @as(usize, enc >> 24);
            si += 2;
        }
        while (si < src_len and di < dst_len and src[si] < 0x80) {
            dst[di] = src[si];
            si += 1;
            di += 1;
        }
        return .{ .in_n = si, .out_n = di };
    }

    return .{ .in_n = si, .out_n = di };
}

/// Returns the number of leading ASCII UTF-16LE code units in `src` (consuming `2 * ret` bytes).
inline fn countUtf16LeAsciiPrefix(src: []const u8) usize {
    const max_units = src.len >> 1;
    var di: usize = 0;
    if (comptime std.simd.suggestVectorLength(u16)) |suggested| {
        const chunk_len = comptime @min(suggested, 16);
        const byte_step = chunk_len * 2;
        const Vec16 = @Vector(chunk_len, u16);
        const Mask = @Int(.unsigned, chunk_len);
        const hi_mask: Vec16 = @splat(std.mem.nativeToLittle(u16, 0xFF80));
        const zero16: Vec16 = @splat(0);
        while (di + chunk_len * 2 <= max_units) : (di += chunk_len * 2) {
            const si = di * 2;
            const raw0: @Vector(byte_step, u8) = src[si..][0..byte_step].*;
            const raw1: @Vector(byte_step, u8) = src[si + byte_step ..][0..byte_step].*;
            const chunk0: Vec16 = @bitCast(raw0);
            const chunk1: Vec16 = @bitCast(raw1);
            if (@as(Mask, @bitCast(((chunk0 | chunk1) & hi_mask) != zero16)) != 0) {
                const hi0 = (chunk0 & hi_mask) != zero16;
                const m0: Mask = @bitCast(hi0);
                if (m0 != 0) return di + @as(usize, @ctz(m0));
                const hi1 = (chunk1 & hi_mask) != zero16;
                return di + chunk_len + @as(usize, @ctz(@as(Mask, @bitCast(hi1))));
            }
        }
        while (di + chunk_len <= max_units) : (di += chunk_len) {
            const si = di * 2;
            const raw: @Vector(byte_step, u8) = src[si..][0..byte_step].*;
            const chunk: Vec16 = @bitCast(raw);
            const hi = (chunk & hi_mask) != zero16;
            const m: Mask = @bitCast(hi);
            if (m != 0) return di + @as(usize, @ctz(m));
        }
    }
    while (di < max_units) : (di += 1) {
        const si = di * 2;
        if (src[si + 1] != 0 or src[si] >= 0x80) break;
    }
    return di;
}

/// Copies leading ASCII UTF-16LE code units from `src` into `dst` (consuming `2 * ret` raw bytes, producing `ret` UTF-8 bytes).
inline fn copyUtf16LeAsciiPrefix(dst: []u8, src: []const u8) usize {
    const max_units = @min(dst.len, src.len >> 1);
    var di: usize = 0;
    if (comptime std.simd.suggestVectorLength(u16)) |suggested| {
        const chunk_len = comptime @min(suggested, 16);
        const byte_step = chunk_len * 2;
        const Vec16 = @Vector(chunk_len, u16);
        const Vec8 = @Vector(chunk_len, u8);
        const Mask = @Int(.unsigned, chunk_len);
        const hi_mask: Vec16 = @splat(std.mem.nativeToLittle(u16, 0xFF80));
        const zero16: Vec16 = @splat(0);
        while (di + chunk_len * 2 <= max_units) : (di += chunk_len * 2) {
            const si = di * 2;
            const raw0: @Vector(byte_step, u8) = src[si..][0..byte_step].*;
            const raw1: @Vector(byte_step, u8) = src[si + byte_step ..][0..byte_step].*;
            const chunk0: Vec16 = @bitCast(raw0);
            const chunk1: Vec16 = @bitCast(raw1);
            if (@as(Mask, @bitCast(((chunk0 | chunk1) & hi_mask) != zero16)) != 0) {
                const hi0 = (chunk0 & hi_mask) != zero16;
                const m0: Mask = @bitCast(hi0);
                dst[di..][0..chunk_len].* = @as(Vec8, @truncate(std.mem.nativeToLittle(Vec16, chunk0)));
                if (m0 != 0) return di + @as(usize, @ctz(m0));
                const hi1 = (chunk1 & hi_mask) != zero16;
                dst[di + chunk_len ..][0..chunk_len].* = @as(Vec8, @truncate(std.mem.nativeToLittle(Vec16, chunk1)));
                return di + chunk_len + @as(usize, @ctz(@as(Mask, @bitCast(hi1))));
            }
            dst[di..][0..chunk_len].* = @as(Vec8, @truncate(std.mem.nativeToLittle(Vec16, chunk0)));
            dst[di + chunk_len ..][0..chunk_len].* = @as(Vec8, @truncate(std.mem.nativeToLittle(Vec16, chunk1)));
        }
        while (di + chunk_len <= max_units) : (di += chunk_len) {
            const si = di * 2;
            const raw: @Vector(byte_step, u8) = src[si..][0..byte_step].*;
            const chunk: Vec16 = @bitCast(raw);
            const hi = (chunk & hi_mask) != zero16;
            const m: Mask = @bitCast(hi);
            dst[di..][0..chunk_len].* = @as(Vec8, @truncate(std.mem.nativeToLittle(Vec16, chunk)));
            if (m != 0) return di + @as(usize, @ctz(m));
        }
    }
    while (di < max_units) : (di += 1) {
        const si = di * 2;
        if (src[si + 1] != 0 or src[si] >= 0x80) break;
        dst[di] = src[si];
    }
    return di;
}

fn convertedLenMode(comptime mode: coded_mode, input: []const u8) usize {
    var i: usize = 0;
    var n: usize = 0;
    while (i < input.len) {
        if (comptime mode == .utf16le) {
            const ascii_units = countUtf16LeAsciiPrefix(input[i..]);
            if (ascii_units != 0) {
                n += ascii_units;
                i += ascii_units * 2;
                continue;
            }
            while (i + 2 <= input.len) {
                const u = std.mem.readInt(u16, input[i..][0..2], .little);
                if (u < 0x80) break;
                if (u >= 0x0800) {
                    if (u >= 0xD800 and u <= 0xDFFF) break;
                    n += 3;
                    i += 2;
                } else {
                    n += 2;
                    i += 2;
                }
            }
            if (i >= input.len) break;
            if (i + 2 <= input.len and input[i + 1] == 0 and input[i] < 0x80) continue;
        } else if (comptime isAsciiCompatible(mode)) {
            const ascii_run = countAsciiPrefix(input[i..]);
            if (ascii_run != 0) {
                n += ascii_run;
                i += ascii_run;
                continue;
            }
            if (comptime mode == .gbk) {
                while (i + 2 <= input.len) {
                    const lead = input[i] -% 0x81;
                    if (lead >= 0x7E) break;
                    const enc = gbk_table.utf8_direct[(@as(usize, lead) << 8) | input[i + 1]];
                    if (enc == 0) break;
                    n += @as(usize, enc >> 24);
                    i += 2;
                }
                if (i >= input.len or input[i] < 0x80) continue;
            }
        }
        const step = decodeModeComptime(mode, input[i..], true) orelse break;
        n += utf8Len(step.cp);
        i += step.n;
    }
    return n;
}

fn convertInto(mode: coded_mode, input: []const u8, out: []u8) usize {
    return switch (mode) {
        inline else => |m| convertIntoModeImpl(m, false, undefined, input, out, 0, undefined) catch unreachable,
    };
}

fn convertIntoWithMap(
    allocator: std.mem.Allocator,
    mode: coded_mode,
    input: []const u8,
    out: []u8,
    raw_base: u64,
    offset_map: ?*decompress.OffsetMap,
) error{OutOfMemory}!usize {
    if (offset_map) |m| {
        return switch (mode) {
            inline else => |cm| convertIntoModeImpl(cm, true, allocator, input, out, raw_base, m),
        };
    }
    return convertInto(mode, input, out);
}

fn convertIntoModeImpl(
    comptime mode: coded_mode,
    comptime has_map: bool,
    allocator: if (has_map) std.mem.Allocator else void,
    input: []const u8,
    out: []u8,
    raw_base: u64,
    m: if (has_map) *decompress.OffsetMap else void,
) error{OutOfMemory}!usize {
    if (comptime has_map) {
        m.base_raw_offset = raw_base;
    }
    var i: usize = 0;
    var w: usize = 0;
    while (i < input.len) {
        if (comptime mode == .utf16le) {
            const ascii_units = copyUtf16LeAsciiPrefix(out[w..], input[i..]);
            if (ascii_units != 0) {
                const run_in = ascii_units * 2;
                if (comptime has_map) {
                    try m.recordRun(allocator, w, raw_base + i, w + ascii_units, raw_base + i + run_in);
                }
                w += ascii_units;
                i += run_in;
                continue;
            }
            const si0 = i;
            const di0 = w;
            while (i + 2 <= input.len and w + 3 <= out.len) {
                const u = std.mem.readInt(u16, input[i..][0..2], .little);
                if (u < 0x80) break;
                if (u >= 0x0800) {
                    if (u >= 0xD800 and u <= 0xDFFF) break;
                    out[w] = @intCast(0xE0 | (u >> 12));
                    out[w + 1] = @intCast(0x80 | ((u >> 6) & 0x3F));
                    out[w + 2] = @intCast(0x80 | (u & 0x3F));
                    i += 2;
                    w += 3;
                } else {
                    if (comptime has_map) break;
                    out[w] = @intCast(0xC0 | (u >> 6));
                    out[w + 1] = @intCast(0x80 | (u & 0x3F));
                    i += 2;
                    w += 2;
                }
            }
            if (i != si0) {
                if (comptime has_map) {
                    try m.recordRun(allocator, di0, raw_base + si0, w, raw_base + i);
                }
                continue;
            }
        } else if (comptime mode == .gbk and !has_map) {
            const fast = decodeGbkFastNoMap(input[i..], out[w..]);
            if (fast.in_n != 0) {
                i += fast.in_n;
                w += fast.out_n;
                if (i >= input.len) break;
            }
        } else if (comptime isAsciiCompatible(mode)) {
            const ascii_run = copyAsciiPrefix(out[w..], input[i..]);
            if (ascii_run != 0) {
                if (comptime has_map) {
                    try m.recordRun(allocator, w, raw_base + i, w + ascii_run, raw_base + i + ascii_run);
                }
                w += ascii_run;
                i += ascii_run;
                continue;
            }
            if (comptime mode == .gbk) {
                const si0 = i;
                const di0 = w;
                while (i + 2 <= input.len and w + 3 <= out.len) {
                    const lead = input[i] -% 0x81;
                    if (lead >= 0x7E) break;
                    const enc = gbk_table.utf8_direct[(@as(usize, lead) << 8) | input[i + 1]];
                    if ((enc >> 24) != 3) break;
                    out[w] = @truncate(enc);
                    out[w + 1] = @truncate(enc >> 8);
                    out[w + 2] = @truncate(enc >> 16);
                    w += 3;
                    i += 2;
                }
                if (i != si0) {
                    if (comptime has_map) {
                        try m.recordRun(allocator, di0, raw_base + si0, w, raw_base + i);
                    }
                    continue;
                }
            }
        }
        const step = decodeModeComptime(mode, input[i..], true) orelse break;
        if (comptime has_map) {
            try m.record(allocator, w, raw_base + i);
        }
        w += encodeCp(step.cp, out[w..]);
        i += step.n;
    }
    if (comptime has_map) {
        try m.record(allocator, w, raw_base + i);
    }
    return w;
}

inline fn decodeModeComptime(comptime mode: coded_mode, bytes: []const u8, eof: bool) ?Step {
    return switch (mode) {
        .utf8 => decodeUtf8(bytes, eof),
        .utf16le => decodeUtf16(bytes, .little, eof),
        .utf16be => decodeUtf16(bytes, .big, eof),
        .gbk => decodeGbk(bytes, eof),
        .latin1 => decodeLatin1(bytes),
        .windows1252 => decodeWindows1252(bytes),
        .gb18030 => decodeGb18030(bytes, eof),
        .shift_jis => decodeShiftJis(bytes, eof),
        .euc_jp => decodeEucJp(bytes, eof),
        .big5 => decodeBig5(bytes, eof),
        .euc_kr => decodeEucKr(bytes, eof),
        .windows1251 => decodeWindows1251(bytes),
        .utf32le => decodeUtf32(bytes, .little, eof),
        .utf32be => decodeUtf32(bytes, .big, eof),
    };
}

fn decodeMode(mode: coded_mode, bytes: []const u8, eof: bool) ?Step {
    return switch (mode) {
        inline else => |m| decodeModeComptime(m, bytes, eof),
    };
}

fn decodeLatin1(bytes: []const u8) ?Step {
    if (bytes.len == 0) return null;
    return .{ .n = 1, .cp = bytes[0] };
}

fn decodeWindows1252(bytes: []const u8) ?Step {
    if (bytes.len == 0) return null;
    const b = bytes[0];
    if (b >= 0x80 and b <= 0x9F) {
        return .{ .n = 1, .cp = legacy_tables.windows1252_80_9f[b - 0x80] };
    }
    return .{ .n = 1, .cp = b };
}

fn decodeWindows1251(bytes: []const u8) ?Step {
    if (bytes.len == 0) return null;
    const b = bytes[0];
    if (b < 0x80) return .{ .n = 1, .cp = b };
    return .{ .n = 1, .cp = legacy_tables.windows1251_high[b - 0x80] };
}

fn decodeGb18030(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const b0 = bytes[0];
    if (b0 < 0x80) return .{ .n = 1, .cp = b0 };
    if (b0 == 0x80) return .{ .n = 1, .cp = 0x20AC };
    if (b0 == 0xFF) return .{ .n = 1, .cp = unicode.replacement_character };
    if (bytes.len < 2) {
        if (!eof) return null;
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    const b1 = bytes[1];
    if (b1 >= 0x30 and b1 <= 0x39) {
        if (bytes.len < 4) {
            if (!eof) return null;
            return .{ .n = 1, .cp = unicode.replacement_character };
        }
        const b2 = bytes[2];
        const b3 = bytes[3];
        if (legacy_tables.lookupGb18030FourByte(b0, b1, b2, b3)) |cp| {
            return .{ .n = 4, .cp = cp };
        }
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    if (legacy_tables.lookupGb18030TwoByteExtra(b0, b1)) |cp| {
        return .{ .n = 2, .cp = cp };
    }
    return decodeGbk(bytes, eof);
}

fn decodeShiftJis(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const b0 = bytes[0];
    if (b0 < 0x80) return .{ .n = 1, .cp = b0 };
    if (b0 >= 0xA1 and b0 <= 0xDF) return .{ .n = 1, .cp = 0xFF61 + @as(u21, b0 - 0xA1) };
    if ((b0 >= 0x81 and b0 <= 0x9F) or (b0 >= 0xE0 and b0 <= 0xFC)) {
        if (bytes.len < 2) {
            if (!eof) return null;
            return .{ .n = 1, .cp = unicode.replacement_character };
        }
        if (legacy_tables.lookupShiftJis(b0, bytes[1])) |cp| {
            return .{ .n = 2, .cp = cp };
        }
    }
    return .{ .n = 1, .cp = unicode.replacement_character };
}

fn decodeEucJp(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const b0 = bytes[0];
    if (b0 < 0x80) return .{ .n = 1, .cp = b0 };
    if (b0 == 0x8E) {
        if (bytes.len < 2) {
            if (!eof) return null;
            return .{ .n = 1, .cp = unicode.replacement_character };
        }
        const b1 = bytes[1];
        if (b1 >= 0xA1 and b1 <= 0xDF) return .{ .n = 2, .cp = 0xFF61 + @as(u21, b1 - 0xA1) };
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    if (b0 >= 0xA1 and b0 <= 0xFE) {
        if (bytes.len < 2) {
            if (!eof) return null;
            return .{ .n = 1, .cp = unicode.replacement_character };
        }
        if (legacy_tables.lookupEucJp(b0, bytes[1])) |cp| {
            return .{ .n = 2, .cp = cp };
        }
    }
    return .{ .n = 1, .cp = unicode.replacement_character };
}

fn decodeBig5(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const b0 = bytes[0];
    if (b0 < 0x80) return .{ .n = 1, .cp = b0 };
    if (b0 >= 0x81 and b0 <= 0xFE) {
        if (bytes.len < 2) {
            if (!eof) return null;
            return .{ .n = 1, .cp = unicode.replacement_character };
        }
        if (legacy_tables.lookupBig5(b0, bytes[1])) |cp| {
            return .{ .n = 2, .cp = cp };
        }
    }
    return .{ .n = 1, .cp = unicode.replacement_character };
}

fn decodeEucKr(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const b0 = bytes[0];
    if (b0 < 0x80) return .{ .n = 1, .cp = b0 };
    if (b0 >= 0x81 and b0 <= 0xFE) {
        if (bytes.len < 2) {
            if (!eof) return null;
            return .{ .n = 1, .cp = unicode.replacement_character };
        }
        if (legacy_tables.lookupEucKr(b0, bytes[1])) |cp| {
            return .{ .n = 2, .cp = cp };
        }
    }
    return .{ .n = 1, .cp = unicode.replacement_character };
}

fn decodeUtf32(bytes: []const u8, endian: std.builtin.Endian, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    if (bytes.len < 4) {
        if (!eof) return null;
        return .{ .n = bytes.len, .cp = unicode.replacement_character };
    }
    const raw = std.mem.readInt(u32, bytes[0..4], endian);
    if (raw > 0x10FFFF or (raw >= 0xD800 and raw <= 0xDFFF)) {
        return .{ .n = 4, .cp = unicode.replacement_character };
    }
    return .{ .n = 4, .cp = @intCast(raw) };
}

fn decodeGbk(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const b1 = bytes[0];
    if (b1 < 0x80) return .{ .n = 1, .cp = b1 };
    if (b1 == 0x80) return .{ .n = 1, .cp = 0x20AC }; // Euro sign
    if (b1 == 0xFF) return .{ .n = 1, .cp = unicode.replacement_character };
    if (bytes.len < 2) {
        if (!eof) return null;
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    const b2 = bytes[1];
    if (b2 < 0x40 or b2 == 0x7F or b2 == 0xFF) {
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    const trail_idx: usize = if (b2 > 0x7F) b2 - 0x41 else b2 - 0x40;
    const linear: usize = (@as(usize, b1 - 0x81) * 190) + trail_idx;
    return .{ .n = 2, .cp = gbk_table.table[linear] };
}

fn decodeUtf8(bytes: []const u8, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    const first = bytes[0];
    if (first < 0x80) return .{ .n = 1, .cp = first };
    const len = unicode.utf8ByteSequenceLength(first) catch return .{ .n = 1, .cp = unicode.replacement_character };
    if (bytes.len < len) {
        if (!eof) return null;
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    const cp = switch (len) {
        2 => unicode.utf8Decode2(bytes[0..2].*),
        3 => unicode.utf8Decode3(bytes[0..3].*),
        4 => unicode.utf8Decode4(bytes[0..4].*),
        else => error.Utf8InvalidStartByte,
    } catch return .{ .n = 1, .cp = unicode.replacement_character };
    return .{ .n = len, .cp = cp };
}

fn decodeUtf16(bytes: []const u8, endian: std.builtin.Endian, eof: bool) ?Step {
    if (bytes.len == 0) return null;
    if (bytes.len < 2) {
        if (!eof) return null;
        return .{ .n = 1, .cp = unicode.replacement_character };
    }
    const unit = std.mem.readInt(u16, bytes[0..2], endian);
    if (unicode.utf16IsHighSurrogate(unit)) {
        if (bytes.len < 4) {
            if (!eof) return null;
            return .{ .n = 2, .cp = unicode.replacement_character };
        }
        const low = std.mem.readInt(u16, bytes[2..4], endian);
        if (!unicode.utf16IsLowSurrogate(low)) return .{ .n = 2, .cp = unicode.replacement_character };
        const pair = [2]u16{ unit, low };
        const cp = unicode.utf16DecodeSurrogatePair(&pair) catch return .{ .n = 2, .cp = unicode.replacement_character };
        return .{ .n = 4, .cp = cp };
    }
    if (unicode.utf16IsLowSurrogate(unit)) return .{ .n = 2, .cp = unicode.replacement_character };
    return .{ .n = 2, .cp = unit };
}

inline fn utf8Len(cp: u21) usize {
    return unicode.utf8CodepointSequenceLength(cp) catch 3;
}

fn encodeCp(cp: u21, out: []u8) usize {
    return unicode.utf8Encode(cp, out) catch {
        const rep = unicode.replacement_character_utf8;
        @memcpy(out[0..rep.len], &rep);
        return rep.len;
    };
}

const testing = std.testing;

test "BOM is only recognized at the beginning" {
    try testing.expectEqual(Sniff.utf8, sniff("\xef\xbb\xbfxyz", false));
    try testing.expectEqual(Sniff.utf16le, sniff("\xff\xfe\x61\x00", false));
    try testing.expectEqual(Sniff.utf16be, sniff("\xfe\xff\x00\x61", false));
    try testing.expectEqual(Sniff.raw, sniff("foo", false));
    try testing.expectEqual(Sniff.need_more, sniff("\xef\xbb", false));
    try testing.expectEqual(Sniff.raw, sniff("\xef\xbb", true));
    try testing.expectEqual(Sniff.need_more, sniff("\xff", false));
    try testing.expectEqual(Sniff.raw, sniff("\xff", true));
}

test "invalid UTF-16 code units are replaced with U+FFFD" {
    const lone = [_]u8{ 0x61, 0x00, 0x00, 0xD8, 0x62, 0x00 };
    const text = try convertAlloc(testing.allocator, .utf16le, &lone);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("a\u{FFFD}b", text);

    const odd = [_]u8{ 0x61, 0x00, 0xff };
    const tail = try convertAlloc(testing.allocator, .utf16le, &odd);
    defer testing.allocator.free(tail);
    try testing.expectEqualStrings("a\u{FFFD}", tail);

    const be = [_]u8{ 0x00, 0x61, 0xD8, 0x00 };
    const wide = try convertAlloc(testing.allocator, .utf16be, &be);
    defer testing.allocator.free(wide);
    try testing.expectEqualStrings("a\u{FFFD}", wide);
}

test "UTF-16 code unit offsets" {
    const bytes = "aé你😀x";
    const x = utf16Span(bytes, 10, 11);
    try testing.expectEqual(@as(usize, 5), x.start);
    try testing.expectEqual(@as(usize, 6), x.end);
    const face = utf16Span(bytes, 6, 10);
    try testing.expectEqual(@as(usize, 3), face.start);
    try testing.expectEqual(@as(usize, 5), face.end);
    const bad = "a\xffb";
    try testing.expectEqualStrings("a\u{FFFD}b", blk: {
        var buf: [8]u8 = undefined;
        const n = writeLossy(bad, &buf);
        break :blk buf[0..n];
    });
    const span = utf16Span(bad, 2, 3);
    try testing.expectEqual(@as(usize, 2), span.start);
    try testing.expectEqual(@as(usize, 3), span.end);
}

const Chunk = struct {
    rest: []const u8,
    cap: usize,
    reads: usize = 0,

    fn read(ctx: *anyopaque, dest: []u8) error{}!usize {
        const self: *Chunk = @ptrCast(@alignCast(ctx));
        self.reads += 1;
        const n = @min(dest.len, @min(self.cap, self.rest.len));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }
};

test "transcodes to UTF-8 even when read buffer is smaller than BOM plus one code unit" {
    const le = [_]u8{ 0xFF, 0xFE, 'f', 0, 'o', 0, 'o', 0, '\n', 0 };
    var src = Chunk{ .rest = &le, .cap = 3 };
    var dec = Decoder.init(.auto);
    defer dec.deinit(testing.allocator);
    var out: [16]u8 = undefined;
    var filled: usize = 0;
    var read_bytes: u64 = 0;
    var guard: usize = 0;
    while (guard < 20) : (guard += 1) {
        const pulled = try dec.pull(testing.allocator, Chunk.read, &src, 3, out[filled..], &read_bytes);
        filled += pulled.n;
        if (pulled.eof) break;
    }
    try testing.expectEqualStrings("foo\n", out[0..filled]);
    try testing.expect(src.reads > 1);
    try testing.expectEqual(@as(u64, le.len), read_bytes);

    const be = [_]u8{ 0xFE, 0xFF, 0, 'f', 0, 'o', 0, 'o', 0, '\n' };
    var src_be = Chunk{ .rest = &be, .cap = 3 };
    var dec_be = Decoder.init(.auto);
    defer dec_be.deinit(testing.allocator);
    filled = 0;
    read_bytes = 0;
    guard = 0;
    while (guard < 20) : (guard += 1) {
        const pulled = try dec_be.pull(testing.allocator, Chunk.read, &src_be, 3, out[filled..], &read_bytes);
        filled += pulled.n;
        if (pulled.eof) break;
    }
    try testing.expectEqualStrings("foo\n", out[0..filled]);
}

test "GBK / CP936 full table decodes Level-1, Level-2, GBK/3, GBK/4, Euro 0x80, and split chunks" {
    // U+4F60 U+597D (C4 E3 BA C3) + U+9555 (GBK/4: E9 46) + U+5586 (GBK/3: 86 B4) + Euro U+20AC (0x80) + "\n"
    const gbk_bytes = [_]u8{ 0xC4, 0xE3, 0xBA, 0xC3, 0xE9, 0x46, 0x86, 0xB4, 0x80, '\n' };
    const decoded = try convertAlloc(testing.allocator, .gbk, &gbk_bytes);
    defer testing.allocator.free(decoded);
    try testing.expectEqualStrings("你好镕喆€\n", decoded);

    // Streaming 1 byte at a time across double-byte boundaries
    var src = Chunk{ .rest = &gbk_bytes, .cap = 1 };
    var dec = Decoder.init(.gbk);
    defer dec.deinit(testing.allocator);
    var out: [64]u8 = undefined;
    var filled: usize = 0;
    var read_bytes: u64 = 0;
    while (true) {
        const pulled = try dec.pull(testing.allocator, Chunk.read, &src, 1, out[filled..], &read_bytes);
        filled += pulled.n;
        if (pulled.eof) break;
    }
    try testing.expectEqualStrings("你好镕喆€\n", out[0..filled]);
    try testing.expectEqual(@as(u64, gbk_bytes.len), read_bytes);

    // Invalid trail byte (0x7F) and truncated lead byte at EOF produce U+FFFD
    const invalid_gbk = [_]u8{ 0x81, 0x7F, 'A', 0xFE };
    const lossy_gbk = try convertAlloc(testing.allocator, .gbk, &invalid_gbk);
    defer testing.allocator.free(lossy_gbk);
    try testing.expectEqualStrings("\u{FFFD}\x7FA\u{FFFD}", lossy_gbk);
}

test "v0.8 encodings: Windows-1252, GB18030, Shift_JIS, EUC-JP, Big5, EUC-KR, Windows-1251, UTF-32" {
    // Windows-1252 (0x80..0x9F differ from ISO-8859-1)
    const cp1252_bytes = [_]u8{ 0x80, 0x31, 0x30, 0x30, 0x20, 0x97, 0x20, 0x93, 0x68, 0x69, 0x94 };
    const cp1252_out = try convertAlloc(testing.allocator, .windows1252, &cp1252_bytes);
    defer testing.allocator.free(cp1252_out);
    try testing.expectEqualStrings("€100 — “hi”", cp1252_out);

    // GB18030: 2-byte + 4-byte BMP (U+0080) + 4-byte supplementary (U+1F600 😀)
    const gb18030_bytes = [_]u8{ 0xC4, 0xE3, 0xBA, 0xC3, 0xA2, 0xE3, 0x81, 0x30, 0x81, 0x30, 0x94, 0x39, 0xFC, 0x36 };
    const gb18030_out = try convertAlloc(testing.allocator, .gb18030, &gb18030_bytes);
    defer testing.allocator.free(gb18030_out);
    try testing.expectEqualStrings("你好€\u{0080}😀", gb18030_out);

    // Shift_JIS (CP932) including half-width katakana
    const sjis_bytes = [_]u8{ 0x82, 0xB1, 0x82, 0xF1, 0x82, 0xC9, 0x82, 0xBF, 0x82, 0xCD, 0xB1, 0xB2, 0xB3 };
    const sjis_out = try convertAlloc(testing.allocator, .shift_jis, &sjis_bytes);
    defer testing.allocator.free(sjis_out);
    try testing.expectEqualStrings("こんにちはｱｲｳ", sjis_out);

    // EUC-JP
    const eucjp_bytes = [_]u8{ 0xA4, 0xB3, 0xA4, 0xF3, 0xA4, 0xCB, 0xA4, 0xC1, 0xA4, 0xCF, 0xC0, 0xA4, 0xB3, 0xA6 };
    const eucjp_out = try convertAlloc(testing.allocator, .euc_jp, &eucjp_bytes);
    defer testing.allocator.free(eucjp_out);
    try testing.expectEqualStrings("こんにちは世界", eucjp_out);

    // Big5
    const big5_bytes = [_]u8{ 0xC1, 0x63, 0xC5, 0xE9, 0xA4, 0xA4, 0xA4, 0xE5, 0xB4, 0xFA, 0xB8, 0xD5 };
    const big5_out = try convertAlloc(testing.allocator, .big5, &big5_bytes);
    defer testing.allocator.free(big5_out);
    try testing.expectEqualStrings("繁體中文測試", big5_out);

    // EUC-KR / CP949
    const euckr_bytes = [_]u8{ 0xBE, 0xC8, 0xB3, 0xE7, 0xC7, 0xCF, 0xBC, 0xBC, 0xBF, 0xE4 };
    const euckr_out = try convertAlloc(testing.allocator, .euc_kr, &euckr_bytes);
    defer testing.allocator.free(euckr_out);
    try testing.expectEqualStrings("안녕하세요", euckr_out);

    // Windows-1251 (Cyrillic)
    const cp1251_bytes = [_]u8{ 0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2, 0x20, 0xEC, 0xE8, 0xF0 };
    const cp1251_out = try convertAlloc(testing.allocator, .windows1251, &cp1251_bytes);
    defer testing.allocator.free(cp1251_out);
    try testing.expectEqualStrings("Привет мир", cp1251_out);

    // UTF-32LE with BOM (FF FE 00 00) + 'A' + 😀 (U+1F600)
    const utf32le_bytes = [_]u8{
        0xFF, 0xFE, 0x00, 0x00,
        'A',  0x00, 0x00, 0x00,
        0x00, 0xF6, 0x01, 0x00,
    };
    const le_sniff = sniff(&utf32le_bytes, true);
    try testing.expectEqual(Sniff.utf32le, le_sniff);
    const utf32le_out = try convertAlloc(testing.allocator, .utf32le, utf32le_bytes[4..]);
    defer testing.allocator.free(utf32le_out);
    try testing.expectEqualStrings("A😀", utf32le_out);

    // UTF-32BE with BOM (00 00 FE FF) + 'A' + 😀 (U+1F600)
    const utf32be_bytes = [_]u8{
        0x00, 0x00, 0xFE, 0xFF,
        0x00, 0x00, 0x00, 'A',
        0x00, 0x01, 0xF6, 0x00,
    };
    const be_sniff = sniff(&utf32be_bytes, true);
    try testing.expectEqual(Sniff.utf32be, be_sniff);
    const utf32be_out = try convertAlloc(testing.allocator, .utf32be, utf32be_bytes[4..]);
    defer testing.allocator.free(utf32be_out);
    try testing.expectEqualStrings("A😀", utf32be_out);

    // fromCharset aliases
    try testing.expectEqual(Encoding.windows1252, fromCharset("windows-1252").?);
    try testing.expectEqual(Encoding.windows1252, fromCharset("cp1252").?);
    try testing.expectEqual(Encoding.gb18030, fromCharset("gb18030").?);
    try testing.expectEqual(Encoding.shift_jis, fromCharset("shift_jis").?);
    try testing.expectEqual(Encoding.shift_jis, fromCharset("cp932").?);
    try testing.expectEqual(Encoding.euc_jp, fromCharset("euc-jp").?);
    try testing.expectEqual(Encoding.big5, fromCharset("big5").?);
    try testing.expectEqual(Encoding.euc_kr, fromCharset("euc-kr").?);
    try testing.expectEqual(Encoding.windows1251, fromCharset("windows-1251").?);
    try testing.expectEqual(Encoding.utf32le, fromCharset("utf-32le").?);
    try testing.expectEqual(Encoding.utf32be, fromCharset("utf-32be").?);

    // Heuristic detectEncoding + streaming Decoder.init(.detect)
    try testing.expectEqual(Encoding.utf8, detectEncoding("hello 世界\n"));
    try testing.expectEqual(Encoding.utf32le, detectEncoding(&utf32le_bytes));
    try testing.expectEqual(Encoding.utf32be, detectEncoding(&utf32be_bytes));
    try testing.expectEqual(Encoding.windows1252, detectEncoding(&cp1252_bytes));
    try testing.expectEqual(Encoding.gb18030, detectEncoding(&gb18030_bytes));
    try testing.expectEqual(Encoding.shift_jis, detectEncoding(&sjis_bytes));

    var det_src = Chunk{ .rest = &sjis_bytes, .cap = 3 };
    var det_dec = Decoder.init(.detect);
    defer det_dec.deinit(testing.allocator);
    var out_buf: [64]u8 = undefined;
    var filled: usize = 0;
    var read_bytes: u64 = 0;
    while (true) {
        const pulled = try det_dec.pull(testing.allocator, Chunk.read, &det_src, 3, out_buf[filled..], &read_bytes);
        filled += pulled.n;
        if (pulled.eof) break;
    }
    try testing.expectEqualStrings("こんにちはｱｲｳ", out_buf[0..filled]);
}

test "SIMD GBK and UTF-16LE parity with and without OffsetMap across slice and streaming" {
    const alloc = testing.allocator;

    // Build a realistic >128-byte mixed GBK log payload (ASCII runs > 64B, short ASCII runs,
    // consecutive GBK Hanzi, 2-byte UTF-8 GBK punctuation/Cyrillic, Euro 0x80, invalid byte 0xFF)
    const gbk_payload =
        "2026-11-23T00:00:01Z level=INFO svc=gateway latency=12ms status=200 path=/api/v1/orders msg=" ++
        "\xC4\xE3\xBA\xC3\xCA\xC0\xBD\xE7" ++ // 你好世界
        " ok " ++
        "\xB2\xE2\xCA\xD4\xB4\xED\xCE\xF3" ++ // 测试错误
        "\x80" ++ // € (0x80)
        "\xA7\xA1" ++ // А (U+0410, 2-byte UTF-8 in GBK)
        " tail_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n";

    // 1. Slice without OffsetMap vs with OffsetMap
    const gbk_no_map = try convertAlloc(alloc, .gbk, gbk_payload);
    defer alloc.free(gbk_no_map);

    var gbk_map = decompress.OffsetMap{};
    defer gbk_map.deinit(alloc);
    const gbk_len = decodedSize(.gbk, gbk_payload);
    try testing.expectEqual(gbk_no_map.len, gbk_len);
    const gbk_with_map = try convertAllocWithMapKnownLen(alloc, .gbk, gbk_payload, 0, &gbk_map, gbk_len);
    defer alloc.free(gbk_with_map);
    try testing.expectEqualStrings(gbk_no_map, gbk_with_map);

    // Verify exact raw offsets for GBK line landmarks:
    // After 92-byte ASCII prefix: raw=92, out=92; after 4 Hanzi (8 raw, 12 out): raw=100, out=104
    try testing.expectEqual(@as(u64, 92), gbk_map.map(92));
    try testing.expectEqual(@as(u64, 100), gbk_map.map(104));
    try testing.expectEqual(@as(u64, gbk_payload.len), gbk_map.map(gbk_no_map.len));

    // 2. Streaming Decoder with small chunks (17B) without map vs with map
    var stream_no_map: std.ArrayList(u8) = .empty;
    defer stream_no_map.deinit(alloc);
    {
        var src = Chunk{ .rest = gbk_payload, .cap = 17 };
        var dec = Decoder.init(.gbk);
        defer dec.deinit(alloc);
        var tmp: [29]u8 = undefined;
        var rb: u64 = 0;
        while (true) {
            const p = try dec.pull(alloc, Chunk.read, &src, 17, &tmp, &rb);
            try stream_no_map.appendSlice(alloc, tmp[0..p.n]);
            if (p.eof) break;
        }
        try testing.expectEqual(@as(u64, gbk_payload.len), rb);
    }
    try testing.expectEqualStrings(gbk_no_map, stream_no_map.items);

    var stream_with_map: std.ArrayList(u8) = .empty;
    defer stream_with_map.deinit(alloc);
    var stream_gbk_map = decompress.OffsetMap{};
    defer stream_gbk_map.deinit(alloc);
    {
        var src = Chunk{ .rest = gbk_payload, .cap = 19 };
        var dec = Decoder.init(.gbk);
        defer dec.deinit(alloc);
        dec.offset_map = &stream_gbk_map;
        var tmp: [31]u8 = undefined;
        var rb: u64 = 0;
        while (true) {
            const p = try dec.pull(alloc, Chunk.read, &src, 19, &tmp, &rb);
            try stream_with_map.appendSlice(alloc, tmp[0..p.n]);
            if (p.eof) break;
        }
    }
    try testing.expectEqualStrings(gbk_no_map, stream_with_map.items);
    try testing.expectEqual(@as(u64, 92), stream_gbk_map.map(92));
    try testing.expectEqual(@as(u64, 100), stream_gbk_map.map(104));

    // 3. UTF-16LE with long ASCII (>64 units), short ASCII before CJK, 2-byte BMP (é), 3-byte BMP (你好), surrogate (😀)
    const utf8_ref =
        "2026-11-23T00:00:01Z level=INFO svc=auth latency=5ms host=node-0123456789abcdef " ++
        "café 你好世界 😀 " ++
        "short_ascii_tail_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
    const u16_units = try unicode.utf8ToUtf16LeAlloc(alloc, utf8_ref);
    defer alloc.free(u16_units);
    const u16_raw = std.mem.sliceAsBytes(u16_units);

    const u16_no_map = try convertAlloc(alloc, .utf16le, u16_raw);
    defer alloc.free(u16_no_map);
    try testing.expectEqualStrings(utf8_ref, u16_no_map);

    var u16_map = decompress.OffsetMap{};
    defer u16_map.deinit(alloc);
    const u16_with_map = try convertAllocWithMap(alloc, .utf16le, u16_raw, 2, &u16_map);
    defer alloc.free(u16_with_map);
    try testing.expectEqualStrings(utf8_ref, u16_with_map);
    try testing.expectEqual(@as(u64, 2 + 80 * 2), u16_map.map(80));
    try testing.expectEqual(@as(u64, 2 + u16_raw.len), u16_map.map(utf8_ref.len));

    // Streaming UTF-16LE with and without map
    var u16_stream: std.ArrayList(u8) = .empty;
    defer u16_stream.deinit(alloc);
    var u16_stream_map = decompress.OffsetMap{};
    defer u16_stream_map.deinit(alloc);
    {
        var src = Chunk{ .rest = u16_raw, .cap = 37 };
        var dec = Decoder.init(.utf16le);
        defer dec.deinit(alloc);
        dec.offset_map = &u16_stream_map;
        var tmp: [43]u8 = undefined;
        var rb: u64 = 0;
        while (true) {
            const p = try dec.pull(alloc, Chunk.read, &src, 37, &tmp, &rb);
            try u16_stream.appendSlice(alloc, tmp[0..p.n]);
            if (p.eof) break;
        }
    }
    try testing.expectEqualStrings(utf8_ref, u16_stream.items);
    try testing.expectEqual(@as(u64, 80 * 2), u16_stream_map.map(80));
    try testing.expectEqual(@as(u64, u16_raw.len), u16_stream_map.map(utf8_ref.len));
}

fn refDecodeGbkAlloc(alloc: std.mem.Allocator, src: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var i: usize = 0;
    var tmp: [4]u8 = undefined;
    while (i < src.len) {
        const step = decodeGbk(src[i..], true) orelse break;
        const n = encodeCp(step.cp, &tmp);
        try out.appendSlice(alloc, tmp[0..n]);
        i += step.n;
    }
    return out.toOwnedSlice(alloc);
}

test "gbk_table.utf8_direct exhaustive parity with decodeGbk + encodeCp" {
    var expected: [4]u8 = undefined;
    var actual: [4]u8 = undefined;
    for (0x81..0xFF) |b1_usize| {
        const b1: u8 = @intCast(b1_usize);
        const row = @as(usize, b1 - 0x81) << 8;
        for (0..256) |b2_usize| {
            const b2: u8 = @intCast(b2_usize);
            const enc = gbk_table.utf8_direct[row | b2];
            if (b2 < 0x40 or b2 == 0x7F or b2 == 0xFF) {
                try testing.expectEqual(@as(u32, 0), enc);
            } else {
                const pair = [_]u8{ b1, b2 };
                const step = decodeGbk(&pair, true).?;
                try testing.expectEqual(@as(usize, 2), step.n);
                const exp_len = encodeCp(step.cp, &expected);
                const act_len: usize = enc >> 24;
                try testing.expectEqual(exp_len, act_len);
                std.mem.writeInt(u32, &actual, enc, .little);
                try testing.expectEqualSlices(u8, expected[0..exp_len], actual[0..act_len]);
            }
        }
    }
}

test "decodeGbkFastNoMap, Decoder, and convertInto bit-for-bit parity and tight dst boundaries" {
    const alloc = testing.allocator;

    // 1. Pure ASCII across scalar, 32B, 64B burst, and odd remainders
    const ascii_lens = [_]usize{ 0, 1, 7, 15, 16, 31, 32, 33, 63, 64, 65, 95, 96, 129, 257 };
    var ascii_buf: [257]u8 = undefined;
    for (&ascii_buf, 0..) |*b, idx| {
        b.* = @intCast(0x20 + (idx % 95));
    }
    for (ascii_lens) |len| {
        const src = ascii_buf[0..len];
        const exact_dst = try alloc.alloc(u8, len);
        defer alloc.free(exact_dst);
        const fast = decodeGbkFastNoMap(src, exact_dst);
        try testing.expectEqual(len, fast.in_n);
        try testing.expectEqual(len, fast.out_n);
        try testing.expectEqualStrings(src, exact_dst);

        const conv_n = convertInto(.gbk, src, exact_dst);
        try testing.expectEqual(len, conv_n);
        try testing.expectEqualStrings(src, exact_dst);
    }

    // 2. Diverse payloads: pure CJK, mixed short-run Y10-style CJK/ASCII with 1B space swallow,
    //    Euro 0x80, invalid 0x7F/0xFF/bad trail bytes, unmapped valid pair, truncated lead byte
    const mixed_short_runs =
        "2026-11-23T00:00:01Z INFO " ++ // 26B ASCII
        "\xC4\xE3\xBA\xC3\xCA\xC0\xBD\xE7\xB2\xE2\xCA\xD4\xB3\xAC\xCA\xB1" ++ // 8 CJK
        " " ++ // 1B ASCII swallow
        "\xB4\xED\xCE\xF3" ++ // 2 CJK
        " " ++ // 1B ASCII swallow
        "\xB3\xAC\xCA\xB1" ++ // 2 CJK
        " svc=a" ++ // 6B ASCII
        "\xC4\xE3\xBA\xC3\xCA\xC0\xBD\xE7\xB2\xE2\xCA\xD4\xE9\x46" ++ // 7 CJK (incl. GBK/4)
        "0123456789012345678901234567890" ++ // 31B ASCII
        " " ++
        "\x86\xB4\xA7\xA1\xC4\xE3\xBA\xC3" ++ // GBK/3 + 2B UTF-8 Cyrillic + Level-1
        " ok";

    const pure_cjk =
        "\xC4\xE3\xBA\xC3\xCA\xC0\xBD\xE7\xE9\x46\x86\xB4\xA7\xA1\xFE\xFE" ++
        "\xB3\xAC\xCA\xB1\xB4\xED\xCE\xF3\xC4\xE3\xBA\xC3\xCA\xC0\xBD\xE7" ++
        "\x81\x40\xFE\x40\xA1\xA1\xA7\xA1\xC4\xE3\xBA\xC3";

    const specials_and_invalid =
        "\x80" ++ // leading Euro
        "\xC4\xE3 \x80 \xBA\xC3" ++ // CJK + 1B space + Euro + 1B space + CJK
        "\x81\x7F" ++ // invalid trail 0x7F (must emit U+FFFD then 0x7F)
        "\xC4\x3F" ++ // invalid trail < 0x40 (must emit U+FFFD then '?')
        "\xC4\xFF" ++ // invalid trail 0xFF (must emit U+FFFD then U+FFFD)
        "\xFF" ++ // invalid lead 0xFF
        "\xFE\xFE" ++ // valid range, unmapped slot -> single U+FFFD (2B consumed)
        "abcd" ++
        "\x80" ++ // Euro after ASCII
        "\xC4\xE3\xBA\xC3\x81\x7F\xC4\xE3" ++ // bad trail in 2nd char of 2x unrolled pair
        "\xFE"; // truncated trailing lead byte

    const payloads = [_][]const u8{
        mixed_short_runs,
        pure_cjk,
        specials_and_invalid,
        "\xC4\xE3", // 1 CJK char (exact 3B dst)
        "\xC4\xE3\xBA\xC3", // 2 CJK chars (exact 6B dst)
        "\x80", // lone Euro
        "\xFF", // lone invalid 0xFF
        "\x81", // lone truncated lead
    };

    for (payloads) |payload| {
        const ref = try refDecodeGbkAlloc(alloc, payload);
        defer alloc.free(ref);

        // Exact-fit convertInto (no extra slack bytes!)
        try testing.expectEqual(ref.len, decodedSize(.gbk, payload));
        const exact_out = try alloc.alloc(u8, ref.len);
        defer alloc.free(exact_out);
        const written = convertInto(.gbk, payload, exact_out);
        try testing.expectEqual(ref.len, written);
        try testing.expectEqualStrings(ref, exact_out);

        // Tight dst boundaries directly on decodeGbkFastNoMap
        var cap: usize = 0;
        while (cap <= ref.len) : (cap += if (cap < 16 or cap + 16 >= ref.len) 1 else 17) {
            const tight_dst = try alloc.alloc(u8, cap);
            defer alloc.free(tight_dst);
            const fast = decodeGbkFastNoMap(payload, tight_dst);
            try testing.expect(fast.in_n <= payload.len);
            try testing.expect(fast.out_n <= cap);
            const fast_ref = try refDecodeGbkAlloc(alloc, payload[0..fast.in_n]);
            defer alloc.free(fast_ref);
            try testing.expectEqualStrings(fast_ref, tight_dst[0..fast.out_n]);
        }

        // Streaming Decoder across tight output buffer sizes and chunk caps
        const out_caps = [_]usize{ 1, 2, 3, 4, 7, 8, 31, 32, 33, 64 };
        for (out_caps) |out_cap| {
            var streamed: std.ArrayList(u8) = .empty;
            defer streamed.deinit(alloc);
            var src_chunk = Chunk{ .rest = payload, .cap = 13 };
            var dec = Decoder.init(.gbk);
            defer dec.deinit(alloc);
            const tmp = try alloc.alloc(u8, out_cap);
            defer alloc.free(tmp);
            var rb: u64 = 0;
            while (true) {
                const p = try dec.pull(alloc, Chunk.read, &src_chunk, 13, tmp, &rb);
                try streamed.appendSlice(alloc, tmp[0..p.n]);
                if (p.eof) break;
            }
            try testing.expectEqual(@as(u64, payload.len), rb);
            try testing.expectEqualStrings(ref, streamed.items);
        }
    }
}
