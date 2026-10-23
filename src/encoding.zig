//! 流开头的 BOM 与 UTF-16 转码。
//!
//! 匹配内核仍吃字节。这里只在搜索前把认出的 UTF-16 换成 UTF-8，
//! 或者在交出一行时把非法 UTF-8 换成 U+FFFD。无 BOM 时不猜测编码。

const std = @import("std");
const unicode = std.unicode;

pub const Encoding = enum {
    /// 只在流开头嗅探 BOM。无 BOM 时按原始字节搜索。
    auto,
    /// 不嗅探、不转码。非法字节原样进入匹配。
    none,
};

pub const Sniff = enum {
    need_more,
    raw,
    utf8,
    utf16le,
    utf16be,
};

const coded_mode = enum { utf8, utf16le, utf16be };

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

/// 只看流开头。`eof` 为真时，凑不齐的 BOM 前缀按原始字节处理。
pub fn sniff(bytes: []const u8, eof: bool) Sniff {
    if (bytes.len >= 3 and std.mem.eql(u8, bytes[0..3], "\xef\xbb\xbf")) return .utf8;
    if (bytes.len >= 2 and bytes[0] == 0xff and bytes[1] == 0xfe) return .utf16le;
    if (bytes.len >= 2 and bytes[0] == 0xfe and bytes[1] == 0xff) return .utf16be;
    if (eof or bytes.len >= 3) return .raw;
    if (bytes.len == 0) return .need_more;
    if (bytes.len == 1) {
        return switch (bytes[0]) {
            0xef, 0xff, 0xfe => .need_more,
            else => .raw,
        };
    }
    if (bytes[0] == 0xef and bytes[1] == 0xbb) return .need_more;
    return .raw;
}

pub fn validUtf8(bytes: []const u8) bool {
    return unicode.utf8ValidateSlice(bytes);
}

pub fn lossyLen(bytes: []const u8) usize {
    return convertedLen(.utf8, bytes);
}

pub fn writeLossy(bytes: []const u8, out: []u8) usize {
    return convertInto(.utf8, bytes, out);
}

/// `start`、`end` 是原始字节上的位置。返回值按有损 UTF-8 的 UTF-16 码元计。
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

/// 转成可搜索字节之后的长度。原始字节原样返回输入长度。
pub fn decodedSize(kind: Sniff, input: []const u8) usize {
    const mode: coded_mode = switch (kind) {
        .utf8 => .utf8,
        .utf16le => .utf16le,
        .utf16be => .utf16be,
        else => return input.len,
    };
    return convertedLen(mode, input);
}

pub fn convertAlloc(allocator: std.mem.Allocator, kind: Sniff, input: []const u8) error{OutOfMemory}![]u8 {
    const mode: coded_mode = switch (kind) {
        .utf8 => .utf8,
        .utf16le => .utf16le,
        .utf16be => .utf16be,
        else => return allocator.dupe(u8, input),
    };
    const len = convertedLen(mode, input);
    const buf = try allocator.alloc(u8, len);
    const n = convertInto(mode, input, buf);
    std.debug.assert(n == len);
    return buf;
}

/// 把上游读到的字节变成可搜索的字节。
/// `encoding == .none` 或无 BOM 时，第一次读取的长度和直接读 `dest` 相同。
pub const Decoder = struct {
    mode: Mode = .undecided,
    in: []u8 = &.{},
    in_len: usize = 0,
    in_i: usize = 0,
    out_hold: [4]u8 = undefined,
    out_len: usize = 0,
    out_i: usize = 0,
    raw_buf: []u8 = &.{},
    saw_eof: bool = false,
    /// 解码输入缓冲的字节上限。超过就返回 `DecodeLimit`，不再扩容。
    max_in: usize = std.math.maxInt(usize),

    const Mode = enum { undecided, raw, utf8, utf16le, utf16be };

    pub fn init(encoding: Encoding) Decoder {
        return .{ .mode = if (encoding == .none) .raw else .undecided };
    }

    pub fn deinit(self: *Decoder, allocator: std.mem.Allocator) void {
        if (self.in.len != 0) allocator.free(self.in);
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
                self.mode = .raw;
                return .{ .n = n, .eof = false };
            },
            .utf8, .utf16le, .utf16be => {
                const copy = try allocator.dupe(u8, dest[0..n]);
                defer allocator.free(copy);
                return self.acceptBom(allocator, kind, copy, dest, false);
            },
        }
    }

    fn decide(self: *Decoder, allocator: std.mem.Allocator, dest: []u8, eof: bool) !Pull {
        const pending = self.in[self.in_i..self.in_len];
        const kind = sniff(pending, eof);
        switch (kind) {
            .need_more => return .{ .n = 0, .eof = false },
            .raw => {
                self.mode = .raw;
                return self.emitPending(dest, eof);
            },
            .utf8, .utf16le, .utf16be => {
                const copy = try allocator.dupe(u8, pending);
                defer allocator.free(copy);
                self.in_i = self.in_len;
                return self.acceptBom(allocator, kind, copy, dest, eof);
            },
        }
    }

    fn acceptBom(
        self: *Decoder,
        allocator: std.mem.Allocator,
        kind: Sniff,
        raw: []const u8,
        dest: []u8,
        eof: bool,
    ) !Pull {
        const mode: coded_mode = switch (kind) {
            .utf8 => .utf8,
            .utf16le => .utf16le,
            .utf16be => .utf16be,
            else => .utf8,
        };
        self.mode = switch (mode) {
            .utf8 => .utf8,
            .utf16le => .utf16le,
            .utf16be => .utf16be,
        };
        const bom: usize = if (mode == .utf8) 3 else 2;
        const payload = if (raw.len >= bom) raw[bom..] else raw[raw.len..];
        self.in_i = 0;
        self.in_len = 0;
        if (payload.len != 0) try self.appendIn(allocator, payload);
        return self.decodeAvailable(dest, eof);
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
        filled += self.decodeInto(dest[filled..], self.saw_eof);
        const eof = self.saw_eof and !self.hasPending();
        return .{ .n = filled, .eof = eof };
    }

    fn emitPending(self: *Decoder, dest: []u8, eof: bool) Pull {
        const pending = self.in[self.in_i..self.in_len];
        const n = @min(pending.len, dest.len);
        @memcpy(dest[0..n], pending[0..n]);
        self.in_i += n;
        const done = eof and self.in_i >= self.in_len;
        return .{ .n = n, .eof = done };
    }

    fn decodeAvailable(self: *Decoder, dest: []u8, eof: bool) Pull {
        const n = self.decodeInto(dest, eof);
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
        if (self.raw_buf.len == 0) {
            self.raw_buf = try allocator.alloc(u8, @max(raw_cap, 1));
        }
        const want = @min(self.raw_buf.len, @max(raw_cap, 1));
        const n = try readFn(read_ctx, self.raw_buf[0..want]);
        if (n != 0) try self.appendIn(allocator, self.raw_buf[0..n]);
        return n;
    }

    fn appendIn(self: *Decoder, allocator: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, DecodeLimit }!void {
        if (bytes.len == 0) return;
        self.compactIn();
        const need = self.in_len + bytes.len;
        if (need > self.max_in) return error.DecodeLimit;
        if (self.in.len < need) {
            const cap = @max(need, if (self.in.len == 0) need else self.in.len * 2);
            if (self.in.len == 0) {
                self.in = try allocator.alloc(u8, cap);
            } else {
                self.in = try allocator.realloc(self.in, cap);
            }
        }
        @memcpy(self.in[self.in_len..][0..bytes.len], bytes);
        self.in_len += bytes.len;
    }

    fn compactIn(self: *Decoder) void {
        if (self.in_i == 0) return;
        const rest = self.in_len - self.in_i;
        if (rest != 0) std.mem.copyForwards(u8, self.in[0..rest], self.in[self.in_i..self.in_len]);
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

    fn decodeInto(self: *Decoder, dest: []u8, eof: bool) usize {
        var filled = self.drainOut(dest);
        const mode = self.coded();
        while (filled < dest.len) {
            const rest = self.in[self.in_i..self.in_len];
            const step = decodeMode(mode, rest, eof) orelse break;
            self.in_i += step.n;
            self.queueCp(step.cp);
            filled += self.drainOut(dest[filled..]);
        }
        return filled;
    }

    fn coded(self: *const Decoder) coded_mode {
        return switch (self.mode) {
            .utf16le => .utf16le,
            .utf16be => .utf16be,
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
    for (bytes[0..end]) |b| if (b >= 0x80) return false;
    return true;
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
    var i: usize = 0;
    var n: usize = 0;
    while (i < input.len) {
        const step = decodeMode(mode, input[i..], true) orelse break;
        n += utf8Len(step.cp);
        i += step.n;
    }
    return n;
}

fn convertInto(mode: coded_mode, input: []const u8, out: []u8) usize {
    var i: usize = 0;
    var w: usize = 0;
    while (i < input.len) {
        const step = decodeMode(mode, input[i..], true) orelse break;
        w += encodeCp(step.cp, out[w..]);
        i += step.n;
    }
    return w;
}

fn decodeMode(mode: coded_mode, bytes: []const u8, eof: bool) ?Step {
    return switch (mode) {
        .utf8 => decodeUtf8(bytes, eof),
        .utf16le => decodeUtf16(bytes, .little, eof),
        .utf16be => decodeUtf16(bytes, .big, eof),
    };
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

fn utf8Len(cp: u21) usize {
    if (cp < 0x80) return 1;
    if (cp < 0x800) return 2;
    if (cp < 0x10000) return 3;
    return 4;
}

fn encodeCp(cp: u21, out: []u8) usize {
    const n = unicode.utf8Encode(cp, out) catch {
        const rep = unicode.replacement_character_utf8;
        @memcpy(out[0..rep.len], &rep);
        return rep.len;
    };
    return n;
}

const testing = std.testing;

test "BOM 只在开头识别" {
    try testing.expectEqual(Sniff.utf8, sniff("\xef\xbb\xbfxyz", false));
    try testing.expectEqual(Sniff.utf16le, sniff("\xff\xfe\x61\x00", false));
    try testing.expectEqual(Sniff.utf16be, sniff("\xfe\xff\x00\x61", false));
    try testing.expectEqual(Sniff.raw, sniff("foo", false));
    try testing.expectEqual(Sniff.need_more, sniff("\xef\xbb", false));
    try testing.expectEqual(Sniff.raw, sniff("\xef\xbb", true));
    try testing.expectEqual(Sniff.need_more, sniff("\xff", false));
    try testing.expectEqual(Sniff.raw, sniff("\xff", true));
}

test "非法 UTF-16 码元换成 U+FFFD" {
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

test "UTF-16 码元偏移" {
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

test "读缓冲小于 BOM 加一个码元时仍能转成 UTF-8" {
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
