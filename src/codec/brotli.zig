//! [Module] codec/brotli.zig
//! [Layer] Layer 3 — Stream Codec (Pure-Zig RFC 7932 Brotli Decoder)
//! [Role] Zero-dependency RFC 7932 Brotli decompressor supporting WBITS 10..24,
//!        uncompressed, metadata, and compressed meta-blocks, context maps, block-type switching,
//!        distance ring buffer, and the full RFC 7932 static dictionary + 121 transforms.

const std = @import("std");
const dict_mod = @import("../tables/brotli_dict.zig");

pub const Error = error{
    CorruptStream,
    OutOfMemory,
};

// ============================================================================
// LSB-First Bit Reader
// ============================================================================

const BitReader = struct {
    upstream: *std.Io.Reader,
    buf: u64 = 0,
    bits: u7 = 0,
    eof_hit: bool = false,

    fn ensure(self: *BitReader, want: u7) Error!void {
        while (self.bits < want) {
            var b: [1]u8 = undefined;
            const n = self.upstream.readSliceShort(&b) catch return error.CorruptStream;
            if (n == 0) {
                self.eof_hit = true;
                return error.CorruptStream;
            }
            self.buf |= @as(u64, b[0]) << @intCast(self.bits);
            self.bits += 8;
        }
    }

    fn fillSoft(self: *BitReader, want: u7) void {
        while (self.bits < want and !self.eof_hit) {
            var b: [1]u8 = undefined;
            const n = self.upstream.readSliceShort(&b) catch {
                self.eof_hit = true;
                return;
            };
            if (n == 0) {
                self.eof_hit = true;
                return;
            }
            self.buf |= @as(u64, b[0]) << @intCast(self.bits);
            self.bits += 8;
        }
    }

    fn readBits(self: *BitReader, n: u6) Error!u32 {
        if (n == 0) return 0;
        try self.ensure(n);
        const mask: u64 = (@as(u64, 1) << n) - 1;
        const val: u32 = @intCast(self.buf & mask);
        self.buf >>= n;
        self.bits -= n;
        return val;
    }

    fn readBit(self: *BitReader) Error!u1 {
        return @intCast(try self.readBits(1));
    }

    fn alignByteZeroCheck(self: *BitReader) Error!void {
        const drop: u6 = @intCast(self.bits % 8);
        if (drop != 0) {
            const pad = try self.readBits(drop);
            if (pad != 0) return error.CorruptStream;
        }
    }

    fn readAlignedByte(self: *BitReader) Error!u8 {
        if (self.bits >= 8) {
            return @intCast(try self.readBits(8));
        }
        var b: [1]u8 = undefined;
        const n = self.upstream.readSliceShort(&b) catch return error.CorruptStream;
        if (n == 0) return error.CorruptStream;
        return b[0];
    }
};

// ============================================================================
// Canonical Prefix Code Tree (LSB-first bit-reversed lookup)
// ============================================================================

const max_huff_bits: usize = 15;

const PrefixTree = struct {
    // Direct lookup for fast decoding + sorted symbol table per bit length (1..15)
    counts: [max_huff_bits + 1]u16 = @splat(0),
    symbols: []u16 = &.{},
    single_sym: u16 = 0,
    is_single: bool = false,

    fn deinit(self: *PrefixTree, allocator: std.mem.Allocator) void {
        if (self.symbols.len > 0) allocator.free(self.symbols);
        self.* = .{};
    }

    fn buildFromLengths(self: *PrefixTree, allocator: std.mem.Allocator, lens: []const u8) Error!void {
        self.counts = @splat(0);
        var total_syms: usize = 0;
        var last_sym: u16 = 0;
        for (lens, 0..) |l, sym| {
            if (l > max_huff_bits) return error.CorruptStream;
            if (l > 0) {
                self.counts[l] += 1;
                total_syms += 1;
                last_sym = @intCast(sym);
            }
        }
        if (total_syms == 0) return error.CorruptStream;
        if (total_syms == 1) {
            self.is_single = true;
            self.single_sym = last_sym;
            return;
        }

        // Verify Kraft inequality
        var left: i32 = 1;
        for (1..max_huff_bits + 1) |bits| {
            left <<= 1;
            left -= @as(i32, self.counts[bits]);
            if (left < 0) return error.CorruptStream;
        }
        if (left != 0) return error.CorruptStream;

        var offsets: [max_huff_bits + 1]u16 = @splat(0);
        var sum: u16 = 0;
        for (1..max_huff_bits + 1) |bits| {
            offsets[bits] = sum;
            sum += self.counts[bits];
        }

        const syms = allocator.alloc(u16, total_syms) catch return error.OutOfMemory;
        for (lens, 0..) |l, sym| {
            if (l > 0) {
                syms[offsets[l]] = @intCast(sym);
                offsets[l] += 1;
            }
        }
        self.symbols = syms;
        self.is_single = false;
    }

    fn decode(self: *const PrefixTree, br: *BitReader) Error!u16 {
        if (self.is_single) return self.single_sym;
        var code: i32 = 0;
        var first: i32 = 0;
        var index: usize = 0;
        for (1..max_huff_bits + 1) |len| {
            const bit = try br.readBit();
            code |= bit;
            const count: i32 = self.counts[len];
            if (code - count < first) {
                return self.symbols[index + @as(usize, @intCast(code - first))];
            }
            index += @intCast(count);
            first = (first + count) << 1;
            code <<= 1;
        }
        return error.CorruptStream;
    }
};

const code_length_order = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

// Exact RFC 7932 Section 3.5 LSB-first 4-bit lookup table:
//   xx00 -> sym 0 (len 2)
//   xx01 -> sym 4 (len 2)
//   xx10 -> sym 3 (len 2)
//   x011 -> sym 2 (len 3)
//   0111 -> sym 1 (len 4)
//   1111 -> sym 5 (len 4)
fn decodeCodeLengthCodeLength(br: *BitReader) Error!u8 {
    br.fillSoft(4);
    if (br.bits < 2) return error.CorruptStream;
    const low2: u2 = @truncate(br.buf);
    switch (low2) {
        0 => {
            _ = try br.readBits(2);
            return 0;
        },
        1 => {
            _ = try br.readBits(2);
            return 4;
        },
        2 => {
            _ = try br.readBits(2);
            return 3;
        },
        3 => {
            if (br.bits < 3) return error.CorruptStream;
            const low3: u3 = @truncate(br.buf);
            if (low3 == 3) {
                _ = try br.readBits(3);
                return 2;
            }
            if (br.bits < 4) return error.CorruptStream;
            const low4: u4 = @truncate(br.buf);
            _ = try br.readBits(4);
            return if (low4 == 7) 1 else 5;
        },
    }
}

fn readPrefixCode(allocator: std.mem.Allocator, br: *BitReader, alphabet_size: usize) Error!PrefixTree {
    var tree = PrefixTree{};
    errdefer tree.deinit(allocator);

    const hskip = try br.readBits(2);
    if (hskip == 1) {
        // Simple prefix code (1..4 symbols) — preserves exact RFC 7932 Section 3.4 symbol order
        const nsym = (try br.readBits(2)) + 1;
        var max_bits: u6 = 0;
        var tmp: usize = if (alphabet_size > 0) alphabet_size - 1 else 0;
        while (tmp > 0) : (tmp >>= 1) max_bits += 1;

        var syms: [4]u16 = @splat(0);
        for (0..nsym) |i| {
            const s = try br.readBits(max_bits);
            if (s >= alphabet_size) return error.CorruptStream;
            syms[i] = @intCast(s);
        }
        // Check duplicate symbols
        for (0..nsym) |i| {
            for (i + 1..nsym) |j| {
                if (syms[i] == syms[j]) return error.CorruptStream;
            }
        }

        if (nsym == 1) {
            tree.is_single = true;
            tree.single_sym = syms[0];
            return tree;
        }

        // RFC 7932 Section 3.4: for nsym == 2, 3, or 4 (tree_select == 0), sort same-length symbols ascending
        // Wait: RFC 7932 Section 3.4 explicitly specifies:
        //   nsym=2: symbols[0..2] sorted ascending -> len [1, 1]
        //   nsym=3: symbols[0] len 1; symbols[1..3] sorted ascending -> len [2, 2]
        //   nsym=4, tree_select=0: symbols[0..4] sorted ascending -> len [2, 2, 2, 2]
        //   nsym=4, tree_select=1: symbols[0] len 1, symbols[1] len 2, symbols[2..4] sorted ascending -> len [3, 3]
        const out_syms = allocator.alloc(u16, nsym) catch return error.OutOfMemory;
        @memcpy(out_syms, syms[0..nsym]);
        tree.symbols = out_syms;
        tree.counts = @splat(0);
        switch (nsym) {
            2 => {
                if (out_syms[0] > out_syms[1]) std.mem.swap(u16, &out_syms[0], &out_syms[1]);
                tree.counts[1] = 2;
            },
            3 => {
                if (out_syms[1] > out_syms[2]) std.mem.swap(u16, &out_syms[1], &out_syms[2]);
                tree.counts[1] = 1;
                tree.counts[2] = 2;
            },
            4 => {
                const tree_select = try br.readBit();
                if (tree_select == 0) {
                    std.mem.sort(u16, out_syms, {}, std.sort.asc(u16));
                    tree.counts[2] = 4;
                } else {
                    if (out_syms[2] > out_syms[3]) std.mem.swap(u16, &out_syms[2], &out_syms[3]);
                    tree.counts[1] = 1;
                    tree.counts[2] = 1;
                    tree.counts[3] = 2;
                }
            },
            else => unreachable,
        }
        return tree;
    }

    // Complex prefix code
    var cl_lens: [18]u8 = @splat(0);
    var space: i32 = 32;
    var num_codes: usize = 0;
    for (hskip..18) |i| {
        const sym = code_length_order[i];
        const v = try decodeCodeLengthCodeLength(br);
        cl_lens[sym] = v;
        if (v != 0) {
            space -= @as(i32, 32) >> @intCast(v);
            num_codes += 1;
            if (space <= 0) break;
        }
    }
    if (num_codes != 1 and space != 0) return error.CorruptStream;

    var cl_tree = PrefixTree{};
    defer cl_tree.deinit(allocator);
    try cl_tree.buildFromLengths(allocator, &cl_lens);

    const lens = allocator.alloc(u8, alphabet_size) catch return error.OutOfMemory;
    defer allocator.free(lens);
    @memset(lens, 0);

    var sym_idx: usize = 0;
    var prev_len: u8 = 8;
    var repeat: usize = 0;
    var repeat_code_len: u8 = 0;
    var rem_space: i32 = 32768;

    while (sym_idx < alphabet_size and rem_space > 0) {
        const code = try cl_tree.decode(br);
        if (code < 16) {
            repeat = 0;
            const cl: u8 = @intCast(code);
            lens[sym_idx] = cl;
            sym_idx += 1;
            if (cl != 0) {
                prev_len = cl;
                rem_space -= @as(i32, 32768) >> @intCast(cl);
            }
        } else {
            const extra_bits: u6 = if (code == 16) 2 else 3;
            const new_len: u8 = if (code == 16) prev_len else 0;
            if (repeat_code_len != new_len) {
                repeat = 0;
                repeat_code_len = new_len;
            }
            const old_repeat = repeat;
            if (repeat > 0) {
                repeat = (repeat - 2) << @intCast(extra_bits);
            }
            repeat += (try br.readBits(extra_bits)) + 3;
            const delta = repeat - old_repeat;
            if (sym_idx + delta > alphabet_size) return error.CorruptStream;
            if (new_len != 0) {
                for (0..delta) |_| {
                    lens[sym_idx] = new_len;
                    sym_idx += 1;
                }
                rem_space -= @as(i32, @intCast(delta)) * (@as(i32, 32768) >> @intCast(new_len));
            } else {
                sym_idx += delta;
            }
        }
    }
    if (rem_space != 0) return error.CorruptStream;

    try tree.buildFromLengths(allocator, lens);
    return tree;
}

// ============================================================================
// RFC 7932 Tables (Block Lengths, Insert-and-Copy, Context Modes)
// ============================================================================

fn decodeVarLenUint8(br: *BitReader) Error!u32 {
    if (try br.readBit() == 0) return 0;
    const nbits: u6 = @intCast(try br.readBits(3));
    if (nbits == 0) return 1;
    return (try br.readBits(nbits)) + (@as(u32, 1) << @intCast(nbits));
}

const block_len_base = [26]u32{
    1,    5,     9,     13,    17,    25,    33,     41,     49,     65,     81,     97,     113,
    145,  177,   209,   241,   305,   369,   497,    753,    1265,   2289,   4337,   8433,   16625,
};
const block_len_extra = [26]u6{
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
};

fn decodeBlockLength(br: *BitReader, tree: *const PrefixTree) Error!u32 {
    const code = try tree.decode(br);
    if (code >= 26) return error.CorruptStream;
    return block_len_base[code] + try br.readBits(block_len_extra[code]);
}

const insert_base = [24]u32{
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594,
};
const insert_extra = [24]u6{
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
};

const copy_base = [24]u32{
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
};
const copy_extra = [24]u6{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
};

const iac_insert_range = [11]u8{ 0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16 };
const iac_copy_range = [11]u8{ 0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16 };

// RFC 7932 Section 7.1 Context Lookup Tables (LUT0, LUT1, LUT2)
const context_lut0 = [256]u8{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    8,  12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
};

const context_lut1 = [256]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};

const context_lut2 = [256]u8{
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
};

inline fn literalContext(mode: u2, p1: u8, p2: u8) u8 {
    return switch (mode) {
        0 => p1 & 0x3F, // LSB6
        1 => p1 >> 2, // MSB6
        2 => context_lut0[p1] | context_lut1[p2], // UTF8
        3 => (context_lut2[p1] << 3) | context_lut2[p2], // Signed
    };
}

fn decodeContextMap(allocator: std.mem.Allocator, br: *BitReader, map_size: usize) Error!struct { map: []u8, num_trees: usize } {
    const num_trees: usize = (try decodeVarLenUint8(br)) + 1;
    const map = allocator.alloc(u8, map_size) catch return error.OutOfMemory;
    errdefer allocator.free(map);

    if (num_trees == 1) {
        @memset(map, 0);
        return .{ .map = map, .num_trees = 1 };
    }

    const use_rle = try br.readBit();
    var max_rle: u32 = 0;
    if (use_rle == 1) {
        max_rle = (try br.readBits(4)) + 1;
    }

    var tree = try readPrefixCode(allocator, br, num_trees + max_rle);
    defer tree.deinit(allocator);

    var i: usize = 0;
    while (i < map_size) {
        const code = try tree.decode(br);
        if (code == 0) {
            map[i] = 0;
            i += 1;
        } else if (code <= max_rle) {
            const run = (@as(usize, 1) << @intCast(code)) + try br.readBits(@intCast(code));
            if (i + run > map_size) return error.CorruptStream;
            @memset(map[i .. i + run], 0);
            i += run;
        } else {
            map[i] = @intCast(code - max_rle);
            i += 1;
        }
    }

    if (try br.readBit() == 1) {
        // Inverse move-to-front transform
        var mtf: [256]u8 = undefined;
        for (0..256) |k| mtf[k] = @intCast(k);
        for (map) |*slot| {
            const idx = slot.*;
            const val = mtf[idx];
            slot.* = val;
            if (idx > 0) {
                @memmove(mtf[1 .. idx + 1], mtf[0..idx]);
                mtf[0] = val;
            }
        }
    }

    return .{ .map = map, .num_trees = num_trees };
}

fn toUpperUtf8At(buf: []u8, pos: usize) usize {
    const c = buf[pos];
    if (c < 0xC0) {
        if (c >= 'a' and c <= 'z') buf[pos] ^= 32;
        return 1;
    }
    if (c < 0xE0) {
        if (pos + 1 < buf.len) buf[pos + 1] ^= 32;
        return 2;
    }
    if (pos + 2 < buf.len) buf[pos + 2] ^= 5;
    return 3;
}

fn applyDictTransform(word: []const u8, transform_id: usize, dest: []u8) Error!usize {
    if (transform_id >= dict_mod.transforms.len) return error.CorruptStream;
    const tr = dict_mod.transforms[transform_id];
    var out_len: usize = 0;

    if (tr.prefix.len > 0) {
        @memcpy(dest[0..tr.prefix.len], tr.prefix);
        out_len += tr.prefix.len;
    }

    var start: usize = 0;
    var end: usize = word.len;
    if (tr.op >= 1 and tr.op <= 9) {
        const omit: usize = tr.op;
        end = if (end > omit) end - omit else 0;
    } else if (tr.op >= 12 and tr.op <= 20) {
        const omit: usize = tr.op - 11;
        start = @min(omit, end);
    }

    const body = word[start..end];
    const body_start = out_len;
    if (body.len > 0) {
        @memcpy(dest[out_len .. out_len + body.len], body);
        out_len += body.len;
    }

    if (tr.op == 10 and body.len > 0) {
        _ = toUpperUtf8At(dest[body_start..out_len], 0);
    } else if (tr.op == 11 and body.len > 0) {
        var p: usize = 0;
        while (p < body.len) {
            p += toUpperUtf8At(dest[body_start..out_len], p);
        }
    }

    if (tr.suffix.len > 0) {
        @memcpy(dest[out_len .. out_len + tr.suffix.len], tr.suffix);
        out_len += tr.suffix.len;
    }

    return out_len;
}

const BlockState = struct {
    num_types: usize = 1,
    cur_type: usize = 0,
    prev_type: usize = 1,
    rem_len: u32 = 1 << 24,
    type_tree: PrefixTree = .{},
    len_tree: PrefixTree = .{},

    fn deinit(self: *BlockState, allocator: std.mem.Allocator) void {
        self.type_tree.deinit(allocator);
        self.len_tree.deinit(allocator);
    }

    fn init(allocator: std.mem.Allocator, br: *BitReader) Error!BlockState {
        var st = BlockState{};
        errdefer st.deinit(allocator);
        st.num_types = (try decodeVarLenUint8(br)) + 1;
        if (st.num_types >= 2) {
            st.type_tree = try readPrefixCode(allocator, br, st.num_types + 2);
            st.len_tree = try readPrefixCode(allocator, br, 26);
            st.rem_len = try decodeBlockLength(br, &st.len_tree);
        }
        return st;
    }

    fn maybeSwitch(self: *BlockState, br: *BitReader) Error!void {
        if (self.rem_len > 0) return;
        const code = try self.type_tree.decode(br);
        const next_type: usize = switch (code) {
            0 => self.prev_type,
            1 => if (self.cur_type + 1 < self.num_types) self.cur_type + 1 else 0,
            else => code - 2,
        };
        if (next_type >= self.num_types) return error.CorruptStream;
        self.prev_type = self.cur_type;
        self.cur_type = next_type;
        self.rem_len = try decodeBlockLength(br, &self.len_tree);
    }
};

pub const BrotliDecompressor = struct {
    allocator: std.mem.Allocator,
    br: BitReader,

    started: bool = false,
    eof: bool = false,
    max_window: usize = 0,

    // Decoded output buffer (retains sliding window history up to max_window)
    out: std.ArrayList(u8) = .empty,
    read_pos: usize = 0,
    total_produced: usize = 0,
    dist_ring: [4]u32 = .{ 4, 11, 15, 16 },
    dist_ring_idx: usize = 0,

    pub fn init(allocator: std.mem.Allocator, upstream: *std.Io.Reader) BrotliDecompressor {
        return .{
            .allocator = allocator,
            .br = .{ .upstream = upstream },
        };
    }

    pub fn deinit(self: *BrotliDecompressor) void {
        self.out.deinit(self.allocator);
        self.* = undefined;
    }

    fn readWbits(self: *BrotliDecompressor) Error!usize {
        if (try self.br.readBit() == 0) return 16;
        const n = try self.br.readBits(3);
        if (n != 0) return 17 + n;
        const m = try self.br.readBits(3);
        if (m != 0) return 8 + m;
        return 17;
    }

    fn pushByte(self: *BrotliDecompressor, b: u8) Error!void {
        self.out.append(self.allocator, b) catch return error.OutOfMemory;
        self.total_produced += 1;
    }

    fn decodeNextMetaBlock(self: *BrotliDecompressor) Error!bool {
        if (!self.started) {
            const wbits = try self.readWbits();
            self.max_window = (@as(usize, 1) << @intCast(wbits)) - 16;
            self.started = true;
        }

        while (true) {
            const is_last = try self.br.readBit();
            if (is_last == 1) {
                const is_last_empty = try self.br.readBit();
                if (is_last_empty == 1) {
                    try self.br.alignByteZeroCheck();
                    self.eof = true;
                    return false;
                }
            }

            const mnibbles_code = try self.br.readBits(2);
            if (mnibbles_code == 3) {
                // Metadata block
                if (try self.br.readBit() != 0) return error.CorruptStream;
                const mskipbytes = try self.br.readBits(2);
                var mskiplen: usize = 0;
                if (mskipbytes > 0) {
                    mskiplen = (try self.br.readBits(@intCast(mskipbytes * 8))) + 1;
                }
                try self.br.alignByteZeroCheck();
                for (0..mskiplen) |_| {
                    _ = try self.br.readAlignedByte();
                }
                if (is_last == 1) {
                    self.eof = true;
                    return false;
                }
                continue;
            }

            const mnibbles: u6 = @intCast(mnibbles_code + 4);
            const mlen: usize = (try self.br.readBits(mnibbles * 4)) + 1;

            var is_uncompressed: u1 = 0;
            if (is_last == 0) {
                is_uncompressed = try self.br.readBit();
            }

            if (is_uncompressed == 1) {
                try self.br.alignByteZeroCheck();
                self.out.ensureUnusedCapacity(self.allocator, mlen) catch return error.OutOfMemory;
                for (0..mlen) |_| {
                    const b = try self.br.readAlignedByte();
                    self.out.appendAssumeCapacity(b);
                    self.total_produced += 1;
                }
                return true;
            }

            // Compressed meta-block
            try self.decodeCompressedMetaBlock(mlen);
            if (is_last == 1) {
                try self.br.alignByteZeroCheck();
                self.eof = true;
            }
            return true;
        }
    }

    fn decodeCompressedMetaBlock(self: *BrotliDecompressor, mlen: usize) Error!void {
        var lit_blk = try BlockState.init(self.allocator, &self.br);
        defer lit_blk.deinit(self.allocator);
        var iac_blk = try BlockState.init(self.allocator, &self.br);
        defer iac_blk.deinit(self.allocator);
        var dist_blk = try BlockState.init(self.allocator, &self.br);
        defer dist_blk.deinit(self.allocator);

        const npostfix: u6 = @intCast(try self.br.readBits(2));
        const ndirect: u32 = (try self.br.readBits(4)) << @intCast(npostfix);

        const ctx_modes = self.allocator.alloc(u2, lit_blk.num_types) catch return error.OutOfMemory;
        defer self.allocator.free(ctx_modes);
        for (ctx_modes) |*cm| {
            cm.* = @intCast(try self.br.readBits(2));
        }

        const lit_cmap = try decodeContextMap(self.allocator, &self.br, lit_blk.num_types * 64);
        defer self.allocator.free(lit_cmap.map);
        const dist_cmap = try decodeContextMap(self.allocator, &self.br, dist_blk.num_types * 4);
        defer self.allocator.free(dist_cmap.map);

        const lit_trees = self.allocator.alloc(PrefixTree, lit_cmap.num_trees) catch return error.OutOfMemory;
        for (lit_trees) |*t| t.* = .{};
        defer {
            for (lit_trees) |*t| t.deinit(self.allocator);
            self.allocator.free(lit_trees);
        }
        for (lit_trees) |*t| {
            t.* = try readPrefixCode(self.allocator, &self.br, 256);
        }

        const iac_trees = self.allocator.alloc(PrefixTree, iac_blk.num_types) catch return error.OutOfMemory;
        for (iac_trees) |*t| t.* = .{};
        defer {
            for (iac_trees) |*t| t.deinit(self.allocator);
            self.allocator.free(iac_trees);
        }
        for (iac_trees) |*t| {
            t.* = try readPrefixCode(self.allocator, &self.br, 704);
        }

        const dist_alpha: usize = 16 + ndirect + (@as(usize, 48) << @intCast(npostfix));
        const dist_trees = self.allocator.alloc(PrefixTree, dist_cmap.num_trees) catch return error.OutOfMemory;
        for (dist_trees) |*t| t.* = .{};
        defer {
            for (dist_trees) |*t| t.deinit(self.allocator);
            self.allocator.free(dist_trees);
        }
        for (dist_trees) |*t| {
            t.* = try readPrefixCode(self.allocator, &self.br, dist_alpha);
        }

        const start_produced = self.total_produced;
        const target_produced = start_produced + mlen;

        while (self.total_produced < target_produced) {
            try iac_blk.maybeSwitch(&self.br);
            iac_blk.rem_len -= 1;

            const iac_sym = try iac_trees[iac_blk.cur_type].decode(&self.br);
            const range_idx: usize = iac_sym >> 6;
            if (range_idx >= 11) return error.CorruptStream;
            const insert_code: usize = iac_insert_range[range_idx] + ((iac_sym >> 3) & 7);
            const copy_code: usize = iac_copy_range[range_idx] + (iac_sym & 7);
            const use_dist0 = (iac_sym < 128);

            const insert_len: usize = insert_base[insert_code] + try self.br.readBits(insert_extra[insert_code]);
            const copy_len: usize = copy_base[copy_code] + try self.br.readBits(copy_extra[copy_code]);

            // Emit literals
            for (0..insert_len) |_| {
                try lit_blk.maybeSwitch(&self.br);
                lit_blk.rem_len -= 1;

                const cur_len = self.out.items.len;
                const p1: u8 = if (cur_len >= 1) self.out.items[cur_len - 1] else 0;
                const p2: u8 = if (cur_len >= 2) self.out.items[cur_len - 2] else 0;
                const ctx_id = literalContext(ctx_modes[lit_blk.cur_type], p1, p2);
                const tree_id = lit_cmap.map[lit_blk.cur_type * 64 + ctx_id];
                const lit_sym = try lit_trees[tree_id].decode(&self.br);
                try self.pushByte(@intCast(lit_sym));
            }

            if (self.total_produced >= target_produced) break;

            // Decode distance
            var dist: u32 = 0;
            if (use_dist0) {
                dist = self.dist_ring[(self.dist_ring_idx + 3) & 3];
            } else {
                try dist_blk.maybeSwitch(&self.br);
                dist_blk.rem_len -= 1;

                const dctx: usize = if (copy_len < 5) copy_len - 2 else 3;
                const dtree_id = dist_cmap.map[dist_blk.cur_type * 4 + dctx];
                const dcode = try dist_trees[dtree_id].decode(&self.br);

                if (dcode < 16) {
                    dist = switch (dcode) {
                        0 => self.dist_ring[(self.dist_ring_idx + 3) & 3],
                        1 => self.dist_ring[(self.dist_ring_idx + 2) & 3],
                        2 => self.dist_ring[(self.dist_ring_idx + 1) & 3],
                        3 => self.dist_ring[self.dist_ring_idx & 3],
                        4 => self.dist_ring[(self.dist_ring_idx + 3) & 3] -| 1,
                        5 => self.dist_ring[(self.dist_ring_idx + 3) & 3] +| 1,
                        6 => self.dist_ring[(self.dist_ring_idx + 3) & 3] -| 2,
                        7 => self.dist_ring[(self.dist_ring_idx + 3) & 3] +| 2,
                        8 => self.dist_ring[(self.dist_ring_idx + 3) & 3] -| 3,
                        9 => self.dist_ring[(self.dist_ring_idx + 3) & 3] +| 3,
                        10 => self.dist_ring[(self.dist_ring_idx + 2) & 3] -| 1,
                        11 => self.dist_ring[(self.dist_ring_idx + 2) & 3] +| 1,
                        12 => self.dist_ring[(self.dist_ring_idx + 2) & 3] -| 2,
                        13 => self.dist_ring[(self.dist_ring_idx + 2) & 3] +| 2,
                        14 => self.dist_ring[(self.dist_ring_idx + 2) & 3] -| 3,
                        15 => self.dist_ring[(self.dist_ring_idx + 2) & 3] +| 3,
                        else => unreachable,
                    };
                    if (dist == 0) return error.CorruptStream;
                } else if (dcode < 16 + ndirect) {
                    dist = @as(u32, dcode) - 15;
                } else {
                    const post_mask: u32 = (@as(u32, 1) << @intCast(npostfix)) - 1;
                    const rel: u32 = @as(u32, dcode) - 16 - ndirect;
                    const hcode: u32 = rel >> @intCast(npostfix);
                    const lcode: u32 = rel & post_mask;
                    const ndistbits: u6 = @intCast(1 + (hcode >> 1));
                    const offset: u32 = ((2 + (hcode & 1)) << @intCast(ndistbits)) - 4;
                    const extra = try self.br.readBits(ndistbits);
                    dist = ((offset + extra) << @intCast(npostfix)) + lcode + ndirect + 1;
                }

                const max_dist = @min(self.total_produced, self.max_window);
                if (dist <= max_dist and dcode != 0) {
                    self.dist_ring[self.dist_ring_idx & 3] = dist;
                    self.dist_ring_idx += 1;
                }
            }

            const max_dist = @min(self.total_produced, self.max_window);
            if (dist <= max_dist) {
                if (dist == 0 or dist > self.out.items.len) return error.CorruptStream;
                for (0..copy_len) |_| {
                    const b = self.out.items[self.out.items.len - dist];
                    try self.pushByte(b);
                }
            } else {
                // Static dictionary word + RFC 7932 Appendix B transform
                if (copy_len < 4 or copy_len > 24) return error.CorruptStream;
                const nbits = dict_mod.size_bits_by_length[copy_len];
                if (nbits == 0) return error.CorruptStream;
                const word_id_raw: usize = @intCast(dist - max_dist - 1);
                const word_mask: usize = (@as(usize, 1) << @intCast(nbits)) - 1;
                const word_idx = word_id_raw & word_mask;
                const transform_id = word_id_raw >> @intCast(nbits);
                const dict_off = dict_mod.offsets_by_length[copy_len] + word_idx * copy_len;
                const word = dict_mod.data[dict_off .. dict_off + copy_len];

                var tr_buf: [64]u8 = undefined;
                const tr_len = try applyDictTransform(word, transform_id, &tr_buf);
                self.out.appendSlice(self.allocator, tr_buf[0..tr_len]) catch return error.OutOfMemory;
                self.total_produced += tr_len;
            }
        }
        if (self.total_produced != target_produced) return error.CorruptStream;
    }

    fn compactHistory(self: *BrotliDecompressor) void {
        if (self.read_pos > self.max_window and self.read_pos > 256 * 1024) {
            const drop = self.read_pos - self.max_window;
            const remain = self.out.items.len - drop;
            @memmove(self.out.items[0..remain], self.out.items[drop..]);
            self.out.shrinkRetainingCapacity(remain);
            self.read_pos -= drop;
        }
    }

    pub fn read(self: *BrotliDecompressor, dest: []u8) Error!usize {
        if (dest.len == 0) return 0;
        while (self.read_pos >= self.out.items.len) {
            if (self.eof) return 0;
            self.compactHistory();
            if (!(try self.decodeNextMetaBlock())) return 0;
        }
        const avail = self.out.items.len - self.read_pos;
        const n = @min(dest.len, avail);
        @memcpy(dest[0..n], self.out.items[self.read_pos .. self.read_pos + n]);
        self.read_pos += n;
        return n;
    }
};

test "brotli: decodes reference brotli CLI q1, q6, and q11 streams with static dictionary and transforms" {
    const alloc = std.testing.allocator;
    const line = "The quick brown fox jumps over the lazy dog. HTTP/1.1 200 OK Content-Type: application/json\n";
    const expected = line ++ line ++ line ++ line ++ line ++ line;

    const q1 = [_]u8{
        0x8f, 0x13, 0x01, 0x00, 0x80, 0xaa, 0xaa, 0xaa, 0xea, 0xff, 0x6e, 0x97, 0x13, 0x1f, 0x2e, 0xb6,
        0x1e, 0xed, 0x6a, 0x17, 0x03, 0xb0, 0x83, 0xd9, 0x41, 0x0e, 0x17, 0x35, 0x33, 0x31, 0x33, 0xb5,
        0x45, 0x44, 0xcd, 0x4c, 0x6d, 0x85, 0x03, 0xb8, 0xf8, 0x95, 0xa6, 0x52, 0x4c, 0x60, 0x03, 0xb8,
        0x04, 0x86, 0xdb, 0x34, 0x31, 0xf6, 0xcb, 0x76, 0x0b, 0xda, 0x43, 0x1f, 0xc1, 0xa0, 0x2f, 0xe6,
        0x6b, 0x73, 0x27, 0xf4, 0xe6, 0x03, 0x7e, 0x62, 0xac, 0xe6, 0xff, 0xd0, 0xeb, 0x18, 0xa1, 0x24,
        0x6a, 0xe2, 0x34, 0x4a, 0x91, 0x25, 0x09, 0xea, 0x0a, 0x85, 0x8a, 0x67, 0xf1, 0x21, 0x7d, 0x8e,
        0x73, 0x18, 0xe7, 0x56, 0xdb, 0x19, 0x6f, 0x55, 0xe2, 0xf9, 0x54, 0x09, 0xe8, 0xff, 0xa0, 0x01,
    };
    const q6 = [_]u8{
        0x1f, 0x27, 0x02, 0x00, 0x04, 0x02, 0xbc, 0xe6, 0x13, 0x3a, 0x90, 0xc5, 0xeb, 0x83, 0x46, 0x83,
        0x44, 0xb4, 0x53, 0x0e, 0xd8, 0xc3, 0x04, 0x6b, 0x21, 0x84, 0x1a, 0x00, 0x9d, 0xe1, 0xb0, 0x31,
        0x76, 0x6e, 0x16, 0x38, 0x4e, 0x4e, 0xdb, 0x0a, 0xe6, 0x2d, 0xf9, 0xbe, 0x3c, 0x33, 0xf5, 0xf2,
        0xd2, 0x5f, 0xd3, 0x7a, 0xb0, 0xdc, 0xd5, 0xfe, 0x81, 0x71, 0x8c, 0xd9, 0xff, 0x51, 0x2e, 0x8d,
        0xc2, 0x63, 0x69, 0x4b, 0x59, 0xd6, 0x87, 0xc0, 0xa1, 0x1e, 0xe5, 0xda, 0xb2, 0x41, 0x40, 0xd8,
        0x37, 0x14, 0xf9,
    };
    const q11 = [_]u8{
        0x1f, 0x27, 0x02, 0xe0, 0x8d, 0x94, 0x6e, 0xe6, 0x22, 0x08, 0xdb, 0x91, 0x3e, 0xc8, 0xb6, 0x9b,
        0x0e, 0x74, 0x30, 0x09, 0xb0, 0xab, 0x20, 0x4b, 0xaa, 0x0a, 0x7b, 0x73, 0x83, 0x03, 0xf6, 0xb2,
        0x34, 0x88, 0x96, 0x04, 0x17, 0x5b, 0xd0, 0x07, 0x0f, 0x59, 0x8b, 0x1f, 0x85, 0x60, 0xe3, 0xb6,
        0x2e, 0x86, 0x18, 0x84, 0x1d, 0x2f, 0xc2, 0x73, 0xc0, 0xee, 0xed, 0x3f, 0xfa, 0xa9, 0xbb, 0x55,
        0xcd, 0xd5, 0x6b, 0x6e, 0x2a, 0xd1, 0x23, 0xb1, 0x77, 0x02, 0x26, 0x1e, 0xaa, 0xdf, 0x10, 0x08,
    };

    for ([_][]const u8{ &q1, &q6, &q11 }) |vec| {
        var r = std.Io.Reader.fixed(vec);
        var dec = BrotliDecompressor.init(alloc, &r);
        defer dec.deinit();

        var out: [1024]u8 = undefined;
        var total: usize = 0;
        while (true) {
            const n = try dec.read(out[total .. @min(out.len, total + 13)]);
            if (n == 0) break;
            total += n;
        }
        try std.testing.expectEqualStrings(expected, out[0..total]);
    }
}
