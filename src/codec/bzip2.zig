//! [Module] codec/bzip2.zig
//! [Layer] Layer 3 — Stream Codec (Pure-Zig Bzip2 Decoder)
//! [Role] Zero-dependency streaming Bzip2 (`BZh1`..`BZh9`) decompressor implementing
//!        canonical Huffman tables, MTF + zero-run RLE1, inverse Burrows-Wheeler Transform,
//!        RLE2 output expansion, block & stream CRC32 verification, and multi-stream support.

const std = @import("std");

pub const Error = error{
    CorruptStream,
    OutOfMemory,
};

const max_alpha_size: usize = 258;
const max_code_len: usize = 20;
const max_groups: usize = 6;
const max_selectors: usize = 32768;
const group_size: usize = 50;

const block_magic: u48 = 0x314159265359;
const eos_magic: u48 = 0x177245385090;

const bzip2_crc_table: [256]u32 = blk: {
    @setEvalBranchQuota(4000);
    var table: [256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = @as(u32, @intCast(i)) << 24;
        for (0..8) |_| {
            if ((c & 0x80000000) != 0) {
                c = (c << 1) ^ 0x04C11DB7;
            } else {
                c <<= 1;
            }
        }
        table[i] = c;
    }
    break :blk table;
};

inline fn updateCrc(crc: u32, byte: u8) u32 {
    const idx: usize = @intCast(((crc >> 24) ^ byte) & 0xFF);
    return (crc << 8) ^ bzip2_crc_table[idx];
}

const BitReader = struct {
    upstream: *std.Io.Reader,
    buf: u64 = 0,
    bits: u7 = 0,
    eof_hit: bool = false,

    fn fill(self: *BitReader, want: u7) Error!void {
        while (self.bits < want) {
            var b: [1]u8 = undefined;
            const n = self.upstream.readSliceShort(&b) catch return error.CorruptStream;
            if (n == 0) {
                self.eof_hit = true;
                return error.CorruptStream;
            }
            self.buf = (self.buf << 8) | b[0];
            self.bits += 8;
        }
    }

    fn readBits(self: *BitReader, comptime T: type, n: u6) Error!T {
        if (n == 0) return 0;
        try self.fill(n);
        const shift: u6 = @intCast(self.bits - n);
        const mask: u64 = if (n == 64) std.math.maxInt(u64) else ((@as(u64, 1) << n) - 1);
        const val: u64 = (self.buf >> shift) & mask;
        self.bits -= n;
        return @intCast(val);
    }

    fn readBit(self: *BitReader) Error!u1 {
        return self.readBits(u1, 1);
    }

    fn alignByte(self: *BitReader) void {
        const drop: u7 = self.bits % 8;
        self.bits -= drop;
    }

    fn tryReadByte(self: *BitReader) Error!?u8 {
        if (self.bits >= 8) {
            return try self.readBits(u8, 8);
        }
        var b: [1]u8 = undefined;
        const n = self.upstream.readSliceShort(&b) catch return error.CorruptStream;
        if (n == 0) return null;
        return b[0];
    }
};

const HuffTable = struct {
    min_len: u5 = 0,
    max_len: u5 = 0,
    limit: [max_code_len + 2]i32 = @splat(0),
    base: [max_code_len + 2]i32 = @splat(0),
    perm: [max_alpha_size]u16 = @splat(0),

    fn build(self: *HuffTable, lens: []const u8, alpha_size: usize) Error!void {
        var min_l: u5 = max_code_len;
        var max_l: u5 = 1;
        for (lens[0..alpha_size]) |l| {
            if (l < 1 or l > max_code_len) return error.CorruptStream;
            const lu: u5 = @intCast(l);
            if (lu < min_l) min_l = lu;
            if (lu > max_l) max_l = lu;
        }
        self.min_len = min_l;
        self.max_len = max_l;

        var pp: usize = 0;
        for (min_l..@as(usize, max_l) + 1) |len| {
            for (0..alpha_size) |sym| {
                if (lens[sym] == len) {
                    self.perm[pp] = @intCast(sym);
                    pp += 1;
                }
            }
        }

        self.base = @splat(0);
        self.limit = @splat(0);
        for (0..alpha_size) |sym| {
            self.base[lens[sym] + 1] += 1;
        }
        for (1..max_code_len + 2) |i| {
            self.base[i] += self.base[i - 1];
        }

        var vec: i32 = 0;
        for (min_l..@as(usize, max_l) + 1) |len| {
            vec += self.base[len + 1] - self.base[len];
            self.limit[len] = vec - 1;
            vec <<= 1;
        }
        for (@as(usize, min_l) + 1..@as(usize, max_l) + 1) |len| {
            self.base[len] = ((self.limit[len - 1] + 1) << 1) - self.base[len];
        }
    }

    fn decode(self: *const HuffTable, br: *BitReader) Error!u16 {
        var len: usize = self.min_len;
        var vec: i32 = @intCast(try br.readBits(u32, self.min_len));
        while (vec > self.limit[len]) {
            len += 1;
            if (len > self.max_len) return error.CorruptStream;
            vec = (vec << 1) | @as(i32, try br.readBit());
        }
        const idx_i = vec - self.base[len];
        if (idx_i < 0 or idx_i >= max_alpha_size) return error.CorruptStream;
        return self.perm[@intCast(idx_i)];
    }
};

pub const Bzip2Decompressor = struct {
    allocator: std.mem.Allocator,
    br: BitReader,

    in_stream: bool = false,
    eof: bool = false,
    block_size: usize = 0,
    combined_crc: u32 = 0,

    // Active decoded BWT block state
    tt: []u32 = &.{},
    block_active: bool = false,
    block_rem: usize = 0,
    t_pos: u32 = 0,
    expected_block_crc: u32 = 0,
    running_crc: u32 = 0xFFFFFFFF,

    // RLE2 state
    rle_byte: u8 = 0,
    rle_same_count: u8 = 0,
    rle_pending: u8 = 0,

    pub fn init(allocator: std.mem.Allocator, upstream: *std.Io.Reader) Bzip2Decompressor {
        return .{
            .allocator = allocator,
            .br = .{ .upstream = upstream },
        };
    }

    pub fn deinit(self: *Bzip2Decompressor) void {
        if (self.tt.len > 0) self.allocator.free(self.tt);
        self.* = undefined;
    }

    fn openNextStream(self: *Bzip2Decompressor) Error!bool {
        self.br.alignByte();
        const b0 = (try self.br.tryReadByte()) orelse {
            self.eof = true;
            return false;
        };
        const b1 = (try self.br.tryReadByte()) orelse return error.CorruptStream;
        const b2 = (try self.br.tryReadByte()) orelse return error.CorruptStream;
        const b3 = (try self.br.tryReadByte()) orelse return error.CorruptStream;
        if (b0 != 'B' or b1 != 'Z' or b2 != 'h' or b3 < '1' or b3 > '9') {
            return error.CorruptStream;
        }
        const level: usize = b3 - '0';
        const new_bs = level * 100_000;
        if (self.tt.len < new_bs) {
            if (self.tt.len > 0) self.allocator.free(self.tt);
            self.tt = self.allocator.alloc(u32, new_bs) catch return error.OutOfMemory;
        }
        self.block_size = new_bs;
        self.combined_crc = 0;
        self.in_stream = true;
        return true;
    }

    fn decodeNextBlock(self: *Bzip2Decompressor) Error!bool {
        while (true) {
            if (!self.in_stream) {
                if (!(try self.openNextStream())) return false;
            }

            const magic = try self.br.readBits(u48, 48);
            if (magic == eos_magic) {
                const stored_combined = try self.br.readBits(u32, 32);
                if (stored_combined != self.combined_crc) return error.CorruptStream;
                self.in_stream = false;
                continue;
            }
            if (magic != block_magic) return error.CorruptStream;

            const block_crc = try self.br.readBits(u32, 32);
            const randomised = try self.br.readBit();
            if (randomised != 0) return error.CorruptStream;
            const orig_ptr = try self.br.readBits(u24, 24);

            // Symbol bitmap (16 x 16)
            var seq_to_unseq: [256]u8 = undefined;
            var n_in_use: usize = 0;
            const in_use_16 = try self.br.readBits(u16, 16);
            for (0..16) |i| {
                const bit16: u4 = @intCast(15 - i);
                if (((in_use_16 >> bit16) & 1) != 0) {
                    const row = try self.br.readBits(u16, 16);
                    for (0..16) |j| {
                        const bitj: u4 = @intCast(15 - j);
                        if (((row >> bitj) & 1) != 0) {
                            seq_to_unseq[n_in_use] = @intCast(i * 16 + j);
                            n_in_use += 1;
                        }
                    }
                }
            }
            if (n_in_use == 0) return error.CorruptStream;
            const alpha_size = n_in_use + 2;
            const eob: u16 = @intCast(alpha_size - 1);

            const n_groups: usize = try self.br.readBits(u3, 3);
            if (n_groups < 2 or n_groups > max_groups) return error.CorruptStream;
            const n_selectors: usize = try self.br.readBits(u15, 15);
            if (n_selectors < 1 or n_selectors > max_selectors) return error.CorruptStream;

            const selectors = self.allocator.alloc(u8, n_selectors) catch return error.OutOfMemory;
            defer self.allocator.free(selectors);

            var sel_mtf: [max_groups]u8 = .{ 0, 1, 2, 3, 4, 5 };
            for (0..n_selectors) |i| {
                var j: usize = 0;
                while (try self.br.readBit() == 1) {
                    j += 1;
                    if (j >= n_groups) return error.CorruptStream;
                }
                const tmp = sel_mtf[j];
                while (j > 0) : (j -= 1) {
                    sel_mtf[j] = sel_mtf[j - 1];
                }
                sel_mtf[0] = tmp;
                selectors[i] = tmp;
            }

            var tables: [max_groups]HuffTable = undefined;
            var lens: [max_alpha_size]u8 = undefined;
            for (0..n_groups) |g| {
                var curr: i32 = @intCast(try self.br.readBits(u5, 5));
                for (0..alpha_size) |sym| {
                    while (try self.br.readBit() == 1) {
                        if (try self.br.readBit() == 0) {
                            curr += 1;
                        } else {
                            curr -= 1;
                        }
                        if (curr < 1 or curr > max_code_len) return error.CorruptStream;
                    }
                    if (curr < 1 or curr > max_code_len) return error.CorruptStream;
                    lens[sym] = @intCast(curr);
                }
                try tables[g].build(&lens, alpha_size);
            }

            // Decode MTF + RLE1 symbols into tt[]
            var mtf: [256]u8 = undefined;
            for (0..n_in_use) |i| mtf[i] = @intCast(i);
            var unzftab: [256]u32 = @splat(0);

            var nblock: usize = 0;
            var sel_idx: usize = 0;
            var group_rem: usize = 0;
            var cur_table: *const HuffTable = &tables[selectors[0]];

            var next_sym: u16 = undefined;
            if (group_rem == 0) {
                if (sel_idx >= n_selectors) return error.CorruptStream;
                cur_table = &tables[selectors[sel_idx]];
                sel_idx += 1;
                group_rem = group_size;
            }
            group_rem -= 1;
            next_sym = try cur_table.decode(&self.br);

            while (next_sym != eob) {
                if (next_sym == 0 or next_sym == 1) {
                    var run: usize = 0;
                    var shift: u5 = 0;
                    while (next_sym == 0 or next_sym == 1) {
                        if (shift >= 24) return error.CorruptStream;
                        run += (@as(usize, next_sym) + 1) << shift;
                        shift += 1;
                        if (group_rem == 0) {
                            if (sel_idx >= n_selectors) return error.CorruptStream;
                            cur_table = &tables[selectors[sel_idx]];
                            sel_idx += 1;
                            group_rem = group_size;
                        }
                        group_rem -= 1;
                        next_sym = try cur_table.decode(&self.br);
                    }
                    if (run > self.block_size - nblock) return error.CorruptStream;
                    const ch = seq_to_unseq[mtf[0]];
                    unzftab[ch] += @intCast(run);
                    for (0..run) |_| {
                        self.tt[nblock] = ch;
                        nblock += 1;
                    }
                } else {
                    const mtf_idx: usize = next_sym - 1;
                    if (mtf_idx >= n_in_use) return error.CorruptStream;
                    const idx_val = mtf[mtf_idx];
                    std.mem.copyBackwards(u8, mtf[1 .. mtf_idx + 1], mtf[0..mtf_idx]);
                    mtf[0] = idx_val;
                    const ch = seq_to_unseq[idx_val];
                    if (nblock >= self.block_size) return error.CorruptStream;
                    unzftab[ch] += 1;
                    self.tt[nblock] = ch;
                    nblock += 1;

                    if (group_rem == 0) {
                        if (sel_idx >= n_selectors) return error.CorruptStream;
                        cur_table = &tables[selectors[sel_idx]];
                        sel_idx += 1;
                        group_rem = group_size;
                    }
                    group_rem -= 1;
                    next_sym = try cur_table.decode(&self.br);
                }
            }

            if (orig_ptr >= nblock) return error.CorruptStream;

            // Build cumulative frequency table and inverse BWT pointer array
            var cftab: [257]u32 = undefined;
            cftab[0] = 0;
            for (0..256) |i| {
                cftab[i + 1] = cftab[i] + unzftab[i];
            }
            for (0..nblock) |i| {
                const ch: usize = @intCast(self.tt[i] & 0xFF);
                self.tt[cftab[ch]] |= (@as(u32, @intCast(i)) << 8);
                cftab[ch] += 1;
            }

            self.t_pos = self.tt[orig_ptr] >> 8;
            self.block_rem = nblock;
            self.expected_block_crc = block_crc;
            self.running_crc = 0xFFFFFFFF;
            self.rle_byte = 0;
            self.rle_same_count = 0;
            self.rle_pending = 0;
            self.block_active = true;
            return true;
        }
    }

    inline fn nextBwtByte(self: *Bzip2Decompressor) u8 {
        const entry = self.tt[self.t_pos];
        self.t_pos = entry >> 8;
        self.block_rem -= 1;
        return @truncate(entry);
    }

    pub fn read(self: *Bzip2Decompressor, dest: []u8) Error!usize {
        if (dest.len == 0 or self.eof) return 0;
        var written: usize = 0;

        while (written < dest.len) {
            if (self.rle_pending > 0) {
                dest[written] = self.rle_byte;
                self.running_crc = updateCrc(self.running_crc, self.rle_byte);
                self.rle_pending -= 1;
                written += 1;
                continue;
            }

            if (!self.block_active) {
                if (!(try self.decodeNextBlock())) break;
            }

            if (self.block_rem == 0) {
                const final_crc = ~self.running_crc;
                if (final_crc != self.expected_block_crc) return error.CorruptStream;
                self.combined_crc = std.math.rotl(u32, self.combined_crc, 1) ^ final_crc;
                self.block_active = false;
                continue;
            }

            const ch = self.nextBwtByte();
            if (self.rle_same_count == 4) {
                self.rle_pending = ch;
                self.rle_same_count = 0;
                continue;
            }

            if (self.rle_same_count == 0 or ch != self.rle_byte) {
                self.rle_byte = ch;
                self.rle_same_count = 1;
            } else {
                self.rle_same_count += 1;
            }

            dest[written] = ch;
            self.running_crc = updateCrc(self.running_crc, ch);
            written += 1;
        }

        return written;
    }
};

test "bzip2: decodes reference Python bz2 stream with RLE2 runs and multi-stream concatenation" {
    const alloc = std.testing.allocator;
    const rep = "AAAAAABBBBBB";
    const expected = "hello bzip2 world! " ++ rep ++ rep ++ rep ++ rep ++ rep ++ rep ++ rep ++ rep ++ "\nline two\n";
    const bz2_vec = [_]u8{
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xe6, 0x98, 0x03, 0x29, 0x00, 0x00,
        0x2e, 0x5d, 0x80, 0x10, 0x10, 0x60, 0x00, 0x10, 0x00, 0x30, 0x00, 0x16, 0x65, 0xd4, 0x90, 0x20,
        0x00, 0x54, 0x50, 0x34, 0xd0, 0xc9, 0x89, 0x81, 0x29, 0x4f, 0xd2, 0x8f, 0x48, 0xf5, 0x1b, 0x49,
        0xa6, 0x90, 0x04, 0x01, 0x4f, 0x0a, 0x79, 0x9c, 0x58, 0x06, 0xb3, 0x34, 0xf4, 0x03, 0x20, 0x15,
        0x62, 0xae, 0xfa, 0xcb, 0xdf, 0x7c, 0xe9, 0x6c, 0x9b, 0xb1, 0x68, 0x91, 0x77, 0x24, 0x53, 0x85,
        0x09, 0x0e, 0x69, 0x80, 0x32, 0x90,
    };

    // Single stream (small 7-byte read chunks)
    {
        var r = std.Io.Reader.fixed(&bz2_vec);
        var dec = Bzip2Decompressor.init(alloc, &r);
        defer dec.deinit();

        var out: [256]u8 = undefined;
        var total: usize = 0;
        while (true) {
            const n = try dec.read(out[total .. @min(out.len, total + 7)]);
            if (n == 0) break;
            total += n;
        }
        try std.testing.expectEqualStrings(expected, out[0..total]);
    }

    // Concatenated two-stream .bz2
    {
        var two: [bz2_vec.len * 2]u8 = undefined;
        @memcpy(two[0..bz2_vec.len], &bz2_vec);
        @memcpy(two[bz2_vec.len..], &bz2_vec);

        var r = std.Io.Reader.fixed(&two);
        var dec = Bzip2Decompressor.init(alloc, &r);
        defer dec.deinit();

        var out: [512]u8 = undefined;
        var total: usize = 0;
        while (true) {
            const n = try dec.read(out[total..]);
            if (n == 0) break;
            total += n;
        }
        try std.testing.expectEqualStrings(expected ++ expected, out[0..total]);
    }
}
