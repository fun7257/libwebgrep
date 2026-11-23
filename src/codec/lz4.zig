//! [Module] codec/lz4.zig
//! [Layer] Layer 3 — Stream Codec (Pure-Zig LZ4 Frame Decoder)
//! [Role] Zero-dependency streaming LZ4 Frame format (magic `0x184D2204`) decompressor
//!        supporting independent/dependent blocks, block & content XXH32 checksums,
//!        skippable frames (`0x184D2A50..0x184D2A5F`), and concatenated multi-frame streams.

const std = @import("std");

pub const lz4_frame_magic: u32 = 0x184D2204;
pub const lz4_skip_magic_lo: u32 = 0x184D2A50;
pub const lz4_skip_magic_hi: u32 = 0x184D2A5F;

pub const Error = error{
    CorruptStream,
    OutOfMemory,
};

/// Minimal streaming XXH32 implementation for LZ4 Frame header/block/content checksums.
pub const XxHash32 = struct {
    const p1: u32 = 0x9E3779B1;
    const p2: u32 = 0x85EBCA77;
    const p3: u32 = 0xC2B2AE3D;
    const p4: u32 = 0x27D4EB2F;
    const p5: u32 = 0x165667B1;

    total_len: u64 = 0,
    v1: u32 = 0 +% p1 +% p2,
    v2: u32 = 0 +% p2,
    v3: u32 = 0,
    v4: u32 = 0 -% p1,
    mem: [16]u8 = undefined,
    mem_len: usize = 0,

    pub fn init(seed: u32) XxHash32 {
        return .{
            .v1 = seed +% p1 +% p2,
            .v2 = seed +% p2,
            .v3 = seed,
            .v4 = seed -% p1,
        };
    }

    inline fn round(acc: u32, lane: u32) u32 {
        return std.math.rotl(u32, acc +% lane *% p2, 13) *% p1;
    }

    pub fn update(self: *XxHash32, input: []const u8) void {
        self.total_len += input.len;
        var pos: usize = 0;

        if (self.mem_len > 0) {
            const need = 16 - self.mem_len;
            if (input.len < need) {
                @memcpy(self.mem[self.mem_len .. self.mem_len + input.len], input);
                self.mem_len += input.len;
                return;
            }
            @memcpy(self.mem[self.mem_len..16], input[0..need]);
            self.v1 = round(self.v1, std.mem.readInt(u32, self.mem[0..4], .little));
            self.v2 = round(self.v2, std.mem.readInt(u32, self.mem[4..8], .little));
            self.v3 = round(self.v3, std.mem.readInt(u32, self.mem[8..12], .little));
            self.v4 = round(self.v4, std.mem.readInt(u32, self.mem[12..16], .little));
            self.mem_len = 0;
            pos = need;
        }

        while (pos + 16 <= input.len) : (pos += 16) {
            self.v1 = round(self.v1, std.mem.readInt(u32, input[pos..][0..4], .little));
            self.v2 = round(self.v2, std.mem.readInt(u32, input[pos + 4 ..][0..4], .little));
            self.v3 = round(self.v3, std.mem.readInt(u32, input[pos + 8 ..][0..4], .little));
            self.v4 = round(self.v4, std.mem.readInt(u32, input[pos + 12 ..][0..4], .little));
        }

        const rem = input.len - pos;
        if (rem > 0) {
            @memcpy(self.mem[0..rem], input[pos..]);
            self.mem_len = rem;
        }
    }

    pub fn final(self: *const XxHash32) u32 {
        var h: u32 = if (self.total_len >= 16)
            std.math.rotl(u32, self.v1, 1) +%
                std.math.rotl(u32, self.v2, 7) +%
                std.math.rotl(u32, self.v3, 12) +%
                std.math.rotl(u32, self.v4, 18)
        else
            self.v3 +% p5;

        h +%= @truncate(self.total_len);

        var pos: usize = 0;
        while (pos + 4 <= self.mem_len) : (pos += 4) {
            const lane = std.mem.readInt(u32, self.mem[pos..][0..4], .little);
            h +%= lane *% p3;
            h = std.math.rotl(u32, h, 17) *% p4;
        }
        while (pos < self.mem_len) : (pos += 1) {
            h +%= @as(u32, self.mem[pos]) *% p5;
            h = std.math.rotl(u32, h, 11) *% p1;
        }

        h ^= h >> 15;
        h *%= p2;
        h ^= h >> 13;
        h *%= p3;
        h ^= h >> 16;
        return h;
    }

    pub fn hash(seed: u32, input: []const u8) u32 {
        var st = init(seed);
        st.update(input);
        return st.final();
    }
};

fn readExact(r: *std.Io.Reader, dest: []u8) Error!bool {
    var got: usize = 0;
    while (got < dest.len) {
        const n = r.readSliceShort(dest[got..]) catch return error.CorruptStream;
        if (n == 0) {
            if (got == 0) return false; // clean EOF before frame
            return error.CorruptStream;
        }
        got += n;
    }
    return true;
}

fn readExactStrict(r: *std.Io.Reader, dest: []u8) Error!void {
    if (!(try readExact(r, dest))) return error.CorruptStream;
}

fn skipBytes(r: *std.Io.Reader, count: u64) Error!void {
    var rem = count;
    var tmp: [4096]u8 = undefined;
    while (rem > 0) {
        const want: usize = @intCast(@min(rem, tmp.len));
        try readExactStrict(r, tmp[0..want]);
        rem -= want;
    }
}

/// Decompresses a single LZ4 block into `out_buf` using optional prior `dict` (last <= 64 KiB)
/// for dependent blocks. Returns the number of uncompressed bytes written.
pub fn decompressBlock(src: []const u8, out_buf: []u8, dict: []const u8) Error!usize {
    var ip: usize = 0;
    var op: usize = 0;

    while (ip < src.len) {
        const token = src[ip];
        ip += 1;

        // 1. Literal length
        var lit_len: usize = @intCast(token >> 4);
        if (lit_len == 15) {
            while (true) {
                if (ip >= src.len) return error.CorruptStream;
                const extra = src[ip];
                ip += 1;
                lit_len = std.math.add(usize, lit_len, extra) catch return error.CorruptStream;
                if (extra != 255) break;
            }
        }

        if (lit_len > src.len - ip) return error.CorruptStream;
        if (lit_len > out_buf.len - op) return error.CorruptStream;
        if (lit_len > 0) {
            @memcpy(out_buf[op .. op + lit_len], src[ip .. ip + lit_len]);
            ip += lit_len;
            op += lit_len;
        }

        // Last sequence ends immediately after literals (no match offset/length)
        if (ip == src.len) break;

        // 2. Match offset (little-endian u16, 1..65535)
        if (src.len - ip < 2) return error.CorruptStream;
        const offset: usize = std.mem.readInt(u16, src[ip..][0..2], .little);
        ip += 2;
        if (offset == 0) return error.CorruptStream;

        // 3. Match length (4 + lower nibble + optional 255-extension bytes)
        var match_len: usize = @as(usize, token & 0x0F) + 4;
        if ((token & 0x0F) == 15) {
            while (true) {
                if (ip >= src.len) return error.CorruptStream;
                const extra = src[ip];
                ip += 1;
                match_len = std.math.add(usize, match_len, extra) catch return error.CorruptStream;
                if (extra != 255) break;
            }
        }

        if (match_len > out_buf.len - op) return error.CorruptStream;

        if (offset <= op) {
            var src_pos = op - offset;
            if (offset >= match_len) {
                @memcpy(out_buf[op .. op + match_len], out_buf[src_pos .. src_pos + match_len]);
                op += match_len;
            } else {
                for (0..match_len) |_| {
                    out_buf[op] = out_buf[src_pos];
                    op += 1;
                    src_pos += 1;
                }
            }
        } else {
            // Pull prefix from dependent-block 64 KiB history dictionary
            const from_dict = offset - op;
            if (from_dict > dict.len) return error.CorruptStream;
            const dict_pos = dict.len - from_dict;
            const take_dict = @min(from_dict, match_len);
            @memcpy(out_buf[op .. op + take_dict], dict[dict_pos .. dict_pos + take_dict]);
            op += take_dict;
            const rem_match = match_len - take_dict;
            if (rem_match > 0) {
                var src_pos = op - offset;
                for (0..rem_match) |_| {
                    out_buf[op] = out_buf[src_pos];
                    op += 1;
                    src_pos += 1;
                }
            }
        }
    }

    return op;
}

pub const Lz4Decompressor = struct {
    allocator: std.mem.Allocator,
    upstream: *std.Io.Reader,

    in_frame: bool = false,
    eof: bool = false,
    block_independent: bool = true,
    has_block_checksum: bool = false,
    has_content_checksum: bool = false,
    has_content_size: bool = false,
    expected_content_size: u64 = 0,
    frame_decoded_bytes: u64 = 0,
    block_max_size: usize = 64 * 1024,
    content_hasher: XxHash32 = XxHash32.init(0),

    comp_buf: []u8 = &.{},
    out_buf: []u8 = &.{},
    out_pos: usize = 0,
    out_len: usize = 0,

    // 64 KiB history dictionary for dependent blocks
    dict_buf: []u8 = &.{},
    dict_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, upstream: *std.Io.Reader) Lz4Decompressor {
        return .{
            .allocator = allocator,
            .upstream = upstream,
        };
    }

    pub fn deinit(self: *Lz4Decompressor) void {
        if (self.comp_buf.len > 0) self.allocator.free(self.comp_buf);
        if (self.out_buf.len > 0) self.allocator.free(self.out_buf);
        if (self.dict_buf.len > 0) self.allocator.free(self.dict_buf);
        self.* = undefined;
    }

    fn ensureBuffers(self: *Lz4Decompressor, block_max: usize, need_dict: bool) Error!void {
        if (self.comp_buf.len < block_max) {
            if (self.comp_buf.len > 0) self.allocator.free(self.comp_buf);
            self.comp_buf = self.allocator.alloc(u8, block_max) catch return error.OutOfMemory;
        }
        if (self.out_buf.len < block_max) {
            if (self.out_buf.len > 0) self.allocator.free(self.out_buf);
            self.out_buf = self.allocator.alloc(u8, block_max) catch return error.OutOfMemory;
        }
        if (need_dict and self.dict_buf.len < 65536) {
            self.dict_buf = self.allocator.alloc(u8, 65536) catch return error.OutOfMemory;
        }
    }

    fn openNextFrame(self: *Lz4Decompressor) Error!bool {
        while (true) {
            var magic_bytes: [4]u8 = undefined;
            if (!(try readExact(self.upstream, &magic_bytes))) {
                self.eof = true;
                return false;
            }
            const magic = std.mem.readInt(u32, &magic_bytes, .little);
            if (magic >= lz4_skip_magic_lo and magic <= lz4_skip_magic_hi) {
                var len_bytes: [4]u8 = undefined;
                try readExactStrict(self.upstream, &len_bytes);
                const skip_len = std.mem.readInt(u32, &len_bytes, .little);
                try skipBytes(self.upstream, skip_len);
                continue;
            }
            if (magic != lz4_frame_magic) return error.CorruptStream;

            var hdr: [15]u8 = undefined;
            try readExactStrict(self.upstream, hdr[0..2]);
            const flg = hdr[0];
            const bd = hdr[1];

            // Version bits (7-6) must be 01
            if ((flg >> 6) != 1) return error.CorruptStream;
            // Reserved bit 1 must be 0
            if ((flg & 0x02) != 0) return error.CorruptStream;
            // BD reserved bits must be 0
            if ((bd & 0x8F) != 0) return error.CorruptStream;

            const block_id = (bd >> 4) & 0x07;
            const block_max: usize = switch (block_id) {
                4 => 64 * 1024,
                5 => 256 * 1024,
                6 => 1024 * 1024,
                7 => 4 * 1024 * 1024,
                else => return error.CorruptStream,
            };

            self.block_independent = (flg & 0x20) != 0;
            self.has_block_checksum = (flg & 0x10) != 0;
            self.has_content_size = (flg & 0x08) != 0;
            self.has_content_checksum = (flg & 0x04) != 0;
            const has_dict_id = (flg & 0x01) != 0;

            var hdr_len: usize = 2;
            if (self.has_content_size) {
                try readExactStrict(self.upstream, hdr[hdr_len .. hdr_len + 8]);
                self.expected_content_size = std.mem.readInt(u64, hdr[hdr_len..][0..8], .little);
                hdr_len += 8;
            } else {
                self.expected_content_size = 0;
            }
            if (has_dict_id) {
                try readExactStrict(self.upstream, hdr[hdr_len .. hdr_len + 4]);
                const dict_id = std.mem.readInt(u32, hdr[hdr_len..][0..4], .little);
                if (dict_id != 0) return error.CorruptStream; // external preset dictionaries not supported
                hdr_len += 4;
            }

            var hc_byte: [1]u8 = undefined;
            try readExactStrict(self.upstream, &hc_byte);
            const expected_hc: u8 = @truncate(std.hash.XxHash32.hash(0, hdr[0..hdr_len]) >> 8);
            if (hc_byte[0] != expected_hc) return error.CorruptStream;

            self.block_max_size = block_max;
            try self.ensureBuffers(block_max, !self.block_independent);
            self.dict_len = 0;
            self.frame_decoded_bytes = 0;
            self.content_hasher = XxHash32.init(0);
            self.in_frame = true;
            return true;
        }
    }

    fn updateDict(self: *Lz4Decompressor, chunk: []const u8) void {
        if (self.block_independent or chunk.len == 0) return;
        if (chunk.len >= 65536) {
            @memcpy(self.dict_buf[0..65536], chunk[chunk.len - 65536 ..]);
            self.dict_len = 65536;
        } else if (self.dict_len + chunk.len <= 65536) {
            @memcpy(self.dict_buf[self.dict_len .. self.dict_len + chunk.len], chunk);
            self.dict_len += chunk.len;
        } else {
            const keep = 65536 - chunk.len;
            @memmove(self.dict_buf[0..keep], self.dict_buf[self.dict_len - keep .. self.dict_len]);
            @memcpy(self.dict_buf[keep..65536], chunk);
            self.dict_len = 65536;
        }
    }

    fn refillBlock(self: *Lz4Decompressor) Error!bool {
        while (true) {
            if (!self.in_frame) {
                if (!(try self.openNextFrame())) return false;
            }

            var bsz_bytes: [4]u8 = undefined;
            try readExactStrict(self.upstream, &bsz_bytes);
            const raw_bsz = std.mem.readInt(u32, &bsz_bytes, .little);
            if (raw_bsz == 0) {
                // EndMark
                if (self.has_content_checksum) {
                    var csum_bytes: [4]u8 = undefined;
                    try readExactStrict(self.upstream, &csum_bytes);
                    const expected = std.mem.readInt(u32, &csum_bytes, .little);
                    if (self.content_hasher.final() != expected) return error.CorruptStream;
                }
                if (self.has_content_size and self.frame_decoded_bytes != self.expected_content_size) {
                    return error.CorruptStream;
                }
                self.in_frame = false;
                continue;
            }

            const is_uncompressed = (raw_bsz & 0x80000000) != 0;
            const block_len: usize = @intCast(raw_bsz & 0x7FFFFFFF);
            if (block_len > self.block_max_size) return error.CorruptStream;

            const read_target = if (is_uncompressed) self.out_buf[0..block_len] else self.comp_buf[0..block_len];
            try readExactStrict(self.upstream, read_target);

            if (self.has_block_checksum) {
                var bcs_bytes: [4]u8 = undefined;
                try readExactStrict(self.upstream, &bcs_bytes);
                const expected_bcs = std.mem.readInt(u32, &bcs_bytes, .little);
                if (std.hash.XxHash32.hash(0, read_target) != expected_bcs) return error.CorruptStream;
            }

            const dec_len: usize = if (is_uncompressed)
                block_len
            else
                try decompressBlock(read_target, self.out_buf[0..self.block_max_size], self.dict_buf[0..self.dict_len]);

            if (self.has_content_checksum) {
                self.content_hasher.update(self.out_buf[0..dec_len]);
            }
            self.frame_decoded_bytes += dec_len;
            self.updateDict(self.out_buf[0..dec_len]);
            self.out_pos = 0;
            self.out_len = dec_len;
            if (dec_len > 0) return true;
        }
    }

    pub fn read(self: *Lz4Decompressor, dest: []u8) Error!usize {
        if (dest.len == 0 or self.eof) return 0;
        if (self.out_pos >= self.out_len) {
            if (!(try self.refillBlock())) return 0;
        }
        const avail = self.out_len - self.out_pos;
        const n = @min(dest.len, avail);
        @memcpy(dest[0..n], self.out_buf[self.out_pos .. self.out_pos + n]);
        self.out_pos += n;
        return n;
    }
};

/// Encodes `payload` into a valid LZ4 Frame (using stored/uncompressed blocks + content checksum)
/// for deterministic self-contained unit tests.
pub fn compressLz4StoredAlloc(allocator: std.mem.Allocator, payload: []const u8) error{OutOfMemory}![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var magic_b: [4]u8 = undefined;
    std.mem.writeInt(u32, &magic_b, lz4_frame_magic, .little);
    try out.appendSlice(allocator, &magic_b);

    // FLG = 0x64 (version=01, B.Indep=1, C.Checksum=1), BD = 0x40 (64 KiB max block)
    const hdr = [2]u8{ 0x64, 0x40 };
    const hc: u8 = @truncate(std.hash.XxHash32.hash(0, &hdr) >> 8);
    try out.appendSlice(allocator, &hdr);
    try out.append(allocator, hc);

    var pos: usize = 0;
    while (pos < payload.len) {
        const chunk_len = @min(payload.len - pos, 64 * 1024);
        var bsz: [4]u8 = undefined;
        std.mem.writeInt(u32, &bsz, @as(u32, @intCast(chunk_len)) | 0x80000000, .little);
        try out.appendSlice(allocator, &bsz);
        try out.appendSlice(allocator, payload[pos .. pos + chunk_len]);
        pos += chunk_len;
    }

    // EndMark (0) + Content XXH32 checksum
    try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 });
    var csum: [4]u8 = undefined;
    std.mem.writeInt(u32, &csum, XxHash32.hash(0, payload), .little);
    try out.appendSlice(allocator, &csum);

    return out.toOwnedSlice(allocator);
}

test "lz4: XXH32, stored frame, compressed block with overlap, and checksum validation" {
    const alloc = std.testing.allocator;
    // Reference XXH32("") with seed 0 = 0x02CC5D05
    try std.testing.expectEqual(@as(u32, 0x02CC5D05), XxHash32.hash(0, ""));

    const payload = "alpha_beta_gamma_0123456789\nsecond line with LZ4 frame test!\n";
    const frame = try compressLz4StoredAlloc(alloc, payload);
    defer alloc.free(frame);

    var r = std.Io.Reader.fixed(frame);
    var dec = Lz4Decompressor.init(alloc, &r);
    defer dec.deinit();

    var out: [128]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try dec.read(out[total..]);
        if (n == 0) break;
        total += n;
    }
    try std.testing.expectEqualStrings(payload, out[0..total]);

    // Compressed block with overlapping RLE-style copy: literal "AB" (len 2), offset 2, match len 10 -> "ABABABABABAB"
    const comp_block = [_]u8{ (2 << 4) | 6, 'A', 'B', 2, 0 };
    var block_out: [32]u8 = undefined;
    const blen = try decompressBlock(&comp_block, &block_out, &.{});
    try std.testing.expectEqualStrings("ABABABABABAB", block_out[0..blen]);
}
