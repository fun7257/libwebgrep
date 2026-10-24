//! In-process streaming decompression and decompression bomb protection (Gzip / Zstd / XZ).
//!
//! Design invariants:
//! 1. Never spawn external decompression processes (`gzip`/`zstd`/`xz` subprocesses are strictly forbidden); 100% in-process streaming.
//! 2. Track decompressed byte count (`decompressed_bytes`) and compression ratio (`decompressed_bytes / raw_bytes`) in real time;
//!    immediately abort and return `error.DecompressLimit` once `max_decompressed_bytes` or `max_compression_ratio` is exceeded
//!    (recorded by Searcher as `LimitHit.decompressed_bytes`).
//! 3. Corrupt compressed streams never panic or raise fatal errors; they map to `error.CorruptStream` (recorded by Searcher as `SoftError.read_failed`).

const std = @import("std");

pub const Compression = enum {
    /// Do not decompress by default; process as a raw byte stream.
    none,
    /// Auto-detect Gzip (`1F 8B`), Zstd (`28 B5 2F FD`), or XZ (`FD 37 7A 58 5A 00`) by magic bytes at the start of the stream.
    auto,
    /// Force Gzip (RFC 1952) decompression.
    gzip,
    /// Force Zstandard (RFC 8878) decompression.
    zstd,
    /// Force XZ container decompression.
    xz,
};

pub const Detected = enum {
    need_more,
    raw,
    gzip,
    zstd,
    xz,
};

pub const default_max_compression_ratio: u64 = 100;
pub const max_compression_ratio_hard_cap: u64 = 1000;
/// Minimum decompressed bytes before enforcing the compression ratio check, avoiding false positives on tiny inputs due to header overhead.
pub const ratio_check_min_bytes: u64 = 64;

pub const Error = error{
    OutOfMemory,
    DecompressLimit,
    CorruptStream,
};

/// Block-level offset map: maps searchable stream offsets after decompression or transcoding back to raw input byte offsets.
pub const OffsetMap = struct {
    pub const Anchor = struct {
        out_offset: u64,
        raw_offset: u64,
    };

    anchors: std.ArrayList(Anchor) = .empty,
    /// Fixed leading offset (e.g., `base_raw_offset = 3` after stripping a 3-byte UTF-8 BOM).
    base_raw_offset: u64 = 0,
    active: bool = false,

    pub fn deinit(self: *OffsetMap, allocator: std.mem.Allocator) void {
        self.anchors.deinit(allocator);
        self.* = .{};
    }

    pub fn record(self: *OffsetMap, allocator: std.mem.Allocator, out_offset: u64, raw_offset: u64) error{OutOfMemory}!void {
        self.active = true;
        if (self.anchors.items.len > 0) {
            const last = &self.anchors.items[self.anchors.items.len - 1];
            if (last.out_offset == out_offset) {
                last.raw_offset = raw_offset;
                return;
            }
            if (out_offset < last.out_offset) return;
        }
        try self.anchors.append(allocator, .{
            .out_offset = out_offset,
            .raw_offset = raw_offset,
        });
    }

    /// Given an absolute offset `out_offset` in the searchable stream, returns the corresponding raw byte stream offset.
    pub fn map(self: *const OffsetMap, out_offset: u64) u64 {
        if (!self.active) return out_offset + self.base_raw_offset;
        const items = self.anchors.items;
        if (items.len == 0) return out_offset + self.base_raw_offset;

        // Binary search for the last `anchor.out_offset <= out_offset`
        var lo: usize = 0;
        var hi: usize = items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (items[mid].out_offset <= out_offset) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo == 0) return items[0].raw_offset;
        const idx = lo - 1;
        const cur = items[idx];
        if (idx + 1 < items.len) {
            const next = items[idx + 1];
            if (next.out_offset > cur.out_offset and next.raw_offset == cur.raw_offset) {
                // Bytes produced within the same compressed block map back to the starting raw offset of that block
                return cur.raw_offset;
            }
            if (next.out_offset > cur.out_offset and next.raw_offset > cur.raw_offset) {
                const out_span = next.out_offset - cur.out_offset;
                const raw_span = next.raw_offset - cur.raw_offset;
                const rel = out_offset - cur.out_offset;
                if (raw_span == out_span) return cur.raw_offset + rel;
                return cur.raw_offset + (rel * raw_span) / out_span;
            }
        }
        return cur.raw_offset;
    }
};

/// Sniff compression magic bytes at the beginning of a stream.
pub fn sniff(bytes: []const u8, eof: bool) Detected {
    if (bytes.len >= 2 and bytes[0] == 0x1F and bytes[1] == 0x8B) return .gzip;
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &.{ 0x28, 0xB5, 0x2F, 0xFD })) return .zstd;
    if (bytes.len >= 6 and std.mem.eql(u8, bytes[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) return .xz;
    if (eof or bytes.len >= 6) return .raw;
    if (bytes.len == 0) return .need_more;
    if (bytes[0] == 0x1F or bytes[0] == 0x28 or bytes[0] == 0xFD) return .need_more;
    return .raw;
}

/// Decompress a slice in memory in a streaming fashion, enforcing `max_decompressed_bytes` and `max_compression_ratio` bomb checks in real time,
/// while recording block-level offset anchors into `offset_map`.
pub fn decompressSlice(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    mode: Compression,
    initial_decompressed: u64,
    max_decompressed_bytes: ?u64,
    max_compression_ratio: ?u64,
    decompressed_out: *u64,
    offset_map: *OffsetMap,
) Error!?[]u8 {
    const format: Detected = switch (mode) {
        .none => return null,
        .gzip => .gzip,
        .zstd => .zstd,
        .xz => .xz,
        .auto => sniff(compressed, true),
    };
    if (format == .raw or format == .need_more) return null;

    const ratio_cap = max_compression_ratio orelse default_max_compression_ratio;
    var out_list = std.ArrayList(u8).empty;
    errdefer out_list.deinit(allocator);

    var in_reader = std.Io.Reader.fixed(compressed);
    var total_decompressed: u64 = initial_decompressed;
    try offset_map.record(allocator, 0, 0);

    switch (format) {
        .gzip => {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var dec = std.compress.flate.Decompress.init(&in_reader, .gzip, &window);
            try pumpDecompress(
                allocator,
                &dec.reader,
                &in_reader,
                compressed.len,
                &out_list,
                &total_decompressed,
                max_decompressed_bytes,
                ratio_cap,
                offset_map,
            );
        },
        .zstd => {
            const win_buf = try allocator.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
            defer allocator.free(win_buf);
            var dec = std.compress.zstd.Decompress.init(&in_reader, win_buf, .{});
            try pumpDecompress(
                allocator,
                &dec.reader,
                &in_reader,
                compressed.len,
                &out_list,
                &total_decompressed,
                max_decompressed_bytes,
                ratio_cap,
                offset_map,
            );
        },
        .xz => {
            var dec = std.compress.xz.Decompress.init(&in_reader, allocator, &.{}) catch return error.CorruptStream;
            defer allocator.free(dec.reader.buffer);
            try pumpDecompress(
                allocator,
                &dec.reader,
                &in_reader,
                compressed.len,
                &out_list,
                &total_decompressed,
                max_decompressed_bytes,
                ratio_cap,
                offset_map,
            );
        },
        .raw, .need_more => unreachable,
    }

    decompressed_out.* = total_decompressed;
    return try out_list.toOwnedSlice(allocator);
}

fn pumpDecompress(
    allocator: std.mem.Allocator,
    dec_reader: *std.Io.Reader,
    raw_reader: *const std.Io.Reader,
    total_raw_len: usize,
    out_list: *std.ArrayList(u8),
    total_decompressed: *u64,
    max_decompressed_bytes: ?u64,
    ratio_cap: u64,
    offset_map: *OffsetMap,
) Error!void {
    var chunk: [16384]u8 = undefined;
    while (true) {
        const raw_before: u64 = @intCast(@min(raw_reader.seek, total_raw_len));
        const n = dec_reader.readSliceShort(&chunk) catch {
            return error.CorruptStream;
        };
        if (n == 0) break;

        const out_before: u64 = @intCast(out_list.items.len);
        try offset_map.record(allocator, out_before, raw_before);

        total_decompressed.* = std.math.add(u64, total_decompressed.*, n) catch return error.DecompressLimit;
        if (max_decompressed_bytes) |cap| {
            if (total_decompressed.* > cap) return error.DecompressLimit;
        }

        const raw_consumed: u64 = @max(1, @as(u64, @intCast(@min(raw_reader.seek, total_raw_len))));
        if (total_decompressed.* >= ratio_check_min_bytes) {
            const max_allowed = std.math.mul(u64, raw_consumed, ratio_cap) catch std.math.maxInt(u64);
            if (total_decompressed.* > max_allowed) return error.DecompressLimit;
        }

        try out_list.appendSlice(allocator, chunk[0..n]);
    }
}

/// Helper to generate a valid Gzip byte stream (using Stored Deflate blocks + CRC32 + ISIZE) for unit tests constructing normal compressed streams and high-ratio bombs.
pub fn compressGzipStoredAlloc(allocator: std.mem.Allocator, payload: []const u8) error{OutOfMemory}![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    // 10-byte Gzip header
    try out.appendSlice(allocator, &[_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 });

    var pos: usize = 0;
    while (true) {
        const rem = payload.len - pos;
        const block_len: u16 = @intCast(@min(rem, 65535));
        const is_final: u8 = if (pos + block_len >= payload.len) 1 else 0;
        try out.append(allocator, is_final); // BFINAL=is_final, BTYPE=00 (stored)
        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u16, len_bytes[0..2], block_len, .little);
        std.mem.writeInt(u16, len_bytes[2..4], ~block_len, .little);
        try out.appendSlice(allocator, &len_bytes);
        try out.appendSlice(allocator, payload[pos .. pos + block_len]);
        pos += block_len;
        if (is_final == 1) break;
    }

    var crc = std.hash.Crc32.init();
    crc.update(payload);
    var footer: [8]u8 = undefined;
    std.mem.writeInt(u32, footer[0..4], crc.final(), .little);
    std.mem.writeInt(u32, footer[4..8], @truncate(payload.len), .little);
    try out.appendSlice(allocator, &footer);

    return out.toOwnedSlice(allocator);
}

/// Helper to generate a valid Zstd frame (uncompressed Raw Block) for unit tests.
pub fn compressZstdRawAlloc(allocator: std.mem.Allocator, payload: []const u8) error{OutOfMemory}![]u8 {
    std.debug.assert(payload.len <= (1 << 17) - 1);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    // Zstd Frame Magic (4B): 0x28, 0xB5, 0x2F, 0xFD
    try out.appendSlice(allocator, &[_]u8{ 0x28, 0xB5, 0x2F, 0xFD });
    // Frame_Header_Descriptor: Single_Segment_Flag = 1 (bit 5 = 0x20), FCS_Field_Size = 0 (1 byte FCS) if <=255 else 1 (2 bytes)
    if (payload.len <= 255) {
        try out.append(allocator, 0x20);
        try out.append(allocator, @intCast(payload.len));
    } else {
        try out.append(allocator, 0x60); // Single_Segment_Flag=1, FCS_Field_Size=1 (2B, +256)
        var fcs: [2]u8 = undefined;
        std.mem.writeInt(u16, &fcs, @intCast(payload.len - 256), .little);
        try out.appendSlice(allocator, &fcs);
    }
    // Block_Header (3B little-endian): Last_Block=1 (bit 0), Block_Type=0 (Raw_Block, bits 1..2), Block_Size=payload.len (bits 3..23)
    const bh: u24 = (@as(u24, @intCast(payload.len)) << 3) | 1;
    var bh_bytes: [3]u8 = undefined;
    std.mem.writeInt(u24, &bh_bytes, bh, .little);
    try out.appendSlice(allocator, &bh_bytes);
    try out.appendSlice(allocator, payload);

    return out.toOwnedSlice(allocator);
}

test "Gzip decompression and bomb limit enforcement" {
    const text = "line1\nMATCH_GZIP\nline3\n";
    const gz = try compressGzipStoredAlloc(std.testing.allocator, text);
    defer std.testing.allocator.free(gz);

    var dec_bytes: u64 = 0;
    var map = OffsetMap{};
    defer map.deinit(std.testing.allocator);

    const out = (try decompressSlice(
        std.testing.allocator,
        gz,
        .auto,
        0,
        1024,
        100,
        &dec_bytes,
        &map,
    )).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(text, out);
    try std.testing.expectEqual(@as(u64, text.len), dec_bytes);

    // Simulate a high-compression-ratio Gzip bomb (a short compressed stream inflating to 1032 'A' bytes, immediately blocked when the ratio cap is low)
    const bomb_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x73, 0x74, 0xa4, 0x3d, 0x00, 0x00, 0x8d, 0xef, 0x72, 0x2f,
        0x08, 0x04, 0x00, 0x00,
    };
    var bomb_bytes: u64 = 0;
    var bomb_map = OffsetMap{};
    defer bomb_map.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.DecompressLimit,
        decompressSlice(std.testing.allocator, &bomb_gz, .gzip, 0, null, 3, &bomb_bytes, &bomb_map),
    );
}

test "Zstd decompression and corrupt stream handling" {
    const text = "hello zstd\nMATCH_ZSTD\n";
    const zst = try compressZstdRawAlloc(std.testing.allocator, text);
    defer std.testing.allocator.free(zst);

    var dec_bytes: u64 = 0;
    var map = OffsetMap{};
    defer map.deinit(std.testing.allocator);

    const out = (try decompressSlice(
        std.testing.allocator,
        zst,
        .auto,
        0,
        1024,
        100,
        &dec_bytes,
        &map,
    )).?;
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(text, out);

    // A corrupt Zstd frame must return error.CorruptStream
    const corrupt_zst = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF, 0xFF };
    try std.testing.expectError(
        error.CorruptStream,
        decompressSlice(std.testing.allocator, &corrupt_zst, .auto, 0, 1024, 100, &dec_bytes, &map),
    );
}
