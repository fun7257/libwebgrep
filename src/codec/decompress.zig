//! [Module] codec/decompress.zig
//! [Layer] Layer 3 — Stream Codec & Bomb-Safe Decompression
//! [Role] In-process streaming decompression and decompression bomb protection (Gzip / Zstd / XZ).
//! [Invariants]
//!   1. Never spawn external decompression subprocesses (`gzip`/`zstd`/`xz` are strictly forbidden); 100% in-process streaming.
//!   2. Track decompressed byte count (`decompressed_bytes`) and compression ratio (`decompressed_bytes / raw_bytes`) in real time;
//!      immediately abort and return `error.DecompressLimit` once `max_decompressed_bytes` or `max_compression_ratio` is exceeded
//!      (recorded by Searcher as `LimitHit.decompressed_bytes`).
//!   3. Corrupt compressed streams never panic or raise fatal errors; they map to `error.CorruptStream` (recorded by Searcher as `SoftError.read_failed`).
//! [HotPath] `sniff` (branch-free header magic check) and `pumpDecompress`.

const std = @import("std");
pub const offset_map_mod = @import("offset_map.zig");
pub const OffsetMap = offset_map_mod.OffsetMap;
pub const SearchByteOffset = offset_map_mod.SearchByteOffset;
pub const RawByteOffset = offset_map_mod.RawByteOffset;
pub const lz4 = @import("lz4.zig");
pub const bzip2 = @import("bzip2.zig");
pub const brotli = @import("brotli.zig");

pub const Compression = enum {
    /// Do not decompress by default; process as a raw byte stream.
    none,
    /// Auto-detect Gzip (`1F 8B`), Zstd (`28 B5 2F FD`), XZ (`FD 37 7A 58 5A 00`), Bzip2 (`BZh[1-9]`), or LZ4 Frame (`04 22 4D 18`) by magic bytes.
    auto,
    /// Force Gzip (RFC 1952) decompression.
    gzip,
    /// Force Zstandard (RFC 8878) decompression.
    zstd,
    /// Force XZ container decompression.
    xz,
    /// Force zlib (RFC 1950) decompression.
    zlib,
    /// Force raw Deflate (RFC 1951) decompression.
    deflate,
    /// Force LZ4 Frame decompression.
    lz4,
    /// Force Bzip2 decompression.
    bzip2,
    /// Force Brotli (RFC 7932) decompression.
    brotli,
};

pub const Detected = enum {
    need_more,
    raw,
    gzip,
    zstd,
    xz,
    zlib,
    deflate,
    lz4,
    bzip2,
    brotli,
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

/// Sniff compression magic bytes at the beginning of a stream.
pub fn sniff(bytes: []const u8, eof: bool) Detected {
    if (bytes.len >= 2 and bytes[0] == 0x1F and bytes[1] == 0x8B) return .gzip;
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &.{ 0x28, 0xB5, 0x2F, 0xFD })) return .zstd;
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &.{ 0x04, 0x22, 0x4D, 0x18 })) return .lz4;
    if (bytes.len >= 4 and bytes[0] == 'B' and bytes[1] == 'Z' and bytes[2] == 'h' and bytes[3] >= '1' and bytes[3] <= '9') return .bzip2;
    if (bytes.len >= 6 and std.mem.eql(u8, bytes[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) return .xz;
    if (eof or bytes.len >= 6) return .raw;
    if (bytes.len == 0) return .need_more;
    if (bytes[0] == 0x1F or bytes[0] == 0x28 or bytes[0] == 0xFD or bytes[0] == 0x04 or bytes[0] == 'B') return .need_more;
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
        .zlib => .zlib,
        .deflate => .deflate,
        .lz4 => .lz4,
        .bzip2 => .bzip2,
        .brotli => .brotli,
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
        .zlib => {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var dec = std.compress.flate.Decompress.init(&in_reader, .zlib, &window);
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
        .deflate => {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var dec = std.compress.flate.Decompress.init(&in_reader, .raw, &window);
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
        .lz4 => {
            var dec = lz4.Lz4Decompressor.init(allocator, &in_reader);
            defer dec.deinit();
            try pumpCustomDecompress(
                lz4.Lz4Decompressor,
                allocator,
                &dec,
                &in_reader,
                compressed.len,
                &out_list,
                &total_decompressed,
                max_decompressed_bytes,
                ratio_cap,
                offset_map,
            );
        },
        .bzip2 => {
            var dec = bzip2.Bzip2Decompressor.init(allocator, &in_reader);
            defer dec.deinit();
            try pumpCustomDecompress(
                bzip2.Bzip2Decompressor,
                allocator,
                &dec,
                &in_reader,
                compressed.len,
                &out_list,
                &total_decompressed,
                max_decompressed_bytes,
                ratio_cap,
                offset_map,
            );
        },
        .brotli => {
            var dec = brotli.BrotliDecompressor.init(allocator, &in_reader);
            defer dec.deinit();
            try pumpCustomDecompress(
                brotli.BrotliDecompressor,
                allocator,
                &dec,
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
    var local_decompressed: u64 = 0;
    while (true) {
        const raw_before: u64 = @intCast(@min(raw_reader.seek, total_raw_len));
        const n = dec_reader.readSliceShort(&chunk) catch {
            @branchHint(.cold);
            return error.CorruptStream;
        };
        if (n == 0) break;

        const out_before: u64 = @intCast(out_list.items.len);
        try offset_map.record(allocator, out_before, raw_before);

        local_decompressed = std.math.add(u64, local_decompressed, n) catch return error.DecompressLimit;
        total_decompressed.* = std.math.add(u64, total_decompressed.*, n) catch return error.DecompressLimit;
        if (max_decompressed_bytes) |cap| {
            if (total_decompressed.* > cap) {
                @branchHint(.cold);
                return error.DecompressLimit;
            }
        }

        const raw_consumed: u64 = @max(1, @as(u64, @intCast(@min(raw_reader.seek, total_raw_len))));
        if (local_decompressed >= ratio_check_min_bytes) {
            const max_allowed = std.math.mul(u64, raw_consumed, ratio_cap) catch std.math.maxInt(u64);
            if (local_decompressed > max_allowed) {
                @branchHint(.cold);
                return error.DecompressLimit;
            }
        }

        try out_list.appendSlice(allocator, chunk[0..n]);
    }
    const final_out: u64 = @intCast(out_list.items.len);
    const final_raw: u64 = @intCast(@min(raw_reader.seek, total_raw_len));
    try offset_map.record(allocator, final_out, final_raw);
}

fn pumpCustomDecompress(
    comptime D: type,
    allocator: std.mem.Allocator,
    dec: *D,
    raw_reader: *const std.Io.Reader,
    total_raw_len: usize,
    out_list: *std.ArrayList(u8),
    total_decompressed: *u64,
    max_decompressed_bytes: ?u64,
    ratio_cap: u64,
    offset_map: *OffsetMap,
) Error!void {
    var chunk: [16384]u8 = undefined;
    var local_decompressed: u64 = 0;
    while (true) {
        const raw_before: u64 = @intCast(@min(raw_reader.seek, total_raw_len));
        const n = dec.read(&chunk) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                @branchHint(.cold);
                return error.CorruptStream;
            },
        };
        if (n == 0) break;

        const out_before: u64 = @intCast(out_list.items.len);
        try offset_map.record(allocator, out_before, raw_before);

        local_decompressed = std.math.add(u64, local_decompressed, n) catch return error.DecompressLimit;
        total_decompressed.* = std.math.add(u64, total_decompressed.*, n) catch return error.DecompressLimit;
        if (max_decompressed_bytes) |cap| {
            if (total_decompressed.* > cap) {
                @branchHint(.cold);
                return error.DecompressLimit;
            }
        }

        const raw_consumed: u64 = @max(1, @as(u64, @intCast(@min(raw_reader.seek, total_raw_len))));
        if (local_decompressed >= ratio_check_min_bytes) {
            const max_allowed = std.math.mul(u64, raw_consumed, ratio_cap) catch std.math.maxInt(u64);
            if (local_decompressed > max_allowed) {
                @branchHint(.cold);
                return error.DecompressLimit;
            }
        }

        try out_list.appendSlice(allocator, chunk[0..n]);
    }
    const final_out: u64 = @intCast(out_list.items.len);
    const final_raw: u64 = @intCast(@min(raw_reader.seek, total_raw_len));
    try offset_map.record(allocator, final_out, final_raw);
}

/// Helper to generate a valid Gzip byte stream (using Stored Deflate blocks + CRC32 + ISIZE) for unit tests constructing normal compressed streams and high-ratio bombs.
pub fn compressGzipStoredAlloc(allocator: std.mem.Allocator, payload: []const u8) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();

    var raw_buf: [4096]u8 = undefined;
    var raw = std.compress.flate.Compress.Raw.init(&out.writer, &raw_buf, .gzip) catch return error.OutOfMemory;
    raw.writer.writeAll(payload) catch return error.OutOfMemory;
    raw.finish() catch return error.OutOfMemory;

    return out.toOwnedSlice();
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

test {
    _ = offset_map_mod;
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

test {
    _ = lz4;
    _ = bzip2;
    _ = brotli;
}
