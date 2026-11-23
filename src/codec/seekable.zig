//! [Module] codec/seekable.zig
//! [Layer] Layer 3 — Seekable Compressed Random Access (`ZstdSeekTable` & `GzipIndex`)
//! [Role] Provides O(log F) / O(log C) random access over Seekable Zstandard streams (official
//!        tail skippable frame `0x184D2A5E` / `0x8F92EAB1`) and multi-member / multi-block Gzip
//!        streams (pure-Zig RFC 1951 Deflate checkpoint indexer & resuming decoder), exposing
//!        `probe.RandomAccess` views for sub-millisecond byte-offset line probing (`probeLineAt`).
//! [Invariants]
//!   1. Zero filesystem file or directory handle references; all positional I/O uses `probe.RandomAccess`.
//!   2. `ZstdSeekTable.parseFromRandomAccess` reads ONLY the trailing skippable seek-table bytes.
//!   3. Corrupt headers, truncated streams, invalid Huffman codes, bad checksums, and decompression
//!      ratio violations never panic and return typed errors (`CorruptSeekTable`, `CorruptStream`,
//!      `CorruptIndex`, `DecompressLimit`).

const std = @import("std");
pub const probe = @import("../probe.zig");
pub const decompress = @import("decompress.zig");

pub const zstd_frame_magic: u32 = 0xFD2FB528;
pub const zstd_skippable_magic_min: u32 = 0x184D2A50;
pub const zstd_skippable_magic_max: u32 = 0x184D2A5F;
pub const zstd_seek_table_magic: u32 = 0x184D2A5E;
pub const zstd_seek_footer_magic: u32 = 0x8F92EAB1;

/// Maximum serialized seek-table / checkpoint-index allocation cap (64 MiB) against malformed headers.
pub const max_seek_table_bytes: u64 = 64 * 1024 * 1024;
pub const default_gzip_checkpoint_interval: u64 = 64 * 1024;

pub const Error = error{
    OutOfMemory,
    CorruptSeekTable,
    CorruptStream,
    CorruptIndex,
    DecompressLimit,
    MissingSourceSize,
    InvalidFrameSize,
    FrameTooLarge,
};

pub const XxHash64 = std.hash.XxHash64;

// ============================================================================
// Zstandard Seekable Format (`ZstdSeekTable` & `SeekableZstdReader`)
// ============================================================================

pub const ZstdSeekTable = struct {
    pub const FrameEntry = struct {
        frame_index: u32,
        comp_offset: u64,
        compressed_size: u32,
        uncomp_offset: u64,
        uncompressed_size: u32,
        checksum: ?u32 = null,
    };

    entries: []FrameEntry = &.{},
    has_checksum: bool = false,
    total_compressed_size: u64 = 0,
    total_uncompressed_size: u64 = 0,

    pub fn deinit(self: *ZstdSeekTable, allocator: std.mem.Allocator) void {
        if (self.entries.len != 0) {
            allocator.free(self.entries);
        }
        self.* = undefined;
    }

    /// Parses an official Zstd Seekable Format tail skippable frame (`0x184D2A5E` .. `0x8F92EAB1`)
    /// from either a standalone seek-table slice or a complete seekable `.zst` slice.
    pub fn parseFromSlice(allocator: std.mem.Allocator, bytes: []const u8) !ZstdSeekTable {
        if (bytes.len < 17) return error.CorruptSeekTable;
        const footer = bytes[bytes.len - 9 ..][0..9];
        const info = try parseFooter(footer);
        if (info.skippable_total > bytes.len) return error.CorruptSeekTable;

        const st_start: usize = bytes.len - @as(usize, @intCast(info.skippable_total));
        const st_bytes = bytes[st_start..];
        const table = try parseSeekTableBody(allocator, st_bytes[0 .. st_bytes.len - 9], info);
        errdefer {
            var tmp = table;
            tmp.deinit(allocator);
        }
        // When embedded at the end of a compressed Zstd stream, frame compressed sizes cannot exceed st_start.
        if (st_start > 0 and table.total_compressed_size > st_start) {
            return error.CorruptSeekTable;
        }
        return table;
    }

    /// Parses the Zstd Seekable Format tail skippable frame via `RandomAccess`, reading ONLY the
    /// trailing seek-table bytes at the end of `source` without scanning compressed frames.
    pub fn parseFromRandomAccess(allocator: std.mem.Allocator, source: probe.RandomAccess) !ZstdSeekTable {
        const total_size = source.size orelse return error.MissingSourceSize;
        if (total_size < 17) return error.CorruptSeekTable;

        var footer: [9]u8 = undefined;
        const fn_read = try source.readAtFull(total_size - 9, &footer);
        if (fn_read != 9) return error.CorruptSeekTable;

        const info = try parseFooter(&footer);
        if (info.skippable_total > total_size) return error.CorruptSeekTable;

        const st_offset: u64 = total_size - info.skippable_total;
        const body_len: usize = @intCast(info.skippable_total - 9);
        const body_buf = try allocator.alloc(u8, body_len);
        defer allocator.free(body_buf);

        const body_read = try source.readAtFull(st_offset, body_buf);
        if (body_read != body_len) return error.CorruptSeekTable;

        const table = try parseSeekTableBody(allocator, body_buf, info);
        errdefer {
            var tmp = table;
            tmp.deinit(allocator);
        }
        if (st_offset > 0 and table.total_compressed_size > st_offset) {
            return error.CorruptSeekTable;
        }
        return table;
    }

    const FooterInfo = struct {
        num_frames: u32,
        has_checksum: bool,
        entry_size: usize,
        entries_bytes: u64,
        expected_frame_size: u64,
        skippable_total: u64,
    };

    fn parseFooter(footer: *const [9]u8) Error!FooterInfo {
        const num_frames = std.mem.readInt(u32, footer[0..4], .little);
        const descriptor = footer[4];
        const footer_magic = std.mem.readInt(u32, footer[5..9], .little);
        if (footer_magic != zstd_seek_footer_magic) return error.CorruptSeekTable;
        // Bits 2..6 are reserved and must be 0 per Zstd Seekable Format specification.
        if ((descriptor & 0x7C) != 0) return error.CorruptSeekTable;

        const has_checksum = (descriptor & 0x80) != 0;
        const entry_size: u64 = if (has_checksum) 12 else 8;
        const entries_bytes = std.math.mul(u64, num_frames, entry_size) catch return error.CorruptSeekTable;
        if (entries_bytes > max_seek_table_bytes) return error.CorruptSeekTable;

        const expected_frame_size = std.math.add(u64, entries_bytes, 9) catch return error.CorruptSeekTable;
        if (expected_frame_size > std.math.maxInt(u32)) return error.CorruptSeekTable;
        const skippable_total = std.math.add(u64, expected_frame_size, 8) catch return error.CorruptSeekTable;

        return .{
            .num_frames = num_frames,
            .has_checksum = has_checksum,
            .entry_size = @intCast(entry_size),
            .entries_bytes = entries_bytes,
            .expected_frame_size = expected_frame_size,
            .skippable_total = skippable_total,
        };
    }

    fn parseSeekTableBody(allocator: std.mem.Allocator, body: []const u8, info: FooterInfo) Error!ZstdSeekTable {
        if (body.len != 8 + @as(usize, @intCast(info.entries_bytes))) return error.CorruptSeekTable;
        const skip_magic = std.mem.readInt(u32, body[0..4], .little);
        const frame_size = std.mem.readInt(u32, body[4..8], .little);
        if (skip_magic != zstd_seek_table_magic) return error.CorruptSeekTable;
        if (@as(u64, frame_size) != info.expected_frame_size) return error.CorruptSeekTable;

        const entries = try allocator.alloc(FrameEntry, info.num_frames);
        errdefer allocator.free(entries);

        var comp_off: u64 = 0;
        var uncomp_off: u64 = 0;
        var pos: usize = 8;

        for (entries, 0..) |*e, idx| {
            const c_size = std.mem.readInt(u32, body[pos..][0..4], .little);
            const u_size = std.mem.readInt(u32, body[pos + 4 ..][0..4], .little);
            const csum: ?u32 = if (info.has_checksum)
                std.mem.readInt(u32, body[pos + 8 ..][0..4], .little)
            else
                null;
            pos += info.entry_size;

            e.* = .{
                .frame_index = @intCast(idx),
                .comp_offset = comp_off,
                .compressed_size = c_size,
                .uncomp_offset = uncomp_off,
                .uncompressed_size = u_size,
                .checksum = csum,
            };
            comp_off = std.math.add(u64, comp_off, c_size) catch return error.CorruptSeekTable;
            uncomp_off = std.math.add(u64, uncomp_off, u_size) catch return error.CorruptSeekTable;
        }

        return .{
            .entries = entries,
            .has_checksum = info.has_checksum,
            .total_compressed_size = comp_off,
            .total_uncompressed_size = uncomp_off,
        };
    }

    /// Scans concatenated Zstd frames in `zst_bytes`, decompressing each frame to compute its exact
    /// uncompressed length and 32-bit XXH64 checksum. Any trailing seek-table skippable frame is ignored.
    pub fn buildFromSlice(allocator: std.mem.Allocator, zst_bytes: []const u8) Error!ZstdSeekTable {
        var list = std.ArrayList(FrameEntry).empty;
        errdefer list.deinit(allocator);

        const win_buf = try allocator.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
        defer allocator.free(win_buf);

        var pos: usize = 0;
        var comp_off: u64 = 0;
        var uncomp_off: u64 = 0;

        while (pos < zst_bytes.len) {
            if (zst_bytes.len - pos < 8) return error.CorruptStream;
            const magic = std.mem.readInt(u32, zst_bytes[pos..][0..4], .little);

            if (magic >= zstd_skippable_magic_min and magic <= zstd_skippable_magic_max) {
                const skip_payload = std.mem.readInt(u32, zst_bytes[pos + 4 ..][0..4], .little);
                const skip_total = std.math.add(usize, 8, @intCast(skip_payload)) catch return error.CorruptStream;
                if (skip_total > zst_bytes.len - pos) return error.CorruptStream;

                // Stop if this is the trailing Zstd Seek Table frame
                if (magic == zstd_seek_table_magic and pos + skip_total == zst_bytes.len and skip_total >= 17) {
                    const tail_footer = zst_bytes[zst_bytes.len - 9 ..][0..9];
                    if (std.mem.readInt(u32, tail_footer[5..9], .little) == zstd_seek_footer_magic) {
                        break;
                    }
                }

                const c_u32 = std.math.cast(u32, skip_total) orelse return error.FrameTooLarge;
                try list.append(allocator, .{
                    .frame_index = @intCast(list.items.len),
                    .comp_offset = comp_off,
                    .compressed_size = c_u32,
                    .uncomp_offset = uncomp_off,
                    .uncompressed_size = 0,
                    .checksum = @truncate(XxHash64.hash(0, "")),
                });
                comp_off += c_u32;
                pos += skip_total;
                continue;
            }

            if (magic != zstd_frame_magic) return error.CorruptStream;

            const frame_len = try scanZstdFrameLength(zst_bytes[pos..]);
            const c_u32 = std.math.cast(u32, frame_len) orelse return error.FrameTooLarge;
            const frame_slice = zst_bytes[pos .. pos + frame_len];

            // Decompress single frame to verify integrity and obtain uncompressed size + XXH64 checksum
            var in_reader = std.Io.Reader.fixed(frame_slice);
            var dec = std.compress.zstd.Decompress.init(&in_reader, win_buf, .{});
            var xxh = XxHash64.init(0);
            var chunk: [16384]u8 = undefined;
            var frame_uncomp: u64 = 0;

            while (true) {
                const n = dec.reader.readSliceShort(&chunk) catch return error.CorruptStream;
                if (n == 0) break;
                frame_uncomp = std.math.add(u64, frame_uncomp, n) catch return error.FrameTooLarge;
                if (frame_uncomp > std.math.maxInt(u32)) return error.FrameTooLarge;
                xxh.update(chunk[0..n]);
            }

            const u_u32: u32 = @intCast(frame_uncomp);
            try list.append(allocator, .{
                .frame_index = @intCast(list.items.len),
                .comp_offset = comp_off,
                .compressed_size = c_u32,
                .uncomp_offset = uncomp_off,
                .uncompressed_size = u_u32,
                .checksum = @truncate(xxh.final()),
            });

            comp_off = std.math.add(u64, comp_off, c_u32) catch return error.FrameTooLarge;
            uncomp_off = std.math.add(u64, uncomp_off, u_u32) catch return error.FrameTooLarge;
            pos += frame_len;
        }

        const owned = try list.toOwnedSlice(allocator);
        return .{
            .entries = owned,
            .has_checksum = true,
            .total_compressed_size = comp_off,
            .total_uncompressed_size = uncomp_off,
        };
    }

    /// Serializes this table as an official Zstd Seekable Format skippable frame (`0x184D2A5E`).
    pub fn serializeAlloc(self: *const ZstdSeekTable, allocator: std.mem.Allocator) Error![]u8 {
        if (self.entries.len > std.math.maxInt(u32)) return error.FrameTooLarge;
        const entry_size: usize = if (self.has_checksum) 12 else 8;
        const entries_bytes = std.math.mul(usize, self.entries.len, entry_size) catch return error.OutOfMemory;
        const frame_payload = std.math.add(usize, entries_bytes, 9) catch return error.OutOfMemory;
        if (frame_payload > std.math.maxInt(u32)) return error.FrameTooLarge;
        const total_len = std.math.add(usize, 8, frame_payload) catch return error.OutOfMemory;

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);

        std.mem.writeInt(u32, out[0..4], zstd_seek_table_magic, .little);
        std.mem.writeInt(u32, out[4..8], @intCast(frame_payload), .little);

        var pos: usize = 8;
        for (self.entries) |e| {
            std.mem.writeInt(u32, out[pos..][0..4], e.compressed_size, .little);
            std.mem.writeInt(u32, out[pos + 4 ..][0..4], e.uncompressed_size, .little);
            if (self.has_checksum) {
                std.mem.writeInt(u32, out[pos + 8 ..][0..4], e.checksum orelse 0, .little);
            }
            pos += entry_size;
        }

        std.mem.writeInt(u32, out[pos..][0..4], @intCast(self.entries.len), .little);
        out[pos + 4] = if (self.has_checksum) 0x80 else 0x00;
        std.mem.writeInt(u32, out[pos + 5 ..][0..4], zstd_seek_footer_magic, .little);

        return out;
    }

    /// Locates the frame containing `uncomp_offset` in O(log F) binary search.
    pub fn locateOffset(self: *const ZstdSeekTable, uncomp_offset: u64) ?FrameEntry {
        if (uncomp_offset >= self.total_uncompressed_size or self.entries.len == 0) return null;

        // Find the first entry with (uncomp_offset + uncompressed_size) > target.
        const lo = std.sort.partitionPoint(FrameEntry, self.entries, uncomp_offset, struct {
            fn pred(target: u64, e: FrameEntry) bool {
                return e.uncomp_offset + @as(u64, e.uncompressed_size) <= target;
            }
        }.pred);
        if (lo >= self.entries.len) return null;
        return self.entries[lo];
    }

    /// Reads uncompressed bytes starting at `uncomp_offset` into `dest`, decompressing only the
    /// overlapping Zstd frame(s) via `source` and enforcing `max_ratio` + optional XXH64 checksums.
    pub fn readAt(
        self: *const ZstdSeekTable,
        allocator: std.mem.Allocator,
        source: probe.RandomAccess,
        uncomp_offset: u64,
        dest: []u8,
        max_ratio: ?u64,
    ) anyerror!usize {
        if (dest.len == 0 or uncomp_offset >= self.total_uncompressed_size) return 0;
        const first = self.locateOffset(uncomp_offset) orelse return 0;
        const ratio_cap = max_ratio orelse decompress.default_max_compression_ratio;

        const win_buf = try allocator.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
        defer allocator.free(win_buf);

        var filled: usize = 0;
        var cur_idx: usize = first.frame_index;
        var cur_uncomp: u64 = uncomp_offset;

        while (filled < dest.len and cur_idx < self.entries.len and cur_uncomp < self.total_uncompressed_size) : (cur_idx += 1) {
            const entry = self.entries[cur_idx];
            if (entry.uncompressed_size == 0) continue;

            if (entry.uncompressed_size >= decompress.ratio_check_min_bytes) {
                const raw_base: u64 = @max(1, @as(u64, entry.compressed_size));
                const max_allowed = std.math.mul(u64, raw_base, ratio_cap) catch std.math.maxInt(u64);
                if (entry.uncompressed_size > max_allowed) return error.DecompressLimit;
            }

            if (source.size) |sz| {
                const comp_end = std.math.add(u64, entry.comp_offset, entry.compressed_size) catch return error.CorruptStream;
                if (comp_end > sz) return error.CorruptStream;
            }
            if (entry.compressed_size > max_seek_table_bytes) return error.CorruptStream;

            const comp_buf = try allocator.alloc(u8, entry.compressed_size);
            defer allocator.free(comp_buf);
            const got_comp = try source.readAtFull(entry.comp_offset, comp_buf);
            if (got_comp != entry.compressed_size) return error.CorruptStream;

            var in_reader = std.Io.Reader.fixed(comp_buf);
            var dec = std.compress.zstd.Decompress.init(&in_reader, win_buf, .{});

            const rel_start: usize = @intCast(cur_uncomp - entry.uncomp_offset);
            const avail_in_frame: usize = @as(usize, entry.uncompressed_size) - rel_start;
            const to_copy: usize = @min(dest.len - filled, avail_in_frame);

            var chunk: [16384]u8 = undefined;
            var decoded_pos: usize = 0;
            var xxh = XxHash64.init(0);
            const check_csum = entry.checksum != null;

            while (true) {
                if (!check_csum and decoded_pos >= rel_start + to_copy) break;
                const n = dec.reader.readSliceShort(&chunk) catch return error.CorruptStream;
                if (n == 0) break;
                if (decoded_pos + n > entry.uncompressed_size) return error.CorruptStream;

                const next_pos = decoded_pos + n;
                if (next_pos >= decompress.ratio_check_min_bytes) {
                    const raw_base: u64 = @max(1, @as(u64, entry.compressed_size));
                    const max_allowed = std.math.mul(u64, raw_base, ratio_cap) catch std.math.maxInt(u64);
                    if (next_pos > max_allowed) return error.DecompressLimit;
                }
                if (check_csum) {
                    xxh.update(chunk[0..n]);
                }

                const copy_lo = @max(decoded_pos, rel_start);
                const copy_hi = @min(next_pos, rel_start + to_copy);
                if (copy_hi > copy_lo) {
                    const dst_off = filled + (copy_lo - rel_start);
                    @memcpy(dest[dst_off .. dst_off + (copy_hi - copy_lo)], chunk[copy_lo - decoded_pos .. copy_hi - decoded_pos]);
                }
                decoded_pos = next_pos;
            }

            if (check_csum) {
                if (decoded_pos != entry.uncompressed_size) return error.CorruptStream;
                const actual_csum: u32 = @truncate(xxh.final());
                if (actual_csum != entry.checksum.?) return error.CorruptStream;
            } else if (decoded_pos < rel_start + to_copy) {
                return error.CorruptStream;
            }

            filled += to_copy;
            cur_uncomp += to_copy;
        }

        return filled;
    }
};

/// Adapter wrapping `ZstdSeekTable` + compressed `probe.RandomAccess` into an uncompressed `probe.RandomAccess`.
pub const SeekableZstdReader = struct {
    allocator: std.mem.Allocator,
    source: probe.RandomAccess,
    table: *const ZstdSeekTable,
    max_ratio: ?u64 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        source: probe.RandomAccess,
        table: *const ZstdSeekTable,
    ) SeekableZstdReader {
        return .{
            .allocator = allocator,
            .source = source,
            .table = table,
        };
    }

    pub fn deinit(self: *SeekableZstdReader) void {
        self.* = undefined;
    }

    pub fn readAt(self: *const SeekableZstdReader, uncomp_offset: u64, dest: []u8) anyerror!usize {
        return self.table.readAt(self.allocator, self.source, uncomp_offset, dest, self.max_ratio);
    }

    pub fn randomAccess(self: *const SeekableZstdReader) probe.RandomAccess {
        return .{
            .ctx = @ptrCast(@constCast(self)),
            .read_at = readAtErased,
            .size = self.table.total_uncompressed_size,
        };
    }

    fn readAtErased(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *const SeekableZstdReader = @ptrCast(@alignCast(ctx.?));
        return self.readAt(offset, dest);
    }
};

fn scanZstdFrameLength(buf: []const u8) Error!usize {
    const ZstdFrame = std.compress.zstd.Decompress.Frame;
    var reader = std.Io.Reader.fixed(buf);
    const magic = reader.takeInt(u32, .little) catch return error.CorruptStream;
    if (magic != @backingInt(ZstdFrame.Zstandard.magic)) return error.CorruptStream;

    const header = ZstdFrame.Zstandard.Header.decode(&reader) catch return error.CorruptStream;

    while (true) {
        const bh = reader.takeStruct(ZstdFrame.Zstandard.Block.Header, .little) catch return error.CorruptStream;
        const payload_bytes: usize = switch (bh.type) {
            .raw => bh.size,
            .rle => 1,
            .compressed => bh.size,
            .reserved => return error.CorruptStream,
        };
        reader.discardAll(payload_bytes) catch return error.CorruptStream;
        if (bh.last) break;
    }

    if (header.descriptor.content_checksum_flag) {
        reader.discardAll(4) catch return error.CorruptStream;
    }
    return reader.seek;
}

/// Compresses `payload` as independent Zstd frames of at most `max_frame_size` uncompressed bytes
/// followed by an official Zstd Seekable Format tail skippable frame (`0x184D2A5E` + XXH64 checksums).
pub fn compressSeekableZstdAlloc(
    allocator: std.mem.Allocator,
    payload: []const u8,
    max_frame_size: usize,
) Error![]u8 {
    if (max_frame_size == 0 or max_frame_size > std.math.maxInt(u32)) return error.InvalidFrameSize;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var entries = std.ArrayList(ZstdSeekTable.FrameEntry).empty;
    defer entries.deinit(allocator);

    var pos: usize = 0;
    var comp_off: u64 = 0;
    var uncomp_off: u64 = 0;

    while (pos < payload.len) {
        const frame_uncomp_len = @min(payload.len - pos, max_frame_size);
        const frame_data = payload[pos .. pos + frame_uncomp_len];
        const frame_start = out.items.len;

        try appendZstdRawFrame(allocator, &out, frame_data);

        const comp_len = out.items.len - frame_start;
        const c_u32 = std.math.cast(u32, comp_len) orelse return error.FrameTooLarge;
        const u_u32: u32 = @intCast(frame_uncomp_len);
        const csum: u32 = @truncate(XxHash64.hash(0, frame_data));

        try entries.append(allocator, .{
            .frame_index = @intCast(entries.items.len),
            .comp_offset = comp_off,
            .compressed_size = c_u32,
            .uncomp_offset = uncomp_off,
            .uncompressed_size = u_u32,
            .checksum = csum,
        });

        comp_off += c_u32;
        uncomp_off += u_u32;
        pos += frame_uncomp_len;
    }

    const table = ZstdSeekTable{
        .entries = entries.items,
        .has_checksum = true,
        .total_compressed_size = comp_off,
        .total_uncompressed_size = uncomp_off,
    };
    const seek_bytes = try table.serializeAlloc(allocator);
    defer allocator.free(seek_bytes);
    try out.appendSlice(allocator, seek_bytes);

    return out.toOwnedSlice(allocator);
}

fn appendZstdRawFrame(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frame_data: []const u8) error{OutOfMemory}!void {
    try out.appendSlice(allocator, &[_]u8{ 0x28, 0xB5, 0x2F, 0xFD });

    // Frame_Header_Descriptor: Single_Segment_Flag = 1 (0x20)
    if (frame_data.len <= 255) {
        try out.append(allocator, 0x20);
        try out.append(allocator, @intCast(frame_data.len));
    } else if (frame_data.len <= 65535 + 256) {
        try out.append(allocator, 0x60);
        var fcs: [2]u8 = undefined;
        std.mem.writeInt(u16, &fcs, @intCast(frame_data.len - 256), .little);
        try out.appendSlice(allocator, &fcs);
    } else {
        try out.append(allocator, 0xA0);
        var fcs: [4]u8 = undefined;
        std.mem.writeInt(u32, &fcs, @intCast(frame_data.len), .little);
        try out.appendSlice(allocator, &fcs);
    }

    // Emit Raw_Block(s) of up to zstd.block_size_max (128 KiB)
    const max_block: usize = std.compress.zstd.block_size_max;
    var bpos: usize = 0;
    while (true) {
        const chunk_len = @min(frame_data.len - bpos, max_block);
        const is_last: u24 = if (bpos + chunk_len >= frame_data.len) 1 else 0;
        const bh: u24 = (@as(u24, @intCast(chunk_len)) << 3) | is_last;
        var bh_bytes: [3]u8 = undefined;
        std.mem.writeInt(u24, &bh_bytes, bh, .little);
        try out.appendSlice(allocator, &bh_bytes);
        try out.appendSlice(allocator, frame_data[bpos .. bpos + chunk_len]);
        bpos += chunk_len;
        if (is_last == 1) break;
    }
}

// ============================================================================
// Pure-Zig RFC 1951 Deflate + Multi-Member Gzip Checkpoint Index (`GzipIndex`)
// ============================================================================

const len_base_table = [29]u16{
    3,   4,   5,   6,   7,   8,   9,   10,
    11,  13,  15,  17,  19,  23,  27,  31,
    35,  43,  51,  59,  67,  83,  99,  115,
    131, 163, 195, 227, 258,
};

const len_extra_table = [29]u5{
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5, 0,
};

const dist_base_table = [30]u16{
    1,     2,     3,     4,     5,     7,
    9,     13,    17,    25,    33,    49,
    65,    97,    129,   193,   257,   385,
    513,   769,   1025,  1537,  2049,  3073,
    4097,  6145,  8193,  12289, 16385, 24577,
};

const dist_extra_table = [30]u5{
    0,  0,  0,  0,  1,  1,
    2,  2,  3,  3,  4,  4,
    5,  5,  6,  6,  7,  7,
    8,  8,  9,  9,  10, 10,
    11, 11, 12, 12, 13, 13,
};

const cl_order = [19]u8{
    16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
    11, 4,  12, 3, 13, 2, 14, 1, 15,
};

const HuffTable = struct {
    /// Entry format:
    /// - `0`: unassigned / invalid code
    /// - `(entry & 0x8000) == 0`: leaf `(sym << 4) | code_len` (`code_len` in 1..15)
    /// - `(entry & 0x8000) != 0`: subtable index `entry & 0x7FFF` into `sub` (`* 64`)
    fast: [512]u16 = @splat(0),
    sub: [128 * 64]u16 = undefined,
    sub_count: usize = 0,

    fn build(self: *HuffTable, lengths: []const u8) Error!void {
        @memset(&self.fast, 0);
        self.sub_count = 0;

        var bl_count: [16]u16 = @splat(0);
        var any_nonzero = false;
        for (lengths) |l| {
            if (l > 15) return error.CorruptStream;
            if (l > 0) {
                bl_count[l] += 1;
                any_nonzero = true;
            }
        }
        if (!any_nonzero) return; // Empty distance alphabet allowed when only literals occur

        var left: i32 = 1;
        for (1..16) |bits| {
            left <<= 1;
            left -= @intCast(bl_count[bits]);
            if (left < 0) return error.CorruptStream; // Oversubscribed canonical tree
        }

        var next_code: [16]u16 = @splat(0);
        var code: u16 = 0;
        for (1..16) |bits| {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for (lengths, 0..) |l, sym| {
            if (l == 0) continue;
            const c = next_code[l];
            next_code[l] += 1;
            const rev: usize = @bitReverse(c) >> @as(u4, @intCast(16 - l));
            const leaf: u16 = (@as(u16, @intCast(sym)) << 4) | @as(u16, l);

            if (l <= 9) {
                const step: usize = @as(usize, 1) << @intCast(l);
                var idx = rev;
                while (idx < 512) : (idx += step) {
                    self.fast[idx] = leaf;
                }
            } else {
                const prefix = rev & 0x1FF;
                var entry = self.fast[prefix];
                if (entry == 0) {
                    if (self.sub_count >= 128) return error.CorruptStream;
                    const s_idx = self.sub_count;
                    self.sub_count += 1;
                    @memset(self.sub[s_idx * 64 ..][0..64], 0);
                    entry = 0x8000 | @as(u16, @intCast(s_idx));
                    self.fast[prefix] = entry;
                } else if ((entry & 0x8000) == 0) {
                    return error.CorruptStream;
                }
                const sub_base: usize = @as(usize, entry & 0x7FFF) * 64;
                const sub_rev: usize = rev >> 9;
                const sub_step: usize = @as(usize, 1) << @intCast(l - 9);
                var idx = sub_rev;
                while (idx < 64) : (idx += sub_step) {
                    self.sub[sub_base + idx] = leaf;
                }
            }
        }
    }

    fn buildFixedLit(self: *HuffTable) void {
        var lens: [288]u8 = undefined;
        @memset(lens[0..144], 8);
        @memset(lens[144..256], 9);
        @memset(lens[256..280], 7);
        @memset(lens[280..288], 8);
        self.build(&lens) catch unreachable;
    }

    fn buildFixedDist(self: *HuffTable) void {
        const lens: [32]u8 = @splat(5);
        self.build(&lens) catch unreachable;
    }
};

const BitSource = union(enum) {
    reader: *std.Io.Reader,
    random_access: struct {
        ra: probe.RandomAccess,
        next_offset: u64,
    },
};

const BitReader = struct {
    src: BitSource,
    buf: [8192]u8 = undefined,
    buf_pos: usize = 0,
    buf_len: usize = 0,
    /// Compressed byte offset immediately after `buf[buf_pos - 1]` (i.e. offset of `buf[buf_pos]`).
    next_byte_offset: u64 = 0,
    bit_buf: u64 = 0,
    avail_bits: u7 = 0,
    eof_reached: bool = false,

    fn initReader(reader: *std.Io.Reader) BitReader {
        return .{ .src = .{ .reader = reader } };
    }

    fn initRandomAccess(ra: probe.RandomAccess, comp_offset: u64, bit_offset: u3) anyerror!BitReader {
        var br = BitReader{
            .src = .{ .random_access = .{ .ra = ra, .next_offset = comp_offset } },
            .next_byte_offset = comp_offset,
        };
        if (bit_offset != 0) {
            const b = (try br.pullRawByte()) orelse return error.CorruptStream;
            br.bit_buf = b >> bit_offset;
            br.avail_bits = @as(u7, 8) - bit_offset;
        }
        return br;
    }

    fn currentBitPos(self: *const BitReader) struct { comp_offset: u64, bit_offset: u3 } {
        const full_bytes: u64 = self.avail_bits / 8;
        const rem_bits: u7 = self.avail_bits % 8;
        if (rem_bits == 0) {
            return .{
                .comp_offset = self.next_byte_offset - full_bytes,
                .bit_offset = 0,
            };
        }
        return .{
            .comp_offset = self.next_byte_offset - full_bytes - 1,
            .bit_offset = @intCast(8 - rem_bits),
        };
    }

    fn pullRawByte(self: *BitReader) anyerror!?u8 {
        if (self.buf_pos >= self.buf_len) {
            if (self.eof_reached) return null;
            const n: usize = switch (self.src) {
                .reader => |r| r.readSliceShort(&self.buf) catch return error.CorruptStream,
                .random_access => |*s| blk: {
                    const got = try s.ra.readAt(s.next_offset, &self.buf);
                    s.next_offset += got;
                    break :blk got;
                },
            };
            self.buf_pos = 0;
            self.buf_len = n;
            if (n == 0) {
                self.eof_reached = true;
                return null;
            }
        }
        const b = self.buf[self.buf_pos];
        self.buf_pos += 1;
        self.next_byte_offset += 1;
        return b;
    }

    inline fn refill(self: *BitReader) anyerror!void {
        while (self.avail_bits <= 56) {
            const b = (try self.pullRawByte()) orelse break;
            self.bit_buf |= @as(u64, b) << @intCast(self.avail_bits);
            self.avail_bits += 8;
        }
    }

    fn readBits(self: *BitReader, n: u6) anyerror!u32 {
        if (n == 0) return 0;
        if (self.avail_bits < n) try self.refill();
        if (self.avail_bits < n) return error.CorruptStream;
        const mask: u64 = (@as(u64, 1) << n) - 1;
        const val: u32 = @intCast(self.bit_buf & mask);
        self.bit_buf >>= n;
        self.avail_bits -= n;
        return val;
    }

    fn alignToByte(self: *BitReader) void {
        const rem: u7 = self.avail_bits % 8;
        if (rem != 0) {
            self.bit_buf >>= @intCast(rem);
            self.avail_bits -= rem;
        }
    }

    fn peekAlignedByte(self: *BitReader) anyerror!?u8 {
        std.debug.assert(self.avail_bits % 8 == 0);
        if (self.avail_bits >= 8) {
            return @truncate(self.bit_buf);
        }
        const b = (try self.pullRawByte()) orelse return null;
        self.bit_buf = b;
        self.avail_bits = 8;
        return b;
    }

    fn readAlignedByte(self: *BitReader) anyerror!u8 {
        std.debug.assert(self.avail_bits % 8 == 0);
        if (self.avail_bits >= 8) {
            const b: u8 = @truncate(self.bit_buf);
            self.bit_buf >>= 8;
            self.avail_bits -= 8;
            return b;
        }
        return (try self.pullRawByte()) orelse return error.CorruptStream;
    }

    inline fn decodeHuff(self: *BitReader, table: *const HuffTable) anyerror!u16 {
        if (self.avail_bits < 15) try self.refill();
        const peek15: usize = @intCast(self.bit_buf & 0x7FFF);
        var entry = table.fast[peek15 & 0x1FF];
        if ((entry & 0x8000) != 0) {
            entry = table.sub[@as(usize, entry & 0x7FFF) * 64 + (peek15 >> 9)];
        }
        if (entry == 0) return error.CorruptStream;
        const code_len: u6 = @intCast(entry & 0x0F);
        if (self.avail_bits < code_len) return error.CorruptStream;
        self.bit_buf >>= code_len;
        self.avail_bits -= code_len;
        return entry >> 4;
    }
};

const DeflateMachine = struct {
    ring: [32768]u8 = @splat(0),
    ring_pos: usize = 0,
    member_produced: usize = 0,
    member_uncomp_total: u64 = 0,
    crc: std.hash.Crc32 = std.hash.Crc32.init(),
    verify_member: bool = true,
    lit_table: HuffTable = .{},
    dist_table: HuffTable = .{},
    cl_table: HuffTable = .{},

    fn resetForMember(self: *DeflateMachine) void {
        @memset(&self.ring, 0);
        self.ring_pos = 0;
        self.member_produced = 0;
        self.member_uncomp_total = 0;
        self.crc = std.hash.Crc32.init();
        self.verify_member = true;
    }

    fn initFromCheckpoint(self: *DeflateMachine, cp: *const GzipIndex.Checkpoint) void {
        if (cp.is_member_start) {
            self.resetForMember();
        } else {
            self.ring = cp.window;
            self.ring_pos = 0;
            self.member_produced = 32768;
            self.member_uncomp_total = 0;
            self.crc = std.hash.Crc32.init();
            self.verify_member = false;
        }
    }

    fn exportWindow(self: *const DeflateMachine, out_win: *[32768]u8) void {
        const first_part = 32768 - self.ring_pos;
        @memcpy(out_win[0..first_part], self.ring[self.ring_pos..32768]);
        if (self.ring_pos > 0) {
            @memcpy(out_win[first_part..32768], self.ring[0..self.ring_pos]);
        }
    }

    fn parseGzipHeader(br: *BitReader) anyerror!void {
        br.alignToByte();
        var hdr: [10]u8 = undefined;
        for (&hdr) |*b| b.* = try br.readAlignedByte();
        if (hdr[0] != 0x1F or hdr[1] != 0x8B or hdr[2] != 0x08) return error.CorruptStream;
        const flg = hdr[3];
        if ((flg & 0xE0) != 0) return error.CorruptStream;

        var hcrc = std.hash.Crc32.init();
        hcrc.update(&hdr);

        if ((flg & 0x04) != 0) { // FEXTRA
            const lo = try br.readAlignedByte();
            const hi = try br.readAlignedByte();
            hcrc.update(&.{ lo, hi });
            const xlen: usize = @as(usize, lo) | (@as(usize, hi) << 8);
            for (0..xlen) |_| {
                const xb = try br.readAlignedByte();
                hcrc.update(&.{xb});
            }
        }
        if ((flg & 0x08) != 0) { // FNAME
            while (true) {
                const nb = try br.readAlignedByte();
                hcrc.update(&.{nb});
                if (nb == 0) break;
            }
        }
        if ((flg & 0x10) != 0) { // FCOMMENT
            while (true) {
                const cb = try br.readAlignedByte();
                hcrc.update(&.{cb});
                if (cb == 0) break;
            }
        }
        if ((flg & 0x02) != 0) { // FHCRC (CRC16)
            const c0 = try br.readAlignedByte();
            const c1 = try br.readAlignedByte();
            const expected_crc16: u16 = @as(u16, c0) | (@as(u16, c1) << 8);
            const actual_crc16: u16 = @truncate(hcrc.final());
            if (actual_crc16 != expected_crc16) return error.CorruptStream;
        }
    }

    fn consumeGzipTrailer(self: *const DeflateMachine, br: *BitReader) anyerror!void {
        br.alignToByte();
        var trailer: [8]u8 = undefined;
        for (&trailer) |*b| b.* = try br.readAlignedByte();
        if (self.verify_member) {
            const expected_crc = std.mem.readInt(u32, trailer[0..4], .little);
            const expected_isize = std.mem.readInt(u32, trailer[4..8], .little);
            if (self.crc.final() != expected_crc) return error.CorruptStream;
            if (@as(u32, @truncate(self.member_uncomp_total)) != expected_isize) return error.CorruptStream;
        }
    }

    fn loadDynamicTables(self: *DeflateMachine, br: *BitReader) anyerror!void {
        const hlit: usize = @as(usize, try br.readBits(5)) + 257;
        const hdist: usize = @as(usize, try br.readBits(5)) + 1;
        const hclen: usize = @as(usize, try br.readBits(4)) + 4;
        if (hlit > 286 or hdist > 32) return error.CorruptStream;

        var cl_lens: [19]u8 = @splat(0);
        for (0..hclen) |i| {
            cl_lens[cl_order[i]] = @intCast(try br.readBits(3));
        }
        try self.cl_table.build(&cl_lens);

        const total_codes = hlit + hdist;
        var lens: [288 + 32]u8 = @splat(0);
        var idx: usize = 0;
        while (idx < total_codes) {
            const sym = try br.decodeHuff(&self.cl_table);
            if (sym <= 15) {
                lens[idx] = @intCast(sym);
                idx += 1;
            } else if (sym == 16) {
                if (idx == 0) return error.CorruptStream;
                const rep: usize = @as(usize, try br.readBits(2)) + 3;
                if (idx + rep > total_codes) return error.CorruptStream;
                const prev = lens[idx - 1];
                @memset(lens[idx .. idx + rep], prev);
                idx += rep;
            } else if (sym == 17) {
                const rep: usize = @as(usize, try br.readBits(3)) + 3;
                if (idx + rep > total_codes) return error.CorruptStream;
                @memset(lens[idx .. idx + rep], 0);
                idx += rep;
            } else if (sym == 18) {
                const rep: usize = @as(usize, try br.readBits(7)) + 11;
                if (idx + rep > total_codes) return error.CorruptStream;
                @memset(lens[idx .. idx + rep], 0);
                idx += rep;
            } else {
                return error.CorruptStream;
            }
        }

        if (lens[256] == 0) return error.CorruptStream;
        try self.lit_table.build(lens[0..hlit]);
        try self.dist_table.build(lens[hlit .. hlit + hdist]);
    }

    inline fn pushOutByte(self: *DeflateMachine, b: u8, sink: anytype) void {
        self.ring[self.ring_pos] = b;
        self.ring_pos = (self.ring_pos + 1) & 32767;
        if (self.member_produced < 32768) self.member_produced += 1;
        self.member_uncomp_total += 1;
        if (self.verify_member) self.crc.update(&.{b});
        sink.onByte(b);
    }

    /// Decodes a single Deflate block. Returns `true` if `BFINAL == 1`.
    /// When `sink.done()` becomes true mid-block (used by `readAt` once `dest` is filled), stops early!
    fn decodeBlock(self: *DeflateMachine, br: *BitReader, sink: anytype) anyerror!bool {
        const bfinal = (try br.readBits(1)) != 0;
        const btype = try br.readBits(2);

        switch (btype) {
            0 => {
                br.alignToByte();
                const l0 = try br.readAlignedByte();
                const l1 = try br.readAlignedByte();
                const n0 = try br.readAlignedByte();
                const n1 = try br.readAlignedByte();
                const len: u16 = @as(u16, l0) | (@as(u16, l1) << 8);
                const nlen: u16 = @as(u16, n0) | (@as(u16, n1) << 8);
                if ((len ^ nlen) != 0xFFFF) return error.CorruptStream;

                for (0..len) |_| {
                    if (sink.done()) return bfinal;
                    const b = try br.readAlignedByte();
                    self.pushOutByte(b, sink);
                }
            },
            1, 2 => {
                if (btype == 1) {
                    self.lit_table.buildFixedLit();
                    self.dist_table.buildFixedDist();
                } else {
                    try self.loadDynamicTables(br);
                }

                while (!sink.done()) {
                    const sym = try br.decodeHuff(&self.lit_table);
                    if (sym < 256) {
                        self.pushOutByte(@intCast(sym), sink);
                    } else if (sym == 256) {
                        break;
                    } else if (sym <= 285) {
                        const len_idx: usize = sym - 257;
                        const extra_len_bits = len_extra_table[len_idx];
                        const match_len: usize = @as(usize, len_base_table[len_idx]) + @as(usize, try br.readBits(extra_len_bits));

                        const dist_sym = try br.decodeHuff(&self.dist_table);
                        if (dist_sym >= 30) return error.CorruptStream;
                        const extra_dist_bits = dist_extra_table[dist_sym];
                        const dist: usize = @as(usize, dist_base_table[dist_sym]) + @as(usize, try br.readBits(extra_dist_bits));
                        if (dist == 0 or dist > self.member_produced) return error.CorruptStream;

                        var k: usize = 0;
                        while (k < match_len and !sink.done()) : (k += 1) {
                            const src_pos = (self.ring_pos + 32768 - dist) & 32767;
                            const b = self.ring[src_pos];
                            self.pushOutByte(b, sink);
                        }
                    } else {
                        return error.CorruptStream;
                    }
                }
            },
            else => return error.CorruptStream,
        }

        return bfinal;
    }
};

pub const GzipIndex = struct {
    pub const Checkpoint = struct {
        comp_offset: u64,
        bit_offset: u3,
        uncomp_offset: u64,
        is_member_start: bool,
        window: [32768]u8,
    };

    checkpoints: []Checkpoint = &.{},
    total_compressed_size: u64 = 0,
    total_uncompressed_size: u64 = 0,

    pub fn deinit(self: *GzipIndex, allocator: std.mem.Allocator) void {
        if (self.checkpoints.len != 0) {
            allocator.free(self.checkpoints);
        }
        self.* = undefined;
    }

    /// Builds a checkpoint index from an in-memory multi-member Gzip slice.
    pub fn buildFromSlice(
        allocator: std.mem.Allocator,
        gz_bytes: []const u8,
        checkpoint_interval: u64,
    ) anyerror!GzipIndex {
        var reader = std.Io.Reader.fixed(gz_bytes);
        return buildFromReader(allocator, &reader, checkpoint_interval);
    }

    /// Streams a single- or multi-member Gzip input from `reader`, recording checkpoints at every
    /// Gzip member start and at Deflate block boundaries spaced by `>= checkpoint_interval` uncompressed bytes.
    pub fn buildFromReader(
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        checkpoint_interval: u64,
    ) anyerror!GzipIndex {
        const eff_interval: u64 = if (checkpoint_interval == 0) default_gzip_checkpoint_interval else checkpoint_interval;

        var list = std.ArrayList(Checkpoint).empty;
        errdefer list.deinit(allocator);

        const machine = try allocator.create(DeflateMachine);
        defer allocator.destroy(machine);
        machine.* = .{};

        var br = BitReader.initReader(reader);

        const CountSink = struct {
            total_uncomp: u64 = 0,
            inline fn onByte(s: *@This(), _: u8) void {
                s.total_uncomp += 1;
            }
            inline fn done(_: *const @This()) bool {
                return false;
            }
        };
        var sink = CountSink{};
        var saw_any_member = false;
        var last_cp_uncomp: u64 = 0;

        while ((try br.peekAlignedByte()) != null) {
            saw_any_member = true;
            const member_pos = br.currentBitPos();
            std.debug.assert(member_pos.bit_offset == 0);

            const cp_ptr = try list.addOne(allocator);
            cp_ptr.* = .{
                .comp_offset = member_pos.comp_offset,
                .bit_offset = 0,
                .uncomp_offset = sink.total_uncomp,
                .is_member_start = true,
                .window = @splat(0),
            };
            last_cp_uncomp = sink.total_uncomp;

            machine.resetForMember();
            try DeflateMachine.parseGzipHeader(&br);

            var block_idx: usize = 0;
            while (true) : (block_idx += 1) {
                if (block_idx > 0 and sink.total_uncomp - last_cp_uncomp >= eff_interval) {
                    const bpos = br.currentBitPos();
                    const blk_cp = try list.addOne(allocator);
                    blk_cp.comp_offset = bpos.comp_offset;
                    blk_cp.bit_offset = bpos.bit_offset;
                    blk_cp.uncomp_offset = sink.total_uncomp;
                    blk_cp.is_member_start = false;
                    machine.exportWindow(&blk_cp.window);
                    last_cp_uncomp = sink.total_uncomp;
                }

                const bfinal = try machine.decodeBlock(&br, &sink);
                if (bfinal) break;
            }

            try machine.consumeGzipTrailer(&br);
        }

        if (!saw_any_member) return error.CorruptStream;

        const end_pos = br.currentBitPos();
        return .{
            .checkpoints = try list.toOwnedSlice(allocator),
            .total_compressed_size = end_pos.comp_offset,
            .total_uncompressed_size = sink.total_uncomp,
        };
    }

    const index_magic = "WGZIDX\x01\x00";

    /// Serializes this `GzipIndex` into a compact binary buffer protected by a trailing CRC32 checksum.
    pub fn serializeAlloc(self: *const GzipIndex, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);

        try out.appendSlice(allocator, index_magic);
        var hdr: [24]u8 = undefined;
        std.mem.writeInt(u64, hdr[0..8], self.total_compressed_size, .little);
        std.mem.writeInt(u64, hdr[8..16], self.total_uncompressed_size, .little);
        std.mem.writeInt(u64, hdr[16..24], @intCast(self.checkpoints.len), .little);
        try out.appendSlice(allocator, &hdr);

        for (self.checkpoints) |*cp| {
            var rec: [17]u8 = undefined;
            std.mem.writeInt(u64, rec[0..8], cp.comp_offset, .little);
            std.mem.writeInt(u64, rec[8..16], cp.uncomp_offset, .little);
            const has_win = !cp.is_member_start and cp.uncomp_offset > 0;
            rec[16] = @as(u8, cp.bit_offset) |
                (if (cp.is_member_start) @as(u8, 0x08) else 0) |
                (if (has_win) @as(u8, 0x10) else 0);
            try out.appendSlice(allocator, &rec);
            if (has_win) {
                try out.appendSlice(allocator, &cp.window);
            }
        }

        const crc = std.hash.Crc32.hash(out.items);
        var tail: [4]u8 = undefined;
        std.mem.writeInt(u32, &tail, crc, .little);
        try out.appendSlice(allocator, &tail);

        return out.toOwnedSlice(allocator);
    }

    /// Deserializes a `GzipIndex` previously created by `serializeAlloc`, verifying header and CRC32 integrity.
    pub fn deserialize(allocator: std.mem.Allocator, bytes: []const u8) Error!GzipIndex {
        if (bytes.len < 8 + 24 + 4) return error.CorruptIndex;
        if (!std.mem.eql(u8, bytes[0..8], index_magic)) return error.CorruptIndex;

        const payload = bytes[0 .. bytes.len - 4];
        const expected_crc = std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little);
        if (std.hash.Crc32.hash(payload) != expected_crc) return error.CorruptIndex;

        const total_comp = std.mem.readInt(u64, payload[8..16], .little);
        const total_uncomp = std.mem.readInt(u64, payload[16..24], .little);
        const count64 = std.mem.readInt(u64, payload[24..32], .little);
        if (count64 > (payload.len - 32) / 17) return error.CorruptIndex;
        const alloc_bytes = std.math.mul(u64, count64, @sizeOf(Checkpoint)) catch return error.CorruptIndex;
        if (alloc_bytes > max_seek_table_bytes) return error.CorruptIndex;
        const count: usize = @intCast(count64);

        const cps = try allocator.alloc(Checkpoint, count);
        errdefer allocator.free(cps);

        var pos: usize = 32;
        var prev_uncomp: u64 = 0;
        for (cps, 0..) |*cp, idx| {
            if (payload.len - pos < 17) return error.CorruptIndex;
            const comp_off = std.mem.readInt(u64, payload[pos..][0..8], .little);
            const uncomp_off = std.mem.readInt(u64, payload[pos + 8 ..][0..8], .little);
            const flags = payload[pos + 16];
            pos += 17;

            if ((flags & 0xE0) != 0) return error.CorruptIndex;
            const bit_off: u3 = @truncate(flags & 0x07);
            const is_member = (flags & 0x08) != 0;
            const has_win = (flags & 0x10) != 0;
            if (is_member and bit_off != 0) return error.CorruptIndex;
            if (idx > 0 and uncomp_off < prev_uncomp) return error.CorruptIndex;
            if (comp_off > total_comp or uncomp_off > total_uncomp) return error.CorruptIndex;
            prev_uncomp = uncomp_off;

            cp.comp_offset = comp_off;
            cp.bit_offset = bit_off;
            cp.uncomp_offset = uncomp_off;
            cp.is_member_start = is_member;
            if (has_win) {
                if (payload.len - pos < 32768) return error.CorruptIndex;
                @memcpy(&cp.window, payload[pos .. pos + 32768]);
                pos += 32768;
            } else {
                @memset(&cp.window, 0);
            }
        }

        if (pos != payload.len) return error.CorruptIndex;

        return .{
            .checkpoints = cps,
            .total_compressed_size = total_comp,
            .total_uncompressed_size = total_uncomp,
        };
    }

    /// Locates the latest checkpoint with `cp.uncomp_offset <= uncomp_offset` in O(log C) binary search.
    pub fn locateOffset(self: *const GzipIndex, uncomp_offset: u64) ?*const Checkpoint {
        if (uncomp_offset >= self.total_uncompressed_size or self.checkpoints.len == 0) return null;

        const lo = std.sort.partitionPoint(Checkpoint, self.checkpoints, uncomp_offset, struct {
            fn pred(target: u64, cp: Checkpoint) bool {
                return cp.uncomp_offset <= target;
            }
        }.pred);
        if (lo == 0) return &self.checkpoints[0];
        return &self.checkpoints[lo - 1];
    }

    /// Reads uncompressed bytes starting at `uncomp_offset` into `dest`, resuming directly from the
    /// nearest preceding checkpoint in `source` and streaming across Deflate blocks / Gzip members.
    pub fn readAt(
        self: *const GzipIndex,
        allocator: std.mem.Allocator,
        source: probe.RandomAccess,
        uncomp_offset: u64,
        dest: []u8,
    ) anyerror!usize {
        if (dest.len == 0 or uncomp_offset >= self.total_uncompressed_size) return 0;
        const cp = self.locateOffset(uncomp_offset) orelse return 0;

        const avail_total = self.total_uncompressed_size - uncomp_offset;
        const want_total: usize = @intCast(@min(@as(u64, dest.len), avail_total));

        const machine = try allocator.create(DeflateMachine);
        defer allocator.destroy(machine);
        machine.* = .{};
        machine.initFromCheckpoint(cp);

        var br = try BitReader.initRandomAccess(source, cp.comp_offset, cp.bit_offset);

        const CopySink = struct {
            skip_rem: u64,
            out: []u8,
            written: usize = 0,

            inline fn onByte(s: *@This(), b: u8) void {
                if (s.skip_rem > 0) {
                    s.skip_rem -= 1;
                    return;
                }
                if (s.written < s.out.len) {
                    s.out[s.written] = b;
                    s.written += 1;
                }
            }

            inline fn done(s: *const @This()) bool {
                return s.written >= s.out.len;
            }
        };

        var sink = CopySink{
            .skip_rem = uncomp_offset - cp.uncomp_offset,
            .out = dest[0..want_total],
        };

        var in_member = !cp.is_member_start;
        if (cp.is_member_start) {
            try DeflateMachine.parseGzipHeader(&br);
            in_member = true;
        }

        while (!sink.done()) {
            if (!in_member) {
                if ((try br.peekAlignedByte()) == null) break;
                machine.resetForMember();
                try DeflateMachine.parseGzipHeader(&br);
                in_member = true;
            }

            const bfinal = try machine.decodeBlock(&br, &sink);
            if (sink.done()) break;
            if (bfinal) {
                try machine.consumeGzipTrailer(&br);
                in_member = false;
            }
        }

        if (sink.written != want_total) return error.CorruptStream;
        return sink.written;
    }
};

/// Adapter wrapping `GzipIndex` + compressed `probe.RandomAccess` into an uncompressed `probe.RandomAccess`.
pub const IndexedGzipReader = struct {
    allocator: std.mem.Allocator,
    source: probe.RandomAccess,
    index: *const GzipIndex,

    pub fn init(
        allocator: std.mem.Allocator,
        source: probe.RandomAccess,
        index: *const GzipIndex,
    ) IndexedGzipReader {
        return .{
            .allocator = allocator,
            .source = source,
            .index = index,
        };
    }

    pub fn deinit(self: *IndexedGzipReader) void {
        self.* = undefined;
    }

    pub fn readAt(self: *const IndexedGzipReader, uncomp_offset: u64, dest: []u8) anyerror!usize {
        return self.index.readAt(self.allocator, self.source, uncomp_offset, dest);
    }

    pub fn randomAccess(self: *const IndexedGzipReader) probe.RandomAccess {
        return .{
            .ctx = @ptrCast(@constCast(self)),
            .read_at = readAtErased,
            .size = self.index.total_uncompressed_size,
        };
    }

    fn readAtErased(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *const IndexedGzipReader = @ptrCast(@alignCast(ctx.?));
        return self.readAt(offset, dest);
    }
};

// ============================================================================
// Gzip / Deflate Compression Helpers (Multi-Member, Fixed & Dynamic Huffman)
// ============================================================================

const BitWriter = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bit_buf: u64 = 0,
    bit_count: u7 = 0,

    fn writeBits(self: *BitWriter, val: u32, n: u5) error{OutOfMemory}!void {
        if (n == 0) return;
        const mask: u64 = (@as(u64, 1) << n) - 1;
        self.bit_buf |= (@as(u64, val) & mask) << @intCast(self.bit_count);
        self.bit_count += n;
        while (self.bit_count >= 8) {
            try self.list.append(self.allocator, @truncate(self.bit_buf));
            self.bit_buf >>= 8;
            self.bit_count -= 8;
        }
    }

    fn writeHuffCode(self: *BitWriter, code_msb: u16, len: u5) error{OutOfMemory}!void {
        const rev: u32 = @bitReverse(code_msb) >> @as(u4, @intCast(16 - @as(u5, len)));
        try self.writeBits(rev, len);
    }

    fn alignZero(self: *BitWriter) error{OutOfMemory}!void {
        if (self.bit_count > 0) {
            try self.list.append(self.allocator, @truncate(self.bit_buf));
            self.bit_buf = 0;
            self.bit_count = 0;
        }
    }
};

fn encodeLenSymbol(match_len: usize) struct { sym: u16, extra_bits: u5, extra_val: u32 } {
    for (0..29) |idx| {
        const base: usize = len_base_table[idx];
        const eb = len_extra_table[idx];
        const max_l = base + ((@as(usize, 1) << eb) - 1);
        if (match_len >= base and match_len <= max_l) {
            return .{
                .sym = @intCast(257 + idx),
                .extra_bits = eb,
                .extra_val = @intCast(match_len - base),
            };
        }
    }
    unreachable;
}

fn encodeDistSymbol(dist: usize) struct { sym: u16, extra_bits: u5, extra_val: u32 } {
    for (0..30) |idx| {
        const base: usize = dist_base_table[idx];
        const eb = dist_extra_table[idx];
        const max_d = base + ((@as(usize, 1) << eb) - 1);
        if (dist >= base and dist <= max_d) {
            return .{
                .sym = @intCast(idx),
                .extra_bits = eb,
                .extra_val = @intCast(dist - base),
            };
        }
    }
    unreachable;
}

fn writeFixedLitSym(bw: *BitWriter, sym: u16) error{OutOfMemory}!void {
    if (sym <= 143) {
        try bw.writeHuffCode(0x30 + sym, 8);
    } else if (sym <= 255) {
        try bw.writeHuffCode(0x190 + (sym - 144), 9);
    } else if (sym <= 279) {
        try bw.writeHuffCode(sym - 256, 7);
    } else {
        try bw.writeHuffCode(0xC0 + (sym - 280), 8);
    }
}

fn findLz77Match(payload: []const u8, pos: usize, head: *[1024]i32) ?struct { len: usize, dist: usize } {
    if (pos + 3 > payload.len) return null;
    const h: usize = ((@as(usize, payload[pos]) *% 2654435761) ^
        (@as(usize, payload[pos + 1]) << 8) ^
        @as(usize, payload[pos + 2])) & 1023;
    const prev = head[h];
    head[h] = @intCast(pos);
    if (prev < 0) return null;
    const cand: usize = @intCast(prev);
    const dist = pos - cand;
    if (dist == 0 or dist > 32768) return null;

    const max_len = @min(@as(usize, 258), payload.len - pos);
    var mlen: usize = 0;
    while (mlen < max_len and payload[cand + mlen] == payload[pos + mlen]) : (mlen += 1) {}
    if (mlen < 3) return null;
    return .{ .len = mlen, .dist = dist };
}

fn appendGzipMemberFixed(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    payload: []const u8,
    block_uncomp_cap: usize,
) error{OutOfMemory}!void {
    try out.appendSlice(allocator, &[_]u8{ 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 });

    var bw = BitWriter{ .list = out, .allocator = allocator };
    var head: [1024]i32 = @splat(-1);
    const cap = @max(@as(usize, 256), block_uncomp_cap);

    var pos: usize = 0;
    while (true) {
        const blk_end = @min(payload.len, pos + cap);
        const is_final: u32 = if (blk_end >= payload.len) 1 else 0;
        try bw.writeBits(is_final, 1);
        try bw.writeBits(1, 2); // BTYPE = 01 (Fixed Huffman)

        while (pos < blk_end) {
            if (findLz77Match(payload, pos, &head)) |m| {
                const mlen = @min(m.len, blk_end - pos);
                if (mlen >= 3) {
                    const ls = encodeLenSymbol(mlen);
                    try writeFixedLitSym(&bw, ls.sym);
                    try bw.writeBits(ls.extra_val, ls.extra_bits);
                    const ds = encodeDistSymbol(m.dist);
                    try bw.writeHuffCode(ds.sym, 5);
                    try bw.writeBits(ds.extra_val, ds.extra_bits);

                    var adv: usize = 1;
                    while (adv < mlen) : (adv += 1) {
                        if (pos + adv + 3 <= payload.len) {
                            const hh: usize = ((@as(usize, payload[pos + adv]) *% 2654435761) ^
                                (@as(usize, payload[pos + adv + 1]) << 8) ^
                                @as(usize, payload[pos + adv + 2])) & 1023;
                            head[hh] = @intCast(pos + adv);
                        }
                    }
                    pos += mlen;
                    continue;
                }
            }
            try writeFixedLitSym(&bw, payload[pos]);
            pos += 1;
        }

        try writeFixedLitSym(&bw, 256); // End of block
        if (is_final == 1) break;
    }

    try bw.alignZero();

    var footer: [8]u8 = undefined;
    std.mem.writeInt(u32, footer[0..4], std.hash.Crc32.hash(payload), .little);
    std.mem.writeInt(u32, footer[4..8], @truncate(payload.len), .little);
    try out.appendSlice(allocator, &footer);
}

/// Compresses `members` into a valid concatenated multi-member Gzip byte buffer, using multi-block
/// Fixed Huffman + LZ77 compression per member so mid-member checkpoints and cross-block windows work out of the box.
pub fn compressMultiMemberGzipAlloc(
    allocator: std.mem.Allocator,
    members: []const []const u8,
) error{OutOfMemory}![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    if (members.len == 0) {
        try appendGzipMemberFixed(allocator, &out, "", 4096);
        return out.toOwnedSlice(allocator);
    }

    for (members) |m| {
        try appendGzipMemberFixed(allocator, &out, m, 4096);
    }
    return out.toOwnedSlice(allocator);
}

// ============================================================================
// Unit Tests
// ============================================================================

const CountingRandomAccess = struct {
    data: []const u8,
    reads: usize = 0,
    bytes_read: u64 = 0,
    min_offset_seen: u64 = std.math.maxInt(u64),

    fn randomAccess(self: *CountingRandomAccess) probe.RandomAccess {
        return .{
            .ctx = self,
            .read_at = readAtFn,
            .size = @intCast(self.data.len),
        };
    }

    fn readAtFn(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *CountingRandomAccess = @ptrCast(@alignCast(ctx.?));
        self.reads += 1;
        if (offset < self.min_offset_seen) self.min_offset_seen = offset;
        if (offset >= self.data.len or dest.len == 0) return 0;
        const off: usize = @intCast(offset);
        const n = @min(dest.len, self.data.len - off);
        @memcpy(dest[0..n], self.data[off .. off + n]);
        self.bytes_read += n;
        return n;
    }
};

test "XxHash64 matches official reference vectors" {
    try std.testing.expectEqual(@as(u64, 0xEF46DB3751D8E999), XxHash64.hash(0, ""));
    try std.testing.expectEqual(@as(u64, 0xD24EC4F1A98C6E5B), XxHash64.hash(0, "a"));
    try std.testing.expectEqual(@as(u64, 0x44BC2CF5AD770999), XxHash64.hash(0, "abc"));

    // Multi-stripe (> 32B) streaming vs single-shot equivalence
    const msg = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_seekable_zstd_xxhash64";
    const one_shot = XxHash64.hash(0, msg);
    var stream = XxHash64.init(0);
    stream.update(msg[0..13]);
    stream.update(msg[13..45]);
    stream.update(msg[45..]);
    try std.testing.expectEqual(one_shot, stream.final());
}

test "ZstdSeekTable: compressSeekableZstdAlloc, tail-only parseFromRandomAccess, binary search, and line probing" {
    const alloc = std.testing.allocator;

    // Build structured log lines (~20 KiB) split across ~20 Zstd frames of max 1024 bytes each
    var raw = std.ArrayList(u8).empty;
    defer raw.deinit(alloc);
    var line_offsets = std.ArrayList(u64).empty;
    defer line_offsets.deinit(alloc);

    var tmp_line: [96]u8 = undefined;
    for (0..300) |idx| {
        try line_offsets.append(alloc, @intCast(raw.items.len));
        const formatted = try std.fmt.bufPrint(&tmp_line, "2026-11-18T00:00:00Z level=INFO seq={d:0>5} msg=seekable_zstd_record_{d}\r\n", .{ idx, idx * 7 });
        try raw.appendSlice(alloc, formatted);
    }

    const seekable_zst = try compressSeekableZstdAlloc(alloc, raw.items, 1024);
    defer alloc.free(seekable_zst);

    // 1. Tail-only read verification via CountingRandomAccess
    var counting = CountingRandomAccess{ .data = seekable_zst };
    var table = try ZstdSeekTable.parseFromRandomAccess(alloc, counting.randomAccess());
    defer table.deinit(alloc);

    try std.testing.expectEqual(@as(u64, raw.items.len), table.total_uncompressed_size);
    try std.testing.expect(table.entries.len >= 20);
    try std.testing.expect(table.has_checksum);
    // Must ONLY have read the trailing seek table (< 512 bytes), never touching the ~20 KiB payload!
    try std.testing.expect(counting.bytes_read < 512);
    try std.testing.expect(counting.min_offset_seen > raw.items.len);

    // 2. buildFromSlice and serializeAlloc / parseFromSlice equivalence
    var scanned = try ZstdSeekTable.buildFromSlice(alloc, seekable_zst);
    defer scanned.deinit(alloc);
    try std.testing.expectEqual(table.entries.len, scanned.entries.len);
    try std.testing.expectEqual(table.total_uncompressed_size, scanned.total_uncompressed_size);

    const standalone_st = try table.serializeAlloc(alloc);
    defer alloc.free(standalone_st);
    var reparsed = try ZstdSeekTable.parseFromSlice(alloc, standalone_st);
    defer reparsed.deinit(alloc);
    try std.testing.expectEqual(table.entries.len, reparsed.entries.len);

    // 3. Cross-frame random reads + SeekableZstdReader.randomAccess() + probeLineAt
    const zstd_reader = SeekableZstdReader.init(alloc, counting.randomAccess(), &table);
    const uncomp_ra = zstd_reader.randomAccess();

    var cross_buf: [2500]u8 = undefined;
    const n_cross = try uncomp_ra.readAtFull(900, &cross_buf);
    try std.testing.expectEqual(@as(usize, 2500), n_cross);
    try std.testing.expectEqualStrings(raw.items[900..3400], cross_buf[0..n_cross]);

    // Probe lines at beginning, frame boundary, middle, and end
    const probe_indices = [_]usize{ 0, 14, 15, 150, 299 };
    for (probe_indices) |line_idx| {
        const target_off = line_offsets.items[line_idx] + 10;
        const expected = probe.probeLineSlice(raw.items, target_off, .{}).?;
        var actual = (try probe.probeLineAt(alloc, uncomp_ra, target_off, .{ .window_chunk_bytes = 256 })).?;
        defer actual.deinit(alloc);
        try std.testing.expectEqual(expected.start_offset, actual.start_offset);
        try std.testing.expectEqual(expected.end_offset, actual.end_offset);
        try std.testing.expectEqual(expected.raw_end_offset, actual.raw_end_offset);
        try std.testing.expectEqualStrings(expected.bytes, actual.bytes);
    }

    // 4. Corruption rejection (footer magic, reserved descriptor bits, and XXH64 frame payload bit-flip)
    var bad_footer = try alloc.dupe(u8, seekable_zst);
    defer alloc.free(bad_footer);
    bad_footer[bad_footer.len - 1] ^= 0xFF;
    try std.testing.expectError(error.CorruptSeekTable, ZstdSeekTable.parseFromSlice(alloc, bad_footer));

    var bad_desc = try alloc.dupe(u8, standalone_st);
    defer alloc.free(bad_desc);
    bad_desc[bad_desc.len - 5] |= 0x04; // Set reserved bit 2
    try std.testing.expectError(error.CorruptSeekTable, ZstdSeekTable.parseFromSlice(alloc, bad_desc));

    var bad_payload = try alloc.dupe(u8, seekable_zst);
    defer alloc.free(bad_payload);
    bad_payload[@as(usize, @intCast(table.entries[3].comp_offset)) + 12] ^= 0x01; // Flip 1 payload bit inside frame 3
    const bad_payload_const: []const u8 = bad_payload;
    const bad_src = probe.RandomAccess.fromSlice(&bad_payload_const);
    var scratch_read: [32]u8 = undefined;
    try std.testing.expectError(
        error.CorruptStream,
        table.readAt(alloc, bad_src, table.entries[3].uncomp_offset, &scratch_read, null),
    );
}

fn appendGzipMemberDynamicTest(allocator: std.mem.Allocator, out: *std.ArrayList(u8), payload: []const u8) !void {
    // Emit a genuine BTYPE=10 Dynamic Huffman Gzip member exercising code-length symbols 0..8, 16, 17, 18 + LZ77
    try out.appendSlice(allocator, &[_]u8{ 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 });
    var bw = BitWriter{ .list = out, .allocator = allocator };

    // BFINAL=1, BTYPE=10 (Dynamic Huffman)
    try bw.writeBits(1, 1);
    try bw.writeBits(2, 2);

    // Build uniform valid canonical lengths:
    // - All 256 byte literals + 256 (EOB) + 257 (length 3): 258 symbols -> 254 of length 9, 4 of length 7?
    //   Check Kraft sum: 4 * 2^-7 + 254 * 2^-9 = 16/512 + 254/512 = 270/512 <= 1 (valid canonical tree; even better: exact Kraft = 1:
    //   254 * 2^-8 + 4 * 2^-9 = 508/512 + 4/512 = 512/512 = 1.0!).
    //   Let's check: symbols 0..253 -> length 8 (254 symbols), symbols 254..257 -> length 9 (4 symbols)!
    //   254 * 2 + 4 * 1 = 512 = 2^9! Exact complete Huffman tree!
    // - Distance codes 0..3 -> length 2 (4 * 2^-2 = 1.0!), 4..29 -> length 0 (26 zeros -> exercises symbol 18!).
    const hlit: usize = 258; // 0..257
    const hdist: usize = 30; // 0..29
    const hclen: usize = 19; // all 19 code-length symbols

    try bw.writeBits(@intCast(hlit - 257), 5);
    try bw.writeBits(@intCast(hdist - 1), 5);
    try bw.writeBits(@intCast(hclen - 4), 4);

    // Code-length alphabet: give symbols {0, 2, 8, 9, 16, 17, 18} (7 symbols) valid Kraft-complete lengths:
    // 1 symbol of len 2 ('8'), 6 symbols of len 3 ({0, 2, 9, 16, 17, 18}) -> 1*(1/4) + 6*(1/8) = 2/8 + 6/8 = 1.0!
    var cl_lens: [19]u5 = @splat(0);
    cl_lens[8] = 2;
    cl_lens[0] = 3;
    cl_lens[2] = 3;
    cl_lens[9] = 3;
    cl_lens[16] = 3;
    cl_lens[17] = 3;
    cl_lens[18] = 3;

    for (0..hclen) |i| {
        try bw.writeBits(cl_lens[cl_order[i]], 3);
    }

    // Compute canonical MSB codes for cl_lens
    var cl_codes: [19]u16 = @splat(0);
    {
        var bl: [16]u16 = @splat(0);
        for (cl_lens) |l| if (l > 0) {
            bl[l] += 1;
        };
        var nc: [16]u16 = @splat(0);
        var c: u16 = 0;
        for (1..16) |b| {
            c = (c + bl[b - 1]) << 1;
            nc[b] = c;
        }
        for (cl_lens, 0..) |l, s| if (l > 0) {
            cl_codes[s] = nc[l];
            nc[l] += 1;
        };
    }

    // Emit 254 copies of length '8' using literal '8' + RLE symbol '16' (repeat 6 at a time)
    try bw.writeHuffCode(cl_codes[8], cl_lens[8]);
    var rem8: usize = 253;
    while (rem8 >= 3) {
        const rep = @min(rem8, 6);
        try bw.writeHuffCode(cl_codes[16], cl_lens[16]);
        try bw.writeBits(@intCast(rep - 3), 2);
        rem8 -= rep;
    }
    while (rem8 > 0) : (rem8 -= 1) {
        try bw.writeHuffCode(cl_codes[8], cl_lens[8]);
    }
    // Emit 4 copies of length '9' (symbols 254..257) using '9' + symbol '16' (repeat 3)
    try bw.writeHuffCode(cl_codes[9], cl_lens[9]);
    try bw.writeHuffCode(cl_codes[16], cl_lens[16]);
    try bw.writeBits(0, 2); // repeat 3 times

    // Emit distance lengths: 0..3 -> len 2 (4 times: '2' + '16' repeat 3), then 26 zeros: '17' (repeat 6 zeros) + '18' (repeat 20 zeros)!
    try bw.writeHuffCode(cl_codes[2], cl_lens[2]);
    try bw.writeHuffCode(cl_codes[16], cl_lens[16]);
    try bw.writeBits(0, 2);
    try bw.writeHuffCode(cl_codes[17], cl_lens[17]);
    try bw.writeBits(6 - 3, 3); // 6 zeros
    try bw.writeHuffCode(cl_codes[18], cl_lens[18]);
    try bw.writeBits(20 - 11, 7); // 20 zeros (6 + 20 = 26)

    // Compute canonical MSB codes for lit_lens: 0..253 -> 8 (codes 0..253), 254..257 -> 9 (codes 508..511)
    // and dist_lens: 0..3 -> 2 (codes 0..3)
    var i: usize = 0;
    while (i < payload.len) {
        // Use LZ77 match of exact length 3 (sym 257) and distance 1..4 (dist_sym 0..3) whenever available!
        var matched_dist: ?usize = null;
        if (i >= 1 and i + 3 <= payload.len) {
            for (1..@min(i, 4) + 1) |d| {
                if (std.mem.eql(u8, payload[i - d .. i - d + 3], payload[i .. i + 3])) {
                    matched_dist = d;
                    break;
                }
            }
        }
        if (matched_dist) |d| {
            // sym 257 -> code 508 + (257 - 254) = 511, len 9
            try bw.writeHuffCode(511, 9);
            try bw.writeHuffCode(@intCast(d - 1), 2);
            i += 3;
        } else {
            const b = payload[i];
            if (b <= 253) {
                try bw.writeHuffCode(b, 8);
            } else {
                try bw.writeHuffCode(508 + (@as(u16, b) - 254), 9);
            }
            i += 1;
        }
    }
    // End of block: sym 256 -> code 508 + (256 - 254) = 510, len 9
    try bw.writeHuffCode(510, 9);
    try bw.alignZero();

    var footer: [8]u8 = undefined;
    std.mem.writeInt(u32, footer[0..4], std.hash.Crc32.hash(payload), .little);
    std.mem.writeInt(u32, footer[4..8], @truncate(payload.len), .little);
    try out.appendSlice(allocator, &footer);
}

test "GzipIndex: Stored + Fixed Huffman + Dynamic Huffman multi-member Gzip, checkpoints, serialization, and probeLineAt" {
    const alloc = std.testing.allocator;

    // Member 0: Stored Deflate blocks (via decompress.compressGzipStoredAlloc)
    const m0_text = "member0_line0\r\nmember0_line1_stored_block\r\n";
    const m0_gz = try decompress.compressGzipStoredAlloc(alloc, m0_text);
    defer alloc.free(m0_gz);

    // Member 1: ~24 KiB Fixed Huffman multi-block stream with cross-block LZ77 dictionary matches
    var m1_buf = std.ArrayList(u8).empty;
    defer m1_buf.deinit(alloc);
    var line_tmp: [128]u8 = undefined;
    for (0..320) |idx| {
        const s = try std.fmt.bufPrint(&line_tmp, "member1_fixed_huffman_repeated_prefix_seq={d:0>4}_payload=alpha_beta_gamma\n", .{idx});
        try m1_buf.appendSlice(alloc, s);
    }
    const m1_gz = try compressMultiMemberGzipAlloc(alloc, &.{m1_buf.items});
    defer alloc.free(m1_gz);

    // Verify m1_gz with Zig stdlib flate.Decompress to prove 100% RFC 1951/1952 compliance
    {
        var fixed_r = std.Io.Reader.fixed(m1_gz);
        var flate_win: [std.compress.flate.max_window_len]u8 = undefined;
        var std_dec = std.compress.flate.Decompress.init(&fixed_r, .gzip, &flate_win);
        const check_m1 = try alloc.alloc(u8, m1_buf.items.len + 16);
        defer alloc.free(check_m1);
        var got_total: usize = 0;
        while (true) {
            const n = try std_dec.reader.readSliceShort(check_m1[got_total..]);
            if (n == 0) break;
            got_total += n;
        }
        try std.testing.expectEqualStrings(m1_buf.items, check_m1[0..got_total]);
    }

    // Member 2: Dynamic Huffman (BTYPE=10) with repeated trigram LZ77 + high bytes 0xFE/0xFF
    const m2_text = "member2_dynamic_huffman_aaabbbccc_111222333_\xFE\xFF_lineA\nmember2_final_line_xyz\n";
    var m2_gz = std.ArrayList(u8).empty;
    defer m2_gz.deinit(alloc);
    try appendGzipMemberDynamicTest(alloc, &m2_gz, m2_text);

    // Verify m2_gz with Zig stdlib flate.Decompress as well!
    {
        var fixed_r = std.Io.Reader.fixed(m2_gz.items);
        var flate_win: [std.compress.flate.max_window_len]u8 = undefined;
        var std_dec = std.compress.flate.Decompress.init(&fixed_r, .gzip, &flate_win);
        var check_m2: [256]u8 = undefined;
        var got_total: usize = 0;
        while (true) {
            const n = try std_dec.reader.readSliceShort(check_m2[got_total..]);
            if (n == 0) break;
            got_total += n;
        }
        try std.testing.expectEqualStrings(m2_text, check_m2[0..got_total]);
    }

    // Concatenate all 3 members (Stored + Multi-block Fixed + Dynamic) into a single multi-member .gz!
    var combined_gz = std.ArrayList(u8).empty;
    defer combined_gz.deinit(alloc);
    try combined_gz.appendSlice(alloc, m0_gz);
    try combined_gz.appendSlice(alloc, m1_gz);
    try combined_gz.appendSlice(alloc, m2_gz.items);

    var combined_uncomp = std.ArrayList(u8).empty;
    defer combined_uncomp.deinit(alloc);
    try combined_uncomp.appendSlice(alloc, m0_text);
    try combined_uncomp.appendSlice(alloc, m1_buf.items);
    try combined_uncomp.appendSlice(alloc, m2_text);

    // Build GzipIndex with 4 KiB checkpoint interval so mid-member Deflate block checkpoints are created
    var gz_index = try GzipIndex.buildFromSlice(alloc, combined_gz.items, 4096);
    defer gz_index.deinit(alloc);

    try std.testing.expectEqual(@as(u64, combined_gz.items.len), gz_index.total_compressed_size);
    try std.testing.expectEqual(@as(u64, combined_uncomp.items.len), gz_index.total_uncompressed_size);
    // At least 3 member starts + multiple mid-member checkpoints in m1!
    try std.testing.expect(gz_index.checkpoints.len >= 6);

    var saw_mid_member = false;
    for (gz_index.checkpoints) |cp| {
        if (!cp.is_member_start) saw_mid_member = true;
    }
    try std.testing.expect(saw_mid_member);

    // Roundtrip serializeAlloc -> deserialize
    const ser = try gz_index.serializeAlloc(alloc);
    defer alloc.free(ser);
    var deser = try GzipIndex.deserialize(alloc, ser);
    defer deser.deinit(alloc);
    try std.testing.expectEqual(gz_index.checkpoints.len, deser.checkpoints.len);
    try std.testing.expectEqual(gz_index.total_uncompressed_size, deser.total_uncompressed_size);

    // Corrupt serialized index CRC rejection
    var bad_ser = try alloc.dupe(u8, ser);
    defer alloc.free(bad_ser);
    bad_ser[bad_ser.len / 2] ^= 0x40;
    try std.testing.expectError(error.CorruptIndex, GzipIndex.deserialize(alloc, bad_ser));

    // Crafted 36-byte GzipIndex with valid CRC32 claiming 3,000,000 checkpoints must be rejected before allocation!
    {
        var crafted: [36]u8 = @splat(0);
        @memcpy(crafted[0..8], "WGZIDX\x01\x00");
        std.mem.writeInt(u64, crafted[8..16], 1000, .little);
        std.mem.writeInt(u64, crafted[16..24], 1000, .little);
        std.mem.writeInt(u64, crafted[24..32], 3_000_000, .little);
        const c_crc = std.hash.Crc32.hash(crafted[0..32]);
        std.mem.writeInt(u32, crafted[32..36], c_crc, .little);
        try std.testing.expectError(error.CorruptIndex, GzipIndex.deserialize(alloc, &crafted));
    }

    // Crafted standalone ZstdSeekTable claiming a huge compressed_size exceeding source.size must be rejected before allocation!
    {
        var bogus_entries = [_]ZstdSeekTable.FrameEntry{.{
            .frame_index = 0,
            .comp_offset = 0,
            .compressed_size = 500 * 1024 * 1024,
            .uncomp_offset = 0,
            .uncompressed_size = 500 * 1024 * 1024,
            .checksum = 0,
        }};
        const bogus_st = ZstdSeekTable{
            .entries = &bogus_entries,
            .has_checksum = true,
            .total_compressed_size = 500 * 1024 * 1024,
            .total_uncompressed_size = 500 * 1024 * 1024,
        };
        const tiny_slice: []const u8 = "tiny";
        const tiny_ra = probe.RandomAccess.fromSlice(&tiny_slice);
        var out_tmp: [16]u8 = undefined;
        try std.testing.expectError(
            error.CorruptStream,
            bogus_st.readAt(alloc, tiny_ra, 0, &out_tmp, null),
        );
    }

    // Random reads across member boundaries and mid-member checkpoints + probe.probeLineAt
    const gz_slice_const: []const u8 = combined_gz.items;
    const raw_ra = probe.RandomAccess.fromSlice(&gz_slice_const);
    const idx_reader = IndexedGzipReader.init(alloc, raw_ra, &deser);
    const uncomp_ra = idx_reader.randomAccess();

    // Cross-member read spanning m0 -> m1 -> m2
    const full_verify = try alloc.alloc(u8, combined_uncomp.items.len);
    defer alloc.free(full_verify);
    const full_n = try uncomp_ra.readAtFull(0, full_verify);
    try std.testing.expectEqual(combined_uncomp.items.len, full_n);
    try std.testing.expectEqualStrings(combined_uncomp.items, full_verify);

    // Probe lines at multiple offsets across Stored, mid-member Fixed checkpoints, and Dynamic member
    const test_offsets = [_]u64{
        5,
        @intCast(m0_text.len + 10),
        @intCast(m0_text.len + 9500),
        @intCast(m0_text.len + 19200),
        @intCast(m0_text.len + m1_buf.items.len + 12),
        @intCast(combined_uncomp.items.len - 5),
    };
    for (test_offsets) |off| {
        const expected = probe.probeLineSlice(combined_uncomp.items, off, .{}).?;
        var actual = (try probe.probeLineAt(alloc, uncomp_ra, off, .{ .window_chunk_bytes = 128 })).?;
        defer actual.deinit(alloc);
        try std.testing.expectEqual(expected.start_offset, actual.start_offset);
        try std.testing.expectEqual(expected.end_offset, actual.end_offset);
        try std.testing.expectEqual(expected.raw_end_offset, actual.raw_end_offset);
        try std.testing.expectEqualStrings(expected.bytes, actual.bytes);
    }
}
