//! [Module] codec/offset_map.zig
//! [Layer] Layer 3 — Stream Codec & Coordinate Mapping
//! [Role] Monotonic piecewise-linear coordinate mapper from searchable UTF-8 stream offsets (`SearchByteOffset`)
//!        back to pre-transcode / pre-decompression raw byte offsets (`RawByteOffset`).
//! [Invariants]
//!   1. Recorded `(out_offset, raw_offset)` anchors must be monotonically non-decreasing in `out_offset`.
//!   2. Consecutive collinear steps (e.g., 2 raw bytes -> 1 UTF-8 byte across ASCII runs in UTF-16LE)
//!      are coalesced in-place in O(1) space.
//! [HotPath] `record` (collinear fast path) and `map` (binary search + linear interpolation).

const std = @import("std");

/// Byte offset within the decoded, searchable UTF-8 byte stream.
pub const SearchByteOffset = u64;

/// Byte offset within the original raw input stream (before BOM stripping, transcoding, or decompression).
pub const RawByteOffset = u64;

/// Block-level and character-run offset map: maps searchable stream offsets after decompression or transcoding
/// back to raw input byte offsets.
pub const OffsetMap = struct {
    pub const Anchor = struct {
        out_offset: SearchByteOffset,
        raw_offset: RawByteOffset,
    };

    anchors: std.ArrayList(Anchor) = .empty,
    /// Fixed leading offset (e.g., `base_raw_offset = 3` after stripping a 3-byte UTF-8 BOM).
    base_raw_offset: RawByteOffset = 0,
    active: bool = false,

    pub fn deinit(self: *OffsetMap, allocator: std.mem.Allocator) void {
        self.anchors.deinit(allocator);
        self.* = .{};
    }

    pub fn record(
        self: *OffsetMap,
        allocator: std.mem.Allocator,
        out_offset: SearchByteOffset,
        raw_offset: RawByteOffset,
    ) error{OutOfMemory}!void {
        self.active = true;
        const len = self.anchors.items.len;
        if (len > 0) {
            const last = &self.anchors.items[len - 1];
            if (last.out_offset == out_offset) {
                last.raw_offset = raw_offset;
                return;
            }
            if (out_offset < last.out_offset) return;
            if (len >= 2) {
                const prev = self.anchors.items[len - 2];
                const d_out1 = last.out_offset - prev.out_offset;
                const d_raw1 = last.raw_offset -| prev.raw_offset;
                const d_out2 = out_offset - last.out_offset;
                const d_raw2 = raw_offset -| last.raw_offset;
                if (d_out1 > 0 and d_out2 > 0 and last.raw_offset >= prev.raw_offset and raw_offset >= last.raw_offset) {
                    if (@as(u128, d_raw1) * @as(u128, d_out2) == @as(u128, d_raw2) * @as(u128, d_out1)) {
                        last.out_offset = out_offset;
                        last.raw_offset = raw_offset;
                        return;
                    }
                }
            }
        }
        try self.anchors.append(allocator, .{
            .out_offset = out_offset,
            .raw_offset = raw_offset,
        });
    }

    /// Given an absolute offset `out_offset` in the searchable stream, returns the corresponding raw byte stream offset.
    pub fn map(self: *const OffsetMap, out_offset: SearchByteOffset) RawByteOffset {
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

test "offset_map: collinear compaction and exact interpolation" {
    const gpa = std.testing.allocator;
    var om: OffsetMap = .{};
    defer om.deinit(gpa);

    // Simulate UTF-16LE after 2-byte BOM: each ASCII byte advances out by 1 and raw by 2
    var i: u64 = 0;
    while (i <= 100) : (i += 1) {
        try om.record(gpa, i, 2 + i * 2);
    }
    // Collinear compaction must collapse all 101 points into just 2 anchors!
    try std.testing.expectEqual(@as(usize, 2), om.anchors.items.len);
    for (0..101) |k| {
        const out_off: u64 = @intCast(k);
        try std.testing.expectEqual(2 + out_off * 2, om.map(out_off));
    }
}
