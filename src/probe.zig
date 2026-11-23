//! [Module] probe.zig
//! [Layer] Layer 1/3 — Byte-Offset Line Probe & RandomAccess Abstraction
//! [Role] Extracts the exact enclosing line (or bounded window) around an arbitrary byte offset
//!        over an in-memory slice or abstract `RandomAccess` source without path or file handles.
//! [Invariants]
//!   1. Zero filesystem file or directory handle references; all positional reads go through `RandomAccess`.
//!   2. Partition invariant: for any `0 <= offset < total_len`, `start_offset <= offset < raw_end_offset`,
//!      and consecutive lines partition `[0, total_len)` into disjoint half-open `[start_offset, raw_end_offset)` spans.
//!   3. Lines exceeding `max_line_bytes` (or `buf.len` in `probeLineAtBuf`) scan at most O(`max_line_bytes`)
//!      bytes around `offset` and report `truncated_left` / `truncated_right` accurately.
//! [HotPath] `probeLineSlice` -> `memchr.findLast` + `memchr.find`.

const std = @import("std");
const memchr = @import("finder/memchr.zig");

/// Handle-free, path-free positional byte reader interface.
/// `read_at` reads bytes starting at `offset` into `dest` and returns `0` at or past EOF.
pub const RandomAccess = struct {
    ctx: ?*anyopaque = null,
    read_at: *const fn (?*anyopaque, u64, []u8) anyerror!usize,
    size: ?u64 = null,

    /// Performs a single positional read at `offset`. Returns `0` when `dest` is empty or `offset` is at/past `size`.
    pub fn readAt(self: RandomAccess, offset: u64, dest: []u8) anyerror!usize {
        if (dest.len == 0) return 0;
        if (self.size) |sz| {
            if (offset >= sz) return 0;
        }
        return self.read_at(self.ctx, offset, dest);
    }

    /// Reads into `dest` starting at `offset`, looping across short reads until `dest.len` is filled or EOF (`0`) is reached.
    pub fn readAtFull(self: RandomAccess, offset: u64, dest: []u8) anyerror!usize {
        if (dest.len == 0) return 0;
        var filled: usize = 0;
        while (filled < dest.len) {
            const cur_off = std.math.add(u64, offset, filled) catch break;
            const n = try self.readAt(cur_off, dest[filled..]);
            if (n == 0) break;
            if (n > dest.len - filled) return error.InvalidReadLength;
            filled += n;
        }
        return filled;
    }

    /// Wraps an in-memory byte slice pointer (`*const []const u8`) as a `RandomAccess` source.
    /// `slice` pointer must remain valid for the lifetime of the returned `RandomAccess`.
    pub fn fromSlice(slice: *const []const u8) RandomAccess {
        return .{
            .ctx = @ptrCast(@constCast(slice)),
            .read_at = sliceReadAt,
            .size = @intCast(slice.*.len),
        };
    }

    fn sliceReadAt(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const ptr: *const []const u8 = @ptrCast(@alignCast(ctx.?));
        const s = ptr.*;
        if (offset >= s.len or dest.len == 0) return 0;
        const off: usize = @intCast(offset);
        const n = @min(dest.len, s.len - off);
        @memcpy(dest[0..n], s[off .. off + n]);
        return n;
    }
};

/// Configuration for byte-offset line probing.
pub const ProbeOptions = struct {
    delimiter: u8 = '\n',
    strip_crlf: bool = true,
    max_line_bytes: usize = 2 * 1024 * 1024,
    window_chunk_bytes: usize = 4096,
};

/// Extracted line (or bounded window) enclosing a probed byte offset.
pub const LineProbe = struct {
    /// Start byte offset of `bytes` in the underlying input.
    start_offset: u64,
    /// End byte offset of `bytes` in the underlying input (excluding stripped delimiter / CRLF).
    end_offset: u64,
    /// Exclusive raw end offset including the terminating delimiter (or truncated window end).
    /// Always satisfies `start_offset <= offset < raw_end_offset`.
    raw_end_offset: u64,
    /// Content bytes `[start_offset .. end_offset)`. Borrows from `haystack`, `buf`, or `owned`.
    bytes: []const u8,
    /// True when the line began strictly before `start_offset` due to `max_line_bytes` (or `buf.len`) cap.
    truncated_left: bool = false,
    /// True when the line content continued strictly past `end_offset` due to `max_line_bytes` (or `buf.len`) cap.
    truncated_right: bool = false,
    /// Heap buffer allocated by `probeLineAt`, or empty (`&.{}`) for zero-allocation probes.
    owned: []u8 = &.{},

    pub fn deinit(self: *LineProbe, allocator: std.mem.Allocator) void {
        if (self.owned.len != 0) {
            allocator.free(self.owned);
        }
        self.* = undefined;
    }
};

const WindowPlan = struct {
    start_offset: u64,
    end_offset: u64,
    raw_end_offset: u64,
    truncated_left: bool,
    truncated_right: bool,
};

fn computeWindowPlan(
    offset: u64,
    max_cap: usize,
    options: ProbeOptions,
    known_true_start: ?u64,
    d_right: ?u64,
    eof_right: ?u64,
    byte_before_d_right: ?u8,
) WindowPlan {
    const known_raw_end: ?u64 = if (d_right) |dr| dr + 1 else eof_right;
    const known_content_end: ?u64 = if (d_right) |dr| blk: {
        var ce = dr;
        if (options.strip_crlf and options.delimiter == '\n') {
            const min_line_start: u64 = known_true_start orelse 0;
            if (ce > min_line_start and byte_before_d_right == '\r') {
                ce -= 1;
            }
        }
        break :blk ce;
    } else eof_right;

    const cap64: u64 = @intCast(max_cap);

    // Fast path: full line fits within max_cap
    if (known_true_start) |ts| {
        if (known_content_end) |ce| {
            if (ce - ts <= cap64) {
                return .{
                    .start_offset = ts,
                    .end_offset = ce,
                    .raw_end_offset = known_raw_end.?,
                    .truncated_left = false,
                    .truncated_right = false,
                };
            }
        }
    }

    // Zero-capacity edge case on a non-empty line
    if (cap64 == 0) {
        const clamped = if (known_content_end) |ce| @min(offset, ce) else offset;
        const trunc_l = if (known_true_start) |ts| clamped > ts else true;
        const trunc_r = if (known_content_end) |ce| clamped < ce else true;
        const raw_end = if (!trunc_r) known_raw_end.? else offset + 1;
        return .{
            .start_offset = clamped,
            .end_offset = clamped,
            .raw_end_offset = raw_end,
            .truncated_left = trunc_l,
            .truncated_right = trunc_r,
        };
    }

    // Truncated long line: center window around offset, pinning to true start or content end if close
    const clamped_off = if (known_content_end) |ce| @min(offset, ce) else offset;
    const half_left: u64 = cap64 / 2;
    const half_right: u64 = cap64 - half_left;

    var win_start: u64 = 0;
    var win_end: u64 = 0;

    if (known_true_start != null and clamped_off - known_true_start.? <= half_left) {
        win_start = known_true_start.?;
        win_end = win_start + cap64;
    } else if (known_content_end != null and (clamped_off >= known_content_end.? or known_content_end.? - clamped_off <= half_right)) {
        win_end = known_content_end.?;
        win_start = win_end - cap64;
    } else {
        win_start = clamped_off - half_left;
        win_end = win_start + cap64;
    }

    const trunc_left = if (known_true_start) |ts| win_start > ts else true;
    const trunc_right = if (known_content_end) |ce| win_end < ce else true;
    const raw_end = if (!trunc_right) known_raw_end.? else @max(win_end, offset + 1);

    return .{
        .start_offset = win_start,
        .end_offset = win_end,
        .raw_end_offset = raw_end,
        .truncated_left = trunc_left,
        .truncated_right = trunc_right,
    };
}

/// Zero-allocation line probe over an in-memory `haystack` slice.
/// Returns `null` when `haystack` is empty or `offset >= haystack.len`.
pub fn probeLineSlice(haystack: []const u8, offset: u64, options: ProbeOptions) ?LineProbe {
    if (haystack.len == 0 or offset >= haystack.len) return null;
    const off: usize = @intCast(offset);
    const max_cap = options.max_line_bytes;
    const scan_budget: usize = max_cap +| 2;

    // Backward scan strictly before `off`, bounded by `scan_budget`
    const back_lo: usize = off -| scan_budget;
    const d_left_usize = memchr.findLast(memchr.native_width, haystack, back_lo, off, options.delimiter);
    const known_true_start: ?u64 = if (d_left_usize) |dl|
        @intCast(dl + 1)
    else if (back_lo == 0)
        0
    else
        null;

    // Forward scan starting at `off`, bounded by `scan_budget`
    const fwd_hi: usize = @min(haystack.len, off +| scan_budget);
    const d_right_usize: ?usize = if (haystack[off] == options.delimiter)
        off
    else
        std.mem.findScalarPos(u8, haystack[0..fwd_hi], off + 1, options.delimiter);

    const d_right: ?u64 = if (d_right_usize) |dr| @intCast(dr) else null;
    const eof_right: ?u64 = if (d_right == null and fwd_hi == haystack.len) @intCast(haystack.len) else null;
    const byte_before_d_right: ?u8 = if (d_right_usize) |dr|
        (if (dr > 0) haystack[dr - 1] else null)
    else
        null;

    const plan = computeWindowPlan(
        offset,
        max_cap,
        options,
        known_true_start,
        d_right,
        eof_right,
        byte_before_d_right,
    );

    const ws: usize = @intCast(plan.start_offset);
    const we: usize = @intCast(plan.end_offset);
    return .{
        .start_offset = plan.start_offset,
        .end_offset = plan.end_offset,
        .raw_end_offset = plan.raw_end_offset,
        .bytes = haystack[ws..we],
        .truncated_left = plan.truncated_left,
        .truncated_right = plan.truncated_right,
        .owned = &.{},
    };
}

fn planRandomAccess(
    source: RandomAccess,
    offset: u64,
    max_cap: usize,
    options: ProbeOptions,
) !?WindowPlan {
    if (source.size) |sz| {
        if (offset >= sz) return null;
    }

    var chunk_buf: [4096]u8 = undefined;
    const raw_step = if (options.window_chunk_bytes == 0) @as(usize, 4096) else options.window_chunk_bytes;
    const step: usize = @max(@as(usize, 1), @min(raw_step, chunk_buf.len));
    const fwd_budget: u64 = @as(u64, max_cap) +| 2;

    // 1. Read forward starting at `offset` (also checks EOF at `offset`)
    const first_want: usize = @intCast(@max(@as(u64, 1), @min(@as(u64, step), fwd_budget)));
    const first_n = try source.readAtFull(offset, chunk_buf[0..first_want]);
    if (first_n == 0) return null;

    var d_right: ?u64 = null;
    var eof_right: ?u64 = null;
    var byte_before_d_right: ?u8 = null;

    if (chunk_buf[0] == options.delimiter) {
        d_right = offset;
    } else if (std.mem.findScalarPos(u8, chunk_buf[0..first_n], 1, options.delimiter)) |rel| {
        d_right = offset + rel;
        byte_before_d_right = chunk_buf[rel - 1];
    } else if (first_n < first_want) {
        eof_right = offset + first_n;
    } else {
        var prev_last: u8 = chunk_buf[first_n - 1];
        var cur: u64 = offset + first_n;
        while (cur - offset < fwd_budget) {
            const rem_budget = fwd_budget - (cur - offset);
            const want: usize = @intCast(@min(@as(u64, step), rem_budget));
            const n = try source.readAtFull(cur, chunk_buf[0..want]);
            if (n == 0) {
                eof_right = cur;
                break;
            }
            if (std.mem.findScalarPos(u8, chunk_buf[0..n], 0, options.delimiter)) |rel| {
                d_right = cur + rel;
                byte_before_d_right = if (rel > 0) chunk_buf[rel - 1] else prev_last;
                break;
            }
            prev_last = chunk_buf[n - 1];
            cur += n;
            if (n < want) {
                eof_right = cur;
                break;
            }
        }
    }

    // 2. Read backward strictly before `offset`
    var d_left: ?u64 = null;
    var reached_bof = (offset == 0);
    var byte_before_offset: ?u8 = null;

    if (offset > 0) {
        const back_budget: u64 = @min(offset, @as(u64, max_cap) +| 2);
        const min_off: u64 = offset - back_budget;
        var cur_end: u64 = offset;
        while (cur_end > min_off) {
            const want: usize = @intCast(@min(@as(u64, step), cur_end - min_off));
            const read_off: u64 = cur_end - want;
            const n = try source.readAtFull(read_off, chunk_buf[0..want]);
            if (n == 0) break;
            if (read_off + n == offset) {
                byte_before_offset = chunk_buf[n - 1];
            }
            if (memchr.findLast(memchr.native_width, chunk_buf[0..n], 0, n, options.delimiter)) |rel| {
                d_left = read_off + rel;
                break;
            }
            cur_end = read_off;
        }
        if (d_left == null and cur_end == 0) {
            reached_bof = true;
        }
    }

    if (d_right != null and d_right.? == offset) {
        byte_before_d_right = byte_before_offset;
    }

    const known_true_start: ?u64 = if (d_left) |dl|
        dl + 1
    else if (reached_bof)
        0
    else
        null;

    return computeWindowPlan(
        offset,
        max_cap,
        options,
        known_true_start,
        d_right,
        eof_right,
        byte_before_d_right,
    );
}

/// Zero-heap-allocation line probe over `RandomAccess`, storing the extracted line bytes into `buf`.
/// Effective maximum line length is `@min(options.max_line_bytes, buf.len)`.
pub fn probeLineAtBuf(
    source: RandomAccess,
    offset: u64,
    buf: []u8,
    options: ProbeOptions,
) !?LineProbe {
    const max_cap = @min(options.max_line_bytes, buf.len);
    const plan = (try planRandomAccess(source, offset, max_cap, options)) orelse return null;
    const win_len: usize = @intCast(plan.end_offset - plan.start_offset);
    if (win_len == 0) {
        return .{
            .start_offset = plan.start_offset,
            .end_offset = plan.end_offset,
            .raw_end_offset = plan.raw_end_offset,
            .bytes = buf[0..0],
            .truncated_left = plan.truncated_left,
            .truncated_right = plan.truncated_right,
            .owned = &.{},
        };
    }
    const got = try source.readAtFull(plan.start_offset, buf[0..win_len]);
    if (got != win_len) return error.UnexpectedEof;
    return .{
        .start_offset = plan.start_offset,
        .end_offset = plan.end_offset,
        .raw_end_offset = plan.raw_end_offset,
        .bytes = buf[0..got],
        .truncated_left = plan.truncated_left,
        .truncated_right = plan.truncated_right,
        .owned = &.{},
    };
}

/// Allocator-backed line probe over `RandomAccess`. Caller owns `LineProbe` and must call `lp.deinit(allocator)`.
pub fn probeLineAt(
    allocator: std.mem.Allocator,
    source: RandomAccess,
    offset: u64,
    options: ProbeOptions,
) !?LineProbe {
    const plan = (try planRandomAccess(source, offset, options.max_line_bytes, options)) orelse return null;
    const win_len: usize = @intCast(plan.end_offset - plan.start_offset);
    if (win_len == 0) {
        return .{
            .start_offset = plan.start_offset,
            .end_offset = plan.end_offset,
            .raw_end_offset = plan.raw_end_offset,
            .bytes = &.{},
            .truncated_left = plan.truncated_left,
            .truncated_right = plan.truncated_right,
            .owned = &.{},
        };
    }
    const owned = try allocator.alloc(u8, win_len);
    errdefer allocator.free(owned);
    const got = try source.readAtFull(plan.start_offset, owned);
    if (got != win_len) return error.UnexpectedEof;
    return .{
        .start_offset = plan.start_offset,
        .end_offset = plan.end_offset,
        .raw_end_offset = plan.raw_end_offset,
        .bytes = owned[0..got],
        .truncated_left = plan.truncated_left,
        .truncated_right = plan.truncated_right,
        .owned = owned,
    };
}

// ============================================================================
// Unit Tests
// ============================================================================

const ShortReadSource = struct {
    data: []const u8,
    max_per_call: usize,
    calls: usize = 0,

    fn randomAccess(self: *ShortReadSource, expose_size: bool) RandomAccess {
        return .{
            .ctx = self,
            .read_at = readAtFn,
            .size = if (expose_size) @intCast(self.data.len) else null,
        };
    }

    fn readAtFn(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *ShortReadSource = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        if (offset >= self.data.len or dest.len == 0) return 0;
        const off: usize = @intCast(offset);
        const cap = @max(@as(usize, 1), self.max_per_call);
        const n = @min(@min(dest.len, cap), self.data.len - off);
        @memcpy(dest[0..n], self.data[off .. off + n]);
        return n;
    }
};

test "probe: empty input, out-of-bounds, single line, empty lines, CRLF, and NUL delimiter" {
    const empty: []const u8 = "";
    try std.testing.expect(probeLineSlice(empty, 0, .{}) == null);
    try std.testing.expect(probeLineSlice(empty, 5, .{}) == null);

    const ra_empty = RandomAccess.fromSlice(&empty);
    var scratch: [64]u8 = undefined;
    try std.testing.expect((try probeLineAtBuf(ra_empty, 0, &scratch, .{})) == null);
    try std.testing.expect((try probeLineAt(std.testing.allocator, ra_empty, 0, .{})) == null);

    // Single line without trailing delimiter
    const single: []const u8 = "hello";
    try std.testing.expect(probeLineSlice(single, 5, .{}) == null);
    for (0..single.len) |off| {
        const p = probeLineSlice(single, off, .{}).?;
        try std.testing.expectEqual(@as(u64, 0), p.start_offset);
        try std.testing.expectEqual(@as(u64, 5), p.end_offset);
        try std.testing.expectEqual(@as(u64, 5), p.raw_end_offset);
        try std.testing.expectEqualStrings("hello", p.bytes);
        try std.testing.expect(!p.truncated_left and !p.truncated_right);
    }

    // Empty line "\n"
    const only_nl: []const u8 = "\n";
    {
        const p = probeLineSlice(only_nl, 0, .{}).?;
        try std.testing.expectEqual(@as(u64, 0), p.start_offset);
        try std.testing.expectEqual(@as(u64, 0), p.end_offset);
        try std.testing.expectEqual(@as(u64, 1), p.raw_end_offset);
        try std.testing.expectEqualStrings("", p.bytes);
    }

    // CRLF stripping vs preservation
    const crlf_text: []const u8 = "alpha\r\n\r\nbeta\r\ngamma";
    // Offsets 0..6 ("alpha\r\n")
    for (0..7) |off| {
        const stripped = probeLineSlice(crlf_text, off, .{ .strip_crlf = true }).?;
        try std.testing.expectEqual(@as(u64, 0), stripped.start_offset);
        try std.testing.expectEqual(@as(u64, 5), stripped.end_offset);
        try std.testing.expectEqual(@as(u64, 7), stripped.raw_end_offset);
        try std.testing.expectEqualStrings("alpha", stripped.bytes);

        const raw_cr = probeLineSlice(crlf_text, off, .{ .strip_crlf = false }).?;
        try std.testing.expectEqual(@as(u64, 6), raw_cr.end_offset);
        try std.testing.expectEqualStrings("alpha\r", raw_cr.bytes);
    }
    // Offsets 7..8 ("\r\n" empty CRLF line)
    for (7..9) |off| {
        const p = probeLineSlice(crlf_text, off, .{ .strip_crlf = true }).?;
        try std.testing.expectEqual(@as(u64, 7), p.start_offset);
        try std.testing.expectEqual(@as(u64, 7), p.end_offset);
        try std.testing.expectEqual(@as(u64, 9), p.raw_end_offset);
        try std.testing.expectEqualStrings("", p.bytes);
    }

    // Custom NUL delimiter (\x00)
    const nul_text: []const u8 = "rec0\nstill0\x00rec1\x00";
    {
        const p0 = probeLineSlice(nul_text, 6, .{ .delimiter = 0 }).?;
        try std.testing.expectEqual(@as(u64, 0), p0.start_offset);
        try std.testing.expectEqual(@as(u64, 11), p0.end_offset);
        try std.testing.expectEqual(@as(u64, 12), p0.raw_end_offset);
        try std.testing.expectEqualStrings("rec0\nstill0", p0.bytes);

        const p1 = probeLineSlice(nul_text, 16, .{ .delimiter = 0 }).?;
        try std.testing.expectEqual(@as(u64, 12), p1.start_offset);
        try std.testing.expectEqual(@as(u64, 16), p1.end_offset);
        try std.testing.expectEqual(@as(u64, 17), p1.raw_end_offset);
        try std.testing.expectEqualStrings("rec1", p1.bytes);
    }
}

test "probe: partition invariant and equivalence across slice, probeLineAtBuf, and probeLineAt with tiny chunks" {
    const corpora = [_][]const u8{
        "\n\n\n",
        "\r\n\r\n",
        "a\nb\r\nc\n\nd",
        "0123456789abcdef0123456789ABCDEF\r\nshort\nVERY_LONG_LINE_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789\nend",
    };
    const chunk_sizes = [_]usize{ 1, 3, 7, 16, 64 };
    const line_caps = [_]usize{ 0, 1, 2, 5, 11, 32, 1024 };

    var buf: [2048]u8 = undefined;

    for (corpora) |corpus| {
        for (line_caps) |cap| {
            for (chunk_sizes) |chunk_sz| {
                const opts = ProbeOptions{
                    .max_line_bytes = cap,
                    .window_chunk_bytes = chunk_sz,
                    .strip_crlf = true,
                };
                var short_src = ShortReadSource{ .data = corpus, .max_per_call = chunk_sz };
                const ra = short_src.randomAccess(chunk_sz % 2 == 0);

                for (0..corpus.len) |off| {
                    const s_probe = probeLineSlice(corpus, off, opts).?;
                    // Partition invariant check
                    try std.testing.expect(s_probe.start_offset <= off);
                    try std.testing.expect(off < s_probe.raw_end_offset);
                    try std.testing.expect(s_probe.bytes.len <= cap);

                    const b_probe = (try probeLineAtBuf(ra, off, buf[0..@max(cap, 1)], opts)).?;
                    var a_probe = (try probeLineAt(std.testing.allocator, ra, off, opts)).?;
                    defer a_probe.deinit(std.testing.allocator);

                    try std.testing.expectEqual(s_probe.start_offset, b_probe.start_offset);
                    try std.testing.expectEqual(s_probe.end_offset, b_probe.end_offset);
                    try std.testing.expectEqual(s_probe.raw_end_offset, b_probe.raw_end_offset);
                    try std.testing.expectEqual(s_probe.truncated_left, b_probe.truncated_left);
                    try std.testing.expectEqual(s_probe.truncated_right, b_probe.truncated_right);
                    try std.testing.expectEqualStrings(s_probe.bytes, b_probe.bytes);

                    try std.testing.expectEqual(s_probe.start_offset, a_probe.start_offset);
                    try std.testing.expectEqual(s_probe.end_offset, a_probe.end_offset);
                    try std.testing.expectEqual(s_probe.raw_end_offset, a_probe.raw_end_offset);
                    try std.testing.expectEqual(s_probe.truncated_left, a_probe.truncated_left);
                    try std.testing.expectEqual(s_probe.truncated_right, a_probe.truncated_right);
                    try std.testing.expectEqualStrings(s_probe.bytes, a_probe.bytes);
                }

                // Exact line decomposition check when untruncated
                if (cap >= corpus.len) {
                    var cursor: u64 = 0;
                    while (cursor < corpus.len) {
                        const p = probeLineSlice(corpus, cursor, opts).?;
                        try std.testing.expectEqual(cursor, p.start_offset);
                        try std.testing.expect(p.raw_end_offset > cursor);
                        // Every offset within [start_offset, raw_end_offset) must yield the exact same line
                        var inner = cursor;
                        while (inner < p.raw_end_offset) : (inner += 1) {
                            const pi = probeLineSlice(corpus, inner, opts).?;
                            try std.testing.expectEqual(p.start_offset, pi.start_offset);
                            try std.testing.expectEqual(p.end_offset, pi.end_offset);
                            try std.testing.expectEqual(p.raw_end_offset, pi.raw_end_offset);
                        }
                        cursor = p.raw_end_offset;
                    }
                    try std.testing.expectEqual(@as(u64, corpus.len), cursor);
                }
            }
        }
    }
}

test "probe: truncated long line bounds read I/O around offset" {
    var huge: [65536]u8 = undefined;
    for (&huge, 0..) |*b, i| b.* = @intCast('a' + (i % 26));
    huge[100] = '\n';
    huge[65000] = '\r';
    huge[65001] = '\n';

    var src = ShortReadSource{ .data = &huge, .max_per_call = 512 };
    const ra = src.randomAccess(true);

    // Probe in the middle of a ~64.9 KiB line with max_line_bytes = 64
    const opts = ProbeOptions{ .max_line_bytes = 64, .window_chunk_bytes = 32 };
    var lp = (try probeLineAt(std.testing.allocator, ra, 30000, opts)).?;
    defer lp.deinit(std.testing.allocator);

    try std.testing.expect(lp.truncated_left);
    try std.testing.expect(lp.truncated_right);
    try std.testing.expectEqual(@as(usize, 64), lp.bytes.len);
    try std.testing.expectEqual(@as(u64, 30000 - 32), lp.start_offset);
    try std.testing.expectEqual(@as(u64, 30000 + 32), lp.end_offset);
    try std.testing.expectEqualStrings(huge[30000 - 32 .. 30000 + 32], lp.bytes);
    // Must have done only bounded local chunk reads (< 20 calls), never scanning the 64 KiB buffer!
    try std.testing.expect(src.calls < 20);

    // Probe near the right end of the huge CRLF line (at '\n' index 65001)
    var lp_end = (try probeLineAt(std.testing.allocator, ra, 65001, opts)).?;
    defer lp_end.deinit(std.testing.allocator);
    try std.testing.expect(lp_end.truncated_left);
    try std.testing.expect(!lp_end.truncated_right);
    try std.testing.expectEqual(@as(u64, 65000 - 64), lp_end.start_offset);
    try std.testing.expectEqual(@as(u64, 65000), lp_end.end_offset);
    try std.testing.expectEqual(@as(u64, 65002), lp_end.raw_end_offset);
    try std.testing.expectEqualStrings(huge[65000 - 64 .. 65000], lp_end.bytes);
}
