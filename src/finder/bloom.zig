//! [Module] finder/bloom.zig
//! [Layer] Layer 2 — N-Gram / Trigram Bloom Filter & Zero-False-Negative Matcher Pre-Screener
//! [Role] Indexes byte slices or streaming chunks into a Kirsch-Mitzenmacher N-gram Bloom filter
//!        and pre-screens `RequiredLiteral`, `Finder`, `Multi`, `Regex`, `RegexSet`, or generic
//!        matchers with strictly zero false negatives across sensitive, insensitive, smart, and
//!        Unicode Simple Case Folding modes (including cross-ASCII `k`/`K`, `s`/`ſ`, and `ß`/`ẞ`).
//! [Invariants]
//!   1. Zero false negatives: if `matcher.find(haystack, 0, mode) != null`, then a Bloom filter
//!      built over `haystack` (via `addSlice` or streaming `Writer.addChunk`) ALWAYS returns `true`.
//!   2. Zero filesystem file or directory handle references; zero allocations on `mayContain*` queries.
//! [HotPath] `addSlice` (inline 64-bit SplitMix/Murmur mix + Kirsch-Mitzenmacher double hashing).

const std = @import("std");
const ascii = @import("ascii.zig");
const unicode_fold = @import("unicode_fold.zig");
const matcher = @import("../matcher.zig");
const finder_mod = @import("finder.zig");
const multi_mod = @import("multi.zig");
const regex_vm = @import("../regex/vm.zig");
const regex_set = @import("../regex/set.zig");

pub const Finder = finder_mod.Finder;
pub const Multi = multi_mod.Multi;
pub const Regex = regex_vm.Regex;
pub const RegexSet = regex_set.RegexSet;

pub const max_ngram_len: u8 = 16;
pub const max_num_hashes: u8 = 32;

pub const Error = error{
    OutOfMemory,
    InvalidConfig,
    BufferTooSmall,
    CorruptBloom,
    IncompatibleConfig,
};

/// Configuration for `NgramBloom`.
pub const BloomConfig = struct {
    bit_count: u32 = 16384,
    num_hashes: u8 = 3,
    ngram_len: u8 = 3,
    ascii_lower: bool = true,

    pub fn validate(self: BloomConfig) Error!void {
        if (self.bit_count == 0) return error.InvalidConfig;
        if (self.num_hashes == 0 or self.num_hashes > max_num_hashes) return error.InvalidConfig;
        if (self.ngram_len == 0 or self.ngram_len > max_ngram_len) return error.InvalidConfig;
    }

    pub fn byteLength(self: BloomConfig) usize {
        return (@as(usize, self.bit_count) + 7) / 8;
    }

    pub fn eql(self: BloomConfig, other: BloomConfig) bool {
        return self.bit_count == other.bit_count and
            self.num_hashes == other.num_hashes and
            self.ngram_len == other.ngram_len and
            self.ascii_lower == other.ascii_lower;
    }
};

/// Space-efficient N-gram / Trigram Bloom filter with zero-false-negative matcher pre-screening.
pub const NgramBloom = struct {
    config: BloomConfig,
    bits: []u8,
    allocator: ?std.mem.Allocator = null,
    is_pow2: bool,
    mask: u32,

    /// Allocates and zero-initializes a new `NgramBloom`.
    pub fn init(allocator: std.mem.Allocator, config: BloomConfig) Error!NgramBloom {
        try config.validate();
        const byte_len = config.byteLength();
        const bits = try allocator.alloc(u8, byte_len);
        @memset(bits, 0);
        const pow2 = std.math.isPowerOfTwo(config.bit_count);
        return .{
            .config = config,
            .bits = bits,
            .allocator = allocator,
            .is_pow2 = pow2,
            .mask = if (pow2) config.bit_count - 1 else 0,
        };
    }

    /// Wraps caller-provided `bits` in-place without heap allocation (retaining existing bits in `bits`).
    /// Call `clear()` if `bits` contains uninitialized scratch memory.
    pub fn initBorrowed(bits: []u8, config: BloomConfig) Error!NgramBloom {
        try config.validate();
        const needed = config.byteLength();
        if (bits.len < needed) return error.BufferTooSmall;
        const pow2 = std.math.isPowerOfTwo(config.bit_count);
        return .{
            .config = config,
            .bits = bits[0..needed],
            .allocator = null,
            .is_pow2 = pow2,
            .mask = if (pow2) config.bit_count - 1 else 0,
        };
    }

    pub fn deinit(self: *NgramBloom) void {
        if (self.allocator) |alloc| {
            alloc.free(self.bits);
        }
        self.* = undefined;
    }

    pub fn clear(self: *NgramBloom) void {
        @memset(self.bits, 0);
    }

    /// Streaming chunk writer that carries the trailing `ngram_len - 1` overlap bytes across chunks.
    pub const Writer = struct {
        bloom: *NgramBloom,
        tail: [max_ngram_len - 1]u8 = undefined,
        tail_len: u8 = 0,

        pub fn init(bloom: *NgramBloom) Writer {
            return .{ .bloom = bloom };
        }

        pub fn reset(self: *Writer) void {
            self.tail_len = 0;
        }

        pub fn addChunk(self: *Writer, chunk: []const u8) void {
            if (chunk.len == 0) return;
            const n: usize = self.bloom.config.ngram_len;
            if (n == 1) {
                self.bloom.addSlice(chunk);
                return;
            }

            const overlap_cap: usize = n - 1;
            if (self.tail_len > 0) {
                var bridge: [max_ngram_len * 2]u8 = undefined;
                const t_len: usize = self.tail_len;
                const take_new = @min(chunk.len, overlap_cap);
                @memcpy(bridge[0..t_len], self.tail[0..t_len]);
                @memcpy(bridge[t_len .. t_len + take_new], chunk[0..take_new]);
                const bridge_len = t_len + take_new;
                if (bridge_len >= n) {
                    self.bloom.addSlice(bridge[0..bridge_len]);
                }
                if (chunk.len < overlap_cap) {
                    const keep = @min(bridge_len, overlap_cap);
                    @memcpy(self.tail[0..keep], bridge[bridge_len - keep .. bridge_len]);
                    self.tail_len = @intCast(keep);
                    return;
                }
            } else if (chunk.len < overlap_cap) {
                @memcpy(self.tail[0..chunk.len], chunk);
                self.tail_len = @intCast(chunk.len);
                return;
            }

            if (chunk.len >= n) {
                self.bloom.addSlice(chunk);
            }
            @memcpy(self.tail[0..overlap_cap], chunk[chunk.len - overlap_cap ..]);
            self.tail_len = @intCast(overlap_cap);
        }
    };

    pub fn writer(self: *NgramBloom) Writer {
        return Writer.init(self);
    }

    inline fn hashGram64(gram: []const u8, ascii_lower: bool) u64 {
        var h: u64 = 0x9E3779B97F4A7C15 ^ (@as(u64, gram.len) *% 0xBF58476D1CE4E5B9);
        if (ascii_lower) {
            for (gram) |raw_b| {
                const b: u8 = std.ascii.toLower(raw_b);
                h = (h ^ b) *% 0xBF58476D1CE4E5B9;
                h ^= h >> 27;
            }
        } else {
            for (gram) |b| {
                h = (h ^ b) *% 0xBF58476D1CE4E5B9;
                h ^= h >> 27;
            }
        }
        h = (h ^ (h >> 30)) *% 0xBF58476D1CE4E5B9;
        h = (h ^ (h >> 27)) *% 0x94D049BB133111EB;
        return h ^ (h >> 31);
    }

    inline fn bitIndex(self: *const NgramBloom, h1: u32, h2: u32, k: u8) usize {
        const combined: u32 = h1 +% (@as(u32, k) *% h2);
        return if (self.is_pow2)
            @intCast(combined & self.mask)
        else
            @intCast(combined % self.config.bit_count);
    }

    inline fn insertNgram(self: *NgramBloom, gram: []const u8) void {
        const h = hashGram64(gram, self.config.ascii_lower);
        const h1: u32 = @truncate(h);
        const h2: u32 = @as(u32, @truncate(h >> 32)) | 1;
        var k: u8 = 0;
        while (k < self.config.num_hashes) : (k += 1) {
            const idx = self.bitIndex(h1, h2, k);
            const byte_idx = idx >> 3;
            const shift: u3 = @truncate(idx & 7);
            self.bits[byte_idx] |= @as(u8, 1) << shift;
        }
    }

    inline fn containsExactNgram(self: *const NgramBloom, gram: []const u8) bool {
        const h = hashGram64(gram, self.config.ascii_lower);
        const h1: u32 = @truncate(h);
        const h2: u32 = @as(u32, @truncate(h >> 32)) | 1;
        var k: u8 = 0;
        while (k < self.config.num_hashes) : (k += 1) {
            const idx = self.bitIndex(h1, h2, k);
            const byte_idx = idx >> 3;
            const shift: u3 = @truncate(idx & 7);
            if ((self.bits[byte_idx] & (@as(u8, 1) << shift)) == 0) return false;
        }
        return true;
    }

    /// Indexes all contiguous `ngram_len`-byte windows of `bytes` into the Bloom filter.
    pub fn addSlice(self: *NgramBloom, bytes: []const u8) void {
        const n: usize = self.config.ngram_len;
        if (bytes.len < n) return;

        // Specialized unrolled fast path for default trigram (n == 3)
        if (n == 3) {
            const limit = bytes.len - 2;
            var i: usize = 0;
            while (i < limit) : (i += 1) {
                self.insertNgram(bytes[i..][0..3]);
            }
            return;
        }

        const limit = bytes.len - n + 1;
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            self.insertNgram(bytes[i .. i + n]);
        }
    }

    const wire_magic = "WGBLM\x01\x00\x00";

    /// Serializes `config` + `bits` + trailing CRC32 into a portable owned byte buffer.
    pub fn serializeAlloc(self: *const NgramBloom, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        const header_len: usize = 16;
        const total_len = header_len + self.bits.len + 4;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);

        @memcpy(out[0..8], wire_magic);
        std.mem.writeInt(u32, out[8..12], self.config.bit_count, .little);
        out[12] = self.config.num_hashes;
        out[13] = self.config.ngram_len;
        out[14] = if (self.config.ascii_lower) 1 else 0;
        out[15] = 0;
        @memcpy(out[header_len .. header_len + self.bits.len], self.bits);

        const crc = std.hash.Crc32.hash(out[0 .. header_len + self.bits.len]);
        std.mem.writeInt(u32, out[header_len + self.bits.len ..][0..4], crc, .little);
        return out;
    }

    /// Deserializes a buffer created by `serializeAlloc`, validating config, byte length, and CRC32.
    pub fn deserialize(allocator: std.mem.Allocator, bytes: []const u8) Error!NgramBloom {
        if (bytes.len < 20) return error.CorruptBloom;
        if (!std.mem.eql(u8, bytes[0..8], wire_magic)) return error.CorruptBloom;

        const payload = bytes[0 .. bytes.len - 4];
        const expected_crc = std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little);
        if (std.hash.Crc32.hash(payload) != expected_crc) return error.CorruptBloom;

        if ((payload[14] & 0xFE) != 0 or payload[15] != 0) return error.CorruptBloom;
        const cfg = BloomConfig{
            .bit_count = std.mem.readInt(u32, payload[8..12], .little),
            .num_hashes = payload[12],
            .ngram_len = payload[13],
            .ascii_lower = (payload[14] & 1) != 0,
        };
        cfg.validate() catch return error.CorruptBloom;

        const expected_bits_len = cfg.byteLength();
        if (payload.len != 16 + expected_bits_len) return error.CorruptBloom;

        const bloom = try NgramBloom.init(allocator, cfg);
        @memcpy(bloom.bits, payload[16..]);
        return bloom;
    }

    /// Unions `other` into `self` in-place via bitwise OR (`self.config` must equal `other.config`).
    pub fn merge(self: *NgramBloom, other: *const NgramBloom) Error!void {
        if (!self.config.eql(other.config)) return error.IncompatibleConfig;
        for (self.bits, other.bits) |*dst, src| {
            dst.* |= src;
        }
    }

    /// Returns the fraction of set bits in `[0.0, 1.0]`.
    pub fn estimatedFillRatio(self: *const NgramBloom) f64 {
        var set_bits: u64 = 0;
        for (self.bits) |b| {
            set_bits += @popCount(b);
        }
        return @as(f64, @floatFromInt(set_bits)) / @as(f64, @floatFromInt(self.config.bit_count));
    }

    fn mayContainAsciiInsensitiveNgram(self: *const NgramBloom, gram: []const u8) bool {
        if (self.config.ascii_lower) {
            return self.containsExactNgram(gram);
        }

        // When !config.ascii_lower, enumerate ASCII case combinations up to 2^4 = 16;
        // if > 4 ASCII letters appear in an n-gram, conservatively return true.
        var alpha_pos: [max_ngram_len]u8 = undefined;
        var alpha_count: usize = 0;
        for (gram, 0..) |b, idx| {
            if (std.ascii.isAlphabetic(b)) {
                alpha_pos[alpha_count] = @intCast(idx);
                alpha_count += 1;
                if (alpha_count > 4) return true;
            }
        }
        if (alpha_count == 0) {
            return self.containsExactNgram(gram);
        }

        var cand: [max_ngram_len]u8 = undefined;
        @memcpy(cand[0..gram.len], gram);
        const combos: u8 = @as(u8, 1) << @as(u3, @intCast(alpha_count));
        var mask_bits: u8 = 0;
        while (mask_bits < combos) : (mask_bits += 1) {
            for (0..alpha_count) |j| {
                const pos = alpha_pos[j];
                const b = gram[pos];
                const bit = (mask_bits >> @as(u3, @intCast(j))) & 1;
                cand[pos] = if (bit != 0) std.ascii.toUpper(b) else std.ascii.toLower(b);
            }
            if (self.containsExactNgram(cand[0..gram.len])) return true;
        }
        return false;
    }

    fn mayContainAsciiInsensitiveSlice(self: *const NgramBloom, s: []const u8) bool {
        const n: usize = self.config.ngram_len;
        if (s.len < n) return true;
        const limit = s.len - n + 1;
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            if (!self.mayContainAsciiInsensitiveNgram(s[i .. i + n])) return false;
        }
        return true;
    }

    fn codepointFoldBranches(cp: u21, out: *[4]u21) struct { count: usize, min_utf8_len: usize } {
        if (cp < 0x80) {
            if (cp == 'k' or cp == 'K') {
                out[0] = 'k';
                out[1] = 0x212A; // Kelvin sign U+212A (3 UTF-8 bytes)
                return .{ .count = 2, .min_utf8_len = 1 };
            }
            if (cp == 's' or cp == 'S') {
                out[0] = 's';
                out[1] = 0x017F; // Latin small letter long s U+017F (2 UTF-8 bytes)
                return .{ .count = 2, .min_utf8_len = 1 };
            }
            // All other ASCII codepoints only fold within ASCII (1 byte), handled by ASCII insensitivity
            out[0] = cp;
            return .{ .count = 1, .min_utf8_len = 1 };
        }

        const n_eq = unicode_fold.foldEquivalents(cp, out);
        var min_len: usize = 4;
        for (out[0..n_eq]) |alt| {
            const l: usize = std.unicode.utf8CodepointSequenceLength(alt) catch 1;
            if (l < min_len) min_len = l;
        }
        return .{ .count = n_eq, .min_utf8_len = min_len };
    }

    fn anyUnicodeWindowVariantMatches(
        self: *const NgramBloom,
        sub: []const u8,
        pos: usize,
        buf: *[64]u8,
        buf_len: usize,
    ) bool {
        if (pos >= sub.len) {
            return self.mayContainAsciiInsensitiveSlice(buf[0..buf_len]);
        }
        const seq_len = std.unicode.utf8ByteSequenceLength(sub[pos]) catch return true;
        if (pos + seq_len > sub.len) return true;
        const cp: u21 = switch (seq_len) {
            1 => sub[pos],
            2 => std.unicode.utf8Decode2(sub[pos..][0..2].*) catch return true,
            3 => std.unicode.utf8Decode3(sub[pos..][0..3].*) catch return true,
            4 => std.unicode.utf8Decode4(sub[pos..][0..4].*) catch return true,
            else => unreachable,
        };

        var alts: [4]u21 = undefined;
        const info = codepointFoldBranches(cp, &alts);
        for (alts[0..info.count]) |alt_cp| {
            var enc: [4]u8 = undefined;
            const enc_len = std.unicode.utf8Encode(alt_cp, &enc) catch return true;
            if (buf_len + enc_len > buf.len) return true;
            @memcpy(buf[buf_len .. buf_len + enc_len], enc[0..enc_len]);
            if (self.anyUnicodeWindowVariantMatches(sub, pos + seq_len, buf, buf_len + enc_len)) {
                return true;
            }
        }
        return false;
    }

    fn mayContainUnicodeFolded(self: *const NgramBloom, lit: []const u8) bool {
        const n: usize = self.config.ngram_len;
        if (lit.len < n) return true;
        if (!std.unicode.utf8ValidateSlice(lit)) return true;

        // Fast check if no cross-ASCII ('k'/'s') or non-ASCII codepoint needs Unicode expansion
        if (!unicode_fold.needsUnicodeExpansion(lit)) {
            return self.mayContainAsciiInsensitiveSlice(lit);
        }

        // Slide a minimal codepoint window whose shortest Unicode-folded UTF-8 encoding is >= n bytes.
        var cp_start: usize = 0;
        while (cp_start < lit.len) {
            const first_step = std.unicode.utf8ByteSequenceLength(lit[cp_start]) catch return true;
            var cp_end: usize = cp_start;
            var min_bytes: usize = 0;
            var branches: usize = 1;
            var overflow = false;

            while (cp_end < lit.len and min_bytes < n) {
                const seq_len = std.unicode.utf8ByteSequenceLength(lit[cp_end]) catch return true;
                const cp: u21 = switch (seq_len) {
                    1 => lit[cp_end],
                    2 => std.unicode.utf8Decode2(lit[cp_end..][0..2].*) catch return true,
                    3 => std.unicode.utf8Decode3(lit[cp_end..][0..3].*) catch return true,
                    4 => std.unicode.utf8Decode4(lit[cp_end..][0..4].*) catch return true,
                    else => unreachable,
                };
                var dummy: [4]u21 = undefined;
                const info = codepointFoldBranches(cp, &dummy);
                min_bytes += info.min_utf8_len;
                branches = std.math.mul(usize, branches, info.count) catch {
                    overflow = true;
                    break;
                };
                if (branches > 16) {
                    overflow = true;
                    break;
                }
                cp_end += seq_len;
            }

            if (min_bytes < n) {
                // Remaining suffix can fold to < n UTF-8 bytes (e.g. "Ka" -> "ka" or "ẞ" -> "ß"); stop safely.
                break;
            }

            if (!overflow and (cp_end - cp_start) <= 48) {
                var stack_buf: [64]u8 = undefined;
                if (!self.anyUnicodeWindowVariantMatches(lit[cp_start..cp_end], 0, &stack_buf, 0)) {
                    return false;
                }
            }

            cp_start += first_step;
        }

        return true;
    }

    /// Zero-false-negative pre-screen for a literal pattern under `case_mode` and `unicode_case`.
    pub fn mayContainLiteral(
        self: *const NgramBloom,
        lit: []const u8,
        case_mode: matcher.CaseMode,
        unicode_case: bool,
    ) bool {
        const n: usize = self.config.ngram_len;
        if (lit.len < n) return true;

        const ignores_case: bool = switch (case_mode) {
            .sensitive => false,
            .insensitive => true,
            .smart => if (unicode_case) !unicode_fold.patternHasUnicodeUpper(lit) else !ascii.patternHasUpper(lit),
        };

        if (!ignores_case) {
            const limit = lit.len - n + 1;
            var i: usize = 0;
            while (i < limit) : (i += 1) {
                if (!self.containsExactNgram(lit[i .. i + n])) return false;
            }
            return true;
        }

        if (unicode_case) {
            return self.mayContainUnicodeFolded(lit);
        }

        return self.mayContainAsciiInsensitiveSlice(lit);
    }

    /// Zero-false-negative pre-screen for a `matcher.RequiredLiteral`.
    pub fn mayContainRequired(
        self: *const NgramBloom,
        req: matcher.RequiredLiteral,
        case_mode: matcher.CaseMode,
        unicode_case: bool,
    ) bool {
        return self.mayContainLiteral(req.bytes, case_mode, unicode_case);
    }

    /// Zero-false-negative pre-screen for a single-literal `Finder`.
    pub fn mayContainFinder(self: *const NgramBloom, f: *const Finder) bool {
        const cm: matcher.CaseMode = if (f.ignore_case) .insensitive else .sensitive;
        return self.mayContainLiteral(f.pattern, cm, f.unicode_folded);
    }

    /// Zero-false-negative pre-screen for a multi-literal `Multi` engine (returns `true` if ANY pattern may match).
    pub fn mayContainMulti(self: *const NgramBloom, m: *const Multi) bool {
        if (m.patterns.len == 0) return false;
        const already_expanded_unicode = (m.owned_variant_bytes != null and m.unicode_case);

        for (m.patterns, 0..) |pat, idx| {
            const fold_i: bool = switch (m.kind) {
                .mixed => |*mx| mx.ignore[idx],
                else => m.ignore_case,
            };
            const cm: matcher.CaseMode = if (fold_i) .insensitive else .sensitive;
            const uc: bool = fold_i and m.unicode_case and !already_expanded_unicode;
            if (self.mayContainLiteral(pat, cm, uc)) return true;
        }
        return false;
    }

    /// Zero-false-negative pre-screen for a compiled `Regex` using `req_literal_bytes`,
    /// `tail_literal_bytes`, and `alt_literal_slices` / `alt_prefilter`.
    pub fn mayContainRegex(self: *const NgramBloom, re: *const Regex) bool {
        const cm: matcher.CaseMode = if (re.ignore_case) .insensitive else .sensitive;
        const uc: bool = re.ignore_case and re.unicode_case;

        if (re.req_literal_bytes.len > 0) {
            if (!self.mayContainLiteral(re.req_literal_bytes, cm, uc)) return false;
            if (re.tail_literal_bytes.len > 0) {
                if (!self.mayContainLiteral(re.tail_literal_bytes, cm, uc)) return false;
            }
            return true;
        }

        if (re.alt_prefilter) |*ap| {
            return self.mayContainMulti(ap);
        }

        if (re.alt_literal_slices.len > 0) {
            for (re.alt_literal_slices) |branch_lit| {
                if (self.mayContainLiteral(branch_lit, cm, uc)) return true;
            }
            return false;
        }

        return true;
    }

    /// Zero-false-negative pre-screen for a compiled `RegexSet`.
    pub fn mayContainRegexSet(self: *const NgramBloom, rs: *const RegexSet) bool {
        if (rs.pattern_count == 0) return false;
        if (rs.prefilter) |*pf| {
            return self.mayContainMulti(pf);
        }
        return true;
    }

    /// Generic zero-false-negative pre-screen dispatching across `Finder`, `Multi`, `Regex`,
    /// `RegexSet`, or any custom matcher type `M` (passed by value or pointer).
    pub fn mayContainMatcher(self: *const NgramBloom, m: anytype) bool {
        const ArgType = @TypeOf(m);
        const Base = matcher.BaseMatcherType(ArgType);
        matcher.validateMatcher(Base);
        const ptr: *const Base = if (@typeInfo(ArgType) == .pointer) m else &m;

        if (Base == Finder) return self.mayContainFinder(ptr);
        if (Base == Multi) return self.mayContainMulti(ptr);
        if (Base == Regex) return self.mayContainRegex(ptr);
        if (Base == RegexSet) return self.mayContainRegexSet(ptr);

        if (@hasDecl(Base, "requiredLiteral")) {
            if (ptr.requiredLiteral()) |req| {
                const cm: matcher.CaseMode = if (@hasField(Base, "case_mode"))
                    ptr.case_mode
                else if (@hasField(Base, "ignore_case"))
                    (if (ptr.ignore_case) .insensitive else .sensitive)
                else
                    .insensitive;
                const uc: bool = if (@hasField(Base, "unicode_case")) ptr.unicode_case else true;
                return self.mayContainRequired(req, cm, uc);
            }
        }
        return true;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "NgramBloom: config validation, borrowed init, streaming chunks, merge, and serialization" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(error.InvalidConfig, NgramBloom.init(alloc, .{ .bit_count = 0 }));
    try std.testing.expectError(error.InvalidConfig, NgramBloom.init(alloc, .{ .num_hashes = 0 }));
    try std.testing.expectError(error.InvalidConfig, NgramBloom.init(alloc, .{ .ngram_len = 0 }));
    try std.testing.expectError(error.InvalidConfig, NgramBloom.init(alloc, .{ .ngram_len = 17 }));

    var tiny_buf: [4]u8 = @splat(0);
    try std.testing.expectError(error.BufferTooSmall, NgramBloom.initBorrowed(&tiny_buf, .{ .bit_count = 64 }));

    // Compare single-shot addSlice vs 1-byte and 2-byte streaming Writer chunks (non-power-of-two bit_count too!)
    const cfg = BloomConfig{ .bit_count = 1000, .num_hashes = 4, .ngram_len = 3, .ascii_lower = true };
    const text = "Streaming chunk boundary test: ERROR_404_TIMEOUT & Kelvin \u{212A}elvin!";

    var b_full = try NgramBloom.init(alloc, cfg);
    defer b_full.deinit();
    b_full.addSlice(text);

    var b_stream1 = try NgramBloom.init(alloc, cfg);
    defer b_stream1.deinit();
    var w1 = b_stream1.writer();
    for (text) |byte| {
        w1.addChunk(&.{byte});
    }
    try std.testing.expectEqualSlices(u8, b_full.bits, b_stream1.bits);

    var b_stream2 = try NgramBloom.init(alloc, cfg);
    defer b_stream2.deinit();
    var w2 = b_stream2.writer();
    var pos: usize = 0;
    while (pos < text.len) {
        const end = @min(pos + 2, text.len);
        w2.addChunk(text[pos..end]);
        pos = end;
    }
    try std.testing.expectEqualSlices(u8, b_full.bits, b_stream2.bits);

    // Fill ratio, serializeAlloc / deserialize, and merge
    const ratio = b_full.estimatedFillRatio();
    try std.testing.expect(ratio > 0.0 and ratio < 1.0);

    const encoded = try b_full.serializeAlloc(alloc);
    defer alloc.free(encoded);
    var decoded = try NgramBloom.deserialize(alloc, encoded);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, b_full.bits, decoded.bits);

    var corrupted = try alloc.dupe(u8, encoded);
    defer alloc.free(corrupted);
    corrupted[18] ^= 0x01;
    try std.testing.expectError(error.CorruptBloom, NgramBloom.deserialize(alloc, corrupted));

    var b_other = try NgramBloom.init(alloc, cfg);
    defer b_other.deinit();
    b_other.addSlice("DIFFERENT_PAYLOAD_XYZ");
    try decoded.merge(&b_other);
    try std.testing.expect(decoded.mayContainLiteral("DIFFERENT_PAYLOAD_XYZ", .sensitive, false));
    try std.testing.expect(decoded.mayContainLiteral("ERROR_404_TIMEOUT", .sensitive, false));
}

test "NgramBloom: zero false negatives across sensitive, insensitive, smart, Unicode folding, Multi, Regex, and RegexSet" {
    const alloc = std.testing.allocator;

    const corpus = "2026-11-18 WARN \u{212A}elvin_sensor \u{017F}ocket STRA\u{1E9E}E \u{03A3}IGMA \u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} [id=987] auth_failed_timeout\n";

    // Test both ascii_lower = true and ascii_lower = false!
    for ([_]bool{ true, false }) |ascii_lower| {
        var bloom = try NgramBloom.init(alloc, .{
            .bit_count = 16384,
            .num_hashes = 3,
            .ngram_len = 3,
            .ascii_lower = ascii_lower,
        });
        defer bloom.deinit();
        bloom.addSlice(corpus);

        // 1. Short patterns (< ngram_len) must ALWAYS return true
        try std.testing.expect(bloom.mayContainLiteral("", .sensitive, false));
        try std.testing.expect(bloom.mayContainLiteral("q", .sensitive, false));
        try std.testing.expect(bloom.mayContainLiteral("qz", .sensitive, false));
        try std.testing.expect(bloom.mayContainLiteral("\u{1E9E}", .insensitive, true)); // 3B -> folds to 2B "ß"!
        try std.testing.expect(bloom.mayContainLiteral("\u{212A}z", .insensitive, true)); // 4B -> folds to 2B "kz"!

        // 2. Cross-ASCII & cross-byte-length Unicode folding partners: ZERO false negatives!
        const f_kelvin = try Finder.init("kelvin_sensor", .{ .case = .insensitive, .unicode_case = true });
        try std.testing.expect(f_kelvin.find(corpus, 0, .earliest) != null);
        try std.testing.expect(bloom.mayContainFinder(&f_kelvin));
        try std.testing.expect(bloom.mayContainMatcher(&f_kelvin));

        const f_socket = try Finder.init("socket", .{ .case = .smart, .unicode_case = true });
        try std.testing.expect(f_socket.find(corpus, 0, .earliest) != null);
        try std.testing.expect(bloom.mayContainFinder(&f_socket));

        const f_strasse = try Finder.init("straße", .{ .case = .insensitive, .unicode_case = true });
        try std.testing.expect(f_strasse.find(corpus, 0, .earliest) != null);
        try std.testing.expect(bloom.mayContainFinder(&f_strasse));

        const f_sigma = try Finder.init("ςigma", .{ .case = .smart, .unicode_case = true });
        try std.testing.expect(f_sigma.find(corpus, 0, .earliest) != null);
        try std.testing.expect(bloom.mayContainFinder(&f_sigma));

        const f_cyr = try Finder.init("привет", .{ .case = .insensitive, .unicode_case = true });
        try std.testing.expect(f_cyr.find(corpus, 0, .earliest) != null);
        try std.testing.expect(bloom.mayContainFinder(&f_cyr));

        // 3. Definite negatives must be cleanly rejected!
        const f_absent = try Finder.init("panicked_database", .{ .case = .insensitive, .unicode_case = true });
        try std.testing.expect(f_absent.find(corpus, 0, .earliest) == null);
        try std.testing.expect(!bloom.mayContainFinder(&f_absent));
        try std.testing.expect(!bloom.mayContainLiteral("Ωmega_absent", .insensitive, true));

        if (!ascii_lower) {
            // Case-sensitive rejection when ascii_lower is false: corpus has "WARN", not "warn"!
            try std.testing.expect(bloom.mayContainLiteral("WARN", .sensitive, false));
            try std.testing.expect(!bloom.mayContainLiteral("warn", .sensitive, false));
            try std.testing.expect(bloom.mayContainLiteral("warn", .smart, false));
            try std.testing.expect(!bloom.mayContainLiteral("Warn", .smart, false));
        }

        // 4. Multi engine (present vs absent)
        var m_hit = try Multi.init(alloc, &.{ "absent_one", "straße" }, .{ .case = .insensitive, .unicode_case = true });
        defer m_hit.deinit();
        try std.testing.expect(m_hit.find(corpus, 0, .earliest) != null);
        try std.testing.expect(bloom.mayContainMulti(&m_hit));

        var m_miss = try Multi.init(alloc, &.{ "absent_one", "absent_two", "missing_three" }, .{ .case = .insensitive, .unicode_case = true });
        defer m_miss.deinit();
        try std.testing.expect(m_miss.find(corpus, 0, .earliest) == null);
        try std.testing.expect(!bloom.mayContainMulti(&m_miss));

        // Multi.initFromText with >64 Unicode branches (initUnicodeFallback: owned_patterns != null, owned_variant_bytes == null)
        var bloom_delta = try NgramBloom.init(alloc, .{ .ascii_lower = ascii_lower });
        defer bloom_delta.deinit();
        const delta_hay = "xx\u{03B4}\u{03B4}\u{03B4}\u{03B4}\u{03B4}\u{03B4}\u{03B4}yy";
        bloom_delta.addSlice(delta_hay);
        var m_fallback = try Multi.initFromText(alloc, "\u{0394}\u{0394}\u{0394}\u{0394}\u{0394}\u{0394}\u{0394}\n", .{
            .case = .insensitive,
            .unicode_case = true,
        });
        defer m_fallback.deinit();
        try std.testing.expect(m_fallback.owned_patterns != null);
        try std.testing.expect(m_fallback.owned_variant_bytes == null);
        try std.testing.expect(m_fallback.find(delta_hay, 0, .earliest) != null);
        try std.testing.expect(bloom_delta.mayContainMulti(&m_fallback));

        // 5. Regex (prefix + tail literal, interior literal, alternation, and pure class fallback)
        var re_hit = try Regex.init(alloc, "WARN.*timeout", .{});
        defer re_hit.deinit();
        try std.testing.expect(re_hit.isMatch(corpus));
        try std.testing.expect(bloom.mayContainRegex(&re_hit));
        try std.testing.expect(bloom.mayContainMatcher(&re_hit));

        // Prefix "WARN" is present, but tail literal "fatal_crash" is absent -> rejected via tail_literal_bytes!
        var re_tail_miss = try Regex.init(alloc, "WARN.*fatal_crash", .{});
        defer re_tail_miss.deinit();
        try std.testing.expect(!re_tail_miss.isMatch(corpus));
        try std.testing.expect(!bloom.mayContainRegex(&re_tail_miss));

        var re_alt_miss = try Regex.init(alloc, "(?:kerberos_err_[0-9]+|ldap_failure_[0-9]+|tls_alert_[0-9]+)", .{});
        defer re_alt_miss.deinit();
        try std.testing.expect(!re_alt_miss.isMatch(corpus));
        try std.testing.expect(!bloom.mayContainRegex(&re_alt_miss));

        // Leading non-optional alternation extracts {kerberos_err_, ldap_failure_, tls_alert_}, all absent -> true negative.
        var re_alt_leading_miss = try Regex.init(alloc, "(?:kerberos_err|ldap_failure|tls_alert)_[0-9]+", .{});
        defer re_alt_leading_miss.deinit();
        try std.testing.expect(!re_alt_leading_miss.isMatch(corpus));
        try std.testing.expect(!bloom.mayContainRegex(&re_alt_leading_miss));

        // Optional leading alternation cannot require any branch -> falls back conservatively to true.
        var re_alt_fallback = try Regex.init(alloc, "(?:kerberos_err|ldap_failure|tls_alert)?_[0-9]+", .{});
        defer re_alt_fallback.deinit();
        try std.testing.expect(bloom.mayContainRegex(&re_alt_fallback));

        var re_class = try Regex.init(alloc, "\\[id=[0-9]+\\]", .{});
        defer re_class.deinit();
        try std.testing.expect(re_class.isMatch(corpus));
        try std.testing.expect(bloom.mayContainRegex(&re_class));

        // 6. RegexSet
        var rs_miss = try RegexSet.init(alloc, &.{ "kerberos_[0-9]+", "postgres_deadlock.*" }, .{});
        defer rs_miss.deinit();
        try std.testing.expect(!rs_miss.isMatch(corpus));
        try std.testing.expect(!bloom.mayContainRegexSet(&rs_miss));
        try std.testing.expect(!bloom.mayContainMatcher(&rs_miss));

        var rs_hit = try RegexSet.init(alloc, &.{ "kerberos_[0-9]+", "auth_failed_[a-z]+" }, .{});
        defer rs_hit.deinit();
        try std.testing.expect(rs_hit.isMatch(corpus));
        try std.testing.expect(bloom.mayContainRegexSet(&rs_hit));
    }
}
