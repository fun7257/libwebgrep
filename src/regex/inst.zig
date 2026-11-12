//! [Module] regex/inst.zig
//! [Layer] Layer 2 — Regex Bytecode Instructions, Diagnostics & Assertion Helpers
//! [Role] Defines NFA bytecode instructions (`Inst`), 256-bit byte classes (`ByteSet`),
//!        Unicode codepoint range classes (`UnicodeRangeList`), compile diagnostics (`CompileDiagnostic`, `DiagnosticCode`),
//!        zero-width assertions (`AssertKind`), submatch `Captures`, and UTF-8 boundary helpers.
//! [Invariants]
//!   1. `ByteSet` is a 256-bit inline bitmap (`[4]u64`) with O(1) membership lookup (`contains`).
//!   2. `unicode_class` decodes a single valid UTF-8 scalar value and binary-searches sorted `CodepointRange` tables.
//!   3. Zero-width assertions (`checkAssert`) inspect surrounding bytes without consuming input.
//! [HotPath] `ByteSet.contains`, `inRanges`, and `checkAssert`.

const std = @import("std");
const matcher = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const unicode_fold = @import("../finder/unicode_fold.zig");
const prop_table = @import("../tables/unicode_prop_table.zig");

pub const Match = matcher.Match;
pub const MatchMode = matcher.MatchMode;
pub const CaseMode = matcher.CaseMode;
pub const RequiredLiteral = matcher.RequiredLiteral;
pub const CodepointRange = prop_table.CodepointRange;
pub const inRanges = prop_table.inRanges;

pub const UnicodeRangeList = struct {
    ranges: []const CodepointRange,
    owned: bool = false,
};

/// Submatch capture spans for a regex match. `groups[0]` corresponds to `$1`, up to `groups[8]` for `$9`.
pub const Captures = struct {
    match: Match,
    groups: [9]?Match = @splat(null),

    pub fn fullMatch(self: Captures) Match {
        return self.match;
    }

    pub fn group(self: Captures, index: usize) ?Match {
        if (index == 0) return self.match;
        if (index > 9) return null;
        return self.groups[index - 1];
    }

    pub fn span(self: Captures, index: usize) ?Match {
        return self.group(index);
    }

    pub fn slice(self: Captures, haystack: []const u8, index: usize) ?[]const u8 {
        const g = self.group(index) orelse return null;
        return haystack[g.start..g.end];
    }
};

/// Default compiled NFA instruction limit.
pub const default_max_inst: usize = 8192;
/// Default bounded repeat count `{m,n}` per quantifier.
pub const default_max_repeat: usize = 1000;
/// Default group nesting recursion depth.
pub const default_max_recursion_depth: usize = 64;
/// Default bounded multiline match window (64 KiB).
pub const default_multiline_window: usize = 64 * 1024;

/// Server hard cap on compiled NFA instruction count (compatibility alias for default_max_inst).
pub const max_inst_hard_cap: usize = default_max_inst;
/// Server hard cap on bounded repeat count `{m,n}` per quantifier (compatibility alias for default_max_repeat).
pub const max_repeat_hard_cap: usize = default_max_repeat;
/// Server hard cap on group nesting recursion depth (compatibility alias for default_max_recursion_depth).
pub const max_recursion_depth: usize = default_max_recursion_depth;
/// Server hard cap on bounded multiline match window (8 MiB) (compatibility alias).
pub const max_multiline_window_hard_cap: usize = 8 * 1024 * 1024;

pub const Error = error{
    RegexSyntax,
    RegexTooLarge,
    PatternHasNewline,
    PatternCountExceeded,
    PatternBytesExceeded,
    InvalidMultilineWindow,
    OutOfMemory,
};

pub const DiagnosticCode = enum {
    none,
    empty_pattern,
    unclosed_group,
    unmatched_close_paren,
    unclosed_char_class,
    invalid_char_range,
    dangling_quantifier,
    invalid_repeat_bounds,
    unclosed_repeat_braces,
    invalid_escape,
    unknown_unicode_property,
    unclosed_unicode_property,
    invalid_inline_flags,
    trailing_backslash,
    invalid_utf8,
    recursion_depth_exceeded,
    instruction_limit_exceeded,
    multiline_window_exceeded,
    pattern_has_newline,
    pattern_limit_exceeded,
    pattern_count_exceeded,
    pattern_bytes_exceeded,
};

pub const CompileDiagnostic = struct {
    err: ?Error = null,
    code: DiagnosticCode = .none,
    offset: usize = 0,
    byte_offset: usize = 0,
    line: usize = 1,
    column: usize = 1,
    message: []const u8 = "",
    pattern_index: ?usize = null,
};

pub fn populateDiagnostic(
    diag: ?*CompileDiagnostic,
    pattern: []const u8,
    err: Error,
    code: DiagnosticCode,
    pos: usize,
    message: []const u8,
    pattern_index: ?usize,
) void {
    const d = diag orelse return;
    const clamped = @min(pos, pattern.len);
    var line: usize = 1;
    var col: usize = 1;
    for (pattern[0..clamped]) |b| {
        if (b == '\n') {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    d.* = .{
        .err = err,
        .code = code,
        .offset = clamped,
        .byte_offset = clamped,
        .line = line,
        .column = col,
        .message = message,
        .pattern_index = pattern_index,
    };
}

/// Returns the byte offset of the first invalid UTF-8 byte sequence in `slice`, or `null` if valid UTF-8.
pub fn findInvalidUtf8Offset(slice: []const u8) ?usize {
    var i: usize = 0;
    while (i < slice.len) {
        const b = slice[i];
        if (b < 0x80) {
            i += 1;
            continue;
        }
        const seq_len = std.unicode.utf8ByteSequenceLength(b) catch return i;
        if (i + seq_len > slice.len) return i;
        _ = std.unicode.utf8Decode(slice[i .. i + seq_len]) catch return i;
        i += seq_len;
    }
    return null;
}

pub const RegexOptions = struct {
    case: CaseMode = .sensitive,
    /// Enable Unicode simple case folding for multi-byte UTF-8 codepoints when case-insensitive or smart-case is active.
    unicode_case: bool = true,
    /// Allow matches to span multiple lines (including `\n`), with `^` and `$` matching line boundaries.
    multiline: bool = false,
    /// Allow `.` to match `\n` (requires `multiline = true` to cross lines).
    dot_all: bool = false,
    /// Maximum compiled instruction count. Null uses default_max_inst (8192).
    max_inst: ?usize = null,
    /// Alias for `max_inst`.
    max_insts: ?usize = null,
    /// Maximum repeat quantifier count. Defaults to default_max_repeat (1000).
    max_repeat: usize = default_max_repeat,
    /// Maximum group nesting recursion depth. Defaults to default_max_recursion_depth (64).
    max_recursion_depth: usize = default_max_recursion_depth,
    /// Maximum pattern count (for RegexSet). Null uses matcher default.
    max_pattern_count: ?usize = null,
    /// Maximum pattern bytes (for RegexSet / prefilters). Null uses matcher default.
    max_pattern_bytes: ?usize = null,
    /// Maximum Unicode variants per pattern expanded during case-insensitive folding. Defaults to 64.
    max_unicode_variants: usize = 64,
    /// Maximum compiled instruction count for AOT DFA construction. Defaults to 256.
    aot_dfa_max_insts: usize = 256,
    /// Maximum byte span window for multiline matching.
    max_multiline_window: usize = default_multiline_window,
    /// Maximum lazy DFA states cached during search.
    max_dfa_states: u16 = 256,

    pub inline fn effectiveMaxInst(self: RegexOptions) ?usize {
        return self.max_inst orelse self.max_insts;
    }
};

pub const ByteSet = struct {
    bits: [4]u64 = .{ 0, 0, 0, 0 },

    pub fn set(self: *ByteSet, b: u8) void {
        self.bits[b >> 6] |= (@as(u64, 1) << @as(u6, @intCast(b & 63)));
    }

    pub fn setWithCase(self: *ByteSet, b: u8, ignore_case: bool) void {
        self.set(b);
        if (ignore_case) {
            if (b >= 'A' and b <= 'Z') self.set(b + 32);
            if (b >= 'a' and b <= 'z') self.set(b - 32);
        }
    }

    pub fn setRange(self: *ByteSet, lo: u8, hi: u8, ignore_case: bool) void {
        if (lo > hi) return;
        var c: u16 = lo;
        while (c <= hi) : (c += 1) {
            self.setWithCase(@intCast(c), ignore_case);
        }
    }

    pub fn invert(self: *ByteSet) void {
        for (&self.bits) |*w| w.* = ~w.*;
    }

    pub fn clear(self: *ByteSet, b: u8) void {
        self.bits[b >> 6] &= ~(@as(u64, 1) << @as(u6, @intCast(b & 63)));
    }

    pub inline fn contains(self: *const ByteSet, b: u8) bool {
        return (self.bits[b >> 6] & (@as(u64, 1) << @as(u6, @intCast(b & 63)))) != 0;
    }
};

pub const Inst = union(enum) {
    /// Match a single byte (ignoring ASCII case when `ignore_case` is true).
    byte: struct { b: u8, ignore_case: bool, out: u32 },
    /// Match any UTF-8 codepoint or single byte (excluding `\n` when `allow_nl` is false).
    any: struct { allow_nl: bool, out: u32, cont1: u32 = 0, cont2: u32 = 0, cont3: u32 = 0 },
    /// Match a UTF-8 continuation byte (`0x80..0xBF`).
    any_cont: struct { out: u32 },
    /// Match a 256-bit byte class (with optional multi-byte UTF-8 continuation states for negated classes).
    class: struct { set: ByteSet, out: u32, utf8_negated: bool = false, cont1: u32 = 0, cont2: u32 = 0, cont3: u32 = 0 },
    /// Match a Unicode codepoint class (`\p{...}`, `\P{...}`, or bracket class containing Unicode properties/ranges).
    /// Consumes a 1..4 byte valid UTF-8 codepoint by routing multi-byte sequences through `cont1`..`cont3` to `out`.
    unicode_class: struct {
        range_idx: u32,
        negated: bool = false,
        ascii_set: ByteSet = .{},
        has_ascii_set: bool = false,
        ignore_case: bool = false,
        allow_nl: bool = false,
        out: u32,
        cont1: u32 = 0,
        cont2: u32 = 0,
        cont3: u32 = 0,
    },
    /// Zero-width branch: prefers `out1`, then `out2`.
    split: struct { out1: u32, out2: u32 },
    /// Unconditional jump.
    jmp: u32,
    /// Zero-width assertion anchor.
    assert: struct { kind: AssertKind, out: u32 },
    /// Zero-width submatch boundary slot (`0..17` for groups `1..9`).
    save: struct { slot: u8, out: u32 },
    /// Accepting match state for single `Regex`.
    match,
    /// Accepting match state for `RegexSet` carrying the matched pattern index (`0..N-1`).
    match_id: u32,
};

pub const AssertKind = enum {
    start_line,
    end_line,
    start_input,
    end_input,
    word_boundary,
    not_word_boundary,
};

pub const Thread = struct {
    pc: u32,
    start: usize,
};

pub fn popLastUtf8Codepoint(list: *std.ArrayList(u8)) void {
    if (list.items.len == 0) return;
    var count: usize = 0;
    while (list.items.len > 0 and count < 4) {
        const b = list.pop().?;
        count += 1;
        if ((b & 0xC0) != 0x80) break;
    }
}

pub fn utf8SeqLenAt(haystack: []const u8, pos: usize, limit: usize) usize {
    if (pos >= limit) return 0;
    const b0 = haystack[pos];
    if (b0 < 0x80) return 1;
    const seq_len = std.unicode.utf8ByteSequenceLength(b0) catch return 1;
    if (pos + seq_len > limit) return 1;
    _ = std.unicode.utf8Decode(haystack[pos .. pos + seq_len]) catch return 1;
    return seq_len;
}

/// Decodes a valid UTF-8 codepoint at `haystack[pos..limit]`. Returns `null` if invalid/truncated UTF-8.
pub inline fn decodeValidUtf8At(haystack: []const u8, pos: usize, limit: usize) ?struct { cp: u21, len: usize } {
    if (pos >= limit) return null;
    const b0 = haystack[pos];
    if (b0 < 0x80) return .{ .cp = b0, .len = 1 };
    const seq_len = std.unicode.utf8ByteSequenceLength(b0) catch return null;
    if (pos + seq_len > limit) return null;
    const cp = std.unicode.utf8Decode(haystack[pos .. pos + seq_len]) catch return null;
    return .{ .cp = cp, .len = seq_len };
}

pub fn allowAnySpan(haystack: []const u8, start: usize, end: usize) bool {
    _ = haystack;
    _ = start;
    _ = end;
    return true;
}

pub fn allowExactLen(haystack: []const u8, start: usize, end: usize) bool {
    return start == 0 and end == haystack.len;
}

pub inline fn invokeAllow(allow_arg: anytype, haystack: []const u8, start: usize, end: usize) bool {
    return switch (@typeInfo(@TypeOf(allow_arg))) {
        .@"fn" => allow_arg(haystack, start, end),
        .pointer => |p| if (@typeInfo(p.child) == .@"fn")
            allow_arg(haystack, start, end)
        else
            allow_arg.allow(haystack, start, end),
        else => allow_arg.allow(haystack, start, end),
    };
}

pub fn hasTopLevelAlt(pattern: []const u8) bool {
    var depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        const c = pattern[i];
        if (c == '\\') {
            i += 1;
            continue;
        }
        if (in_class) {
            if (c == ']') in_class = false;
            continue;
        }
        switch (c) {
            '[' => in_class = true,
            '(' => depth += 1,
            ')' => if (depth > 0) {
                depth -= 1;
            },
            '|' => if (depth == 0) return true,
            else => {},
        }
    }
    return false;
}

pub fn lineStartAt(haystack: []const u8, pos: usize) usize {
    if (pos == 0) return 0;
    if (memchr.findLast(memchr.native_width, haystack, 0, pos, '\n')) |nl| return nl + 1;
    return 0;
}

pub fn isWordChar(b: u8) bool {
    return switch (b) {
        '0'...'9', 'A'...'Z', 'a'...'z', '_' => true,
        else => false,
    };
}

pub fn checkAssert(kind: AssertKind, haystack: []const u8, pos: usize) bool {
    return switch (kind) {
        .start_line => pos == 0 or (pos <= haystack.len and haystack[pos - 1] == '\n'),
        .end_line => pos == haystack.len or haystack[pos] == '\n' or (pos + 1 < haystack.len and haystack[pos] == '\r' and haystack[pos + 1] == '\n'),
        .start_input => pos == 0,
        .end_input => pos == haystack.len,
        .word_boundary => blk: {
            const left = unicode_fold.isWordBefore(haystack, pos);
            const right = unicode_fold.isWordAt(haystack, pos);
            break :blk left != right;
        },
        .not_word_boundary => blk: {
            const left = unicode_fold.isWordBefore(haystack, pos);
            const right = unicode_fold.isWordAt(haystack, pos);
            break :blk left == right;
        },
    };
}

pub fn hasLiteralUpper(pattern: []const u8, unicode_case: bool) bool {
    var i: usize = 0;
    while (i < pattern.len) {
        if (pattern[i] == '\\') {
            if (i + 1 < pattern.len and (pattern[i + 1] == 'p' or pattern[i + 1] == 'P')) {
                i += 2;
                if (i < pattern.len and pattern[i] == '{') {
                    while (i < pattern.len and pattern[i] != '}') : (i += 1) {}
                    if (i < pattern.len) i += 1;
                } else if (i < pattern.len) {
                    i += 1;
                }
                continue;
            }
            i += 2;
            continue;
        }
        if (pattern[i] == '(' and i + 1 < pattern.len and pattern[i + 1] == '?') {
            i += 2;
            while (i < pattern.len and (pattern[i] == 'i' or pattern[i] == 'm' or pattern[i] == 's' or pattern[i] == '-')) : (i += 1) {}
            if (i < pattern.len and (pattern[i] == ':' or pattern[i] == ')')) i += 1;
            continue;
        }
        if (pattern[i] >= 'A' and pattern[i] <= 'Z') return true;
        if (unicode_case and pattern[i] >= 0x80) {
            const seq_len = utf8SeqLenAt(pattern, i, pattern.len);
            if (seq_len > 1) {
                const cp = std.unicode.utf8Decode(pattern[i .. i + seq_len]) catch {
                    i += 1;
                    continue;
                };
                if (unicode_fold.isUpperCodepoint(cp)) return true;
                i += seq_len;
                continue;
            }
        }
        i += 1;
    }
    return false;
}

pub fn addShorthand(set: *ByteSet, kind: u8) void {
    var tmp = ByteSet{};
    switch (kind) {
        'd', 'D' => tmp.setRange('0', '9', false),
        'w', 'W' => {
            tmp.setRange('0', '9', false);
            tmp.setRange('A', 'Z', false);
            tmp.setRange('a', 'z', false);
            tmp.set('_');
        },
        's', 'S' => {
            tmp.set(' ');
            tmp.set('\t');
            tmp.set('\n');
            tmp.set('\r');
            tmp.set(0x0B);
            tmp.set(0x0C);
        },
        else => unreachable,
    }
    if (kind == 'D' or kind == 'W' or kind == 'S') tmp.invert();
    for (0..4) |i| set.bits[i] |= tmp.bits[i];
}
