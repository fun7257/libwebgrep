//! [Module] regex/tests.zig
//! [Layer] Layer 2 — Regex Unit & Property Tests
//! [Role] Verifies linear-time Thompson NFA execution, instruction caps, SIMD prefilter extraction,
//!        alternation priority, bounded multiline windows, UTF-8 character classes, and capture groups.

const std = @import("std");
const vm = @import("vm.zig");
const Regex = vm.Regex;
const isWordChar = @import("inst.zig").isWordChar;

test "regex compilation size exceeding hard cap is rejected" {
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.init(std.testing.allocator, "a{5000}", .{}),
    );
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.init(std.testing.allocator, "abcdefghij", .{ .max_inst = 5 }),
    );
}

test "pathological pattern steps scale linearly with input length" {
    // Traditional backtracking engines suffer O(2^n) exponential blowup on `(a+)+b` against all-'a' strings;
    // Thompson NFA visits each instruction at most once per input byte regardless of input length.
    var re = try Regex.init(std.testing.allocator, "(a+)+b", .{});
    defer re.deinit();

    const small_input: [64]u8 = @splat('a');
    re.resetStats();
    try std.testing.expect(re.find(&small_input, 0, .earliest) == null);
    const steps_64 = re.steps;

    const large_input: [256]u8 = @splat('a');
    re.resetStats();
    try std.testing.expect(re.find(&large_input, 0, .earliest) == null);
    const steps_256 = re.steps;

    // Steps for 256 bytes should be roughly 4x those for 64 bytes (allowing a small constant factor, never exponential)
    try std.testing.expect(steps_256 <= steps_64 * 5);
    try std.testing.expect(steps_256 <= 256 * re.insts.len * 2);
}

test "RequiredLiteral extraction and SIMD prefilter hit" {
    var re = try Regex.init(std.testing.allocator, "ERROR_[0-9]+:.*timeout", .{});
    defer re.deinit();

    const req = re.requiredLiteral().?;
    try std.testing.expectEqualStrings("ERROR_", req.bytes);
    try std.testing.expectEqual(@as(usize, 0), req.offset_in_match);

    const hay = "INFO ok\nWARN retry\nERROR_404: gateway timeout after 30s\n";
    const hit = re.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("ERROR_404: gateway timeout", hay[hit.start..hit.end]);
}

test "bounded multiline window matches within limit and fails immediately when exceeded" {
    var re = try Regex.init(std.testing.allocator, "BEGIN.*END", .{
        .multiline = true,
        .dot_all = true,
        .max_multiline_window = 32,
    });
    defer re.deinit();

    const short_hay = "header\nBEGIN\nmid\nEND\nfooter\n";
    const hit = re.find(short_hay, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("BEGIN\nmid\nEND", short_hay[hit.start..hit.end]);

    // When the span exceeds the 32-byte window, the multiline match immediately fails
    const filler: [40]u8 = @splat('x');
    const long_hay = "BEGIN\n" ++ filler ++ "\nEND\n";
    try std.testing.expect(re.find(long_hay, 0, .leftmost_first) == null);
}

test "caret start-of-line anchor matches on subsequent lines and with start > 0" {
    var re = try Regex.init(std.testing.allocator, "^ERROR", .{});
    defer re.deinit();

    const hay = "INFO ok\nERROR failed\n";
    const hit1 = re.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 8), hit1.start);
    try std.testing.expectEqual(@as(usize, 13), hit1.end);

    const hit2 = re.find(hay, 4, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 8), hit2.start);
    try std.testing.expectEqual(@as(usize, 13), hit2.end);
}

test "acceptsSpan and findAllowed respect lower-priority alternation branches" {
    var re_whole = try Regex.init(std.testing.allocator, "a|ab", .{});
    defer re_whole.deinit();
    try std.testing.expect(re_whole.acceptsSpan("ab", 0, 2));
    try std.testing.expect(re_whole.acceptsSpan("a", 0, 1));
    try std.testing.expect(!re_whole.acceptsSpan("abc", 0, 3));

    var re_word = try Regex.init(std.testing.allocator, "foo|foobar", .{});
    defer re_word.deinit();
    const WordCheck = struct {
        fn allow(h: []const u8, s: usize, e: usize) bool {
            const left = s > 0 and isWordChar(h[s - 1]);
            const right = e < h.len and isWordChar(h[e]);
            return !left and !right;
        }
    };
    const hit = re_word.findAllowed("foobar", 0, .leftmost_first, WordCheck.allow).?;
    try std.testing.expectEqual(@as(usize, 0), hit.start);
    try std.testing.expectEqual(@as(usize, 6), hit.end);
}

test "patterns starting with \\b or \\B match on indented lines and after non-word prefixes" {
    var re_lit = try Regex.init(std.testing.allocator, "\\bErrorCode\\b", .{});
    defer re_lit.deinit();
    const indented = "    if (err == ErrorCode) return;\n";
    const hit_lit = re_lit.find(indented, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("ErrorCode", indented[hit_lit.start..hit_lit.end]);
    const hit_ro = re_lit.findReadOnly(indented, 0, .leftmost_first).?;
    try std.testing.expectEqual(hit_lit, hit_ro);

    var re_short = try Regex.init(std.testing.allocator, "\\bid\\b", .{});
    defer re_short.deinit();
    const tab_line = "\tconst my_id = id;\n";
    const hit_short = re_short.find(tab_line, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 15), hit_short.start);
    try std.testing.expectEqual(@as(usize, 17), hit_short.end);

    var re_digits = try Regex.init(std.testing.allocator, "\\b\\d{4}\\b", .{});
    defer re_digits.deinit();
    const punct_line = "  [status: 2026]\n";
    const hit_digits = re_digits.find(punct_line, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("2026", punct_line[hit_digits.start..hit_digits.end]);

    var re_non_wb = try Regex.init(std.testing.allocator, "\\BCode\\b", .{});
    defer re_non_wb.deinit();
    const word_start_line = "ErrorCode = 1;\n";
    const hit_non_wb = re_non_wb.find(word_start_line, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("Code", word_start_line[hit_non_wb.start..hit_non_wb.end]);
}

test "multi-byte UTF-8 atoms, Unicode case folding, inline flags, [!...] negation, and capture groups" {
    var re_utf8 = try Regex.init(std.testing.allocator, "中+", .{});
    defer re_utf8.deinit();
    const hay_utf8 = "a中中中b";
    const hit_utf8 = re_utf8.find(hay_utf8, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("中中中", hay_utf8[hit_utf8.start..hit_utf8.end]);

    var re_dot = try Regex.init(std.testing.allocator, "^.$", .{});
    defer re_dot.deinit();
    try std.testing.expect(re_dot.acceptsSpan("中", 0, "中".len));
    try std.testing.expect(re_dot.acceptsSpan("😀", 0, "😀".len));

    var re_neg = try Regex.init(std.testing.allocator, "^[^a-z]{2}$", .{});
    defer re_neg.deinit();
    try std.testing.expect(re_neg.acceptsSpan("你好", 0, "你好".len));
    try std.testing.expect(!re_neg.acceptsSpan("你a", 0, "你a".len));

    var re_bang = try Regex.init(std.testing.allocator, "^[!a-z]+$", .{});
    defer re_bang.deinit();
    try std.testing.expect(re_bang.acceptsSpan("123", 0, 3));
    try std.testing.expect(!re_bang.acceptsSpan("1a3", 0, 3));

    var re_uclass = try Regex.init(std.testing.allocator, "[你好α-ω]+", .{});
    defer re_uclass.deinit();
    const hit_uclass = re_uclass.find("x你好β你y", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("你好β你", "x你好β你y"[hit_uclass.start..hit_uclass.end]);

    var re_ufold = try Regex.init(std.testing.allocator, "ω+", .{ .case = .smart });
    defer re_ufold.deinit();
    const hit_ufold = re_ufold.find("xΩωΩy", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("ΩωΩ", "xΩωΩy"[hit_ufold.start..hit_ufold.end]);

    var re_inline = try Regex.init(std.testing.allocator, "(?i:foo)bar", .{});
    defer re_inline.deinit();
    try std.testing.expect(re_inline.find("FOObar", 0, .leftmost_first) != null);
    try std.testing.expect(re_inline.find("FOOBAR", 0, .leftmost_first) == null);

    var re_uwb = try Regex.init(std.testing.allocator, "\\b你好\\b", .{});
    defer re_uwb.deinit();
    try std.testing.expect(re_uwb.find(" (你好) ", 0, .leftmost_first) != null);
    try std.testing.expect(re_uwb.find("世界你好吗", 0, .leftmost_first) == null);

    var re_cap = try Regex.init(std.testing.allocator, "([a-z]+)=([0-9]+)", .{});
    defer re_cap.deinit();
    const caps = re_cap.findCaptures("id=42", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("id=42", caps.slice("id=42", 0).?);
    try std.testing.expectEqualStrings("id", caps.slice("id=42", 1).?);
    try std.testing.expectEqualStrings("42", caps.slice("id=42", 2).?);
    try std.testing.expectEqual(@as(usize, 0), caps.fullMatch().start);
    try std.testing.expectEqual(@as(usize, 5), caps.fullMatch().end);
}


