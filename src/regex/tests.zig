//! [Module] regex/tests.zig
//! [Layer] Layer 2 — Regex Unit & Property Tests
//! [Role] Verifies linear-time Thompson NFA execution, instruction caps, SIMD prefilter extraction,
//!        alternation priority, bounded multiline windows, UTF-8 character classes, capture groups,
//!        F1 (`*const Regex`, `RegexScratch`), F3 (`RegexSet`), F5 (`BoundedDfa`), F6 (Unicode properties & UAX #29),
//!        and F13 (`CompileDiagnostic`).

const std = @import("std");
const vm = @import("vm.zig");
const set_mod = @import("set.zig");
const inst_mod = @import("inst.zig");
const dfa_mod = @import("dfa.zig");
const Regex = vm.Regex;
const RegexScratch = vm.RegexScratch;
const RegexSet = set_mod.RegexSet;
const CompileDiagnostic = inst_mod.CompileDiagnostic;
const DiagnosticCode = inst_mod.DiagnosticCode;
const isWordChar = inst_mod.isWordChar;

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
    try std.testing.expect(re_whole.acceptsSpan("ab", .leftmost_first));
    try std.testing.expect(re_whole.acceptsSpan("a", .leftmost_first));
    try std.testing.expect(!re_whole.acceptsSpan("abc", .leftmost_first));

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
    try std.testing.expect(re_dot.acceptsSpan("中", .leftmost_first));
    try std.testing.expect(re_dot.acceptsSpan("😀", .leftmost_first));

    var re_neg = try Regex.init(std.testing.allocator, "^[^a-z]{2}$", .{});
    defer re_neg.deinit();
    try std.testing.expect(re_neg.acceptsSpan("你好", .leftmost_first));
    try std.testing.expect(!re_neg.acceptsSpan("你a", .leftmost_first));

    var re_bang = try Regex.init(std.testing.allocator, "^[!a-z]+$", .{});
    defer re_bang.deinit();
    try std.testing.expect(re_bang.acceptsSpan("123", .leftmost_first));
    try std.testing.expect(!re_bang.acceptsSpan("1a3", .leftmost_first));

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

test "M2 F1: *const Regex thread-safe search and RegexScratch reuse" {
    var re = try Regex.init(std.testing.allocator, "[a-z]{3}_[0-9]{2,4}", .{});
    defer re.deinit();

    const const_re: *const Regex = &re;
    try std.testing.expect(const_re.isMatch("prefix abc_123 suffix"));
    const hit = const_re.find("prefix abc_123 suffix", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("abc_123", "prefix abc_123 suffix"[hit.start..hit.end]);

    var scratch = RegexScratch.init(std.testing.allocator);
    defer scratch.deinit();
    try std.testing.expect(const_re.isMatchWithScratch("prefix xyz_99 suffix", &scratch));
    const hit2 = const_re.findWithScratch("prefix xyz_99 suffix", 0, .leftmost_first, &scratch).?;
    try std.testing.expectEqualStrings("xyz_99", "prefix xyz_99 suffix"[hit2.start..hit2.end]);
    try std.testing.expect(scratch.dfa != null);
    try std.testing.expect(scratch.dfa_scratch != null);
}

test "M2 F3: RegexSet single-pass evaluation, pattern_id, and Multi prefilter" {
    var set = try RegexSet.init(std.testing.allocator, &.{
        "ERROR_[0-9]+",
        "WARN_[a-z]+",
        "FATAL: .*",
    }, .{});
    defer set.deinit();

    try std.testing.expectEqual(@as(usize, 3), set.len());
    try std.testing.expect(!set.isEmpty());
    try std.testing.expect(set.prefilter != null);

    const hay = "INFO ok\nWARN_disk: full\nERROR_503\nFATAL: crash\n";
    try std.testing.expect(set.isMatch(hay));

    const first = set.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(?u32, 1), first.pattern_id);
    try std.testing.expectEqualStrings("WARN_disk", hay[first.start..first.end]);

    var ids: [8]u32 = undefined;
    const count = set.matches(hay, &ids);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2 }, ids[0..count]);
}

test "M2 F6: Unicode property classes \\p{...}, \\P{...}, scripts, and UAX #29 word boundaries" {
    var re_han = try Regex.init(std.testing.allocator, "\\p{Han}+", .{});
    defer re_han.deinit();
    const hit_han = re_han.find("abc你好世界123", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("你好世界", "abc你好世界123"[hit_han.start..hit_han.end]);

    var re_norm = try Regex.init(std.testing.allocator, "\\p{ gc = Uppercase_Letter }+", .{});
    defer re_norm.deinit();
    const hit_norm = re_norm.find("123ABCdef", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("ABC", "123ABCdef"[hit_norm.start..hit_norm.end]);

    var re_icase = try Regex.init(std.testing.allocator, "\\p{Lu}+", .{ .case = .insensitive });
    defer re_icase.deinit();
    const hit_icase = re_icase.find("123AbCdEf456", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("AbCdEf", "123AbCdEf456"[hit_icase.start..hit_icase.end]);

    var re_neg = try Regex.init(std.testing.allocator, "\\P{Han}+", .{});
    defer re_neg.deinit();
    const hit_neg = re_neg.find("abc\n你好", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("abc", "abc\n你好"[hit_neg.start..hit_neg.end]);

    var re_wb = try Regex.init(std.testing.allocator, "\\bcafé\\b", .{});
    defer re_wb.deinit();
    try std.testing.expect(re_wb.isMatch("🚀café。"));
}

test "M2 F13: CompileDiagnostic line, column, offset, and reuse reset" {
    var diag: CompileDiagnostic = .{};
    try std.testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(std.testing.allocator, "abc\ndef(ghi", .{ .multiline = true }, &diag),
    );
    try std.testing.expectEqual(DiagnosticCode.unclosed_group, diag.code);
    try std.testing.expectEqual(@as(usize, 7), diag.offset);
    try std.testing.expectEqual(@as(usize, 2), diag.line);
    try std.testing.expectEqual(@as(usize, 4), diag.column);

    // Reuse diag on a valid pattern: must reset to .none and .err = null
    var ok_re = try Regex.initDiagnostic(std.testing.allocator, "abc", .{}, &diag);
    defer ok_re.deinit();
    try std.testing.expectEqual(DiagnosticCode.none, diag.code);
    try std.testing.expectEqual(@as(?inst_mod.Error, null), diag.err);
}
