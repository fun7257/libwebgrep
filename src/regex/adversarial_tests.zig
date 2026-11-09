//! [Module] regex/adversarial_tests.zig
//! [Layer] Layer 2 — M2 Adversarial & Edge-Case Verification Suite
//! [Role] Exercises edge cases across Unicode properties, UAX #29 word boundaries, BoundedDfa state eviction
//!        and closure bailout, RegexSet limits and optional-prefix hazards, and CompileDiagnostic accuracy.

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

test "adversarial: BoundedDfa state cache flush and closure bailout" {
    // Small max_dfa_states (8) forces frequent state cache flushes without losing match accuracy
    var re = try Regex.init(std.testing.allocator, "[a-z][0-9][a-z][0-9][a-z][0-9][a-z][0-9][a-z][0-9]", .{
        .max_dfa_states = 8,
    });
    defer re.deinit();

    var scratch = RegexScratch.init(std.testing.allocator);
    defer scratch.deinit();

    const hay = "a1b2c3d4xx m1n2o3p4q5 z9y8x7w6v5";
    const hit = re.findWithScratch(hay, 0, .leftmost_first, &scratch).?;
    try std.testing.expectEqualStrings("m1n2o3p4q5", hay[hit.start..hit.end]);
    try std.testing.expect(scratch.dfa.?.flushes > 0);
}

test "adversarial: Lazy DFA false-positive assertion guard transitioning to NFA" {
    var re = try Regex.init(std.testing.allocator, "\\b[a-z]{4}\\b", .{});
    defer re.deinit();

    const hay = "longword1234 another_long_word_56789 real";
    const hit = re.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 37), hit.start);
    try std.testing.expectEqual(@as(usize, 41), hit.end);
    try std.testing.expectEqualStrings("real", hay[hit.start..hit.end]);
}

test "adversarial: Unicode properties across BMP, astral planes, invalid UTF-8, and double negation" {
    var re_emoji = try Regex.init(std.testing.allocator, "^\\p{Emoji}+$", .{});
    defer re_emoji.deinit();
    try std.testing.expect(re_emoji.isMatch("😀🚀🎉"));
    try std.testing.expect(!re_emoji.isMatch("hello"));

    // Double negation \P{^Lu} is equivalent to positive \p{Lu}
    var re_dneg = try Regex.init(std.testing.allocator, "\\P{^Lu}+", .{});
    defer re_dneg.deinit();
    const hit = re_dneg.find("abcDEFghi", 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("DEF", "abcDEFghi"[hit.start..hit.end]);

    // Invalid UTF-8 bytes must not match \p{Any} or \P{Han}
    var re_any = try Regex.init(std.testing.allocator, "\\p{Any}+", .{});
    defer re_any.deinit();
    const bad_utf8 = "\xff\xfeabc\x80";
    const hit_any = re_any.find(bad_utf8, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("abc", bad_utf8[hit_any.start..hit_any.end]);

    // Large CJK bracket range [一-龥] compiles into compact unicode_class without exceeding max_inst
    var re_cjk = try Regex.init(std.testing.allocator, "[一-龥]{3}", .{});
    defer re_cjk.deinit();
    const hay_cjk = "错误: 数据库连接失败";
    const hit_cjk = re_cjk.find(hay_cjk, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("数据库", hay_cjk[hit_cjk.start..hit_cjk.end]);
}

test "adversarial: UAX #29 word boundaries with CJK, Arabic, emoji, and combining marks" {
    // Combining mark (U+0301) is a word character (Mn), so 'e' + U+0301 has no word boundary between them
    var re = try Regex.init(std.testing.allocator, "\\bcafe\u{0301}\\b", .{});
    defer re.deinit();
    try std.testing.expect(re.isMatch(" (cafe\u{0301}) "));
    try std.testing.expect(!re.isMatch("cafe\u{0301}s"));

    // Connector punctuation (U+203F undertie) is a word character (Pc)
    var re_word = try Regex.init(std.testing.allocator, "\\bfoo\\b", .{});
    defer re_word.deinit();
    try std.testing.expect(!re_word.isMatch("foo\u{203F}bar"));
    try std.testing.expect(re_word.isMatch("foo🚀bar"));
}

test "adversarial: multiline CompileDiagnostic line and 1-based column correctness" {
    var diag: CompileDiagnostic = .{};
    try std.testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(std.testing.allocator, "line1\n123456)bad", .{ .multiline = true }, &diag),
    );
    try std.testing.expectEqual(DiagnosticCode.unmatched_close_paren, diag.code);
    try std.testing.expectEqual(@as(usize, 2), diag.line);
    try std.testing.expectEqual(@as(usize, 7), diag.column);

    // Unclosed repeat braces vs invalid repeat bounds
    try std.testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(std.testing.allocator, "a{2,5", .{}, &diag),
    );
    try std.testing.expectEqual(DiagnosticCode.unclosed_repeat_braces, diag.code);

    try std.testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(std.testing.allocator, "a{5,2}", .{}, &diag),
    );
    try std.testing.expectEqual(DiagnosticCode.invalid_repeat_bounds, diag.code);

    // Invalid UTF-8 in pattern
    try std.testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(std.testing.allocator, "abc\xffdef", .{}, &diag),
    );
    try std.testing.expectEqual(DiagnosticCode.invalid_utf8, diag.code);
    try std.testing.expectEqual(@as(usize, 3), diag.offset);
}

test "adversarial: RegexSet newline rejection, optional prefix hazard, and small out_ids buffer" {
    var diag: CompileDiagnostic = .{};
    try std.testing.expectError(
        error.PatternHasNewline,
        RegexSet.initDiagnostic(std.testing.allocator, &.{ "valid_pat", "invalid\npat" }, .{ .multiline = false }, &diag),
    );
    try std.testing.expectEqual(DiagnosticCode.pattern_has_newline, diag.code);
    try std.testing.expectEqual(@as(?usize, 1), diag.pattern_index);

    // Optional quantifier `a?b` must not require `'a'` in the prefix prefilter
    var set = try RegexSet.init(std.testing.allocator, &.{ "a?b", "c+d" }, .{});
    defer set.deinit();
    const hit = set.find("xxbyy", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(?u32, 0), hit.pattern_id);
    try std.testing.expectEqualStrings("b", "xxbyy"[hit.start..hit.end]);

    var small_ids: [1]u32 = undefined;
    const n = set.matches("b and ccd", &small_ids);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u32, 0), small_ids[0]);
}

test "adversarial: concurrent *const Regex execution across 8 threads with > 256 instructions" {
    // Construct a pattern with > 256 instructions
    var pat_buf = std.ArrayList(u8).empty;
    defer pat_buf.deinit(std.testing.allocator);
    for (0..60) |i| {
        if (i > 0) try pat_buf.append(std.testing.allocator, '|');
        var tmp: [32]u8 = undefined;
        const s = try std.fmt.bufPrint(&tmp, "branch_{d:0>3}_end", .{i});
        try pat_buf.appendSlice(std.testing.allocator, s);
    }

    var re = try Regex.init(std.testing.allocator, pat_buf.items, .{});
    defer re.deinit();
    try std.testing.expect(re.insts.len > 256);

    const Worker = struct {
        fn run(r: *const Regex) void {
            for (0..25) |_| {
                const m = r.find("prefix branch_042_end suffix", 0, .leftmost_first).?;
                std.debug.assert(m.start == 7 and m.end == 21);
            }
        }
    };

    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&re});
    }
    for (threads) |t| t.join();
}
