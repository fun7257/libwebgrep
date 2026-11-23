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

test "v0.7.0: named capture groups, up to 32 captures, diagnostics, and smart-case" {
    const alloc = std.testing.allocator;

    // 1. (?P<name>...) and (?<name>...)
    {
        var re = try Regex.init(alloc, "(?P<user>[a-z]+):(?<id>[0-9]+):([a-z]+)", .{});
        defer re.deinit();
        try std.testing.expectEqual(@as(?usize, 1), re.groupIndexByName("user"));
        try std.testing.expectEqual(@as(?usize, 2), re.groupIndexByName("id"));
        try std.testing.expectEqual(@as(?usize, null), re.groupIndexByName("missing"));
        try std.testing.expectEqual(@as(u8, 3), re.group_count);

        const hay = "  alice:1024:admin  ";
        const caps = re.findCaptures(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        const u_span = caps.byName(&re, "user") orelse return error.TestUnexpectedResult;
        const id_span = caps.byName(&re, "id") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("alice", hay[u_span.start..u_span.end]);
        try std.testing.expectEqualStrings("1024", hay[id_span.start..id_span.end]);
        try std.testing.expectEqualStrings("admin", caps.slice(hay, 3).?);
    }

    // 2. Named group inside {m,n} bounded repeat does not trigger duplicate_group_name
    {
        var re = try Regex.init(alloc, "(?P<pair>[a-z][0-9]){2,3}", .{});
        defer re.deinit();
        try std.testing.expectEqual(@as(?usize, 1), re.groupIndexByName("pair"));
        const hay = "a1b2c3";
        const caps = re.findCaptures(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        const span = caps.byName(&re, "pair") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("c3", hay[span.start..span.end]);
    }

    // 3. Smart case must NOT treat uppercase inside group name (?P<ID>...) as case-sensitive literal
    {
        var re = try Regex.init(alloc, "(?P<ID>[a-z]+)", .{ .case = .smart });
        defer re.deinit();
        try std.testing.expect(re.ignore_case);
        const hay = "HELLO";
        const caps = re.findCaptures(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        const span = caps.byName(&re, "ID") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("HELLO", hay[span.start..span.end]);
    }

    // 4. Up to 32 capture groups (e.g. 12 and 32)
    {
        var re12 = try Regex.init(alloc, "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(?P<last>l)", .{});
        defer re12.deinit();
        try std.testing.expectEqual(@as(u8, 12), re12.group_count);
        const caps = re12.findCaptures("abcdefghijkl", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("j", caps.slice("abcdefghijkl", 10).?);
        try std.testing.expectEqualStrings("k", caps.slice("abcdefghijkl", 11).?);
        try std.testing.expectEqualStrings("l", caps.slice("abcdefghijkl", 12).?);
        const named_last = caps.byName(&re12, "last") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("l", "abcdefghijkl"[named_last.start..named_last.end]);

        var re32 = try Regex.init(
            alloc,
            "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)(m)(n)(o)(p)(q)(r)(s)(t)(u)(v)(w)(x)(y)(z)(0)(1)(2)(3)(4)(?P<g32>5)",
            .{},
        );
        defer re32.deinit();
        try std.testing.expectEqual(@as(u8, 32), re32.group_count);
        const hay32 = "abcdefghijklmnopqrstuvwxyz012345";
        const caps32 = re32.findCaptures(hay32, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("4", caps32.slice(hay32, 31).?);
        try std.testing.expectEqualStrings("5", caps32.slice(hay32, 32).?);
        try std.testing.expectEqualStrings("5", hay32[caps32.byName(&re32, "g32").?.start..caps32.byName(&re32, "g32").?.end]);
    }

    // 5. Invalid and duplicate group name diagnostics
    {
        var diag: CompileDiagnostic = .{};
        try std.testing.expectError(
            error.RegexSyntax,
            Regex.initDiagnostic(alloc, "(?P<1bad>a)", .{}, &diag),
        );
        try std.testing.expectEqual(DiagnosticCode.invalid_group_name, diag.code);

        try std.testing.expectError(
            error.RegexSyntax,
            Regex.initDiagnostic(alloc, "(?P<dup>a)(?<dup>b)", .{}, &diag),
        );
        try std.testing.expectEqual(DiagnosticCode.duplicate_group_name, diag.code);
    }
}

test "v0.7.0: hex/unicode escapes, \\Q..\\E, \\a/\\f/\\v/\\Z, POSIX classes, (?x), and (?U)" {
    const alloc = std.testing.allocator;

    // 1. \xHH, \x{...}, \uHHHH, \u{...} outside and inside [...]
    {
        var re = try Regex.init(alloc, "\\x41\\x{1F600}\\u0042\\u{4E2D}", .{});
        defer re.deinit();
        const hay = "prefix A😀B中 suffix";
        const m = re.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("A😀B中", hay[m.start..m.end]);

        var re_cls = try Regex.init(alloc, "[\\x41-\\x43\\u{4E00}-\\u{9FFF}]+", .{});
        defer re_cls.deinit();
        const hay_cls = "zzAB你好Czz";
        const m_cls = re_cls.find(hay_cls, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("AB你好C", hay_cls[m_cls.start..m_cls.end]);

        var diag: CompileDiagnostic = .{};
        try std.testing.expectError(error.RegexSyntax, Regex.initDiagnostic(alloc, "\\uD800", .{}, &diag));
        try std.testing.expectEqual(DiagnosticCode.invalid_escape, diag.code);
        try std.testing.expectError(error.RegexSyntax, Regex.initDiagnostic(alloc, "\\x{110000}", .{}, &diag));
        try std.testing.expectEqual(DiagnosticCode.invalid_escape, diag.code);
    }

    // 2. \Q...\E literal quoting (outside and inside [...], plus empty and unclosed to EOF)
    {
        var re = try Regex.init(alloc, "\\Q[a]+.*(b)\\E!", .{});
        defer re.deinit();
        try std.testing.expect(re.find("[a]+.*(b)!", 0, .leftmost_first) != null);
        try std.testing.expect(re.find("aaaxxxb!", 0, .leftmost_first) == null);

        var re_opt = try Regex.init(alloc, "\\Qabc\\E?", .{});
        defer re_opt.deinit();
        try std.testing.expect(re_opt.isMatch("xyz"));

        var re_cls_q = try Regex.init(alloc, "[\\Qa-z\\E]+", .{});
        defer re_cls_q.deinit();
        try std.testing.expect(re_cls_q.acceptsSpan("a-z", .leftmost_first));
        try std.testing.expect(!re_cls_q.acceptsSpan("b", .leftmost_first));

        var re_unclosed = try Regex.init(alloc, "\\Qfoo[0", .{});
        defer re_unclosed.deinit();
        try std.testing.expect(re_unclosed.isMatch("foo[0"));

        var re_empty_q = try Regex.init(alloc, "a\\Q\\Eb", .{});
        defer re_empty_q.deinit();
        try std.testing.expect(re_empty_q.isMatch("ab"));
    }

    // 3. \a, \f, \v, \Z
    {
        var re_ctrl = try Regex.init(alloc, "\\a\\f\\v", .{});
        defer re_ctrl.deinit();
        try std.testing.expect(re_ctrl.isMatch("ok\x07\x0C\x0Bdone"));

        var re_z = try Regex.init(alloc, "end\\Z", .{});
        defer re_z.deinit();
        const m_eof = re_z.find("end", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("end", "end"[m_eof.start..m_eof.end]);
        const m_nl = re_z.find("end\n", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("end", "end\n"[m_nl.start..m_nl.end]);
        try std.testing.expect(re_z.find("end\nmore", 0, .leftmost_first) == null);
    }

    // 4. All 14 POSIX character classes and negation
    {
        const cases = [_]struct { pat: []const u8, yes: []const u8, no: []const u8 }{
            .{ .pat = "^[[:alnum:]]+$", .yes = "aZ09", .no = "a_9" },
            .{ .pat = "^[[:alpha:]]+$", .yes = "aZb", .no = "a1b" },
            .{ .pat = "^[[:ascii:]]+$", .yes = "abc~!", .no = "α" },
            .{ .pat = "^[[:blank:]]+$", .yes = " \t ", .no = " \n " },
            .{ .pat = "^[[:cntrl:]]+$", .yes = "\x01\x7F", .no = "a" },
            .{ .pat = "^[[:digit:]]+$", .yes = "0129", .no = "0a" },
            .{ .pat = "^[[:graph:]]+$", .yes = "a!~", .no = "a b" },
            .{ .pat = "^[[:lower:]]+$", .yes = "abc", .no = "aBc" },
            .{ .pat = "^[[:print:]]+$", .yes = "a !~", .no = "a\x07" },
            .{ .pat = "^[[:punct:]]+$", .yes = ".,!?@[]{}", .no = "a!" },
            .{ .pat = "^[[:space:]]+$", .yes = " \t\r\x0B\x0C", .no = " x" },
            .{ .pat = "^[[:upper:]]+$", .yes = "XYZ", .no = "XyZ" },
            .{ .pat = "^[[:word:]]+$", .yes = "ab_09", .no = "ab-09" },
            .{ .pat = "^[[:xdigit:]]+$", .yes = "09afAF", .no = "09fg" },
            .{ .pat = "^[[:^digit:]]+$", .yes = "ab你好!", .no = "a5b" },
        };
        for (cases) |tc| {
            var re = try Regex.init(alloc, tc.pat, .{});
            defer re.deinit();
            try std.testing.expect(re.acceptsSpan(tc.yes, .leftmost_first));
            try std.testing.expect(!re.acceptsSpan(tc.no, .leftmost_first));
        }

        // Case-insensitive [[:lower:]] and [[:upper:]]
        var re_ic = try Regex.init(alloc, "(?i)[[:lower:]]+", .{});
        defer re_ic.deinit();
        try std.testing.expect(re_ic.acceptsSpan("aBc", .leftmost_first));

        var diag: CompileDiagnostic = .{};
        try std.testing.expectError(error.RegexSyntax, Regex.initDiagnostic(alloc, "[[:bogus:]]", .{}, &diag));
        try std.testing.expectEqual(DiagnosticCode.invalid_posix_class, diag.code);
        try std.testing.expectError(error.RegexSyntax, Regex.initDiagnostic(alloc, "[[:digit:", .{}, &diag));
        try std.testing.expectEqual(DiagnosticCode.invalid_posix_class, diag.code);
    }

    // 5. Extended mode (?x) with multi-line layout & comments in single-line mode + (?-x) + RegexSet
    {
        const pat =
            \\(?x)
            \\  foo     # match prefix
            \\  _       # underscore
            \\  [0-9]+  # digits
            \\  (?-x: bar) # trailing literal space inside non-x group
        ;
        var re = try Regex.init(alloc, pat, .{});
        defer re.deinit();
        const m = re.find("xxx foo_123 bar yyy", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("foo_123 bar", "xxx foo_123 bar yyy"[m.start..m.end]);

        var set = try RegexSet.init(alloc, &.{
            "(?x)\n  alpha  # first\n  _[0-9]+\n",
            "(?x)\n  beta   # second\n  _[a-z]+\n",
        }, .{});
        defer set.deinit();
        const mset = set.find("test beta_ok done", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(?u32, 1), mset.pattern_id);
        try std.testing.expectEqualStrings("beta_ok", "test beta_ok done"[mset.start..mset.end]);
    }

    // 6. Ungreedy flag (?U) and toggle (?U:...) / (?-U)
    {
        var re_u = try Regex.init(alloc, "(?U)a+b+", .{});
        defer re_u.deinit();
        const mu = re_u.find("aaabbb", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("aaab", "aaabbb"[mu.start..mu.end]);

        var re_u_flip = try Regex.init(alloc, "(?U)a+?b+?", .{});
        defer re_u_flip.deinit();
        const mf = re_u_flip.find("aaabbb", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("aaabbb", "aaabbb"[mf.start..mf.end]);

        var re_u_neg = try Regex.init(alloc, "(?U)(?-U)a+b+", .{});
        defer re_u_neg.deinit();
        const mn = re_u_neg.find("aaabbb", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("aaabbb", "aaabbb"[mn.start..mn.end]);

        var re_u_one = try Regex.init(alloc, "(?U)a+", .{});
        defer re_u_one.deinit();
        const m1 = re_u_one.find("aaa", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("a", "aaa"[m1.start..m1.end]);

        var re_u_scoped = try Regex.init(alloc, "(?U:a+)a+b", .{});
        defer re_u_scoped.deinit();
        const ms = re_u_scoped.find("aaaab", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("aaaab", "aaaab"[ms.start..ms.end]);
    }
}

test "regex v0.8: unicode_classes option and (?u)/(?-u) inline flags for \\d \\w \\s" {
    const alloc = std.testing.allocator;

    // 1. ASCII default vs unicode_classes = true for \d (Arabic-Indic ٠١٢ & Fullwidth ０１２)
    {
        var re_ascii = try Regex.init(alloc, "\\d+", .{});
        defer re_ascii.deinit();
        try std.testing.expect(re_ascii.find("٠١٢", 0, .leftmost_first) == null);

        var re_uni = try Regex.init(alloc, "\\d+", .{ .unicode_classes = true });
        defer re_uni.deinit();
        const hay = "val=٠١٢/０１２!";
        const m1 = re_uni.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("٠١٢", hay[m1.start..m1.end]);
        const m2 = re_uni.find(hay, m1.end, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("０１２", hay[m2.start..m2.end]);
    }

    // 2. Unicode \w and \W (Han, Cyrillic, Latin accents, underscore, punctuation exclusion)
    {
        var re_w = try Regex.init(alloc, "(?u)\\w+", .{});
        defer re_w.deinit();
        const hay = "。中文_café123，Привет!";
        const m1 = re_w.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("中文_café123", hay[m1.start..m1.end]);
        const m2 = re_w.find(hay, m1.end, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("Привет", hay[m2.start..m2.end]);

        var re_W = try Regex.init(alloc, "(?u)\\W+", .{});
        defer re_W.deinit();
        const mw = re_W.find("中文，Привет", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("，", "中文，Привет"[mw.start..mw.end]);
    }

    // 3. Unicode \s and \S (NBSP U+00A0 and Ideographic Space U+3000)
    {
        var re_s = try Regex.init(alloc, "(?u)\\s+", .{});
        defer re_s.deinit();
        const hay = "a\u{00A0}\u{3000}b";
        const ms = re_s.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("\u{00A0}\u{3000}", hay[ms.start..ms.end]);
    }

    // 4. Inside character classes [...] and scoped (?u:...) / (?-u:...)
    {
        var re_cls = try Regex.init(alloc, "(?u)[\\d\\s]+", .{});
        defer re_cls.deinit();
        const hay = "x٠\u{3000}９y";
        const mc = re_cls.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("٠\u{3000}９", hay[mc.start..mc.end]);

        var re_toggle = try Regex.init(alloc, "(?u:\\w+)-(?-u:\\d+)", .{ .unicode_classes = true });
        defer re_toggle.deinit();
        try std.testing.expect(re_toggle.find("中文-42", 0, .leftmost_first) != null);
        try std.testing.expect(re_toggle.find("中文-٠١", 0, .leftmost_first) == null);
    }
}

test "Regex SIMD ByteContextPrefilter, 4-byte suffix Teddy promotion, and Unicode prefix fast path" {
    const alloc = std.testing.allocator;

    // 1. \p{Han}+_[0-9]{4}: uses ByteContextPrefilter + direct reverse Unicode class verification
    {
        var re = try Regex.init(alloc, "\\p{Han}+_[0-9]{4}", .{ .unicode_classes = true });
        defer re.deinit();
        try std.testing.expect(re.byte_ctx_prefilter != null);
        try std.testing.expect(re.req_prefix_uclass_pc != std.math.maxInt(u32));
        try std.testing.expect(re.dfa_suffix_is_exact);

        var buf: [260]u8 = @splat(' ');
        const noise = "user_session_9012 Café_LATTE ";
        @memcpy(buf[10..][0..noise.len], noise);
        const target = "异常订单超时_2026";
        @memcpy(buf[160..][0..target.len], target);

        const m = re.find(&buf, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(target, buf[m.start..m.end]);

        const m_e = re.find(&buf, 0, .earliest) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(target, buf[m_e.start..m_e.end]);

        var nul: ?usize = null;
        buf[100] = 0;
        try std.testing.expect(re.findWatched(&buf, 0, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 100), nul);

        buf[100] = ' ';
        buf[160 + target.len + 2] = 0;
        nul = null;
        const mw = re.findWatched(&buf, 0, &nul) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul == null);
        try std.testing.expectEqualStrings(target, buf[mw.start..mw.end]);
    }

    // 2. (a|b){15}c: promotes 3 preceding bytes into 8 4-byte patterns (aaac..bbbc)
    {
        var re = try Regex.init(alloc, "(a|b){15}c", .{});
        defer re.deinit();
        try std.testing.expect(re.pair_prefilter != null);
        try std.testing.expectEqual(@as(u8, 3), re.pair_prefilter_prefix_len);

        const hay = "service=cache compaction_cycle ababababaabbabac_sentinel";
        const m = re.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("ababababaabbabac", hay[m.start..m.end]);

        var nul: ?usize = null;
        const mw = re.findWatched(hay, 0, &nul) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul == null);
        try std.testing.expectEqualStrings("ababababaabbabac", hay[mw.start..mw.end]);
    }

    // 3. Disjointness guard: \p{L}+a[0-9]* must NOT take uclass fast path because 'a' is in \p{L}
    {
        var re = try Regex.init(alloc, "\\p{L}+a[0-9]*", .{ .unicode_classes = true });
        defer re.deinit();
        try std.testing.expectEqual(std.math.maxInt(u32), re.req_prefix_uclass_pc);
        const hay = "baa1";
        const m = re.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("baa1", hay[m.start..m.end]);
    }
}

test "P0-1: Unanchored DFA with \\b[a-z]{6,10}\\s+[0-9]{3,5}\\b (ASCII & Unicode, find & findWatched)" {
    const alloc = std.testing.allocator;

    // 1. ASCII mode
    {
        var re = try Regex.init(alloc, "\\b[a-z]{6,10}\\s+[0-9]{3,5}\\b", .{});
        defer re.deinit();
        try std.testing.expect(re.prefilter == null);
        try std.testing.expect(re.alt_prefilter == null);
        try std.testing.expect(re.unanchored_dfa != null);
        const udfa = re.unanchored_dfa.?;
        try std.testing.expect(!udfa.start_reentrant);
        try std.testing.expect(udfa.start_skip == .range1);
        try std.testing.expectEqual(@as(u8, 'a'), udfa.start_skip.range1.lo);
        try std.testing.expectEqual(@as(u8, 25), udfa.start_skip.range1.span);

        const hay =
            "2026-11-23T12:00:00Z [INFO] short 123 toolongwordx 456 Xabcdef 789 user_abcdef 123\n" ++
            "abcdef 12 abcdef 123456 abcdef\n999 Xabcdef 123  latency  12345  done\n" ++
            "another 987\n";
        const m1 = re.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("latency  12345", hay[m1.start..m1.end]);
        const m1_e = re.find(hay, 0, .earliest) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("latency  12345", hay[m1_e.start..m1_e.end]);

        const m2 = re.find(hay, m1.end, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("another 987", hay[m2.start..m2.end]);
        try std.testing.expect(re.find(hay, m2.end, .leftmost_first) == null);

        // findWatched: no NUL
        var nul: ?usize = null;
        const mw = re.findWatched(hay, 0, &nul) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul == null);
        try std.testing.expectEqualStrings("latency  12345", hay[mw.start..mw.end]);

        // findWatched: NUL before match
        var nul_buf: [128]u8 = @splat(' ');
        const prefix = "2026 [INFO] Xabcdef 123 ";
        @memcpy(nul_buf[0..prefix.len], prefix);
        nul_buf[40] = 0;
        const good = "worker 4321";
        @memcpy(nul_buf[60..][0..good.len], good);
        var nul_at: ?usize = null;
        try std.testing.expect(re.findWatched(&nul_buf, 0, &nul_at) == null);
        try std.testing.expectEqual(@as(?usize, 40), nul_at);

        // findWatched: NUL right at m.end (`worker 4321\x00`) must return match with nul == null
        nul_buf[40] = ' ';
        nul_buf[60 + good.len] = 0;
        nul_at = null;
        const mw2 = re.findWatched(&nul_buf, 0, &nul_at) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul_at == null);
        try std.testing.expectEqualStrings("worker 4321", nul_buf[mw2.start..mw2.end]);
    }

    // 2. Unicode mode (`\s+` matches NBSP U+00A0 and Ideographic Space U+3000)
    {
        var re_u = try Regex.init(alloc, "\\b[a-z]{6,10}\\s+[0-9]{3,5}\\b", .{ .unicode_classes = true });
        defer re_u.deinit();
        try std.testing.expect(re_u.unanchored_dfa != null);

        const hay_u = "前缀测试 Xabcdef\u{3000}123  metric\u{00A0}\u{3000}2048  后缀";
        const mu = re_u.find(hay_u, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("metric\u{00A0}\u{3000}2048", hay_u[mu.start..mu.end]);

        var nul_u: ?usize = null;
        const mwu = re_u.findWatched(hay_u, 0, &nul_u) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul_u == null);
        try std.testing.expectEqualStrings("metric\u{00A0}\u{3000}2048", hay_u[mwu.start..mwu.end]);

        // ASCII mode must NOT match U+00A0/U+3000
        var re_a = try Regex.init(alloc, "\\b[a-z]{6,10}\\s+[0-9]{3,5}\\b", .{ .unicode_classes = false });
        defer re_a.deinit();
        try std.testing.expect(re_a.find(hay_u, 0, .leftmost_first) == null);
    }

    // 3. Zero-length match stays on PikeVM; start-reentrant pattern remains exact
    {
        var re_empty = try Regex.init(alloc, "[a-z]*", .{});
        defer re_empty.deinit();
        try std.testing.expect(re_empty.unanchored_dfa == null);
        const me = re_empty.find("123", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 0), me.start);
        try std.testing.expectEqual(@as(usize, 0), me.end);

        var re_reent = try Regex.init(alloc, "(?:[a-b][c-d])*[0-9]{2}", .{});
        defer re_reent.deinit();
        if (re_reent.unanchored_dfa) |ud| {
            try std.testing.expect(ud.start_reentrant);
        }
        const mr = re_reent.find("zzacbd42yy", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("acbd42", "zzacbd42yy"[mr.start..mr.end]);
    }
}

test "P1: Leading group alternation prefilter (?:err|warn|fail|crit|fatal)_[a-z]+_[0-9]{3}" {
    const alloc = std.testing.allocator;

    // 1. Main leading group + suffix `_`
    {
        var re = try Regex.init(alloc, "(?:err|warn|fail|crit|fatal)_[a-z]+_[0-9]{3}", .{});
        defer re.deinit();
        try std.testing.expect(re.prefilter == null);
        try std.testing.expect(re.alt_prefilter != null);
        try std.testing.expect(re.alt_is_prefix);
        try std.testing.expect(!re.alt_is_exact);
        try std.testing.expect(re.precomputed_dfa != null);
        try std.testing.expectEqual(@as(usize, 5), re.alt_literal_slices.len);
        try std.testing.expectEqualStrings("err_", re.alt_literal_slices[0]);
        try std.testing.expectEqualStrings("fatal_", re.alt_literal_slices[4]);

        const hay = "ok err_123 warn_abc_12 fail_abc_xyz crit_timeout_503 fatal_oom_999\n";
        const m1 = re.find(hay, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("crit_timeout_503", hay[m1.start..m1.end]);
        const m2 = re.find(hay, m1.end, .earliest) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("fatal_oom_999", hay[m2.start..m2.end]);

        var nul: ?usize = null;
        const mw = re.findWatched(hay, 0, &nul) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul == null);
        try std.testing.expectEqualStrings("crit_timeout_503", hay[mw.start..mw.end]);

        const hay_nul = "err_123\x00crit_timeout_503\n";
        var nul2: ?usize = null;
        try std.testing.expect(re.findWatched(hay_nul, 0, &nul2) == null);
        try std.testing.expectEqual(@as(?usize, 7), nul2);

        const hay_nul_after = "crit_timeout_503\x00";
        var nul3: ?usize = null;
        const mw3 = re.findWatched(hay_nul_after, 0, &nul3) orelse return error.TestUnexpectedResult;
        try std.testing.expect(nul3 == null);
        try std.testing.expectEqualStrings("crit_timeout_503", hay_nul_after[mw3.start..mw3.end]);
    }

    // 2. Optional leading group must NOT assume required alt prefix
    {
        var re_opt = try Regex.init(alloc, "(?:err|warn)?_[a-z]+", .{});
        defer re_opt.deinit();
        try std.testing.expect(!re_opt.alt_is_prefix);
        const mo = re_opt.find("foo _abc bar", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("_abc", "foo _abc bar"[mo.start..mo.end]);
    }

    // 3. Repeated leading group with `+` must NOT append post-group suffix
    {
        var re_plus = try Regex.init(alloc, "(?:err|warn)+_[0-9]{2}", .{});
        defer re_plus.deinit();
        try std.testing.expect(re_plus.alt_prefilter != null);
        try std.testing.expect(re_plus.alt_is_prefix);
        const mp = re_plus.find("xx errwarn_42 yy", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("errwarn_42", "xx errwarn_42 yy"[mp.start..mp.end]);
    }
}

test "P4: Uniform terminal prefix DFA chain for \"uid\":[0-9]{7} on single-line JSON" {
    const alloc = std.testing.allocator;
    var re = try Regex.init(alloc, "\"uid\":[0-9]{7}", .{});
    defer re.deinit();

    try std.testing.expect(re.req_is_prefix);
    try std.testing.expect(re.precomputed_dfa != null);
    const dfa = re.precomputed_dfa.?;
    try std.testing.expect(dfa.stops_on_crlf);
    try std.testing.expectEqual(@as(usize, 6), re.dfa_prefix_len);
    const s0 = re.dfa_prefix_state;
    try std.testing.expectEqual(@as(u8, 7), dfa.chain_len[s0]);
    try std.testing.expectEqual(@as(u8, '0'), dfa.chain_uniform_lo[s0]);
    try std.testing.expectEqual(@as(u8, 9), dfa.chain_uniform_span[s0]);
    try std.testing.expect(dfa.is_terminal[s0 + 7]);

    const json = "[{\"uid\":123456,\"n\":\"a\"},{\"uid\":\"bad\"},{\"uid\":7654321,\"ok\":true}]";
    const m = re.find(json, 0, .leftmost_first) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("\"uid\":7654321", json[m.start..m.end]);

    var nul: ?usize = null;
    const mw = re.findWatched(json, 0, &nul) orelse return error.TestUnexpectedResult;
    try std.testing.expect(nul == null);
    try std.testing.expectEqualStrings("\"uid\":7654321", json[mw.start..mw.end]);

    const json_nul = "{\"uid\":123456,\x00\"uid\":7654321}";
    var nul2: ?usize = null;
    try std.testing.expect(re.findWatched(json_nul, 0, &nul2) == null);
    try std.testing.expectEqual(@as(?usize, 14), nul2);
}
