//! Folds ASCII letters only; non-letters are returned unchanged.

const std = @import("std");

pub fn fold(b: u8) u8 {
    return std.ascii.toLower(b);
}

pub fn eq(a: u8, b: u8, ignore_case: bool) bool {
    if (!ignore_case) return a == b;
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

pub fn eql(a: []const u8, b: []const u8, ignore_case: bool) bool {
    return if (ignore_case) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
}

/// Lowercase and uppercase variants of a letter; identical in both slots for non-letters.
pub fn caseVariants(b: u8) [2]u8 {
    const lower = fold(b);
    if (lower >= 'a' and lower <= 'z') return .{ lower, lower - ('a' - 'A') };
    return .{ b, b };
}

pub fn patternHasUpper(pattern: []const u8) bool {
    for (pattern) |b| {
        if (std.ascii.isUpper(b)) return true;
    }
    return false;
}
