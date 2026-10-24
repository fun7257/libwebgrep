//! Folds ASCII letters only; non-letters are returned unchanged.

pub fn fold(b: u8) u8 {
    if (b >= 'A' and b <= 'Z') return b + ('a' - 'A');
    return b;
}

pub fn eq(a: u8, b: u8, ignore_case: bool) bool {
    if (!ignore_case) return a == b;
    return fold(a) == fold(b);
}

pub fn eql(a: []const u8, b: []const u8, ignore_case: bool) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!eq(x, y, ignore_case)) return false;
    }
    return true;
}

/// Lowercase and uppercase variants of a letter; identical in both slots for non-letters.
pub fn caseVariants(b: u8) [2]u8 {
    const lower = fold(b);
    if (lower >= 'a' and lower <= 'z') return .{ lower, lower - ('a' - 'A') };
    return .{ b, b };
}

pub fn patternHasUpper(pattern: []const u8) bool {
    for (pattern) |b| {
        if (b >= 'A' and b <= 'Z') return true;
    }
    return false;
}
