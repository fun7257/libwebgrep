//! Default byte frequency ranks. Smaller values indicate rarer bytes, which packed pair prefers as anchors.
//!
//! Hand-assigned ranks based on English prose and source code frequency rather than copied from another project.
//! Callers can supply their own `[256]u8` table.

const std = @import("std");

pub const default_rank: [256]u8 = defaultRank();

fn defaultRank() [256]u8 {
    var rank: [256]u8 = @splat(12);

    // Control bytes and NUL rarely appear in text.
    for (0..32) |i| rank[i] = 1;
    rank['\t'] = 80;
    rank['\n'] = 140;
    rank['\r'] = 40;
    rank[' '] = 255;

    // Lowercase letters ordered from most to least frequent in English.
    // Uppercase is rarer in both source code and prose, so its rank is roughly scaled down.
    const lower_by_frequency = "etaoinshrdlcumwfgypbvkjxqz";
    var score: u8 = 230;
    for (lower_by_frequency) |c| {
        rank[c] = score;
        rank[c - ('a' - 'A')] = score / 3;
        score -= 7;
    }

    var digit: u8 = '0';
    while (digit <= '9') : (digit += 1) rank[digit] = 70;

    for ("_./-") |c| rank[c] = 160;
    for (",;:'\"()[]{}") |c| rank[c] = 90;
    for ("*#@$%^&!~`|\\<>?+=") |c| rank[c] = 25;

    return rank;
}

test "more frequent bytes have higher rank" {
    const rank = default_rank;
    try std.testing.expect(rank['z'] < rank['e']);
    try std.testing.expect(rank['E'] < rank['e']);
    try std.testing.expect(rank[0] < rank['e']);
    try std.testing.expect(rank['q'] < rank[' ']);
    try std.testing.expect(rank['*'] < rank['_']);
}
