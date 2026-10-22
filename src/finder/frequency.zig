//! 默认字节频率秩。值越小越稀有，packed pair 会优先拿它做锚点。
//!
//! 这是按英文散文和源码的常见程度手写的秩，不是从别的项目抄来的表。
//! 调用方可以换成自己的 `[256]u8`。

const std = @import("std");

pub const default_rank: [256]u8 = defaultRank();

fn defaultRank() [256]u8 {
    var rank: [256]u8 = @splat(12);

    // 控制字节和 NUL 极少出现在文本里。
    for (0..32) |i| rank[i] = 1;
    rank['\t'] = 80;
    rank['\n'] = 140;
    rank['\r'] = 40;
    rank[' '] = 255;

    // 小写按英文频率从高到低。大写在源码和散文里都更少，秩大约减半。
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

test "越常见的字节秩越高" {
    const rank = default_rank;
    try std.testing.expect(rank['z'] < rank['e']);
    try std.testing.expect(rank['E'] < rank['e']);
    try std.testing.expect(rank[0] < rank['e']);
    try std.testing.expect(rank['q'] < rank[' ']);
    try std.testing.expect(rank['*'] < rank['_']);
}
