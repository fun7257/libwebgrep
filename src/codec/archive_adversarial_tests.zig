//! Adversarial test suite for `src/codec/archive.zig` covering Zip-Slip / Tar-Slip path traversal,
//! symlink injection, compression bombs, integer overflows, CRC-32 mismatches, and truncated structures.

const std = @import("std");
const archive_mod = @import("archive.zig");
const ArchiveTree = archive_mod.ArchiveTree;
const source_mod = @import("../source.zig");
const decompress_mod = @import("decompress.zig");

test "adversarial: tar path traversal ../../etc/passwd rejected" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "../../etc/passwd", .data = "root:x:0:0" },
    });
    defer std.testing.allocator.free(tar);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, tar, .{}));
}

test "adversarial: tar path traversal a/../../secret.txt rejected" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "a/../../secret.txt", .data = "secret" },
    });
    defer std.testing.allocator.free(tar);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, tar, .{}));
}

test "adversarial: tar path traversal C:\\evil rejected" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "C:\\evil", .data = "evil" },
    });
    defer std.testing.allocator.free(tar);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, tar, .{}));
}

test "adversarial: tar path traversal ..\\evil rejected" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "..\\evil", .data = "evil" },
    });
    defer std.testing.allocator.free(tar);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, tar, .{}));
}

test "adversarial: zip path traversal ../../etc/passwd rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "../../etc/passwd", .data = "root:x:0:0" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: zip path traversal a/../../secret.txt rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "a/../../secret.txt", .data = "secret" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: zip path traversal C:\\evil rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "C:\\evil", .data = "evil" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: zip path traversal ..\\evil rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "..\\evil", .data = "evil" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: zip null byte injection foo\\x00bar rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "foo\x00bar.txt", .data = "evil" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: tar symlink typeflag '2' is skipped and not followed" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "link_to_etc", .kind = .symlink, .link_target = "/etc/shadow" },
        .{ .path = "normal.txt", .data = "ok\n" },
    });
    defer std.testing.allocator.free(tar);

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, tar, .{});
    defer tree.deinit();

    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "link_to_etc") == null);
    const normal = source_mod.Memory.lookup(tree.rootNode(), "normal.txt");
    try std.testing.expect(normal != null);
    try std.testing.expectEqualStrings("ok\n", normal.?.bytes);
}

test "adversarial: zip symlink with POSIX S_IFLNK is skipped" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "sym.txt", .kind = .symlink, .link_target = "../../etc/passwd" },
        .{ .path = "legit.txt", .data = "legit\n" },
    });
    defer std.testing.allocator.free(zip);

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, zip, .{});
    defer tree.deinit();

    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "sym.txt") == null);
    const legit = source_mod.Memory.lookup(tree.rootNode(), "legit.txt");
    try std.testing.expect(legit != null);
    try std.testing.expectEqualStrings("legit\n", legit.?.bytes);
}

test "adversarial: zip bomb exceeding compression ratio > 100x is rejected" {
    // Raw deflate stream of 1032 'A' bytes (only 10 bytes compressed -> >100x ratio)
    const raw_deflate_bomb = [_]u8{
        0x73, 0x74, 0xa4, 0x3d, 0x00, 0x00,
    };
    const uncomp_len: u32 = 1032;
    const expected_crc: u32 = 0x72ef8d00;
    const name = "bomb.txt";

    var zip = std.ArrayList(u8).empty;
    defer zip.deinit(std.testing.allocator);

    var lfh: [30]u8 = @splat(0);
    std.mem.writeInt(u32, lfh[0..4], 0x04034b50, .little);
    std.mem.writeInt(u16, lfh[8..10], 8, .little); // deflate
    std.mem.writeInt(u32, lfh[14..18], expected_crc, .little);
    std.mem.writeInt(u32, lfh[18..22], raw_deflate_bomb.len, .little);
    std.mem.writeInt(u32, lfh[22..26], uncomp_len, .little);
    std.mem.writeInt(u16, lfh[26..28], name.len, .little);
    try zip.appendSlice(std.testing.allocator, &lfh);
    try zip.appendSlice(std.testing.allocator, name);
    try zip.appendSlice(std.testing.allocator, &raw_deflate_bomb);

    const cd_offset: u32 = @intCast(zip.items.len);
    var cdh: [46]u8 = @splat(0);
    std.mem.writeInt(u32, cdh[0..4], 0x02014b50, .little);
    std.mem.writeInt(u16, cdh[10..12], 8, .little);
    std.mem.writeInt(u32, cdh[16..20], expected_crc, .little);
    std.mem.writeInt(u32, cdh[20..24], raw_deflate_bomb.len, .little);
    std.mem.writeInt(u32, cdh[24..28], uncomp_len, .little);
    std.mem.writeInt(u16, cdh[28..30], name.len, .little);
    std.mem.writeInt(u32, cdh[38..42], @as(u32, 0o100644) << 16, .little);
    try zip.appendSlice(std.testing.allocator, &cdh);
    try zip.appendSlice(std.testing.allocator, name);
    const cd_size: u32 = @intCast(zip.items.len - cd_offset);

    var eocd: [22]u8 = @splat(0);
    std.mem.writeInt(u32, eocd[0..4], 0x06054b50, .little);
    std.mem.writeInt(u16, eocd[8..10], 1, .little);
    std.mem.writeInt(u16, eocd[10..12], 1, .little);
    std.mem.writeInt(u32, eocd[12..16], cd_size, .little);
    std.mem.writeInt(u32, eocd[16..20], cd_offset, .little);
    try zip.appendSlice(std.testing.allocator, &eocd);

    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, zip.items, .{ .max_compression_ratio = 100 }),
    );
}

test "adversarial: zip enforces max_entries cap" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "a.txt", .data = "1" },
        .{ .path = "b.txt", .data = "2" },
        .{ .path = "c.txt", .data = "3" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, zip, .{ .max_entries = 2 }),
    );
}

test "adversarial: zip enforces max_entry_bytes cap" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "large.txt", .data = "0123456789ABCDEF", .zip_method = .deflate },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, zip, .{ .max_entry_bytes = 10 }),
    );
}

test "adversarial: zip enforces max_total_bytes cap" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "1.txt", .data = "0123456789" },
        .{ .path = "2.txt", .data = "0123456789" },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, zip, .{ .max_total_bytes = 15 }),
    );
}

test "adversarial: zip corrupted CRC-32 is rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "crc.txt", .data = "hello world" },
    });
    defer std.testing.allocator.free(zip);

    // Flip a payload byte so CRC-32 mismatches
    zip[30 + "crc.txt".len] ^= 0xFF;
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: zip corrupted deflate stream is rejected" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "bad_deflate.txt", .data = "hello deflate stream", .zip_method = .deflate },
    });
    defer std.testing.allocator.free(zip);

    // Corrupt deflate block header
    zip[30 + "bad_deflate.txt".len + 1] ^= 0xFF;
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: zip bad or missing EOCD signature is rejected" {
    var bad_zip: [34]u8 = @splat(0);
    @memcpy(bad_zip[0..4], "PK\x03\x04");
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, &bad_zip, .{}));
}

test "adversarial: corrupted tar header checksum is rejected" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "valid.txt", .data = "hello" },
    });
    defer std.testing.allocator.free(tar);

    // Corrupt a byte in the filename after checksum calculation
    tar[0] = 'X';
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, tar, .{}));
}

test "adversarial: truncated tar block is rejected" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "trunc.txt", .data = "hello world" },
    });
    defer std.testing.allocator.free(tar);

    // Truncate mid-header (200 bytes) and mid-data block (520 bytes)
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, tar[0..200], .{ .format = .tar }));
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, tar[0..520], .{}));
}

test "adversarial: non-archive garbage bytes rejected" {
    const garbage = "This is definitely not a valid tar, gzip, zstd, xz, or zip archive!";
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, garbage, .{ .format = .auto }));
}

test "adversarial: crafted zip with cd_offset integer overflow" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "a.txt", .data = "a" },
    });
    defer std.testing.allocator.free(zip);

    const eocd_pos = zip.len - 22;
    std.mem.writeInt(u32, zip[eocd_pos + 16 ..][0..4], 0xFFFF_FFF0, .little);
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: crafted zip with local_offset integer overflow" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "a.txt", .data = "a" },
    });
    defer std.testing.allocator.free(zip);

    const eocd_pos = zip.len - 22;
    const cd_offset = std.mem.readInt(u32, zip[eocd_pos + 16 ..][0..4], .little);
    std.mem.writeInt(u32, zip[cd_offset + 42 ..][0..4], 0xFFFF_FFF0, .little);
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: tar directories exceeding max_entries cap" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "d1", .kind = .directory },
        .{ .path = "d2", .kind = .directory },
        .{ .path = "d3", .kind = .directory },
    });
    defer std.testing.allocator.free(tar);
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, tar, .{ .max_entries = 2 }),
    );
}

test "adversarial: zip directories exceeding max_entries cap" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "d1/", .kind = .directory },
        .{ .path = "d2/", .kind = .directory },
        .{ .path = "d3/", .kind = .directory },
    });
    defer std.testing.allocator.free(zip);
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, zip, .{ .max_entries = 2 }),
    );
}

test "adversarial: tar total uncompressed bytes exceeding max_total_bytes" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "f1.txt", .data = "0123456789" },
        .{ .path = "f2.txt", .data = "0123456789" },
    });
    defer std.testing.allocator.free(tar);
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, tar, .{ .max_total_bytes = 15 }),
    );
}

test "adversarial: path traversal variations with backslashes, mixed slashes, null bytes" {
    try std.testing.expectError(error.PathTraversal, archive_mod.sanitizeArchivePath("a\\b.txt"));
    try std.testing.expectError(error.PathTraversal, archive_mod.sanitizeArchivePath("a/..\\b.txt"));
    try std.testing.expectError(error.PathTraversal, archive_mod.sanitizeArchivePath("a/b\x00.txt"));
    try std.testing.expectError(error.PathTraversal, archive_mod.sanitizeArchivePath("D:/secret.txt"));
}

test "adversarial: zip central directory truncated midway through record" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "file1.txt", .data = "hello" },
    });
    defer std.testing.allocator.free(zip);

    const eocd_pos = zip.len - 22;
    // Shrink cd_size in EOCD so the CD record is truncated mid-header
    std.mem.writeInt(u32, zip[eocd_pos + 12 ..][0..4], 20, .little);
    try std.testing.expectError(error.CorruptArchive, ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}));
}

test "adversarial: tar.gz compression bomb exceeding max_compression_ratio is rejected" {
    const bomb_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x73, 0x74, 0xa4, 0x3d, 0x00, 0x00, 0x8d, 0xef, 0x72, 0x2f,
        0x08, 0x04, 0x00, 0x00,
    };
    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, &bomb_gz, .{ .max_compression_ratio = 3 }),
    );
}

test "adversarial: searchArchiveSlice rejects malicious archive without leaking" {
    const tree_mod = @import("../search/tree.zig");
    const finder_mod = @import("../finder/finder.zig");

    const bad_tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "ok.txt", .data = "allocated before error" },
        .{ .path = "../../evil.txt", .data = "traversal" },
    });
    defer std.testing.allocator.free(bad_tar);

    const finder = try finder_mod.Finder.init("allocated", .{});
    var void_sink: void = {};
    try std.testing.expectError(
        error.PathTraversal,
        tree_mod.searchArchiveSlice(void, std.testing.allocator, std.testing.io, &void_sink, bad_tar, &finder, .{}),
    );
}

test "adversarial: searchArchive initFromReader enforces max_total_bytes on stream" {
    const tree_mod = @import("../search/tree.zig");
    const finder_mod = @import("../finder/finder.zig");

    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "a.txt", .data = "hello world" },
    });
    defer std.testing.allocator.free(tar);

    const finder = try finder_mod.Finder.init("hello", .{});
    var void_sink: void = {};
    var reader = std.Io.Reader.fixed(tar);
    try std.testing.expectError(
        error.ArchiveLimit,
        tree_mod.searchArchive(void, std.testing.allocator, std.testing.io, &void_sink, &reader, &finder, .{
            .archive = .{ .max_total_bytes = 100 },
        }),
    );
}
