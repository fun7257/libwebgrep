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

test "entry_filter: tar filters by extension, size, and mtime before limits and propagates Node.mtime" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "src", .kind = .directory, .mtime = 1_700_000_000 },
        .{ .path = "src/keep.zig", .data = "pub const k = 1;\n", .mtime = 1_700_000_500 },
        .{ .path = "src/stale.zig", .data = "pub const s = 2;\n", .mtime = 1_600_000_000 },
        .{ .path = "assets/huge.bin", .data = &(@as([128]u8, @splat('X'))), .mtime = 1_700_000_900 },
    });
    defer std.testing.allocator.free(tar);

    const FilterCtx = struct {
        min_mtime: i64,
        max_size: u64,
        seen: usize = 0,
        accepted: usize = 0,

        fn filter(raw_ctx: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
            const self: *@This() = @ptrCast(@alignCast(raw_ctx.?));
            self.seen += 1;
            if (meta.kind == .directory) {
                self.accepted += 1;
                return true;
            }
            if (!std.mem.endsWith(u8, meta.path, ".zig")) return false;
            if (meta.size > self.max_size) return false;
            const mt = meta.mtime orelse return false;
            if (mt < self.min_mtime) return false;
            self.accepted += 1;
            return true;
        }
    };

    var ctx = FilterCtx{ .min_mtime = 1_700_000_100, .max_size = 64 };
    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, tar, .{
        .max_entries = 2,
        .max_entry_bytes = 64,
        .max_total_bytes = 64,
        .entry_filter = FilterCtx.filter,
        .entry_filter_ctx = &ctx,
    });
    defer tree.deinit();

    try std.testing.expectEqual(@as(usize, 4), ctx.seen);
    try std.testing.expectEqual(@as(usize, 2), ctx.accepted);

    const src_dir = source_mod.Memory.lookup(tree.rootNode(), "src");
    try std.testing.expect(src_dir != null);
    try std.testing.expectEqual(@as(?i64, 1_700_000_000), src_dir.?.mtime);

    const kept = source_mod.Memory.lookup(tree.rootNode(), "src/keep.zig");
    try std.testing.expect(kept != null);
    try std.testing.expectEqualStrings("pub const k = 1;\n", kept.?.bytes);
    try std.testing.expectEqual(@as(?i64, 1_700_000_500), kept.?.mtime);

    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "src/stale.zig") == null);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "assets/huge.bin") == null);
}

test "entry_filter: tar.gz filters by extension, size, and mtime before per-entry caps" {
    const tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "docs/guide.md", .data = "# Guide\nsearchable line\n", .mtime = 1_720_000_000 },
        .{ .path = "docs/old.md", .data = "# Old\n", .mtime = 1_500_000_000 },
        .{ .path = "logs/giant.log", .data = &(@as([96]u8, @splat('L'))), .mtime = 1_720_000_100 },
    });
    defer std.testing.allocator.free(tar);

    const tgz = try decompress_mod.compressGzipStoredAlloc(std.testing.allocator, tar);
    defer std.testing.allocator.free(tgz);

    const Filter = struct {
        fn keepRecentMd(_: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
            if (meta.kind == .directory) return true;
            if (!std.mem.endsWith(u8, meta.path, ".md")) return false;
            const mt = meta.mtime orelse return false;
            return mt >= 1_700_000_000 and meta.size <= 48;
        }
    };

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, tgz, .{
        .format = .auto,
        .max_entries = 1,
        .max_entry_bytes = 48,
        .entry_filter = Filter.keepRecentMd,
    });
    defer tree.deinit();

    const guide = source_mod.Memory.lookup(tree.rootNode(), "docs/guide.md");
    try std.testing.expect(guide != null);
    try std.testing.expectEqualStrings("# Guide\nsearchable line\n", guide.?.bytes);
    try std.testing.expectEqual(@as(?i64, 1_720_000_000), guide.?.mtime);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "docs/old.md") == null);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "logs/giant.log") == null);
}

test "entry_filter: zip skips corrupt deflate payload and oversized entries strictly before decompression" {
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{
            .path = "bad/corrupt.bin",
            .data = "this deflate stream will be corrupted in place",
            .zip_method = .deflate,
            .mtime = 1_718_461_330,
        },
        .{
            .path = "big/oversized.bin",
            .data = &(@as([200]u8, @splat('B'))),
            .zip_method = .deflate,
            .mtime = 1_718_461_330,
        },
        .{
            .path = "src/target.zig",
            .data = "pub const answer = 42;\n",
            .zip_method = .deflate,
            .mtime = 1_718_461_331,
        },
    });
    defer std.testing.allocator.free(zip);

    // Corrupt the compressed Deflate stream of the first entry ("bad/corrupt.bin" starts at offset 0).
    const first_data_start = 30 + "bad/corrupt.bin".len;
    zip[first_data_start] = 0xFF;
    zip[first_data_start + 1] ^= 0xAA;

    // Without entry_filter, unpacking must fail on the corrupt deflate stream.
    try std.testing.expectError(
        error.CorruptArchive,
        ArchiveTree.initFromSlice(std.testing.allocator, zip, .{}),
    );

    const ZigOnlyFilter = struct {
        seen_corrupt_comp_size: u64 = 0,

        fn allow(raw_ctx: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
            const self: *@This() = @ptrCast(@alignCast(raw_ctx.?));
            if (std.mem.eql(u8, meta.path, "bad/corrupt.bin")) {
                self.seen_corrupt_comp_size = meta.compressed_size;
            }
            if (meta.kind == .directory) return true;
            return std.mem.endsWith(u8, meta.path, ".zig");
        }
    };

    var fctx = ZigOnlyFilter{};
    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, zip, .{
        .max_entries = 1,
        .max_entry_bytes = 32,
        .max_total_bytes = 32,
        .entry_filter = ZigOnlyFilter.allow,
        .entry_filter_ctx = &fctx,
    });
    defer tree.deinit();

    try std.testing.expect(fctx.seen_corrupt_comp_size > 0);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "bad/corrupt.bin") == null);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "big/oversized.bin") == null);

    const target = source_mod.Memory.lookup(tree.rootNode(), "src/target.zig");
    try std.testing.expect(target != null);
    try std.testing.expectEqualStrings("pub const answer = 42;\n", target.?.bytes);
    try std.testing.expectEqual(@as(?i64, 1_718_461_331), target.?.mtime);
}

test "entry_filter: zip MS-DOS dosDateTimeToUnix and 0x5455 Extended Timestamp mtime parsing" {
    // 1980-01-01 00:00:00 UTC -> 315532800
    const dos_epoch = archive_mod.unixToDosDateTime(315_532_800);
    try std.testing.expectEqual(@as(i64, 315_532_800), archive_mod.dosDateTimeToUnix(dos_epoch.mod_time, dos_epoch.mod_date));

    // Leap day 2000-02-29 12:30:44 UTC -> 951827444
    const dos_leap = archive_mod.unixToDosDateTime(951_827_444);
    try std.testing.expectEqual(@as(i64, 951_827_444), archive_mod.dosDateTimeToUnix(dos_leap.mod_time, dos_leap.mod_date));

    // 2024-06-15 14:22:10 UTC -> 1718461330
    const dos_2024 = archive_mod.unixToDosDateTime(1_718_461_330);
    try std.testing.expectEqual(@as(i64, 1_718_461_330), archive_mod.dosDateTimeToUnix(dos_2024.mod_time, dos_2024.mod_date));

    // Pure MS-DOS timestamp entries (no 0x5455 extra field) + Extended Timestamp odd-second entry
    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{
            .path = "dos_2020.txt",
            .data = "2020",
            .mtime = 1_577_836_800,
            .zip_extended_timestamp = false,
        },
        .{
            .path = "dos_2024.txt",
            .data = "2024",
            .mtime = 1_718_461_330,
            .zip_extended_timestamp = false,
        },
        .{
            .path = "ext_odd_sec.txt",
            .data = "odd",
            .mtime = 1_718_461_331,
            .zip_extended_timestamp = true,
        },
        .{
            .path = "unset_mtime.txt",
            .data = "none",
            .mtime = null,
        },
    });
    defer std.testing.allocator.free(zip);

    const MtimeFilter = struct {
        saw_null_mtime: bool = false,

        fn after2023(raw_ctx: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
            const self: *@This() = @ptrCast(@alignCast(raw_ctx.?));
            const mt = meta.mtime orelse {
                self.saw_null_mtime = true;
                return false;
            };
            return mt >= 1_700_000_000;
        }
    };

    var mctx = MtimeFilter{};
    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, zip, .{
        .entry_filter = MtimeFilter.after2023,
        .entry_filter_ctx = &mctx,
    });
    defer tree.deinit();

    try std.testing.expect(mctx.saw_null_mtime);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "dos_2020.txt") == null);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "unset_mtime.txt") == null);

    const n_dos = source_mod.Memory.lookup(tree.rootNode(), "dos_2024.txt");
    try std.testing.expect(n_dos != null);
    try std.testing.expectEqual(@as(?i64, 1_718_461_330), n_dos.?.mtime);

    const n_ext = source_mod.Memory.lookup(tree.rootNode(), "ext_odd_sec.txt");
    try std.testing.expect(n_ext != null);
    try std.testing.expectEqual(@as(?i64, 1_718_461_331), n_ext.?.mtime);
}

test "entry_filter: path traversal is still rejected even when entry_filter rejects all entries" {
    const RejectAll = struct {
        fn none(_: ?*anyopaque, _: archive_mod.ArchiveEntryMeta) bool {
            return false;
        }
    };

    const bad_tar = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "../../etc/passwd", .data = "evil" },
    });
    defer std.testing.allocator.free(bad_tar);
    try std.testing.expectError(
        error.PathTraversal,
        ArchiveTree.initFromSlice(std.testing.allocator, bad_tar, .{ .entry_filter = RejectAll.none }),
    );

    const bad_zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "sub/../../evil.txt", .data = "evil" },
    });
    defer std.testing.allocator.free(bad_zip);
    try std.testing.expectError(
        error.PathTraversal,
        ArchiveTree.initFromSlice(std.testing.allocator, bad_zip, .{ .entry_filter = RejectAll.none }),
    );
}

test "entry_filter: searchArchiveSlice respects TreeConfig.archive.entry_filter" {
    const tree_mod = @import("../search/tree.zig");
    const finder_mod = @import("../finder/finder.zig");

    const zip = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "skip.bin", .data = "needle in corrupt entry\n", .zip_method = .deflate },
        .{ .path = "keep.txt", .data = "needle in valid entry\n", .zip_method = .deflate },
    });
    defer std.testing.allocator.free(zip);

    // Corrupt skip.bin's deflate payload to prove searchArchiveSlice never decompresses it.
    zip[30 + "skip.bin".len] = 0xFF;

    const Filter = struct {
        fn onlyTxt(_: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
            if (meta.kind == .directory) return true;
            return std.mem.endsWith(u8, meta.path, ".txt");
        }
    };

    const finder = try finder_mod.Finder.init("needle", .{});
    var void_sink: void = {};
    const summary = try tree_mod.searchArchiveSlice(
        void,
        std.testing.allocator,
        std.testing.io,
        &void_sink,
        zip,
        &finder,
        .{ .archive = .{ .entry_filter = Filter.onlyTxt } },
    );
    try std.testing.expectEqual(@as(u64, 1), summary.searches);
    try std.testing.expectEqual(@as(u64, 1), summary.matches);
}

