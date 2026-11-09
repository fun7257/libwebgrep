//! [Module] codec/archive.zig
//! [Layer] Layer 3 — Zero-Disk-Landing In-Memory Archive Unpacker
//! [Role] Unpacks `.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, and `.zip` archives purely in memory
//!        into a virtual `source.Node` / `source.Memory` hierarchy with strict bomb, entry, and path-traversal guards.

const std = @import("std");
pub const source_mod = @import("../source.zig");
pub const decompress_mod = @import("decompress.zig");

pub const ArchiveFormat = enum {
    auto,
    tar,
    tar_gz,
    tar_zst,
    tar_xz,
    zip,
};

pub const ArchiveOptions = struct {
    format: ArchiveFormat = .auto,
    max_entries: usize = 10_000,
    max_entry_bytes: u64 = 64 * 1024 * 1024,
    max_total_bytes: u64 = 256 * 1024 * 1024,
    max_compression_ratio: u64 = 100,
};

pub const ArchiveError = error{
    UnsupportedFormat,
    CorruptArchive,
    ArchiveLimit,
    PathTraversal,
    OutOfMemory,
};

const TempNode = struct {
    name: []const u8,
    kind: source_mod.Kind,
    bytes: []const u8 = &.{},
    children: std.ArrayList(*TempNode) = .empty,
};

pub const ArchiveTree = struct {
    arena: std.heap.ArenaAllocator,
    root_node: *const source_mod.Node,
    memory: source_mod.Memory,

    pub fn initFromSlice(
        allocator: std.mem.Allocator,
        archive_bytes: []const u8,
        options: ArchiveOptions,
    ) ArchiveError!ArchiveTree {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        const root_temp = try arena_alloc.create(TempNode);
        root_temp.* = .{
            .name = "",
            .kind = .directory,
        };

        if (archive_bytes.len > 0) {
            const fmt = try detectFormat(archive_bytes, options.format);
            switch (fmt) {
                .tar => try unpackTar(arena_alloc, archive_bytes, root_temp, options),
                .tar_gz, .tar_zst, .tar_xz => {
                    var dec_bytes: u64 = 0;
                    var offset_map = decompress_mod.OffsetMap{};
                    defer offset_map.deinit(arena_alloc);

                    const comp_mode: decompress_mod.Compression = switch (fmt) {
                        .tar_gz => .gzip,
                        .tar_zst => .zstd,
                        .tar_xz => .xz,
                        else => unreachable,
                    };

                    const decompressed = decompress_mod.decompressSlice(
                        arena_alloc,
                        archive_bytes,
                        comp_mode,
                        0,
                        options.max_total_bytes,
                        options.max_compression_ratio,
                        &dec_bytes,
                        &offset_map,
                    ) catch |err| switch (err) {
                        error.DecompressLimit => return error.ArchiveLimit,
                        error.CorruptStream => return error.CorruptArchive,
                        error.OutOfMemory => return error.OutOfMemory,
                    };

                    const tar_slice = decompressed orelse return error.CorruptArchive;
                    try unpackTar(arena_alloc, tar_slice, root_temp, options);
                },
                .zip => try unpackZip(arena_alloc, archive_bytes, root_temp, options),
                .auto => unreachable,
            }
        } else if (options.format == .zip) {
            return error.CorruptArchive;
        }

        const frozen_root = try freezeTree(arena_alloc, root_temp);
        return .{
            .arena = arena,
            .root_node = frozen_root,
            .memory = .{ .root = frozen_root },
        };
    }

    pub fn initFromReader(
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        options: ArchiveOptions,
    ) ArchiveError!ArchiveTree {
        var raw_buf = std.ArrayList(u8).empty;
        defer raw_buf.deinit(allocator);

        var chunk: [16384]u8 = undefined;
        var total_read: u64 = 0;
        while (true) {
            const n = reader.readSliceShort(&chunk) catch return error.CorruptArchive;
            if (n == 0) break;
            total_read = std.math.add(u64, total_read, n) catch return error.ArchiveLimit;
            if (total_read > options.max_total_bytes) return error.ArchiveLimit;
            try raw_buf.appendSlice(allocator, chunk[0..n]);
        }

        return initFromSlice(allocator, raw_buf.items, options);
    }

    pub fn deinit(self: *ArchiveTree) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn source(self: *ArchiveTree) source_mod.Source {
        return self.memory.source();
    }

    pub fn rootNode(self: *const ArchiveTree) *const source_mod.Node {
        return self.root_node;
    }
};

pub fn detectFormat(bytes: []const u8, requested: ArchiveFormat) ArchiveError!ArchiveFormat {
    if (requested != .auto) return requested;
    if (bytes.len == 0) return .tar;

    if (bytes.len >= 4) {
        if (std.mem.eql(u8, bytes[0..4], "PK\x03\x04") or
            std.mem.eql(u8, bytes[0..4], "PK\x05\x06") or
            std.mem.eql(u8, bytes[0..4], "PK\x07\x08"))
        {
            return .zip;
        }
    }
    if (bytes.len >= 2 and bytes[0] == 0x1F and bytes[1] == 0x8B) {
        return .tar_gz;
    }
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &.{ 0x28, 0xB5, 0x2F, 0xFD })) {
        return .tar_zst;
    }
    if (bytes.len >= 6 and std.mem.eql(u8, bytes[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) {
        return .tar_xz;
    }
    if (looksLikeTar(bytes)) {
        return .tar;
    }
    return error.CorruptArchive;
}

fn looksLikeTar(bytes: []const u8) bool {
    if (bytes.len < 512) return false;
    const block = bytes[0..512];
    if (std.mem.allEqual(u8, block, 0)) return true;
    if (std.mem.eql(u8, block[257..262], "ustar")) return true;
    return hasValidTarChecksum(block);
}

fn hasValidTarChecksum(block: *const [512]u8) bool {
    const raw_chk = block[148..156];
    const ltrimmed = std.mem.trimStart(u8, raw_chk, "0 ");
    const rtrimmed = std.mem.trimEnd(u8, ltrimmed, " \x00");
    if (rtrimmed.len == 0) return false;
    const expected = std.fmt.parseInt(u64, rtrimmed, 8) catch return false;

    var unsigned_sum: u64 = 0;
    var signed_sum: i64 = 0;
    for (block, 0..) |b, i| {
        const v: u8 = if (i >= 148 and i < 156) ' ' else b;
        unsigned_sum += v;
        signed_sum += @as(i8, @bitCast(v));
    }
    return expected == unsigned_sum or expected == @as(u64, @bitCast(signed_sum));
}

pub fn sanitizeArchivePath(raw_path: []const u8) ArchiveError!?[]const u8 {
    if (std.mem.indexOfScalar(u8, raw_path, 0) != null) return error.PathTraversal;
    if (std.mem.indexOfScalar(u8, raw_path, '\\') != null) return error.PathTraversal;
    if (raw_path.len >= 2 and std.ascii.isAlphabetic(raw_path[0]) and raw_path[1] == ':') {
        return error.PathTraversal;
    }

    var it = std.mem.splitScalar(u8, raw_path, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return error.PathTraversal;
        if (part.len >= 2 and std.ascii.isAlphabetic(part[0]) and part[1] == ':') {
            return error.PathTraversal;
        }
    }

    var p = raw_path;
    while (p.len > 0) {
        if (p[0] == '/') {
            p = p[1..];
        } else if (std.mem.startsWith(u8, p, "./")) {
            p = p[2..];
        } else if (std.mem.eql(u8, p, ".")) {
            p = "";
        } else {
            break;
        }
    }
    p = std.mem.trimEnd(u8, p, "/");
    if (p.len == 0 or std.mem.eql(u8, p, ".")) return null;
    return p;
}

fn ensureDirPath(
    arena_alloc: std.mem.Allocator,
    root: *TempNode,
    dir_path: []const u8,
) ArchiveError!*TempNode {
    var curr = root;
    var it = std.mem.splitScalar(u8, dir_path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) return error.PathTraversal;
        var found: ?*TempNode = null;
        for (curr.children.items) |child| {
            if (std.mem.eql(u8, child.name, seg)) {
                found = child;
                break;
            }
        }
        if (found) |existing| {
            if (existing.kind != .directory) return error.CorruptArchive;
            curr = existing;
        } else {
            const new_dir = try arena_alloc.create(TempNode);
            new_dir.* = .{
                .name = try arena_alloc.dupe(u8, seg),
                .kind = .directory,
            };
            try curr.children.append(arena_alloc, new_dir);
            curr = new_dir;
        }
    }
    return curr;
}

fn insertFile(
    arena_alloc: std.mem.Allocator,
    root: *TempNode,
    clean_path: []const u8,
    payload: []const u8,
) ArchiveError!void {
    const parent, const base = if (std.mem.lastIndexOfScalar(u8, clean_path, '/')) |slash| blk: {
        const dir = try ensureDirPath(arena_alloc, root, clean_path[0..slash]);
        break :blk .{ dir, clean_path[slash + 1 ..] };
    } else .{ root, clean_path };

    if (base.len == 0 or std.mem.eql(u8, base, ".")) return;
    if (std.mem.eql(u8, base, "..")) return error.PathTraversal;

    for (parent.children.items) |child| {
        if (std.mem.eql(u8, child.name, base)) {
            if (child.kind != .file) return error.CorruptArchive;
            child.bytes = payload;
            return;
        }
    }

    const new_file = try arena_alloc.create(TempNode);
    new_file.* = .{
        .name = try arena_alloc.dupe(u8, base),
        .kind = .file,
        .bytes = payload,
    };
    try parent.children.append(arena_alloc, new_file);
}

fn freezeTree(
    arena_alloc: std.mem.Allocator,
    temp: *const TempNode,
) ArchiveError!*const source_mod.Node {
    const node = try arena_alloc.create(source_mod.Node);
    if (temp.kind == .directory) {
        const children = try arena_alloc.alloc(*const source_mod.Node, temp.children.items.len);
        for (temp.children.items, 0..) |child, i| {
            children[i] = try freezeTree(arena_alloc, child);
        }
        node.* = .{
            .name = temp.name,
            .kind = .directory,
            .bytes = &.{},
            .children = children,
        };
    } else {
        node.* = .{
            .name = temp.name,
            .kind = temp.kind,
            .bytes = temp.bytes,
            .children = &.{},
        };
    }
    return node;
}

fn unpackTar(
    arena_alloc: std.mem.Allocator,
    tar_bytes: []const u8,
    root: *TempNode,
    options: ArchiveOptions,
) ArchiveError!void {
    if (tar_bytes.len == 0) return;
    if (tar_bytes.len < 512) return error.CorruptArchive;

    // Pre-scan raw 512-byte header blocks for null-byte injection inside the nominal filename
    // or invalid checksums before handing off to std.tar.Iterator.
    var reader = std.Io.Reader.fixed(tar_bytes);
    const file_name_buf = try arena_alloc.alloc(u8, 4096);
    const link_name_buf = try arena_alloc.alloc(u8, 4096);
    var diag = std.tar.Diagnostics{ .allocator = arena_alloc };

    var it = std.tar.Iterator.init(&reader, .{
        .file_name_buffer = file_name_buf,
        .link_name_buffer = link_name_buf,
        .diagnostics = &diag,
    });

    var entry_count: usize = 0;
    var total_uncompressed: u64 = 0;

    while (true) {
        const maybe_file = it.next() catch |err| switch (err) {
            error.PaxNullInValue, error.PaxNullInKeyword => return error.PathTraversal,
            else => return error.CorruptArchive,
        };
        const file = maybe_file orelse break;

        // Skip symlinks so they are never followed or exposed in the virtual tree.
        if (file.kind == .sym_link) {
            continue;
        }

        const clean = (try sanitizeArchivePath(file.name)) orelse continue;

        entry_count += 1;
        if (entry_count > options.max_entries) return error.ArchiveLimit;

        if (file.size > options.max_entry_bytes) return error.ArchiveLimit;
        total_uncompressed = std.math.add(u64, total_uncompressed, file.size) catch return error.ArchiveLimit;
        if (total_uncompressed > options.max_total_bytes) return error.ArchiveLimit;

        switch (file.kind) {
            .directory => {
                _ = try ensureDirPath(arena_alloc, root, clean);
            },
            .file => {
                const payload = try arena_alloc.alloc(u8, @intCast(file.size));
                reader.readSliceAll(payload) catch return error.CorruptArchive;
                it.unread_file_bytes = 0;
                try insertFile(arena_alloc, root, clean, payload);
            },
            .sym_link => unreachable,
        }
    }
}

fn unpackZip(
    arena_alloc: std.mem.Allocator,
    zip_bytes: []const u8,
    root: *TempNode,
    options: ArchiveOptions,
) ArchiveError!void {
    if (zip_bytes.len < 22) return error.CorruptArchive;

    var eocd_pos: ?usize = null;
    const min_pos = zip_bytes.len -| (22 + 65535);
    var pos: usize = zip_bytes.len - 22;
    while (true) {
        if (std.mem.readInt(u32, zip_bytes[pos..][0..4], .little) == 0x06054b50) {
            const comment_len = std.mem.readInt(u16, zip_bytes[pos + 20 ..][0..2], .little);
            if (pos + 22 + comment_len <= zip_bytes.len) {
                eocd_pos = pos;
                break;
            }
        }
        if (pos == min_pos) break;
        pos -= 1;
    }
    const eocd = eocd_pos orelse return error.CorruptArchive;

    const total_entries = std.mem.readInt(u16, zip_bytes[eocd + 10 ..][0..2], .little);
    const cd_size = std.mem.readInt(u32, zip_bytes[eocd + 12 ..][0..4], .little);
    const cd_offset = std.mem.readInt(u32, zip_bytes[eocd + 16 ..][0..4], .little);

    const cd_end = std.math.add(usize, @as(usize, cd_offset), @as(usize, cd_size)) catch return error.CorruptArchive;
    if (cd_end > eocd or cd_end > zip_bytes.len) return error.CorruptArchive;

    var cd_pos: usize = @intCast(cd_offset);
    var entry_count: usize = 0;
    var total_uncompressed: u64 = 0;

    var idx: usize = 0;
    while (idx < total_entries) : (idx += 1) {
        const hdr_end = std.math.add(usize, cd_pos, 46) catch return error.CorruptArchive;
        if (hdr_end > cd_end) return error.CorruptArchive;

        const sig = std.mem.readInt(u32, zip_bytes[cd_pos..][0..4], .little);
        if (sig != 0x02014b50) return error.CorruptArchive;

        const flags = std.mem.readInt(u16, zip_bytes[cd_pos + 8 ..][0..2], .little);
        const method = std.mem.readInt(u16, zip_bytes[cd_pos + 10 ..][0..2], .little);
        const expected_crc32 = std.mem.readInt(u32, zip_bytes[cd_pos + 16 ..][0..4], .little);
        const comp_size = std.mem.readInt(u32, zip_bytes[cd_pos + 20 ..][0..4], .little);
        const uncomp_size = std.mem.readInt(u32, zip_bytes[cd_pos + 24 ..][0..4], .little);
        const name_len = std.mem.readInt(u16, zip_bytes[cd_pos + 28 ..][0..2], .little);
        const extra_len = std.mem.readInt(u16, zip_bytes[cd_pos + 30 ..][0..2], .little);
        const comment_len = std.mem.readInt(u16, zip_bytes[cd_pos + 32 ..][0..2], .little);
        const external_attr = std.mem.readInt(u32, zip_bytes[cd_pos + 38 ..][0..4], .little);
        const local_offset = std.mem.readInt(u32, zip_bytes[cd_pos + 42 ..][0..4], .little);

        const var_len = @as(usize, name_len) + @as(usize, extra_len) + @as(usize, comment_len);
        const rec_end = std.math.add(usize, hdr_end, var_len) catch return error.CorruptArchive;
        if (rec_end > cd_end) return error.CorruptArchive;

        const raw_name = zip_bytes[hdr_end .. hdr_end + name_len];
        cd_pos = rec_end;

        if ((flags & 1) != 0) return error.UnsupportedFormat;

        // Check POSIX S_IFLNK (0o120000) in upper 16 bits of external_attr; skip symlinks.
        const unix_mode = (external_attr >> 16) & 0o170000;
        if (unix_mode == 0o120000) {
            continue;
        }

        const is_dir = (raw_name.len > 0 and raw_name[raw_name.len - 1] == '/') or (unix_mode == 0o040000);
        const clean = (try sanitizeArchivePath(raw_name)) orelse continue;

        entry_count += 1;
        if (entry_count > options.max_entries) return error.ArchiveLimit;

        if (is_dir) {
            _ = try ensureDirPath(arena_alloc, root, clean);
            continue;
        }

        if (uncomp_size > options.max_entry_bytes) return error.ArchiveLimit;
        const projected_total = std.math.add(u64, total_uncompressed, uncomp_size) catch return error.ArchiveLimit;
        if (projected_total > options.max_total_bytes) return error.ArchiveLimit;

        if (uncomp_size >= decompress_mod.ratio_check_min_bytes) {
            const raw_base: u64 = @max(1, @as(u64, comp_size));
            const max_allowed = std.math.mul(u64, raw_base, options.max_compression_ratio) catch std.math.maxInt(u64);
            if (uncomp_size > max_allowed) return error.ArchiveLimit;
        }

        // Validate Local File Header (LFH)
        const lfh_off: usize = @intCast(local_offset);
        const lfh_end = std.math.add(usize, lfh_off, 30) catch return error.CorruptArchive;
        if (lfh_end > cd_offset or lfh_end > zip_bytes.len) return error.CorruptArchive;

        const lfh_sig = std.mem.readInt(u32, zip_bytes[lfh_off..][0..4], .little);
        if (lfh_sig != 0x04034b50) return error.CorruptArchive;

        const lfh_name_len = std.mem.readInt(u16, zip_bytes[lfh_off + 26 ..][0..2], .little);
        const lfh_extra_len = std.mem.readInt(u16, zip_bytes[lfh_off + 28 ..][0..2], .little);
        const data_start = std.math.add(usize, lfh_end, @as(usize, lfh_name_len) + @as(usize, lfh_extra_len)) catch return error.CorruptArchive;
        const data_end = std.math.add(usize, data_start, @as(usize, comp_size)) catch return error.CorruptArchive;
        if (data_end > cd_offset or data_end > zip_bytes.len) return error.CorruptArchive;

        const comp_slice = zip_bytes[data_start..data_end];

        const payload: []u8 = switch (method) {
            0 => blk: {
                if (comp_size != uncomp_size) return error.CorruptArchive;
                total_uncompressed = projected_total;
                const out = try arena_alloc.dupe(u8, comp_slice);
                break :blk out;
            },
            8 => blk: {
                var in_reader = std.Io.Reader.fixed(comp_slice);
                var dec_win: [std.compress.flate.max_window_len]u8 = undefined;
                var decompressor = std.compress.flate.Decompress.init(&in_reader, .raw, &dec_win);

                var out_list = std.ArrayList(u8).empty;
                var chunk: [16384]u8 = undefined;
                var entry_dec: u64 = 0;
                const raw_base: u64 = @max(1, @as(u64, comp_size));

                while (true) {
                    const n = decompressor.reader.readSliceShort(&chunk) catch return error.CorruptArchive;
                    if (n == 0) break;

                    entry_dec = std.math.add(u64, entry_dec, n) catch return error.ArchiveLimit;
                    if (entry_dec > options.max_entry_bytes) return error.ArchiveLimit;

                    total_uncompressed = std.math.add(u64, total_uncompressed, n) catch return error.ArchiveLimit;
                    if (total_uncompressed > options.max_total_bytes) return error.ArchiveLimit;

                    if (entry_dec >= decompress_mod.ratio_check_min_bytes) {
                        const max_allowed = std.math.mul(u64, raw_base, options.max_compression_ratio) catch std.math.maxInt(u64);
                        if (entry_dec > max_allowed) return error.ArchiveLimit;
                    }

                    try out_list.appendSlice(arena_alloc, chunk[0..n]);
                }

                if (entry_dec != uncomp_size) return error.CorruptArchive;
                break :blk try out_list.toOwnedSlice(arena_alloc);
            },
            else => return error.UnsupportedFormat,
        };

        const actual_crc32 = std.hash.Crc32.hash(payload);
        if (actual_crc32 != expected_crc32) return error.CorruptArchive;

        try insertFile(arena_alloc, root, clean, payload);
    }
}

pub const TestArchiveEntry = struct {
    path: []const u8,
    data: []const u8 = "",
    kind: enum { file, directory, symlink } = .file,
    link_target: []const u8 = "",
    zip_method: enum { store, deflate } = .store,
};

pub fn buildTestTarAlloc(allocator: std.mem.Allocator, entries: []const TestArchiveEntry) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);

    for (entries) |entry| {
        var hdr = std.tar.Writer.Header.init(switch (entry.kind) {
            .file => .regular,
            .directory => .directory,
            .symlink => .symbolic_link,
        });
        if (entry.path.len <= hdr.name.len) {
            @memcpy(hdr.name[0..entry.path.len], entry.path);
        } else {
            return error.NameTooLong;
        }
        const size: u64 = if (entry.kind == .file) entry.data.len else 0;
        try hdr.setSize(size);
        if (entry.kind == .symlink) {
            try hdr.setLinkname(entry.link_target);
        }
        try hdr.updateChecksum();
        try buf.appendSlice(allocator, std.mem.asBytes(&hdr));
        if (entry.kind == .file and entry.data.len > 0) {
            try buf.appendSlice(allocator, entry.data);
            const rem = entry.data.len % 512;
            if (rem != 0) {
                try buf.appendNTimes(allocator, 0, 512 - rem);
            }
        }
    }
    // Two 512-byte zero blocks at end of archive
    try buf.appendNTimes(allocator, 0, 1024);
    return buf.toOwnedSlice(allocator);
}

pub fn deflateRawStoredAlloc(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var pos: usize = 0;
    while (true) {
        const rem = payload.len - pos;
        const block_len: u16 = @intCast(@min(rem, 65535));
        const is_final: u8 = if (pos + block_len >= payload.len) 1 else 0;
        try out.append(allocator, is_final);
        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u16, len_bytes[0..2], block_len, .little);
        std.mem.writeInt(u16, len_bytes[2..4], ~block_len, .little);
        try out.appendSlice(allocator, &len_bytes);
        try out.appendSlice(allocator, payload[pos .. pos + block_len]);
        pos += block_len;
        if (is_final == 1) break;
    }
    return out.toOwnedSlice(allocator);
}

pub fn buildTestZipAlloc(allocator: std.mem.Allocator, entries: []const TestArchiveEntry) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const CdRec = struct {
        method: u16,
        crc32: u32,
        comp_size: u32,
        uncomp_size: u32,
        external_attr: u32,
        local_offset: u32,
        path: []const u8,
    };
    var cd_recs = std.ArrayList(CdRec).empty;
    defer cd_recs.deinit(allocator);

    for (entries) |entry| {
        const local_offset: u32 = @intCast(out.items.len);
        const raw_data = if (entry.kind == .file) entry.data else if (entry.kind == .symlink) entry.link_target else "";
        const crc = std.hash.Crc32.hash(raw_data);

        var comp_owned: ?[]u8 = null;
        defer if (comp_owned) |c| allocator.free(c);

        const method: u16, const comp_slice: []const u8 = if (entry.kind == .file and entry.zip_method == .deflate) blk: {
            comp_owned = try deflateRawStoredAlloc(allocator, raw_data);
            break :blk .{ 8, comp_owned.? };
        } else .{ 0, raw_data };

        // Local File Header (30 bytes)
        var lfh: [30]u8 = @splat(0);
        std.mem.writeInt(u32, lfh[0..4], 0x04034b50, .little);
        std.mem.writeInt(u16, lfh[4..6], 20, .little);
        std.mem.writeInt(u16, lfh[8..10], method, .little);
        std.mem.writeInt(u32, lfh[14..18], crc, .little);
        std.mem.writeInt(u32, lfh[18..22], @intCast(comp_slice.len), .little);
        std.mem.writeInt(u32, lfh[22..26], @intCast(raw_data.len), .little);
        std.mem.writeInt(u16, lfh[26..28], @intCast(entry.path.len), .little);
        try out.appendSlice(allocator, &lfh);
        try out.appendSlice(allocator, entry.path);
        try out.appendSlice(allocator, comp_slice);

        const ext_attr: u32 = switch (entry.kind) {
            .file => @as(u32, 0o100644) << 16,
            .directory => @as(u32, 0o040755) << 16,
            .symlink => @as(u32, 0o120777) << 16,
        };

        try cd_recs.append(allocator, .{
            .method = method,
            .crc32 = crc,
            .comp_size = @intCast(comp_slice.len),
            .uncomp_size = @intCast(raw_data.len),
            .external_attr = ext_attr,
            .local_offset = local_offset,
            .path = entry.path,
        });
    }

    const cd_offset: u32 = @intCast(out.items.len);
    for (cd_recs.items) |rec| {
        var cdh: [46]u8 = @splat(0);
        std.mem.writeInt(u32, cdh[0..4], 0x02014b50, .little);
        std.mem.writeInt(u16, cdh[4..6], 0x0314, .little); // UNIX, 2.0
        std.mem.writeInt(u16, cdh[6..8], 20, .little);
        std.mem.writeInt(u16, cdh[10..12], rec.method, .little);
        std.mem.writeInt(u32, cdh[16..20], rec.crc32, .little);
        std.mem.writeInt(u32, cdh[20..24], rec.comp_size, .little);
        std.mem.writeInt(u32, cdh[24..28], rec.uncomp_size, .little);
        std.mem.writeInt(u16, cdh[28..30], @intCast(rec.path.len), .little);
        std.mem.writeInt(u32, cdh[38..42], rec.external_attr, .little);
        std.mem.writeInt(u32, cdh[42..46], rec.local_offset, .little);
        try out.appendSlice(allocator, &cdh);
        try out.appendSlice(allocator, rec.path);
    }
    const cd_size: u32 = @intCast(out.items.len - cd_offset);

    var eocd: [22]u8 = @splat(0);
    std.mem.writeInt(u32, eocd[0..4], 0x06054b50, .little);
    std.mem.writeInt(u16, eocd[8..10], @intCast(cd_recs.items.len), .little);
    std.mem.writeInt(u16, eocd[10..12], @intCast(cd_recs.items.len), .little);
    std.mem.writeInt(u32, eocd[12..16], cd_size, .little);
    std.mem.writeInt(u32, eocd[16..20], cd_offset, .little);
    try out.appendSlice(allocator, &eocd);

    return out.toOwnedSlice(allocator);
}

test "ArchiveTree unpacks uncompressed .tar in memory" {
    const tar_bytes = try buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "src", .kind = .directory },
        .{ .path = "src/main.zig", .data = "pub fn main() void {}\n" },
        .{ .path = "README.md", .data = "# Hello\n" },
    });
    defer std.testing.allocator.free(tar_bytes);

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, tar_bytes, .{ .format = .auto });
    defer tree.deinit();

    const src = tree.source();
    const h = try src.open(std.testing.io, "src/main.zig");
    defer src.close(std.testing.io, h);

    var buf: [64]u8 = undefined;
    const n = try src.read(std.testing.io, h, &buf);
    try std.testing.expectEqualStrings("pub fn main() void {}\n", buf[0..n]);
}

test "ArchiveTree unpacks .zip with Store and Deflate + CRC32" {
    const zip_bytes = try buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "stored.txt", .data = "stored payload", .zip_method = .store },
        .{ .path = "nested/deflated.txt", .data = "deflated payload line", .zip_method = .deflate },
    });
    defer std.testing.allocator.free(zip_bytes);

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, zip_bytes, .{ .format = .auto });
    defer tree.deinit();

    const src = tree.source();
    const h1 = try src.open(std.testing.io, "stored.txt");
    defer src.close(std.testing.io, h1);
    var buf1: [64]u8 = undefined;
    const n1 = try src.read(std.testing.io, h1, &buf1);
    try std.testing.expectEqualStrings("stored payload", buf1[0..n1]);

    const h2 = try src.open(std.testing.io, "nested/deflated.txt");
    defer src.close(std.testing.io, h2);
    var buf2: [64]u8 = undefined;
    const n2 = try src.read(std.testing.io, h2, &buf2);
    try std.testing.expectEqualStrings("deflated payload line", buf2[0..n2]);
}

test "ArchiveTree unpacks .tar.gz with auto-detection" {
    const tar_bytes = try buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "pkg/lib.zig", .data = "const x = 42;\n" },
    });
    defer std.testing.allocator.free(tar_bytes);

    const tgz_bytes = try decompress_mod.compressGzipStoredAlloc(std.testing.allocator, tar_bytes);
    defer std.testing.allocator.free(tgz_bytes);

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, tgz_bytes, .{ .format = .auto });
    defer tree.deinit();

    const node = source_mod.Memory.lookup(tree.rootNode(), "pkg/lib.zig");
    try std.testing.expect(node != null);
    try std.testing.expectEqualStrings("const x = 42;\n", node.?.bytes);
}

test "ArchiveTree rejects path traversal entries" {
    const bad_tar = try buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "../escape.txt", .data = "evil" },
    });
    defer std.testing.allocator.free(bad_tar);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, bad_tar, .{}));

    const bad_zip = try buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "a/../../escape.txt", .data = "evil" },
    });
    defer std.testing.allocator.free(bad_zip);
    try std.testing.expectError(error.PathTraversal, ArchiveTree.initFromSlice(std.testing.allocator, bad_zip, .{}));
}

test "ArchiveTree rejects symlink entries" {
    const tar_with_link = try buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "evil_link", .kind = .symlink, .link_target = "/etc/passwd" },
        .{ .path = "safe.txt", .data = "safe content" },
    });
    defer std.testing.allocator.free(tar_with_link);

    var tree = try ArchiveTree.initFromSlice(std.testing.allocator, tar_with_link, .{});
    defer tree.deinit();

    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "evil_link") == null);
    try std.testing.expect(source_mod.Memory.lookup(tree.rootNode(), "safe.txt") != null);
}

test "ArchiveTree enforces max_entries cap" {
    const tar_bytes = try buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "1.txt", .data = "1" },
        .{ .path = "2.txt", .data = "2" },
        .{ .path = "3.txt", .data = "3" },
    });
    defer std.testing.allocator.free(tar_bytes);

    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, tar_bytes, .{ .max_entries = 2 }),
    );
}

test "ArchiveTree enforces max_entry_bytes cap" {
    const tar_bytes = try buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "big.txt", .data = "0123456789ABCDEF" },
    });
    defer std.testing.allocator.free(tar_bytes);

    try std.testing.expectError(
        error.ArchiveLimit,
        ArchiveTree.initFromSlice(std.testing.allocator, tar_bytes, .{ .max_entry_bytes = 8 }),
    );
}

test "ArchiveTree handles empty archives" {
    const empty_tar = try buildTestTarAlloc(std.testing.allocator, &.{});
    defer std.testing.allocator.free(empty_tar);
    var t1 = try ArchiveTree.initFromSlice(std.testing.allocator, empty_tar, .{});
    defer t1.deinit();
    try std.testing.expectEqual(@as(usize, 0), t1.rootNode().children.len);

    const empty_zip = try buildTestZipAlloc(std.testing.allocator, &.{});
    defer std.testing.allocator.free(empty_zip);
    var t2 = try ArchiveTree.initFromSlice(std.testing.allocator, empty_zip, .{});
    defer t2.deinit();
    try std.testing.expectEqual(@as(usize, 0), t2.rootNode().children.len);
}

test {
    _ = @import("archive_adversarial_tests.zig");
}
