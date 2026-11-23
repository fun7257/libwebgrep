//! File filtering by extension and a small set of fixed filenames. Names align with ripgrep's `-t` for common file types.
//! Patterns reuse glob matching: when no slash is present, they match against the final filename segment.

const std = @import("std");
const glob = @import("glob.zig");

pub const Type = struct {
    name: []const u8,
    patterns: []const []const u8,
};

pub const builtin = [_]Type{
    .{ .name = "ada", .patterns = &.{ "*.adb", "*.ads" } },
    .{ .name = "agda", .patterns = &.{ "*.agda", "*.lagda" } },
    .{ .name = "asciidoc", .patterns = &.{ "*.adoc", "*.asc", "*.asciidoc" } },
    .{ .name = "asm", .patterns = &.{ "*.S", "*.asm", "*.s" } },
    .{ .name = "avro", .patterns = &.{ "*.avdl", "*.avpr", "*.avsc" } },
    .{ .name = "awk", .patterns = &.{"*.awk"} },
    .{ .name = "bat", .patterns = &.{"*.bat"} },
    .{ .name = "batch", .patterns = &.{"*.bat"} },
    .{ .name = "bazel", .patterns = &.{ "*.BUILD", "*.bazel", "*.bazelrc", "*.bzl", "BUILD", "MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod" } },
    .{ .name = "brotli", .patterns = &.{"*.br"} },
    .{ .name = "bzip2", .patterns = &.{ "*.bz2", "*.tbz2" } },
    .{ .name = "c", .patterns = &.{ "*.C", "*.H", "*.H.in", "*.c", "*.c.in", "*.cats", "*.h", "*.h.in" } },
    .{ .name = "cabal", .patterns = &.{"*.cabal"} },
    .{ .name = "clojure", .patterns = &.{ "*.clj", "*.cljc", "*.cljs", "*.cljx" } },
    .{ .name = "cmake", .patterns = &.{ "*.cmake", "CMakeLists.txt" } },
    .{ .name = "cmd", .patterns = &.{ "*.bat", "*.cmd" } },
    .{ .name = "coffeescript", .patterns = &.{"*.coffee"} },
    .{ .name = "config", .patterns = &.{ "*.cfg", "*.conf", "*.config", "*.ini" } },
    .{ .name = "container", .patterns = &.{ "*Containerfile*", "*Dockerfile*" } },
    .{ .name = "coq", .patterns = &.{"*.v"} },
    .{ .name = "cpp", .patterns = &.{ "*.C", "*.C.in", "*.H", "*.H.in", "*.cc", "*.cc.in", "*.cpp", "*.cpp.in", "*.cxx", "*.cxx.in", "*.h", "*.h.in", "*.hh", "*.hh.in", "*.hpp", "*.hpp.in", "*.hxx", "*.hxx.in", "*.inl" } },
    .{ .name = "crystal", .patterns = &.{ "*.cr", "*.ecr", "Projectfile", "shard.yml" } },
    .{ .name = "cs", .patterns = &.{"*.cs"} },
    .{ .name = "csharp", .patterns = &.{"*.cs"} },
    .{ .name = "css", .patterns = &.{ "*.css", "*.scss" } },
    .{ .name = "csv", .patterns = &.{"*.csv"} },
    .{ .name = "cuda", .patterns = &.{ "*.cu", "*.cuh" } },
    .{ .name = "cython", .patterns = &.{ "*.pxd", "*.pxi", "*.pyx" } },
    .{ .name = "d", .patterns = &.{"*.d"} },
    .{ .name = "dart", .patterns = &.{"*.dart"} },
    .{ .name = "dhall", .patterns = &.{"*.dhall"} },
    .{ .name = "diff", .patterns = &.{ "*.diff", "*.patch" } },
    .{ .name = "docker", .patterns = &.{"*Dockerfile*"} },
    .{ .name = "dockercompose", .patterns = &.{ "docker-compose.*.yml", "docker-compose.yml" } },
    .{ .name = "dockerfile", .patterns = &.{"*Dockerfile*"} },
    .{ .name = "edn", .patterns = &.{"*.edn"} },
    .{ .name = "elisp", .patterns = &.{"*.el"} },
    .{ .name = "elixir", .patterns = &.{ "*.eex", "*.ex", "*.exs", "*.heex", "*.leex", "*.livemd" } },
    .{ .name = "elm", .patterns = &.{"*.elm"} },
    .{ .name = "erb", .patterns = &.{"*.erb"} },
    .{ .name = "erlang", .patterns = &.{ "*.erl", "*.hrl" } },
    .{ .name = "fennel", .patterns = &.{"*.fnl"} },
    .{ .name = "fish", .patterns = &.{"*.fish"} },
    .{ .name = "flatbuffers", .patterns = &.{"*.fbs"} },
    .{ .name = "fortran", .patterns = &.{ "*.F", "*.F77", "*.F90", "*.F95", "*.f", "*.f77", "*.f90", "*.f95", "*.pfo" } },
    .{ .name = "fsharp", .patterns = &.{ "*.fs", "*.fsi", "*.fsx" } },
    .{ .name = "gdscript", .patterns = &.{"*.gd"} },
    .{ .name = "gleam", .patterns = &.{"*.gleam"} },
    .{ .name = "glsl", .patterns = &.{ "*.comp", "*.frag", "*.geom", "*.glsl", "*.tesc", "*.tese", "*.vert" } },
    .{ .name = "gn", .patterns = &.{ "*.gn", "*.gni" } },
    .{ .name = "go", .patterns = &.{"*.go"} },
    .{ .name = "gradle", .patterns = &.{ "*.gradle", "*.gradle.kts", "gradle-wrapper.*", "gradle.properties", "gradlew", "gradlew.bat" } },
    .{ .name = "graphql", .patterns = &.{ "*.graphql", "*.graphqls" } },
    .{ .name = "groovy", .patterns = &.{ "*.gradle", "*.groovy" } },
    .{ .name = "gzip", .patterns = &.{ "*.gz", "*.tgz" } },
    .{ .name = "h", .patterns = &.{ "*.h", "*.hh", "*.hpp" } },
    .{ .name = "haml", .patterns = &.{"*.haml"} },
    .{ .name = "hare", .patterns = &.{"*.ha"} },
    .{ .name = "haskell", .patterns = &.{ "*.c2hs", "*.cpphs", "*.hs", "*.hsc", "*.lhs" } },
    .{ .name = "hbs", .patterns = &.{"*.hbs"} },
    .{ .name = "hlsl", .patterns = &.{ "*.cginc", "*.compute", "*.fx", "*.fxh", "*.hlsl", "*.hlsli" } },
    .{ .name = "hs", .patterns = &.{ "*.hs", "*.lhs" } },
    .{ .name = "html", .patterns = &.{ "*.ejs", "*.htm", "*.html" } },
    .{ .name = "idris", .patterns = &.{ "*.idr", "*.lidr" } },
    .{ .name = "ini", .patterns = &.{"*.ini"} },
    .{ .name = "java", .patterns = &.{ "*.java", "*.jsp", "*.jspx", "*.properties" } },
    .{ .name = "jinja", .patterns = &.{ "*.j2", "*.jinja", "*.jinja2" } },
    .{ .name = "jl", .patterns = &.{"*.jl"} },
    .{ .name = "js", .patterns = &.{ "*.cjs", "*.js", "*.jsx", "*.mjs", "*.vue" } },
    .{ .name = "json", .patterns = &.{ "*.json", "*.sarif", "composer.lock" } },
    .{ .name = "jsonl", .patterns = &.{"*.jsonl"} },
    .{ .name = "julia", .patterns = &.{"*.jl"} },
    .{ .name = "jupyter", .patterns = &.{ "*.ipynb", "*.jpynb" } },
    .{ .name = "kconfig", .patterns = &.{ "Kconfig", "Kconfig.*" } },
    .{ .name = "kotlin", .patterns = &.{ "*.kt", "*.kts" } },
    .{ .name = "lean", .patterns = &.{"*.lean"} },
    .{ .name = "less", .patterns = &.{"*.less"} },
    .{ .name = "license", .patterns = &.{ "*[.-]LICEN[CS]E*", "AGPL-*[0-9]*", "APACHE-*[0-9]*", "BSD-*[0-9]*", "CC-BY-*", "COPYING", "COPYING[.-]*", "COPYRIGHT", "COPYRIGHT[.-]*", "EULA", "EULA[.-]*", "GFDL-*[0-9]*", "GNU-*[0-9]*", "GPL-*[0-9]*", "LGPL-*[0-9]*", "LICEN[CS]E", "LICEN[CS]E[.-]*", "MIT-*[0-9]*", "MPL-*[0-9]*", "NOTICE", "NOTICE[.-]*", "OFL-*[0-9]*", "PATENTS", "PATENTS[.-]*", "UNLICEN[CS]E", "UNLICEN[CS]E[.-]*", "agpl[.-]*", "gpl[.-]*", "lgpl[.-]*", "licen[cs]e", "licen[cs]e.*" } },
    .{ .name = "lisp", .patterns = &.{ "*.el", "*.jl", "*.lisp", "*.lsp" } },
    .{ .name = "llvm", .patterns = &.{"*.ll"} },
    .{ .name = "lock", .patterns = &.{ "*.lock", ".terraform.lock.hcl", "gradle.lockfile", "package-lock.json", "pnpm-lock.yaml", "pylock*.toml" } },
    .{ .name = "log", .patterns = &.{"*.log"} },
    .{ .name = "lua", .patterns = &.{"*.lua"} },
    .{ .name = "lz4", .patterns = &.{"*.lz4"} },
    .{ .name = "lzma", .patterns = &.{"*.lzma"} },
    .{ .name = "m4", .patterns = &.{ "*.ac", "*.m4" } },
    .{ .name = "make", .patterns = &.{ "*.mak", "*.mk", "Makefile.*", "[Gg][Nn][Uu]makefile", "[Gg][Nn][Uu]makefile.am", "[Gg][Nn][Uu]makefile.in", "[Mm]akefile", "[Mm]akefile.am", "[Mm]akefile.in" } },
    .{ .name = "man", .patterns = &.{ "*.[0-9][cEFMmpSx]", "*.[0-9lnpx]" } },
    .{ .name = "markdown", .patterns = &.{ "*.markdown", "*.md", "*.mdown", "*.mdwn", "*.mdx", "*.mkd", "*.mkdn" } },
    .{ .name = "md", .patterns = &.{ "*.markdown", "*.md", "*.mdown", "*.mdwn", "*.mdx", "*.mkd", "*.mkdn" } },
    .{ .name = "meson", .patterns = &.{ "meson.build", "meson.options", "meson_options.txt" } },
    .{ .name = "minified", .patterns = &.{ "*.min.css", "*.min.html", "*.min.js" } },
    .{ .name = "ml", .patterns = &.{"*.ml"} },
    .{ .name = "mojo", .patterns = &.{"*.mojo"} },
    .{ .name = "msbuild", .patterns = &.{ "*.csproj", "*.fsproj", "*.proj", "*.props", "*.sln", "*.slnf", "*.slnx", "*.targets", "*.vcxproj" } },
    .{ .name = "nim", .patterns = &.{ "*.nim", "*.nimble", "*.nimf", "*.nims" } },
    .{ .name = "ninja", .patterns = &.{"*.ninja"} },
    .{ .name = "nix", .patterns = &.{"*.nix"} },
    .{ .name = "objc", .patterns = &.{ "*.h", "*.m" } },
    .{ .name = "objcpp", .patterns = &.{ "*.h", "*.mm" } },
    .{ .name = "ocaml", .patterns = &.{ "*.ml", "*.mli", "*.mll", "*.mly" } },
    .{ .name = "org", .patterns = &.{ "*.org", "*.org_archive" } },
    .{ .name = "pascal", .patterns = &.{ "*.dpr", "*.inc", "*.lpr", "*.pas", "*.pp" } },
    .{ .name = "pdf", .patterns = &.{"*.pdf"} },
    .{ .name = "perl", .patterns = &.{ "*.PL", "*.perl", "*.pl", "*.plh", "*.plx", "*.pm", "*.t" } },
    .{ .name = "php", .patterns = &.{ "*.php", "*.php3", "*.php4", "*.php5", "*.php7", "*.php8", "*.pht", "*.phtml" } },
    .{ .name = "po", .patterns = &.{"*.po"} },
    .{ .name = "powershell", .patterns = &.{ "*.cdxml", "*.ps1", "*.ps1xml", "*.psc1", "*.psd1", "*.psm1", "*.psr", "*.psrc", "*.pssc", "*.psxml" } },
    .{ .name = "prolog", .patterns = &.{ "*.P", "*.pl", "*.pro", "*.prolog" } },
    .{ .name = "proto", .patterns = &.{"*.proto"} },
    .{ .name = "protobuf", .patterns = &.{"*.proto"} },
    .{ .name = "ps", .patterns = &.{ "*.cdxml", "*.ps1", "*.ps1xml", "*.psc1", "*.psd1", "*.psm1", "*.psr", "*.psrc", "*.pssc", "*.psxml" } },
    .{ .name = "puppet", .patterns = &.{ "*.epp", "*.erb", "*.pp", "*.rb" } },
    .{ .name = "purs", .patterns = &.{"*.purs"} },
    .{ .name = "py", .patterns = &.{ "*.py", "*.pyi" } },
    .{ .name = "python", .patterns = &.{ "*.py", "*.pyi" } },
    .{ .name = "qml", .patterns = &.{"*.qml"} },
    .{ .name = "r", .patterns = &.{ "*.R", "*.Rmd", "*.Rnw", "*.r", "*.rmd", "*.rnw" } },
    .{ .name = "racket", .patterns = &.{"*.rkt"} },
    .{ .name = "raku", .patterns = &.{ "*.p6", "*.pl6", "*.pm6", "*.raku", "*.rakudoc", "*.rakumod", "*.rakutest" } },
    .{ .name = "readme", .patterns = &.{ "*README", "README*" } },
    .{ .name = "reasonml", .patterns = &.{ "*.re", "*.rei" } },
    .{ .name = "rescript", .patterns = &.{ "*.res", "*.resi" } },
    .{ .name = "rst", .patterns = &.{"*.rst"} },
    .{ .name = "ruby", .patterns = &.{ "*.gemspec", "*.rake", "*.rb", "*.rbw", ".irbrc", "Gemfile", "Rakefile", "config.ru" } },
    .{ .name = "rust", .patterns = &.{"*.rs"} },
    .{ .name = "sass", .patterns = &.{ "*.sass", "*.scss" } },
    .{ .name = "scala", .patterns = &.{ "*.sbt", "*.scala" } },
    .{ .name = "scheme", .patterns = &.{ "*.sc", "*.scm", "*.sld", "*.ss" } },
    .{ .name = "scss", .patterns = &.{"*.scss"} },
    .{ .name = "sh", .patterns = &.{ "*.bash", "*.bashrc", "*.csh", "*.cshrc", "*.env", "*.ksh", "*.kshrc", "*.sh", "*.tcsh", "*.zsh", ".bash_login", ".bash_logout", ".bash_profile", ".bashrc", ".cshrc", ".env", ".kshrc", ".login", ".logout", ".profile", ".tcshrc", ".zlogin", ".zlogout", ".zprofile", ".zshenv", ".zshrc", "bash_login", "bash_logout", "bash_profile", "bashrc", "profile", "zlogin", "zlogout", "zprofile", "zshenv", "zshrc" } },
    .{ .name = "slim", .patterns = &.{ "*.skim", "*.slim", "*.slime" } },
    .{ .name = "sml", .patterns = &.{ "*.sig", "*.sml" } },
    .{ .name = "solidity", .patterns = &.{"*.sol"} },
    .{ .name = "spec", .patterns = &.{"*.spec"} },
    .{ .name = "sql", .patterns = &.{ "*.psql", "*.sql" } },
    .{ .name = "stylus", .patterns = &.{"*.styl"} },
    .{ .name = "svelte", .patterns = &.{ "*.svelte", "*.svelte.ts" } },
    .{ .name = "svg", .patterns = &.{"*.svg"} },
    .{ .name = "swift", .patterns = &.{"*.swift"} },
    .{ .name = "systemd", .patterns = &.{ "*.automount", "*.conf", "*.device", "*.link", "*.mount", "*.path", "*.scope", "*.service", "*.slice", "*.socket", "*.swap", "*.target", "*.timer" } },
    .{ .name = "tcl", .patterns = &.{"*.tcl"} },
    .{ .name = "terraform", .patterns = &.{ "*.terraform.lock.hcl", "*.terraformrc", "*.tf", "*.tf.json", "*.tfrc", "*.tfvars", "*.tfvars.json", "terraform.rc" } },
    .{ .name = "tex", .patterns = &.{ "*.bib", "*.cls", "*.dtx", "*.ins", "*.ltx", "*.sty", "*.tex" } },
    .{ .name = "texinfo", .patterns = &.{"*.texi"} },
    .{ .name = "tf", .patterns = &.{ "*.terraform.lock.hcl", "*.terraformrc", "*.tf", "*.tf.json", "*.tfrc", "*.tfvars", "*.tfvars.json", "terraform.rc" } },
    .{ .name = "thrift", .patterns = &.{"*.thrift"} },
    .{ .name = "toml", .patterns = &.{ "*.toml", "Cargo.lock" } },
    .{ .name = "ts", .patterns = &.{ "*.cts", "*.mts", "*.ts", "*.tsx" } },
    .{ .name = "twig", .patterns = &.{"*.twig"} },
    .{ .name = "txt", .patterns = &.{"*.txt"} },
    .{ .name = "typescript", .patterns = &.{ "*.cts", "*.mts", "*.ts", "*.tsx" } },
    .{ .name = "typst", .patterns = &.{"*.typ"} },
    .{ .name = "v", .patterns = &.{ "*.v", "*.vsh" } },
    .{ .name = "vala", .patterns = &.{"*.vala"} },
    .{ .name = "vb", .patterns = &.{"*.vb"} },
    .{ .name = "verilog", .patterns = &.{ "*.sv", "*.svh", "*.v", "*.vh" } },
    .{ .name = "vhdl", .patterns = &.{ "*.vhd", "*.vhdl" } },
    .{ .name = "vim", .patterns = &.{ "*.vim", ".gvimrc", ".vimrc", "_gvimrc", "_vimrc", "gvimrc", "vimrc" } },
    .{ .name = "vimscript", .patterns = &.{ "*.vim", ".gvimrc", ".vimrc", "_gvimrc", "_vimrc", "gvimrc", "vimrc" } },
    .{ .name = "vue", .patterns = &.{"*.vue"} },
    .{ .name = "webidl", .patterns = &.{ "*.idl", "*.webidl", "*.widl" } },
    .{ .name = "wgsl", .patterns = &.{"*.wgsl"} },
    .{ .name = "wiki", .patterns = &.{ "*.mediawiki", "*.wiki" } },
    .{ .name = "xml", .patterns = &.{ "*.dtd", "*.rng", "*.sch", "*.xhtml", "*.xjb", "*.xml", "*.xml.dist", "*.xsd", "*.xsl", "*.xslt" } },
    .{ .name = "xz", .patterns = &.{ "*.txz", "*.xz" } },
    .{ .name = "yacc", .patterns = &.{"*.y"} },
    .{ .name = "yaml", .patterns = &.{ "*.yaml", "*.yml" } },
    .{ .name = "yang", .patterns = &.{"*.yang"} },
    .{ .name = "zig", .patterns = &.{"*.zig"} },
    .{ .name = "zsh", .patterns = &.{ "*.zsh", ".zlogin", ".zlogout", ".zprofile", ".zshenv", ".zshrc", "zlogin", "zlogout", "zprofile", "zshenv", "zshrc" } },
    .{ .name = "zstd", .patterns = &.{ "*.zst", "*.zstd" } },
};

comptime {
    for (1..builtin.len) |i| {
        if (std.mem.order(u8, builtin[i - 1].name, builtin[i].name) != .lt) {
            @compileError(std.fmt.comptimePrint(
                "types.builtin must be strictly sorted in ascending lexicographical order: {s} >= {s}",
                .{ builtin[i - 1].name, builtin[i].name },
            ));
        }
    }
}

pub fn find(name: []const u8) ?Type {
    return findInTable(&.{}, name);
}

/// Searches the caller-supplied `table` in reverse (last-defined wins) before falling back to `builtin`.
pub fn findInTable(table: []const Type, name: []const u8) ?Type {
    var i: usize = table.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, table[i].name, name)) return table[i];
    }
    const idx = std.sort.binarySearch(Type, &builtin, name, struct {
        fn cmp(key: []const u8, item: Type) std.math.Order {
            return std.mem.order(u8, key, item.name);
        }
    }.cmp) orelse return null;
    return builtin[idx];
}

/// Expands caller-selected and excluded type names (combining `table` and `builtin`) into a slice of `glob.Glob`.
pub fn expandTypesToGlobs(
    arena: std.mem.Allocator,
    table: []const Type,
    include: []const []const u8,
    exclude: []const []const u8,
) glob.GlobError![]glob.Glob {
    return expandTypesToGlobsWithOptions(arena, table, include, exclude, .{});
}

pub fn expandTypesToGlobsWithOptions(
    arena: std.mem.Allocator,
    table: []const Type,
    include: []const []const u8,
    exclude: []const []const u8,
    options: glob.CompileOptions,
) glob.GlobError![]glob.Glob {
    const max_rules = options.max_rules orelse glob.rule_count_hard_cap;
    var raw_list: std.ArrayList([]const u8) = .empty;
    defer raw_list.deinit(arena);

    for (include) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pat| {
            if (raw_list.items.len >= max_rules) return error.GlobCountExceeded;
            try raw_list.append(arena, pat);
        }
    }
    for (exclude) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pat| {
            if (raw_list.items.len >= max_rules) return error.GlobCountExceeded;
            const neg = try std.fmt.allocPrint(arena, "!{s}", .{pat});
            try raw_list.append(arena, neg);
        }
    }
    return glob.compileGlobs(arena, raw_list.items, options);
}

/// An empty `selected` slice applies no positive type filter; matching any `excluded` type rejects the file immediately.
pub fn matchesWithTable(
    table: []const Type,
    selected: []const []const u8,
    excluded: []const []const u8,
    base: []const u8,
) bool {
    for (excluded) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pattern| {
            var compiled = glob.classify(pattern);
            compiled.anchored = false;
            if (glob.matches(compiled, base, base, false)) return false;
        }
    }
    if (selected.len == 0) return true;
    for (selected) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pattern| {
            var compiled = glob.classify(pattern);
            compiled.anchored = false;
            if (glob.matches(compiled, base, base, false)) return true;
        }
    }
    return false;
}

/// An empty `selected` slice applies no filter. Otherwise, the filename matches if it hits at least one selected type.
pub fn matches(selected: []const []const u8, base: []const u8) bool {
    return matchesWithTable(&.{}, selected, &.{}, base);
}

test "type table recognizes zig and Makefile" {
    try std.testing.expect(find("zig") != null);
    try std.testing.expect(find("nope") == null);
    try std.testing.expect(matches(&.{"zig"}, "main.zig"));
    try std.testing.expect(!matches(&.{"zig"}, "main.txt"));
    try std.testing.expect(matches(&.{"make"}, "Makefile"));
    try std.testing.expect(matches(&.{ "zig", "txt" }, "a.txt"));
    try std.testing.expect(matches(&.{}, "anything"));
}

test "caller-supplied type table expands to globs and filters exclusions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const custom = [_]Type{
        .{ .name = "proto", .patterns = &.{ "*.proto", "*.{pb.go,pb.cc}" } },
    };
    const expanded = try expandTypesToGlobs(arena, &custom, &.{ "proto", "zig" }, &.{"c"});
    try std.testing.expect(glob.matchGlobs(expanded, "api.proto", "api.proto", false));
    try std.testing.expect(glob.matchGlobs(expanded, "api.pb.go", "api.pb.go", false));
    try std.testing.expect(glob.matchGlobs(expanded, "main.zig", "main.zig", false));
    try std.testing.expect(!glob.matchGlobs(expanded, "legacy.c", "legacy.c", false));
    try std.testing.expect(!glob.matchGlobs(expanded, "readme.md", "readme.md", false));

    try std.testing.expect(matchesWithTable(&custom, &.{"proto"}, &.{"go"}, "api.proto"));
    try std.testing.expect(!matchesWithTable(&custom, &.{"proto"}, &.{"go"}, "api.pb.go"));
}

test "expanded builtin type table binary search and canonical entries" {
    try std.testing.expect(builtin.len >= 150);
    for (builtin) |item| {
        const found = find(item.name) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(item.name, found.name);
    }
    try std.testing.expect(find("ada") != null);
    try std.testing.expect(find("rust") != null);
    try std.testing.expect(find("zstd") != null);
    try std.testing.expect(find("aaaa") == null);
    try std.testing.expect(find("zzzz") == null);
    try std.testing.expect(matches(&.{"ts"}, "index.mts"));
    try std.testing.expect(matches(&.{"markdown"}, "doc.mdx"));
    try std.testing.expect(matches(&.{"toml"}, "Cargo.lock"));
    try std.testing.expect(matches(&.{"dockerfile"}, "Dockerfile.prod"));
    try std.testing.expect(matches(&.{"cpp"}, "header.inl"));
}
