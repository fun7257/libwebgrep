//! [Module] regex.zig
//! [Layer] Layer 2 — Linear-Time Regular Expression Engine Facade
//! [Role] Re-exports the modularized Thompson NFA / PikeVM regex engine (`src/regex/`).
//! [Invariants]
//!   1. Zero exponential backtracking: O(N * M) worst-case execution time.
//!   2. Hard cap on compiled instructions (`max_inst_hard_cap = 4096`) and bounded multiline windows.
//!   3. Automatic SIMD prefiltering (`Finder` for required literals, `Multi` for top-level alternations).

pub const inst_mod = @import("regex/inst.zig");
pub const compiler_mod = @import("regex/compiler.zig");
pub const prefilter_mod = @import("regex/prefilter.zig");
pub const vm_mod = @import("regex/vm.zig");

pub const Match = inst_mod.Match;
pub const MatchMode = inst_mod.MatchMode;
pub const CaseMode = inst_mod.CaseMode;
pub const RequiredLiteral = inst_mod.RequiredLiteral;
pub const Captures = inst_mod.Captures;
pub const max_inst_hard_cap = inst_mod.max_inst_hard_cap;
pub const max_multiline_window_hard_cap = inst_mod.max_multiline_window_hard_cap;
pub const default_multiline_window = inst_mod.default_multiline_window;
pub const Error = inst_mod.Error;
pub const RegexOptions = inst_mod.RegexOptions;
pub const ByteSet = inst_mod.ByteSet;
pub const Inst = inst_mod.Inst;
pub const AssertKind = inst_mod.AssertKind;
pub const Regex = vm_mod.Regex;

test {
    _ = inst_mod;
    _ = compiler_mod;
    _ = prefilter_mod;
    _ = vm_mod;
    _ = @import("regex/tests.zig");
}
