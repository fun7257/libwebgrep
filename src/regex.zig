//! [Module] regex.zig
//! [Layer] Layer 2 — Linear-Time Regular Expression Engine Facade
//! [Role] Re-exports the modularized Hybrid Lazy DFA & Thompson NFA / PikeVM regex engine (`src/regex/`).
//! [Invariants]
//!   1. Zero exponential backtracking: O(N * M) worst-case execution time.
//!   2. Hard cap on compiled instructions (`max_inst_hard_cap`) and bounded multiline windows.
//!   3. Automatic SIMD prefiltering (`Finder` for required literals, `Multi` for top-level alternations and `RegexSet`).
//!   4. Thread-safe, lock-free `*const Regex` and `*const RegexSet` search with optional `RegexScratch`.

pub const inst_mod = @import("regex/inst.zig");
pub const compiler_mod = @import("regex/compiler.zig");
pub const prefilter_mod = @import("regex/prefilter.zig");
pub const dfa_mod = @import("regex/dfa.zig");
pub const vm_mod = @import("regex/vm.zig");
pub const set_mod = @import("regex/set.zig");

pub const Match = inst_mod.Match;
pub const MatchMode = inst_mod.MatchMode;
pub const CaseMode = inst_mod.CaseMode;
pub const RequiredLiteral = inst_mod.RequiredLiteral;
pub const Captures = inst_mod.Captures;
pub const max_inst_hard_cap = inst_mod.max_inst_hard_cap;
pub const max_multiline_window_hard_cap = inst_mod.max_multiline_window_hard_cap;
pub const default_multiline_window = inst_mod.default_multiline_window;
pub const Error = inst_mod.Error;
pub const DiagnosticCode = inst_mod.DiagnosticCode;
pub const CompileDiagnostic = inst_mod.CompileDiagnostic;
pub const RegexOptions = inst_mod.RegexOptions;
pub const ByteSet = inst_mod.ByteSet;
pub const Inst = inst_mod.Inst;
pub const AssertKind = inst_mod.AssertKind;
pub const CodepointRange = inst_mod.CodepointRange;
pub const UnicodeRangeList = inst_mod.UnicodeRangeList;
pub const BoundedDfa = dfa_mod.BoundedDfa;
pub const StackDfa = dfa_mod.StackDfa;
pub const HeapDfa = dfa_mod.HeapDfa;
pub const Regex = vm_mod.Regex;
pub const RegexScratch = vm_mod.RegexScratch;
pub const RegexSet = set_mod.RegexSet;

test {
    _ = @import("tables/unicode_prop_table.zig");
    _ = inst_mod;
    _ = compiler_mod;
    _ = prefilter_mod;
    _ = dfa_mod;
    _ = vm_mod;
    _ = set_mod;
    _ = @import("regex/tests.zig");
    _ = @import("regex/adversarial_tests.zig");
}
