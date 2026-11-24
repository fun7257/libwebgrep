/**
 * @file webgrep.h
 * @brief C ABI and Cross-Language FFI Header for libwebgrep v0.10.0.
 *
 * Thread-safe, zero-global-state SIMD literal, multi-pattern, and linear-time
 * regular expression search engine with in-memory archive and streaming reader support.
 */

#ifndef WEBGREP_H
#define WEBGREP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WEBGREP_API
#  if defined(_WIN32) && defined(WEBGREP_SHARED)
#    ifdef WEBGREP_BUILD_SHARED
#      define WEBGREP_API __declspec(dllexport)
#    else
#      define WEBGREP_API __declspec(dllimport)
#    endif
#  else
#    define WEBGREP_API
#  endif
#endif

/* ============================================================================
 * Version Information
 * ========================================================================= */

#define WEBGREP_VERSION_MAJOR 0
#define WEBGREP_VERSION_MINOR 10
#define WEBGREP_VERSION_PATCH 0
#define WEBGREP_VERSION_STRING "0.10.0"

/* ============================================================================
 * Status & Error Codes
 * ========================================================================= */

typedef enum webgrep_status_e {
    WEBGREP_OK                  =  0,
    WEBGREP_ERR_INVALID_ARG     = -1,
    WEBGREP_ERR_OUT_OF_MEMORY   = -2,
    WEBGREP_ERR_SYNTAX          = -3,
    WEBGREP_ERR_TOO_LARGE       = -4,
    WEBGREP_ERR_BUDGET_EXCEEDED = -5,
    WEBGREP_ERR_IO              = -6,
    WEBGREP_ERR_CORRUPT_ARCHIVE = -7,
    WEBGREP_ERR_ARCHIVE_LIMIT   = -8
} webgrep_status_t;

/* Convenience aliases for error codes */
#define WEBGREP_ERR_INVALID_ARGUMENT   WEBGREP_ERR_INVALID_ARG
#define WEBGREP_ERR_OOM                WEBGREP_ERR_OUT_OF_MEMORY
#define WEBGREP_ERR_REGEX_SYNTAX       WEBGREP_ERR_SYNTAX
#define WEBGREP_ERR_REGEX_TOO_LARGE    WEBGREP_ERR_TOO_LARGE
#define WEBGREP_ERR_PATTERN_TOO_LARGE  WEBGREP_ERR_TOO_LARGE
#define WEBGREP_ERR_LIMIT_EXCEEDED     WEBGREP_ERR_BUDGET_EXCEEDED
#define WEBGREP_ERR_BUDGET             WEBGREP_ERR_BUDGET_EXCEEDED
#define WEBGREP_ERR_READ_FAILED        WEBGREP_ERR_IO
#define WEBGREP_ERR_ARCHIVE_INVALID    WEBGREP_ERR_CORRUPT_ARCHIVE
#define WEBGREP_ERR_ARCHIVE_CORRUPT    WEBGREP_ERR_CORRUPT_ARCHIVE
#define WEBGREP_ERR_ARCHIVE            WEBGREP_ERR_CORRUPT_ARCHIVE
#define WEBGREP_ERR_PATH_TRAVERSAL     WEBGREP_ERR_CORRUPT_ARCHIVE
#define WEBGREP_ERR_UNSUPPORTED_FORMAT WEBGREP_ERR_CORRUPT_ARCHIVE

/* ============================================================================
 * Enumerations
 * ========================================================================= */

/** Case sensitivity mode for literal, multi-literal, and regex compilation. */
typedef enum webgrep_case_mode_e {
    WEBGREP_CASE_SENSITIVE   = 0,
    WEBGREP_CASE_INSENSITIVE = 1,
    WEBGREP_CASE_SMART       = 2
} webgrep_case_mode_t;

/** Match selection mode (`earliest` ends earliest; `leftmost_first` leftmost start). */
typedef enum webgrep_match_mode_e {
    WEBGREP_MATCH_EARLIEST       = 0,
    WEBGREP_MATCH_LEFTMOST_FIRST = 1
} webgrep_match_mode_t;

/** Binary file handling policy. */
typedef enum webgrep_binary_policy_e {
    WEBGREP_BINARY_QUIT   = 0,
    WEBGREP_BINARY_REPORT = 1,
    WEBGREP_BINARY_NONE   = 2
} webgrep_binary_policy_t;

/** Character encoding mode. */
typedef enum webgrep_encoding_e {
    WEBGREP_ENCODING_AUTO        = 0,
    WEBGREP_ENCODING_UTF8        = 1,
    WEBGREP_ENCODING_UTF16LE     = 2,
    WEBGREP_ENCODING_UTF16BE     = 3,
    WEBGREP_ENCODING_GBK         = 4,
    WEBGREP_ENCODING_LATIN1      = 5,
    WEBGREP_ENCODING_NONE        = 6,
    WEBGREP_ENCODING_WINDOWS1252 = 7,
    WEBGREP_ENCODING_GB18030     = 8,
    WEBGREP_ENCODING_SHIFT_JIS   = 9,
    WEBGREP_ENCODING_EUC_JP      = 10,
    WEBGREP_ENCODING_BIG5        = 11,
    WEBGREP_ENCODING_EUC_KR      = 12,
    WEBGREP_ENCODING_WINDOWS1251 = 13,
    WEBGREP_ENCODING_UTF32LE     = 14,
    WEBGREP_ENCODING_UTF32BE     = 15,
    WEBGREP_ENCODING_DETECT      = 16
} webgrep_encoding_t;

/** Streaming decompression mode. */
typedef enum webgrep_compression_e {
    WEBGREP_COMPRESSION_NONE    = 0,
    WEBGREP_COMPRESSION_AUTO    = 1,
    WEBGREP_COMPRESSION_GZIP    = 2,
    WEBGREP_COMPRESSION_ZSTD    = 3,
    WEBGREP_COMPRESSION_XZ      = 4,
    WEBGREP_COMPRESSION_ZLIB    = 5,
    WEBGREP_COMPRESSION_DEFLATE = 6,
    WEBGREP_COMPRESSION_LZ4     = 7,
    WEBGREP_COMPRESSION_BZIP2   = 8,
    WEBGREP_COMPRESSION_BROTLI  = 9
} webgrep_compression_t;

/** In-memory archive format. */
typedef enum webgrep_archive_format_e {
    WEBGREP_ARCHIVE_AUTO    = 0,
    WEBGREP_ARCHIVE_TAR     = 1,
    WEBGREP_ARCHIVE_TAR_GZ  = 2,
    WEBGREP_ARCHIVE_TAR_ZST = 3,
    WEBGREP_ARCHIVE_TAR_XZ  = 4,
    WEBGREP_ARCHIVE_ZIP     = 5,
    WEBGREP_ARCHIVE_TAR_BZ2 = 6,
    WEBGREP_ARCHIVE_TAR_LZ4 = 7
} webgrep_archive_format_t;

/** Flow control action returned via `webgrep_flow_t` from `webgrep_flow_line_cb`. */
typedef enum webgrep_flow_action_e {
    WEBGREP_FLOW_CONT    = 0,
    WEBGREP_FLOW_STOP    = 1,
    WEBGREP_FLOW_PAUSE   = 2,
    WEBGREP_FLOW_SKIP_TO = 3
} webgrep_flow_action_t;

/** Budget limit reached during a search. */
typedef enum webgrep_limit_hit_e {
    WEBGREP_LIMIT_NONE               = 0,
    WEBGREP_LIMIT_MAX_RESULTS        = 1,
    WEBGREP_LIMIT_MAX_BYTES          = 2,
    WEBGREP_LIMIT_DEADLINE           = 3,
    WEBGREP_LIMIT_DECOMPRESSED_BYTES = 4,
    WEBGREP_LIMIT_CANCELLED          = 5
} webgrep_limit_hit_t;

/** Line numbering policy for mid-file range and reverse tail searches. */
typedef enum webgrep_line_number_mode_e {
    WEBGREP_LINE_NUM_AUTO     = 0,
    WEBGREP_LINE_NUM_FROM_ONE = 1,
    WEBGREP_LINE_NUM_UNKNOWN  = 2
} webgrep_line_number_mode_t;

/** Archive entry kind reported to `webgrep_archive_entry_filter_cb`. */
typedef enum webgrep_entry_kind_e {
    WEBGREP_ENTRY_FILE      = 0,
    WEBGREP_ENTRY_DIRECTORY = 1,
    WEBGREP_ENTRY_OTHER     = 2
} webgrep_entry_kind_t;

/** Whole-word boundary mode for `webgrep_config_t.whole_word`. */
typedef enum webgrep_whole_word_mode_e {
    WEBGREP_WHOLE_WORD_OFF     = 0,
    WEBGREP_WHOLE_WORD_UNICODE = 1,
    WEBGREP_WHOLE_WORD_ASCII   = 2
} webgrep_whole_word_mode_t;

/* ============================================================================
 * Opaque Handles
 * ========================================================================= */

/** Opaque compiled matcher handle (`Finder`, `Multi`, `Regex`, or `RegexSet`). Thread-safe for concurrent searches. */
typedef struct webgrep_matcher_s webgrep_matcher_t;

/** Opaque per-thread reusable scratch buffer pool (`Scratch`). Not shared concurrently across threads. */
typedef struct webgrep_scratch_s webgrep_scratch_t;

/** Opaque atomic cancellation token (`CancelToken`). Thread-safe to trigger from another thread. */
typedef struct webgrep_cancel_s webgrep_cancel_t;

/** Opaque pull-mode line event iterator handle. Not shared concurrently across threads. */
typedef struct webgrep_pull_s webgrep_pull_t;

/** Opaque N-gram Bloom filter handle for zero-false-negative pre-screening. */
typedef struct webgrep_bloom_s webgrep_bloom_t;

/** Opaque parsed Zstd Seek Table handle for random-access decompression. */
typedef struct webgrep_zstd_seek_table_s webgrep_zstd_seek_table_t;

/** Opaque indexed Gzip checkpoint table handle for random-access decompression. */
typedef struct webgrep_gzip_index_s webgrep_gzip_index_t;

/** Opaque stateless resume cursor handle for pause/resume pagination (`ResumeState`). */
typedef struct webgrep_resume_state_s webgrep_resume_state_t;

/* ============================================================================
 * Option, Pattern, Match, Event, & Summary Structures
 * ========================================================================= */

/** Pattern slice descriptor for multi-pattern literal and RegexSet compilation. */
typedef struct webgrep_pattern_s {
    const uint8_t *ptr;
    size_t         len;
} webgrep_pattern_t;

/** Options for literal (`Finder`) and multi-literal (`Multi`) compilation. */
typedef struct webgrep_find_options_s {
    int      case_mode;
    uint8_t  unicode_case;
    uint8_t  multiline;
    size_t   max_multiline_window;
    size_t   max_patterns;
    size_t   max_pattern_bytes;
    size_t   max_unicode_variants;
} webgrep_find_options_t;

/** Options for `Regex` and `RegexSet` compilation. */
typedef struct webgrep_regex_options_s {
    int      case_mode;
    uint8_t  unicode_case;
    uint8_t  multiline;
    uint8_t  dot_all;
    size_t   max_inst;
    size_t   max_multiline_window;
    uint16_t max_dfa_states;
    size_t   max_repeat;
    size_t   max_recursion_depth;
    size_t   max_patterns;
    size_t   max_pattern_bytes;
    uint8_t  unicode_classes;
} webgrep_regex_options_t;

/** Structured compile diagnostic populated when regex compilation fails. */
typedef struct webgrep_compile_diag_s {
    int     code;
    size_t  offset;
    size_t  line;
    size_t  column;
    size_t  pattern_index;
    uint8_t has_pattern_index;
    char    message[128];
} webgrep_compile_diag_t;

/** Match result returned by `webgrep_find`. */
typedef struct webgrep_match_s {
    size_t   start;
    size_t   end;
    uint32_t pattern_id;
    uint8_t  has_pattern_id;
} webgrep_match_t;

/** Span within an emitted matching line (`pattern_id` is -1 if not applicable). */
typedef struct webgrep_span_s {
    size_t  start;
    size_t  end;
    int32_t pattern_id;
    size_t  u16_start;
    size_t  u16_end;
} webgrep_span_t;

/** Line event payload passed to `webgrep_line_cb`. */
typedef struct webgrep_line_event_s {
    const uint8_t        *path_ptr;
    size_t                path_len;
    uint64_t              line_number;
    uint64_t              byte_offset;
    uint64_t              column;
    uint64_t              u16_column;
    const uint8_t        *text_ptr;
    size_t                text_len;
    const uint8_t        *bytes_ptr;
    size_t                bytes_len;
    const uint8_t        *replaced_ptr;
    size_t                replaced_len;
    const webgrep_span_t *matches_ptr;
    size_t                matches_len;
    uint8_t               is_context;
    uint8_t               truncated;
    uint8_t               line_number_known;
} webgrep_line_event_t;

/** Candidate line passed to `webgrep_line_filter_cb` before consuming quota or counters. */
typedef struct webgrep_line_filter_candidate_s {
    const uint8_t *bytes_ptr;
    size_t         bytes_len;
    const uint8_t *raw_bytes_ptr;
    size_t         raw_bytes_len;
    uint64_t       absolute_offset;
    webgrep_span_t first_match;
    uint8_t        is_inverted;
} webgrep_line_filter_candidate_t;

/**
 * Pre-count / pre-quota line filter callback.
 * Borrowed pointers inside `cand` are valid only until this callback returns.
 * Return `true` to accept the line, or `false` to reject it strictly before `max_count`,
 * `max_results`, `matched_lines`, `matches`, or context emission.
 */
typedef bool (*webgrep_line_filter_cb)(void *user_data, const webgrep_line_filter_candidate_t *cand);

/** Archive entry metadata passed to `webgrep_archive_entry_filter_cb` before decompression. */
typedef struct webgrep_archive_entry_meta_s {
    const uint8_t *path_ptr;
    size_t         path_len;
    int32_t        kind;
    uint64_t       size;
    uint64_t       compressed_size;
    int64_t        mtime;
    uint8_t        has_mtime;
} webgrep_archive_entry_meta_t;

/**
 * Pre-decompression archive entry filter callback.
 * Return `true` to unpack and search the entry, or `false` to skip it before decompression or quota checks.
 */
typedef bool (*webgrep_archive_entry_filter_cb)(void *user_data, const webgrep_archive_entry_meta_t *meta);

/** Options for byte-offset line probing (`NULL` uses defaults: `delimiter = '\n'`, `strip_crlf = 1`, `max_line_bytes = 2 MiB`). */
typedef struct webgrep_probe_options_s {
    uint8_t delimiter;
    uint8_t strip_crlf;
    size_t  max_line_bytes;
} webgrep_probe_options_t;

/** Extracted line (or bounded window) enclosing a probed byte offset. */
typedef struct webgrep_line_probe_s {
    uint64_t       start_offset;
    uint64_t       end_offset;
    uint64_t       raw_end_offset;
    const uint8_t *bytes_ptr;
    size_t         bytes_len;
    uint8_t        truncated_left;
    uint8_t        truncated_right;
} webgrep_line_probe_t;

/** Search configuration for slice, streaming, and reverse tail searches. */
typedef struct webgrep_config_s {
    webgrep_scratch_t     *scratch;
    const uint8_t         *replacement_ptr;
    size_t                 replacement_len;
    uint32_t               before_context;
    uint32_t               after_context;
    uint64_t               max_count;
    uint64_t               max_results;
    uint64_t               max_bytes;
    size_t                 max_decode_bytes;
    size_t                 buffer_size;
    size_t                 max_line_len;
    int                    encoding;
    int                    compression;
    int                    binary_mode;
    int                    match_mode;
    uint8_t                invert_match;
    uint8_t                passthru;
    uint8_t                line_number;
    uint8_t                column;
    uint8_t                whole_word;
    uint8_t                line_regexp;
    uint8_t                multiline;
    size_t                 max_multiline_window;
    uint32_t               max_context_lines;
    uint64_t               max_compression_ratio;
    uint64_t               time_budget_ns;
    uint64_t               max_output_bytes;
    uint8_t                has_byte_range;
    uint8_t                has_byte_range_end;
    uint8_t                  range_align_lines;
    int32_t                  line_number_mode;
    uint64_t                 byte_range_start;
    uint64_t                 byte_range_end;
    uint64_t                 initial_line_number;
    webgrep_line_filter_cb   line_filter;
    void                    *line_filter_ctx;
    const char              *charset_ptr;
    size_t                   charset_len;
    const webgrep_pattern_t *contains_ptr;
    size_t                   contains_len;
    const webgrep_pattern_t *excludes_ptr;
    size_t                   excludes_len;
    uint8_t                  filter_case_insensitive;
    uint8_t                  filter_smart_case;
    const webgrep_cancel_t         *cancel;
    uint64_t                        resume_from;
    uint64_t                        progress_interval;
    const webgrep_matcher_t *const *contains_regexes_ptr;
    size_t                          contains_regexes_len;
    const webgrep_matcher_t *const *excludes_regexes_ptr;
    size_t                          excludes_regexes_len;
} webgrep_config_t;

#define WEBGREP_MAX_CAPTURE_GROUPS 32

/** Single capture group byte range inside a searched slice. */
typedef struct webgrep_capture_group_s {
    size_t  start;
    size_t  end;
    uint8_t matched;
} webgrep_capture_group_t;

/** Full regex capture match (`$0` plus `$1`..`$32`). */
typedef struct webgrep_captures_s {
    webgrep_capture_group_t full;
    webgrep_capture_group_t groups[WEBGREP_MAX_CAPTURE_GROUPS];
    size_t                  group_count;
} webgrep_captures_t;

/** Configuration for constructing an N-gram Bloom filter. */
typedef struct webgrep_bloom_config_s {
    uint32_t bit_count;
    uint8_t  num_hashes;
    uint8_t  ngram_len;
    uint8_t  ascii_lower;
} webgrep_bloom_config_t;

/** Summary populated by `webgrep_search_slice`, `webgrep_search_reader`, and `webgrep_search_reverse_slice`. */
typedef struct webgrep_summary_s {
    uint64_t matched_lines;
    uint64_t matches;
    uint64_t bytes_searched;
    uint64_t bytes_read;
    uint64_t elapsed_ns;
    uint8_t  stopped;
    uint8_t  partial;
    uint8_t  binary_detected;
    int      limit_hit;
    uint64_t resume_at;
    uint8_t  has_resume_at;
} webgrep_summary_t;

/** Tree & in-memory archive search configuration. */
typedef struct webgrep_tree_config_s {
    webgrep_config_t                search;
    int                             format;
    size_t                          max_entries;
    uint64_t                        max_entry_bytes;
    uint64_t                        max_total_bytes;
    uint64_t                        max_compression_ratio;
    size_t                          max_depth;
    size_t                          max_concurrency;
    uint8_t                         hidden;
    uint8_t                         skip_git;
    uint8_t                         respect_gitignore;
    uint8_t                         respect_ignore;
    size_t                          max_ignore_file_bytes;
    size_t                          max_glob_rules;
    size_t                          max_glob_rule_len;
    size_t                          max_glob_brace_depth;
    webgrep_archive_entry_filter_cb entry_filter;
    void                           *entry_filter_ctx;
    uint32_t                        max_archive_depth;
} webgrep_tree_config_t;

/** Summary populated by `webgrep_search_archive_slice`. */
typedef struct webgrep_tree_summary_s {
    uint64_t files_searched;
    uint64_t matched_files;
    uint64_t matched_lines;
    uint64_t matches;
    uint64_t bytes_searched;
    uint64_t files_skipped_binary;
    uint64_t files_failed;
    uint8_t  stopped;
} webgrep_tree_summary_t;

/* ============================================================================
 * Callback Signatures
 * ========================================================================= */

/** Flow control directive populated by `webgrep_flow_line_cb`. */
typedef struct webgrep_flow_s {
    int      action;
    uint64_t skip_to_offset;
} webgrep_flow_t;

/**
 * Flow-control line callback invoked synchronously by `webgrep_search_slice_flow` and
 * `webgrep_search_reader_flow`.
 * `*out_flow` is initialized to `{ WEBGREP_FLOW_CONT, 0 }` before each invocation.
 * Set `out_flow->action` to `WEBGREP_FLOW_STOP`, `WEBGREP_FLOW_PAUSE`, or
 * `WEBGREP_FLOW_SKIP_TO` (with `out_flow->skip_to_offset`) to steer the search engine.
 */
typedef void (*webgrep_flow_line_cb)(
    const webgrep_line_event_t *ev,
    void                       *userdata,
    webgrep_flow_t             *out_flow
);

/**
 * Line callback invoked synchronously for each matched or context line.
 * Borrowed pointers inside `ev` are valid only until this callback returns.
 * Return 0 to continue searching, or any non-zero value to stop early.
 */
typedef int (*webgrep_line_cb)(const webgrep_line_event_t *ev, void *userdata);

/**
 * Streaming read callback invoked by `webgrep_search_reader`.
 * Reads up to `cap` bytes into `buf` and writes the number of bytes read into `*out_n`.
 * Setting `*out_n = 0` indicates EOF.
 * Return 0 on success, or any non-zero value on read error.
 */
typedef int (*webgrep_read_cb)(uint8_t *buf, size_t cap, size_t *out_n, void *userdata);

/**
 * Random-access positional read callback invoked by `webgrep_search_range`,
 * `webgrep_search_reverse_at`, `webgrep_probe_line_at`, `webgrep_zstd_seek_table_*`,
 * and `webgrep_gzip_index_read_at`.
 * Reads up to `cap` bytes starting at `offset` into `buf` and writes bytes read into `*out_n`.
 * Return 0 on success (`*out_n = 0` at EOF), or any non-zero value on error.
 */
typedef int (*webgrep_read_at_cb)(uint64_t offset, uint8_t *buf, size_t cap, size_t *out_n, void *userdata);

/* ============================================================================
 * Exported C ABI Functions (59 Functions)
 * ========================================================================= */

/** 1. Returns the null-terminated semantic version string ("0.10.0"). */
WEBGREP_API const char *webgrep_version(void);

/** 2. Returns default literal/multi find options by value. */
WEBGREP_API webgrep_find_options_t webgrep_find_options_default(void);

/** 3. Returns default regex compilation options by value. */
WEBGREP_API webgrep_regex_options_t webgrep_regex_options_default(void);

/** 4. Returns default search configuration by value. */
WEBGREP_API webgrep_config_t webgrep_config_default(void);

/** 5. Returns default tree/archive search configuration by value. */
WEBGREP_API webgrep_tree_config_t webgrep_tree_config_default(void);

/** 6. Compiles a single-literal SIMD `Finder` matcher. Returns 0 (`WEBGREP_OK`) on success. */
WEBGREP_API int webgrep_matcher_compile_literal(
    const uint8_t                *pattern_ptr,
    size_t                        pattern_len,
    const webgrep_find_options_t *opts,
    webgrep_matcher_t           **out_matcher
);

/** 7. Compiles a multi-literal SIMD `Multi` matcher. Returns 0 (`WEBGREP_OK`) on success. */
WEBGREP_API int webgrep_matcher_compile_multi(
    const webgrep_pattern_t      *patterns_ptr,
    size_t                        patterns_len,
    const webgrep_find_options_t *opts,
    webgrep_matcher_t           **out_matcher
);

/** 8. Compiles a linear-time `Regex` matcher with optional diagnostic output on failure. */
WEBGREP_API int webgrep_matcher_compile_regex(
    const uint8_t                 *pattern_ptr,
    size_t                         pattern_len,
    const webgrep_regex_options_t *opts,
    webgrep_compile_diag_t        *out_diag,
    webgrep_matcher_t            **out_matcher
);

/** 9. Compiles a multi-pattern `RegexSet` matcher with optional diagnostic output on failure. */
WEBGREP_API int webgrep_matcher_compile_regex_set(
    const webgrep_pattern_t       *patterns_ptr,
    size_t                         patterns_len,
    const webgrep_regex_options_t *opts,
    webgrep_compile_diag_t        *out_diag,
    webgrep_matcher_t            **out_matcher
);

/** 10. Frees a compiled matcher handle. Safe to call with NULL. */
WEBGREP_API void webgrep_matcher_free(webgrep_matcher_t *matcher);

/** 11. Allocates a reusable per-thread scratch buffer pool (`webgrep_scratch_t`). Returns NULL on OOM. */
WEBGREP_API webgrep_scratch_t *webgrep_scratch_new(void);

/** 12. Frees a reusable scratch buffer pool. Safe to call with NULL. */
WEBGREP_API void webgrep_scratch_free(webgrep_scratch_t *scratch);

/**
 * 13. Finds the first match in `haystack_ptr[start_offset..haystack_len]` using `matcher`.
 * Returns 1 if a match was found (populating `*out_match`), 0 if no match, or < 0 on invalid arguments.
 */
WEBGREP_API int webgrep_find(
    const webgrep_matcher_t *matcher,
    const uint8_t           *haystack_ptr,
    size_t                   haystack_len,
    size_t                   start_offset,
    webgrep_match_t         *out_match
);

/**
 * 14. Evaluates a compiled `RegexSet` matcher against `haystack_ptr[0..haystack_len]` in a single pass,
 * writing matching 0-based pattern IDs into `out_ids_ptr` (up to `out_ids_cap`) and storing the count in `*out_count`.
 * Returns 0 (`WEBGREP_OK`) on success, or < 0 on invalid arguments or non-RegexSet matcher.
 */
WEBGREP_API int webgrep_regex_set_matches(
    const webgrep_matcher_t *matcher,
    const uint8_t           *haystack_ptr,
    size_t                   haystack_len,
    uint32_t                *out_ids_ptr,
    size_t                   out_ids_cap,
    size_t                  *out_count
);

/** 15. Searches an in-memory byte slice, invoking `on_line` for each matched or context line. */
WEBGREP_API int webgrep_search_slice(
    const webgrep_matcher_t *matcher,
    const uint8_t           *data_ptr,
    size_t                   data_len,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *userdata,
    webgrep_summary_t       *out_summary
);

/** 16. Searches a streaming reader driven by `read_cb`, invoking `on_line` for each matched or context line. */
WEBGREP_API int webgrep_search_reader(
    const webgrep_matcher_t *matcher,
    webgrep_read_cb          read_cb,
    void                    *read_userdata,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *line_userdata,
    webgrep_summary_t       *out_summary
);

/** 17. Unpacks and searches an in-memory archive (`.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`) without touching disk. */
WEBGREP_API int webgrep_search_archive_slice(
    const webgrep_matcher_t     *matcher,
    const uint8_t               *archive_ptr,
    size_t                       archive_len,
    const webgrep_tree_config_t *tree_cfg,
    webgrep_line_cb              on_line,
    void                        *userdata,
    webgrep_tree_summary_t      *out_summary
);

/** 18. Returns default byte-offset line probe options by value. */
WEBGREP_API webgrep_probe_options_t webgrep_probe_options_default(void);

/**
 * 19. Zero-allocation byte-offset line probe over `data_ptr[0..data_len]`.
 * Pass `opts = NULL` for default options (`delimiter = '\n'`, `strip_crlf = 1`, `max_line_bytes = 2 MiB`).
 * Borrowed `out_probe->bytes_ptr` points directly into `data_ptr`.
 * Returns 1 if `offset < data_len` (populating `*out_probe`), 0 if empty or `offset >= data_len`,
 * or < 0 (`WEBGREP_ERR_INVALID_ARG`) on invalid arguments.
 */
WEBGREP_API int webgrep_probe_line_slice(
    const uint8_t                 *data_ptr,
    size_t                         data_len,
    uint64_t                       offset,
    const webgrep_probe_options_t *opts,
    webgrep_line_probe_t          *out_probe
);

/**
 * 20. Searches an in-memory byte slice backward from the end (or `cfg->byte_range`),
 * invoking `on_line` for each matching line in newest-first (reverse) order.
 */
WEBGREP_API int webgrep_search_reverse_slice(
    const webgrep_matcher_t *matcher,
    const uint8_t           *data_ptr,
    size_t                   data_len,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *userdata,
    webgrep_summary_t       *out_summary
);

/** 21. Allocates a thread-safe atomic cancellation token. Returns NULL on OOM. */
WEBGREP_API webgrep_cancel_t *webgrep_cancel_new(void);

/** 22. Signals cancellation on `cancel`. Thread-safe. No-op if NULL. */
WEBGREP_API void webgrep_cancel_trigger(webgrep_cancel_t *cancel);

/** 23. Resets `cancel` back to non-cancelled state. Thread-safe. No-op if NULL. */
WEBGREP_API void webgrep_cancel_reset(webgrep_cancel_t *cancel);

/** 24. Frees a cancellation token. Safe to call with NULL. */
WEBGREP_API void webgrep_cancel_free(webgrep_cancel_t *cancel);

/**
 * 25. Finds the next regex match with submatch capture groups `$0`..`$32`.
 * `match_mode`: 0 = earliest, 1 = leftmost_first. `scratch` may be NULL.
 * Returns 1 on match, 0 if no match, or < 0 on invalid arguments or non-Regex matcher.
 */
WEBGREP_API int webgrep_find_captures(
    const webgrep_matcher_t *matcher,
    const uint8_t           *haystack_ptr,
    size_t                   haystack_len,
    size_t                   start_offset,
    int                      match_mode,
    webgrep_scratch_t       *scratch,
    webgrep_captures_t      *out_captures
);

/**
 * 26. Resolves a named capture group `(?P<name>...)` / `(?<name>...)` to its 1-based capture index (1..32).
 * Returns 1..32 if found, 0 if not found, or < 0 on invalid arguments or non-Regex matcher.
 */
WEBGREP_API int webgrep_matcher_group_index(
    const webgrep_matcher_t *matcher,
    const char              *name_ptr,
    size_t                   name_len
);

/**
 * 27. Searches byte range `[range_start, range_end)` over a random-access `read_at_cb` source.
 */
WEBGREP_API int webgrep_search_range(
    const webgrep_matcher_t *matcher,
    webgrep_read_at_cb       read_at_cb,
    void                    *read_userdata,
    uint64_t                 total_size,
    uint8_t                  has_total_size,
    uint64_t                 range_start,
    uint64_t                 range_end,
    uint8_t                  has_range_end,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *line_userdata,
    webgrep_summary_t       *out_summary
);

/**
 * 28. Searches backward in newest-first order over a random-access `read_at_cb` source.
 */
WEBGREP_API int webgrep_search_reverse_at(
    const webgrep_matcher_t *matcher,
    webgrep_read_at_cb       read_at_cb,
    void                    *read_userdata,
    uint64_t                 total_size,
    uint8_t                  has_total_size,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *line_userdata,
    webgrep_summary_t       *out_summary
);

/**
 * 29. Zero-allocation byte-offset line probe over a random-access `read_at_cb` source into `buf_ptr[0..buf_cap]`.
 * Borrowed `out_probe->bytes_ptr` points into `buf_ptr`. Returns 1 on hit, 0 if EOF/empty, or < 0 on error.
 */
WEBGREP_API int webgrep_probe_line_at(
    webgrep_read_at_cb             read_at_cb,
    void                          *read_userdata,
    uint64_t                       total_size,
    uint8_t                        has_total_size,
    uint64_t                       offset,
    uint8_t                       *buf_ptr,
    size_t                         buf_cap,
    const webgrep_probe_options_t *opts,
    webgrep_line_probe_t          *out_probe
);

/** 30. Opens a pull-mode event iterator over an in-memory slice. Caller must keep `data_ptr` alive until freed. */
WEBGREP_API int webgrep_pull_open_slice(
    const webgrep_matcher_t *matcher,
    const uint8_t           *data_ptr,
    size_t                   data_len,
    const webgrep_config_t  *cfg,
    webgrep_pull_t         **out_pull
);

/** 31. Opens a pull-mode streaming event iterator driven by `read_cb`. */
WEBGREP_API int webgrep_pull_open_reader(
    const webgrep_matcher_t *matcher,
    webgrep_read_cb          read_cb,
    void                    *read_userdata,
    const webgrep_config_t  *cfg,
    webgrep_pull_t         **out_pull
);

/**
 * 32. Advances the pull iterator to the next matched/context line.
 * Returns 1 and fills `*out_event` (borrowed pointers valid until the next `webgrep_pull_next` or `webgrep_pull_free`),
 * 0 at end-of-stream (filling `*out_summary` if non-NULL), or < 0 on error.
 */
WEBGREP_API int webgrep_pull_next(
    webgrep_pull_t       *pull,
    webgrep_line_event_t *out_event,
    webgrep_summary_t    *out_summary
);

/** 33. Frees a pull iterator handle. Safe to call with NULL. */
WEBGREP_API void webgrep_pull_free(webgrep_pull_t *pull);

/**
 * 34. Searches a streaming archive reader (`.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`).
 * Streams TAR archives in constant memory without buffering the full archive.
 */
WEBGREP_API int webgrep_search_archive_reader(
    const webgrep_matcher_t     *matcher,
    webgrep_read_cb              read_cb,
    void                        *read_userdata,
    const webgrep_tree_config_t *tree_cfg,
    webgrep_line_cb              on_line,
    void                        *line_userdata,
    webgrep_tree_summary_t      *out_summary
);

/** 35. Returns default N-gram Bloom filter configuration by value. */
WEBGREP_API webgrep_bloom_config_t webgrep_bloom_config_default(void);

/** 36. Creates an N-gram Bloom filter handle. */
WEBGREP_API int webgrep_bloom_new(
    const webgrep_bloom_config_t *cfg,
    webgrep_bloom_t             **out_bloom
);

/** 37. Frees an N-gram Bloom filter handle. Safe to call with NULL. */
WEBGREP_API void webgrep_bloom_free(webgrep_bloom_t *bloom);

/** 38. Indexes `data_ptr[0..data_len]` N-grams into `bloom`. */
WEBGREP_API int webgrep_bloom_add(
    webgrep_bloom_t *bloom,
    const uint8_t   *data_ptr,
    size_t           data_len
);

/** 39. Unions bits from `src` into `dst` (both must share identical configuration). */
WEBGREP_API int webgrep_bloom_merge(
    webgrep_bloom_t       *dst,
    const webgrep_bloom_t *src
);

/**
 * 40. Zero-false-negative pre-screen check: returns 1 if `matcher` may match, 0 if definitely absent,
 * or < 0 on invalid arguments.
 */
WEBGREP_API int webgrep_bloom_may_contain(
    const webgrep_bloom_t   *bloom,
    const webgrep_matcher_t *matcher
);

/**
 * 41. Serializes `bloom` into `out_buf[0..out_cap]`.
 * Pass `out_buf = NULL` to query the required byte length in `*out_len` (`WEBGREP_OK`).
 * Returns `WEBGREP_ERR_TOO_LARGE` (while writing `*out_len`) if `out_cap` is smaller than required.
 */
WEBGREP_API int webgrep_bloom_serialize(
    const webgrep_bloom_t *bloom,
    uint8_t               *out_buf,
    size_t                 out_cap,
    size_t                *out_len
);

/** 42. Deserializes an N-gram Bloom filter from `data_ptr[0..data_len]`. */
WEBGREP_API int webgrep_bloom_deserialize(
    const uint8_t    *data_ptr,
    size_t            data_len,
    webgrep_bloom_t **out_bloom
);

/** 43. Parses a Zstd Seek Table footer from a random-access `read_at_cb` source. */
WEBGREP_API int webgrep_zstd_seek_table_parse(
    webgrep_read_at_cb           read_at_cb,
    void                        *read_userdata,
    uint64_t                     total_size,
    webgrep_zstd_seek_table_t **out_table
);

/** 44. Frees a parsed Zstd Seek Table handle. Safe to call with NULL. */
WEBGREP_API void webgrep_zstd_seek_table_free(webgrep_zstd_seek_table_t *table);

/** 45. Returns the total uncompressed byte size covered by `table` (or 0 if NULL). */
WEBGREP_API uint64_t webgrep_zstd_seek_table_uncompressed_size(const webgrep_zstd_seek_table_t *table);

/** 46. Random-access reads uncompressed bytes at `uncomp_offset` using `table` and `read_at_cb`. */
WEBGREP_API int webgrep_zstd_seek_table_read_at(
    const webgrep_zstd_seek_table_t *table,
    webgrep_read_at_cb               read_at_cb,
    void                            *read_userdata,
    uint64_t                         total_size,
    uint64_t                         uncomp_offset,
    uint8_t                         *out_buf,
    size_t                           out_cap,
    uint64_t                         max_ratio,
    size_t                          *out_n
);

/** 47. Builds an indexed Gzip checkpoint table by streaming `read_cb`. */
WEBGREP_API int webgrep_gzip_index_build(
    webgrep_read_cb        read_cb,
    void                  *read_userdata,
    uint64_t               checkpoint_interval,
    webgrep_gzip_index_t **out_index
);

/** 48. Frees a Gzip index handle. Safe to call with NULL. */
WEBGREP_API void webgrep_gzip_index_free(webgrep_gzip_index_t *index);

/** 49. Returns the total uncompressed byte size indexed by `index` (or 0 if NULL). */
WEBGREP_API uint64_t webgrep_gzip_index_uncompressed_size(const webgrep_gzip_index_t *index);

/**
 * 50. Serializes `index` into `out_buf[0..out_cap]`.
 * Pass `out_buf = NULL` to query the required byte length in `*out_len` (`WEBGREP_OK`).
 * Returns `WEBGREP_ERR_TOO_LARGE` (while writing `*out_len`) if `out_cap` is smaller than required.
 */
WEBGREP_API int webgrep_gzip_index_serialize(
    const webgrep_gzip_index_t *index,
    uint8_t                    *out_buf,
    size_t                      out_cap,
    size_t                     *out_len
);

/** 51. Deserializes an indexed Gzip table from `data_ptr[0..data_len]`. */
WEBGREP_API int webgrep_gzip_index_deserialize(
    const uint8_t         *data_ptr,
    size_t                 data_len,
    webgrep_gzip_index_t **out_index
);

/** 52. Random-access reads uncompressed bytes at `uncomp_offset` using `index` and `read_at_cb`. */
WEBGREP_API int webgrep_gzip_index_read_at(
    const webgrep_gzip_index_t *index,
    webgrep_read_at_cb          read_at_cb,
    void                       *read_userdata,
    uint64_t                    total_size,
    uint8_t                     has_total_size,
    uint64_t                    uncomp_offset,
    uint8_t                    *out_buf,
    size_t                      out_cap,
    size_t                     *out_n
);

/** 53. Allocates a stateless resume state cursor for pause/resume pagination. Free with `webgrep_resume_state_free`. */
WEBGREP_API webgrep_resume_state_t *webgrep_resume_state_new(void);

/** 54. Frees a resume state cursor. Safe to call with NULL. */
WEBGREP_API void webgrep_resume_state_free(webgrep_resume_state_t *state);

/** 55. Resets a resume state cursor back to initial unpaused state. No-op if NULL. */
WEBGREP_API void webgrep_resume_state_reset(webgrep_resume_state_t *state);

/** 56. Returns the next searchable byte offset recorded in `state` (or 0 if NULL/initial). */
WEBGREP_API uint64_t webgrep_resume_state_offset(const webgrep_resume_state_t *state);

/** 57. Returns 1 if `state` currently represents a paused search that can be resumed, 0 otherwise. */
WEBGREP_API uint8_t webgrep_resume_state_is_paused(const webgrep_resume_state_t *state);

/**
 * 58. Searches an in-memory slice with full `Flow` control (`cont`, `stop`, `pause`, `skip_to`)
 * and optional stateless `resume_state` pagination.
 * When `resume_state` is non-NULL and paused, resumes seamlessly without re-emitting `begin`,
 * and updates `resume_state` upon completion or pause.
 */
WEBGREP_API int webgrep_search_slice_flow(
    const webgrep_matcher_t *matcher,
    const uint8_t           *data_ptr,
    size_t                   data_len,
    const webgrep_config_t  *cfg,
    webgrep_resume_state_t  *resume_state,
    webgrep_flow_line_cb     on_line,
    void                    *userdata,
    webgrep_summary_t       *out_summary
);

/**
 * 59. Searches a streaming `read_cb` source with full `Flow` control (`cont`, `stop`, `pause`, `skip_to`)
 * and optional stateless `resume_state` pagination.
 */
WEBGREP_API int webgrep_search_reader_flow(
    const webgrep_matcher_t *matcher,
    webgrep_read_cb          read_cb,
    void                    *read_userdata,
    const webgrep_config_t  *cfg,
    webgrep_resume_state_t  *resume_state,
    webgrep_flow_line_cb     on_line,
    void                    *userdata,
    webgrep_summary_t       *out_summary
);

#ifdef __cplusplus
}
#endif

#endif /* WEBGREP_H */
