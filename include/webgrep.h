/**
 * @file webgrep.h
 * @brief C ABI and Cross-Language FFI Header for libwebgrep v0.3.0.
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

/* ============================================================================
 * Version Information
 * ========================================================================= */

#define WEBGREP_VERSION_MAJOR 0
#define WEBGREP_VERSION_MINOR 3
#define WEBGREP_VERSION_PATCH 0
#define WEBGREP_VERSION_STRING "0.3.0"

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
    WEBGREP_ENCODING_AUTO    = 0,
    WEBGREP_ENCODING_UTF8    = 1,
    WEBGREP_ENCODING_UTF16LE = 2,
    WEBGREP_ENCODING_UTF16BE = 3,
    WEBGREP_ENCODING_GBK     = 4,
    WEBGREP_ENCODING_LATIN1  = 5,
    WEBGREP_ENCODING_NONE    = 6
} webgrep_encoding_t;

/** Streaming decompression mode. */
typedef enum webgrep_compression_e {
    WEBGREP_COMPRESSION_NONE = 0,
    WEBGREP_COMPRESSION_AUTO = 1,
    WEBGREP_COMPRESSION_GZIP = 2,
    WEBGREP_COMPRESSION_ZSTD = 3,
    WEBGREP_COMPRESSION_XZ   = 4
} webgrep_compression_t;

/** In-memory archive format. */
typedef enum webgrep_archive_format_e {
    WEBGREP_ARCHIVE_AUTO    = 0,
    WEBGREP_ARCHIVE_TAR     = 1,
    WEBGREP_ARCHIVE_TAR_GZ  = 2,
    WEBGREP_ARCHIVE_TAR_ZST = 3,
    WEBGREP_ARCHIVE_TAR_XZ  = 4,
    WEBGREP_ARCHIVE_ZIP     = 5
} webgrep_archive_format_t;

/** Budget limit reached during a search. */
typedef enum webgrep_limit_hit_e {
    WEBGREP_LIMIT_NONE               = 0,
    WEBGREP_LIMIT_MAX_RESULTS        = 1,
    WEBGREP_LIMIT_MAX_BYTES          = 2,
    WEBGREP_LIMIT_DEADLINE           = 3,
    WEBGREP_LIMIT_DECOMPRESSED_BYTES = 4,
    WEBGREP_LIMIT_CANCELLED          = 5
} webgrep_limit_hit_t;

/* ============================================================================
 * Opaque Handles
 * ========================================================================= */

/** Opaque compiled matcher handle (`Finder`, `Multi`, `Regex`, or `RegexSet`). Thread-safe for concurrent searches. */
typedef struct webgrep_matcher_s webgrep_matcher_t;

/** Opaque per-thread reusable scratch buffer pool (`Scratch`). Not shared concurrently across threads. */
typedef struct webgrep_scratch_s webgrep_scratch_t;

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
    size_t   max_patterns;
    size_t   max_pattern_bytes;
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
} webgrep_line_event_t;

/** Search configuration for slice and streaming searches. */
typedef struct webgrep_config_s {
    webgrep_scratch_t *scratch;
    const uint8_t     *replacement_ptr;
    size_t             replacement_len;
    uint32_t           before_context;
    uint32_t           after_context;
    uint64_t           max_count;
    uint64_t           max_results;
    uint64_t           max_bytes;
    size_t             max_decode_bytes;
    size_t             buffer_size;
    size_t             max_line_len;
    int                encoding;
    int                compression;
    int                binary_mode;
    int                match_mode;
    uint8_t            invert_match;
    uint8_t            passthru;
    uint8_t            line_number;
    uint8_t            column;
    uint8_t            whole_word;
    uint8_t            line_regexp;
} webgrep_config_t;

/** Summary populated by `webgrep_search_slice` and `webgrep_search_reader`. */
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
} webgrep_summary_t;

/** Tree & in-memory archive search configuration. */
typedef struct webgrep_tree_config_s {
    webgrep_config_t search;
    int              format;
    size_t           max_entries;
    uint64_t         max_entry_bytes;
    uint64_t         max_total_bytes;
    uint64_t         max_compression_ratio;
    size_t           max_depth;
    size_t           max_concurrency;
    uint8_t          hidden;
    uint8_t          skip_git;
    uint8_t          respect_gitignore;
    uint8_t          respect_ignore;
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

/* ============================================================================
 * Exported C ABI Functions (17 Functions)
 * ========================================================================= */

/** 1. Returns the null-terminated semantic version string ("0.3.0"). */
const char *webgrep_version(void);

/** 2. Returns default literal/multi find options by value. */
webgrep_find_options_t webgrep_find_options_default(void);

/** 3. Returns default regex compilation options by value. */
webgrep_regex_options_t webgrep_regex_options_default(void);

/** 4. Returns default search configuration by value. */
webgrep_config_t webgrep_config_default(void);

/** 5. Returns default tree/archive search configuration by value. */
webgrep_tree_config_t webgrep_tree_config_default(void);

/** 6. Compiles a single-literal SIMD `Finder` matcher. Returns 0 (`WEBGREP_OK`) on success. */
int webgrep_matcher_compile_literal(
    const uint8_t                *pattern_ptr,
    size_t                        pattern_len,
    const webgrep_find_options_t *opts,
    webgrep_matcher_t           **out_matcher
);

/** 7. Compiles a multi-literal SIMD `Multi` matcher. Returns 0 (`WEBGREP_OK`) on success. */
int webgrep_matcher_compile_multi(
    const webgrep_pattern_t      *patterns_ptr,
    size_t                        patterns_len,
    const webgrep_find_options_t *opts,
    webgrep_matcher_t           **out_matcher
);

/** 8. Compiles a linear-time `Regex` matcher with optional diagnostic output on failure. */
int webgrep_matcher_compile_regex(
    const uint8_t                 *pattern_ptr,
    size_t                         pattern_len,
    const webgrep_regex_options_t *opts,
    webgrep_compile_diag_t        *out_diag,
    webgrep_matcher_t            **out_matcher
);

/** 9. Compiles a multi-pattern `RegexSet` matcher with optional diagnostic output on failure. */
int webgrep_matcher_compile_regex_set(
    const webgrep_pattern_t       *patterns_ptr,
    size_t                         patterns_len,
    const webgrep_regex_options_t *opts,
    webgrep_compile_diag_t        *out_diag,
    webgrep_matcher_t            **out_matcher
);

/** 10. Frees a compiled matcher handle. Safe to call with NULL. */
void webgrep_matcher_free(webgrep_matcher_t *matcher);

/** 11. Allocates a reusable per-thread scratch buffer pool (`webgrep_scratch_t`). Returns NULL on OOM. */
webgrep_scratch_t *webgrep_scratch_new(void);

/** 12. Frees a reusable scratch buffer pool. Safe to call with NULL. */
void webgrep_scratch_free(webgrep_scratch_t *scratch);

/**
 * 13. Finds the first match in `haystack_ptr[start_offset..haystack_len]` using `matcher`.
 * Returns 1 if a match was found (populating `*out_match`), 0 if no match, or < 0 on invalid arguments.
 */
int webgrep_find(
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
int webgrep_regex_set_matches(
    const webgrep_matcher_t *matcher,
    const uint8_t           *haystack_ptr,
    size_t                   haystack_len,
    uint32_t                *out_ids_ptr,
    size_t                   out_ids_cap,
    size_t                  *out_count
);

/** 15. Searches an in-memory byte slice, invoking `on_line` for each matched or context line. */
int webgrep_search_slice(
    const webgrep_matcher_t *matcher,
    const uint8_t           *data_ptr,
    size_t                   data_len,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *userdata,
    webgrep_summary_t       *out_summary
);

/** 16. Searches a streaming reader driven by `read_cb`, invoking `on_line` for each matched or context line. */
int webgrep_search_reader(
    const webgrep_matcher_t *matcher,
    webgrep_read_cb          read_cb,
    void                    *read_userdata,
    const webgrep_config_t  *cfg,
    webgrep_line_cb          on_line,
    void                    *line_userdata,
    webgrep_summary_t       *out_summary
);

/** 17. Unpacks and searches an in-memory archive (`.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`) without touching disk. */
int webgrep_search_archive_slice(
    const webgrep_matcher_t     *matcher,
    const uint8_t               *archive_ptr,
    size_t                       archive_len,
    const webgrep_tree_config_t *tree_cfg,
    webgrep_line_cb              on_line,
    void                        *userdata,
    webgrep_tree_summary_t      *out_summary
);

#ifdef __cplusplus
}
#endif

#endif /* WEBGREP_H */
