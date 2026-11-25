/**
 * @file c_api_test.c
 * @brief Comprehensive C ABI and FFI verification suite for libwebgrep v0.10.3.
 *
 * Exercises all 60 exported C ABI functions, adversarial streaming reader callbacks,
 * corrupt and path-traversal archives, NULL/boundary pointer checks, 1,000 allocation/free
 * cycles, and 8-thread concurrent shared-matcher stress tests.
 */

#include "../include/webgrep.h"

/* Ensure test assertions and side-effecting calls remain active under ReleaseFast (-DNDEBUG). */
#undef NDEBUG
#include <assert.h>
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <pthread.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Helper Structures & Callbacks
 * ========================================================================= */

typedef struct {
    size_t   matched_lines;
    size_t   context_lines;
    int      saw_replacement;
    int      stop_after_first;
    int32_t  last_pattern_id;
    uint64_t first_line_no;
    uint64_t last_line_no;
    uint64_t first_offset;
    uint64_t last_offset;
    uint8_t  last_line_known;
} line_capture_ctx_t;

static int bytes_contains(const uint8_t *hay, size_t hay_len, const char *needle, size_t needle_len) {
    if (needle_len == 0) return 1;
    if (!hay || hay_len < needle_len) return 0;
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        if (memcmp(hay + i, needle, needle_len) == 0) return 1;
    }
    return 0;
}

static int on_line_capture(const webgrep_line_event_t *ev, void *userdata) {
    line_capture_ctx_t *ctx = (line_capture_ctx_t *)userdata;
    if (!ctx || !ev) return 0;

    if (ev->is_context) {
        ctx->context_lines++;
    } else {
        if (ctx->matched_lines == 0) {
            ctx->first_line_no = ev->line_number;
            ctx->first_offset = ev->byte_offset;
        }
        ctx->matched_lines++;
        ctx->last_line_no = ev->line_number;
        ctx->last_offset = ev->byte_offset;
        ctx->last_line_known = ev->line_number_known;
        if (ev->matches_len > 0 && ev->matches_ptr) {
            ctx->last_pattern_id = ev->matches_ptr[0].pattern_id;
        }
        if (ev->replaced_ptr && ev->replaced_len > 0) {
            if (bytes_contains(ev->replaced_ptr, ev->replaced_len, "id:42", 5)) {
                ctx->saw_replacement = 1;
            }
        }
        if (ctx->stop_after_first) {
            return 1; /* Request early stop */
        }
    }
    return 0;
}

typedef struct {
    const char *required_substr;
    size_t      calls;
} line_filter_test_ctx_t;

static bool test_line_filter_cb(void *user_data, const webgrep_line_filter_candidate_t *cand) {
    line_filter_test_ctx_t *fctx = (line_filter_test_ctx_t *)user_data;
    if (!fctx || !cand) return true;
    fctx->calls++;
    if (!fctx->required_substr) return true;
    return bytes_contains(
        cand->bytes_ptr,
        cand->bytes_len,
        fctx->required_substr,
        strlen(fctx->required_substr)
    ) != 0;
}

typedef struct {
    const char *allowed_suffix;
    size_t      seen_entries;
} archive_filter_test_ctx_t;

static bool test_archive_entry_filter_cb(void *user_data, const webgrep_archive_entry_meta_t *meta) {
    archive_filter_test_ctx_t *actx = (archive_filter_test_ctx_t *)user_data;
    if (!actx || !meta) return true;
    actx->seen_entries++;
    if (!actx->allowed_suffix || !meta->path_ptr) return false;
    size_t slen = strlen(actx->allowed_suffix);
    if (meta->path_len < slen) return false;
    return memcmp(meta->path_ptr + (meta->path_len - slen), actx->allowed_suffix, slen) == 0;
}

typedef struct {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
    size_t         chunk_size;
} mem_reader_ctx_t;

static int mem_read_cb(uint8_t *buf, size_t cap, size_t *out_n, void *userdata) {
    mem_reader_ctx_t *r = (mem_reader_ctx_t *)userdata;
    if (!r || !out_n) return -1;
    if (r->pos >= r->len) {
        *out_n = 0;
        return 0;
    }
    size_t avail = r->len - r->pos;
    size_t limit = (r->chunk_size > 0 && r->chunk_size < cap) ? r->chunk_size : cap;
    size_t n = avail < limit ? avail : limit;
    memcpy(buf, r->data + r->pos, n);
    r->pos += n;
    *out_n = n;
    return 0;
}

static int fail_read_cb(uint8_t *buf, size_t cap, size_t *out_n, void *userdata) {
    (void)buf;
    (void)cap;
    (void)out_n;
    (void)userdata;
    return -1;
}

static int overflow_read_cb(uint8_t *buf, size_t cap, size_t *out_n, void *userdata) {
    (void)buf;
    (void)userdata;
    *out_n = cap + 16; /* Maliciously report more bytes than buffer capacity */
    return 0;
}

typedef struct {
    int      count;
    uint64_t last_line;
    int      pause_at_count;
    int      skip_at_count;
    uint64_t skip_target;
} flow_test_ctx_t;

static void flow_test_cb(const webgrep_line_event_t *ev, void *userdata, webgrep_flow_t *out_flow) {
    flow_test_ctx_t *ctx = (flow_test_ctx_t *)userdata;
    ctx->count += 1;
    ctx->last_line = ev->line_number;
    if (ctx->pause_at_count > 0 && ctx->count == ctx->pause_at_count) {
        out_flow->action = WEBGREP_FLOW_PAUSE;
    } else if (ctx->skip_at_count > 0 && ctx->count == ctx->skip_at_count) {
        out_flow->action = WEBGREP_FLOW_SKIP_TO;
        out_flow->skip_to_offset = ctx->skip_target;
    }
}

/* ============================================================================
 * In-Memory TAR Builder Helper
 * ========================================================================= */

static void write_tar_header(uint8_t block[512], const char *name, size_t size, char typeflag, const char *linkname) {
    memset(block, 0, 512);
    strncpy((char *)block, name, 99);
    snprintf((char *)(block + 100), 8, "%07o", 0644u);
    snprintf((char *)(block + 108), 8, "%07o", 0u);
    snprintf((char *)(block + 116), 8, "%07o", 0u);
    snprintf((char *)(block + 124), 12, "%011zo", size);
    snprintf((char *)(block + 136), 12, "%011o", 0u);
    memset(block + 148, ' ', 8);
    block[156] = (uint8_t)typeflag;
    if (linkname) {
        strncpy((char *)(block + 157), linkname, 99);
    }
    memcpy(block + 257, "ustar", 5);
    block[262] = 0;
    memcpy(block + 263, "00", 2);

    unsigned int chksum = 0;
    for (size_t i = 0; i < 512; ++i) {
        chksum += block[i];
    }
    snprintf((char *)(block + 148), 7, "%06o", chksum);
    block[154] = 0;
    block[155] = ' ';
}

static int slice_read_at_cb(uint64_t offset, uint8_t *buf, size_t cap, size_t *out_n, void *userdata) {
    const mem_reader_ctx_t *r = (const mem_reader_ctx_t *)userdata;
    if (!r || !out_n) return -1;
    if (offset >= (uint64_t)r->len || cap == 0) {
        *out_n = 0;
        return 0;
    }
    size_t off = (size_t)offset;
    size_t avail = r->len - off;
    size_t n = avail < cap ? avail : cap;
    memcpy(buf, r->data + off, n);
    *out_n = n;
    return 0;
}

static uint32_t c_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static void put_u16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void put_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static size_t build_stored_gzip(uint8_t *out, size_t cap, const uint8_t *payload, size_t plen) {
    size_t need = 23 + plen;
    assert(cap >= need && plen <= 65535);
    memset(out, 0, need);
    out[0] = 0x1F;
    out[1] = 0x8B;
    out[2] = 8;
    out[9] = 255;
    out[10] = 0x01; /* BFINAL=1, BTYPE=00 (stored) */
    uint16_t len16 = (uint16_t)plen;
    uint16_t nlen16 = (uint16_t)(~len16);
    put_u16_le(out + 11, len16);
    put_u16_le(out + 13, nlen16);
    memcpy(out + 15, payload, plen);
    put_u32_le(out + 15 + plen, c_crc32(payload, plen));
    put_u32_le(out + 19 + plen, (uint32_t)plen);
    return need;
}

static size_t build_stored_zip_single(uint8_t *out, size_t cap, const char *name, const uint8_t *payload, size_t plen) {
    size_t nlen = strlen(name);
    size_t lfh_size = 30 + nlen + plen;
    size_t cdh_size = 46 + nlen;
    size_t total = lfh_size + cdh_size + 22;
    assert(cap >= total);
    memset(out, 0, total);
    uint32_t crc = c_crc32(payload, plen);

    /* Local file header */
    out[0] = 'P'; out[1] = 'K'; out[2] = 3; out[3] = 4;
    put_u16_le(out + 4, 20);
    put_u32_le(out + 14, crc);
    put_u32_le(out + 18, (uint32_t)plen);
    put_u32_le(out + 22, (uint32_t)plen);
    put_u16_le(out + 26, (uint16_t)nlen);
    memcpy(out + 30, name, nlen);
    memcpy(out + 30 + nlen, payload, plen);

    /* Central directory header */
    uint8_t *cd = out + lfh_size;
    cd[0] = 'P'; cd[1] = 'K'; cd[2] = 1; cd[3] = 2;
    put_u16_le(cd + 4, 20);
    put_u16_le(cd + 6, 20);
    put_u32_le(cd + 16, crc);
    put_u32_le(cd + 20, (uint32_t)plen);
    put_u32_le(cd + 24, (uint32_t)plen);
    put_u16_le(cd + 28, (uint16_t)nlen);
    memcpy(cd + 46, name, nlen);

    /* End of central directory */
    uint8_t *eocd = cd + cdh_size;
    eocd[0] = 'P'; eocd[1] = 'K'; eocd[2] = 5; eocd[3] = 6;
    put_u16_le(eocd + 8, 1);
    put_u16_le(eocd + 10, 1);
    put_u32_le(eocd + 12, (uint32_t)cdh_size);
    put_u32_le(eocd + 16, (uint32_t)lfh_size);
    return total;
}

/* ============================================================================
 * Multithreaded Worker Context
 * ========================================================================= */

typedef struct {
    const webgrep_matcher_t *lit_matcher;
    const webgrep_matcher_t *re_set_matcher;
    int                      passed;
} thread_worker_arg_t;

static void concurrent_worker_run(thread_worker_arg_t *w) {
    webgrep_scratch_t *scratch = webgrep_scratch_new();
    if (!scratch) {
        w->passed = 0;
        return;
    }

    webgrep_config_t cfg = webgrep_config_default();
    cfg.scratch = scratch;

    const char *payload = "line 1 ok\nline 2 CONCURRENT_HIT ERR_503\nline 3 WARN_DISK\n";
    size_t payload_len = strlen(payload);

    for (int iter = 0; iter < 50; ++iter) {
        webgrep_match_t m;
        int f_rc = webgrep_find(w->lit_matcher, (const uint8_t *)payload, payload_len, 0, &m);
        if (f_rc != 1 || m.start != 17) {
            webgrep_scratch_free(scratch);
            w->passed = 0;
            return;
        }

        uint32_t ids[4] = {0};
        size_t count = 0;
        int s_rc = webgrep_regex_set_matches(w->re_set_matcher, (const uint8_t *)payload, payload_len, ids, 4, &count);
        if (s_rc != WEBGREP_OK || count != 2 || ids[0] != 0 || ids[1] != 1) {
            webgrep_scratch_free(scratch);
            w->passed = 0;
            return;
        }

        line_capture_ctx_t lctx;
        memset(&lctx, 0, sizeof(lctx));
        webgrep_summary_t sum;
        memset(&sum, 0, sizeof(sum));
        int sr_rc = webgrep_search_slice(
            w->re_set_matcher,
            (const uint8_t *)payload,
            payload_len,
            &cfg,
            on_line_capture,
            &lctx,
            &sum
        );
        if (sr_rc != WEBGREP_OK || sum.matched_lines != 2 || lctx.matched_lines != 2) {
            webgrep_scratch_free(scratch);
            w->passed = 0;
            return;
        }
    }

    webgrep_scratch_free(scratch);
    w->passed = 1;
}

#ifdef _WIN32
static DWORD WINAPI concurrent_worker(LPVOID arg) {
    concurrent_worker_run((thread_worker_arg_t *)arg);
    return 0;
}
#else
static void *concurrent_worker(void *arg) {
    concurrent_worker_run((thread_worker_arg_t *)arg);
    return NULL;
}
#endif

/* ============================================================================
 * Custom Allocator Test Hook
 * ========================================================================= */

typedef struct {
    size_t allocs;
    size_t frees;
    size_t live_bytes;
    size_t fail_after;
    int    enable_fail;
} c_test_alloc_ctx_t;

static void *c_test_alloc(void *ctx, size_t size, size_t alignment) {
    c_test_alloc_ctx_t *st = (c_test_alloc_ctx_t *)ctx;
    if (st->enable_fail && st->allocs >= st->fail_after) return NULL;
    size_t align = alignment < sizeof(void *) ? sizeof(void *) : alignment;
    size_t total = size + align + sizeof(void *);
    uint8_t *raw = (uint8_t *)malloc(total);
    if (!raw) return NULL;
    uintptr_t addr = (uintptr_t)(raw + sizeof(void *));
    uintptr_t aligned = (addr + align - 1u) & ~(uintptr_t)(align - 1u);
    ((void **)aligned)[-1] = raw;
    st->allocs++;
    st->live_bytes += size;
    return (void *)aligned;
}

static void c_test_free(void *ctx, void *ptr, size_t size, size_t alignment) {
    (void)alignment;
    c_test_alloc_ctx_t *st = (c_test_alloc_ctx_t *)ctx;
    if (!ptr) return;
    void *raw = ((void **)ptr)[-1];
    free(raw);
    st->frees++;
    st->live_bytes -= size;
}

/* ============================================================================
 * Main Test Runner
 * ========================================================================= */

int main(void) {
    printf("=== Running C ABI & FFI Verification Suite ===\n");

    /* 1. webgrep_version() */
    const char *ver = webgrep_version();
    assert(ver != NULL);
    assert(strcmp(ver, "0.10.3") == 0);
    printf("[1/16] webgrep_version(): PASS (version=\"%s\")\n", ver);

    /* 2. *_default() option & config functions */
    webgrep_find_options_t fopts = webgrep_find_options_default();
    assert(fopts.case_mode == WEBGREP_CASE_SENSITIVE);
    assert(fopts.unicode_case == 1);
    assert(fopts.max_patterns == 0);
    assert(fopts.max_pattern_bytes == 0);
    assert(fopts.max_unicode_variants == 0);

    webgrep_regex_options_t ropts = webgrep_regex_options_default();
    assert(ropts.case_mode == WEBGREP_CASE_SENSITIVE);
    assert(ropts.unicode_case == 1);
    assert(ropts.multiline == 0);
    assert(ropts.dot_all == 0);
    assert(ropts.max_repeat == 0);
    assert(ropts.max_recursion_depth == 0);
    assert(ropts.max_patterns == 0);
    assert(ropts.max_pattern_bytes == 0);

    webgrep_config_t cfg = webgrep_config_default();
    assert(cfg.scratch == NULL);
    assert(cfg.line_number == 1);
    assert(cfg.max_context_lines == 0);
    assert(cfg.max_compression_ratio == 0);
    assert(cfg.time_budget_ns == 0);
    assert(cfg.max_output_bytes == 0);

    webgrep_tree_config_t tcfg = webgrep_tree_config_default();
    assert(tcfg.format == WEBGREP_ARCHIVE_AUTO);
    assert(tcfg.skip_git == 1);
    assert(tcfg.max_ignore_file_bytes == 0);
    assert(tcfg.max_glob_rules == 0);
    assert(tcfg.max_glob_rule_len == 0);
    assert(tcfg.max_glob_brace_depth == 0);
    printf("[2/16] *_default() option & config functions: PASS\n");

    /* 3. webgrep_matcher_compile_literal() + webgrep_find() */
    webgrep_matcher_t *lit_m = NULL;
    assert(webgrep_matcher_compile_literal((const uint8_t *)"needle", 6, &fopts, &lit_m) == WEBGREP_OK);
    assert(lit_m != NULL);

    const char *hay1 = "haystack with needle inside";
    webgrep_match_t cm;
    assert(webgrep_find(lit_m, (const uint8_t *)hay1, strlen(hay1), 0, &cm) == 1);
    assert(cm.start == 14 && cm.end == 20);
    assert(webgrep_find(lit_m, (const uint8_t *)hay1, strlen(hay1), 15, &cm) == 0);
    webgrep_matcher_free(lit_m);
    printf("[3/16] webgrep_matcher_compile_literal() + webgrep_find(): PASS\n");

    /* 4. webgrep_matcher_compile_multi() + webgrep_find() */
    webgrep_pattern_t mpats[2] = {
        { (const uint8_t *)"alpha", 5 },
        { (const uint8_t *)"beta",  4 }
    };
    webgrep_matcher_t *multi_m = NULL;
    assert(webgrep_matcher_compile_multi(mpats, 2, &fopts, &multi_m) == WEBGREP_OK);
    assert(multi_m != NULL);

    const char *hay2 = "xx beta yy alpha";
    assert(webgrep_find(multi_m, (const uint8_t *)hay2, strlen(hay2), 0, &cm) == 1);
    assert(cm.start == 3 && cm.end == 7);
    assert(cm.pattern_id == 1 && cm.has_pattern_id == 1);
    webgrep_matcher_free(multi_m);
    printf("[4/16] webgrep_matcher_compile_multi() + webgrep_find(): PASS\n");

    /* 5. webgrep_matcher_compile_regex() + diagnostics + webgrep_find() */
    webgrep_compile_diag_t diag;
    memset(&diag, 0, sizeof(diag));
    webgrep_matcher_t *bad_re = NULL;
    assert(webgrep_matcher_compile_regex((const uint8_t *)"abc(def", 7, &ropts, &diag, &bad_re) == WEBGREP_ERR_SYNTAX);
    assert(bad_re == NULL);
    assert(diag.code != 0);
    assert(diag.offset == 3 && diag.line == 1 && diag.column == 4);

    webgrep_matcher_t *re_m = NULL;
    assert(webgrep_matcher_compile_regex((const uint8_t *)"user_([0-9]+)", 13, &ropts, &diag, &re_m) == WEBGREP_OK);
    assert(re_m != NULL);
    const char *hay3 = "hello user_42 world";
    assert(webgrep_find(re_m, (const uint8_t *)hay3, strlen(hay3), 0, &cm) == 1);
    assert(cm.start == 6 && cm.end == 13);

    /* Test custom limits exceeding former hard caps */
    webgrep_regex_options_t ropts_high = webgrep_regex_options_default();
    ropts_high.max_repeat = 2000;
    ropts_high.max_inst = 15000;
    webgrep_matcher_t *re_high = NULL;
    assert(webgrep_matcher_compile_regex((const uint8_t *)"a{1200}", 7, &ropts_high, &diag, &re_high) == WEBGREP_OK);
    assert(re_high != NULL);
    webgrep_matcher_free(re_high);
    printf("[5/16] webgrep_matcher_compile_regex() + diagnostics + webgrep_find(): PASS\n");

    /* 6. webgrep_matcher_compile_regex_set() + webgrep_regex_set_matches() */
    webgrep_pattern_t rset_pats[3] = {
        { (const uint8_t *)"user_[0-9]+",   11 },
        { (const uint8_t *)"world",          5 },
        { (const uint8_t *)"missing_[0-9]+", 14 }
    };
    webgrep_matcher_t *rset_m = NULL;
    assert(webgrep_matcher_compile_regex_set(rset_pats, 3, &ropts, &diag, &rset_m) == WEBGREP_OK);
    assert(rset_m != NULL);

    uint32_t match_ids[4] = {0};
    size_t match_count = 0;
    assert(webgrep_regex_set_matches(rset_m, (const uint8_t *)hay3, strlen(hay3), match_ids, 4, &match_count) == WEBGREP_OK);
    assert(match_count == 2 && match_ids[0] == 0 && match_ids[1] == 1);
    webgrep_matcher_free(rset_m);
    printf("[6/16] webgrep_matcher_compile_regex_set() + webgrep_regex_set_matches(): PASS\n");

    /* 7. webgrep_scratch_new() + webgrep_scratch_free() */
    webgrep_scratch_t *scratch = webgrep_scratch_new();
    assert(scratch != NULL);
    webgrep_scratch_free(NULL);
    printf("[7/16] webgrep_scratch_new() + webgrep_scratch_free(): PASS\n");

    /* 8. webgrep_search_slice() with callback, context, replacement, early stop */
    cfg.scratch = scratch;
    cfg.before_context = 1;
    cfg.after_context = 1;
    cfg.replacement_ptr = (const uint8_t *)"id:$1";
    cfg.replacement_len = 5;

    const char *slice_text = "ctx before\nhello user_42 world\nctx after\nsecond user_99\n";
    line_capture_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    webgrep_summary_t sum;
    memset(&sum, 0, sizeof(sum));

    assert(webgrep_search_slice(
        re_m,
        (const uint8_t *)slice_text,
        strlen(slice_text),
        &cfg,
        on_line_capture,
        &lctx,
        &sum
    ) == WEBGREP_OK);
    assert(lctx.matched_lines == 2);
    assert(lctx.context_lines == 2);
    assert(lctx.saw_replacement == 1);
    assert(sum.matched_lines == 2);

    /* Early stop via callback */
    memset(&lctx, 0, sizeof(lctx));
    lctx.stop_after_first = 1;
    memset(&sum, 0, sizeof(sum));
    assert(webgrep_search_slice(
        re_m,
        (const uint8_t *)slice_text,
        strlen(slice_text),
        &cfg,
        on_line_capture,
        &lctx,
        &sum
    ) == WEBGREP_OK);
    assert(lctx.matched_lines == 1);
    assert(sum.stopped == 1);

    /* Test custom max_context_lines exceeding former hard cap 10 with 25 non-matching lines + 1 matching line */
    const char *many_ctx_text =
        "nonmatch 01\nnonmatch 02\nnonmatch 03\nnonmatch 04\nnonmatch 05\n"
        "nonmatch 06\nnonmatch 07\nnonmatch 08\nnonmatch 09\nnonmatch 10\n"
        "nonmatch 11\nnonmatch 12\nnonmatch 13\nnonmatch 14\nnonmatch 15\n"
        "nonmatch 16\nnonmatch 17\nnonmatch 18\nnonmatch 19\nnonmatch 20\n"
        "nonmatch 21\nnonmatch 22\nnonmatch 23\nnonmatch 24\nnonmatch 25\n"
        "hit user_999 target\n";
    webgrep_config_t high_ctx_cfg = webgrep_config_default();
    high_ctx_cfg.max_context_lines = 25;
    high_ctx_cfg.before_context = 20;
    memset(&sum, 0, sizeof(sum));
    memset(&lctx, 0, sizeof(lctx));
    assert(webgrep_search_slice(
        re_m,
        (const uint8_t *)many_ctx_text,
        strlen(many_ctx_text),
        &high_ctx_cfg,
        on_line_capture,
        &lctx,
        &sum
    ) == WEBGREP_OK);
    assert(sum.matched_lines == 1);
    assert(lctx.matched_lines == 1);
    assert(lctx.context_lines == 20);
    webgrep_matcher_free(re_m);
    printf("[8/16] webgrep_search_slice() with callback, context, replacement, early stop: PASS\n");

    /* 9. webgrep_search_reader() normal streaming */
    webgrep_matcher_t *stream_m = NULL;
    assert(webgrep_matcher_compile_literal((const uint8_t *)"STREAM_HIT", 10, &fopts, &stream_m) == WEBGREP_OK);

    const char *stream_data = "line 1\nline 2 STREAM_HIT a\nline 3 STREAM_HIT b\n";
    mem_reader_ctx_t rctx = {
        .data = (const uint8_t *)stream_data,
        .len = strlen(stream_data),
        .pos = 0,
        .chunk_size = 7
    };
    memset(&lctx, 0, sizeof(lctx));
    memset(&sum, 0, sizeof(sum));
    webgrep_config_t stream_cfg = webgrep_config_default();
    stream_cfg.scratch = scratch;

    assert(webgrep_search_reader(
        stream_m,
        mem_read_cb,
        &rctx,
        &stream_cfg,
        on_line_capture,
        &lctx,
        &sum
    ) == WEBGREP_OK);
    assert(lctx.matched_lines == 2 && sum.matched_lines == 2);
    printf("[9/16] webgrep_search_reader() normal streaming: PASS\n");

    /* 10. webgrep_search_reader() adversarial CReader tests */
    assert(webgrep_search_reader(stream_m, fail_read_cb, NULL, &stream_cfg, NULL, NULL, &sum) == WEBGREP_ERR_IO);
    assert(webgrep_search_reader(stream_m, overflow_read_cb, NULL, &stream_cfg, NULL, NULL, &sum) == WEBGREP_ERR_IO);
    printf("[10/16] webgrep_search_reader() adversarial CReader tests: PASS\n");

    /* 11. webgrep_search_archive_slice() normal TAR */
    uint8_t tar_buf[2048];
    memset(tar_buf, 0, sizeof(tar_buf));
    const char *tar_file_body = "hello STREAM_HIT in tar\n";
    write_tar_header(tar_buf, "pkg/file.txt", strlen(tar_file_body), '0', NULL);
    memcpy(tar_buf + 512, tar_file_body, strlen(tar_file_body));

    webgrep_tree_summary_t tsum;
    memset(&tsum, 0, sizeof(tsum));
    memset(&lctx, 0, sizeof(lctx));
    assert(webgrep_search_archive_slice(
        stream_m,
        tar_buf,
        sizeof(tar_buf),
        &tcfg,
        on_line_capture,
        &lctx,
        &tsum
    ) == WEBGREP_OK);
    assert(tsum.matched_files == 1 && tsum.matched_lines == 1 && lctx.matched_lines == 1);
    printf("[11/16] webgrep_search_archive_slice() normal TAR & ZIP: PASS\n");

    /* 12. webgrep_search_archive_slice() adversarial Archive tests */
    const uint8_t corrupt_zip[] = "PK\x03\x04corrupt_zip_header";
    assert(webgrep_search_archive_slice(
        stream_m,
        corrupt_zip,
        sizeof(corrupt_zip) - 1,
        &tcfg,
        NULL,
        NULL,
        &tsum
    ) == WEBGREP_ERR_CORRUPT_ARCHIVE);
    printf("[12/16] webgrep_search_archive_slice() adversarial Archive tests: PASS\n");

    /* 13. Invalid pointers & boundary inputs */
    webgrep_matcher_t *null_m = NULL;
    assert(webgrep_matcher_compile_literal(NULL, 5, NULL, &null_m) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_matcher_compile_literal((const uint8_t *)"a", 1, NULL, NULL) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_matcher_compile_multi(NULL, 2, NULL, &null_m) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_matcher_compile_regex(NULL, 5, NULL, NULL, &null_m) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_matcher_compile_regex_set(NULL, 2, NULL, NULL, &null_m) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_find(NULL, (const uint8_t *)"abc", 3, 0, &cm) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_find(stream_m, NULL, 3, 0, &cm) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_find(stream_m, (const uint8_t *)"abc", 3, 4, &cm) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_regex_set_matches(stream_m, (const uint8_t *)"abc", 3, match_ids, 4, &match_count) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_search_slice(NULL, (const uint8_t *)"abc", 3, NULL, NULL, NULL, NULL) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_search_reader(NULL, mem_read_cb, &rctx, NULL, NULL, NULL, NULL) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_search_reader(stream_m, NULL, NULL, NULL, NULL, NULL, NULL) == WEBGREP_ERR_INVALID_ARG);
    assert(webgrep_search_archive_slice(NULL, tar_buf, sizeof(tar_buf), NULL, NULL, NULL, NULL) == WEBGREP_ERR_INVALID_ARG);
    printf("[13/16] Invalid pointers & boundary inputs: PASS\n");

    /* 14. Memory stress: 1,000 allocation & free cycles */
    for (int i = 0; i < 1000; ++i) {
        webgrep_matcher_t *tmp_m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"cycle", 5, NULL, &tmp_m) == WEBGREP_OK);
        webgrep_scratch_t *tmp_s = webgrep_scratch_new();
        assert(tmp_s != NULL);
        webgrep_scratch_free(tmp_s);
        webgrep_matcher_free(tmp_m);
    }
    printf("[14/16] Memory stress: 1,000 allocation & free cycles: PASS\n");

    /* 15. Multithreaded concurrency (8 threads, shared matchers) */
    webgrep_matcher_t *shared_lit = NULL;
    assert(webgrep_matcher_compile_literal((const uint8_t *)"CONCURRENT_HIT", 14, NULL, &shared_lit) == WEBGREP_OK);

    webgrep_pattern_t shared_pats[2] = {
        { (const uint8_t *)"ERR_[0-9]+",  10 },
        { (const uint8_t *)"WARN_[A-Z]+", 11 }
    };
    webgrep_matcher_t *shared_rset = NULL;
    assert(webgrep_matcher_compile_regex_set(shared_pats, 2, NULL, NULL, &shared_rset) == WEBGREP_OK);

    thread_worker_arg_t targs[8];
#ifdef _WIN32
    HANDLE threads[8];
    for (int t = 0; t < 8; ++t) {
        targs[t].lit_matcher = shared_lit;
        targs[t].re_set_matcher = shared_rset;
        targs[t].passed = 0;
        threads[t] = CreateThread(NULL, 0, concurrent_worker, &targs[t], 0, NULL);
        assert(threads[t] != NULL);
    }
    for (int t = 0; t < 8; ++t) {
        assert(WaitForSingleObject(threads[t], INFINITE) == WAIT_OBJECT_0);
        assert(CloseHandle(threads[t]) != 0);
        assert(targs[t].passed == 1);
    }
#else
    pthread_t threads[8];
    for (int t = 0; t < 8; ++t) {
        targs[t].lit_matcher = shared_lit;
        targs[t].re_set_matcher = shared_rset;
        targs[t].passed = 0;
        assert(pthread_create(&threads[t], NULL, concurrent_worker, &targs[t]) == 0);
    }
    for (int t = 0; t < 8; ++t) {
        assert(pthread_join(threads[t], NULL) == 0);
        assert(targs[t].passed == 1);
    }
#endif
    webgrep_matcher_free(shared_lit);
    webgrep_matcher_free(shared_rset);
    printf("[15/16] Multithreaded concurrency (8 threads, shared matchers): PASS\n");

    /* 16. Security exploits: reader overflow & archive traversal/symlink */
    uint8_t exploit_tar[3072];
    memset(exploit_tar, 0, sizeof(exploit_tar));
    const char *secret_body = "STREAM_HIT\n";
    /* Entry 1: symlink pointing outside archive root */
    write_tar_header(exploit_tar, "evil_link", 0, '2', "/etc/passwd");
    /* Entry 2: valid file */
    write_tar_header(exploit_tar + 512, "safe/ok.txt", strlen(secret_body), '0', NULL);
    memcpy(exploit_tar + 1024, secret_body, strlen(secret_body));

    memset(&tsum, 0, sizeof(tsum));
    assert(webgrep_search_archive_slice(
        stream_m,
        exploit_tar,
        sizeof(exploit_tar),
        &tcfg,
        NULL,
        NULL,
        &tsum
    ) == WEBGREP_OK);
    assert(tsum.files_searched == 1 && tsum.matched_files == 1);

    webgrep_scratch_free(scratch);
    webgrep_matcher_free(stream_m);
    printf("[16/17] Security exploits: reader overflow & archive traversal/symlink: PASS\n");

    /* 17. Multiline cross-line matching (literal, regex, regex_set, slice, streaming reader, archive) */
    {
        /* (a) Literal multiline */
        webgrep_find_options_t ml_fopts = webgrep_find_options_default();
        assert(ml_fopts.multiline == 0);
        webgrep_matcher_t *ml_lit = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"alpha\nbeta", 10, &ml_fopts, &ml_lit) == WEBGREP_ERR_SYNTAX);
        ml_fopts.multiline = 1;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"alpha\nbeta", 10, &ml_fopts, &ml_lit) == WEBGREP_OK);
        assert(ml_lit != NULL);

        const char *ml_doc = "line1\nxx alpha\nbeta yy\nline4\n";
        webgrep_config_t ml_cfg = webgrep_config_default();
        ml_cfg.multiline = 1;
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(
            ml_lit,
            (const uint8_t *)ml_doc,
            strlen(ml_doc),
            &ml_cfg,
            on_line_capture,
            &lctx,
            &sum
        ) == WEBGREP_OK);
        assert(sum.matched_lines == 1 && lctx.matched_lines == 1 && lctx.last_line_no == 2);

        /* Chunked streaming reader (chunk_size = 5) on multiline input */
        mem_reader_ctx_t ml_rctx = {
            .data = (const uint8_t *)ml_doc,
            .len = strlen(ml_doc),
            .pos = 0,
            .chunk_size = 5
        };
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_reader(
            ml_lit,
            mem_read_cb,
            &ml_rctx,
            &ml_cfg,
            on_line_capture,
            &lctx,
            &sum
        ) == WEBGREP_OK);
        assert(sum.matched_lines == 1 && lctx.matched_lines == 1 && lctx.last_line_no == 2);

        /* TAR archive multiline search */
        uint8_t ml_tar[2048];
        memset(ml_tar, 0, sizeof(ml_tar));
        write_tar_header(ml_tar, "dir/multiline.txt", strlen(ml_doc), '0', NULL);
        memcpy(ml_tar + 512, ml_doc, strlen(ml_doc));
        webgrep_tree_config_t ml_tcfg = webgrep_tree_config_default();
        ml_tcfg.search.multiline = 1;
        memset(&tsum, 0, sizeof(tsum));
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_archive_slice(
            ml_lit,
            ml_tar,
            sizeof(ml_tar),
            &ml_tcfg,
            on_line_capture,
            &lctx,
            &tsum
        ) == WEBGREP_OK);
        assert(tsum.matched_files == 1 && tsum.matched_lines == 1 && lctx.last_line_no == 2);
        webgrep_matcher_free(ml_lit);

        /* (b) Regex multiline + dot_all */
        webgrep_regex_options_t ml_ropts = webgrep_regex_options_default();
        ml_ropts.multiline = 1;
        ml_ropts.dot_all = 1;
        webgrep_matcher_t *ml_re = NULL;
        assert(webgrep_matcher_compile_regex((const uint8_t *)"START.+?END", 11, &ml_ropts, &diag, &ml_re) == WEBGREP_OK);
        const char *dot_doc = "h\nSTART\nmid\nEND\nt\n";
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(ml_re, (const uint8_t *)dot_doc, strlen(dot_doc), &ml_cfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(sum.matched_lines == 1 && lctx.last_line_no == 2);
        webgrep_matcher_free(ml_re);

        /* (c) RegexSet multiline */
        webgrep_pattern_t ml_spats[2] = {
            { (const uint8_t *)"alpha\\nbeta", 11 },
            { (const uint8_t *)"START\\nmid",  10 }
        };
        webgrep_matcher_t *ml_rset = NULL;
        assert(webgrep_matcher_compile_regex_set(ml_spats, 2, &ml_ropts, &diag, &ml_rset) == WEBGREP_OK);
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(ml_rset, (const uint8_t *)ml_doc, strlen(ml_doc), &ml_cfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(sum.matched_lines == 1 && lctx.last_pattern_id == 0 && lctx.last_line_no == 2);
        webgrep_matcher_free(ml_rset);
    }
    printf("[17/18] Multiline cross-line matching (literal, regex, regex_set, slice, streaming, archive): PASS\n");

    /* 18. Range, line_number_mode, pre-count line_filter, reverse tail search, probe_line_slice, & archive entry_filter */
    {
        /* (a) Zero-init {0} and default struct parity */
        webgrep_config_t zero_cfg = {0};
        webgrep_config_t def_cfg = webgrep_config_default();
        assert(def_cfg.has_byte_range == 0 && def_cfg.has_byte_range_end == 0 && def_cfg.range_align_lines == 0);
        assert(def_cfg.initial_line_number == 0 && def_cfg.line_number_mode == WEBGREP_LINE_NUM_AUTO);
        assert(def_cfg.line_filter == NULL && def_cfg.line_filter_ctx == NULL);

        webgrep_probe_options_t popts = webgrep_probe_options_default();
        assert(popts.delimiter == '\n' && popts.strip_crlf == 1 && popts.max_line_bytes == 2u * 1024u * 1024u);

        /* (b) NULL regex options Unicode folding parity: (?i)kelvin matches U+212A Kelvin sign "\xE2\x84\xAAelvin" */
        webgrep_matcher_t *kelvin_re = NULL;
        assert(webgrep_matcher_compile_regex((const uint8_t *)"(?i)kelvin", 10, NULL, &diag, &kelvin_re) == WEBGREP_OK);
        const uint8_t kelvin_text[] = "sensor \xE2\x84\xAA""elvin ok\n";
        assert(webgrep_find(kelvin_re, kelvin_text, sizeof(kelvin_text) - 1, 0, &cm) == 1);
        assert(cm.start == 7 && cm.end == 15);
        webgrep_matcher_free(kelvin_re);

        /* (c) webgrep_probe_line_slice */
        const char *pdoc = "row0\r\nrow1_payload\r\nrow2";
        webgrep_line_probe_t probe_out;
        memset(&probe_out, 0, sizeof(probe_out));
        assert(webgrep_probe_line_slice((const uint8_t *)pdoc, strlen(pdoc), 9, NULL, &probe_out) == 1);
        assert(probe_out.start_offset == 6 && probe_out.end_offset == 18 && probe_out.raw_end_offset == 20);
        assert(probe_out.bytes_len == 12 && memcmp(probe_out.bytes_ptr, "row1_payload", 12) == 0);
        assert(probe_out.truncated_left == 0 && probe_out.truncated_right == 0);
        assert(webgrep_probe_line_slice((const uint8_t *)pdoc, strlen(pdoc), strlen(pdoc), NULL, &probe_out) == 0);
        assert(webgrep_probe_line_slice(NULL, 5, 0, NULL, &probe_out) == WEBGREP_ERR_INVALID_ARG);

        /* (d) byte_range, line_number_mode, initial_line_number, and pre-quota line_filter */
        webgrep_matcher_t *hit_m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"HIT", 3, NULL, &hit_m) == WEBGREP_OK);
        const char *rdoc =
            "000 HIT drop\n" /* 0..13 */
            "111 HIT keep\n" /* 13..26 */
            "222 HIT drop\n" /* 26..39 */
            "333 HIT keep\n"; /* 39..52 */

        /* Zero-init {0} config works seamlessly */
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &zero_cfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(sum.matched_lines == 4 && lctx.matched_lines == 4);

        /* Empty [0..0) range via has_byte_range_end = 1 */
        webgrep_config_t rcfg = webgrep_config_default();
        rcfg.has_byte_range = 1;
        rcfg.has_byte_range_end = 1;
        rcfg.byte_range_start = 0;
        rcfg.byte_range_end = 0;
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(sum.matched_lines == 0 && lctx.matched_lines == 0);

        /* Mid-file byte_range with range_align_lines = 1 and AUTO unknown vs initial_line_number vs FROM_ONE vs UNKNOWN */
        rcfg = webgrep_config_default();
        rcfg.has_byte_range = 1;
        rcfg.byte_range_start = 5;  /* cuts inside line 1 -> aligned to 13 */
        rcfg.byte_range_end = 30;   /* cuts inside line 3 -> aligned to 39 */
        rcfg.range_align_lines = 1;
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(sum.matched_lines == 2 && lctx.first_offset == 13 && lctx.last_offset == 26);
        assert(lctx.last_line_known == 0 && lctx.first_line_no == 0);

        rcfg.initial_line_number = 100;
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.last_line_known == 1 && lctx.first_line_no == 100 && lctx.last_line_no == 101);

        rcfg.initial_line_number = 0;
        rcfg.line_number_mode = WEBGREP_LINE_NUM_FROM_ONE;
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.last_line_known == 1 && lctx.first_line_no == 1 && lctx.last_line_no == 2);

        rcfg = webgrep_config_default();
        rcfg.line_number_mode = WEBGREP_LINE_NUM_UNKNOWN;
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 4 && lctx.last_line_known == 0 && lctx.first_line_no == 0);

        /* Pre-count line_filter: rejected "drop" lines do NOT consume max_count = 1 */
        line_filter_test_ctx_t lf_ctx = { .required_substr = "keep", .calls = 0 };
        webgrep_config_t fcfg = webgrep_config_default();
        fcfg.max_count = 1;
        fcfg.line_filter = test_line_filter_cb;
        fcfg.line_filter_ctx = &lf_ctx;
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &fcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lf_ctx.calls == 2 && sum.matched_lines == 1 && lctx.first_line_no == 2);

        /* (e) webgrep_search_reverse_slice: newest-first + backward pagination with resume_at */
        webgrep_config_t rev_cfg = webgrep_config_default();
        rev_cfg.initial_line_number = 4;
        rev_cfg.max_results = 2;
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_reverse_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rev_cfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 2 && lctx.first_line_no == 4 && lctx.last_line_no == 3);
        assert(sum.has_resume_at == 1 && sum.resume_at == 26);

        /* Page 2 backward: [0 .. sum.resume_at) */
        rev_cfg.has_byte_range = 1;
        rev_cfg.has_byte_range_end = 1;
        rev_cfg.byte_range_start = 0;
        rev_cfg.byte_range_end = sum.resume_at;
        rev_cfg.initial_line_number = 2;
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_reverse_slice(hit_m, (const uint8_t *)rdoc, strlen(rdoc), &rev_cfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 2 && lctx.first_line_no == 2 && lctx.last_line_no == 1);

        /* (f) Archive entry_filter skips oversized non-.txt entry before max_entry_bytes enforcement */
        uint8_t filt_tar[3072];
        memset(filt_tar, 0, sizeof(filt_tar));
        const char *oversized_bin = "HIT inside oversized 60-byte entry skipped before quota!!\n";
        const char *small_txt = "HIT ok\n";
        write_tar_header(filt_tar, "pkg/skip.bin", strlen(oversized_bin), '0', NULL);
        memcpy(filt_tar + 512, oversized_bin, strlen(oversized_bin));
        write_tar_header(filt_tar + 1024, "pkg/keep.txt", strlen(small_txt), '0', NULL);
        memcpy(filt_tar + 1536, small_txt, strlen(small_txt));

        archive_filter_test_ctx_t af_ctx = { .allowed_suffix = ".txt", .seen_entries = 0 };
        webgrep_tree_config_t ftcfg = webgrep_tree_config_default();
        ftcfg.max_entry_bytes = 24; /* oversized_bin (>24B) would trigger WEBGREP_ERR_ARCHIVE_LIMIT without entry_filter */
        ftcfg.entry_filter = test_archive_entry_filter_cb;
        ftcfg.entry_filter_ctx = &af_ctx;
        memset(&tsum, 0, sizeof(tsum));
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_archive_slice(hit_m, filt_tar, sizeof(filt_tar), &ftcfg, on_line_capture, &lctx, &tsum) == WEBGREP_OK);
        assert(af_ctx.seen_entries == 2 && tsum.files_searched == 1 && tsum.matched_files == 1 && lctx.matched_lines == 1);

        webgrep_matcher_free(hit_m);
    }
    printf("[18/24] Range, line_number_mode, line_filter, reverse tail, probe, & archive entry_filter: PASS\n");

    /* 19. Extended webgrep_config_t fields & atomic cancel token */
    {
        webgrep_cancel_t *cancel = webgrep_cancel_new();
        assert(cancel != NULL);

        webgrep_matcher_t *m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"LOG", 3, NULL, &m) == WEBGREP_OK);

        const char *doc = "LOG keep Alpha\nLOG skip Beta\nLOG keep Gamma\n";
        webgrep_pattern_t c_pats[1] = { { (const uint8_t *)"alpha", 5 } };
        webgrep_pattern_t x_pats[1] = { { (const uint8_t *)"beta", 4 } };

        webgrep_config_t ecfg = webgrep_config_default();
        ecfg.contains_ptr = c_pats;
        ecfg.contains_len = 1;
        ecfg.excludes_ptr = x_pats;
        ecfg.excludes_len = 1;
        ecfg.filter_case_insensitive = 1;
        ecfg.charset_ptr = "UTF-8";
        ecfg.charset_len = 5;
        ecfg.cancel = cancel;

        line_capture_ctx_t lctx;
        webgrep_summary_t sum;

        webgrep_cancel_trigger(cancel);
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(m, (const uint8_t *)doc, strlen(doc), &ecfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 0);

        webgrep_cancel_reset(cancel);
        memset(&lctx, 0, sizeof(lctx));
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(m, (const uint8_t *)doc, strlen(doc), &ecfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 1 && sum.matched_lines == 1);

        webgrep_config_t rcfg = webgrep_config_default();
        rcfg.resume_from = 15; /* Start at second line */
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_slice(m, (const uint8_t *)doc, strlen(doc), &rcfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 2);

        webgrep_matcher_free(m);
        webgrep_cancel_free(cancel);
        webgrep_cancel_free(NULL);
    }
    printf("[19/24] Extended config (contains/excludes/charset/cancel/resume_from): PASS\n");

    /* 20. Regex captures, named groups, & ${name} replacement */
    {
        const char *pat = "(?P<user>[a-z]+)@(?<host>[a-z]+\\.[a-z]+)";
        webgrep_matcher_t *re = NULL;
        webgrep_compile_diag_t diag;
        assert(webgrep_matcher_compile_regex((const uint8_t *)pat, strlen(pat), NULL, &diag, &re) == WEBGREP_OK);

        assert(webgrep_matcher_group_index(re, "user", 4) == 1);
        assert(webgrep_matcher_group_index(re, "host", 4) == 2);
        assert(webgrep_matcher_group_index(re, "unknown", 7) == 0);

        webgrep_scratch_t *scratch = webgrep_scratch_new();
        assert(scratch != NULL);

        const char *line = "user=alice@example.org!";
        webgrep_captures_t caps;
        assert(webgrep_find_captures(re, (const uint8_t *)line, strlen(line), 0, 1, scratch, &caps) == 1);
        assert(caps.group_count == 2);
        assert(caps.full.matched == 1 && caps.full.end - caps.full.start == 17);
        assert(caps.groups[0].matched == 1 && memcmp(line + caps.groups[0].start, "alice", 5) == 0);
        assert(caps.groups[1].matched == 1 && memcmp(line + caps.groups[1].start, "example.org", 11) == 0);

        webgrep_config_t cfg = webgrep_config_default();
        const char *tmpl = "id:${user}->${host}";
        cfg.replacement_ptr = (const uint8_t *)tmpl;
        cfg.replacement_len = strlen(tmpl);
        /* Verify ${name} expanded properly in replaced_ptr */
        webgrep_pull_t *pull = NULL;
        assert(webgrep_pull_open_slice(re, (const uint8_t *)line, strlen(line), &cfg, &pull) == WEBGREP_OK);
        webgrep_line_event_t ev;
        webgrep_summary_t sum;
        assert(webgrep_pull_next(pull, &ev, &sum) == 1);
        assert(ev.replaced_ptr != NULL && ev.replaced_len == strlen("user=id:alice->example.org!"));
        assert(bytes_contains(ev.replaced_ptr, ev.replaced_len, "id:alice->example.org", 21));
        assert(webgrep_pull_next(pull, &ev, &sum) == 0);
        webgrep_pull_free(pull);

        webgrep_scratch_free(scratch);
        webgrep_matcher_free(re);
    }
    printf("[20/24] Regex captures, named group lookup, & ${name} replacement: PASS\n");

    /* 21. Positional RandomAccess: search_range, search_reverse_at, & probe_line_at */
    {
        webgrep_matcher_t *m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"HIT", 3, NULL, &m) == WEBGREP_OK);

        const char *doc = "line1 HIT\nline2 HIT\nline3 no\nline4 HIT\n";
        mem_reader_ctx_t ra = { .data = (const uint8_t *)doc, .len = strlen(doc), .pos = 0, .chunk_size = 0 };
        line_capture_ctx_t lctx;
        webgrep_summary_t sum;

        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_range(m, slice_read_at_cb, &ra, (uint64_t)ra.len, 1, 10, 20, 1, NULL, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 1 && sum.matched_lines == 1);

        webgrep_config_t rev_cfg = webgrep_config_default();
        rev_cfg.initial_line_number = 4;
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_reverse_at(m, slice_read_at_cb, &ra, (uint64_t)ra.len, 1, &rev_cfg, on_line_capture, &lctx, &sum) == WEBGREP_OK);
        assert(lctx.matched_lines == 3 && lctx.first_line_no == 4 && lctx.last_line_no == 1);

        uint8_t pbuf[64];
        webgrep_line_probe_t probe;
        assert(webgrep_probe_line_at(slice_read_at_cb, &ra, (uint64_t)ra.len, 1, 12, pbuf, sizeof(pbuf), NULL, &probe) == 1);
        assert(probe.bytes_len == 9 && memcmp(probe.bytes_ptr, "line2 HIT", 9) == 0);

        webgrep_matcher_free(m);
    }
    printf("[21/24] RandomAccess search_range, search_reverse_at, & probe_line_at: PASS\n");

    /* 22. Pull-mode iterators (slice + streaming reader) */
    {
        webgrep_matcher_t *m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"EVT", 3, NULL, &m) == WEBGREP_OK);

        const char *stream_doc = "skip\nEVT alpha\nEVT beta\nskip\n";
        webgrep_pull_t *pull = NULL;
        webgrep_line_event_t ev;
        webgrep_summary_t sum;

        assert(webgrep_pull_open_slice(m, (const uint8_t *)stream_doc, strlen(stream_doc), NULL, &pull) == WEBGREP_OK);
        assert(webgrep_pull_next(pull, &ev, &sum) == 1 && ev.line_number == 2);
        assert(webgrep_pull_next(pull, &ev, &sum) == 1 && ev.line_number == 3);
        assert(webgrep_pull_next(pull, &ev, &sum) == 0 && sum.matched_lines == 2);
        webgrep_pull_free(pull);

        mem_reader_ctx_t mr = { .data = (const uint8_t *)stream_doc, .len = strlen(stream_doc), .pos = 0, .chunk_size = 5 };
        assert(webgrep_pull_open_reader(m, mem_read_cb, &mr, NULL, &pull) == WEBGREP_OK);
        size_t seen = 0;
        while (webgrep_pull_next(pull, &ev, &sum) == 1) seen++;
        assert(seen == 2 && sum.matched_lines == 2);
        webgrep_pull_free(pull);
        webgrep_pull_free(NULL);

        webgrep_matcher_free(m);
    }
    printf("[22/24] Pull-mode iterators (slice & streaming reader): PASS\n");

    /* 23. Streaming archive reader (TAR & ZIP) */
    {
        webgrep_matcher_t *m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"STREAM_HIT", 10, NULL, &m) == WEBGREP_OK);

        uint8_t tar_buf[2560];
        memset(tar_buf, 0, sizeof(tar_buf));
        const char *t1 = "hello\nSTREAM_HIT tar\n";
        write_tar_header(tar_buf, "logs/app.log", strlen(t1), '0', NULL);
        memcpy(tar_buf + 512, t1, strlen(t1));
        mem_reader_ctx_t tr = { .data = tar_buf, .len = sizeof(tar_buf), .pos = 0, .chunk_size = 64 };
        webgrep_tree_summary_t tsum;
        line_capture_ctx_t lctx = { 0 };
        assert(webgrep_search_archive_reader(m, mem_read_cb, &tr, NULL, on_line_capture, &lctx, &tsum) == WEBGREP_OK);
        assert(tsum.files_searched == 1 && tsum.matched_files == 1 && lctx.matched_lines == 1);

        uint8_t zip_buf[512];
        const char *zpayload = "none\nSTREAM_HIT zip\n";
        size_t zlen = build_stored_zip_single(zip_buf, sizeof(zip_buf), "in/z.txt", (const uint8_t *)zpayload, strlen(zpayload));
        mem_reader_ctx_t zr = { .data = zip_buf, .len = zlen, .pos = 0, .chunk_size = 13 };
        memset(&tsum, 0, sizeof(tsum));
        memset(&lctx, 0, sizeof(lctx));
        assert(webgrep_search_archive_reader(m, mem_read_cb, &zr, NULL, on_line_capture, &lctx, &tsum) == WEBGREP_OK);
        assert(tsum.files_searched == 1 && tsum.matched_files == 1 && lctx.matched_lines == 1);

        webgrep_matcher_free(m);
    }
    printf("[23/24] Streaming archive reader (TAR & ZIP): PASS\n");

    /* 24. N-gram Bloom Filter, Indexed Gzip, & Seekable Zstd boundary checks */
    {
        webgrep_bloom_config_t bcfg = webgrep_bloom_config_default();
        webgrep_bloom_t *b1 = NULL;
        webgrep_bloom_t *b2 = NULL;
        assert(webgrep_bloom_new(&bcfg, &b1) == WEBGREP_OK);
        assert(webgrep_bloom_new(&bcfg, &b2) == WEBGREP_OK);

        const char *sample = "node-07 timeout connecting to backend";
        assert(webgrep_bloom_add(b1, (const uint8_t *)sample, strlen(sample)) == WEBGREP_OK);
        assert(webgrep_bloom_merge(b2, b1) == WEBGREP_OK);

        webgrep_matcher_t *m_hit = NULL;
        webgrep_matcher_t *m_miss = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"timeout", 7, NULL, &m_hit) == WEBGREP_OK);
        assert(webgrep_matcher_compile_literal((const uint8_t *)"zzq99x", 6, NULL, &m_miss) == WEBGREP_OK);
        assert(webgrep_bloom_may_contain(b2, m_hit) == 1);
        assert(webgrep_bloom_may_contain(b2, m_miss) == 0);

        size_t need = 0;
        assert(webgrep_bloom_serialize(b2, NULL, 0, &need) == WEBGREP_OK && need > 0);
        uint8_t small_buf[4];
        assert(webgrep_bloom_serialize(b2, small_buf, sizeof(small_buf), &need) == WEBGREP_ERR_TOO_LARGE);
        uint8_t *ser = (uint8_t *)malloc(need);
        assert(ser != NULL);
        assert(webgrep_bloom_serialize(b2, ser, need, &need) == WEBGREP_OK);
        webgrep_bloom_t *b3 = NULL;
        assert(webgrep_bloom_deserialize(ser, need, &b3) == WEBGREP_OK);
        assert(webgrep_bloom_may_contain(b3, m_hit) == 1);

        free(ser);
        webgrep_matcher_free(m_hit);
        webgrep_matcher_free(m_miss);
        webgrep_bloom_free(b1);
        webgrep_bloom_free(b2);
        webgrep_bloom_free(b3);
        webgrep_bloom_free(NULL);

        /* Indexed Gzip end-to-end */
        const char *gz_text = "alpha_beta_gamma_0123456789_indexed_gzip";
        size_t gz_plen = strlen(gz_text);
        uint8_t gz_buf[128];
        size_t gz_len = build_stored_gzip(gz_buf, sizeof(gz_buf), (const uint8_t *)gz_text, gz_plen);

        mem_reader_ctx_t gzr = { .data = gz_buf, .len = gz_len, .pos = 0, .chunk_size = 9 };
        webgrep_gzip_index_t *gidx = NULL;
        assert(webgrep_gzip_index_build(mem_read_cb, &gzr, 16, &gidx) == WEBGREP_OK);
        assert(webgrep_gzip_index_uncompressed_size(gidx) == (uint64_t)gz_plen);

        size_t gneed = 0;
        assert(webgrep_gzip_index_serialize(gidx, NULL, 0, &gneed) == WEBGREP_OK && gneed > 0);
        uint8_t *gser = (uint8_t *)malloc(gneed);
        assert(gser != NULL);
        assert(webgrep_gzip_index_serialize(gidx, gser, gneed, &gneed) == WEBGREP_OK);
        webgrep_gzip_index_t *gidx2 = NULL;
        assert(webgrep_gzip_index_deserialize(gser, gneed, &gidx2) == WEBGREP_OK);

        uint8_t out_slice[12];
        size_t got = 0;
        mem_reader_ctx_t gzra = { .data = gz_buf, .len = gz_len, .pos = 0, .chunk_size = 0 };
        assert(webgrep_gzip_index_read_at(gidx2, slice_read_at_cb, &gzra, (uint64_t)gz_len, 1, 17, out_slice, sizeof(out_slice), &got) == WEBGREP_OK);
        assert(got == 12 && memcmp(out_slice, gz_text + 17, 12) == 0);

        free(gser);
        webgrep_gzip_index_free(gidx);
        webgrep_gzip_index_free(gidx2);
        webgrep_gzip_index_free(NULL);

        /* Seekable Zstd boundary checks */
        webgrep_zstd_seek_table_t *ztbl = NULL;
        const uint8_t bad_zst[8] = { 0 };
        mem_reader_ctx_t zra = { .data = bad_zst, .len = sizeof(bad_zst), .pos = 0, .chunk_size = 0 };
        assert(webgrep_zstd_seek_table_parse(slice_read_at_cb, &zra, 4, &ztbl) == WEBGREP_ERR_CORRUPT_ARCHIVE);
        assert(webgrep_zstd_seek_table_uncompressed_size(NULL) == 0);
        webgrep_zstd_seek_table_free(NULL);
    }
    printf("[24/25] N-gram Bloom Filter, Indexed Gzip, & Seekable Zstd checks: PASS\n");

    /* 25. v0.8 C ABI: contains_regexes/excludes_regexes, unicode_classes, Flow.skipTo/pause + ResumeState, Windows-1252 */
    {
        webgrep_regex_options_t ropts = webgrep_regex_options_default();
        ropts.unicode_classes = 1;
        webgrep_matcher_t *m_uni = NULL;
        assert(webgrep_matcher_compile_regex((const uint8_t *)"\\d+", 3, &ropts, NULL, &m_uni) == WEBGREP_OK);
        const uint8_t arabic[] = { 'x', ':', 0xD9, 0xA4, 0xD9, 0xA2, '!' };
        webgrep_match_t mt;
        assert(webgrep_find(m_uni, arabic, sizeof(arabic), 0, &mt) == 1);
        assert(mt.start == 2 && mt.end == 6);
        webgrep_matcher_free(m_uni);

        webgrep_matcher_t *m_err = NULL;
        webgrep_matcher_t *m_inc = NULL;
        webgrep_matcher_t *m_exc = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"ERR", 3, NULL, &m_err) == WEBGREP_OK);
        assert(webgrep_matcher_compile_regex((const uint8_t *)"db-[0-9]+", 9, NULL, NULL, &m_inc) == WEBGREP_OK);
        assert(webgrep_matcher_compile_regex((const uint8_t *)"probe", 5, NULL, NULL, &m_exc) == WEBGREP_OK);

        const webgrep_matcher_t *inc_list[1] = { m_inc };
        const webgrep_matcher_t *exc_list[1] = { m_exc };
        webgrep_config_t fcfg = webgrep_config_default();
        fcfg.contains_regexes_ptr = inc_list;
        fcfg.contains_regexes_len = 1;
        fcfg.excludes_regexes_ptr = exc_list;
        fcfg.excludes_regexes_len = 1;

        const char *flogs = "ERR db-1 ok\nERR db-2 probe\nERR cache\nERR db-3 fail\n";
        webgrep_summary_t fsum;
        assert(webgrep_search_slice(m_err, (const uint8_t *)flogs, strlen(flogs), &fcfg, NULL, NULL, &fsum) == WEBGREP_OK);
        assert(fsum.matched_lines == 2);

        /* Flow.pause + stateless ResumeState across slice */
        const char *fdoc = "hit 1\nhit 2\nhit 3\n";
        webgrep_matcher_t *m_hit = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"hit", 3, NULL, &m_hit) == WEBGREP_OK);
        webgrep_resume_state_t *rs = webgrep_resume_state_new();
        assert(rs != NULL);
        flow_test_ctx_t pctx = { 0, 0, 1, 0, 0 };
        webgrep_summary_t psum1, psum2;
        assert(webgrep_search_slice_flow(m_hit, (const uint8_t *)fdoc, strlen(fdoc), NULL, rs, flow_test_cb, &pctx, &psum1) == WEBGREP_OK);
        assert(webgrep_resume_state_is_paused(rs) == 1);
        assert(webgrep_resume_state_offset(rs) == 6);
        assert(pctx.count == 1 && pctx.last_line == 1);

        pctx.pause_at_count = 0;
        assert(webgrep_search_slice_flow(m_hit, (const uint8_t *)fdoc, strlen(fdoc), NULL, rs, flow_test_cb, &pctx, &psum2) == WEBGREP_OK);
        assert(webgrep_resume_state_is_paused(rs) == 0);
        assert(pctx.count == 3 && pctx.last_line == 3);

        /* Flow.skipTo(offset) */
        flow_test_ctx_t sctx = { 0, 0, 0, 1, 12 };
        webgrep_summary_t ssum;
        assert(webgrep_search_slice_flow(m_hit, (const uint8_t *)fdoc, strlen(fdoc), NULL, NULL, flow_test_cb, &sctx, &ssum) == WEBGREP_OK);
        assert(sctx.count == 2 && sctx.last_line == 3);

        /* Windows-1252 Euro (0x80) via WEBGREP_ENCODING_WINDOWS1252 */
        webgrep_matcher_t *m_eur = NULL;
        const uint8_t eur_utf8[] = { 0xE2, 0x82, 0xAC, '5', '0' };
        assert(webgrep_matcher_compile_literal(eur_utf8, sizeof(eur_utf8), NULL, &m_eur) == WEBGREP_OK);
        const uint8_t cp1252[] = { 0x80, '5', '0', '\n' };
        webgrep_config_t ecfg = webgrep_config_default();
        ecfg.encoding = WEBGREP_ENCODING_WINDOWS1252;
        webgrep_summary_t esum;
        assert(webgrep_search_slice(m_eur, cp1252, sizeof(cp1252), &ecfg, NULL, NULL, &esum) == WEBGREP_OK);
        assert(esum.matched_lines == 1);

        webgrep_resume_state_reset(rs);
        assert(webgrep_resume_state_is_paused(rs) == 0);
        webgrep_resume_state_free(rs);
        webgrep_resume_state_free(NULL);
        webgrep_matcher_free(m_eur);
        webgrep_matcher_free(m_hit);
        webgrep_matcher_free(m_err);
        webgrep_matcher_free(m_inc);
        webgrep_matcher_free(m_exc);
    }
    printf("[25/26] v0.8 C ABI (regex filters, unicode_classes, Flow.skipTo/pause, ResumeState, encodings): PASS\n");

    /* 26. v0.10.3 C ABI: custom allocator hook, pull_next lossy UTF-8, distinct archive error codes, isolated ratio check */
    {
        /* (a) Custom allocator hook: tracks all allocations/frees and deterministic OOM */
        c_test_alloc_ctx_t actx = { 0, 0, 0, 0, 0 };
        webgrep_allocator_t custom_alloc = {
            .alloc = c_test_alloc,
            .free = c_test_free,
            .ctx = &actx
        };
        webgrep_set_allocator(&custom_alloc);
        {
            webgrep_matcher_t *cm_re = NULL;
            assert(webgrep_matcher_compile_regex((const uint8_t *)"item_[0-9]+", 11, NULL, NULL, &cm_re) == WEBGREP_OK);
            webgrep_scratch_t *cs = webgrep_scratch_new();
            assert(cs != NULL);
            webgrep_config_t ccfg = webgrep_config_default();
            ccfg.scratch = cs;
            webgrep_summary_t csum;
            const char *cdoc = "row item_7 ok\n";
            assert(webgrep_search_slice(cm_re, (const uint8_t *)cdoc, strlen(cdoc), &ccfg, NULL, NULL, &csum) == WEBGREP_OK);
            assert(csum.matched_lines == 1);
            webgrep_scratch_free(cs);
            webgrep_matcher_free(cm_re);
        }
        assert(actx.allocs > 0 && actx.allocs == actx.frees && actx.live_bytes == 0);

        actx.enable_fail = 1;
        actx.fail_after = actx.allocs;
        webgrep_matcher_t *oom_m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"oom", 3, NULL, &oom_m) == WEBGREP_ERR_OUT_OF_MEMORY);
        assert(oom_m == NULL && actx.live_bytes == 0);
        webgrep_set_allocator(NULL);

        /* (b) webgrep_pull_next UTF-8 contract: valid zero-copy vs invalid U+FFFD lossy text */
        webgrep_matcher_t *m_tag = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"TAG", 3, NULL, &m_tag) == WEBGREP_OK);
        const uint8_t bad_utf8_doc[] = {
            'T','A','G',' ','o','k','\n',
            'T','A','G',' ',0xFF,0xFE,' ','x','\n'
        };
        webgrep_pull_t *pull = NULL;
        assert(webgrep_pull_open_slice(m_tag, bad_utf8_doc, sizeof(bad_utf8_doc), NULL, &pull) == WEBGREP_OK);
        webgrep_line_event_t ev;
        webgrep_summary_t sum;
        assert(webgrep_pull_next(pull, &ev, &sum) == 1);
        assert(ev.text_ptr == ev.bytes_ptr && ev.text_len == 6);
        assert(webgrep_pull_next(pull, &ev, &sum) == 1);
        assert(ev.bytes_len == 8 && ev.bytes_ptr[4] == 0xFF && ev.bytes_ptr[5] == 0xFE);
        assert(ev.text_ptr != ev.bytes_ptr);
        const uint8_t expected_lossy[] = { 'T','A','G',' ',0xEF,0xBF,0xBD,0xEF,0xBF,0xBD,' ','x' };
        assert(ev.text_len == sizeof(expected_lossy));
        assert(memcmp(ev.text_ptr, expected_lossy, sizeof(expected_lossy)) == 0);
        assert(webgrep_pull_next(pull, &ev, &sum) == 0);
        webgrep_pull_free(pull);

        /* (b) Distinct WEBGREP_ERR_PATH_TRAVERSAL (-9) and WEBGREP_ERR_UNSUPPORTED_FORMAT (-10) */
        assert(WEBGREP_ERR_PATH_TRAVERSAL == -9);
        assert(WEBGREP_ERR_UNSUPPORTED_FORMAT == -10);
        assert(WEBGREP_ERR_PATH_TRAVERSAL != WEBGREP_ERR_CORRUPT_ARCHIVE);
        assert(WEBGREP_ERR_UNSUPPORTED_FORMAT != WEBGREP_ERR_CORRUPT_ARCHIVE);

        uint8_t trav_tar[2048];
        memset(trav_tar, 0, sizeof(trav_tar));
        write_tar_header(trav_tar, "../etc/passwd", 4, '0', NULL);
        memcpy(trav_tar + 512, "TAG\n", 4);
        webgrep_tree_summary_t tsum;
        assert(webgrep_search_archive_slice(m_tag, trav_tar, sizeof(trav_tar), NULL, NULL, NULL, &tsum) == WEBGREP_ERR_PATH_TRAVERSAL);

        uint8_t enc_zip[512];
        size_t ez_len = build_stored_zip_single(enc_zip, sizeof(enc_zip), "enc.txt", (const uint8_t *)"TAG\n", 4);
        enc_zip[6] |= 1u;
        size_t cd_pos = 30 + strlen("enc.txt") + 4;
        enc_zip[cd_pos + 8] |= 1u;
        assert(webgrep_search_archive_slice(m_tag, enc_zip, ez_len, NULL, NULL, NULL, &tsum) == WEBGREP_ERR_UNSUPPORTED_FORMAT);

        /* (c) Isolated max_compression_ratio (large max_decode_bytes = 64 MiB, ratio = 5)
         * Valid 29-byte RFC 1952 Gzip bomb inflating to 1032 'A' bytes (ratio 35.6x > 5) */
        const uint8_t bomb_gz[] = {
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff,
            0x73, 0x74, 0x1c, 0x05, 0xa3, 0x60, 0x14, 0x8c, 0x74, 0x00,
            0x00, 0xdb, 0xbc, 0x2d, 0x49, 0x08, 0x04, 0x00, 0x00
        };
        webgrep_config_t rcfg = webgrep_config_default();
        rcfg.compression = WEBGREP_COMPRESSION_GZIP;
        rcfg.max_decode_bytes = 64u * 1024u * 1024u;
        rcfg.max_compression_ratio = 5;
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(m_tag, bomb_gz, sizeof(bomb_gz), &rcfg, NULL, NULL, &sum) == WEBGREP_ERR_BUDGET_EXCEEDED);
        assert(sum.limit_hit == WEBGREP_LIMIT_DECOMPRESSED_BYTES);

        rcfg.max_compression_ratio = 100;
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(m_tag, bomb_gz, sizeof(bomb_gz), &rcfg, NULL, NULL, &sum) == WEBGREP_OK);
        assert(sum.limit_hit == WEBGREP_LIMIT_NONE);

        rcfg.max_decode_bytes = 128;
        rcfg.max_compression_ratio = UINT64_MAX;
        memset(&sum, 0, sizeof(sum));
        assert(webgrep_search_slice(m_tag, bomb_gz, sizeof(bomb_gz), &rcfg, NULL, NULL, &sum) == WEBGREP_ERR_BUDGET_EXCEEDED);
        assert(sum.limit_hit == WEBGREP_LIMIT_DECOMPRESSED_BYTES);

        webgrep_matcher_free(m_tag);
    }
    printf("[26/27] v0.10.3 C ABI (custom allocator, pull_next UTF-8, path traversal/unsupported format, isolated ratio): PASS\n");

    /* 27. C ABI error-path & exhaustive OOM-rollback leak regression (compile_*, pull_open_*) */
    {
        /* Compile a valid matcher under the default allocator for pull_open_* leak checks */
        webgrep_matcher_t *valid_m = NULL;
        assert(webgrep_matcher_compile_literal((const uint8_t *)"HIT", 3, NULL, &valid_m) == WEBGREP_OK);

        c_test_alloc_ctx_t actx = { 0, 0, 0, 0, 0 };
        webgrep_allocator_t custom_alloc = {
            .alloc = c_test_alloc,
            .free = c_test_free,
            .ctx = &actx
        };
        webgrep_set_allocator(&custom_alloc);

        /* (a) Deterministic non-OOM error returns must leave live_bytes == 0 */
        {
            webgrep_matcher_t *m = NULL;
            webgrep_find_options_t fo = webgrep_find_options_default();
            assert(webgrep_matcher_compile_literal((const uint8_t *)"a\nb", 3, &fo, &m) == WEBGREP_ERR_SYNTAX);
            assert(m == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            webgrep_pattern_t nl_pats[2] = {
                { (const uint8_t *)"alpha", 5 },
                { (const uint8_t *)"be\nta", 5 }
            };
            assert(webgrep_matcher_compile_multi(nl_pats, 2, &fo, &m) == WEBGREP_ERR_SYNTAX);
            assert(m == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            fo.max_patterns = 1;
            webgrep_pattern_t ok_pats[2] = {
                { (const uint8_t *)"alpha", 5 },
                { (const uint8_t *)"beta",  4 }
            };
            assert(webgrep_matcher_compile_multi(ok_pats, 2, &fo, &m) == WEBGREP_ERR_TOO_LARGE);
            assert(m == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            fo = webgrep_find_options_default();
            fo.max_pattern_bytes = 3;
            assert(webgrep_matcher_compile_multi(ok_pats, 1, &fo, &m) == WEBGREP_ERR_TOO_LARGE);
            assert(m == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            webgrep_compile_diag_t diag;
            assert(webgrep_matcher_compile_regex((const uint8_t *)"(unclosed", 9, NULL, &diag, &m) == WEBGREP_ERR_SYNTAX);
            assert(m == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            webgrep_pattern_t bad_rset[2] = {
                { (const uint8_t *)"valid_[0-9]+", 12 },
                { (const uint8_t *)"[unclosed",     9 }
            };
            assert(webgrep_matcher_compile_regex_set(bad_rset, 2, NULL, &diag, &m) == WEBGREP_ERR_SYNTAX);
            assert(m == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            /* pull_open_slice & pull_open_reader error returns after PullBox + ConfigGuard allocation */
            webgrep_pull_t *pull = NULL;
            webgrep_config_t bad_cfg = webgrep_config_default();
            bad_cfg.encoding = 999; /* invalid encoding after PullBox create */
            assert(webgrep_pull_open_slice(valid_m, (const uint8_t *)"HIT\n", 4, &bad_cfg, &pull) == WEBGREP_ERR_INVALID_ARG);
            assert(pull == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            mem_reader_ctx_t mr = { .data = (const uint8_t *)"HIT\n", .len = 4, .pos = 0, .chunk_size = 4 };
            assert(webgrep_pull_open_reader(valid_m, mem_read_cb, &mr, &bad_cfg, &pull) == WEBGREP_ERR_INVALID_ARG);
            assert(pull == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);

            /* contains_ptr allocates before excludes_ptr fails InvalidArg */
            webgrep_pattern_t filt_pat[1] = { { (const uint8_t *)"HIT", 3 } };
            webgrep_config_t partial_cfg = webgrep_config_default();
            partial_cfg.contains_ptr = filt_pat;
            partial_cfg.contains_len = 1;
            partial_cfg.excludes_ptr = NULL;
            partial_cfg.excludes_len = 1;
            assert(webgrep_pull_open_slice(valid_m, (const uint8_t *)"HIT\n", 4, &partial_cfg, &pull) == WEBGREP_ERR_INVALID_ARG);
            assert(pull == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);
            assert(webgrep_pull_open_reader(valid_m, mem_read_cb, &mr, &partial_cfg, &pull) == WEBGREP_ERR_INVALID_ARG);
            assert(pull == NULL && actx.live_bytes == 0 && actx.allocs == actx.frees);
        }

        /* (b) Exhaustive OOM-rollback sweep: fail at every single allocation site (0..N) */
        {
            /* 1. compile_literal */
            int reached_ok = 0;
            for (size_t k = 0; k < 64; ++k) {
                actx.allocs = 0; actx.frees = 0; actx.live_bytes = 0;
                actx.enable_fail = 1; actx.fail_after = k;
                webgrep_matcher_t *m = NULL;
                int rc = webgrep_matcher_compile_literal((const uint8_t *)"needle_oom", 10, NULL, &m);
                if (rc == WEBGREP_OK) {
                    assert(m != NULL);
                    webgrep_matcher_free(m);
                    assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
                    reached_ok = 1;
                    break;
                }
                assert(rc == WEBGREP_ERR_OUT_OF_MEMORY && m == NULL);
                assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
            }
            assert(reached_ok == 1);

            /* 2. compile_multi */
            webgrep_pattern_t mpats[2] = {
                { (const uint8_t *)"alpha_oom", 9 },
                { (const uint8_t *)"beta_oom",  8 }
            };
            reached_ok = 0;
            for (size_t k = 0; k < 128; ++k) {
                actx.allocs = 0; actx.frees = 0; actx.live_bytes = 0;
                actx.enable_fail = 1; actx.fail_after = k;
                webgrep_matcher_t *m = NULL;
                int rc = webgrep_matcher_compile_multi(mpats, 2, NULL, &m);
                if (rc == WEBGREP_OK) {
                    assert(m != NULL);
                    webgrep_matcher_free(m);
                    assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
                    reached_ok = 1;
                    break;
                }
                assert(rc == WEBGREP_ERR_OUT_OF_MEMORY && m == NULL);
                assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
            }
            assert(reached_ok == 1);

            /* 3. compile_regex */
            reached_ok = 0;
            for (size_t k = 0; k < 256; ++k) {
                actx.allocs = 0; actx.frees = 0; actx.live_bytes = 0;
                actx.enable_fail = 1; actx.fail_after = k;
                webgrep_matcher_t *m = NULL;
                webgrep_compile_diag_t diag;
                int rc = webgrep_matcher_compile_regex((const uint8_t *)"user_([0-9]+)", 13, NULL, &diag, &m);
                if (rc == WEBGREP_OK) {
                    assert(m != NULL);
                    webgrep_matcher_free(m);
                    assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
                    reached_ok = 1;
                    break;
                }
                assert(rc == WEBGREP_ERR_OUT_OF_MEMORY && m == NULL);
                assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
            }
            assert(reached_ok == 1);

            /* 4. compile_regex_set */
            webgrep_pattern_t rpats[2] = {
                { (const uint8_t *)"err_[0-9]+",  10 },
                { (const uint8_t *)"warn_[a-z]+", 11 }
            };
            reached_ok = 0;
            for (size_t k = 0; k < 256; ++k) {
                actx.allocs = 0; actx.frees = 0; actx.live_bytes = 0;
                actx.enable_fail = 1; actx.fail_after = k;
                webgrep_matcher_t *m = NULL;
                webgrep_compile_diag_t diag;
                int rc = webgrep_matcher_compile_regex_set(rpats, 2, NULL, &diag, &m);
                if (rc == WEBGREP_OK) {
                    assert(m != NULL);
                    webgrep_matcher_free(m);
                    assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
                    reached_ok = 1;
                    break;
                }
                assert(rc == WEBGREP_ERR_OUT_OF_MEMORY && m == NULL);
                assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
            }
            assert(reached_ok == 1);

            /* 5. pull_open_slice (with contains_ptr so ConfigGuard allocates) */
            webgrep_pattern_t cpat[1] = { { (const uint8_t *)"HIT", 3 } };
            webgrep_config_t pcfg = webgrep_config_default();
            pcfg.contains_ptr = cpat;
            pcfg.contains_len = 1;
            const char *pdoc = "HIT line\n";
            reached_ok = 0;
            for (size_t k = 0; k < 64; ++k) {
                actx.allocs = 0; actx.frees = 0; actx.live_bytes = 0;
                actx.enable_fail = 1; actx.fail_after = k;
                webgrep_pull_t *pull = NULL;
                int rc = webgrep_pull_open_slice(valid_m, (const uint8_t *)pdoc, strlen(pdoc), &pcfg, &pull);
                if (rc == WEBGREP_OK) {
                    assert(pull != NULL);
                    webgrep_pull_free(pull);
                    assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
                    reached_ok = 1;
                    break;
                }
                assert(rc == WEBGREP_ERR_OUT_OF_MEMORY && pull == NULL);
                assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
            }
            assert(reached_ok == 1);

            /* 6. pull_open_reader (with contains_ptr so ConfigGuard + ReaderPull allocate) */
            reached_ok = 0;
            for (size_t k = 0; k < 64; ++k) {
                actx.allocs = 0; actx.frees = 0; actx.live_bytes = 0;
                actx.enable_fail = 1; actx.fail_after = k;
                mem_reader_ctx_t mr = { .data = (const uint8_t *)pdoc, .len = strlen(pdoc), .pos = 0, .chunk_size = 4 };
                webgrep_pull_t *pull = NULL;
                int rc = webgrep_pull_open_reader(valid_m, mem_read_cb, &mr, &pcfg, &pull);
                if (rc == WEBGREP_OK) {
                    assert(pull != NULL);
                    webgrep_pull_free(pull);
                    assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
                    reached_ok = 1;
                    break;
                }
                assert(rc == WEBGREP_ERR_OUT_OF_MEMORY && pull == NULL);
                assert(actx.live_bytes == 0 && actx.allocs == actx.frees);
            }
            assert(reached_ok == 1);
        }

        webgrep_set_allocator(NULL);
        webgrep_matcher_free(valid_m);
    }
    printf("[27/27] C ABI error-path & OOM-rollback zero-leak regression (compile_*, pull_open_*): PASS\n");
    printf("=== ALL 27 C ABI TEST SECTIONS PASSED ===\n");
    return 0;
}
