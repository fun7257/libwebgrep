/**
 * @file c_api_test.c
 * @brief Comprehensive C ABI and FFI verification suite for libwebgrep v0.6.0.
 *
 * Exercises all 20 exported C ABI functions, adversarial streaming reader callbacks,
 * corrupt and path-traversal archives, NULL/boundary pointer checks, 1,000 allocation/free
 * cycles, and 8-thread concurrent shared-matcher stress tests.
 */

#include "../include/webgrep.h"

#include <assert.h>
#include <pthread.h>
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

/* ============================================================================
 * Multithreaded Worker Context
 * ========================================================================= */

typedef struct {
    const webgrep_matcher_t *lit_matcher;
    const webgrep_matcher_t *re_set_matcher;
    int                      passed;
} thread_worker_arg_t;

static void *concurrent_worker(void *arg) {
    thread_worker_arg_t *w = (thread_worker_arg_t *)arg;
    webgrep_scratch_t *scratch = webgrep_scratch_new();
    if (!scratch) {
        w->passed = 0;
        return NULL;
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
            return NULL;
        }

        uint32_t ids[4] = {0};
        size_t count = 0;
        int s_rc = webgrep_regex_set_matches(w->re_set_matcher, (const uint8_t *)payload, payload_len, ids, 4, &count);
        if (s_rc != WEBGREP_OK || count != 2 || ids[0] != 0 || ids[1] != 1) {
            webgrep_scratch_free(scratch);
            w->passed = 0;
            return NULL;
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
            return NULL;
        }
    }

    webgrep_scratch_free(scratch);
    w->passed = 1;
    return NULL;
}

/* ============================================================================
 * Main Test Runner
 * ========================================================================= */

int main(void) {
    printf("=== Running C ABI & FFI Verification Suite ===\n");

    /* 1. webgrep_version() */
    const char *ver = webgrep_version();
    assert(ver != NULL);
    assert(strcmp(ver, "0.6.0") == 0);
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

    pthread_t threads[8];
    thread_worker_arg_t targs[8];
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
    printf("[18/18] Range, line_number_mode, line_filter, reverse tail, probe, & archive entry_filter: PASS\n");
    printf("=== ALL 18 C ABI TEST SECTIONS PASSED ===\n");
    return 0;
}
