#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_CORPUS_DIR "/home/fun/code/zig/zg-corpus"
#define DEFAULT_RG_BIN     "/usr/bin/rg"

typedef struct {
    const char *id;
    const char *desc;
    int is_dir;
    int check_exact_bytes; /* 1 = verify byte-for-byte FNV-1a hash of stdout; 0 = verify count */
    int threads;
    const char *target_subpath; /* NULL = corpus root directory */
    const char *cache_subpath;  /* Optional single file for cache warmup/eviction when target is dir with -g */
    const char *args[20];       /* NULL-terminated common flags + pattern(s), WITHOUT target_path or --mmap/--no-mmap */
} Scenario;

static const Scenario SCENARIOS[] = {
    {
        "S01_log_lit_rare",
        "log.txt (514 MB) rare literal 'req=04203afdc6de' (-c)",
        0, 0, 1, "log.txt", NULL,
        { "-c", "--no-config", "-F", "-j", "1", "req=04203afdc6de", NULL }
    },
    {
        "S02_log_lit_dense",
        "log.txt (514 MB) dense literal 'ERROR [http]' (-c, 249k hits)",
        0, 0, 1, "log.txt", NULL,
        { "-c", "--no-config", "-F", "-j", "1", "ERROR [http]", NULL }
    },
    {
        "S03_log_lit_dense_lines",
        "log.txt (514 MB) dense literal 'ERROR [http]' (-n full line output, 26 MB stdout)",
        0, 1, 1, "log.txt", NULL,
        { "-n", "--no-config", "-F", "-j", "1", "ERROR [http]", NULL }
    },
    {
        "S04_log_lit_icase",
        "log.txt (514 MB) case-insensitive '-F -i error [http]' (-c, 249k hits)",
        0, 0, 1, "log.txt", NULL,
        { "-c", "--no-config", "-F", "-i", "-j", "1", "error [http]", NULL }
    },
    {
        "S05_log_multi6_or",
        "log.txt (514 MB) 6-pattern literal OR (-c)",
        0, 0, 1, "log.txt", NULL,
        {
            "-c", "--no-config", "-F", "-j", "1",
            "-e", "req=04203afdc6de",
            "-e", "req=e5fbdd210a72",
            "-e", "FATAL [auth]",
            "-e", "PANIC [kernel]",
            "-e", "DEADLOCK [tx]",
            "-e", "CORRUPT [wal]",
            NULL
        }
    },
    {
        "S06_log_regex_prefilter",
        "log.txt (514 MB) prefix regex 'ERROR \\[http\\] req=[0-9a-f]{12}...' (-c, 125k hits)",
        0, 0, 1, "log.txt", NULL,
        {
            "-c", "--no-config", "--no-unicode", "-j", "1",
            "ERROR \\[http\\] req=[0-9a-f]{12} user=[0-9]+ latency=[0-9]{4}ms",
            NULL
        }
    },
    {
        "S07_log_regex_midlit",
        "log.txt (514 MB) interior-literal regex '\\[[a-z]{4,5}\\] req=0000[0-9a-f]{8}' (-c)",
        0, 0, 1, "log.txt", NULL,
        {
            "-c", "--no-config", "--no-unicode", "-j", "1",
            "\\[[a-z]{4,5}\\] req=0000[0-9a-f]{8}",
            NULL
        }
    },
    {
        "S08_log_regex_alt",
        "log.txt (514 MB) alternation regex '(FATAL \\[auth\\]|PANIC \\[kernel\\]|...)' (-c)",
        0, 0, 1, "log.txt", NULL,
        {
            "-c", "--no-config", "--no-unicode", "-j", "1",
            "(FATAL \\[auth\\]|PANIC \\[kernel\\]|DEADLOCK \\[tx\\]|req=04203afdc6de)",
            NULL
        }
    },
    {
        "S09_long_lit_miss",
        "long.txt (512 MB, 310-600 KiB lines) literal miss (-c)",
        0, 0, 1, "long.txt", NULL,
        { "-c", "--no-config", "-F", "-j", "1", "UNLIKELY_NEEDLE_XYZ99", NULL }
    },
    {
        "S10_short_lit_miss",
        "short.txt (300 MB, 120M short lines) literal miss (-c)",
        0, 0, 1, "short.txt", NULL,
        { "-c", "--no-config", "-F", "-j", "1", "UNLIKELY_NEEDLE_XYZ99", NULL }
    },
    {
        "S11_words_lit_rare",
        "words.txt (540 MB) rare literal 'zealtionou' (-c, 1356 hits)",
        0, 0, 1, "words.txt", NULL,
        { "-c", "--no-config", "-F", "-j", "1", "zealtionou", NULL }
    },
    {
        "S12_words_regex",
        "words.txt (540 MB) regex 'zealtionou\\s+[a-z]+\\s+the' (-c, 40 hits)",
        0, 0, 1, "words.txt", NULL,
        { "-c", "--no-config", "--no-unicode", "-j", "1", "zealtionou\\s+[a-z]+\\s+the", NULL }
    },
    {
        "S12b_words_regex_dense",
        "words.txt (540 MB) regex '[a-z]+tion\\s+[a-z]+\\s+the' (-c, 27k hits)",
        0, 0, 1, "words.txt", NULL,
        { "-c", "--no-config", "--no-unicode", "-j", "1", "[a-z]+tion\\s+[a-z]+\\s+the", NULL }
    },
    {
        "S13_random_bin_quit",
        "random.bin (537 MB binary) early NUL binary quit via -g random.bin (-c)",
        1, 0, 1, NULL, "random.bin",
        { "-c", "--no-config", "--no-ignore", "-g", "random.bin", "-F", "-j", "1", "NEEDLE", NULL }
    },
    {
        "S13b_random_bin_text",
        "random.bin (537 MB binary) full-file scan with -a/--text (-c)",
        0, 0, 1, "random.bin", NULL,
        { "-c", "--no-config", "-a", "-F", "-j", "1", "NEEDLE", NULL }
    },
    {
        "S14_dir_all_T1",
        "zg-corpus/ (2.488 GB, 9 files, 1 thread) directory search (-c)",
        1, 0, 1, NULL, NULL,
        { "-c", "--no-config", "--no-ignore", "-F", "-j", "1", "req=04203afdc6de", NULL }
    },
    {
        "S15_dir_all_T8",
        "zg-corpus/ (2.488 GB, 9 files, 8 threads) directory search (-c)",
        1, 0, 8, NULL, NULL,
        { "-c", "--no-config", "--no-ignore", "-F", "-j", "8", "req=04203afdc6de", NULL }
    },
};

#define NUM_SCENARIOS (sizeof(SCENARIOS) / sizeof(SCENARIOS[0]))

static const char *g_corpus_dir = DEFAULT_CORPUS_DIR;
static const char *g_rg_bin     = DEFAULT_RG_BIN;

static void resolve_target_path(const Scenario *sc, char *buf, size_t cap) {
    if (sc->target_subpath == NULL) {
        snprintf(buf, cap, "%s", g_corpus_dir);
    } else {
        snprintf(buf, cap, "%s/%s", g_corpus_dir, sc->target_subpath);
    }
}

static void resolve_cache_path(const Scenario *sc, char *buf, size_t cap, int *out_is_dir) {
    if (sc->cache_subpath != NULL) {
        snprintf(buf, cap, "%s/%s", g_corpus_dir, sc->cache_subpath);
        *out_is_dir = 0;
    } else if (sc->target_subpath != NULL) {
        snprintf(buf, cap, "%s/%s", g_corpus_dir, sc->target_subpath);
        *out_is_dir = 0;
    } else {
        snprintf(buf, cap, "%s", g_corpus_dir);
        *out_is_dir = 1;
    }
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void pin_cpus(int threads) {
    long ncpu_raw = sysconf(_SC_NPROCESSORS_ONLN);
    int ncpu = (ncpu_raw > 0) ? (int)ncpu_raw : 1;
    if (ncpu > CPU_SETSIZE) ncpu = CPU_SETSIZE;

    cpu_set_t mask;
    CPU_ZERO(&mask);
    if (threads <= 1) {
        /* Pin single-thread runs to physical Core 2 (if available) instead of Core 0 (IRQ/housekeeping core) */
        int target_cpu = (ncpu > 2) ? 2 : 0;
        CPU_SET(target_cpu, &mask);
    } else {
        /* Prefer even physical core IDs (e.g. 8 physical Zen 3+ cores on Ryzen 7 7735U), clamped to ncpu */
        int added = 0;
        for (int c = 0; c < ncpu && added < threads; c += 2) {
            CPU_SET(c, &mask);
            added++;
        }
        for (int c = 1; c < ncpu && added < threads; c += 2) {
            CPU_SET(c, &mask);
            added++;
        }
    }
    if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
        CPU_ZERO(&mask);
        for (int i = 0; i < ncpu; i++) CPU_SET(i, &mask);
        (void)sched_setaffinity(0, sizeof(mask), &mask);
    }
}

static size_t g_walk_root_len = 0;
static uint64_t g_sum_bytes = 0;
static uint64_t g_res_pages = 0;
static uint64_t g_tot_pages = 0;

static void count_file_residency(const char *fpath, uint64_t *out_res, uint64_t *out_tot) {
    int fd = open(fpath, O_RDONLY);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return;
    }
    size_t sz = (size_t)st.st_size;
    long ps = sysconf(_SC_PAGESIZE);
    size_t npages = (sz + (size_t)ps - 1) / (size_t)ps;
    void *addr = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr != MAP_FAILED) {
        unsigned char *vec = (unsigned char *)malloc(npages);
        if (vec && mincore(addr, sz, vec) == 0) {
            uint64_t r = 0;
            for (size_t i = 0; i < npages; i++) r += (vec[i] & 1u);
            *out_res += r;
            *out_tot += npages;
        }
        free(vec);
        munmap(addr, sz);
    }
    close(fd);
}

static void drop_single_file_cache(const char *fpath) {
    int fd = open(fpath, O_RDONLY);
    if (fd < 0) return;
    (void)fsync(fd);
    (void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
}

static void warm_file(const char *fpath) {
    int fd = open(fpath, O_RDONLY);
    if (fd < 0) return;
    char *buf = (char *)malloc(1024 * 1024);
    if (buf) {
        volatile unsigned char acc = 0;
        ssize_t n;
        while ((n = read(fd, buf, 1024 * 1024)) > 0) {
            for (ssize_t i = 0; i < n; i += 4096) acc ^= (unsigned char)buf[i];
        }
        (void)acc;
        free(buf);
    }
    close(fd);
}

static int nftw_sum_bytes(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (typeflag != FTW_F || !sb) return 0;
    if (strstr(fpath + g_walk_root_len, "/.") != NULL) return 0;
    g_sum_bytes += (uint64_t)sb->st_size;
    return 0;
}

static int nftw_drop_cache(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    if (strstr(fpath + g_walk_root_len, "/.") != NULL) return 0;
    drop_single_file_cache(fpath);
    return 0;
}

static int nftw_count_residency(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    if (strstr(fpath + g_walk_root_len, "/.") != NULL) return 0;
    count_file_residency(fpath, &g_res_pages, &g_tot_pages);
    return 0;
}

static int nftw_warm_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    if (strstr(fpath + g_walk_root_len, "/.") != NULL) return 0;
    warm_file(fpath);
    return 0;
}

static uint64_t get_target_bytes(const Scenario *sc) {
    char cpath[1024];
    int is_dir = 0;
    resolve_cache_path(sc, cpath, sizeof(cpath), &is_dir);
    struct stat st;
    if (!is_dir) {
        if (stat(cpath, &st) == 0) return (uint64_t)st.st_size;
        return 0;
    }
    g_walk_root_len = strlen(cpath);
    g_sum_bytes = 0;
    (void)nftw(cpath, nftw_sum_bytes, 16, FTW_PHYS);
    return g_sum_bytes;
}

/* Drops OS page cache and verifies via mincore() that 0 pages remain resident. */
static uint64_t evict_and_verify_zero(const Scenario *sc) {
    char cpath[1024];
    int is_dir = 0;
    resolve_cache_path(sc, cpath, sizeof(cpath), &is_dir);
    g_walk_root_len = strlen(cpath);

    for (int attempt = 0; attempt < 3; attempt++) {
        if (!is_dir) {
            drop_single_file_cache(cpath);
        } else {
            (void)nftw(cpath, nftw_drop_cache, 16, FTW_PHYS);
        }
        g_res_pages = 0;
        g_tot_pages = 0;
        if (!is_dir) {
            count_file_residency(cpath, &g_res_pages, &g_tot_pages);
        } else {
            (void)nftw(cpath, nftw_count_residency, 16, FTW_PHYS);
        }
        if (g_res_pages == 0) return 0;
    }
    g_res_pages = 0;
    g_tot_pages = 0;
    if (!is_dir) {
        count_file_residency(cpath, &g_res_pages, &g_tot_pages);
    } else {
        (void)nftw(cpath, nftw_count_residency, 16, FTW_PHYS);
    }
    return g_res_pages;
}

static double ensure_warm_cache(const Scenario *sc) {
    char cpath[1024];
    int is_dir = 0;
    resolve_cache_path(sc, cpath, sizeof(cpath), &is_dir);
    g_walk_root_len = strlen(cpath);

    if (!is_dir) {
        warm_file(cpath);
    } else {
        (void)nftw(cpath, nftw_warm_file, 16, FTW_PHYS);
    }
    g_res_pages = 0;
    g_tot_pages = 0;
    if (!is_dir) {
        count_file_residency(cpath, &g_res_pages, &g_tot_pages);
    } else {
        (void)nftw(cpath, nftw_count_residency, 16, FTW_PHYS);
    }
    return g_tot_pages > 0 ? (100.0 * (double)g_res_pages / (double)g_tot_pages) : 100.0;
}

static void build_argv(const char *bin, const Scenario *sc, const char *io_flag, char *target_buf, size_t target_cap, char **argv_out) {
    resolve_target_path(sc, target_buf, target_cap);
    int k = 0;
    argv_out[k++] = (char *)bin;
    for (int i = 0; sc->args[i] != NULL; i++) {
        argv_out[k++] = (char *)sc->args[i];
    }
    if (io_flag != NULL) {
        argv_out[k++] = (char *)io_flag;
    }
    argv_out[k++] = target_buf;
    argv_out[k] = NULL;
}

typedef struct {
    int exit_code;
    uint64_t total_bytes;
    uint64_t fnv_hash;
    uint64_t parsed_count;
} CaptureResult;

static void parse_count_line(const char *line, int is_dir, uint64_t *parsed_count) {
    if (line[0] == '\0') return;
    const char *colon = strrchr(line, ':');
    const char *num_str = (is_dir && colon) ? (colon + 1) : line;
    char *endp = NULL;
    unsigned long long v = strtoull(num_str, &endp, 10);
    if (endp && endp != num_str) *parsed_count += (uint64_t)v;
}

static CaptureResult run_and_capture(const char *bin, const Scenario *sc, const char *io_flag) {
    CaptureResult cr = { -1, 0, 14695981039346656037ULL, 0 };
    int pipefd[2];
    if (pipe(pipefd) != 0) return cr;

    char target_buf[1024];
    char *argv[32];
    build_argv(bin, sc, io_flag, target_buf, sizeof(target_buf), argv);

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        close(pipefd[1]);
        execv(bin, argv);
        _exit(127);
    }
    close(pipefd[1]);

    char line_buf[4096];
    size_t line_len = 0;

    unsigned char buf[65536];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            cr.fnv_hash ^= (uint64_t)buf[i];
            cr.fnv_hash *= 1099511628211ULL;
            if (!sc->check_exact_bytes) {
                if (buf[i] == '\n') {
                    line_buf[line_len] = '\0';
                    parse_count_line(line_buf, sc->is_dir, &cr.parsed_count);
                    line_len = 0;
                } else if (line_len + 1 < sizeof(line_buf)) {
                    line_buf[line_len++] = (char)buf[i];
                }
            }
        }
        cr.total_bytes += (uint64_t)n;
    }
    if (!sc->check_exact_bytes && line_len > 0) {
        line_buf[line_len] = '\0';
        parse_count_line(line_buf, sc->is_dir, &cr.parsed_count);
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) cr.exit_code = WEXITSTATUS(status);

    return cr;
}

typedef struct {
    double wall_ms;
    double user_ms;
    double sys_ms;
    long minflt;
    long majflt;
} TimedSample;

static TimedSample run_timed_once(const char *bin, const Scenario *sc, const char *io_flag, int devnull_fd) {
    TimedSample s = { 0, 0, 0, 0, 0 };
    char target_buf[1024];
    char *argv[32];
    build_argv(bin, sc, io_flag, target_buf, sizeof(target_buf), argv);

    double t0 = now_ms();
    pid_t pid = fork();
    if (pid == 0) {
        dup2(devnull_fd, STDOUT_FILENO);
        dup2(devnull_fd, STDERR_FILENO);
        execv(bin, argv);
        _exit(127);
    }
    int status = 0;
    struct rusage ru;
    wait4(pid, &status, 0, &ru);
    s.wall_ms = now_ms() - t0;
    s.user_ms = (double)ru.ru_utime.tv_sec * 1000.0 + (double)ru.ru_utime.tv_usec / 1000.0;
    s.sys_ms  = (double)ru.ru_stime.tv_sec * 1000.0 + (double)ru.ru_stime.tv_usec / 1000.0;
    s.minflt  = ru.ru_minflt;
    s.majflt  = ru.ru_majflt;
    return s;
}

static int cmp_sample_by_wall(const void *a, const void *b) {
    const TimedSample *sa = (const TimedSample *)a;
    const TimedSample *sb = (const TimedSample *)b;
    return (sa->wall_ms > sb->wall_ms) - (sa->wall_ms < sb->wall_ms);
}

typedef struct {
    double median;
    double min;
    double max;
    double mean;
    double cv_pct;
    double med_user;
    double med_sys;
    long med_minflt;
    long med_majflt;
} Stats;

static Stats compute_stats(const TimedSample *samples, int n) {
    TimedSample sorted[32];
    for (int i = 0; i < n; i++) sorted[i] = samples[i];
    qsort(sorted, (size_t)n, sizeof(TimedSample), cmp_sample_by_wall);

    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += sorted[i].wall_ms;
    double mean = sum / (double)n;
    double var = 0.0;
    for (int i = 0; i < n; i++) {
        double d = sorted[i].wall_ms - mean;
        var += d * d;
    }
    double sd = (n > 1) ? sqrt(var / (double)(n - 1)) : 0.0;

    const TimedSample *med = &sorted[n / 2];
    Stats st;
    st.median     = med->wall_ms;
    st.min        = sorted[0].wall_ms;
    st.max        = sorted[n - 1].wall_ms;
    st.mean       = mean;
    st.cv_pct     = (mean > 0.0) ? (sd / mean * 100.0) : 0.0;
    st.med_user   = med->user_ms;
    st.med_sys    = med->sys_ms;
    st.med_minflt = med->minflt;
    st.med_majflt = med->majflt;
    return st;
}

typedef struct {
    const char *label;
    const char *bin;
    const char *io_flag;
} Contender;

static int run_scenario(const Scenario *sc, const char *wg_bin, int warm_rounds, int do_cold) {
    pin_cpus(sc->threads);
    uint64_t target_bytes = get_target_bytes(sc);
    char target_buf[1024];
    resolve_target_path(sc, target_buf, sizeof(target_buf));

    printf("\n========================================================================================\n");
    printf("SCENARIO: %s | %s\n", sc->id, sc->desc);
    printf("Target:   %s (%llu bytes = %.2f MB = %.2f MiB) | Threads: %d\n",
           target_buf, (unsigned long long)target_bytes,
           (double)target_bytes / 1e6, (double)target_bytes / (1024.0 * 1024.0), sc->threads);
    printf("----------------------------------------------------------------------------------------\n");

    /* Phase 0: Strict Accuracy Verification */
    CaptureResult rg_cap_nm = run_and_capture(g_rg_bin, sc, "--no-mmap");
    CaptureResult rg_cap_mm = run_and_capture(g_rg_bin, sc, "--mmap");
    CaptureResult wg_cap_nm = run_and_capture(wg_bin, sc, "--no-mmap");
    CaptureResult wg_cap_mm = run_and_capture(wg_bin, sc, "--mmap");

    if (sc->check_exact_bytes) {
        int ok = (rg_cap_nm.exit_code == wg_cap_nm.exit_code) &&
                 (rg_cap_nm.total_bytes == wg_cap_nm.total_bytes) &&
                 (rg_cap_nm.fnv_hash == wg_cap_nm.fnv_hash) &&
                 (rg_cap_nm.fnv_hash == wg_cap_mm.fnv_hash);
        printf("[Accuracy] Exact Byte-for-Byte stdout check: rg=%llu bytes (hash=%016llx) vs wg=%llu bytes (hash=%016llx) -> %s\n",
               (unsigned long long)rg_cap_nm.total_bytes, (unsigned long long)rg_cap_nm.fnv_hash,
               (unsigned long long)wg_cap_nm.total_bytes, (unsigned long long)wg_cap_nm.fnv_hash,
               ok ? "PASS (100% IDENTICAL)" : "FAIL");
        if (!ok) return 1;
    } else {
        int ok = (rg_cap_nm.exit_code == wg_cap_nm.exit_code) &&
                 (rg_cap_mm.exit_code == wg_cap_mm.exit_code) &&
                 (rg_cap_nm.parsed_count == wg_cap_nm.parsed_count) &&
                 (rg_cap_nm.parsed_count == wg_cap_mm.parsed_count);
        printf("[Accuracy] Count & Exit check: rg=%llu (rc=%d) | wg_nommap=%llu wg_mmap=%llu (rc=%d) -> %s\n",
               (unsigned long long)rg_cap_nm.parsed_count, rg_cap_nm.exit_code,
               (unsigned long long)wg_cap_nm.parsed_count,
               (unsigned long long)wg_cap_mm.parsed_count,
               wg_cap_nm.exit_code,
               ok ? "PASS" : "FAIL");
        if (!ok) return 1;
    }

    int devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0) return 1;

    Contender contenders[4] = {
        { "wg --no-mmap",   wg_bin,   "--no-mmap" },
        { "wg --mmap",      wg_bin,   "--mmap" },
        { "rg --no-mmap",   g_rg_bin, "--no-mmap" },
        { "rg --mmap",      g_rg_bin, "--mmap" },
    };

    /* Phase 1: Warm-Cache Interleaved ABBA Benchmark */
    double res_pct = ensure_warm_cache(sc);
    for (int w = 0; w < 2; w++) {
        for (int c = 0; c < 4; c++) {
            (void)run_timed_once(contenders[c].bin, sc, contenders[c].io_flag, devnull);
        }
    }

    TimedSample warm_samples[4][32];
    for (int r = 0; r < warm_rounds; r++) {
        for (int step = 0; step < 4; step++) {
            int c = (r % 2 == 0) ? step : (3 - step);
            warm_samples[c][r] = run_timed_once(contenders[c].bin, sc, contenders[c].io_flag, devnull);
        }
    }

    Stats warm_st[4];
    printf("[Warm Cache (mincore=%.1f%%, %d interleaved rounds)]\n", res_pct, warm_rounds);
    for (int c = 0; c < 4; c++) {
        warm_st[c] = compute_stats(warm_samples[c], warm_rounds);
        double gbs = ((double)target_bytes / 1e9) / (warm_st[c].median / 1000.0);
        printf("  %-14s : med=%7.2f ms (min=%6.2f, max=%6.2f, cv=%4.1f%%) | %6.3f GB/s | usr=%5.1f sys=%5.1f minflt=%ld\n",
               contenders[c].label, warm_st[c].median, warm_st[c].min, warm_st[c].max, warm_st[c].cv_pct,
               gbs, warm_st[c].med_user, warm_st[c].med_sys, warm_st[c].med_minflt);
    }

    double wg_best_warm = warm_st[0].median < warm_st[1].median ? warm_st[0].median : warm_st[1].median;
    double rg_best_warm = warm_st[2].median < warm_st[3].median ? warm_st[2].median : warm_st[3].median;
    double speedup_best   = rg_best_warm / wg_best_warm;
    double speedup_nommap = warm_st[2].median / warm_st[0].median;
    double speedup_mmap   = warm_st[3].median / warm_st[1].median;

    printf("  >> WARM VERDICT: wg_best=%.2f ms vs rg_best=%.2f ms => %.2fx [%s] | (no-mmap: %.2fx, mmap: %.2fx)\n",
           wg_best_warm, rg_best_warm, speedup_best,
           (wg_best_warm <= rg_best_warm) ? "WIN (SURPASSED rg!)" : "LAGGING (NEEDS OPT)",
           speedup_nommap, speedup_mmap);

    /* Phase 2: Cold-Disk Interleaved ABBA Benchmark */
    if (do_cold) {
        int cold_rounds = 5;
        TimedSample cold_samples[4][16];
        uint64_t max_residual_pages = 0;
        for (int r = 0; r < cold_rounds; r++) {
            for (int step = 0; step < 4; step++) {
                int c = (r % 2 == 0) ? step : (3 - step);
                uint64_t rem = evict_and_verify_zero(sc);
                if (rem != 0) {
                    fprintf(stderr, "FATAL: cold cache eviction failed (residual pages = %llu > 0)\n",
                            (unsigned long long)rem);
                    close(devnull);
                    return 2;
                }
                if (rem > max_residual_pages) max_residual_pages = rem;
                cold_samples[c][r] = run_timed_once(contenders[c].bin, sc, contenders[c].io_flag, devnull);
            }
        }
        Stats cold_st[4];
        printf("[Cold Disk (fsync + POSIX_FADV_DONTNEED + mincore max_res_pages=%llu, %d interleaved rounds)]\n",
               (unsigned long long)max_residual_pages, cold_rounds);
        for (int c = 0; c < 4; c++) {
            cold_st[c] = compute_stats(cold_samples[c], cold_rounds);
            double gbs = ((double)target_bytes / 1e9) / (cold_st[c].median / 1000.0);
            printf("  %-14s : med=%7.2f ms (min=%6.2f, max=%6.2f, cv=%4.1f%%) | %6.3f GB/s | usr=%5.1f sys=%5.1f majflt=%ld\n",
                   contenders[c].label, cold_st[c].median, cold_st[c].min, cold_st[c].max, cold_st[c].cv_pct,
                   gbs, cold_st[c].med_user, cold_st[c].med_sys, cold_st[c].med_majflt);
        }
        double wg_best_cold = cold_st[0].median < cold_st[1].median ? cold_st[0].median : cold_st[1].median;
        double rg_best_cold = cold_st[2].median < cold_st[3].median ? cold_st[2].median : cold_st[3].median;
        printf("  >> COLD VERDICT: wg_best=%.2f ms vs rg_best=%.2f ms => %.2fx [%s] | (no-mmap: %.2fx, mmap: %.2fx)\n",
               wg_best_cold, rg_best_cold, rg_best_cold / wg_best_cold,
               (wg_best_cold <= rg_best_cold) ? "WIN (SURPASSED rg!)" : "LAGGING (NEEDS OPT)",
               cold_st[2].median / cold_st[0].median,
               cold_st[3].median / cold_st[1].median);
    }

    close(devnull);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    const char *wg_bin = "zig-out/bin/wg-cli";
    const char *filter = (argc > 1) ? argv[1] : "all";
    int do_cold = 0;
    int warm_rounds = 9;

    const char *env_corpus = getenv("CORPUS_DIR");
    if (env_corpus && env_corpus[0]) g_corpus_dir = env_corpus;
    const char *env_rg = getenv("RG_BIN");
    if (env_rg && env_rg[0]) g_rg_bin = env_rg;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--cold") == 0) do_cold = 1;
        else if (strcmp(argv[i], "--warm-rounds") == 0 && i + 1 < argc) {
            warm_rounds = atoi(argv[++i]);
            if (warm_rounds < 3) warm_rounds = 3;
            if (warm_rounds > 31) warm_rounds = 31;
        } else if (strcmp(argv[i], "--wg-bin") == 0 && i + 1 < argc) {
            wg_bin = argv[++i];
        } else if (strcmp(argv[i], "--corpus-dir") == 0 && i + 1 < argc) {
            g_corpus_dir = argv[++i];
        } else if (strcmp(argv[i], "--rg-bin") == 0 && i + 1 < argc) {
            g_rg_bin = argv[++i];
        }
    }

    if (strcmp(filter, "list") == 0) {
        for (size_t i = 0; i < NUM_SCENARIOS; i++) {
            printf("%2zu: %-24s %s\n", i + 1, SCENARIOS[i].id, SCENARIOS[i].desc);
        }
        return 0;
    }

    int ran = 0;
    for (size_t i = 0; i < NUM_SCENARIOS; i++) {
        if (strcmp(filter, "all") == 0 || strstr(SCENARIOS[i].id, filter) != NULL) {
            int rc = run_scenario(&SCENARIOS[i], wg_bin, warm_rounds, do_cold);
            if (rc != 0) return rc;
            ran++;
        }
    }
    if (ran == 0) {
        fprintf(stderr, "No scenario matched '%s'\n", filter);
        return 2;
    }
    return 0;
}
