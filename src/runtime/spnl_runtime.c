/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * spinel-ebpf host-side runtime — libbpf wrapper. Implements spnl_runtime.h.
 *
 * Build: cc -O2 -I include -I src/runtime -c src/runtime/spnl_runtime.c
 * Link:  -lbpf -lelf -lz
 *
 * Per-runtime state caches `struct ring_buffer*` instances keyed by map name
 * so repeated drains of the same ringbuf don't re-create the consumer.
 */

#include "spnl_runtime.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* user-space symbolization needs ELF + mmap + /proc/<pid>/maps. */
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define SPNL_MAX_RB    8   /* number of ringbuf consumers we cache per runtime */
#define SPNL_MAX_LINKS 32  /* max programs attached via spnl_runtime_attach_all */

struct rb_slot {
    char map_name[64];
    struct ring_buffer *rb;
    spnl_runtime_event_cb cb;
    void *user_ctx;
};

struct spnl_runtime {
    struct bpf_object *obj;
    struct rb_slot rbs[SPNL_MAX_RB];
    int rb_count;

    struct bpf_link *links[SPNL_MAX_LINKS];   /* keeps kprobe etc. attached */
    int link_count;
};

static int default_libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, args);
}

spnl_runtime *spnl_runtime_init(const char *bpf_obj_path)
{
    libbpf_set_print(default_libbpf_print);

    spnl_runtime *rt = calloc(1, sizeof(*rt));
    if (!rt) return NULL;

    rt->obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!rt->obj || libbpf_get_error(rt->obj)) {
        fprintf(stderr, "spnl_runtime: open failed for %s\n", bpf_obj_path);
        free(rt);
        return NULL;
    }
    if (bpf_object__load(rt->obj)) {
        fprintf(stderr, "spnl_runtime: load failed for %s: %s\n",
                bpf_obj_path, strerror(errno));
        bpf_object__close(rt->obj);
        free(rt);
        return NULL;
    }
    return rt;
}

void spnl_runtime_destroy(spnl_runtime *rt)
{
    if (!rt) return;
    /* detach kprobe/tracepoint/... links before closing the object. */
    for (int i = 0; i < rt->link_count; i++) {
        if (rt->links[i]) bpf_link__destroy(rt->links[i]);
    }
    for (int i = 0; i < rt->rb_count; i++) {
        if (rt->rbs[i].rb) ring_buffer__free(rt->rbs[i].rb);
    }
    if (rt->obj) bpf_object__close(rt->obj);
    free(rt);
}

int spnl_runtime_attach_all(spnl_runtime *rt)
{
    if (!rt) return -EINVAL;
    struct bpf_program *p;
    int attached = 0;
    bpf_object__for_each_program(p, rt->obj) {
        const char *sec = bpf_program__section_name(p);
        if (!sec) continue;
        /* Skip SEC("syscall") — those are invoked via spnl_runtime_call(),
         * not auto-attached. */
        if (strncmp(sec, "syscall", 7) == 0) continue;
        struct bpf_link *link = bpf_program__attach(p);
        if (!link || libbpf_get_error(link)) {
            fprintf(stderr, "spnl_runtime: attach failed for %s (sec=%s)\n",
                    bpf_program__name(p), sec);
            continue;
        }
        if (rt->link_count >= SPNL_MAX_LINKS) {
            bpf_link__destroy(link);
            return -ENOSPC;
        }
        rt->links[rt->link_count++] = link;
        attached++;
    }
    return attached;
}

int spnl_runtime_call(spnl_runtime *rt,
                      const char *func_name,
                      const void *ctx_in, size_t ctx_size,
                      __u32 *retval_out)
{
    if (!rt || !func_name) return -EINVAL;
    struct bpf_program *p = bpf_object__find_program_by_name(rt->obj, func_name);
    if (!p) return -ENOENT;
    int fd = bpf_program__fd(p);
    if (fd < 0) return fd;

    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .ctx_in = ctx_in, .ctx_size_in = (__u32)ctx_size,
    );
    int err = bpf_prog_test_run_opts(fd, &opts);
    if (err) return err;
    if (retval_out) *retval_out = opts.retval;
    return 0;
}

/* Find or create the ring_buffer consumer for `map_name`. The cb/user_ctx
 * we record is what libbpf invokes from inside ring_buffer__poll(). */
static struct rb_slot *find_or_create_rb(spnl_runtime *rt, const char *map_name,
                                         spnl_runtime_event_cb cb, void *user_ctx,
                                         int *err_out)
{
    for (int i = 0; i < rt->rb_count; i++) {
        if (strcmp(rt->rbs[i].map_name, map_name) == 0) {
            rt->rbs[i].cb = cb;
            rt->rbs[i].user_ctx = user_ctx;
            return &rt->rbs[i];
        }
    }
    if (rt->rb_count >= SPNL_MAX_RB) { *err_out = -ENOSPC; return NULL; }
    if (strlen(map_name) + 1 > sizeof(rt->rbs[0].map_name)) { *err_out = -ENAMETOOLONG; return NULL; }

    struct bpf_map *m = bpf_object__find_map_by_name(rt->obj, map_name);
    if (!m) { *err_out = -ENOENT; return NULL; }
    int fd = bpf_map__fd(m);
    if (fd < 0) { *err_out = fd; return NULL; }

    struct rb_slot *slot = &rt->rbs[rt->rb_count];
    strncpy(slot->map_name, map_name, sizeof(slot->map_name) - 1);
    slot->cb = cb;
    slot->user_ctx = user_ctx;

    /* Indirect to a per-slot trampoline so libbpf's callback (which takes
     * a single void* ctx) can dispatch to our (user_ctx, data, size) form. */
    slot->rb = ring_buffer__new(fd, NULL, NULL, NULL);
    if (!slot->rb) { *err_out = -errno; return NULL; }

    /* Add ourselves with a trampoline. */
    struct ring_buffer_opts opts = { .sz = sizeof(opts) };
    (void)opts;  /* placeholder; ring_buffer__add isn't widely available */

    rt->rb_count++;
    return slot;
}

/* libbpf forwards each record to our cb via this trampoline.
 * The user_ctx libbpf gives us is the rb_slot pointer. */
static int rb_trampoline(void *raw_slot, void *data, size_t sz)
{
    struct rb_slot *slot = raw_slot;
    return slot->cb(slot->user_ctx, data, sz);
}

int spnl_runtime_ringbuf_drain(spnl_runtime *rt,
                               const char *map_name,
                               spnl_runtime_event_cb cb, void *user_ctx,
                               int timeout_ms)
{
    if (!rt || !map_name || !cb) return -EINVAL;

    /* For simplicity (libbpf API limits on dynamic cb), we create a fresh
     * ring_buffer with the right cb each call. Cache the slot only for
     * map-name de-dup of repeated drains. */
    struct bpf_map *m = bpf_object__find_map_by_name(rt->obj, map_name);
    if (!m) return -ENOENT;
    int fd = bpf_map__fd(m);
    if (fd < 0) return fd;

    /* Stash cb+user_ctx in a slot so the trampoline can fetch them. */
    struct rb_slot slot = { .cb = cb, .user_ctx = user_ctx };
    strncpy(slot.map_name, map_name, sizeof(slot.map_name) - 1);

    struct ring_buffer *rb = ring_buffer__new(fd, rb_trampoline, &slot, NULL);
    if (!rb) return -errno;
    int n = ring_buffer__poll(rb, timeout_ms);
    ring_buffer__free(rb);
    return n;
}

/* ASCII-art log2 histogram dump, bcc-compatible format.
 * Reads `map_name` (BPF_MAP_TYPE_ARRAY of __u64, max_entries=64), bins them
 * into rows with a 40-char bar scaled to the maximum count, prefixed by the
 * value range covered by that bucket (2^slot .. 2^(slot+1)-1).
 *
 * Implementation lives in spnl_print_log2_hist_obj — the spnl_runtime_*
 * variant is a thin wrapper that unwraps rt->obj. Both surfaces stay
 * stable so glue.c (which only has a skeleton) can call the obj form. */
/* Core log2-hist renderer: given a counts[64] array (n slots), print a
 * bcc-style ASCII bar chart. Shared by the ARRAY (non-keyed) and keyed
 * readers — only the source of `counts` differs. */
static void _spnl_hist_print_counts(const __u64 *counts, __u32 n,
                                     const char *label, FILE *fp)
{
    /* Print only the active range [first_nonzero, last_nonzero] — bcc does the
     * same, so a sparse histogram doesn't dump dozens of empty rows. */
    __u64 max_count = 0;
    int lo_slot = -1, hi_slot = -1;
    for (__u32 i = 0; i < n; i++) {
        if (counts[i] == 0) continue;
        if (lo_slot < 0) lo_slot = (int)i;
        hi_slot = (int)i;
        if (counts[i] > max_count) max_count = counts[i];
    }
    fprintf(fp, "  %16s        : count    distribution\n", label);
    if (lo_slot < 0) { fprintf(fp, "  (no samples)\n"); return; }

    const int bar_width = 40;
    for (int i = lo_slot; i <= hi_slot; i++) {
        /* Bucket label: slot k bins values where floor(log2(v)) == k.
         * For k>=1 that's [2^k, 2^(k+1)-1]. Slot 0 covers v in {0, 1}. */
        __u64 lo = (i == 0) ? 0 : (1ULL << i);
        __u64 hi = (i == 0) ? 1 : ((1ULL << (i + 1)) - 1);
        int bars = (max_count == 0) ? 0 : (int)((counts[i] * (__u64)bar_width) / max_count);
        if (bars > bar_width) bars = bar_width;
        fprintf(fp, "%10llu -> %-10llu : %-8llu |", (unsigned long long)lo,
                (unsigned long long)hi, (unsigned long long)counts[i]);
        for (int b = 0; b < bars; b++) fputc('*', fp);
        for (int b = bars; b < bar_width; b++) fputc(' ', fp);
        fprintf(fp, "|\n");
    }
}

/* Core percentile: upper edge of the bucket where cumulative count first
 * crosses `percentile * total`. Shared by keyed / non-keyed readers. */
static int _spnl_hist_percentile_counts(const __u64 *counts, __u32 n,
                                        double percentile, __u64 *value_out)
{
    __u64 total = 0;
    for (__u32 i = 0; i < n; i++) total += counts[i];
    if (total == 0) { *value_out = 0; return 0; }
    __u64 target = (__u64)((double)total * percentile + 0.999999);
    if (target == 0) target = 1;
    __u64 cum = 0;
    for (__u32 i = 0; i < n; i++) {
        cum += counts[i];
        if (cum >= target) {
            *value_out = (i == 0) ? 1 : ((1ULL << (i + 1)) - 1);
            return 0;
        }
    }
    *value_out = (1ULL << (n - 1));
    return 0;
}

int spnl_print_log2_hist_obj(struct bpf_object *obj,
                             const char *map_name,
                             const char *label,
                             FILE *fp)
{
    if (!obj || !map_name) return -EINVAL;
    if (!fp) fp = stderr;
    if (!label || !*label) label = "value";

    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) return -ENOENT;
    if (bpf_map__type(m) != BPF_MAP_TYPE_ARRAY) return -EINVAL;
    __u32 n = bpf_map__max_entries(m);
    if (n == 0 || n > 64) return -EINVAL;
    int fd = bpf_map__fd(m);
    if (fd < 0) return fd;

    __u64 counts[64] = {0};
    for (__u32 i = 0; i < n; i++) {
        __u64 v = 0;
        if (bpf_map_lookup_elem(fd, &i, &v) == 0) counts[i] = v;
    }
    _spnl_hist_print_counts(counts, n, label, fp);
    return 0;
}

/* backward-compat wrapper. */
int spnl_runtime_print_log2_hist(spnl_runtime *rt,
                                 const char *map_name,
                                 const char *label,
                                 FILE *fp)
{
    if (!rt) return -EINVAL;
    return spnl_print_log2_hist_obj(rt->obj, map_name, label, fp);
}

/* read a log2 histogram and return an approximate percentile.
 * Returns the upper edge of the bucket where cumulative count first crosses
 * `percentile * total` — an over-approximation by at most one log2 step. */
int spnl_log2_hist_percentile_obj(struct bpf_object *obj,
                                  const char *map_name,
                                  double percentile,
                                  __u64 *value_out)
{
    if (!obj || !map_name || !value_out) return -EINVAL;
    if (percentile <= 0.0 || percentile > 1.0) return -EINVAL;

    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) return -ENOENT;
    if (bpf_map__type(m) != BPF_MAP_TYPE_ARRAY) return -EINVAL;
    __u32 n = bpf_map__max_entries(m);
    if (n == 0 || n > 64) return -EINVAL;
    int fd = bpf_map__fd(m);
    if (fd < 0) return fd;

    __u64 counts[64] = {0};
    for (__u32 i = 0; i < n; i++) {
        __u64 v = 0;
        if (bpf_map_lookup_elem(fd, &i, &v) == 0) counts[i] = v;
    }
    return _spnl_hist_percentile_counts(counts, n, percentile, value_out);
}

/* backward-compat wrapper. */
int spnl_runtime_log2_hist_percentile(spnl_runtime *rt,
                                      const char *map_name,
                                      double percentile,
                                      __u64 *value_out)
{
    if (!rt) return -EINVAL;
    return spnl_log2_hist_percentile_obj(rt->obj, map_name, percentile, value_out);
}

/* keyed log2 histogram readers (bpf_hist_keyed: HASH u64 -> u64[64]).
 * Used by --instrument to report per-method duration. Look up the 64-slot
 * bucket array for `key` and reuse the shared renderer/percentile core. */
static int _spnl_hist_keyed_lookup(struct bpf_object *obj, const char *map_name,
                                   __u64 key, __u64 counts[64])
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) return -ENOENT;
    if (bpf_map__type(m) != BPF_MAP_TYPE_HASH) return -EINVAL;
    int fd = bpf_map__fd(m);
    if (fd < 0) return fd;
    /* value is struct { __u64 buckets[64]; } — 512 bytes, copied into counts. */
    if (bpf_map_lookup_elem(fd, &key, counts) != 0) {
        for (int i = 0; i < 64; i++) counts[i] = 0; /* absent key = empty hist */
    }
    return 0;
}

int spnl_print_log2_hist_keyed_obj(struct bpf_object *obj, const char *map_name,
                                   unsigned long long key, const char *label, FILE *fp)
{
    if (!obj || !map_name) return -EINVAL;
    if (!fp) fp = stderr;
    if (!label || !*label) label = "value";
    __u64 counts[64] = {0};
    int rc = _spnl_hist_keyed_lookup(obj, map_name, (__u64)key, counts);
    if (rc) return rc;
    _spnl_hist_print_counts(counts, 64, label, fp);
    return 0;
}

int spnl_log2_hist_percentile_keyed_obj(struct bpf_object *obj, const char *map_name,
                                        unsigned long long key, double percentile,
                                        __u64 *value_out)
{
    if (!obj || !map_name || !value_out) return -EINVAL;
    if (percentile <= 0.0 || percentile > 1.0) return -EINVAL;
    __u64 counts[64] = {0};
    int rc = _spnl_hist_keyed_lookup(obj, map_name, (__u64)key, counts);
    if (rc) return rc;
    return _spnl_hist_percentile_counts(counts, 64, percentile, value_out);
}

/* total sample count in the keyed log2 hist under `key` (= per-method
 * call count for --instrument; overflow-immune, unlike a ringbuf rate). */
int spnl_log2_hist_count_keyed_obj(struct bpf_object *obj, const char *map_name,
                                   unsigned long long key, __u64 *count_out)
{
    if (!obj || !map_name || !count_out) return -EINVAL;
    __u64 counts[64] = {0};
    int rc = _spnl_hist_keyed_lookup(obj, map_name, (__u64)key, counts);
    if (rc) return rc;
    __u64 total = 0;
    for (int i = 0; i < 64; i++) total += counts[i];
    *count_out = total;
    return 0;
}

/* dump a linear histogram (caller-bucketed). `slot_label_fmt` is
 * a printf format applied to each slot index (e.g. "%d us"). NULL/empty
 * label defaults to "%d". */
int spnl_print_linear_hist_obj(struct bpf_object *obj,
                               const char *map_name,
                               const char *slot_label_fmt,
                               FILE *fp)
{
    if (!obj || !map_name) return -EINVAL;
    if (!fp) fp = stderr;
    if (!slot_label_fmt || !*slot_label_fmt) slot_label_fmt = "%d";

    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) return -ENOENT;
    if (bpf_map__type(m) != BPF_MAP_TYPE_ARRAY) return -EINVAL;
    __u32 n = bpf_map__max_entries(m);
    if (n == 0) return -EINVAL;
    int fd = bpf_map__fd(m);
    if (fd < 0) return fd;

    __u64 max_count = 0;
    for (__u32 i = 0; i < n; i++) {
        __u64 v = 0;
        if (bpf_map_lookup_elem(fd, &i, &v) == 0 && v > max_count) max_count = v;
    }
    const int bar_width = 40;
    fprintf(fp, "  %16s : count    distribution\n", "slot");
    for (__u32 i = 0; i < n; i++) {
        __u64 v = 0;
        bpf_map_lookup_elem(fd, &i, &v);
        if (v == 0 && (i == 0 || i == n - 1)) {
            int has_data = 0;
            for (__u32 j = i + 1; j < n; j++) {
                __u64 w = 0;
                bpf_map_lookup_elem(fd, &j, &w);
                if (w) { has_data = 1; break; }
            }
            if (!has_data) break;
            if (i == 0) continue;
        }
        char label[64];
        snprintf(label, sizeof(label), slot_label_fmt, (int)i);
        int bars = (max_count == 0) ? 0 : (int)((v * (__u64)bar_width) / max_count);
        if (bars > bar_width) bars = bar_width;
        fprintf(fp, "%18s : %-8llu |", label, (unsigned long long)v);
        for (int b = 0; b < bars; b++) fputc('*', fp);
        for (int b = bars; b < bar_width; b++) fputc(' ', fp);
        fprintf(fp, "|\n");
    }
    return 0;
}

/* backward-compat wrapper. */
int spnl_runtime_print_linear_hist(spnl_runtime *rt,
                                   const char *map_name,
                                   const char *slot_label_fmt,
                                   FILE *fp)
{
    if (!rt) return -EINVAL;
    return spnl_print_linear_hist_obj(rt->obj, map_name, slot_label_fmt, fp);
}

/* best-effort kernel symbol resolver. Reads /proc/kallsyms on first
 * call and caches a sorted (PC, name) table. Returns 1 if `*out_name` was
 * filled and `*out_off` is the byte offset from the symbol; 0 otherwise. */
static struct {
    __u64       *pcs;
    char       **names;
    size_t       count;
    int          loaded;
    int          load_err;
} _spnl_kallsyms;

static int _spnl_kallsyms_load(void)
{
    if (_spnl_kallsyms.loaded) return _spnl_kallsyms.load_err;
    _spnl_kallsyms.loaded = 1;

    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) { _spnl_kallsyms.load_err = -errno; return _spnl_kallsyms.load_err; }

    size_t cap = 16384;
    _spnl_kallsyms.pcs   = calloc(cap, sizeof(__u64));
    _spnl_kallsyms.names = calloc(cap, sizeof(char *));
    if (!_spnl_kallsyms.pcs || !_spnl_kallsyms.names) {
        fclose(fp);
        _spnl_kallsyms.load_err = -ENOMEM;
        return -ENOMEM;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long pc;
        char type;
        char name[256];
        if (sscanf(line, "%llx %c %255s", &pc, &type, name) != 3) continue;
        /* Skip data symbols ("d"/"D"/"b"/"B"/"r"/"R") — only text-ish help. */
        if (type != 't' && type != 'T' && type != 'w' && type != 'W') continue;
        if (_spnl_kallsyms.count >= cap) {
            cap *= 2;
            __u64 *npcs   = realloc(_spnl_kallsyms.pcs,   cap * sizeof(__u64));
            char **nnames = realloc(_spnl_kallsyms.names, cap * sizeof(char *));
            if (!npcs || !nnames) {
                fclose(fp);
                _spnl_kallsyms.load_err = -ENOMEM;
                return -ENOMEM;
            }
            _spnl_kallsyms.pcs   = npcs;
            _spnl_kallsyms.names = nnames;
        }
        _spnl_kallsyms.pcs[_spnl_kallsyms.count]   = (__u64)pc;
        _spnl_kallsyms.names[_spnl_kallsyms.count] = strdup(name);
        _spnl_kallsyms.count++;
    }
    fclose(fp);

    /* The table is already sorted (kallsyms is sorted by addr), but let's
     * not assume — bsearch needs strict order. Quick bubble check + a
     * pointer-swap sort would be overkill; trust kernel ordering for now. */
    return 0;
}

static const char *_spnl_kallsyms_resolve(__u64 pc, __u64 *out_off)
{
    if (_spnl_kallsyms_load() != 0 || _spnl_kallsyms.count == 0) return NULL;
    /* Binary search for largest pcs[i] <= pc. */
    size_t lo = 0, hi = _spnl_kallsyms.count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (_spnl_kallsyms.pcs[mid] <= pc) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return NULL;
    *out_off = pc - _spnl_kallsyms.pcs[lo - 1];
    return _spnl_kallsyms.names[lo - 1];
}

/* emit folded-stacks format compatible with flamegraph.pl.
 * For each stack id with non-zero total in the keyed hist, look up its
 * PCs in the STACK_TRACE map, symbolize, reverse, join with ';', and
 * append the count. PCs that fail to resolve get printed as `0xNN` so
 * the output line is still valid for flamegraph.pl. */
int spnl_print_folded_stacks_obj(struct bpf_object *obj,
                                 const char *hist_map_name,
                                 const char *stacks_map_name,
                                 FILE *fp)
{
    if (!obj || !hist_map_name || !stacks_map_name) return -EINVAL;
    if (!fp) fp = stderr;

    struct bpf_map *hist_map = bpf_object__find_map_by_name(obj, hist_map_name);
    if (!hist_map) return -ENOENT;
    if (bpf_map__type(hist_map) != BPF_MAP_TYPE_HASH) return -EINVAL;
    int hist_fd = bpf_map__fd(hist_map);
    if (hist_fd < 0) return hist_fd;

    struct bpf_map *st_map = bpf_object__find_map_by_name(obj, stacks_map_name);
    if (!st_map) return -ENOENT;
    if (bpf_map__type(st_map) != BPF_MAP_TYPE_STACK_TRACE) return -EINVAL;
    int st_fd = bpf_map__fd(st_map);
    if (st_fd < 0) return st_fd;

    /* The hist map value is `struct { __u64 buckets[64] }`. Iterate via
     * bpf_map_get_next_key + bpf_map_lookup_elem. */
    __u64 key = 0, next_key = 0;
    struct { __u64 buckets[64]; } val;
    int first = 1;
    int emitted = 0;

    while (1) {
        int rc;
        if (first) {
            rc = bpf_map_get_next_key(hist_fd, NULL, &next_key);
            first = 0;
        } else {
            rc = bpf_map_get_next_key(hist_fd, &key, &next_key);
        }
        if (rc != 0) break;
        key = next_key;

        if (bpf_map_lookup_elem(hist_fd, &key, &val) != 0) continue;

        __u64 total = 0;
        for (int i = 0; i < 64; i++) total += val.buckets[i];
        if (total == 0) continue;

        __u32 stack_id = (__u32)key;
        __u64 pcs[127] = {0};
        if (bpf_map_lookup_elem(st_fd, &stack_id, pcs) != 0) {
            /* No stack data — emit a stub line so the total count is
             * preserved in the folded output. */
            fprintf(fp, "[unknown];stack_%u %llu\n", stack_id,
                    (unsigned long long)total);
            emitted++;
            continue;
        }
        /* Count valid frames. */
        int n = 0;
        for (int i = 0; i < 127; i++) {
            if (pcs[i] == 0) break;
            n++;
        }
        if (n == 0) {
            fprintf(fp, "[unknown];stack_%u %llu\n", stack_id,
                    (unsigned long long)total);
            emitted++;
            continue;
        }
        /* flamegraph.pl wants bottom-up (oldest frame first). bpf_get_stackid
         * returns top-down (innermost first), so iterate reversed. */
        for (int i = n - 1; i >= 0; i--) {
            __u64 off = 0;
            const char *sym = _spnl_kallsyms_resolve(pcs[i], &off);
            if (sym) {
                fprintf(fp, "%s%s", (i == n - 1) ? "" : ";", sym);
            } else {
                fprintf(fp, "%s0x%llx", (i == n - 1) ? "" : ";",
                        (unsigned long long)pcs[i]);
            }
        }
        fprintf(fp, " %llu\n", (unsigned long long)total);
        emitted++;
    }
    return emitted;
}

/* dump a stack trace by stack id. PCs are resolved to func+offset
 * via /proc/kallsyms when symbolize_kernel is non-zero. */
/* resolve a file offset inside an ELF to "<sym>" + offset by scanning
 * .symtab / .dynsym for the enclosing STT_FUNC. Raw Elf64 parsing, no libelf. */
static int _spnl_elf_resolve(const char *path, unsigned long file_off,
                             char *symbuf, size_t symlen, unsigned long *off_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); return -1; }
    void *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;

    int ret = -1;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) goto out;

    /* file offset -> ELF virtual address via the covering PT_LOAD segment. */
    unsigned long vaddr = file_off;
    Elf64_Phdr *ph = (Elf64_Phdr *)((char *)base + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD &&
            file_off >= ph[i].p_offset && file_off < ph[i].p_offset + ph[i].p_filesz) {
            vaddr = file_off - ph[i].p_offset + ph[i].p_vaddr;
            break;
        }
    }

    Elf64_Shdr *sh = (Elf64_Shdr *)((char *)base + eh->e_shoff);
    unsigned long best_val = 0, best_off = 0;
    const char *best_name = NULL;
    for (int s = 0; s < eh->e_shnum; s++) {
        if (sh[s].sh_type != SHT_SYMTAB && sh[s].sh_type != SHT_DYNSYM) continue;
        if (sh[s].sh_entsize == 0) continue;
        Elf64_Sym *syms = (Elf64_Sym *)((char *)base + sh[s].sh_offset);
        long nsyms = sh[s].sh_size / sizeof(Elf64_Sym);
        const char *strtab = (const char *)base + sh[sh[s].sh_link].sh_offset;
        for (long k = 0; k < nsyms; k++) {
            if (ELF64_ST_TYPE(syms[k].st_info) != STT_FUNC) continue;
            if (syms[k].st_value == 0 || syms[k].st_name == 0) continue;
            unsigned long lo = syms[k].st_value;
            unsigned long hi = lo + (syms[k].st_size ? syms[k].st_size : 1);
            if (vaddr >= lo && vaddr < hi && lo >= best_val) {
                best_val = lo; best_off = vaddr - lo; best_name = strtab + syms[k].st_name;
            }
        }
    }
    if (best_name) {
        snprintf(symbuf, symlen, "%s", best_name);
        if (off_out) *off_out = best_off;
        ret = 0;
    }
out:
    munmap(base, st.st_size);
    return ret;
}

#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif

/* derive the separate debug-info path for an ELF from its GNU build-id
 * note. Stripped shared objects (e.g. distro libruby) keep .note.gnu.build-id
 * but drop .symtab; the static functions (vm_exec_core, ...) live only in the
 * matching /usr/lib/debug/.build-id/<xx>/<rest>.debug file (as fetched by
 * debuginfod). Returns 0 and fills `out` if such a file exists, else -1.
 * The debug ELF preserves the original program headers, so the same file
 * offset resolves through _spnl_elf_resolve against it. */
static int _spnl_debug_path_for(const char *elf_path, char *out, size_t outlen)
{
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); return -1; }
    void *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;

    int ret = -1;
    unsigned char id[64]; size_t id_len = 0;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) goto out;

    Elf64_Shdr *sh = (Elf64_Shdr *)((char *)base + eh->e_shoff);
    for (int s = 0; s < eh->e_shnum && id_len == 0; s++) {
        if (sh[s].sh_type != SHT_NOTE) continue;
        const char *p   = (const char *)base + sh[s].sh_offset;
        const char *end = p + sh[s].sh_size;
        while (p + sizeof(Elf64_Nhdr) <= end) {
            Elf64_Nhdr *nh = (Elf64_Nhdr *)p;
            const char *name = p + sizeof(Elf64_Nhdr);
            const char *desc = name + ((nh->n_namesz + 3) & ~3u);
            if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 &&
                memcmp(name, "GNU", 4) == 0 && nh->n_descsz > 0 &&
                nh->n_descsz <= sizeof(id) && desc + nh->n_descsz <= end) {
                memcpy(id, desc, nh->n_descsz);
                id_len = nh->n_descsz;
                break;
            }
            p = desc + ((nh->n_descsz + 3) & ~3u);
        }
    }
    if (id_len >= 2) {
        char hex[2 * sizeof(id) + 1];
        for (size_t i = 0; i < id_len; i++) snprintf(hex + 2 * i, 3, "%02x", id[i]);
        snprintf(out, outlen, "/usr/lib/debug/.build-id/%c%c/%s.debug",
                 hex[0], hex[1], hex + 2);
        if (access(out, R_OK) == 0) ret = 0;
    }
out:
    munmap(base, st.st_size);
    return ret;
}

/* best-effort user-space symbol resolver. Maps a user PC in process
 * `pid` to "<sym>+0xoff [binary]" using /proc/<pid>/maps + the mapped ELF.
 * bcc's BPF_STACK_TRACE user-symbolization equivalent (the kernel side stays
 * on /proc/kallsyms). Returns 0 on a resolved symbol, -1 otherwise (out
 * is still filled with the hex address). */
int spnl_sym_user(int pid, unsigned long pc, char *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;
    out[0] = '\0';
    char mapspath[64];
    snprintf(mapspath, sizeof(mapspath), "/proc/%d/maps", pid);
    FILE *fp = fopen(mapspath, "r");
    if (!fp) { snprintf(out, outlen, "0x%lx", pc); return -1; }

    char line[640];
    int rc = -1;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end, off;
        char perms[8], path[400];
        path[0] = '\0';
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %399[^\n]", &start, &end, perms, &off, path);
        if (n < 4 || pc < start || pc >= end) continue;
        if (!strchr(perms, 'x')) continue;
        char *p = path; while (*p == ' ') p++;
        if (*p != '/') { snprintf(out, outlen, "0x%lx", pc); break; }
        const char *bn = strrchr(p, '/'); bn = bn ? bn + 1 : p;
        unsigned long file_off = pc - start + off, soff = 0;
        char sym[256];
        if (_spnl_elf_resolve(p, file_off, sym, sizeof(sym), &soff) == 0) {
            snprintf(out, outlen, "%s+0x%lx [%s]", sym, soff, bn);
            rc = 0;
        } else {
            /* stripped .so — try the separate build-id debug file so
             * static functions (e.g. libruby's vm_exec_core) still resolve. */
            char dbg[512];
            if (_spnl_debug_path_for(p, dbg, sizeof(dbg)) == 0 &&
                _spnl_elf_resolve(dbg, file_off, sym, sizeof(sym), &soff) == 0) {
                snprintf(out, outlen, "%s+0x%lx [%s]", sym, soff, bn);
                rc = 0;
            } else {
                snprintf(out, outlen, "0x%lx [%s]", pc, bn);
            }
        }
        break;
    }
    fclose(fp);
    if (out[0] == '\0') snprintf(out, outlen, "0x%lx", pc);
    return rc;
}

/* like spnl_print_folded_stacks_obj, but for USER stacks captured with
 * user_stack_id(). The keyed-hist key packs the process id in the high 32 bits
 * and the user stack id in the low 32 bits (the profiler does
 * `hist_observe_by((tgid << 32) | user_stack_id, 1)`), so each stack can be
 * symbolized against the right /proc/<pid> address space via spnl_sym_user.
 * The "+0xoff" suffix is dropped from each frame so identical functions merge
 * into one wide box in the flame graph (the binary tag "[name]" is kept). The
 * target processes must still be alive at dump time (maps are read then). */
static void _spnl_folded_frame(char *s)
{
    /* "sym+0xoff [bin]" -> "sym [bin]" ; leave hex-only frames untouched. */
    char *plus = strstr(s, "+0x");
    if (!plus) return;
    char *sp = strchr(plus, ' ');
    if (sp) memmove(plus, sp, strlen(sp) + 1);
    else    *plus = '\0';
}

/* (pid, pc) -> folded frame name memo. Recursive workloads (fib) and shared
 * hot functions (libruby's vm_exec_core) repeat the same PCs across thousands
 * of stacks, and symbolizing through a separate debug file mmaps + scans it
 * per call, so without a cache a dump can take minutes. Open-addressed, keyed
 * on (pid,pc) so it stays correct in system-wide mode (pid varies per stack). */
struct _spnl_frame_cache { int n; struct { int pid; __u64 pc; char frame[288]; } *e; };

static const char *_spnl_frame_cached(struct _spnl_frame_cache *c, int pid, __u64 pc)
{
    if (pc == 0 || !c->e) {
        static char tmp[288];
        spnl_sym_user(pid, pc, tmp, sizeof(tmp));
        _spnl_folded_frame(tmp);
        return tmp;
    }
    unsigned idx = (unsigned)(((pc >> 4) ^ (unsigned)pid) % (unsigned)c->n);
    for (int probe = 0; probe < c->n; probe++) {
        int j = (int)((idx + probe) % (unsigned)c->n);
        if (c->e[j].pc == pc && c->e[j].pid == pid) return c->e[j].frame;  /* hit */
        if (c->e[j].pc == 0) {                                            /* miss */
            spnl_sym_user(pid, pc, c->e[j].frame, sizeof(c->e[j].frame));
            _spnl_folded_frame(c->e[j].frame);
            c->e[j].pid = pid; c->e[j].pc = pc;
            return c->e[j].frame;
        }
    }
    static char full[288];                                            /* table full */
    spnl_sym_user(pid, pc, full, sizeof(full));
    _spnl_folded_frame(full);
    return full;
}

int spnl_print_folded_user_stacks_obj(struct bpf_object *obj,
                                      const char *hist_map_name,
                                      const char *stacks_map_name,
                                      int pid_override,
                                      FILE *fp)
{
    if (!obj || !hist_map_name || !stacks_map_name) return -EINVAL;
    if (!fp) fp = stderr;

    struct bpf_map *hist_map = bpf_object__find_map_by_name(obj, hist_map_name);
    if (!hist_map) return -ENOENT;
    if (bpf_map__type(hist_map) != BPF_MAP_TYPE_HASH) return -EINVAL;
    int hist_fd = bpf_map__fd(hist_map);
    if (hist_fd < 0) return hist_fd;

    struct bpf_map *st_map = bpf_object__find_map_by_name(obj, stacks_map_name);
    if (!st_map) return -ENOENT;
    if (bpf_map__type(st_map) != BPF_MAP_TYPE_STACK_TRACE) return -EINVAL;
    int st_fd = bpf_map__fd(st_map);
    if (st_fd < 0) return st_fd;

    __u64 key = 0, next_key = 0;
    struct { __u64 buckets[64]; } val;
    int first = 1, emitted = 0;

    struct _spnl_frame_cache fc = { .n = 8192 };
    fc.e = calloc((size_t)fc.n, sizeof(*fc.e));   /* NULL -> _spnl_frame_cached degrades gracefully */

    while (1) {
        int rc = first ? bpf_map_get_next_key(hist_fd, NULL, &next_key)
                       : bpf_map_get_next_key(hist_fd, &key, &next_key);
        first = 0;
        if (rc != 0) break;
        key = next_key;
        if (bpf_map_lookup_elem(hist_fd, &key, &val) != 0) continue;

        __u64 total = 0;
        for (int i = 0; i < 64; i++) total += val.buckets[i];
        if (total == 0) continue;

        /* The key packs (tgid << 32) | stack_id. The packed tgid is the
         * kernel's (init-namespace) pid; under a nested pid namespace (e.g. a
         * container) it does not match this process's /proc view, so callers
         * pass pid_override (the namespace-local pid of the target) to
         * symbolize against. pid_override < 0 keeps the system-wide behavior. */
        int pid = (pid_override >= 0) ? pid_override : (int)(key >> 32);
        __u32 stack_id = (__u32)key;
        __u64 pcs[127] = {0};
        if (bpf_map_lookup_elem(st_fd, &stack_id, pcs) != 0) {
            fprintf(fp, "[unknown];stack_%u %llu\n", stack_id,
                    (unsigned long long)total);
            emitted++;
            continue;
        }
        int n = 0;
        for (int i = 0; i < 127; i++) { if (pcs[i] == 0) break; n++; }
        if (n == 0) {
            fprintf(fp, "[unknown];stack_%u %llu\n", stack_id,
                    (unsigned long long)total);
            emitted++;
            continue;
        }
        /* flamegraph.pl wants bottom-up; bpf_get_stackid is top-down. */
        for (int i = n - 1; i >= 0; i--) {
            const char *frame = _spnl_frame_cached(&fc, pid, pcs[i]);
            fprintf(fp, "%s%s", (i == n - 1) ? "" : ";", frame);
        }
        fprintf(fp, " %llu\n", (unsigned long long)total);
        emitted++;
    }
    free(fc.e);
    return emitted;
}

int spnl_print_stack_trace_obj(struct bpf_object *obj,
                               const char *map_name,
                               __u32 stack_id,
                               int symbolize_kernel,
                               FILE *fp)
{
    if (!obj || !map_name) return -EINVAL;
    if (!fp) fp = stderr;

    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) return -ENOENT;
    if (bpf_map__type(m) != BPF_MAP_TYPE_STACK_TRACE) return -EINVAL;
    int fd = bpf_map__fd(m);
    if (fd < 0) return fd;

    /* PERF_MAX_STACK_DEPTH = 127 frames, 8 bytes each. */
    __u64 pcs[127] = {0};
    if (bpf_map_lookup_elem(fd, &stack_id, pcs) != 0) {
        fprintf(fp, "  stack id=%u: lookup failed (%s)\n",
                stack_id, strerror(errno));
        return -errno;
    }
    fprintf(fp, "  stack id=%u:\n", stack_id);
    int printed = 0;
    for (int i = 0; i < 127; i++) {
        if (pcs[i] == 0) break;
        if (symbolize_kernel) {
            __u64 off = 0;
            const char *sym = _spnl_kallsyms_resolve(pcs[i], &off);
            if (sym) {
                fprintf(fp, "    %s+0x%llx\n", sym, (unsigned long long)off);
            } else {
                fprintf(fp, "    0x%llx\n", (unsigned long long)pcs[i]);
            }
        } else {
            fprintf(fp, "    0x%llx\n", (unsigned long long)pcs[i]);
        }
        printed++;
    }
    if (printed == 0) fprintf(fp, "    (empty)\n");
    return 0;
}

/* dump outstanding (un-freed) allocations grouped by allocation stack.
 * `allocs_map` is a HASH of u64 ptr -> struct { __s64 size; __s64 stack_id }
 * (spinel-ebpf's bpf_allocs, written by leak_record/leak_forget). For each
 * distinct stack we sum the surviving bytes + count, sort by bytes desc, and
 * print the top `top_n` stacks with their kernel symbols (via /proc/kallsyms).
 * This is the bcc memleak report. */
struct _spnl_leak_group { __s64 stack_id; __u64 bytes; __u64 count; };

int spnl_dump_leaks_obj(struct bpf_object *obj,
                        const char *allocs_map_name,
                        const char *stacks_map_name,
                        int top_n,
                        FILE *fp)
{
    if (!obj || !allocs_map_name || !stacks_map_name) return -EINVAL;
    if (!fp) fp = stderr;
    if (top_n <= 0) top_n = 10;

    struct bpf_map *am = bpf_object__find_map_by_name(obj, allocs_map_name);
    if (!am) return -ENOENT;
    if (bpf_map__type(am) != BPF_MAP_TYPE_HASH) return -EINVAL;
    int afd = bpf_map__fd(am);
    if (afd < 0) return afd;

    struct bpf_map *sm = bpf_object__find_map_by_name(obj, stacks_map_name);
    int sfd = sm ? bpf_map__fd(sm) : -1;

    /* Accumulate surviving allocations into a per-stack table. The number of
     * distinct allocation stacks is small, so a linear-probe array is fine. */
    struct _spnl_leak_group *grp = NULL;
    size_t ngrp = 0, cap = 0;
    __u64 total_bytes = 0, total_allocs = 0;

    __u64 key = 0, next_key = 0;
    struct { __s64 size; __s64 stack_id; } val;
    int first = 1;
    while (1) {
        int rc = first ? bpf_map_get_next_key(afd, NULL, &next_key)
                       : bpf_map_get_next_key(afd, &key, &next_key);
        first = 0;
        if (rc != 0) break;
        key = next_key;
        if (bpf_map_lookup_elem(afd, &key, &val) != 0) continue;

        total_bytes += (__u64)val.size;
        total_allocs++;

        size_t i;
        for (i = 0; i < ngrp; i++) {
            if (grp[i].stack_id == val.stack_id) break;
        }
        if (i == ngrp) {
            if (ngrp >= cap) {
                cap = cap ? cap * 2 : 64;
                struct _spnl_leak_group *ng = realloc(grp, cap * sizeof(*grp));
                if (!ng) { free(grp); return -ENOMEM; }
                grp = ng;
            }
            grp[ngrp].stack_id = val.stack_id;
            grp[ngrp].bytes = 0;
            grp[ngrp].count = 0;
            ngrp++;
        }
        grp[i].bytes += (__u64)val.size;
        grp[i].count++;
    }

    /* Selection sort the top_n groups by bytes desc (ngrp is small). */
    for (size_t a = 0; a < ngrp && a < (size_t)top_n; a++) {
        size_t best = a;
        for (size_t b = a + 1; b < ngrp; b++)
            if (grp[b].bytes > grp[best].bytes) best = b;
        if (best != a) {
            struct _spnl_leak_group t = grp[a]; grp[a] = grp[best]; grp[best] = t;
        }
    }

    fprintf(fp, "[memleak] %llu outstanding allocation(s), %llu bytes, %zu distinct stack(s)\n",
            (unsigned long long)total_allocs, (unsigned long long)total_bytes, ngrp);

    size_t shown = ngrp < (size_t)top_n ? ngrp : (size_t)top_n;
    for (size_t a = 0; a < shown; a++) {
        fprintf(fp, "  %llu bytes in %llu allocation(s) [stack id %lld]:\n",
                (unsigned long long)grp[a].bytes,
                (unsigned long long)grp[a].count,
                (long long)grp[a].stack_id);
        if (sfd >= 0 && grp[a].stack_id >= 0) {
            __u32 sid = (__u32)grp[a].stack_id;
            __u64 pcs[127] = {0};
            if (bpf_map_lookup_elem(sfd, &sid, pcs) == 0) {
                for (int i = 0; i < 127; i++) {
                    if (pcs[i] == 0) break;
                    __u64 off = 0;
                    const char *sym = _spnl_kallsyms_resolve(pcs[i], &off);
                    if (sym) fprintf(fp, "      %s+0x%llx\n", sym, (unsigned long long)off);
                    else     fprintf(fp, "      0x%llx\n", (unsigned long long)pcs[i]);
                }
            } else {
                fprintf(fp, "      (stack unavailable)\n");
            }
        }
    }
    free(grp);
    return 0;
}

/* deadlock detection. `edges_map` is a HASH of struct {u64 a; u64 b} ->
 * u64 count (spinel-ebpf's bpf_lock_edges, written by lock_edge): a was held
 * when b was acquired. A cycle a->b AND b->a (observed on different threads) is
 * a lock-order inversion = potential deadlock. We read every edge and report
 * each such 2-cycle once. (Handles 2-lock inversions; the classic AB-BA bug.) */
struct _spnl_edge { __u64 a, b, count; };

int spnl_dump_deadlocks_obj(struct bpf_object *obj,
                            const char *edges_map_name,
                            int top_n,
                            FILE *fp)
{
    if (!obj || !edges_map_name) return -EINVAL;
    if (!fp) fp = stderr;
    if (top_n <= 0) top_n = 100;

    struct bpf_map *em = bpf_object__find_map_by_name(obj, edges_map_name);
    if (!em) return -ENOENT;
    if (bpf_map__type(em) != BPF_MAP_TYPE_HASH) return -EINVAL;
    int efd = bpf_map__fd(em);
    if (efd < 0) return efd;

    struct _spnl_edge *edges = NULL;
    size_t n = 0, cap = 0;

    struct { __u64 a, b; } key = {0, 0}, next_key;
    __u64 count = 0;
    int first = 1;
    while (1) {
        int rc = first ? bpf_map_get_next_key(efd, NULL, &next_key)
                       : bpf_map_get_next_key(efd, &key, &next_key);
        first = 0;
        if (rc != 0) break;
        key = next_key;
        if (bpf_map_lookup_elem(efd, &key, &count) != 0) continue;
        if (key.a == key.b) continue;   /* ignore recursive self-edges */
        if (n >= cap) {
            cap = cap ? cap * 2 : 128;
            struct _spnl_edge *ne = realloc(edges, cap * sizeof(*ne));
            if (!ne) { free(edges); return -ENOMEM; }
            edges = ne;
        }
        edges[n].a = key.a; edges[n].b = key.b; edges[n].count = count;
        n++;
    }

    int inversions = 0;
    for (size_t i = 0; i < n && inversions < top_n; i++) {
        /* report each unordered pair once: only when a < b */
        if (edges[i].a >= edges[i].b) continue;
        for (size_t j = 0; j < n; j++) {
            if (edges[j].a == edges[i].b && edges[j].b == edges[i].a) {
                fprintf(fp,
                        "  POTENTIAL DEADLOCK: lock 0x%llx <-> lock 0x%llx "
                        "(0x%llx->0x%llx x%llu, 0x%llx->0x%llx x%llu)\n",
                        (unsigned long long)edges[i].a, (unsigned long long)edges[i].b,
                        (unsigned long long)edges[i].a, (unsigned long long)edges[i].b,
                        (unsigned long long)edges[i].count,
                        (unsigned long long)edges[j].a, (unsigned long long)edges[j].b,
                        (unsigned long long)edges[j].count);
                inversions++;
                break;
            }
        }
    }

    fprintf(fp, "[deadlock] %zu lock-order edge(s), %d potential inversion(s)\n",
            n, inversions);
    free(edges);
    return inversions;
}
