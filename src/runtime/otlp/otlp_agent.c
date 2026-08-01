/*
 * otlp_agent.c -- the OTLP push implementation behind an --instrument agent.
 * See otlp_agent.h.
 */
#include "otlp_agent.h"
#include "otlp_metrics.h"
#include "otlp_traces.h"
#include "otlp_logs.h"
#include "otlp_http.h"
#include "otlp_grpc.h"   /* otlp_transport_send (http/grpc routing) + gRPC service paths */
#include "otlp_json.h"   /* otlp_want_json / otlp_endpoint_is_grpc / otlp_json_*_build */
#include "otlp_enrich.h" /* the enricher registry, through which k8s and peer are applied */
#include "spnl_runtime.h"   /* spnl_log2_hist_count_keyed_obj / spnl_hist_buckets_keyed_obj, __u64 */
#include "spnl/types.h"     /* struct spnl_event_hdr, for decoding records by type */
/* The userspace mirror of the ringbuf records. It is generated from the same
 * declaration as the kernel producer structs (src/codegen_c/record_schema.h), so
 * the offsets are computed rather than written: there is no hand-maintained
 * `data + H + 88` anywhere below. Regenerate it with `make -C src/codegen_c mirror`.
 *
 * Including it with SPNL_REC_CONSUME_IMPL defined also puts the typed-consumer
 * accessors -- spnl_rec_dns_qname and friends, which are what Ruby's `ev.qname`
 * actually calls -- into *this* translation unit. In exchange this file must
 * provide spnl_rec_<id>_at() and every declared derivation such as spnl_dns_qname;
 * both are defined below. Omitting one is a link error rather than a silently
 * wrong value. */
#define SPNL_REC_CONSUME_IMPL 1
#include "record_mirror_gen.h"

/* Whatever a declared derivation produces also has to fit the value buffer of a
 * span attribute. Those two live in different layers -- the record contract on one
 * side, the transport's attribute type on the other -- so the fit is checked here
 * mechanically. Without the check, only the attribute would be truncated, silently,
 * and the "same function, two different widths" bug would come back wearing a new
 * hat. Widening a cap past the buffer is meant to fail this: widen the buffer
 * first. */
#define SPNL_ATTR_VAL_CAP (sizeof(((otlp_kv_t *)0)->val))
_Static_assert(SPNL_REC_DERIVED_DNS_QNAME_CAP      <= SPNL_ATTR_VAL_CAP, "ev.qname does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_CONN_PEER_CAP      <= SPNL_ATTR_VAL_CAP, "ev.peer does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_CONN_DIRECTION_CAP <= SPNL_ATTR_VAL_CAP, "ev.direction does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_HTTP_METHOD_CAP    <= SPNL_ATTR_VAL_CAP, "ev.method does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_HTTP_PATH_CAP      <= SPNL_ATTR_VAL_CAP, "ev.path does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_METHOD_CAP  <= SPNL_ATTR_VAL_CAP, "offcpu ev.method does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_PATH_CAP    <= SPNL_ATTR_VAL_CAP, "offcpu ev.path does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP <= SPNL_ATTR_VAL_CAP, "ev.wait_kind does not fit in an attribute value");
/* The off-CPU and HTTP channels share the *same* derivation for method and path.
 * Each declaring its own bound is right -- a cap belongs to a derivation, it is not
 * a shared constant -- but handing one shared function two different widths brings
 * the "same function, two different widths" bug straight back. As long as the
 * source fields are the same width, the two declarations must agree, and this
 * pins that down. */
_Static_assert(SPNL_REC_DERIVED_OFFCPU_METHOD_CAP == SPNL_REC_DERIVED_HTTP_METHOD_CAP,
               "offcpu and http declare different caps for the shared derivation spnl_http_method()");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_PATH_CAP == SPNL_REC_DERIVED_HTTP_PATH_CAP,
               "offcpu and http declare different caps for the shared derivation spnl_http_path()");

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>         /* getenv, for the audit span's service.name */
#include <string.h>
#include <time.h>
#include <unistd.h>         /* getpid (id seed) */
#include <arpa/inet.h>      /* inet_ntop, for network.peer.address */
#include <bpf/libbpf.h>     /* ring_buffer (trace events drain) */
#include <bpf/bpf.h>

#define OTLP_MAX_METHODS 1024
#define OTLP_NAME_LEN    256

static struct {
    char    ruby[OTLP_NAME_LEN];
    char    file[OTLP_NAME_LEN];
    int32_t line;
    int32_t idx;
} g_methods[OTLP_MAX_METHODS];
static int      g_nmethods = 0;
static char     g_service[128] = "spinel-ebpf-instrument";
static char     g_version[64]  = "0";
static uint64_t g_start_ns     = 0;

static uint64_t wall_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int spnl_otlp_set_service(const char *name, const char *version) {
    if (name && name[0])    snprintf(g_service, sizeof g_service, "%s", name);
    if (version && version[0]) snprintf(g_version, sizeof g_version, "%s", version);
    return 0;
}

int spnl_otlp_add_method(const char *ruby, const char *file, long long line, long long idx) {
    if (g_nmethods >= OTLP_MAX_METHODS) {
        fprintf(stderr, "[otlp] method table full (%d), dropping %s\n",
                OTLP_MAX_METHODS, ruby ? ruby : "?");
        return -1;
    }
    int i = g_nmethods++;
    snprintf(g_methods[i].ruby, sizeof g_methods[i].ruby, "%s", ruby ? ruby : "");
    snprintf(g_methods[i].file, sizeof g_methods[i].file, "%s", file ? file : "");
    g_methods[i].line = (int32_t)line;
    g_methods[i].idx  = (int32_t)idx;
    return 0;
}

int spnl_otlp_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;

    /* static so that many methods do not eat the stack: each otlp_method_metric_t
     * carries buckets[64], about 520 bytes. */
    static otlp_method_metric_t mm[OTLP_MAX_METHODS];
    size_t n = 0;
    for (int i = 0; i < g_nmethods; i++) {
        unsigned long long key = (unsigned long long)g_methods[i].idx;
        __u64 count = 0;
        /* The runtime uses __u64 (unsigned long long) while the metric struct uses
         * uint64_t. On Linux those are distinct types, so read into a temporary and
         * memcpy across rather than aliasing. */
        __u64 buckets[64] = {0};
        spnl_log2_hist_count_keyed_obj(obj, map_name, key, &count);
        spnl_hist_buckets_keyed_obj(obj, map_name, key, buckets);
        memcpy(mm[n].buckets, buckets, sizeof buckets);
        mm[n].method = g_methods[i].ruby;
        mm[n].file   = g_methods[i].file;
        mm[n].line   = g_methods[i].line;
        mm[n].calls  = count;
        n++;
    }

    uint64_t now = wall_now_ns();
    if (g_start_ns == 0) g_start_ns = now;

    int status = 0;
    char err[256] = {0};
    int rc = otlp_metrics_export(endpoint, g_service, g_version, "spinel-ebpf",
                                 now, g_start_ns, mm, n, &status, err, sizeof err);
    if (rc != 0) {
        fprintf(stderr, "[otlp] export error: %s\n", err);
        return -1;
    }
    fprintf(stderr, "[otlp] pushed %zu methods -> %s (HTTP %d)\n", n, endpoint, status);
    return status;
}

/* ---- shared ringbuf draining and time conversion ---- */

/* Drain an emit ringbuf completely; records are buffered by the caller. Returns 0
 * or -1. poll_ms is how long a single poll waits, with 0 meaning non-blocking. It
 * is a parameter only so a typed consumer can pass a wait from Ruby; every other
 * caller still uses 100ms. */
static int otlp_drain_ms(struct bpf_object *obj, const char *map_name,
                         ring_buffer_sample_fn cb, void *ctx, int poll_ms) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) { fprintf(stderr, "[otlp] map '%s' not found\n", map_name); return -1; }
    int fd = bpf_map__fd(m);
    if (fd < 0) return -1;
    struct ring_buffer *rb = ring_buffer__new(fd, cb, ctx, NULL);
    if (!rb) { fprintf(stderr, "[otlp] ring_buffer__new failed\n"); return -1; }
    while (ring_buffer__poll(rb, poll_ms) > 0) { /* drain buffered records */ }
    ring_buffer__free(rb);
    return 0;
}

static int otlp_drain(struct bpf_object *obj, const char *map_name,
                      ring_buffer_sample_fn cb, void *ctx) {
    return otlp_drain_ms(obj, map_name, cb, ctx, 100);
}

/* The offset added to a monotonic ktime to get unix nanoseconds: realtime minus monotonic. */
static int64_t otlp_ktime_to_unix_off(void) {
    struct timespec rt, mono;
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    return ((int64_t)rt.tv_sec * 1000000000LL + rt.tv_nsec)
         - ((int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec);
}

/* ---- attribute enrichment goes through the registry in otlp_enrich ---- */
/* Every span push path packs what it has -- a cgroup id, a peer address, which
 * signal it is -- into an otlp_enrich_ctx_t and calls otlp_enrich_run() once. The
 * registered enrichers are then filtered by signal mask and applied in order: the
 * Kubernetes one everywhere, the peer one only for connections. An enricher whose
 * preconditions do not hold adds nothing, leaving the span exactly as it was. See
 * otlp_enrich.h for the details, and for how to add another. */

/* ---- span batching, so that one record does not mean one POST ---- */
/* Each span push path -- dns, conn, l7, http, offcpu, audit -- used to build a span
 * per record and POST it immediately, which turns a high-frequency event into a
 * flood of tiny requests. This funnel deep-copies spans into a buffer and sends
 * them as a single POST either when batch_max have accumulated or at the end of a
 * drain cycle. Every path builds an otlp_generic_span_t, so one helper covers them
 * all at once.
 *
 * Mixing is legitimate: the resource attributes (service.*) are common to every
 * span, while per-pod facts such as k8s.* are span attributes, so spans from
 * different pods can share one ResourceSpans.
 *
 * Setting SPNL_OTLP_BATCH_MAX=1 restores one span per POST, and the body is then
 * byte-identical to the single-span encoding. The default is 64. The copy has to be
 * deep because otlp_generic_span_t holds its name and attributes by pointer, and
 * each push loop reuses the same buffers. */
#define OTLP_BATCH_HARD_MAX 128   /* the fixed storage ceiling; the env var clamps to it */
#define OTLP_BATCH_ATTR_CAP 20    /* most attributes on one span; a connection span
                                     peaks at 15: 6 base, comm, 6 from Kubernetes, 2 peer */
#define OTLP_BATCH_NAME_CAP 320   /* longest span name; the longest in practice is an audit name at 300 */

typedef struct {
    otlp_generic_span_t spans[OTLP_BATCH_HARD_MAX];
    char      names[OTLP_BATCH_HARD_MAX][OTLP_BATCH_NAME_CAP];
    otlp_kv_t attrs[OTLP_BATCH_HARD_MAX][OTLP_BATCH_ATTR_CAP];
    int  n;            /* spans currently buffered */
    int  max;          /* flush threshold, within [1, HARD_MAX] */
    int  posts;        /* flushes so far, which is the POST count; used in tests */
    int  last_status;  /* HTTP status of the most recent flush */
    const char *endpoint;
    const char *svc;
    const char *ver;
    const char *scope;
} otlp_span_batch_t;

/* The runtime is single-threaded and the push functions run one at a time, so all
 * paths share a single buffer -- about 1.4 MB of BSS. */
static otlp_span_batch_t g_span_batch;

static int otlp_batch_env_max(void) {
    const char *e = getenv("SPNL_OTLP_BATCH_MAX");
    int m = 64;   /* batching on by default */
    if (e && e[0]) { int v = atoi(e); if (v >= 1) m = v; }
    if (m < 1) m = 1;
    if (m > OTLP_BATCH_HARD_MAX) m = OTLP_BATCH_HARD_MAX;
    return m;
}

static void otlp_batch_begin(otlp_span_batch_t *b, const char *endpoint,
                             const char *svc, const char *ver, const char *scope) {
    b->n = 0; b->posts = 0; b->last_status = 0;
    b->max = otlp_batch_env_max();
    b->endpoint = endpoint; b->svc = svc; b->ver = ver; b->scope = scope;
}

/* Send everything buffered as one request. Returns the HTTP status, 0 when there
 * was nothing to send, or -1 on failure. */
static int otlp_batch_flush(otlp_span_batch_t *b) {
    if (b->n <= 0) return 0;
    static uint8_t buf[1 << 20];   /* 1 MB, enough for HARD_MAX spans */
    long blen = otlp_traces_generic_build_multi(buf, sizeof buf, b->svc, b->ver, b->scope,
                                                b->spans, (size_t)b->n);
    int had = b->n; b->n = 0;   /* clear regardless of outcome: dropping on failure is
                                   preferable to sending the same spans twice */
    if (blen < 0) { fprintf(stderr, "[otlp] batch encode failed (n=%d)\n", had); return -1; }
    int status = 0; char err[256] = {0};
    int rc = otlp_transport_send(b->endpoint, "/v1/traces", OTLP_GRPC_PATH_TRACES,
                                 "application/x-protobuf", buf, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] batch send error: %s\n", err); return -1; }
    b->posts++; b->last_status = status;
    return status;
}

/* Deep-copy a span into the batch, flushing first when full. Returns 1 once the
 * span is buffered -- including when that flush failed to send -- and -1 when it
 * could not be copied. The stored name and attributes point at buffer-owned copies. */
static int otlp_batch_add(otlp_span_batch_t *b, const otlp_generic_span_t *s) {
    if (b->n >= b->max) otlp_batch_flush(b);   /* full: flush, and buffer this one regardless */
    if (b->n >= OTLP_BATCH_HARD_MAX) return -1;
    int i = b->n;
    otlp_generic_span_t *d = &b->spans[i];
    memcpy(d, s, sizeof *d);
    snprintf(b->names[i], OTLP_BATCH_NAME_CAP, "%s", s->name ? s->name : "");
    d->name = b->names[i];
    int na = s->nattrs; if (na < 0) na = 0; if (na > OTLP_BATCH_ATTR_CAP) na = OTLP_BATCH_ATTR_CAP;
    for (int k = 0; k < na; k++) b->attrs[i][k] = s->attrs[k];   /* struct copy, key and value arrays included */
    d->attrs = b->attrs[i]; d->nattrs = na;
    b->n++;
    (void)spnl_oneshot_add(1);   /* one span counts as one event; the exit check runs at the final flush */
    return 1;
}

/* The flush at the end of each drain cycle. It sends the tail batch, then checks
 * SPNL_MAX_EVENTS: once the running span count reaches K the process exits cleanly,
 * and because the tail has already been sent nothing is lost. The check happens on
 * a batch boundary, so any overshoot is bounded by the spans buffered in that last
 * cycle. */
static int otlp_batch_flush_final(otlp_span_batch_t *b) {
    int st = otlp_batch_flush(b);
    if (spnl_oneshot_add(0)) spnl_oneshot_exit();
    return st;
}

/* ---- traces: emit4 ringbuf -> span -> OTLP traces ---- */

#define OTLP_MAX_EVENTS 65536

struct ev_collector { otlp_span_event_t *ev; size_t n; size_t cap; };

/* emit4 record: spnl_event_hdr + __s64 a,b,c,d (a=kind, b=idx, c=ktime_ns, d=tid)。 */
static int trace_rb_cb(void *ctx, void *data, size_t size) {
    struct ev_collector *c = (struct ev_collector *)ctx;
    const size_t H = sizeof(struct spnl_event_hdr);
    if (size < H + 32 || c->n >= c->cap) return 0;
    const uint8_t *pl = (const uint8_t *)data + H;  /* the payload, immediately after the header */
    int64_t a, b, cc, d;
    memcpy(&a, pl + 0, 8); memcpy(&b, pl + 8, 8);
    memcpy(&cc, pl + 16, 8); memcpy(&d, pl + 24, 8);
    otlp_span_event_t *e = &c->ev[c->n++];
    e->kind = (int32_t)a; e->idx = (int32_t)b;
    e->ktime_ns = (uint64_t)cc; e->tid = (uint64_t)d;
    return 0;
}

int spnl_otlp_trace_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;

    static otlp_span_event_t events[OTLP_MAX_EVENTS];
    struct ev_collector coll = { events, 0, OTLP_MAX_EVENTS };
    if (otlp_drain(obj, map_name, trace_rb_cb, &coll) != 0) return -1;
    if (coll.n >= coll.cap)
        fprintf(stderr, "[otlp] WARNING: span events capped at %zu (truncated)\n", coll.cap);

    int64_t off = otlp_ktime_to_unix_off();
    uint64_t seed = wall_now_ns() ^ (uint64_t)getpid();

    static otlp_span_t spans[OTLP_MAX_EVENTS / 2 + 1];
    int nsp = otlp_traces_assemble(events, coll.n, off, seed,
                                   spans, sizeof spans / sizeof spans[0]);

    static otlp_method_meta_t metas[OTLP_MAX_METHODS];
    for (int i = 0; i < g_nmethods; i++) {
        metas[i].idx = g_methods[i].idx;
        metas[i].method = g_methods[i].ruby;
        metas[i].file = g_methods[i].file;
        metas[i].line = g_methods[i].line;
    }

    static uint8_t buf[1 << 18];
    long blen; const char *ct; const uint8_t *body;
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        static char jbuf[1 << 19];
        blen = otlp_json_traces_build(jbuf, sizeof jbuf, g_service, g_version, "spinel-ebpf",
                                      spans, (size_t)nsp, metas, (size_t)g_nmethods);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        blen = otlp_traces_build(buf, sizeof buf, g_service, g_version, "spinel-ebpf",
                                 spans, (size_t)nsp, metas, (size_t)g_nmethods);
        body = buf; ct = "application/x-protobuf";
    }
    if (blen < 0) { fprintf(stderr, "[otlp] trace encode failed\n"); return -1; }

    int status = 0; char err[256] = {0};
    int rc = otlp_transport_send(endpoint, "/v1/traces", OTLP_GRPC_PATH_TRACES,
                                 ct, body, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] trace send error: %s\n", err); return -1; }
    fprintf(stderr, "[otlp] pushed %d spans (%zu events) -> %s (status %d)\n",
            nsp, coll.n, endpoint, status);
    if (spnl_oneshot_add((long)coll.n)) spnl_oneshot_exit();   /* one drained record counts as one event */
    return status;
}

/* ---- logs: drain an emit ringbuf, turn each event into a LogRecord, POST ---- */

#define OTLP_MAX_LOGS 8192

struct log_rec_raw { uint64_t ktime; int64_t ival; char sval[256]; };
struct log_collector { struct log_rec_raw *recs; size_t n; size_t cap; int is_str; };

/* An emit record is a spnl_event_hdr followed by either an __s64 value or a
 * char str[256]; the timestamp comes from the header. */
static int log_rb_cb(void *ctx, void *data, size_t size) {
    struct log_collector *c = (struct log_collector *)ctx;
    const size_t H = sizeof(struct spnl_event_hdr);
    if (size < H || c->n >= c->cap) return 0;
    const struct spnl_event_hdr *hdr = (const struct spnl_event_hdr *)data;
    const uint8_t *pl = (const uint8_t *)data + H;  /* the payload, immediately after the header */
    struct log_rec_raw *r = &c->recs[c->n];
    r->ktime = hdr->timestamp;
    r->ival = 0; r->sval[0] = '\0';
    if (c->is_str) {
        size_t avail = size - H;
        if (avail > sizeof r->sval - 1) avail = sizeof r->sval - 1;
        memcpy(r->sval, pl, avail);
        r->sval[avail] = '\0';
    } else {
        if (size < H + 8) return 0;
        memcpy(&r->ival, pl, 8);
    }
    c->n++;
    return 0;
}

int spnl_otlp_log_push_obj(struct bpf_object *obj, const char *map_name, int is_str,
                           const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;

    static struct log_rec_raw raw[OTLP_MAX_LOGS];
    struct log_collector coll = { raw, 0, OTLP_MAX_LOGS, is_str };
    if (otlp_drain(obj, map_name, log_rb_cb, &coll) != 0) return -1;
    if (coll.n >= coll.cap)
        fprintf(stderr, "[otlp] WARNING: log events capped at %zu (truncated)\n", coll.cap);

    int64_t off = otlp_ktime_to_unix_off();

    static otlp_log_record_t recs[OTLP_MAX_LOGS];
    for (size_t i = 0; i < coll.n; i++) {
        recs[i].time_unix_ns = (uint64_t)((int64_t)raw[i].ktime + off);
        recs[i].severity = 0; /* INFO */
        recs[i].event_name = NULL;
        if (is_str) { recs[i].body_is_str = true;  recs[i].body_str = raw[i].sval; recs[i].body_int = 0; }
        else        { recs[i].body_is_str = false; recs[i].body_int = raw[i].ival; recs[i].body_str = NULL; }
    }

    static uint8_t buf[1 << 18];
    long blen; const char *ct; const uint8_t *body;
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        static char jbuf[1 << 19];
        blen = otlp_json_logs_build(jbuf, sizeof jbuf, g_service, g_version, "spinel-ebpf", recs, coll.n);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        blen = otlp_logs_build(buf, sizeof buf, g_service, g_version, "spinel-ebpf", recs, coll.n);
        body = buf; ct = "application/x-protobuf";
    }
    if (blen < 0) { fprintf(stderr, "[otlp] log encode failed\n"); return -1; }

    int status = 0; char err[256] = {0};
    int rc = otlp_transport_send(endpoint, "/v1/logs", OTLP_GRPC_PATH_LOGS,
                                 ct, body, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] log send error: %s\n", err); return -1; }
    fprintf(stderr, "[otlp] pushed %zu logs -> %s (status %d)\n", coll.n, endpoint, status);
    if (spnl_oneshot_add((long)coll.n)) spnl_oneshot_exit();   /* one log record counts as one event */
    return status;
}

/* ---- live audit spans: the [file, comm, parent] triple becomes one span ---- */
/* This assumes the probe emits three records per file_open into the string ringbuf,
 * in a fixed order:
 *   emit_path(file)        -> file.path
 *   emit_comm              -> process.executable.name (semconv)
 *   emit_parent_path       -> process.parent.executable.path, an attribute of our own
 * The header timestamp is a monotonic ktime, converted here to unix nanoseconds and
 * used as the span time. Resolving it in C matters: passing nanoseconds across the
 * FFI integer boundary truncates them, and the span lands in 1970.
 * The three records are submitted back to back within one execution of the BPF
 * handler, so with a marker-comm filter and a single-process probe they do not
 * interleave. */
static uint64_t audit_splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void audit_put_u64_be(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

int spnl_otlp_audit_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;

    static struct log_rec_raw raw[OTLP_MAX_LOGS];
    struct log_collector coll = { raw, 0, OTLP_MAX_LOGS, 1 /* is_str */ };
    if (otlp_drain(obj, map_name, log_rb_cb, &coll) != 0) return -1;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;

    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i + 2 < coll.n; i += 3) {
        const char *file   = raw[i].sval;      /* emit_path */
        const char *comm   = raw[i + 1].sval;  /* emit_comm */
        const char *parent = raw[i + 2].sval;  /* emit_parent_path */
        uint64_t t = (uint64_t)((int64_t)raw[i].ktime + off);   /* when the event actually happened */

        otlp_generic_span_t s;
        memset(&s, 0, sizeof s);
        audit_put_u64_be(s.trace_id,     audit_splitmix64(&seed));
        audit_put_u64_be(s.trace_id + 8, audit_splitmix64(&seed));
        audit_put_u64_be(s.span_id,      audit_splitmix64(&seed));
        s.has_parent = false;
        s.start_unix_ns = t;
        s.end_unix_ns = t;
        s.kind = 0; /* INTERNAL */
        s.is_error = false; /* observation only; the enforcing variant sets verdict=deny and is_error */

        static char namebuf[300];
        snprintf(namebuf, sizeof namebuf, "file_open %s", file[0] ? file : "?");
        s.name = namebuf;

        otlp_kv_t attrs[4];
        int n = 0;
        if (file[0])   { snprintf(attrs[n].key, sizeof attrs[n].key, "file.path");
                         snprintf(attrs[n].val, sizeof attrs[n].val, "%s", file); n++; }
        if (comm[0])   { snprintf(attrs[n].key, sizeof attrs[n].key, "process.executable.name");
                         snprintf(attrs[n].val, sizeof attrs[n].val, "%s", comm); n++; }
        if (parent[0]) { snprintf(attrs[n].key, sizeof attrs[n].key, "process.parent.executable.path");
                         snprintf(attrs[n].val, sizeof attrs[n].val, "%s", parent); n++; }
        { snprintf(attrs[n].key, sizeof attrs[n].key, "verdict");
          snprintf(attrs[n].val, sizeof attrs[n].val, "observe"); n++; }
        s.attrs = attrs; s.nattrs = n;

        otlp_batch_add(&g_span_batch, &s);   /* buffer it; one POST when full or at the end */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);   /* end of the cycle: flush the remainder, losing nothing */
    /* One span is three str records (path/comm/parent), so `out` is counted in
     * records too -- otherwise a healthy run would read as if two thirds of the
     * traffic had been discarded. A leftover fraction is dropped rather than
     * carried to the next drain: the packed-record channels avoid this triple
     * desync by construction, but the str path still has it, and it disappearing
     * silently is exactly what this counter exists to prevent. */
    spnl_channel_out(map_name, (long)sent * 3);
    if (coll.n > (size_t)sent * 3)
        spnl_channel_dropped(map_name, "incomplete_triple",
            "emit_path / emit_comm / emit_parent_path form one span only as a "
            "complete set of three. A leftover fraction means the three are "
            "emitted under different conditions, or a triple was split across a "
            "drain boundary. Call all three unconditionally in the handler.");
    fprintf(stderr, "[otlp] pushed %d audit spans (%zu str records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ================= the span slots shared by every typed consumer =================
 *
 * Slots for assembled spans. Ruby holds slot index + 1 as its handle, so 0 means
 * "no span". The batch deep-copies on add, so a slot only has to survive until the
 * send; it is a small ring anyway, so that nesting several
 * `send_otlp(to_span(a), ep)` calls cannot corrupt one another.
 *
 * Every channel's to_span shares these, so they must be wide enough for the
 * broadest one: a connection span carries 7 of its own and can reach 20 once the
 * enrichers have run. Each channel's fill_span still caps at the same count the
 * one-call form uses, so nothing about the wire changes -- this is only about the
 * container. They sit ahead of all the channels rather than inside the dns section,
 * since four channels use them. */
#define OTLP_EV_SPAN_SLOTS 4
#define OTLP_EV_SPAN_ATTRS 20
static otlp_generic_span_t g_ev_span[OTLP_EV_SPAN_SLOTS];
static otlp_kv_t           g_ev_attrs[OTLP_EV_SPAN_SLOTS][OTLP_EV_SPAN_ATTRS];
static char                g_ev_name[OTLP_EV_SPAN_SLOTS][160];
static int                 g_ev_slot;
static uint64_t            g_ev_seed;
static int                 g_ev_batch_open;   /* has a batch been opened this drain cycle */
static int                 g_ev_sent;         /* spans buffered before the flush, for reporting */

/* ---- network audit spans: a packed connect event becomes a network span ---- */
/* The connection record was the worst of the hand-written mirrors: a comment block
 * spelling out `pid(0..4) comm(4..20) ... daddr6_lo(64..72)` next to eleven
 * memcpy()s with literal offsets, kept in step with the kernel struct by review
 * alone. Both ends now derive from record_schema.h (cc_rec_conn). */
struct conn_collector { spnl_rec_conn_t *recs; size_t n; size_t cap; };

static int conn_rb_cb(void *ctx, void *data, size_t size) {
    struct conn_collector *c = (struct conn_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_conn_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* The connection record's two declared derivations. They are deliberately not
 * static: the generated accessors behind `ev.peer` and `ev.direction` call them,
 * and so does the span builder -- one function, one answer.
 *
 * Connections were the last channel to gain typed consumers because neither value
 * can be written from a single field: the destination depends on the address family
 * (daddr, or the two halves of daddr6), and the direction is a reading of the
 * previous socket state. That is what the record-to-string derivation form is for.
 *
 * Keeping the v4/v6 branch on this side is the point. Ruby writes `ev.peer` and
 * never learns that AF_INET6 exists; deciding what the bytes mean belongs here. */

/* The destination address as text. daddr is a raw big-endian IPv4 address; for
 * AF_INET6 the two halves of the v6 address, read as network-order u64s, are
 * reassembled into an in6_addr and formatted. The span's network.peer.address is
 * exactly what this returns. */
static void conn_peer_addr(const spnl_rec_conn_t *r, char *out, size_t cap) {
    if (r->family != 10 /* AF_INET6 */) {
        struct in_addr a; a.s_addr = r->daddr;
        inet_ntop(AF_INET, &a, out, (socklen_t)cap);
    } else {
        struct in6_addr a6;
        memcpy(&a6.s6_addr[0], &r->daddr6_hi, 8);
        memcpy(&a6.s6_addr[8], &r->daddr6_lo, 8);
        inet_ntop(AF_INET6, &a6, out, (socklen_t)cap);
    }
}

/* `ev.peer` is "<address>:<port>", where the address comes from the same function
 * that produces network.peer.address and the port is network.peer.port. It is
 * therefore the same string the span name is built from, which is what makes it
 * structurally impossible for what Ruby sees to disagree with what is sent. */
void spnl_conn_peer(const spnl_rec_conn_t *r, char *out, int cap) {
    char addr[INET6_ADDRSTRLEN] = {0};
    if (!r || cap <= 0) { if (out && cap > 0) out[0] = '\0'; return; }
    conn_peer_addr(r, addr, sizeof addr);
    snprintf(out, (size_t)cap, "%s:%u", addr, r->dport);
}

/* `ev.direction` is the spnl.conn.direction attribute itself, read from the state
 * the socket was in just before it reached ESTABLISHED: from SYN_SENT we dialled
 * out (active), from SYN_RECV we accepted (passive), and anything else is other. */
void spnl_conn_direction(const spnl_rec_conn_t *r, char *out, int cap) {
    const char *dir;
    if (!r || cap <= 0) { if (out && cap > 0) out[0] = '\0'; return; }
    dir = (r->oldstate == 2) ? "active" : (r->oldstate == 3) ? "passive" : "other";
    snprintf(out, (size_t)cap, "%s", dir);
}

/* `ev.srtt_us` is the net.peer.srtt_us attribute itself. The kernel's
 * tcp_sock->srtt_us is in eighths of a microsecond, so the real value is that
 * shifted right by three.
 *
 * This field was once exposed raw, and was the one property where the value Ruby
 * saw differed from the value on the wire: a 1 ms round trip read as 1000 in the
 * span and 8000 in Ruby. Writing "divide by 8" in a note is a warning, not a
 * contract. Confining the unit to one function -- called by both span-building
 * forms and by the request-tree assembly -- makes "what Ruby sees is what goes out"
 * structural instead. A scale is part of what a number means, so it belongs on
 * this side. */
long spnl_conn_srtt_us(const spnl_rec_conn_t *r) {
    return r ? (long)(r->srtt_us >> 3) : 0;
}

/* Build the span its egress declaration describes from one record. Both the
 * one-call push and the explicit to_span go through this, as they do for the other
 * channels. attrs holds 20 entries -- 7 of its own, and room for the enrichers --
 * and namebuf receives the span name. Returns 1: a connection record always
 * becomes a span. */
static int conn_fill_span(const spnl_rec_conn_t *rr, int64_t off, uint64_t *seed,
                          otlp_generic_span_t *s, otlp_kv_t *attrs,
                          char *namebuf, size_t namecap) {
    /* The width here matches the accessor's, for the same reason it does for the
     * DNS name below. Direction only ever yields "active", "passive" or "other", so
     * nothing would actually break, but the rule is kept without exceptions. That
     * shared width comes from direction's own declared cap. */
    char peer[INET6_ADDRSTRLEN] = {0}, dir[SPNL_REC_DERIVED_CONN_DIRECTION_CAP] = {0};
    int is6 = (rr->family == 10 /* AF_INET6 */);
    conn_peer_addr(rr, peer, sizeof peer);        /* the address half of ev.peer */
    spnl_conn_direction(rr, dir, (int)sizeof dir);/* ev.direction, the very same function */
    uint64_t t = (uint64_t)((int64_t)rr->hdr.timestamp + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* the one place trace contexts are minted */
    s->start_unix_ns = t; s->end_unix_ns = t; s->kind = 0;

    snprintf(namebuf, namecap, SPNL_EGRESS_CONN_SPAN_NAME_FMT, peer, rr->dport);
    s->name = namebuf;

    int n = 0;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_ADDRESS); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",peer); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_PORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"%u",rr->dport); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_TRANSPORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"tcp"); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_TYPE);         snprintf(attrs[n].val,sizeof attrs[n].val,"%s",is6?"ipv6":"ipv4"); n++;
    /* Microseconds. semconv has no attribute for round-trip time, so the name is
     * ours. The scaling lives in the derivation, so this is literally the output of
     * the same function `ev.srtt_us` calls. */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NET_PEER_SRTT_US);     snprintf(attrs[n].val,sizeof attrs[n].val,"%lld",(long long)spnl_conn_srtt_us(rr)); n++;
    /* active/passive. semconv has no connection-direction key -> custom. */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_SPNL_CONN_DIRECTION);  snprintf(attrs[n].val,sizeof attrs[n].val,"%s",dir); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    /* Connections are the one signal both enrichers apply to: Kubernetes for the
     * originating pod and its workload, peer for the destination. They run in
     * registry order, k8s then peer. */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, rr->cgid, peer };
    n += otlp_enrich_run(&ec, attrs + n, 20 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* The connection records from the last drain. The one-call push and the typed
 * consumer share this buffer. */
static spnl_rec_conn_t g_rec_conn[OTLP_MAX_LOGS];
static int             g_rec_conn_n;

int spnl_otlp_conn_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct conn_collector coll = { g_rec_conn, 0, OTLP_MAX_LOGS };
    g_rec_conn_n = 0;
    if (otlp_drain(obj, map_name, conn_rb_cb, &coll) != 0) return -1;
    g_rec_conn_n = (int)coll.n;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        otlp_generic_span_t s;
        otlp_kv_t attrs[20];
        static char namebuf[128];
        if (!conn_fill_span(&coll.recs[i], off, &seed, &s, attrs, namebuf, sizeof namebuf)) continue;
        otlp_batch_add(&g_span_batch, &s);   /* buffer it; the batch flushes at the end of the cycle */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    spnl_channel_out(map_name, (long)sent);
    fprintf(stderr, "[otlp] pushed %d conn spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- typed record consumer: `on_emit :conn do |ev|` ---- */
const spnl_rec_conn_t *spnl_rec_conn_at(int i) {
    return (i >= 0 && i < g_rec_conn_n) ? &g_rec_conn[i] : NULL;
}

int spnl_rec_conn_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct conn_collector coll = { g_rec_conn, 0, OTLP_MAX_LOGS };
    g_rec_conn_n = 0;
    if (otlp_drain_ms(obj, map_name, conn_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
    g_rec_conn_n = (int)coll.n;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
       record cannot filter one either. */
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);
    return g_rec_conn_n;
}

/* `to_span(ev)` and `conn_span(ev)`: one record becomes the span its declaration
 * describes. A 0 return means the handle was not valid. */
int spnl_rec_conn_to_span(int i) {
    const spnl_rec_conn_t *r = spnl_rec_conn_at(i);
    if (!r) return 0;
    if (!g_ev_seed) g_ev_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    int slot = g_ev_slot;
    g_ev_slot = (g_ev_slot + 1) % OTLP_EV_SPAN_SLOTS;
    if (!conn_fill_span(r, otlp_ktime_to_unix_off(), &g_ev_seed, &g_ev_span[slot],
                        g_ev_attrs[slot], g_ev_name[slot], sizeof g_ev_name[slot]))
        return 0;
    return slot + 1;
}

/* ---- DNS query spans: the QNAME seen on a socket bound to port 53 ----
 * Watching the socket rather than a resolver library is what makes this
 * resolver-independent.
 * The record type and its field offsets are generated into record_mirror_gen.h. A
 * record shorter than the contract makes unpack return -1 and is dropped; the
 * threshold is derived from the declared record size rather than written out. */
struct dns_collector { spnl_rec_dns_t *recs; size_t n; size_t cap; };

static int dns_rb_cb(void *ctx, void *data, size_t size) {
    struct dns_collector *c = (struct dns_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_dns_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* length-prefixed QNAME (raw[12..]) -> dotted host. userspace parse (no verifier).
 * Not static, because it is the declared implementation of the derived
 * This is the `ev.qname` property. The generated accessor calls this function, so
 * the hostname Ruby reads and the span's dns.question.name come out of one parser. */
void spnl_dns_qname(const unsigned char *raw, char *out, int cap) {
    int off = 12, o = 0;
    while (off < 60 && o < cap - 1) {
        int l = raw[off++];
        if (l == 0 || l > 63) break;
        for (int k = 0; k < l && off < 64 && o < cap - 1; k++) out[o++] = raw[off++];
        out[o++] = '.';
    }
    if (o > 0 && out[o-1] == '.') o--;
    out[o] = 0;
}

/* Build the span its egress declaration describes from one record. Both forms come
 * through here: the one-call push is sugar that applies this to every record and
 * sends them, and to_span applies it to the record the consumer chose. That the
 * sugar unwraps to the explicit form is therefore a structural fact rather than a
 * comment -- there is exactly one author of the attributes, the span kind and the
 * timestamps, so the two cannot drift apart.
 *
 * attrs holds 8 entries and namebuf receives the span name; both are owned by the
 * caller and need only survive until the batch deep-copies them. Returns 1 when a
 * span was built, and 0 when this record does not become one -- an unparseable
 * QNAME, which the declaration records as its drop condition. */
static int dns_fill_span(const spnl_rec_dns_t *rr, int64_t off, uint64_t *seed,
                         otlp_generic_span_t *s, otlp_kv_t *attrs,
                         char *namebuf, size_t namecap) {
    /* The same width the generated accessor passes for `ev.qname`. Handing one
     * function two different caps makes long values truncate in two different
     * places; the single width comes from qname's own declaration, 255 for a DNS
     * name plus the terminator. */
    char host[SPNL_REC_DERIVED_DNS_QNAME_CAP]; spnl_dns_qname(rr->raw, host, sizeof host);
    if (!host[0]) return 0;   /* not a parseable DNS query */
    uint64_t t = (uint64_t)((int64_t)rr->hdr.timestamp + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* the one place trace contexts are minted */
    /* The latency-aware emit carries a real resolution round trip (duration_ns>0);
     * the query-only emit is
     * query-only (duration_ns==0 -> span end == start, as before). */
    s->start_unix_ns = t; s->end_unix_ns = t + rr->duration_ns; s->kind = 0;
    snprintf(namebuf, namecap, SPNL_EGRESS_DNS_SPAN_NAME_FMT, host);
    s->name = namebuf;

    /* The span name and attribute keys are the SPNL_EGRESS_DNS_* macros, generated
     * from the egress declaration. This code consumes that declaration rather than
     * authoring it, which is why the contract `capabilities --json` and `describe`
     * report is the same thing that goes on the wire. */
    int n = 0;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_DNS_ATTR_DNS_QUESTION_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",host); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_DNS_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    if (rr->duration_ns) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_DNS_ATTR_SPNL_DNS_LATENCY_NS); snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)rr->duration_ns); n++; }   /* the resolution round-trip time */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_DNS, rr->cgid, NULL };   /* Kubernetes only; peer is for connections */
    n += otlp_enrich_run(&ec, attrs + n, 8 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* The DNS records from the last drain. Both forms use this one buffer rather than
 * keeping two copies of about a megabyte. The runtime is single-threaded and these
 * are called in sequence. */
static spnl_rec_dns_t g_rec_dns[OTLP_MAX_LOGS];
static int            g_rec_dns_n;

int spnl_otlp_dns_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct dns_collector coll = { g_rec_dns, 0, OTLP_MAX_LOGS };
    g_rec_dns_n = 0;
    if (otlp_drain(obj, map_name, dns_rb_cb, &coll) != 0) return -1;
    g_rec_dns_n = (int)coll.n;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        otlp_generic_span_t s;
        otlp_kv_t attrs[8];
        static char namebuf[160];
        if (!dns_fill_span(&coll.recs[i], off, &seed, &s, attrs, namebuf, sizeof namebuf)) {
            /* The channel's egress contract says a record whose QNAME does not
             * parse produces no span. Counting it here turns that silent
             * discard into something a reader can see. */
            spnl_channel_dropped(map_name, "unparseable_qname",
                "the record's raw bytes are not a DNS query. emit_dns expects the "
                "payload of a UDP send to port 53 -- check the attach point "
                "(udp_sendmsg) and the port filter (dport == 13568).");
            continue;
        }
        otlp_batch_add(&g_span_batch, &s);   /* buffer it; the batch flushes at the end of the cycle */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    spnl_channel_out(map_name, (long)sent);
    fprintf(stderr, "[otlp] pushed %d dns spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ================= typed record consumer: `on_emit :dns do |ev|` ===================
 *
 * The one-call form collapses drain, build and send into a single verb, which
 * leaves nowhere for the probe author's own logic to go. These split that verb into
 * three: drain hands out records, to_span turns one into a span, send sends it.
 * None of them exposes the record's bytes to Ruby: what Ruby holds is an index into
 * the drain, and fields are reachable only through the generated accessors.
 *
 * The span itself is built by the same function the one-call form uses, so writing
 * the explicit form changes not one byte of the attributes, the span kind or the
 * timestamps. The only thing that changes is which records get sent. */

/* The lookup the generated accessors call; its prototype is in the generated
 * header. An out-of-range index yields NULL, and the accessor then returns a zero
 * value: Ruby has no way to hold an invalid handle, so this must not crash. */
const spnl_rec_dns_t *spnl_rec_dns_at(int i) {
    return (i >= 0 && i < g_rec_dns_n) ? &g_rec_dns[i] : NULL;
}

/* drain: read the ringbuf's records into an array and return how many there were;
 * Ruby's handles are the indices 0..n-1. timeout_ms is how long a single poll
 * waits, with 0 meaning non-blocking and a negative value meaning the 100ms the
 * one-call form uses. */
int spnl_rec_dns_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct dns_collector coll = { g_rec_dns, 0, OTLP_MAX_LOGS };
    g_rec_dns_n = 0;
    if (otlp_drain_ms(obj, map_name, dns_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
    g_rec_dns_n = (int)coll.n;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
       record cannot filter one either. */
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);
    return g_rec_dns_n;
}

/* The slots, the seed and the batch state are shared by every typed channel; see
 * the section above. */

/* `to_span(ev)`: one record becomes the span its declaration describes. A 0 return
 * means this record does not become a span -- an unparseable QNAME. Sending handle
 * 0 is a no-op, so a probe need not branch on it. */
int spnl_rec_dns_to_span(int i) {
    const spnl_rec_dns_t *r = spnl_rec_dns_at(i);
    if (!r) return 0;
    if (!g_ev_seed) g_ev_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    int slot = g_ev_slot;
    g_ev_slot = (g_ev_slot + 1) % OTLP_EV_SPAN_SLOTS;
    if (!dns_fill_span(r, otlp_ktime_to_unix_off(), &g_ev_seed, &g_ev_span[slot],
                       g_ev_attrs[slot], g_ev_name[slot], sizeof g_ev_name[slot]))
        return 0;
    return slot + 1;
}

/* `send_otlp(span, ep)`: add a span to the send batch, through the same funnel
 * everything else uses -- one POST when it fills, the rest at the flush. Returns 1
 * when the span was buffered and 0 when nothing happened, such as an invalid
 * handle. The endpoint is taken from the first send of the cycle; nothing needs to
 * change it midway. */
int spnl_otlp_span_send(int handle, const char *endpoint) {
    if (handle <= 0 || handle > OTLP_EV_SPAN_SLOTS || !endpoint || !endpoint[0]) return 0;
    if (!g_ev_batch_open) {
        const char *svc = getenv("OTEL_SERVICE_NAME");
        if (!svc || !svc[0]) svc = g_service;
        otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
        g_ev_batch_open = 1;
        g_ev_sent = 0;
    }
    otlp_batch_add(&g_span_batch, &g_ev_span[handle - 1]);
    g_ev_sent++;
    return 1;
}

/* The end-of-cycle flush, which the generated driver calls every cycle. It returns
 * the HTTP status of the last POST, or 0 if nothing was buffered -- the same thing
 * the one-call push returns. */
int spnl_otlp_span_flush(void) {
    if (!g_ev_batch_open) return 0;
    int st = otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] typed consumer: sent %d spans (%d posts, last HTTP %d) -> %s\n",
            g_ev_sent, g_span_batch.posts, g_span_batch.last_status,
            g_span_batch.endpoint ? g_span_batch.endpoint : "?");
    g_ev_batch_open = 0;
    return st;
}

/* ---- L7 request/response latency span: the send-to-recv round trip ---- */
/* l7_event: hdr + {pid, comm[16], daddr(be32), dport(host), family, start_ktime, duration_ns}.
 * Unlike a connect span, whose duration is zero, the L7 span's duration IS the payload:
 * end_unix = start_unix + duration_ns = time-to-first-response-byte. */
/* The record type and offsets come from record_mirror_gen.h (generated from the
 * same record_schema.h the kernel struct is generated from); the hand-typed
 * `memcpy(p + 32, ...)` ladder that used to live here is gone. */
struct l7_collector { spnl_rec_l7_t *recs; size_t n; size_t cap; };

static int l7_rb_cb(void *ctx, void *data, size_t size) {
    struct l7_collector *c = (struct l7_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_l7_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* Build the span its egress declaration describes from one record; both forms come
 * through here, exactly as they do for DNS, so that the attributes, span kind and
 * timestamps have a single author. attrs holds 10 entries. Returns 1: an L7 record
 * always becomes a span. */
static int l7_fill_span(const spnl_rec_l7_t *rr, int64_t off, uint64_t *seed,
                        otlp_generic_span_t *s, otlp_kv_t *attrs,
                        char *namebuf, size_t namecap) {
    char peer[INET6_ADDRSTRLEN] = {0};
    int is6 = (rr->family == 10 /* AF_INET6 */);
    if (!is6) { struct in_addr a; a.s_addr = rr->daddr; inet_ntop(AF_INET, &a, peer, sizeof peer); }
    else      { snprintf(peer, sizeof peer, "(ipv6 not carried)"); }
    uint64_t start_unix = (uint64_t)((int64_t)rr->start_ktime + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* the one place trace contexts are minted */
    /* span duration = L7 round-trip latency (NOT srtt); this is the payload. */
    s->start_unix_ns = start_unix; s->end_unix_ns = start_unix + rr->duration_ns; s->kind = 3 /* CLIENT */;

    snprintf(namebuf, namecap, SPNL_EGRESS_L7_SPAN_NAME_FMT, peer, rr->dport);
    s->name = namebuf;

    int n = 0;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_L7_ATTR_NETWORK_PEER_ADDRESS); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",peer); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_L7_ATTR_NETWORK_PEER_PORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"%u",rr->dport); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_L7_ATTR_NETWORK_TRANSPORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"tcp"); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_L7_ATTR_NETWORK_TYPE);         snprintf(attrs[n].val,sizeof attrs[n].val,"%s",is6?"ipv6":"ipv4"); n++;
    /* L7 round-trip latency in ns (span duration is authoritative; this is a convenience attr). */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_L7_ATTR_SPNL_L7_LATENCY_NS); snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)rr->duration_ns); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_L7_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    /* The peer enricher is for connections only, so L7 gets just the Kubernetes one. */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_L7, rr->cgid, peer };
    n += otlp_enrich_run(&ec, attrs + n, 10 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* The L7 records from the last drain, shared by both forms. */
static spnl_rec_l7_t g_rec_l7[OTLP_MAX_LOGS];
static int           g_rec_l7_n;

int spnl_otlp_l7_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct l7_collector coll = { g_rec_l7, 0, OTLP_MAX_LOGS };
    g_rec_l7_n = 0;
    if (otlp_drain(obj, map_name, l7_rb_cb, &coll) != 0) return -1;
    g_rec_l7_n = (int)coll.n;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        otlp_generic_span_t s;
        otlp_kv_t attrs[10];
        static char namebuf[128];
        if (!l7_fill_span(&coll.recs[i], off, &seed, &s, attrs, namebuf, sizeof namebuf)) continue;
        otlp_batch_add(&g_span_batch, &s);   /* buffer it; the batch flushes at the end of the cycle */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    spnl_channel_out(map_name, (long)sent);
    fprintf(stderr, "[otlp] pushed %d l7 spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- typed record consumer: `on_emit :l7 do |ev|` ---- */
const spnl_rec_l7_t *spnl_rec_l7_at(int i) {
    return (i >= 0 && i < g_rec_l7_n) ? &g_rec_l7[i] : NULL;
}

int spnl_rec_l7_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct l7_collector coll = { g_rec_l7, 0, OTLP_MAX_LOGS };
    g_rec_l7_n = 0;
    if (otlp_drain_ms(obj, map_name, l7_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
    g_rec_l7_n = (int)coll.n;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
       record cannot filter one either. */
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);
    return g_rec_l7_n;
}

/* `to_span(ev)` and `l7_span(ev)`: one record becomes its declared span; 0 means
 * the handle was not valid. */
int spnl_rec_l7_to_span(int i) {
    const spnl_rec_l7_t *r = spnl_rec_l7_at(i);
    if (!r) return 0;
    if (!g_ev_seed) g_ev_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    int slot = g_ev_slot;
    g_ev_slot = (g_ev_slot + 1) % OTLP_EV_SPAN_SLOTS;
    if (!l7_fill_span(r, otlp_ktime_to_unix_off(), &g_ev_seed, &g_ev_span[slot],
                      g_ev_attrs[slot], g_ev_name[slot], sizeof g_ev_name[slot]))
        return 0;
    return slot + 1;
}

/* ---- HTTP RED span: method, path, status and duration ---- */
/* http_event: hdr + {pid, comm[16], daddr, dport, family, start_ktime, duration_ns,
 * req[64], resp[16]}. method/path parsed from req ("METHOD path HTTP/.."), status from
 * resp ("HTTP/1.1 NNN ..") in userspace; the kernel only did a bounded copy, as it
 * does for a DNS name.
 * Span duration = L7 round-trip; status>=500 -> Span.status=ERROR (RED error axis). */
/* The layout comes from the record declaration, via the generated mirror. */
struct http_collector { spnl_rec_http_t *recs; size_t n; size_t cap; };

static int http_rb_cb(void *ctx, void *data, size_t size) {
    struct http_collector *c = (struct http_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_http_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* copy a token (up to space/CR/LF/NUL, printable only) from src into dst[cap]. */
static void http_token(const unsigned char *src, size_t srclen, char *dst, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; i < srclen && j + 1 < cap; i++) {
        unsigned char ch = src[i];
        if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\0') break;
        dst[j++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
    }
    dst[j] = '\0';
}

/* The HTTP record's three declared derivations. They are deliberately not static:
 * the generated accessors behind `ev.method` and friends call them, and so does the
 * span builder -- so the value a probe filters on cannot differ from the value that
 * ends up on the span. Each implementation knows the width of its own source field,
 * taken from the generated struct, which is why no literal 64 or 16 appears here. */
#define SPNL_HTTP_REQ_LEN  (sizeof(((const spnl_rec_http_t *)0)->req))
#define SPNL_HTTP_RESP_LEN (sizeof(((const spnl_rec_http_t *)0)->resp))

void spnl_http_method(const unsigned char *req, char *out, int cap) {
    http_token(req, SPNL_HTTP_REQ_LEN, out, (size_t)cap);
}

void spnl_http_path(const unsigned char *req, char *out, int cap) {
    size_t mo = 0;
    out[0] = '\0';
    while (mo < SPNL_HTTP_REQ_LEN && req[mo] != ' ' &&
           req[mo] != '\r' && req[mo] != '\n' && req[mo] != '\0') mo++;   /* end of method */
    while (mo < SPNL_HTTP_REQ_LEN && req[mo] == ' ') mo++;                /* skip the space */
    if (mo < SPNL_HTTP_REQ_LEN) http_token(req + mo, SPNL_HTTP_REQ_LEN - mo, out, (size_t)cap);
}

long spnl_http_status(const unsigned char *resp) {
    size_t k = 0;
    long status = 0;
    while (k < SPNL_HTTP_RESP_LEN && resp[k] != ' ') k++;      /* skip "HTTP/1.1" */
    while (k < SPNL_HTTP_RESP_LEN && resp[k] == ' ') k++;
    for (int d = 0; d < 3 && k < SPNL_HTTP_RESP_LEN && resp[k] >= '0' && resp[k] <= '9'; d++, k++)
        status = status * 10 + (resp[k] - '0');
    return status;
}

/* Build the span its egress declaration describes from one record; the shared
 * builder for both forms. attrs holds 14 entries and namebuf receives the span
 * name. Returns 1: an HTTP record always becomes a span. */
static int http_fill_span(const spnl_rec_http_t *rr, int64_t off, uint64_t *seed,
                          otlp_generic_span_t *s, otlp_kv_t *attrs,
                          char *namebuf, size_t namecap) {
    /* Method, path and status are the outputs of the declared derivations -- the
     * same functions `ev.method` and friends call. The width is part of that
     * contract, so the same one is passed here. A 16-byte method buffer once made
     * these disagree: a 64-byte request head with no space in it (reachable,
     * because the kernel-side filter only inspects the first four bytes) gave Ruby
     * 64 characters and the span 15. Real HTTP methods are at most seven
     * characters, so ordinary traffic never saw a difference. The width now comes
     * from each derivation's own declaration: it cannot exceed the field it is cut
     * from, plus a terminator. */
    char method[SPNL_REC_DERIVED_HTTP_METHOD_CAP] = {0}, path[SPNL_REC_DERIVED_HTTP_PATH_CAP] = {0};
    spnl_http_method(rr->req, method, (int)sizeof method);
    spnl_http_path(rr->req, path, (int)sizeof path);
    int status = (int)spnl_http_status(rr->resp);

    char peer[INET6_ADDRSTRLEN] = {0};
    int is6 = (rr->family == 10 /* AF_INET6 */);
    if (!is6) { struct in_addr a; a.s_addr = rr->daddr; inet_ntop(AF_INET, &a, peer, sizeof peer); }
    else      { snprintf(peer, sizeof peer, "(ipv6 not carried)"); }
    uint64_t start_unix = (uint64_t)((int64_t)rr->start_ktime + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* the one place trace contexts are minted */
    s->start_unix_ns = start_unix; s->end_unix_ns = start_unix + rr->duration_ns;
    s->kind = 3 /* CLIENT — we observe the caller (curl) */;
    s->is_error = (status >= 500);   /* RED error axis: status>=500 -> Span.status=ERROR */

    snprintf(namebuf, namecap, SPNL_EGRESS_HTTP_SPAN_NAME_FMT, method[0] ? method : "HTTP", path);
    s->name = namebuf;

    int n = 0;
    if (method[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_HTTP_REQUEST_METHOD); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",method); n++; }
    if (path[0])   { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_URL_PATH); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",path); n++; }
    if (status>0)  { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_HTTP_RESPONSE_STATUS_CODE); snprintf(attrs[n].val,sizeof attrs[n].val,"%d",status); n++; }
    /* TLS-plaintext path (SSL uprobe) carries no sock -> daddr==0. Mark url.scheme=https
     * and omit peer. The plain TCP path, where daddr is set, is unchanged. */
    if (rr->daddr == 0 && rr->dport == 0) {
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_URL_SCHEME); snprintf(attrs[n].val,sizeof attrs[n].val,"https"); n++;
    } else {
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_ADDRESS); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",peer); n++;
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_PORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"%u",rr->dport); n++;
    }
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_NETWORK_TRANSPORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"tcp"); n++;
    /* Symmetric with the L7 channel's latency attribute. The span's own start and
     * end are authoritative for its length; this attribute exists so the same
     * number is searchable. It also removes an asymmetry: `ev.duration_ns` is
     * published on both channels, but only L7 had a matching span attribute. */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_SPNL_HTTP_LATENCY_NS); snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)rr->duration_ns); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    /* The peer enricher is for connections only, so HTTP gets just the Kubernetes
     * one. The cap of 14 leaves the same room for enrichers as before. */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_HTTP, rr->cgid, peer };
    n += otlp_enrich_run(&ec, attrs + n, 14 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* The HTTP records from the last drain, shared by both forms. */
static spnl_rec_http_t g_rec_http[OTLP_MAX_LOGS];
static int             g_rec_http_n;

int spnl_otlp_http_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct http_collector coll = { g_rec_http, 0, OTLP_MAX_LOGS };
    g_rec_http_n = 0;
    if (otlp_drain(obj, map_name, http_rb_cb, &coll) != 0) return -1;
    g_rec_http_n = (int)coll.n;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        otlp_generic_span_t s;
        otlp_kv_t attrs[14];   /* 14 since the latency attribute was added */
        static char namebuf[96];
        if (!http_fill_span(&coll.recs[i], off, &seed, &s, attrs, namebuf, sizeof namebuf)) continue;
        otlp_batch_add(&g_span_batch, &s);   /* buffer it; the batch flushes at the end of the cycle */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    spnl_channel_out(map_name, (long)sent);
    fprintf(stderr, "[otlp] pushed %d http spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- typed record consumer: `on_emit :http do |ev|` ---- */
const spnl_rec_http_t *spnl_rec_http_at(int i) {
    return (i >= 0 && i < g_rec_http_n) ? &g_rec_http[i] : NULL;
}

int spnl_rec_http_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct http_collector coll = { g_rec_http, 0, OTLP_MAX_LOGS };
    g_rec_http_n = 0;
    if (otlp_drain_ms(obj, map_name, http_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
    g_rec_http_n = (int)coll.n;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
       record cannot filter one either. */
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);
    return g_rec_http_n;
}

/* `to_span(ev)` and `http_span(ev)`: one record becomes its declared span; 0 means
 * the handle was not valid. */
int spnl_rec_http_to_span(int i) {
    const spnl_rec_http_t *r = spnl_rec_http_at(i);
    if (!r) return 0;
    if (!g_ev_seed) g_ev_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    int slot = g_ev_slot;
    g_ev_slot = (g_ev_slot + 1) % OTLP_EV_SPAN_SLOTS;
    if (!http_fill_span(r, otlp_ktime_to_unix_off(), &g_ev_seed, &g_ev_span[slot],
                        g_ev_attrs[slot], g_ev_name[slot], sizeof g_ev_name[slot]))
        return 0;
    return slot + 1;
}

/* ---- Redis RED span: command, error and duration ---- */
/* redis_event has the same byte layout as http_event, and used to borrow http_rec_raw /
 * http_rb_cb outright. It now has its own declaration, and hence its own
 * generated mirror: the two records are equal today but are separate contracts, and `describe`
 * should name the struct a Redis probe actually writes. Only the userspace parse differs
 * (RESP command / -ERR reply instead of method/path/status).
 * Command (rate axis) is the first bulk string of the request array; error axis = a reply that
 * begins with '-' (RESP error). db.* semconv, kind=CLIENT. */

struct redis_collector { spnl_rec_redis_t *recs; size_t n; size_t cap; };

static int redis_rb_cb(void *ctx, void *data, size_t size) {
    struct redis_collector *c = (struct redis_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_redis_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* Parse the first RESP array element (command) and optional second element (key) from a request
 * buffer "*N\r\n$len\r\n<CMD>\r\n$len\r\n<key>\r\n..". Values (3rd+ element) are never read
 * (avoid capturing sensitive payloads). cmd is upper-cased. */
static void redis_parse_cmd_key(const unsigned char *req, size_t reqlen,
                                char *cmd, size_t cmdcap, char *key, size_t keycap) {
    cmd[0] = '\0'; key[0] = '\0';
    size_t i = 0;
    if (reqlen < 4 || req[0] != '*') return;
    /* skip "*N\r\n" */
    while (i < reqlen && req[i] != '\n') i++;
    i++;
    /* element 1: "$len\r\n<CMD>\r\n" */
    if (i >= reqlen || req[i] != '$') return;
    i++;
    long l1 = 0; int seen = 0;
    while (i < reqlen && req[i] >= '0' && req[i] <= '9') { l1 = l1 * 10 + (req[i] - '0'); i++; seen = 1; }
    if (!seen || l1 < 0) return;
    while (i < reqlen && req[i] != '\n') i++;   /* to end of "$len\r" */
    i++;
    size_t j = 0;
    for (long k = 0; k < l1 && i < reqlen && j + 1 < cmdcap; k++, i++) {
        unsigned char c = req[i];
        cmd[j++] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : (char)c;  /* upper-case */
    }
    cmd[j] = '\0';
    while (i < reqlen && req[i] != '\n') i++;   /* skip trailing \r\n of element 1 */
    i++;
    /* element 2 (key): "$len\r\n<key>\r\n" — read as-is (no upper-case), values beyond are skipped */
    if (i >= reqlen || req[i] != '$') return;
    i++;
    long l2 = 0; seen = 0;
    while (i < reqlen && req[i] >= '0' && req[i] <= '9') { l2 = l2 * 10 + (req[i] - '0'); i++; seen = 1; }
    if (!seen || l2 < 0) return;
    while (i < reqlen && req[i] != '\n') i++;
    i++;
    j = 0;
    for (long k = 0; k < l2 && i < reqlen && j + 1 < keycap; k++, i++) {
        unsigned char c = req[i];
        key[j++] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    key[j] = '\0';
}

int spnl_otlp_redis_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    static spnl_rec_redis_t raw[OTLP_MAX_LOGS];
    struct redis_collector coll = { raw, 0, OTLP_MAX_LOGS };
    if (otlp_drain(obj, map_name, redis_rb_cb, &coll) != 0) return -1;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        spnl_rec_redis_t *rr = &coll.recs[i];
        char cmd[24] = {0}, key[48] = {0};
        redis_parse_cmd_key(rr->req, sizeof(rr->req), cmd, sizeof(cmd), key, sizeof(key));
        int is_error = (rr->resp[0] == '-');   /* RESP error reply -> RED error axis */

        char peer[INET6_ADDRSTRLEN] = {0};
        int is6 = (rr->family == 10 /* AF_INET6 */);
        if (!is6) { struct in_addr a; a.s_addr = rr->daddr; inet_ntop(AF_INET, &a, peer, sizeof peer); }
        else      { snprintf(peer, sizeof peer, "(ipv6 not carried)"); }
        uint64_t start_unix = (uint64_t)((int64_t)rr->start_ktime + off);

        otlp_generic_span_t s; memset(&s, 0, sizeof s);
        otlp_span_new_root(&s, &seed);
        s.start_unix_ns = start_unix; s.end_unix_ns = start_unix + rr->duration_ns;
        s.kind = 3 /* CLIENT — we observe the caller (the Redis client) */;
        s.is_error = is_error;

        static char namebuf[32];
        snprintf(namebuf, sizeof namebuf, SPNL_EGRESS_REDIS_SPAN_NAME_FMT, cmd[0] ? cmd : "REDIS");
        s.name = namebuf;

        otlp_kv_t attrs[13]; int n = 0;
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_DB_SYSTEM); snprintf(attrs[n].val,sizeof attrs[n].val,"redis"); n++;
        if (cmd[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_DB_OPERATION_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",cmd); n++; }
        if (cmd[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_DB_QUERY_TEXT);
                      if (key[0]) snprintf(attrs[n].val,sizeof attrs[n].val,"%s %s",cmd,key);
                      else        snprintf(attrs[n].val,sizeof attrs[n].val,"%s",cmd); n++; }   /* command + key only, no values */
        if (is_error) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_ERROR_TYPE); snprintf(attrs[n].val,sizeof attrs[n].val,"redis_error"); n++; }
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_NETWORK_PEER_ADDRESS); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",peer); n++;
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_NETWORK_PEER_PORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"%u",rr->dport); n++;
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_NETWORK_TRANSPORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"tcp"); n++;
        if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_REDIS_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
        /* Kubernetes attribution only: the peer enricher is for connections, so this
         * reuses the HTTP signal. */
        otlp_enrich_ctx_t ec = { OTLP_SIGNAL_HTTP, rr->cgid, peer };
        n += otlp_enrich_run(&ec, attrs + n, 13 - n);
        s.attrs = attrs; s.nattrs = n;

        otlp_batch_add(&g_span_batch, &s);
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    spnl_channel_out(map_name, (long)sent);
    fprintf(stderr, "[otlp] pushed %d redis spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- off-CPU-during-request span: why the request was slow ---- */
/* offcpu_event: hdr + {pid, comm[16], pad, duration_ns, offcpu_ns, wait_stack(s32), req[64],
 * resp[16]}. The span is an HTTP span (method/path/status/duration) PLUS spnl.offcpu_ns /
 * spnl.oncpu_ns / wait.kind. wait.kind is classified in userspace by scanning the captured
 * kernel wait-stack frames against /proc/kallsyms (io/lock/sleep/net/other). */
/* The one channel where the append-only *reading* rule is load-bearing: the tree
 * appended start_ktime and hdr_ext, and a producer built before that writes a shorter
 * record which must still be accepted with the two new fields zero. That rule is now
 * declared (cc_rec_offcpu.required_through = "cgid") and the generated unpack applies
 * it, instead of two hand-written `if (size >= H + 144)` guards. */
/* The off-CPU channel's request and response buffers hold the same first bytes off
 * the wire as the HTTP channel's, and are read the same way, so this channel calls
 * the HTTP channel's declared derivations rather than parsing them again. There
 * used to be a copy of that parsing here, and it had drifted: its method buffer was
 * narrower, and it located the path from the strlen of an already-truncated method,
 * which shifts once the method is long. The same request head could therefore yield
 * different values on an HTTP span and an off-CPU span.
 *
 * The derivations take their source width from the HTTP record, so reusing them
 * depends on both records declaring the same width. If that ever stops being true,
 * the build fails here: */
_Static_assert(sizeof(((const spnl_rec_offcpu_t *)0)->req)  == sizeof(((const spnl_rec_http_t *)0)->req),
               "offcpu.req is no longer the same width as http.req -- the shared HTTP derivation "
               "(spnl_http_method/_path) reads http's width and would over/under-read this record");
_Static_assert(sizeof(((const spnl_rec_offcpu_t *)0)->resp) == sizeof(((const spnl_rec_http_t *)0)->resp),
               "offcpu.resp is no longer the same width as http.resp -- see spnl_http_status()");

struct offcpu_collector { spnl_rec_offcpu_t *recs; size_t n; size_t cap; };

static int offcpu_rb_cb(void *ctx, void *data, size_t size) {
    struct offcpu_collector *c = (struct offcpu_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_offcpu_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* Look for a W3C traceparent header in the captured request bytes and copy its
 * value out. As everywhere else, the kernel does a bounded copy and userspace does
 * the parsing. Returns 1 when found, 0 otherwise. The search for "traceparent:" is
 * case-insensitive, and the first 55 characters of the value are copied. */
static int otlp_find_traceparent(const unsigned char *buf, size_t n, char *out, size_t outcap) {
    static const char *KEY = "traceparent:";
    size_t klen = strlen(KEY);
    for (size_t i = 0; i + klen <= n; i++) {
        int m = 1;
        for (size_t k = 0; k < klen; k++) {
            unsigned char ch = buf[i + k]; if (ch >= 'A' && ch <= 'Z') ch = (unsigned char)(ch - 'A' + 'a');
            if (ch != (unsigned char)KEY[k]) { m = 0; break; }
        }
        if (!m) continue;
        size_t j = i + klen;
        while (j < n && (buf[j] == ' ' || buf[j] == '\t')) j++;   /* OWS */
        size_t o = 0;
        while (j < n && o + 1 < outcap && buf[j] != '\r' && buf[j] != '\n' && buf[j] >= 0x20 && buf[j] < 0x7f)
            out[o++] = (char)buf[j++];
        out[o] = '\0';
        return o > 0;
    }
    return 0;
}

/* minimal self-contained kallsyms (addr-sorted) for classifying the wait stack. */
struct _oc_sym { uint64_t a; char n[56]; };
static struct _oc_sym *_oc_syms; static int _oc_nsyms; static int _oc_loaded;
static int _oc_symcmp(const void *x, const void *y) {
    uint64_t ax = ((const struct _oc_sym *)x)->a, ay = ((const struct _oc_sym *)y)->a;
    return ax < ay ? -1 : ax > ay ? 1 : 0;
}
static void _oc_load_kallsyms(void) {
    if (_oc_loaded) return; _oc_loaded = 1;
    FILE *f = fopen("/proc/kallsyms", "r"); if (!f) return;
    int cap = 200000; _oc_syms = malloc((size_t)cap * sizeof(struct _oc_sym));
    if (!_oc_syms) { fclose(f); return; }
    char line[256];
    while (fgets(line, sizeof line, f) && _oc_nsyms < cap) {
        uint64_t a; char t, nm[128];
        if (sscanf(line, "%llx %c %127s", (unsigned long long *)&a, &t, nm) == 3) {
            _oc_syms[_oc_nsyms].a = a; strncpy(_oc_syms[_oc_nsyms].n, nm, 55);
            _oc_syms[_oc_nsyms].n[55] = 0; _oc_nsyms++;
        }
    }
    fclose(f);
    qsort(_oc_syms, _oc_nsyms, sizeof(struct _oc_sym), _oc_symcmp);
}
static const char *_oc_sym_of(uint64_t pc) {
    int lo = 0, hi = _oc_nsyms - 1, r = -1;
    while (lo <= hi) { int m = (lo + hi) / 2; if (_oc_syms[m].a <= pc) { r = m; lo = m + 1; } else hi = m - 1; }
    return r >= 0 ? _oc_syms[r].n : "?";
}
/* classify a wait by scanning the stack frames for a known blocking signature. */
static const char *_oc_wait_kind(struct bpf_object *obj, const char *stacks_map, int32_t sid) {
    if (sid < 0) return "none";
    /* the classification needs the stack map of the object this record was
     * drained from. Without one (a caller that has no object -- e.g. the host
     * oracle in tests/runtime/record_span_parity_test.c) the honest answer is
     * "unknown", the same word an unreadable map already produced. */
    if (!obj || !stacks_map || !stacks_map[0]) return "unknown";
    _oc_load_kallsyms();
    if (!_oc_nsyms) return "unknown";
    int mfd = bpf_object__find_map_fd_by_name(obj, stacks_map);
    if (mfd < 0) return "unknown";
    static uint64_t pcs[127];
    if (bpf_map_lookup_elem(mfd, &sid, pcs) != 0) return "unknown";
    for (int i = 0; i < 127 && pcs[i]; i++) {
        const char *s = _oc_sym_of(pcs[i]);
        if (strstr(s, "io_schedule") || strstr(s, "folio_wait") || strstr(s, "wait_on_page") ||
            strstr(s, "jbd2") || strstr(s, "blk_") || strstr(s, "submit_bio")) return "io";
        if (strstr(s, "futex")) return "lock";
        if (strstr(s, "nanosleep") || strstr(s, "hrtimer_") || strstr(s, "schedule_timeout") ||
            strstr(s, "do_sys_poll") || strstr(s, "do_epoll")) return "sleep";
        if (strstr(s, "sk_wait") || strstr(s, "tcp_recv") || strstr(s, "inet_")) return "net";
    }
    return "other";
}

/* --- the off-CPU record's three own derivations ---------------------------
 *
 * Not static: the generated accessors behind `ev.offcpu_ns`, `ev.oncpu_ns` and
 * `ev.wait_kind` call these, and so does the span builder. Method, path and status
 * are shared with the HTTP channel, so these three are all that is specific here.
 *
 * This channel was the last to gain typed consumers because none of its three
 * attributes can be published as a field:
 *   - spnl.offcpu_ns  is min(offcpu_ns, duration_ns), a clamped value
 *   - spnl.oncpu_ns   is the difference, a number no field holds
 *   - spnl.wait.kind  classifies a captured stack against kallsyms, which is state
 *                     outside the record entirely
 * Exposing the raw fields instead would create three separate ways for what Ruby
 * sees to disagree with what is sent. */

/* Which object and which stack map wait.kind should resolve against. The record
 * carries only a stack *id*, and resolving it needs the object the record was
 * drained from. Every other derivation is a function of the record alone, so rather
 * than inventing a fifth derivation form for this, both entry points simply
 * remember the pair on the way in:
 *   - each already receives the stack map name as an argument
 *   - an accessor is only ever called straight after that drain, since a handle is
 *     an index into the most recent one
 * so what is remembered always belongs to the object that carried the record. When
 * nothing has been remembered -- a host-side test, say -- the answer is "unknown",
 * which is the same word an unreadable stack map produces. */
static struct bpf_object *g_offcpu_obj;
static char               g_offcpu_stacks[64];

static void offcpu_set_stack_ctx(struct bpf_object *obj, const char *stacks_map) {
    g_offcpu_obj = obj;
    snprintf(g_offcpu_stacks, sizeof g_offcpu_stacks, "%s", stacks_map ? stacks_map : "");
}

/* `ev.offcpu_ns` is the spnl.offcpu_ns attribute itself. The clamp is not
 * decoration: the off-CPU total is accumulated by the scheduler tracepoint while
 * the window is measured by the recv/send pair, and two hooks measuring separately
 * can produce a total that exceeds the window. Spans have always reported the
 * clamped value, so Ruby gets the clamped value too. Handing over the raw one would
 * agree on ordinary records and differ only on anomalous ones -- lying exactly
 * where a filter matters most. */
long spnl_offcpu_offcpu_ns(const spnl_rec_offcpu_t *r) {
    if (!r) return 0;
    return (long)(r->offcpu_ns > r->duration_ns ? r->duration_ns : r->offcpu_ns);
}

/* `ev.oncpu_ns` is the spnl.oncpu_ns attribute: not a field but a difference, the
 * window minus the wait. That makes ev.oncpu_ns + ev.offcpu_ns == ev.duration_ns
 * true by construction. */
long spnl_offcpu_oncpu_ns(const spnl_rec_offcpu_t *r) {
    if (!r) return 0;
    return (long)(r->duration_ns - (uint64_t)spnl_offcpu_offcpu_ns(r));
}

/* `ev.wait_kind` is the spnl.wait.kind attribute itself, from the same classifier. */
void spnl_offcpu_wait_kind(const spnl_rec_offcpu_t *r, char *out, int cap) {
    if (!out || cap <= 0) return;
    out[0] = '\0';
    if (!r) return;
    snprintf(out, (size_t)cap, "%s",
             _oc_wait_kind(g_offcpu_obj, g_offcpu_stacks[0] ? g_offcpu_stacks : NULL, r->wait_stack));
}

/* Build the request-window span its egress declaration describes from one record;
 * the shared builder for both forms, as elsewhere. attrs holds 13 entries.
 *
 * Two things differ from the other channels, and both follow from what this record
 * is:
 *   (1) The span starts at "now minus duration" rather than at a timestamp in the
 *       record. What this record carries is an elapsed time -- the length of the
 *       window -- and that anchor is what the one-call push has always used. (A
 *       start_ktime field was added later, but only the request-tree path reads
 *       it.) So this takes the current unix time rather than a ktime offset.
 *   (2) One record can become *two* spans: the window, and a child for the off-CPU
 *       wait. What is built here is the parent. Nesting the child is part of how
 *       the one-call push renders the record, as its declaration notes.
 *       The explicit `to_span(ev)` returns just the parent. The wait's numbers are
 *       on the parent too, so a consumer reads the same values either way; only the
 *       shape of the waterfall differs. */
static int offcpu_fill_span(const spnl_rec_offcpu_t *rr, uint64_t now_unix, uint64_t *seed,
                            otlp_generic_span_t *s, otlp_kv_t *attrs,
                            char *namebuf, size_t namecap) {
    /* Receive each derivation's output in a buffer of that derivation's own
     * declared cap. Method and path share the HTTP channel's functions, and their
     * caps agree -- which the assertions at the top of this file enforce. */
    char method[SPNL_REC_DERIVED_OFFCPU_METHOD_CAP] = {0}, path[SPNL_REC_DERIVED_OFFCPU_PATH_CAP] = {0};
    char wk[SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP] = {0};
    spnl_http_method(rr->req, method, (int)sizeof method);
    spnl_http_path(rr->req, path, (int)sizeof path);
    int status = (int)spnl_http_status(rr->resp);
    uint64_t offcpu = (uint64_t)spnl_offcpu_offcpu_ns(rr);   /* ev.offcpu_ns, same function */
    uint64_t oncpu  = (uint64_t)spnl_offcpu_oncpu_ns(rr);    /* ev.oncpu_ns,  same function */
    spnl_offcpu_wait_kind(rr, wk, (int)sizeof wk);           /* ev.wait_kind, same function */
    uint64_t start_unix = now_unix - rr->duration_ns;

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* the one place trace contexts are minted */
    s->start_unix_ns = start_unix; s->end_unix_ns = start_unix + rr->duration_ns;
    s->kind = 2 /* SERVER — we observe the request handler */;
    s->is_error = (status >= 500);

    snprintf(namebuf, namecap, SPNL_EGRESS_OFFCPU_SPAN_NAME_FMT, method[0] ? method : "HTTP", path);
    s->name = namebuf;

    int n = 0;
    if (method[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_HTTP_REQUEST_METHOD); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",method); n++; }
    if (path[0])   { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_URL_PATH); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",path); n++; }
    if (status>0)  { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_HTTP_RESPONSE_STATUS_CODE); snprintf(attrs[n].val,sizeof attrs[n].val,"%d",status); n++; }
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_OFFCPU_NS); snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)offcpu); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_ONCPU_NS);  snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)oncpu); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_WAIT_KIND); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",wk); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_OFFCPU, rr->cgid, NULL };   /* Kubernetes only; peer is for connections */
    n += otlp_enrich_run(&ec, attrs + n, 13 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* The off-CPU records from the last drain, shared by both forms. */
static spnl_rec_offcpu_t g_rec_offcpu[OTLP_MAX_LOGS];
static int               g_rec_offcpu_n;

int spnl_otlp_offcpu_span_push_obj(struct bpf_object *obj, const char *map_name,
                                   const char *stacks_map, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct offcpu_collector coll = { g_rec_offcpu, 0, OTLP_MAX_LOGS };
    g_rec_offcpu_n = 0;
    offcpu_set_stack_ctx(obj, stacks_map);   /* the stack map wait.kind resolves against */
    if (otlp_drain(obj, map_name, offcpu_rb_cb, &coll) != 0) return -1;
    g_rec_offcpu_n = (int)coll.n;
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);

    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    /* duration/offcpu are elapsed spans of ktime; anchor start at "now - duration" in unix. */
    struct timespec tnow; clock_gettime(CLOCK_REALTIME, &tnow);
    uint64_t now_unix = (uint64_t)tnow.tv_sec * 1000000000ull + (uint64_t)tnow.tv_nsec;
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    /* `out` is counted in records, not spans: this is the one channel where a
     * single record can become two spans (the request window and the wait
     * nested inside it), and counting spans would make out exceed in and turn
     * the balance into nonsense. */
    int rec_out = 0;
    for (size_t i = 0; i < coll.n; i++) {
        spnl_rec_offcpu_t *rr = &coll.recs[i];
        /* Render one record as a two-span tree:
         *   parent  the request span (SERVER), lasting the whole recv-to-send window
         *   child   the off-CPU wait (INTERNAL), lasting offcpu_ns, nested inside it
         * They share a trace id, and the child's parent is the parent's span id. The
         * wait numbers stay on the parent as they always have, and the child exists
         * so the wait shows up as its own bar in a waterfall view.
         * One approximation: the record carries the *total* off-CPU time, not when
         * each wait happened, so the child is placed at the start of the window.
         * Children that come from other records do carry real timestamps. */
        otlp_generic_span_t parent;
        otlp_kv_t attrs[13];
        static char namebuf[96];
        if (!offcpu_fill_span(rr, now_unix, &seed, &parent, attrs, namebuf, sizeof namebuf)) continue;

        otlp_batch_add(&g_span_batch, &parent);   /* the whole tree goes into one batch */
        sent++;
        rec_out++;

        /* Emit the wait child only when there actually was one. A CPU-bound request
         * has no wait and so gets no child, which is an honest waterfall of pure
         * on-CPU time. The values come from the same derivations the parent used, so
         * parent and child cannot disagree. */
        uint64_t offcpu = (uint64_t)spnl_offcpu_offcpu_ns(rr);
        if (offcpu > 0) {
            char wk[SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP] = {0};
            spnl_offcpu_wait_kind(rr, wk, (int)sizeof wk);
            otlp_generic_span_t child; memset(&child, 0, sizeof child);
            otlp_span_new_child(&child, &parent, &seed);
            child.start_unix_ns = parent.start_unix_ns;    /* approximation: the start of the window */
            child.end_unix_ns   = parent.start_unix_ns + offcpu;
            child.kind = 1 /* INTERNAL */;
            static char cnamebuf[64];
            snprintf(cnamebuf, sizeof cnamebuf, "off-CPU wait (%s)", wk);
            child.name = cnamebuf;
            otlp_kv_t cattrs[3]; int cn = 0;
            snprintf(cattrs[cn].key,sizeof cattrs[cn].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_WAIT_KIND); snprintf(cattrs[cn].val,sizeof cattrs[cn].val,"%s",wk); cn++;
            snprintf(cattrs[cn].key,sizeof cattrs[cn].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_OFFCPU_NS); snprintf(cattrs[cn].val,sizeof cattrs[cn].val,"%llu",(unsigned long long)offcpu); cn++;
            child.attrs = cattrs; child.nattrs = cn;
            otlp_batch_add(&g_span_batch, &child);   /* buffer it; the batch flushes at the end of the cycle */
            sent++;
        }
    }
    otlp_batch_flush_final(&g_span_batch);
    spnl_channel_out(map_name, (long)rec_out);
    fprintf(stderr, "[otlp] pushed %d offcpu spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- typed record consumer: `on_emit :offcpu do |ev|` ---- */
const spnl_rec_offcpu_t *spnl_rec_offcpu_at(int i) {
    return (i >= 0 && i < g_rec_offcpu_n) ? &g_rec_offcpu[i] : NULL;
}

/* Unlike the other drains this one also takes a stack map name, so that
 * `ev.wait_kind` can remember it alongside the object this drain came from. */
int spnl_rec_offcpu_drain_obj(struct bpf_object *obj, const char *map_name,
                              const char *stacks_map, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct offcpu_collector coll = { g_rec_offcpu, 0, OTLP_MAX_LOGS };
    g_rec_offcpu_n = 0;
    offcpu_set_stack_ctx(obj, stacks_map);
    if (otlp_drain_ms(obj, map_name, offcpu_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    g_rec_offcpu_n = (int)coll.n;
    /* Typed consumers drain here, and they are as entitled to the
       diagnosis as any other path: a consumer that never sees a
       record cannot filter one either. */
    spnl_channel_seen(map_name);
    spnl_channel_in(map_name, (long)coll.n);
    return g_rec_offcpu_n;
}

/* `to_span(ev)` and `offcpu_span(ev)`: one record becomes its declared window span;
 * 0 means the handle was not valid. Where the one-call form takes "now" once per
 * drain cycle, this takes it per record; the difference is the sub-millisecond
 * elapsed within a cycle, and the anchor means the same thing. The off-CPU wait
 * child is part of how the one-call form renders a record: the explicit form returns
 * one span per record, and the wait's numbers are on it. */
int spnl_rec_offcpu_to_span(int i) {
    const spnl_rec_offcpu_t *r = spnl_rec_offcpu_at(i);
    if (!r) return 0;
    if (!g_ev_seed) g_ev_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    struct timespec tnow; clock_gettime(CLOCK_REALTIME, &tnow);
    uint64_t now_unix = (uint64_t)tnow.tv_sec * 1000000000ull + (uint64_t)tnow.tv_nsec;
    int slot = g_ev_slot;
    g_ev_slot = (g_ev_slot + 1) % OTLP_EV_SPAN_SLOTS;
    if (!offcpu_fill_span(r, now_unix, &g_ev_seed, &g_ev_span[slot],
                          g_ev_attrs[slot], g_ev_name[slot], sizeof g_ev_name[slot]))
        return 0;
    return slot + 1;
}

/* ---- multi-source request tree: a request window and its cross-record children ---- */
/* Drain the off-CPU window records as parents and the DNS and connection records as
 * children, and assemble a tree per request: the parent is the request span covering
 * the recv-to-send window, and the children are the off-CPU wait from the same
 * record plus any DNS resolve or TCP connect that shares its thread group and falls
 * inside its window. The whole tree goes out in one POST.
 *
 * A child can be drained in a cycle that runs *before* its parent's window closes,
 * so children that match nothing are carried forward in a pending buffer and nested
 * when their parent turns up in a later cycle. Only a child whose parent never
 * arrives within the time-to-live (30 seconds by default, SPNL_TREE_CHILD_TTL_MS)
 * falls back to a standalone span -- safer than inventing a parent, and nothing is
 * lost either way. Parents are emitted as soon as their window closes, since their
 * children are already pending.
 * This assumes a synchronous handler where one thread serves one request. The DNS
 * and connection maps are optional; a probe without one simply contributes no
 * children from that source. */

/* Turn a DNS or connection record into a span; the caller has already assigned its
 * ids as a root or a child. Returns 1 when the record parsed, 0 otherwise. */
static int otlp_tree_fill_dns(const spnl_rec_dns_t *d, int64_t off, int as_child,
                              otlp_generic_span_t *s, otlp_kv_t *a, char *nb, size_t nbcap) {
    char host[SPNL_REC_DERIVED_DNS_QNAME_CAP]; spnl_dns_qname(d->raw, host, sizeof host);   /* the same width the accessor uses: qname's declared cap */
    if (!host[0]) return 0;
    uint64_t ds = (uint64_t)((int64_t)d->hdr.timestamp + off);
    s->start_unix_ns = ds; s->end_unix_ns = ds + d->duration_ns; s->kind = as_child ? 3 /*CLIENT*/ : 0;
    snprintf(nb, nbcap, SPNL_EGRESS_DNS_SPAN_NAME_FMT, host); s->name = nb;
    /* A second consumer of the same record. The attribute keys come from the same
     * declaration; the only difference when nested is the span kind, and the
     * declaration says so. */
    int an = 0;
    snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_DNS_ATTR_DNS_QUESTION_NAME); snprintf(a[an].val,sizeof a[an].val,"%s",host); an++;
    if (d->duration_ns) { snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_DNS_ATTR_SPNL_DNS_LATENCY_NS); snprintf(a[an].val,sizeof a[an].val,"%llu",(unsigned long long)d->duration_ns); an++; }
    if (d->comm[0]) { snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_DNS_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(a[an].val,sizeof a[an].val,"%s",d->comm); an++; }
    s->attrs = a; s->nattrs = an;
    return 1;
}
static int otlp_tree_fill_conn(const spnl_rec_conn_t *co, int64_t off, int as_child,
                               otlp_generic_span_t *s, otlp_kv_t *a, char *nb, size_t nbcap) {
    char peer[INET6_ADDRSTRLEN] = {0};
    conn_peer_addr(co, peer, sizeof peer);   /* the v4/v6 choice lives in one place, the same one ev.peer uses */
    uint64_t cs = (uint64_t)((int64_t)co->hdr.timestamp + off);
    s->start_unix_ns = cs; s->end_unix_ns = cs; s->kind = as_child ? 3 /*CLIENT*/ : 0;
    snprintf(nb, nbcap, SPNL_EGRESS_CONN_SPAN_NAME_FMT, peer, co->dport); s->name = nb;
    int an = 0;
    snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_ADDRESS); snprintf(a[an].val,sizeof a[an].val,"%s",peer); an++;
    snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_PORT); snprintf(a[an].val,sizeof a[an].val,"%u",co->dport); an++;
    /* The unit conversion lives in one function, whose output is what both
     * ev.srtt_us and the one-call span carry. Whether the attribute appears at all
     * is still decided from the raw field, so behaviour here is unchanged. */
    if (co->srtt_us > 0) { snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_NET_PEER_SRTT_US); snprintf(a[an].val,sizeof a[an].val,"%lld",(long long)spnl_conn_srtt_us(co)); an++; }
    if (co->comm[0]) { snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(a[an].val,sizeof a[an].val,"%s",co->comm); an++; }
    s->attrs = a; s->nattrs = an;
    return 1;
}

/* The pending-children buffer, which holds children across push cycles so a later
 * parent can adopt them. */
static spnl_rec_dns_t      g_pend_dns[OTLP_MAX_LOGS];  static size_t g_npend_dns;
static spnl_rec_conn_t     g_pend_conn[OTLP_MAX_LOGS]; static size_t g_npend_conn;

int spnl_otlp_request_tree_push_obj(struct bpf_object *obj,
                                    const char *offcpu_map, const char *dns_map,
                                    const char *conn_map, const char *stacks_map,
                                    const char *endpoint) {
    if (!obj || !offcpu_map || !endpoint) return -1;
    static spnl_rec_offcpu_t     praw[OTLP_MAX_LOGS];
    static spnl_rec_dns_t        draw[OTLP_MAX_LOGS];
    static spnl_rec_conn_t       craw[OTLP_MAX_LOGS];
    struct offcpu_collector pc = { praw, 0, OTLP_MAX_LOGS };
    struct dns_collector    dc = { draw, 0, OTLP_MAX_LOGS };
    struct conn_collector   cc = { craw, 0, OTLP_MAX_LOGS };
    offcpu_set_stack_ctx(obj, stacks_map);   /* the stack map wait.kind resolves against, here too */
    if (otlp_drain(obj, offcpu_map, offcpu_rb_cb, &pc) != 0) return -1;   /* the parent source is required */
    /* Children are optional: a missing map skips that source rather than failing. */
    if (dns_map  && bpf_object__find_map_by_name(obj, dns_map))  (void)otlp_drain(obj, dns_map,  dns_rb_cb,  &dc);
    if (conn_map && bpf_object__find_map_by_name(obj, conn_map)) (void)otlp_drain(obj, conn_map, conn_rb_cb, &cc);

    /* Carry the newly drained children forward; when the buffer is full the new
     * ones are dropped, which is rare. */
    for (size_t j = 0; j < dc.n && g_npend_dns < OTLP_MAX_LOGS; j++)  g_pend_dns[g_npend_dns++]  = dc.recs[j];
    for (size_t j = 0; j < cc.n && g_npend_conn < OTLP_MAX_LOGS; j++) g_pend_conn[g_npend_conn++] = cc.recs[j];

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    struct timespec mono; clock_gettime(CLOCK_MONOTONIC, &mono);
    uint64_t now_mono = (uint64_t)mono.tv_sec*1000000000ull + (uint64_t)mono.tv_nsec;
    uint64_t ttl_ns = 30000ull * 1000000ull;   /* 30 seconds by default */
    { const char *e = getenv("SPNL_TREE_CHILD_TTL_MS"); if (e && e[0]) { long v = atol(e); if (v > 0) ttl_ns = (uint64_t)v * 1000000ull; } }
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");

    static char dns_used[OTLP_MAX_LOGS];
    static char conn_used[OTLP_MAX_LOGS];
    memset(dns_used, 0, g_npend_dns); memset(conn_used, 0, g_npend_conn);
    int nspans = 0, nchild = 0, nfallback = 0;

    for (size_t i = 0; i < pc.n; i++) {
        spnl_rec_offcpu_t *rr = &pc.recs[i];
        /* As in the push path above, this shares the HTTP channel's declared
         * derivations, so the request-tree parent reads the same method, path and
         * status out of the same request head. */
        char method[SPNL_REC_DERIVED_OFFCPU_METHOD_CAP] = {0}, path[SPNL_REC_DERIVED_OFFCPU_PATH_CAP] = {0};
        spnl_http_method(rr->req, method, (int)sizeof method);
        spnl_http_path(rr->req, path, (int)sizeof path);
        int status = (int)spnl_http_status(rr->resp);
        /* The clamp and the difference are declared derivations too, so this second
         * consumer of the record reports exactly what the first one does. */
        uint64_t offcpu = (uint64_t)spnl_offcpu_offcpu_ns(rr);
        uint64_t oncpu  = (uint64_t)spnl_offcpu_oncpu_ns(rr);
        /* The exact window start. An older record without one falls back to
         * now minus duration. */
        uint64_t start_unix;
        if (rr->start_ktime) start_unix = (uint64_t)((int64_t)rr->start_ktime + off);
        else { struct timespec tn; clock_gettime(CLOCK_REALTIME,&tn);
               start_unix = (uint64_t)tn.tv_sec*1000000000ull + (uint64_t)tn.tv_nsec - rr->duration_ns; }

        otlp_generic_span_t parent; memset(&parent, 0, sizeof parent);
        /* If the request carried a traceparent, adopt its trace id and nest our
         * SERVER span underneath the caller's, making this part of their distributed
         * trace; otherwise mint a new one. Nothing is injected into outbound
         * requests: this observes, it does not propagate. */
        char tp[64];
        if (otlp_find_traceparent(rr->hdr_ext, sizeof rr->hdr_ext, tp, sizeof tp))
            otlp_span_root_from_traceparent(&parent, tp, &seed);
        else
            otlp_span_new_root(&parent, &seed);
        parent.start_unix_ns = start_unix; parent.end_unix_ns = start_unix + rr->duration_ns;
        parent.kind = 2 /* SERVER */; parent.is_error = (status >= 500);
        static char pname[96];
        snprintf(pname, sizeof pname, SPNL_EGRESS_OFFCPU_SPAN_NAME_FMT, method[0] ? method : "HTTP", path);
        parent.name = pname;
        otlp_kv_t pattrs[13]; int n = 0;
        if (method[0]) { snprintf(pattrs[n].key,sizeof pattrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_HTTP_REQUEST_METHOD); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%s",method); n++; }
        if (path[0])   { snprintf(pattrs[n].key,sizeof pattrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_URL_PATH); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%s",path); n++; }
        if (status>0)  { snprintf(pattrs[n].key,sizeof pattrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_HTTP_RESPONSE_STATUS_CODE); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%d",status); n++; }
        snprintf(pattrs[n].key,sizeof pattrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_ONCPU_NS); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%llu",(unsigned long long)oncpu); n++;
        if (rr->comm[0]) { snprintf(pattrs[n].key,sizeof pattrs[n].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%s",rr->comm); n++; }
        otlp_enrich_ctx_t ec = { OTLP_SIGNAL_OFFCPU, rr->cgid, NULL };   /* Kubernetes only; this is the request-tree parent */
        n += otlp_enrich_run(&ec, pattrs + n, 13 - n);
        parent.attrs = pattrs; parent.nattrs = n;
        otlp_batch_add(&g_span_batch, &parent); nspans++;

        /* child: the off-CPU wait, from this same record */
        if (offcpu > 0) {
            char wk[SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP] = {0};
            spnl_offcpu_wait_kind(rr, wk, (int)sizeof wk);   /* ev.wait_kind, same function */
            otlp_generic_span_t ch; memset(&ch, 0, sizeof ch);
            otlp_span_new_child(&ch, &parent, &seed);
            ch.start_unix_ns = start_unix; ch.end_unix_ns = start_unix + offcpu; ch.kind = 1 /* INTERNAL */;
            static char cn[64]; snprintf(cn, sizeof cn, "off-CPU wait (%s)", wk); ch.name = cn;
            otlp_kv_t ca[2]; int m = 0;
            snprintf(ca[m].key,sizeof ca[m].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_WAIT_KIND); snprintf(ca[m].val,sizeof ca[m].val,"%s",wk); m++;
            snprintf(ca[m].key,sizeof ca[m].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_OFFCPU_NS); snprintf(ca[m].val,sizeof ca[m].val,"%llu",(unsigned long long)offcpu); m++;
            ch.attrs = ca; ch.nattrs = m;
            otlp_batch_add(&g_span_batch, &ch); nspans++; nchild++;
        }
        /* children: pending DNS resolves inside the window, same thread group */
        for (size_t j = 0; j < g_npend_dns; j++) {
            if (dns_used[j]) continue;
            spnl_rec_dns_t *d = &g_pend_dns[j];
            if (!otlp_child_in_window(d->pid, d->hdr.timestamp, rr->pid, rr->start_ktime, rr->duration_ns)) continue;
            dns_used[j] = 1;
            otlp_generic_span_t ch; memset(&ch, 0, sizeof ch);
            otlp_span_new_child(&ch, &parent, &seed);
            static otlp_kv_t ca[3]; static char cn[160];
            if (otlp_tree_fill_dns(d, off, 1, &ch, ca, cn, sizeof cn)) { otlp_batch_add(&g_span_batch, &ch); nspans++; nchild++; }
        }
        /* children: pending TCP connects inside the window, same thread group */
        for (size_t j = 0; j < g_npend_conn; j++) {
            if (conn_used[j]) continue;
            spnl_rec_conn_t *co = &g_pend_conn[j];
            if (!otlp_child_in_window(co->pid, co->hdr.timestamp, rr->pid, rr->start_ktime, rr->duration_ns)) continue;
            conn_used[j] = 1;
            otlp_generic_span_t ch; memset(&ch, 0, sizeof ch);
            otlp_span_new_child(&ch, &parent, &seed);
            static otlp_kv_t cca[4]; static char ccn[160];
            if (otlp_tree_fill_conn(co, off, 1, &ch, cca, ccn, sizeof ccn)) { otlp_batch_add(&g_span_batch, &ch); nspans++; nchild++; }
        }
    }

    /* Sweep the pending buffer: drop what was matched; send what is unmatched and
     * past its time-to-live as a standalone span, so nothing is lost; and carry the
     * rest forward, since their parent may still be coming. */
    { size_t w = 0;
      for (size_t j = 0; j < g_npend_dns; j++) {
          if (dns_used[j]) continue;                                  /* matched -> drop */
          int expired = (now_mono >= g_pend_dns[j].hdr.timestamp) && (now_mono - g_pend_dns[j].hdr.timestamp > ttl_ns);
          if (expired) {
              otlp_generic_span_t s; memset(&s,0,sizeof s); otlp_span_new_root(&s,&seed);
              static otlp_kv_t a[3]; static char nb[160];
              if (otlp_tree_fill_dns(&g_pend_dns[j], off, 0, &s, a, nb, sizeof nb)) { otlp_batch_add(&g_span_batch, &s); nspans++; nfallback++; }
          } else {
              g_pend_dns[w++] = g_pend_dns[j];                        /* keep for next cycle */
          }
      }
      g_npend_dns = w;
    }
    { size_t w = 0;
      for (size_t j = 0; j < g_npend_conn; j++) {
          if (conn_used[j]) continue;
          int expired = (now_mono >= g_pend_conn[j].hdr.timestamp) && (now_mono - g_pend_conn[j].hdr.timestamp > ttl_ns);
          if (expired) {
              otlp_generic_span_t s; memset(&s,0,sizeof s); otlp_span_new_root(&s,&seed);
              static otlp_kv_t a[4]; static char nb[160];
              if (otlp_tree_fill_conn(&g_pend_conn[j], off, 0, &s, a, nb, sizeof nb)) { otlp_batch_add(&g_span_batch, &s); nspans++; nfallback++; }
          } else {
              g_pend_conn[w++] = g_pend_conn[j];
          }
      }
      g_npend_conn = w;
    }

    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d request-tree spans (%zu windows, %d nested, %d fallback, %zu pending, %d posts, last HTTP %d) -> %s\n",
            nspans, pc.n, nchild, nfallback, g_npend_dns + g_npend_conn, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return nspans > 0 ? g_span_batch.last_status : 0;
}



