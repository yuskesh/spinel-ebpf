/*
 * otlp_agent.c — `--instrument` agent の OTLP push 実装
 * 詳細は otlp_agent.h を参照。
 */
#include "otlp_agent.h"
#include "otlp_metrics.h"
#include "otlp_traces.h"
#include "otlp_logs.h"
#include "otlp_http.h"
#include "otlp_grpc.h"   /* otlp_transport_send (http/grpc routing) + gRPC service paths */
#include "otlp_json.h"   /* otlp_want_json / otlp_endpoint_is_grpc / otlp_json_*_build */
#include "otlp_enrich.h" /* E313: 層 2 enricher レジストリ (k8s / peer を registry 経由に) */
#include "spnl_runtime.h"   /* spnl_log2_hist_count_keyed_obj / spnl_hist_buckets_keyed_obj, __u64 */
#include "spnl/types.h"     /* struct spnl_event_hdr (record の型付き decode、E263 G2) */
/* S2/E369: ringbuf record の userspace mirror。kernel の producer struct と同じ宣言
 * (src/codegen_c/record_schema.h) から生成された derived artifact — offset は計算済で、
 * ここに `data + H + 88` のような手書き定数はもう無い (再生成は make -C src/codegen_c mirror)。
 *
 * S4/E371: SPNL_REC_CONSUME_IMPL を定義して include すると、生成ヘッダは型付き consumer の
 * accessor (`spnl_rec_dns_qname` 等 = Ruby の `ev.qname` の実体) も**この TU に**定義する。
 * その代わり本 TU が spnl_rec_<id>_at() と宣言された derivation (spnl_dns_qname) を持つ責任を
 * 負う (どちらも下方で定義。欠けたら link error = silent な誤値にならない)。 */
#define SPNL_REC_CONSUME_IMPL 1
#include "record_mirror_gen.h"

/* 宣言された derivation の出力は span 属性の値バッファにも入る。両者は別の層
 * (契約 = 表 / 送信器 = otlp_http.h) にあるので、「収まる」ことをここで機械検査する
 * — 収まらなければ属性側だけが黙って切り詰められ、E377 が消した「同じ関数・違う幅」が
 * 別の姿で戻ってくる。cap を広げるときに落ちるのが正しい (器を先に広げよ)。 */
#define SPNL_ATTR_VAL_CAP (sizeof(((otlp_kv_t *)0)->val))
_Static_assert(SPNL_REC_DERIVED_DNS_QNAME_CAP      <= SPNL_ATTR_VAL_CAP, "ev.qname does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_CONN_PEER_CAP      <= SPNL_ATTR_VAL_CAP, "ev.peer does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_CONN_DIRECTION_CAP <= SPNL_ATTR_VAL_CAP, "ev.direction does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_HTTP_METHOD_CAP    <= SPNL_ATTR_VAL_CAP, "ev.method does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_HTTP_PATH_CAP      <= SPNL_ATTR_VAL_CAP, "ev.path does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_METHOD_CAP  <= SPNL_ATTR_VAL_CAP, "offcpu ev.method does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_PATH_CAP    <= SPNL_ATTR_VAL_CAP, "offcpu ev.path does not fit in an attribute value");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP <= SPNL_ATTR_VAL_CAP, "ev.wait_kind does not fit in an attribute value");
/* offcpu と http は method/path について**同じ derivation**を共有する。両 channel が
 * それぞれ自分の bound を宣言するのは正しい (cap はその derivation の上限であって共有定数ではない、
 * E378) が、共有された関数に 2 つの違う幅が渡ると E377 の「同じ関数・違う幅」がそのまま戻る。
 * 源のフィールド幅が同じである限り 2 つの宣言は同じ数でなければならない — それをここで固定する。 */
_Static_assert(SPNL_REC_DERIVED_OFFCPU_METHOD_CAP == SPNL_REC_DERIVED_HTTP_METHOD_CAP,
               "offcpu and http declare different caps for the shared derivation spnl_http_method()");
_Static_assert(SPNL_REC_DERIVED_OFFCPU_PATH_CAP == SPNL_REC_DERIVED_HTTP_PATH_CAP,
               "offcpu and http declare different caps for the shared derivation spnl_http_path()");

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>         /* getenv (E293 audit span service.name) */
#include <string.h>
#include <time.h>
#include <unistd.h>         /* getpid (id seed) */
#include <arpa/inet.h>      /* inet_ntop (E294 network.peer.address) */
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

    /* static: メソッド多数でも stack を食わない (各 otlp_method_metric_t は buckets[64] で ~520B) */
    static otlp_method_metric_t mm[OTLP_MAX_METHODS];
    size_t n = 0;
    for (int i = 0; i < g_nmethods; i++) {
        unsigned long long key = (unsigned long long)g_methods[i].idx;
        __u64 count = 0;
        /* runtime は __u64 (unsigned long long)、otlp_method_metric_t.buckets は uint64_t。
         * Linux では別型 (long long vs long) なので temp で受けて memcpy (alias 安全)。 */
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

/* ---- 共通 drain / 時刻 (P003 R1, E263 G2) ---- */

/* emit 系 ringbuf を全 drain (records は呼出前に buffer 済)。0/-1。
 * poll_ms は 1 回の poll 待ち時間 (0 = 非ブロッキング)。S4/E371 の typed consumer が
 * Ruby から待ち時間を渡せるように分離しただけで、既存経路は従来どおり 100ms。 */
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

/* ktime(monotonic) -> unix nano の加算オフセット (= realtime - monotonic) */
static int64_t otlp_ktime_to_unix_off(void) {
    struct timespec rt, mono;
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    return ((int64_t)rt.tv_sec * 1000000000LL + rt.tv_nsec)
         - ((int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec);
}

/* ---- E304/E310/E313: span 属性の enrich は層 2 enricher レジストリ (otlp_enrich) に集約 ---- */
/* 各 span push 経路は record から必要な入力 (cgid / peer address / signal 種別) を
 * otlp_enrich_ctx_t に詰めて otlp_enrich_run() を 1 回呼ぶ。登録済み enricher
 * (k8s=cgroup_id->k8s.* / peer=network.peer.address->peer.*) が signal_mask で判定され
 * 順に適用される (k8s は全経路、peer は conn のみ)。適用条件を満たさなければ hard no-op
 * (span byte は E304/E310 導入前と同一)。詳細・将来の enricher 追加は otlp_enrich.h。 */

/* ---- E308: span バッチ化 (「1 record = 1 POST」を潰す) ---- */
/* 各 span-push 経路 (dns/conn/l7/http/offcpu/audit) はこれまで record ごとに span を組んで
 * 即 POST していた (高頻度イベントで小 POST が大量に出る)。ここで span を deep-copy して積み、
 * (a) batch_max 件たまったら、または (b) drain サイクルの最後 (各 push 関数末尾) で 1 POST に
 * まとめて送る funnel を用意する。全経路が otlp_generic_span_t を組むので 1 ヘルパで一斉に効く。
 *
 * 混在可否: resource 属性 (service.*) は全 span 共通、k8s.* 等は **span 属性** なので
 * 別 pod の span を同じ ResourceSpans に混ぜてよい (otlp_traces_generic_build_multi が
 * 1 ResourceSpans/ScopeSpans に repeated Span を並べる)。
 *
 * 後方互換: env SPNL_OTLP_BATCH_MAX=1 で 1 span=1 POST に戻る (body は multi(n=1)=単一 build と
 * byte 一致)。既定はバッチ有効 (64)。deep-copy が要るのは otlp_generic_span_t が name/attrs を
 * ポインタで持ち、各 push ループが同じ static/stack バッファを使い回すため。 */
#define OTLP_BATCH_HARD_MAX 128   /* 固定ストレージ上限 (env はここまで) */
#define OTLP_BATCH_ATTR_CAP 20    /* 1 span の最大属性数 (E310 conn: base6+comm+k8s源6+peer2=15) */
#define OTLP_BATCH_NAME_CAP 320   /* span 名の最大長 (実使用の最大は audit の 300) */

typedef struct {
    otlp_generic_span_t spans[OTLP_BATCH_HARD_MAX];
    char      names[OTLP_BATCH_HARD_MAX][OTLP_BATCH_NAME_CAP];
    otlp_kv_t attrs[OTLP_BATCH_HARD_MAX][OTLP_BATCH_ATTR_CAP];
    int  n;            /* バッファ済 span 数 */
    int  max;          /* flush 閾値 ([1, HARD_MAX]) */
    int  posts;        /* flush 回数 (= POST 数、計測用) */
    int  last_status;  /* 最終 flush の HTTP status */
    const char *endpoint;
    const char *svc;
    const char *ver;
    const char *scope;
} otlp_span_batch_t;

/* single-threaded runtime + push 関数は逐次呼出なので 1 個を全経路で共有 (~1.4MB BSS)。 */
static otlp_span_batch_t g_span_batch;

static int otlp_batch_env_max(void) {
    const char *e = getenv("SPNL_OTLP_BATCH_MAX");
    int m = 64;   /* 既定: バッチ有効 */
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

/* 積んだ span を 1 リクエストにまとめて送る。送ったら HTTP status、空なら 0、失敗 -1。 */
static int otlp_batch_flush(otlp_span_batch_t *b) {
    if (b->n <= 0) return 0;
    static uint8_t buf[1 << 20];   /* HARD_MAX span 分を格納 (1MB static) */
    long blen = otlp_traces_generic_build_multi(buf, sizeof buf, b->svc, b->ver, b->scope,
                                                b->spans, (size_t)b->n);
    int had = b->n; b->n = 0;   /* 成否に関わらずバッファはクリア (取りこぼしより二重送出回避) */
    if (blen < 0) { fprintf(stderr, "[otlp] batch encode failed (n=%d)\n", had); return -1; }
    int status = 0; char err[256] = {0};
    int rc = otlp_transport_send(b->endpoint, "/v1/traces", OTLP_GRPC_PATH_TRACES,
                                 "application/x-protobuf", buf, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] batch send error: %s\n", err); return -1; }
    b->posts++; b->last_status = status;
    return status;
}

/* span を batch に deep-copy して積む (満杯なら先に flush)。積めたら 1、送信失敗でも 1
 * (span は積まれる)、encode/copy 不能で -1。name/attrs はバッファ所有の複製を指す。 */
static int otlp_batch_add(otlp_span_batch_t *b, const otlp_generic_span_t *s) {
    if (b->n >= b->max) otlp_batch_flush(b);   /* 満杯 flush (失敗しても次を積む) */
    if (b->n >= OTLP_BATCH_HARD_MAX) return -1;
    int i = b->n;
    otlp_generic_span_t *d = &b->spans[i];
    memcpy(d, s, sizeof *d);
    snprintf(b->names[i], OTLP_BATCH_NAME_CAP, "%s", s->name ? s->name : "");
    d->name = b->names[i];
    int na = s->nattrs; if (na < 0) na = 0; if (na > OTLP_BATCH_ATTR_CAP) na = OTLP_BATCH_ATTR_CAP;
    for (int k = 0; k < na; k++) b->attrs[i][k] = s->attrs[k];   /* struct copy (key/val 配列ごと) */
    d->attrs = b->attrs[i]; d->nattrs = na;
    b->n++;
    (void)spnl_oneshot_add(1);   /* E323: 1 span = 1 event (exit は末尾の final flush で) */
    return 1;
}

/* 各 drain サイクル末尾の flush。tail batch を送出したあと SPNL_MAX_EVENTS を確認し、
 * 積算 span 数が K に達していれば clean exit (tail は flush 済 = 取りこぼしゼロ)。
 * K 到達判定はバッチ境界なので overshoot は「最後の 1 サイクルで積んだ span 数」に有界。 */
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
    const uint8_t *pl = (const uint8_t *)data + H;  /* payload (hdr の直後) */
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
    if (spnl_oneshot_add((long)coll.n)) spnl_oneshot_exit();   /* E323: 1 event = 1 drained record */
    return status;
}

/* ---- logs: emit ringbuf を drain -> LogRecord -> OTLP logs POST ---- */

#define OTLP_MAX_LOGS 8192

struct log_rec_raw { uint64_t ktime; int64_t ival; char sval[256]; };
struct log_collector { struct log_rec_raw *recs; size_t n; size_t cap; int is_str; };

/* emit record: spnl_event_hdr + (__s64 value | char str[256])。timestamp は hdr から。 */
static int log_rb_cb(void *ctx, void *data, size_t size) {
    struct log_collector *c = (struct log_collector *)ctx;
    const size_t H = sizeof(struct spnl_event_hdr);
    if (size < H || c->n >= c->cap) return 0;
    const struct spnl_event_hdr *hdr = (const struct spnl_event_hdr *)data;
    const uint8_t *pl = (const uint8_t *)data + H;  /* payload (hdr の直後) */
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
    if (spnl_oneshot_add((long)coll.n)) spnl_oneshot_exit();   /* E323: 1 event = 1 log record */
    return status;
}

/* ---- E293: live 監査 span (str ringbuf の [file, comm, parent] 三つ組 -> 1 span) ---- */
/* str ringbuf に 1 file_open あたり 3 record を fixed order で emit する前提:
 *   emit_path(file)        -> file.path
 *   emit_comm              -> process.executable.name (semconv)
 *   emit_parent_path       -> process.parent.executable.path (独自 key)
 * hdr.timestamp (bpf_ktime_get_ns、monotonic) を unix nano に直して span 時刻にする
 * (E292 の 1970 = FFI :int 境界での ns 切り詰めを回避: 時刻は C 内で解決)。
 * 3 record は 1 BPF handler 実行内で連続 submit され、marker-comm filter + 単一プロセスの
 * probe なら interleave しない (§Edoc)。 */
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
        uint64_t t = (uint64_t)((int64_t)raw[i].ktime + off);   /* 実イベント時刻 */

        otlp_generic_span_t s;
        memset(&s, 0, sizeof s);
        audit_put_u64_be(s.trace_id,     audit_splitmix64(&seed));
        audit_put_u64_be(s.trace_id + 8, audit_splitmix64(&seed));
        audit_put_u64_be(s.span_id,      audit_splitmix64(&seed));
        s.has_parent = false;
        s.start_unix_ns = t;
        s.end_unix_ns = t;
        s.kind = 0; /* INTERNAL */
        s.is_error = false; /* observe (記録のみ)。deny 版は verdict=deny + is_error */

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

        otlp_batch_add(&g_span_batch, &s);   /* E308: 積んで満杯 or 末尾で 1 POST にまとめる */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);   /* drain サイクル末尾: 残りを flush (取りこぼしゼロ) */
    fprintf(stderr, "[otlp] pushed %d audit spans (%zu str records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ================= S4/E371: typed consumer が共有する span スロット ==============
 *
 * 組み立て済 span の slot。Ruby は slot index+1 を handle として持つ (0 = span 無し)。
 * batch は add で deep-copy するので slot は send までしか生きていなくてよいが、
 * `send_otlp(to_span(a), ep)` を入れ子で複数書いても壊れないよう小さなリングにする。
 *
 * **全 typed channel の to_span が共有する**ので、最も広い channel の属性集合が
 * 入る大きさが要る (conn は 7 + 層 2 enricher で 20 まで積む)。各 channel の fill_span は
 * 従来どおり簡潔形と同じ本数で cap するので wire は不変 — ここは器の話だけ。
 * dns 節にあったものを E375 で全 channel の手前に移した (4 channel が使う共有物なので、
 * どれか 1 つの節の中にあるのは構造として嘘だった)。 */
#define OTLP_EV_SPAN_SLOTS 4
#define OTLP_EV_SPAN_ATTRS 20
static otlp_generic_span_t g_ev_span[OTLP_EV_SPAN_SLOTS];
static otlp_kv_t           g_ev_attrs[OTLP_EV_SPAN_SLOTS][OTLP_EV_SPAN_ATTRS];
static char                g_ev_name[OTLP_EV_SPAN_SLOTS][160];
static int                 g_ev_slot;
static uint64_t            g_ev_seed;
static int                 g_ev_batch_open;   /* この drain サイクルで batch を begin 済か */
static int                 g_ev_sent;         /* flush までに積んだ span 数 (報告用) */

/* ---- E294: network 監査 span (packed connect-event -> network span) ---- */
/* S5/E372: conn_event was the worst of the hand-written mirrors — a comment block
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

/* S4/E375: the conn record's two declared derivations (record_schema.h の
 * cc_rec_conn_derived)。**非 static** — 生成 accessor (`ev.peer` / `ev.direction`)
 * がここを呼び、span builder も同じ関数を呼ぶ。conn が E374 で据え置かれたのは、
 * どちらも**単一フィールドでは書けない** (宛先は family を見て daddr か daddr6_hi/lo、
 * direction は oldstate の読み替え) からで、E375 の 3 つ目の impl_form
 * "record_to_str" (record 丸ごとを受ける) がその形。
 *
 * v4/v6 の分岐を C 側に置くのが肝: Ruby は `ev.peer` と書くだけで AF_INET6 を知らない
 * (意味づけは層 2 が所有、ADR-017 D1)。 */

/* 宛先アドレス文字列。daddr は raw be32 (IPv4)。E306: family==AF_INET6 のとき
 * daddr6_hi/lo (daddr_v6[16] を u64 2 分割で読んだもの、network order) を in6_addr に
 * 戻して v6 表記に。**span の network.peer.address はこの関数の出力そのもの**。 */
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

/* `ev.peer` = "<address>:<port>" — アドレス部は network.peer.address と同じ関数の出力、
 * ポート部は network.peer.port。つまり span 名 (SPNL_EGRESS_CONN_SPAN_NAME_FMT =
 * "connect %s:%u") の主語と同じ文字列で、Ruby が見る値と wire が構造的に食い違えない。 */
void spnl_conn_peer(const spnl_rec_conn_t *r, char *out, int cap) {
    char addr[INET6_ADDRSTRLEN] = {0};
    if (!r || cap <= 0) { if (out && cap > 0) out[0] = '\0'; return; }
    conn_peer_addr(r, addr, sizeof addr);
    snprintf(out, (size_t)cap, "%s:%u", addr, r->dport);
}

/* `ev.direction` = span 属性 spnl.conn.direction そのもの。E306: ESTABLISHED 遷移の
 * 直前状態から。SYN_SENT(2)->ESTABLISHED = 自分から張った (active/client)、
 * SYN_RECV(3)->ESTABLISHED = 受けた (passive/server)。それ以外は other。 */
void spnl_conn_direction(const spnl_rec_conn_t *r, char *out, int cap) {
    const char *dir;
    if (!r || cap <= 0) { if (out && cap > 0) out[0] = '\0'; return; }
    dir = (r->oldstate == 2) ? "active" : (r->oldstate == 3) ? "passive" : "other";
    snprintf(out, (size_t)cap, "%s", dir);
}

/* `ev.srtt_us` = 属性 net.peer.srtt_us **そのもの** (E376、4 つ目の impl_form
 * record_to_int)。kernel の tcp_sock->srtt_us は 1/8 us スケールなので実 us は >>3。
 *
 * E375 まではフィールドを生のまま expose していて、**Ruby が見る値と span の値が
 * 食い違う唯一のプロパティ**だった (RTT 1ms なら span=1000 / Ruby=8000)。宣言の note に
 * 「DIVIDE BY 8」と書く対処は警告であって契約ではない — 単位を 1 関数に閉じ込め、
 * span builder (簡潔形/明示形の両方) と E312 の request tree が同じ出力を使うことで、
 * 「Ruby が見る値 = 出て行く値」を構造で保つ。スケールは意味なので層 2 の持ち物 (D1)。 */
long spnl_conn_srtt_us(const spnl_rec_conn_t *r) {
    return r ? (long)(r->srtt_us >> 3) : 0;
}

/* S4/E375: 1 record -> egress 宣言が記述する span (簡潔形 push と明示形 to_span の共通
 * builder — dns/l7/http と同じ構造)。attrs は 20 要素 (7 + 層 2 enricher の余地)、
 * namebuf は span 名。戻り 1 = span を組んだ (conn record は常に span になる)。 */
static int conn_fill_span(const spnl_rec_conn_t *rr, int64_t off, uint64_t *seed,
                          otlp_generic_span_t *s, otlp_kv_t *attrs,
                          char *namebuf, size_t namecap) {
    /* dir の幅も accessor と同じ (E377、上の qname と同じ理由 — direction は "active" /
     * "passive" / "other" しか返さないので実害は無いが、規則を例外なしにしておく)。
     * その「同じ幅」は direction 自身に宣言された cap (16 = "passive" + NUL に余裕)。 */
    char peer[INET6_ADDRSTRLEN] = {0}, dir[SPNL_REC_DERIVED_CONN_DIRECTION_CAP] = {0};
    int is6 = (rr->family == 10 /* AF_INET6 */);
    conn_peer_addr(rr, peer, sizeof peer);        /* = ev.peer のアドレス部 */
    spnl_conn_direction(rr, dir, (int)sizeof dir);/* = ev.direction (同じ関数) */
    uint64_t t = (uint64_t)((int64_t)rr->hdr.timestamp + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* E312: 単一 trace-context 生成 (共通プリミティブ) */
    s->start_unix_ns = t; s->end_unix_ns = t; s->kind = 0;

    snprintf(namebuf, namecap, SPNL_EGRESS_CONN_SPAN_NAME_FMT, peer, rr->dport);
    s->name = namebuf;

    int n = 0;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_ADDRESS); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",peer); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_PORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"%u",rr->dport); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_TRANSPORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"tcp"); n++;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_TYPE);         snprintf(attrs[n].val,sizeof attrs[n].val,"%s",is6?"ipv6":"ipv4"); n++;
    /* 実 us。semconv に RTT 属性が無いので独自 key。E376: スケーリングは derivation に
     * 集約したので、この値は `ev.srtt_us` と**同じ関数の出力** (= 同値)。 */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_NET_PEER_SRTT_US);     snprintf(attrs[n].val,sizeof attrs[n].val,"%lld",(long long)spnl_conn_srtt_us(rr)); n++;
    /* active/passive. semconv has no connection-direction key -> custom. */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_SPNL_CONN_DIRECTION);  snprintf(attrs[n].val,sizeof attrs[n].val,"%s",dir); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_CONN_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    /* 層 2 enricher レジストリ — CONN は k8s (発信元 pod + workload/service) と
     * peer (宛先 -> peer pod/service/external) の両方が適用対象。出力順は registry 順
     * (k8s -> peer) で E304+E310 の直呼びと byte 同一。 */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, rr->cgid, peer };
    n += otlp_enrich_run(&ec, attrs + n, 20 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* 直近 drain の conn record (簡潔形 push と明示形 typed consumer が同じ器を共有)。 */
static spnl_rec_conn_t g_rec_conn[OTLP_MAX_LOGS];
static int             g_rec_conn_n;

int spnl_otlp_conn_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct conn_collector coll = { g_rec_conn, 0, OTLP_MAX_LOGS };
    g_rec_conn_n = 0;
    if (otlp_drain(obj, map_name, conn_rb_cb, &coll) != 0) return -1;
    g_rec_conn_n = (int)coll.n;

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
        otlp_batch_add(&g_span_batch, &s);   /* E308 */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d conn spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- S4/E375: typed record consumer (`on_emit :conn do |ev|`) ---- */
const spnl_rec_conn_t *spnl_rec_conn_at(int i) {
    return (i >= 0 && i < g_rec_conn_n) ? &g_rec_conn[i] : NULL;
}

int spnl_rec_conn_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct conn_collector coll = { g_rec_conn, 0, OTLP_MAX_LOGS };
    g_rec_conn_n = 0;
    if (otlp_drain_ms(obj, map_name, conn_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    g_rec_conn_n = (int)coll.n;
    return g_rec_conn_n;
}

/* `to_span(ev)` / `conn_span(ev)` — 1 record を egress 宣言どおりの span に (0 = 無効 handle)。 */
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

/* ---- E295: DNS query span (resolver-independent、socket :53 の QNAME) ---- */
/* record 型 (spnl_rec_dns_t) と各フィールドの offset は record_mirror_gen.h の生成物。
 * 短い record (contract 未満) は unpack が -1 を返して捨てる (旧 `size < H + 104` 検査に相当、
 * 閾値は record サイズ = SPNL_REC_DNS_SIZE から導出)。 */
struct dns_collector { spnl_rec_dns_t *recs; size_t n; size_t cap; };

static int dns_rb_cb(void *ctx, void *data, size_t size) {
    struct dns_collector *c = (struct dns_collector *)ctx;
    if (c->n >= c->cap) return 0;
    if (spnl_rec_dns_unpack(data, size, &c->recs[c->n]) != 0) return 0;
    c->n++;
    return 0;
}

/* length-prefixed QNAME (raw[12..]) -> dotted host. userspace parse (no verifier).
 * S4/E371: non-static because it is the declared implementation of the derived
 * property `ev.qname` (record_schema.h の CcRecDerived)。生成 accessor
 * spnl_rec_dns_qname() がこの関数を呼ぶので、Ruby が読む hostname と span の
 * dns.question.name は**同じ 1 つのパーサ**の出力になる。 */
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

/* S4/E371: 1 record -> egress 宣言が記述する span。**簡潔形と明示形の両方がここを通る**
 * (spnl_otlp_dns_span_push_obj = 全 record にこれを適用して送る sugar、
 *  spnl_rec_dns_to_span = Ruby の `to_span(ev)` が 1 record に適用する明示形)。
 * 「糖衣を剥がすと明示形が出る」がコメントでなく構造的事実になる — 属性・SpanKind・
 * 時刻の作者が 1 箇所しかないので、2 形式が食い違うことがない。
 *
 * attrs は 8 要素、namebuf は span 名バッファ (呼び手所有 = batch へ deep-copy されるまで
 * 生きていればよい)。戻り 1 = span を組んだ、0 = この record は span にならない
 * (QNAME が parse できない = egress 宣言の condition "always (…dropped, no span)")。 */
static int dns_fill_span(const spnl_rec_dns_t *rr, int64_t off, uint64_t *seed,
                         otlp_generic_span_t *s, otlp_kv_t *attrs,
                         char *namebuf, size_t namecap) {
    /* 幅は生成 accessor が `ev.qname` に渡すのと同じ — 同じ関数に違う cap を渡すと、
     * 長い値で切り詰め位置が食い違う。E378: その 1 つの幅は qname 自身の宣言 (cap 256 =
     * DNS 名の上限 255 + NUL) から来る。 */
    char host[SPNL_REC_DERIVED_DNS_QNAME_CAP]; spnl_dns_qname(rr->raw, host, sizeof host);
    if (!host[0]) return 0;   /* not a parseable DNS query */
    uint64_t t = (uint64_t)((int64_t)rr->hdr.timestamp + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* E312: 単一 trace-context 生成 (共通プリミティブ) */
    /* dns_emit carries a real resolution RTT (duration_ns>0); E295 emit_dns is
     * query-only (duration_ns==0 -> span end == start, as before). */
    s->start_unix_ns = t; s->end_unix_ns = t + rr->duration_ns; s->kind = 0;
    snprintf(namebuf, namecap, SPNL_EGRESS_DNS_SPAN_NAME_FMT, host);
    s->name = namebuf;

    /* S3/E370: span 名と属性キーは record_schema.h の egress 宣言から生成された
     * SPNL_EGRESS_DNS_* (record_mirror_gen.h)。ここは宣言の**消費者**であって
     * 作者ではない — `capabilities --json` / `describe` が出す契約と wire が同一。 */
    int n = 0;
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_DNS_ATTR_DNS_QUESTION_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",host); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_DNS_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    if (rr->duration_ns) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_DNS_ATTR_SPNL_DNS_LATENCY_NS); snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)rr->duration_ns); n++; }   /* E311: DNS resolution RTT */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_DNS, rr->cgid, NULL };   /* E313: k8s のみ (peer は conn 専用) */
    n += otlp_enrich_run(&ec, attrs + n, 8 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* 直近 drain の DNS record。簡潔形 (push) と明示形 (typed consumer) が同じ器を使う
 * ので、record を 2 度持たない (~1MB static)。single-threaded・逐次呼出前提。 */
static spnl_rec_dns_t g_rec_dns[OTLP_MAX_LOGS];
static int            g_rec_dns_n;

int spnl_otlp_dns_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct dns_collector coll = { g_rec_dns, 0, OTLP_MAX_LOGS };
    g_rec_dns_n = 0;
    if (otlp_drain(obj, map_name, dns_rb_cb, &coll) != 0) return -1;
    g_rec_dns_n = (int)coll.n;

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
        if (!dns_fill_span(&coll.recs[i], off, &seed, &s, attrs, namebuf, sizeof namebuf)) continue;
        otlp_batch_add(&g_span_batch, &s);   /* E308 */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d dns spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ================= S4/E371: typed record consumer (`on_emit :dns do |ev|`) ==========
 *
 * 簡潔形 (`spnl_otlp_dns_span_push(ep)`) は「drain -> 全 record を span 化 -> 送信」を
 * 1 語に潰しており、間に Ruby のロジックを挟めない。ここはその 1 語を **3 つの語**に
 * 分解する: drain (record を配る) / to_span (1 record を span に) / send (span を送る)。
 * どれも record の byte 像を Ruby に渡さない — Ruby が持つのは drain 内の index (handle) で、
 * フィールドは生成 accessor (spnl_rec_dns_*、record_mirror_gen.h) 越しにだけ見える。
 *
 * span の中身は dns_fill_span() = 簡潔形と同じ builder なので、明示形で書いても属性・
 * SpanKind・時刻は 1 バイトも変わらない (差は「どの record を送るか」だけ = 利益②)。 */

/* 生成 accessor が呼ぶ lookup (record_mirror_gen.h が prototype を宣言)。範囲外は NULL
 * = accessor が zero-value を返す (Ruby に不正な handle の持ちようが無いので crash させない)。 */
const spnl_rec_dns_t *spnl_rec_dns_at(int i) {
    return (i >= 0 && i < g_rec_dns_n) ? &g_rec_dns[i] : NULL;
}

/* drain: ringbuf の record を配列に読み、件数を返す (Ruby の handle 0..n-1)。
 * timeout_ms は 1 poll の待ち時間 (0 = 非ブロッキング)。負値は簡潔形と同じ 100ms。 */
int spnl_rec_dns_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct dns_collector coll = { g_rec_dns, 0, OTLP_MAX_LOGS };
    g_rec_dns_n = 0;
    if (otlp_drain_ms(obj, map_name, dns_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    g_rec_dns_n = (int)coll.n;
    return g_rec_dns_n;
}

/* slot / seed / batch 状態は全 typed channel 共有 (上方の "typed consumer が共有する
 * span スロット" 節)。 */

/* `to_span(ev)` — 1 record を egress 宣言どおりの span に。0 = span にならない record
 * (QNAME 不成立)。send_otlp(0, ep) は no-op なので Ruby 側で分岐しなくても安全。 */
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

/* `send_otlp(span, ep)` — span を送信バッチに積む (E308 と同じ funnel: 満杯で 1 POST、
 * 残りは flush で)。戻り 1 = 積んだ、0 = 何もしなかった (無効 handle / 引数不足)。
 * endpoint はサイクル最初の send のものを使う (途中で変えたい用途は今は無い)。 */
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

/* サイクル末尾の flush (生成 driver が毎サイクル呼ぶ)。戻りは最後の POST の HTTP status
 * (1 本も積んでいなければ 0) — 簡潔形の push が返すものと同じ意味。 */
int spnl_otlp_span_flush(void) {
    if (!g_ev_batch_open) return 0;
    int st = otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] typed consumer: sent %d spans (%d posts, last HTTP %d) -> %s\n",
            g_ev_sent, g_span_batch.posts, g_span_batch.last_status,
            g_span_batch.endpoint ? g_span_batch.endpoint : "?");
    g_ev_batch_open = 0;
    return st;
}

/* ---- E297: L7 request/response latency span (send->recv round-trip) ---- */
/* l7_event: hdr + {pid, comm[16], daddr(be32), dport(host), family, start_ktime, duration_ns}.
 * Unlike E294/E296 connect spans (duration=0), the L7 span's duration IS the payload:
 * end_unix = start_unix + duration_ns = time-to-first-response-byte. */
/* S5/E372: record type + offsets come from record_mirror_gen.h (generated from the
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

/* S4/E374: 1 record -> egress 宣言が記述する span。**簡潔形と明示形の両方がここを通る**
 * (dns_fill_span と同じ構造 — 属性・SpanKind・時刻の作者を 1 箇所に保つ)。
 * attrs は 10 要素。戻り 1 = span を組んだ (l7 record は常に span になる)。 */
static int l7_fill_span(const spnl_rec_l7_t *rr, int64_t off, uint64_t *seed,
                        otlp_generic_span_t *s, otlp_kv_t *attrs,
                        char *namebuf, size_t namecap) {
    char peer[INET6_ADDRSTRLEN] = {0};
    int is6 = (rr->family == 10 /* AF_INET6 */);
    if (!is6) { struct in_addr a; a.s_addr = rr->daddr; inet_ntop(AF_INET, &a, peer, sizeof peer); }
    else      { snprintf(peer, sizeof peer, "(ipv6 not carried)"); }
    uint64_t start_unix = (uint64_t)((int64_t)rr->start_ktime + off);

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* E312: 単一 trace-context 生成 (共通プリミティブ) */
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
    /* peer は conn 専用 (signal_mask) なので L7 では k8s のみ適用 = E304 と byte 同一。 */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_L7, rr->cgid, peer };
    n += otlp_enrich_run(&ec, attrs + n, 10 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* 直近 drain の L7 record (簡潔形 push と明示形 typed consumer が同じ器を共有)。 */
static spnl_rec_l7_t g_rec_l7[OTLP_MAX_LOGS];
static int           g_rec_l7_n;

int spnl_otlp_l7_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct l7_collector coll = { g_rec_l7, 0, OTLP_MAX_LOGS };
    g_rec_l7_n = 0;
    if (otlp_drain(obj, map_name, l7_rb_cb, &coll) != 0) return -1;
    g_rec_l7_n = (int)coll.n;

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
        otlp_batch_add(&g_span_batch, &s);   /* E308 */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d l7 spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- S4/E374: typed record consumer (`on_emit :l7 do |ev|`) ---- */
const spnl_rec_l7_t *spnl_rec_l7_at(int i) {
    return (i >= 0 && i < g_rec_l7_n) ? &g_rec_l7[i] : NULL;
}

int spnl_rec_l7_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct l7_collector coll = { g_rec_l7, 0, OTLP_MAX_LOGS };
    g_rec_l7_n = 0;
    if (otlp_drain_ms(obj, map_name, l7_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    g_rec_l7_n = (int)coll.n;
    return g_rec_l7_n;
}

/* `to_span(ev)` / `l7_span(ev)` — 1 record を egress 宣言どおりの span に (0 = 無効 handle)。 */
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

/* ---- E298: HTTP L7 RED span (method/path/status + duration) ---- */
/* http_event: hdr + {pid, comm[16], daddr, dport, family, start_ktime, duration_ns,
 * req[64], resp[16]}. method/path parsed from req ("METHOD path HTTP/.."), status from
 * resp ("HTTP/1.1 NNN ..") in userspace (kernel only did a bounded copy — QNAME/E295 pattern).
 * Span duration = L7 round-trip; status>=500 -> Span.status=ERROR (RED error axis). */
/* S5/E372: layout from record_schema.h (cc_rec_http) via the generated mirror. */
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

/* S4/E374: the three declared derivations of the HTTP record (record_schema.h の
 * cc_rec_http_derived)。**非 static** — 生成 accessor (spnl_rec_http_method 等 =
 * Ruby の `ev.method`) がここを呼び、span builder も同じ関数を呼ぶので、Ruby が
 * フィルタに使う値と span に載る値が構造的に食い違えない (E371 の qname と同型)。
 * 各 impl は自分の source field の幅を知っている (表は長さを渡さない、E371 の慣行) —
 * 幅は生成 struct から取るので、ここに手書きの 64 / 16 は無い。 */
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

/* S4/E374: 1 record -> egress 宣言が記述する span (簡潔形 push と明示形 to_span の共通 builder)。
 * attrs は 14 要素 (E378 で latency 属性が 1 個増えた)、namebuf は span 名。
 * 戻り 1 = span を組んだ (http record は常に span になる)。 */
static int http_fill_span(const spnl_rec_http_t *rr, int64_t off, uint64_t *seed,
                          otlp_generic_span_t *s, otlp_kv_t *attrs,
                          char *namebuf, size_t namecap) {
    /* method/path/status は宣言された derivation (= `ev.method` の実体) の出力。
     * 幅も derivation の契約の一部 — 生成 accessor と同じ幅を渡す。E298 以来の
     * method[16] は、空白を含まない 64B の head (kernel 側 filter spnl_is_http_req は
     * 先頭 4 byte しか見ないので到達可能) で `ev.method` が 64 文字・span が 15 文字と
     * 食い違っていた。実 HTTP の method は 7 文字以下なので、通常のトラフィックでは
     * 出力は 1 byte も変わらない。E378: その幅は各 derivation 自身の宣言 (65 = req[64] +
     * NUL = 切り出し元より長くなり得ないという上限)。 */
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
    otlp_span_new_root(s, seed);   /* E312: 単一 trace-context 生成 (共通プリミティブ) */
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
     * and omit peer. The tcp path (E298, daddr!=0) is byte-identical to before. */
    if (rr->daddr == 0 && rr->dport == 0) {
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_URL_SCHEME); snprintf(attrs[n].val,sizeof attrs[n].val,"https"); n++;
    } else {
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_ADDRESS); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",peer); n++;
        snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_PORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"%u",rr->dport); n++;
    }
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_NETWORK_TRANSPORT);    snprintf(attrs[n].val,sizeof attrs[n].val,"tcp"); n++;
    /* l7 の spnl.l7.latency_ns と対称。span の長さが正 (start/end) で、この属性は
     * 同じ数を検索可能にするためのもの — `ev.duration_ns` が両 channel で公開されている
     * のに http だけ span 側に対応物が無い、という非対称を解消する。 */
    snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_SPNL_HTTP_LATENCY_NS); snprintf(attrs[n].val,sizeof attrs[n].val,"%llu",(unsigned long long)rr->duration_ns); n++;
    if (rr->comm[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",SPNL_EGRESS_HTTP_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(attrs[n].val,sizeof attrs[n].val,"%s",rr->comm); n++; }
    /* peer は conn 専用 (signal_mask) なので HTTP では k8s のみ適用 = E304 と byte 同一。
     * 上限は 14 (E378 で属性 1 個増えたぶん 13 から繰り上げ — 層 2 enricher の余地 6 は不変)。 */
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_HTTP, rr->cgid, peer };
    n += otlp_enrich_run(&ec, attrs + n, 14 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* 直近 drain の HTTP record (簡潔形 push と明示形 typed consumer が同じ器を共有)。 */
static spnl_rec_http_t g_rec_http[OTLP_MAX_LOGS];
static int             g_rec_http_n;

int spnl_otlp_http_span_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct http_collector coll = { g_rec_http, 0, OTLP_MAX_LOGS };
    g_rec_http_n = 0;
    if (otlp_drain(obj, map_name, http_rb_cb, &coll) != 0) return -1;
    g_rec_http_n = (int)coll.n;

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        otlp_generic_span_t s;
        otlp_kv_t attrs[14];   /* E378: 属性 1 個 (spnl.http.latency_ns) 追加ぶん 13 -> 14 */
        static char namebuf[96];
        if (!http_fill_span(&coll.recs[i], off, &seed, &s, attrs, namebuf, sizeof namebuf)) continue;
        otlp_batch_add(&g_span_batch, &s);   /* E308 */
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d http spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- S4/E374: typed record consumer (`on_emit :http do |ev|`) ---- */
const spnl_rec_http_t *spnl_rec_http_at(int i) {
    return (i >= 0 && i < g_rec_http_n) ? &g_rec_http[i] : NULL;
}

int spnl_rec_http_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct http_collector coll = { g_rec_http, 0, OTLP_MAX_LOGS };
    g_rec_http_n = 0;
    if (otlp_drain_ms(obj, map_name, http_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    g_rec_http_n = (int)coll.n;
    return g_rec_http_n;
}

/* `to_span(ev)` / `http_span(ev)` — 1 record を egress 宣言どおりの span に (0 = 無効 handle)。 */
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

/* ---- E341: Redis L7 RED span (command/error/duration) ---- */
/* redis_event has the same byte layout as http_event, and used to borrow http_rec_raw /
 * http_rb_cb outright. S5/E372 gives it its own declaration (cc_rec_redis) and hence its own
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
        /* k8s pod attribution; L7 signal (peer is conn-only, E313) -> reuse HTTP signal. */
        otlp_enrich_ctx_t ec = { OTLP_SIGNAL_HTTP, rr->cgid, peer };
        n += otlp_enrich_run(&ec, attrs + n, 13 - n);
        s.attrs = attrs; s.nattrs = n;

        otlp_batch_add(&g_span_batch, &s);
        sent++;
    }
    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d redis spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- E300: off-CPU-during-request span (why is the L7 span slow) ---- */
/* offcpu_event: hdr + {pid, comm[16], pad, duration_ns, offcpu_ns, wait_stack(s32), req[64],
 * resp[16]}. The span is an HTTP span (method/path/status/duration) PLUS spnl.offcpu_ns /
 * spnl.oncpu_ns / wait.kind. wait.kind is classified in userspace by scanning the captured
 * kernel wait-stack frames against /proc/kallsyms (io/lock/sleep/net/other). */
/* S5/E372: the one channel whose append-only *reading* rule is load-bearing — E312
 * appended start_ktime and hdr_ext, and a producer built before that writes a shorter
 * record which must still be accepted with the two new fields zero. That rule is now
 * declared (cc_rec_offcpu.required_through = "cgid") and the generated unpack applies
 * it, instead of two hand-written `if (size >= H + 144)` guards. */
/* offcpu の req/resp は http record と同じ「ワイヤの先頭 N バイト」で、L7 の
 * 読み方 (method/path/status) も同じ — なのでこの channel は http の**宣言された
 * derivation** (spnl_http_method / _path / _status) をそのまま呼ぶ。E377 まではここに
 * パースのコピーがあり、(a) 幅が古く (method[16])、(b) path の開始位置を切り詰め済み
 * method の strlen から求めていた (長い method で開始位置がずれる) ため、**同じ HTTP head
 * から http span と offcpu span で違う値**が出得た。
 *
 * derivation の impl は自分の source field の幅を http record から取る (SPNL_HTTP_REQ_LEN)
 * ので、両 record の幅が一致していることがこの再利用の前提。ずれたらビルドで落とす: */
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

/* E312 Step3: request 先頭バイト列から W3C traceparent ヘッダ値を探して out[56] に取り出す
 * (E295 パターン: kernel は bounded copy、userspace で parse)。見つかれば 1、無ければ 0。
 * 大小無視で "traceparent:" を探し、値の先頭 55 文字 ("vv-<32>-<16>-ff") をコピー。 */
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

/* --- S4/E379: the offcpu record's three own derivations -------------------
 *
 * 非 static — 生成 accessor (`ev.offcpu_ns` / `ev.oncpu_ns` / `ev.wait_kind`) がここを呼び、
 * span builder も同じ関数を呼ぶ。method/path/status は http の derivation をそのまま共有
 * なので、offcpu 固有はこの 3 つだけ。
 *
 * この channel の typed 化が最後になったのは、**egress 属性の 3 つがフィールドそのままでは
 * 出せない**から:
 *   - spnl.offcpu_ns  = min(offcpu_ns, duration_ns)   … clamp した値 (生フィールドでない)
 *   - spnl.oncpu_ns   = duration_ns - 上記            … フィールドに存在しない計算値
 *   - spnl.wait.kind  = wait_stack を kallsyms で分類 … record 外の状態を読む
 * 生フィールドを expose すると E376 (srtt の 1/8 us) と同じ食い違いが 3 通り生まれる。 */

/* wait.kind が読む「どの object の どの stack map か」。record には stack **id** しか無く、
 * その id を引くには drain 元の object が要る。E371 以来の 4 形式は全て「record + (定数)」で
 * 完結していたが、これは**同じ record を持ってきた側が知っている周辺情報**なので、5 つ目の
 * impl_form を足すのではなく **drain / push の入口で覚えておく** 形にした:
 *   - どちらの経路も stacks_map を引数で受け取っている (glue が "bpf_stacks" を渡す)
 *   - accessor が呼ばれるのは必ずその drain の直後 (`ev` は「直近 drain の index」)
 * ので、覚えている値は常に「その record を運んできた object」。無い場合 (host オラクル等)
 * の答えは "unknown" で、それは読めない stack map と同じ語 (_oc_wait_kind)。 */
static struct bpf_object *g_offcpu_obj;
static char               g_offcpu_stacks[64];

static void offcpu_set_stack_ctx(struct bpf_object *obj, const char *stacks_map) {
    g_offcpu_obj = obj;
    snprintf(g_offcpu_stacks, sizeof g_offcpu_stacks, "%s", stacks_map ? stacks_map : "");
}

/* `ev.offcpu_ns` = 属性 spnl.offcpu_ns そのもの。clamp は飾りではない: offcpu_ns は
 * sched_switch が積む合計、duration_ns は recv/send の対が測る窓で、**別のフックが別々に
 * 測る**ので合計が窓を超える record は表現可能。span は E300 以来 clamp 後を報告してきたので、
 * Ruby にも clamp 後を渡す (生値を渡すと「普通の record では一致し、異常な record でだけ
 * 食い違う」= フィルタが最も効いてほしい所で嘘をつく)。 */
long spnl_offcpu_offcpu_ns(const spnl_rec_offcpu_t *r) {
    if (!r) return 0;
    return (long)(r->offcpu_ns > r->duration_ns ? r->duration_ns : r->offcpu_ns);
}

/* `ev.oncpu_ns` = 属性 spnl.oncpu_ns。フィールドではなく差 (窓 - 待ち) なので、
 * ev.oncpu_ns + ev.offcpu_ns == ev.duration_ns が構造的に成り立つ。 */
long spnl_offcpu_oncpu_ns(const spnl_rec_offcpu_t *r) {
    if (!r) return 0;
    return (long)(r->duration_ns - (uint64_t)spnl_offcpu_offcpu_ns(r));
}

/* `ev.wait_kind` = 属性 spnl.wait.kind そのもの (同じ _oc_wait_kind の出力)。 */
void spnl_offcpu_wait_kind(const spnl_rec_offcpu_t *r, char *out, int cap) {
    if (!out || cap <= 0) return;
    out[0] = '\0';
    if (!r) return;
    snprintf(out, (size_t)cap, "%s",
             _oc_wait_kind(g_offcpu_obj, g_offcpu_stacks[0] ? g_offcpu_stacks : NULL, r->wait_stack));
}

/* S4/E379: 1 record -> egress 宣言が記述する **request-window span** (簡潔形 push と
 * 明示形 to_span の共通 builder — dns/conn/l7/http と同じ構造)。attrs は 13 要素。
 *
 * 他 channel との違いが 2 つあり、どちらも E300 の性質そのもの:
 *   (1) 時刻の起点は record の ktime ではなく **"now - duration"**。この record は経過時間
 *       (窓の長さ) を運ぶもので、簡潔形 push は E300 以来この anchor を使っている
 *       (E312 が start_ktime を append したが、それを使うのは request tree 経路だけ)。
 *       なので他 channel の `off` (ktime->unix) ではなく now_unix を受け取る。
 *   (2) 1 record は **2 span** になり得る (窓 + off-CPU wait の子)。ここが組むのは親 =
 *       window span で、子を nest するのは簡潔形 push のレンダリング (egress 宣言の note)。
 *       明示形 `to_span(ev)` が返すのは親 1 本 — 待ちの値 (spnl.offcpu_ns / spnl.wait.kind)
 *       は親にも載るので、消費者が読む値は同じ。 */
static int offcpu_fill_span(const spnl_rec_offcpu_t *rr, uint64_t now_unix, uint64_t *seed,
                            otlp_generic_span_t *s, otlp_kv_t *attrs,
                            char *namebuf, size_t namecap) {
    /* 宣言された derivation の出力を、その derivation 自身の宣言 cap で受ける。
     * method/path は http と共有の関数で、cap も同値 (冒頭の _Static_assert)。 */
    char method[SPNL_REC_DERIVED_OFFCPU_METHOD_CAP] = {0}, path[SPNL_REC_DERIVED_OFFCPU_PATH_CAP] = {0};
    char wk[SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP] = {0};
    spnl_http_method(rr->req, method, (int)sizeof method);
    spnl_http_path(rr->req, path, (int)sizeof path);
    int status = (int)spnl_http_status(rr->resp);
    uint64_t offcpu = (uint64_t)spnl_offcpu_offcpu_ns(rr);   /* = ev.offcpu_ns (同じ関数) */
    uint64_t oncpu  = (uint64_t)spnl_offcpu_oncpu_ns(rr);    /* = ev.oncpu_ns  (同じ関数) */
    spnl_offcpu_wait_kind(rr, wk, (int)sizeof wk);           /* = ev.wait_kind (同じ関数) */
    uint64_t start_unix = now_unix - rr->duration_ns;

    memset(s, 0, sizeof *s);
    otlp_span_new_root(s, seed);   /* E312: 単一 trace-context 生成 (共通プリミティブ) */
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
    otlp_enrich_ctx_t ec = { OTLP_SIGNAL_OFFCPU, rr->cgid, NULL };   /* E313: k8s のみ (peer は conn 専用) */
    n += otlp_enrich_run(&ec, attrs + n, 13 - n);
    s->attrs = attrs; s->nattrs = n;
    return 1;
}

/* 直近 drain の offcpu record (簡潔形 push と明示形 typed consumer が同じ器を共有)。 */
static spnl_rec_offcpu_t g_rec_offcpu[OTLP_MAX_LOGS];
static int               g_rec_offcpu_n;

int spnl_otlp_offcpu_span_push_obj(struct bpf_object *obj, const char *map_name,
                                   const char *stacks_map, const char *endpoint) {
    if (!obj || !map_name || !endpoint) return -1;
    struct offcpu_collector coll = { g_rec_offcpu, 0, OTLP_MAX_LOGS };
    g_rec_offcpu_n = 0;
    offcpu_set_stack_ctx(obj, stacks_map);   /* E379: wait.kind が引く stack map */
    if (otlp_drain(obj, map_name, offcpu_rb_cb, &coll) != 0) return -1;
    g_rec_offcpu_n = (int)coll.n;

    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    /* duration/offcpu are elapsed spans of ktime; anchor start at "now - duration" in unix. */
    struct timespec tnow; clock_gettime(CLOCK_REALTIME, &tnow);
    uint64_t now_unix = (uint64_t)tnow.tv_sec * 1000000000ull + (uint64_t)tnow.tv_nsec;
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");
    int sent = 0;
    for (size_t i = 0; i < coll.n; i++) {
        spnl_rec_offcpu_t *rr = &coll.recs[i];
        /* 1 offcpu record を 2 span の木にレンダリング。
         *   parent = request span (SERVER, duration = recv->send の window 全体) = fill_span
         *   child  = off-CPU wait span (INTERNAL, duration = offcpu_ns、window 内に nest)
         * 共通 trace_id + child.parent_span_id = parent.span_id。E300 の 1-span 属性
         * (spnl.offcpu_ns/oncpu_ns/wait.kind) は parent に残す (後方互換) + 待ちを子 span に
         * 分離して Span Performance の waterfall に見せる。近似: E300 は off-CPU の合計 offcpu_ns
         * を持つ (各待ちの発生時刻でない) ため、子は window 先頭に配置 (start=親start,
         * dur=offcpu_ns)。cross-record 子 (DNS/L7) は実 timestamp を持つので後段 (E312 Step2)。 */
        otlp_generic_span_t parent;
        otlp_kv_t attrs[13];
        static char namebuf[96];
        if (!offcpu_fill_span(rr, now_unix, &seed, &parent, attrs, namebuf, sizeof namebuf)) continue;

        otlp_batch_add(&g_span_batch, &parent);   /* E308: 木ごと 1 バッチに */
        sent++;

        /* off-CPU wait child: 実 off-CPU があった (offcpu>0) ときだけ。/spin (CPU-bound、
         * offcpu≈0) は待ち子を出さない = 全 on-CPU の正直な waterfall。値は親と同じ
         * derivation の出力 なので、親の属性と子の属性が食い違うことはない。 */
        uint64_t offcpu = (uint64_t)spnl_offcpu_offcpu_ns(rr);
        if (offcpu > 0) {
            char wk[SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP] = {0};
            spnl_offcpu_wait_kind(rr, wk, (int)sizeof wk);
            otlp_generic_span_t child; memset(&child, 0, sizeof child);
            otlp_span_new_child(&child, &parent, &seed);
            child.start_unix_ns = parent.start_unix_ns;    /* 近似: window 先頭 (E312 Step0) */
            child.end_unix_ns   = parent.start_unix_ns + offcpu;
            child.kind = 1 /* INTERNAL */;
            static char cnamebuf[64];
            snprintf(cnamebuf, sizeof cnamebuf, "off-CPU wait (%s)", wk);
            child.name = cnamebuf;
            otlp_kv_t cattrs[3]; int cn = 0;
            snprintf(cattrs[cn].key,sizeof cattrs[cn].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_WAIT_KIND); snprintf(cattrs[cn].val,sizeof cattrs[cn].val,"%s",wk); cn++;
            snprintf(cattrs[cn].key,sizeof cattrs[cn].key,"%s",SPNL_EGRESS_OFFCPU_ATTR_SPNL_OFFCPU_NS); snprintf(cattrs[cn].val,sizeof cattrs[cn].val,"%llu",(unsigned long long)offcpu); cn++;
            child.attrs = cattrs; child.nattrs = cn;
            otlp_batch_add(&g_span_batch, &child);   /* E308 */
            sent++;
        }
    }
    otlp_batch_flush_final(&g_span_batch);
    fprintf(stderr, "[otlp] pushed %d offcpu spans (%zu records, %d posts, last HTTP %d) -> %s\n",
            sent, coll.n, g_span_batch.posts, g_span_batch.last_status, endpoint);
    return sent > 0 ? g_span_batch.last_status : 0;
}

/* ---- S4/E379: typed record consumer (`on_emit :offcpu do |ev|`) ---- */
const spnl_rec_offcpu_t *spnl_rec_offcpu_at(int i) {
    return (i >= 0 && i < g_rec_offcpu_n) ? &g_rec_offcpu[i] : NULL;
}

/* 他 channel の drain と違い stacks_map も受ける — `ev.wait_kind` が引く stack map を
 * この drain の object と一緒に覚えるため (glue が "bpf_stacks" を渡す)。 */
int spnl_rec_offcpu_drain_obj(struct bpf_object *obj, const char *map_name,
                              const char *stacks_map, int timeout_ms) {
    if (!obj || !map_name) return -1;
    struct offcpu_collector coll = { g_rec_offcpu, 0, OTLP_MAX_LOGS };
    g_rec_offcpu_n = 0;
    offcpu_set_stack_ctx(obj, stacks_map);
    if (otlp_drain_ms(obj, map_name, offcpu_rb_cb, &coll, timeout_ms < 0 ? 100 : timeout_ms) != 0) return -1;
    g_rec_offcpu_n = (int)coll.n;
    return g_rec_offcpu_n;
}

/* `to_span(ev)` / `offcpu_span(ev)` — 1 record を egress 宣言どおりの **window span** に
 * (0 = 無効 handle)。簡潔形が drain サイクルごとに 1 度取る "now" を、こちらは record ごとに
 * 取る (差はサイクル内の経過分 = sub-ms、anchor の意味は同じ)。off-CPU wait の子 span は
 * 簡潔形のレンダリング — 明示形は 1 record = 1 span を返す (待ちの値は親に載っている)。 */
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

/* ---- E312 Step2: multi-source request tree (request window + cross-record children) ---- */
/* offcpu window record (parent) + dns/conn record (children) を drain し、リクエスト単位の
 * TREE を組む: parent = request span (SERVER, recv->send window)、children = off-CPU wait
 * (同一 record) + DNS resolve + TCP connect を **同 tgid かつ window 内 ktime** で相関 (E312
 * otlp_child_in_window)。木全体は 1 POST (E308 バッチ)。
 *
 * window-buffered: 子 (dns/conn) は親 window が閉じる**前**の push cycle で drain され得るので、
 * 相関できない子を**永続 pending バッファに繰り越し** (g_pend_*)、後続 cycle で親が現れたら nest。
 * TTL (既定 30s、SPNL_TREE_CHILD_TTL_MS) を超えても親が来ない子だけ standalone 単一 span に
 * フォールバック (誤った親子より安全 + 取りこぼしゼロ)。親 (window close) は即 emit (子は既に pending)。
 * 前提: 1 tid=1 リクエストの同期ハンドラ (sequential)。dns/conn map は任意 (無ければその子源はスキップ)。 */

/* DNS/conn record を span に (id は呼び出し側が root/child で設定済)。parseable なら 1、else 0。 */
static int otlp_tree_fill_dns(const spnl_rec_dns_t *d, int64_t off, int as_child,
                              otlp_generic_span_t *s, otlp_kv_t *a, char *nb, size_t nbcap) {
    char host[SPNL_REC_DERIVED_DNS_QNAME_CAP]; spnl_dns_qname(d->raw, host, sizeof host);   /* E377/E378: 幅も accessor と同じ (qname の宣言 cap) */
    if (!host[0]) return 0;
    uint64_t ds = (uint64_t)((int64_t)d->hdr.timestamp + off);
    s->start_unix_ns = ds; s->end_unix_ns = ds + d->duration_ns; s->kind = as_child ? 3 /*CLIENT*/ : 0;
    snprintf(nb, nbcap, SPNL_EGRESS_DNS_SPAN_NAME_FMT, host); s->name = nb;
    /* 同じ record の別 consumer (E312 request tree)。属性キーは同一宣言 (S3/E370) 由来で、
     * 違うのは nest 時の SpanKind (CLIENT) だけ — その差は egress 宣言の note に書いてある。 */
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
    conn_peer_addr(co, peer, sizeof peer);   /* E375: v4/v6 の選択は 1 箇所 (= ev.peer と同じ) */
    uint64_t cs = (uint64_t)((int64_t)co->hdr.timestamp + off);
    s->start_unix_ns = cs; s->end_unix_ns = cs; s->kind = as_child ? 3 /*CLIENT*/ : 0;
    snprintf(nb, nbcap, SPNL_EGRESS_CONN_SPAN_NAME_FMT, peer, co->dport); s->name = nb;
    int an = 0;
    snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_ADDRESS); snprintf(a[an].val,sizeof a[an].val,"%s",peer); an++;
    snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_PORT); snprintf(a[an].val,sizeof a[an].val,"%u",co->dport); an++;
    /* 単位変換は spnl_conn_srtt_us に 1 箇所 (= ev.srtt_us / 簡潔形 span と同じ出力)。
     * 「srtt を持つ record だけ属性を載せる」判定は生フィールドのまま = E312 と挙動同一。 */
    if (co->srtt_us > 0) { snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_NET_PEER_SRTT_US); snprintf(a[an].val,sizeof a[an].val,"%lld",(long long)spnl_conn_srtt_us(co)); an++; }
    if (co->comm[0]) { snprintf(a[an].key,sizeof a[an].key,"%s",SPNL_EGRESS_CONN_ATTR_PROCESS_EXECUTABLE_NAME); snprintf(a[an].val,sizeof a[an].val,"%s",co->comm); an++; }
    s->attrs = a; s->nattrs = an;
    return 1;
}

/* 永続 pending 子バッファ (push cycle を跨いで子を保持し、後続の親に nest する) */
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
    offcpu_set_stack_ctx(obj, stacks_map);   /* E379: wait.kind が引く stack map (この経路も同じ) */
    if (otlp_drain(obj, offcpu_map, offcpu_rb_cb, &pc) != 0) return -1;   /* parent source 必須 */
    /* children 任意: map が無い子源はスキップ (エラーにしない) */
    if (dns_map  && bpf_object__find_map_by_name(obj, dns_map))  (void)otlp_drain(obj, dns_map,  dns_rb_cb,  &dc);
    if (conn_map && bpf_object__find_map_by_name(obj, conn_map)) (void)otlp_drain(obj, conn_map, conn_rb_cb, &cc);

    /* 新しく drain した子を永続 pending に繰り越す (満杯なら新規を捨てる = 稀) */
    for (size_t j = 0; j < dc.n && g_npend_dns < OTLP_MAX_LOGS; j++)  g_pend_dns[g_npend_dns++]  = dc.recs[j];
    for (size_t j = 0; j < cc.n && g_npend_conn < OTLP_MAX_LOGS; j++) g_pend_conn[g_npend_conn++] = cc.recs[j];

    int64_t off = otlp_ktime_to_unix_off();
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = g_service;
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    struct timespec mono; clock_gettime(CLOCK_MONOTONIC, &mono);
    uint64_t now_mono = (uint64_t)mono.tv_sec*1000000000ull + (uint64_t)mono.tv_nsec;
    uint64_t ttl_ns = 30000ull * 1000000ull;   /* 既定 30s */
    { const char *e = getenv("SPNL_TREE_CHILD_TTL_MS"); if (e && e[0]) { long v = atol(e); if (v > 0) ttl_ns = (uint64_t)v * 1000000ull; } }
    otlp_batch_begin(&g_span_batch, endpoint, svc, g_version, "spinel-ebpf");

    static char dns_used[OTLP_MAX_LOGS];
    static char conn_used[OTLP_MAX_LOGS];
    memset(dns_used, 0, g_npend_dns); memset(conn_used, 0, g_npend_conn);
    int nspans = 0, nchild = 0, nfallback = 0;

    for (size_t i = 0; i < pc.n; i++) {
        spnl_rec_offcpu_t *rr = &pc.recs[i];
        /* 上の push 経路と同じ — http の宣言された derivation を共有する
         * (request tree の親 span も、同じ head から同じ method/path/status を出す)。 */
        char method[SPNL_REC_DERIVED_OFFCPU_METHOD_CAP] = {0}, path[SPNL_REC_DERIVED_OFFCPU_PATH_CAP] = {0};
        spnl_http_method(rr->req, method, (int)sizeof method);
        spnl_http_path(rr->req, path, (int)sizeof path);
        int status = (int)spnl_http_status(rr->resp);
        /* clamp と差も宣言された derivation の出力 (= `ev.offcpu_ns` / `ev.oncpu_ns`)。
         * 同じ record を読む 2 つ目の消費者がここ (E312 request tree) なので、E378 が
         * method/path/status でやったことを残り 3 プロパティにも及ぼす。 */
        uint64_t offcpu = (uint64_t)spnl_offcpu_offcpu_ns(rr);
        uint64_t oncpu  = (uint64_t)spnl_offcpu_oncpu_ns(rr);
        /* 正確な window 開始 (start_ktime)。無い旧 record は now-duration に退避。 */
        uint64_t start_unix;
        if (rr->start_ktime) start_unix = (uint64_t)((int64_t)rr->start_ktime + off);
        else { struct timespec tn; clock_gettime(CLOCK_REALTIME,&tn);
               start_unix = (uint64_t)tn.tv_sec*1000000000ull + (uint64_t)tn.tv_nsec - rr->duration_ns; }

        otlp_generic_span_t parent; memset(&parent, 0, sizeof parent);
        /* E312 Step3: 受信 traceparent (W3C) があれば その trace_id を根にし、我々の SERVER span を
         * その子に nest (分散トレースの一部)。無ければ生成。outbound へは注入しない (観測専用)。 */
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
        otlp_enrich_ctx_t ec = { OTLP_SIGNAL_OFFCPU, rr->cgid, NULL };   /* E313: k8s のみ (request-tree parent) */
        n += otlp_enrich_run(&ec, pattrs + n, 13 - n);
        parent.attrs = pattrs; parent.nattrs = n;
        otlp_batch_add(&g_span_batch, &parent); nspans++;

        /* child: off-CPU wait (同一 record) */
        if (offcpu > 0) {
            char wk[SPNL_REC_DERIVED_OFFCPU_WAIT_KIND_CAP] = {0};
            spnl_offcpu_wait_kind(rr, wk, (int)sizeof wk);   /* E379: = ev.wait_kind (同じ関数) */
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
        /* child: pending DNS resolves in window (同 tgid) */
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
        /* child: pending TCP connects in window (同 tgid) */
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

    /* pending の掃除: matched は除去。unmatched かつ TTL 超過 -> standalone フォールバック (取りこぼしゼロ)。
     * 未 matched かつ TTL 内は次 cycle に繰り越し (親がまだ来ていないかもしれない)。 */
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



