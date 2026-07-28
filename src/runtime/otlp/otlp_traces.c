/*
 * otlp_traces.c — メソッド呼び出しツリー -> OTLP traces
 * 詳細は otlp_traces.h を参照。assemble (events->spans) と build (spans->OTLP) はどちらも
 * libbpf 非依存で host 単体検証できる。
 */
#include "otlp_traces.h"
#include "otlp_pbutil.h"  /* otlp_enc_string / otlp_enc_bytes / otlp_put_kv_* / otlp_enc_one_sub / otlp_resource_t */

#include <string.h>

#include <pb_encode.h>
#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"

/* ---- id 生成 (splitmix64) ---- */

static uint64_t splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void put_u64_be(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* ---- E312: trace 組み立てプリミティブ (共通 trace_id + 親子リンク) ---- */

void otlp_span_new_root(otlp_generic_span_t *s, uint64_t *seed) {
    put_u64_be(s->trace_id,     splitmix64(seed));
    put_u64_be(s->trace_id + 8, splitmix64(seed));
    put_u64_be(s->span_id,      splitmix64(seed));
    s->has_parent = false;
    memset(s->parent_span_id, 0, 8);
}

void otlp_span_new_child(otlp_generic_span_t *child,
                         const otlp_generic_span_t *parent, uint64_t *seed) {
    memcpy(child->trace_id, parent->trace_id, 16);
    memcpy(child->parent_span_id, parent->span_id, 8);
    child->has_parent = true;
    put_u64_be(child->span_id, splitmix64(seed));
}

/* hex nibble -> 0..15, or -1 on non-hex. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* parse n bytes (2n hex chars) from s into out; return 1 ok / 0 bad (also rejects all-zero). */
static int parse_hex(const char *s, uint8_t *out, int nbytes) {
    int any = 0;
    for (int i = 0; i < nbytes; i++) {
        int hi = hexval(s[2*i]), lo = hexval(s[2*i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
        if (out[i]) any = 1;
    }
    return any;   /* all-zero trace/span id is invalid per W3C */
}

int otlp_span_root_from_traceparent(otlp_generic_span_t *s, const char *traceparent,
                                    uint64_t *seed) {
    /* W3C traceparent: "vv-<32hex trace_id>-<16hex span_id>-<2hex flags>" (55 chars). */
    if (traceparent && strlen(traceparent) >= 55 &&
        traceparent[2] == '-' && traceparent[35] == '-' && traceparent[52] == '-') {
        uint8_t tid[16], pid[8];
        if (parse_hex(traceparent + 3, tid, 16) && parse_hex(traceparent + 36, pid, 8)) {
            memcpy(s->trace_id, tid, 16);           /* 受信 trace_id を根に */
            memcpy(s->parent_span_id, pid, 8);      /* 受信 span-id = 我々の親 */
            s->has_parent = true;
            put_u64_be(s->span_id, splitmix64(seed));   /* 我々の span は新規 */
            return 1;
        }
    }
    otlp_span_new_root(s, seed);   /* 無効/無し -> 生成 */
    return 0;
}

int otlp_child_in_window(uint32_t child_tgid, uint64_t child_ktime,
                         uint32_t parent_tgid, uint64_t parent_start_ktime,
                         uint64_t parent_dur_ns) {
    if (parent_start_ktime == 0) return 0;          /* window 不明 (旧 record) は相関しない */
    if (child_tgid != parent_tgid) return 0;        /* 同一プロセス (tgid) が必須 */
    return child_ktime >= parent_start_ktime &&
           child_ktime <= parent_start_ktime + parent_dur_ns;
}

/* ---- assemble: events -> spans (per-tid スタック) ---- */

typedef struct {
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    uint8_t  trace_id[16];
    uint64_t start;
    int32_t  idx;
} pending_t;

typedef struct {
    uint64_t  tid;
    int       depth;
    uint8_t   trace_id[16];
    pending_t stack[OTLP_TRACE_MAX_DEPTH];
} tidslot_t;

int otlp_traces_assemble(const otlp_span_event_t *ev, size_t nev,
                         int64_t off_ns, uint64_t seed,
                         otlp_span_t *out, size_t max_out) {
    static tidslot_t slots[OTLP_TRACE_MAX_TIDS]; /* static: 大きめなので stack を避ける */
    int nslots = 0;
    uint64_t rng = seed;
    size_t nout = 0;

    for (size_t i = 0; i < nev; i++) {
        const otlp_span_event_t *e = &ev[i];
        /* tid -> slot (見つからなければ作る) */
        tidslot_t *s = NULL;
        for (int k = 0; k < nslots; k++) if (slots[k].tid == e->tid) { s = &slots[k]; break; }
        if (!s) {
            if (nslots >= OTLP_TRACE_MAX_TIDS) continue;
            s = &slots[nslots++];
            s->tid = e->tid; s->depth = 0;
        }
        uint64_t unix_ns = (uint64_t)((int64_t)e->ktime_ns + off_ns);

        if (e->kind == 0) { /* enter */
            if (s->depth >= OTLP_TRACE_MAX_DEPTH) continue;
            if (s->depth == 0) { /* 最外 -> 新しい trace */
                put_u64_be(s->trace_id,     splitmix64(&rng));
                put_u64_be(s->trace_id + 8, splitmix64(&rng));
            }
            pending_t *p = &s->stack[s->depth];
            put_u64_be(p->span_id, splitmix64(&rng));
            p->has_parent = (s->depth > 0);
            if (p->has_parent) memcpy(p->parent_span_id, s->stack[s->depth - 1].span_id, 8);
            memcpy(p->trace_id, s->trace_id, 16);
            p->start = unix_ns;
            p->idx = e->idx;
            s->depth++;
        } else { /* exit */
            if (s->depth <= 0) continue; /* 未対応 enter */
            pending_t *p = &s->stack[--s->depth];
            if (nout >= max_out) continue;
            otlp_span_t *o = &out[nout++];
            memcpy(o->trace_id, p->trace_id, 16);
            memcpy(o->span_id, p->span_id, 8);
            o->has_parent = p->has_parent;
            if (p->has_parent) memcpy(o->parent_span_id, p->parent_span_id, 8);
            else memset(o->parent_span_id, 0, 8);
            o->method_idx = p->idx;
            o->start_unix_ns = p->start;
            o->end_unix_ns = unix_ns;
        }
    }
    return (int)nout;
}

/* ---- OTLP encode (scalar/属性/envelope は otlp_pbutil.h) ---- */

typedef struct {
    const otlp_span_t *spans; size_t n;
    const otlp_method_meta_t *metas; size_t nmetas;
} trace_ctx_t;

static const otlp_method_meta_t *find_meta(const trace_ctx_t *c, int32_t idx) {
    for (size_t i = 0; i < c->nmetas; i++) if (c->metas[i].idx == idx) return &c->metas[i];
    return NULL;
}

/* arg = const otlp_method_meta_t* (NULL 可) */
static bool enc_span_attrs(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp_method_meta_t *m = (const otlp_method_meta_t *)(*arg);
    if (!m) return true;
    if (!otlp_put_kv_str(st, fld, "code.function", m->method ? m->method : "")) return false;
    if (m->file && m->file[0] && !otlp_put_kv_str(st, fld, "code.filepath", m->file)) return false;
    if (m->line > 0 && !otlp_put_kv_int(st, fld, "code.lineno", m->line)) return false;
    return true;
}

/* ScopeSpans.spans: span 群 (arg = trace_ctx_t*) */
static bool enc_spans(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const trace_ctx_t *c = (const trace_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_span_t *s = &c->spans[i];
        const otlp_method_meta_t *m = find_meta(c, s->method_idx);

        opentelemetry_proto_trace_v1_Span sp = opentelemetry_proto_trace_v1_Span_init_zero;
        otlp_bytes_t tid_a = { s->trace_id, 16 };
        otlp_bytes_t sid_a = { s->span_id, 8 };
        otlp_bytes_t pid_a = { s->parent_span_id, 8 };
        sp.trace_id.funcs.encode = otlp_enc_bytes; sp.trace_id.arg = &tid_a;
        sp.span_id.funcs.encode  = otlp_enc_bytes; sp.span_id.arg  = &sid_a;
        if (s->has_parent) { sp.parent_span_id.funcs.encode = otlp_enc_bytes; sp.parent_span_id.arg = &pid_a; }
        sp.name.funcs.encode = otlp_enc_string;
        sp.name.arg = (void *)((m && m->method) ? m->method : "?");
        sp.kind = opentelemetry_proto_trace_v1_Span_SpanKind_SPAN_KIND_INTERNAL;
        sp.start_time_unix_nano = s->start_unix_ns;
        sp.end_time_unix_nano = s->end_unix_ns;
        sp.attributes.funcs.encode = enc_span_attrs;
        sp.attributes.arg = (void *)m;

        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st, opentelemetry_proto_trace_v1_Span_fields, &sp)) return false;
    }
    return true;
}

long otlp_traces_build(uint8_t *buf, size_t cap,
                       const char *service_name, const char *service_version,
                       const char *scope_name,
                       const otlp_span_t *spans, size_t nspans,
                       const otlp_method_meta_t *metas, size_t nmetas) {
    trace_ctx_t tctx = { spans, nspans, metas, nmetas };
    otlp_resource_t rctx = { service_name, service_version };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_trace_v1_ScopeSpans ss =
        opentelemetry_proto_trace_v1_ScopeSpans_init_zero;
    ss.has_scope = true;
    ss.scope = scope;
    ss.spans.funcs.encode = enc_spans;
    ss.spans.arg = &tctx;

    opentelemetry_proto_trace_v1_ResourceSpans rs =
        opentelemetry_proto_trace_v1_ResourceSpans_init_zero;
    rs.has_resource = true;
    rs.resource = res;
    otlp_one_sub_t ss_sub = { opentelemetry_proto_trace_v1_ScopeSpans_fields, &ss };
    rs.scope_spans.funcs.encode = otlp_enc_one_sub;
    rs.scope_spans.arg = &ss_sub;

    otlp_one_sub_t rs_sub = { opentelemetry_proto_trace_v1_ResourceSpans_fields, &rs };
    opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest req =
        opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest_init_zero;
    req.resource_spans.funcs.encode = otlp_enc_one_sub;
    req.resource_spans.arg = &rs_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}

/* ---- HTTP server span (kind=SERVER + http.* 属性) ---- */

static bool enc_http_attrs(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp_http_span_t *s = (const otlp_http_span_t *)(*arg);
    if (s->http_method && s->http_method[0] &&
        !otlp_put_kv_str(st, fld, "http.request.method", s->http_method)) return false;
    if (s->url_path && s->url_path[0] &&
        !otlp_put_kv_str(st, fld, "url.path", s->url_path)) return false;
    if (s->status_code > 0 &&
        !otlp_put_kv_int(st, fld, "http.response.status_code", s->status_code)) return false;
    /* OBI/semconv v1.41.0 互換の追加属性 */
    if (s->server_address && s->server_address[0] &&
        !otlp_put_kv_str(st, fld, "server.address", s->server_address)) return false;
    if (s->server_port > 0 &&
        !otlp_put_kv_int(st, fld, "server.port", s->server_port)) return false;
    if (s->client_address && s->client_address[0] &&
        !otlp_put_kv_str(st, fld, "client.address", s->client_address)) return false;
    if (s->url_scheme && s->url_scheme[0] &&
        !otlp_put_kv_str(st, fld, "url.scheme", s->url_scheme)) return false;
    if (s->route && s->route[0] &&
        !otlp_put_kv_str(st, fld, "http.route", s->route)) return false;
    /* L2–L8 横断相関の追加属性 (L8 tenant + L3/L4 4-tuple keyed メトリクス) */
    if (s->tenant && s->tenant[0] &&
        !otlp_put_kv_str(st, fld, "tenant", s->tenant)) return false;
    if (s->tcp_established >= 0 &&
        !otlp_put_kv_int(st, fld, "net.tcp.established", s->tcp_established)) return false;
    if (s->tcp_state_changes >= 0 &&
        !otlp_put_kv_int(st, fld, "net.tcp.state_changes", s->tcp_state_changes)) return false;
    return true;
}

static bool enc_http_span(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp_http_span_t *s = (const otlp_http_span_t *)(*arg);
    opentelemetry_proto_trace_v1_Span sp = opentelemetry_proto_trace_v1_Span_init_zero;
    otlp_bytes_t tid_a = { s->trace_id, 16 };
    otlp_bytes_t sid_a = { s->span_id, 8 };
    otlp_bytes_t pid_a = { s->parent_span_id, 8 };
    sp.trace_id.funcs.encode = otlp_enc_bytes; sp.trace_id.arg = &tid_a;
    sp.span_id.funcs.encode  = otlp_enc_bytes; sp.span_id.arg  = &sid_a;
    if (s->has_parent) { sp.parent_span_id.funcs.encode = otlp_enc_bytes; sp.parent_span_id.arg = &pid_a; }
    sp.name.funcs.encode = otlp_enc_string;
    sp.name.arg = (void *)(s->name ? s->name : "");
    sp.kind = opentelemetry_proto_trace_v1_Span_SpanKind_SPAN_KIND_SERVER;
    sp.start_time_unix_nano = s->start_unix_ns;
    sp.end_time_unix_nano = s->end_unix_ns;
    sp.attributes.funcs.encode = enc_http_attrs;
    sp.attributes.arg = (void *)s;
    /* HTTP server 規約 (OBI/semconv) — status >= 500 で ERROR、それ以外は UNSET (省略) */
    if (s->status_code >= 500) {
        sp.has_status = true;
        sp.status.code = opentelemetry_proto_trace_v1_Status_StatusCode_STATUS_CODE_ERROR;
    }
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_submessage(st, opentelemetry_proto_trace_v1_Span_fields, &sp);
}

long otlp_traces_http_build(uint8_t *buf, size_t cap,
                            const char *service_name, const char *service_version,
                            const char *scope_name, const otlp_http_span_t *span) {
    otlp_resource_t rctx = { service_name, service_version };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_trace_v1_ScopeSpans ss =
        opentelemetry_proto_trace_v1_ScopeSpans_init_zero;
    ss.has_scope = true;
    ss.scope = scope;
    ss.spans.funcs.encode = enc_http_span;
    ss.spans.arg = (void *)span;

    opentelemetry_proto_trace_v1_ResourceSpans rs =
        opentelemetry_proto_trace_v1_ResourceSpans_init_zero;
    rs.has_resource = true;
    rs.resource = res;
    otlp_one_sub_t ss_sub = { opentelemetry_proto_trace_v1_ScopeSpans_fields, &ss };
    rs.scope_spans.funcs.encode = otlp_enc_one_sub;
    rs.scope_spans.arg = &ss_sub;

    otlp_one_sub_t rs_sub = { opentelemetry_proto_trace_v1_ResourceSpans_fields, &rs };
    opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest req =
        opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest_init_zero;
    req.resource_spans.funcs.encode = otlp_enc_one_sub;
    req.resource_spans.arg = &rs_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}

/* ---- E292: 汎用 span (任意 KV 属性) — 監査 span 用 ---- */

typedef struct { const otlp_kv_t *attrs; int n; } gattrs_ctx_t;

static bool enc_generic_attrs(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const gattrs_ctx_t *c = (const gattrs_ctx_t *)(*arg);
    for (int i = 0; i < c->n; i++) {
        const otlp_kv_t *kv = &c->attrs[i];
        if (!kv->key[0] || !kv->val[0]) continue;   /* 空 key/val は省略 */
        if (!otlp_put_kv_str(st, fld, kv->key, kv->val)) return false;
    }
    return true;
}

/* 1 span を Span submessage に符号化する共通ルーチン (単一/複数 build で共有)。 */
static bool enc_generic_span_one(pb_ostream_t *st, const pb_field_iter_t *fld,
                                 const otlp_generic_span_t *s) {
    opentelemetry_proto_trace_v1_Span sp = opentelemetry_proto_trace_v1_Span_init_zero;
    otlp_bytes_t tid_a = { s->trace_id, 16 };
    otlp_bytes_t sid_a = { s->span_id, 8 };
    otlp_bytes_t pid_a = { s->parent_span_id, 8 };
    sp.trace_id.funcs.encode = otlp_enc_bytes; sp.trace_id.arg = &tid_a;
    sp.span_id.funcs.encode  = otlp_enc_bytes; sp.span_id.arg  = &sid_a;
    if (s->has_parent) { sp.parent_span_id.funcs.encode = otlp_enc_bytes; sp.parent_span_id.arg = &pid_a; }
    sp.name.funcs.encode = otlp_enc_string;
    sp.name.arg = (void *)(s->name ? s->name : "");
    sp.kind = s->kind ? s->kind : opentelemetry_proto_trace_v1_Span_SpanKind_SPAN_KIND_INTERNAL;
    sp.start_time_unix_nano = s->start_unix_ns;
    sp.end_time_unix_nano = s->end_unix_ns;
    /* gctx は本 submessage 符号化中だけ生きていればよい (pb_encode_submessage は同期呼出) →
     * ローカルで安全。複数 span を跨いだ静的共有は不要 (E308 batch)。 */
    gattrs_ctx_t gctx;
    gctx.attrs = s->attrs; gctx.n = s->nattrs;
    sp.attributes.funcs.encode = enc_generic_attrs;
    sp.attributes.arg = &gctx;
    if (s->is_error) {          /* deny 等: APM で ERROR 色分け */
        sp.has_status = true;
        sp.status.code = opentelemetry_proto_trace_v1_Status_StatusCode_STATUS_CODE_ERROR;
    }
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_submessage(st, opentelemetry_proto_trace_v1_Span_fields, &sp);
}

/* ScopeSpans.spans: 汎用 span 群 (arg = gspans_ctx_t*、E308 batch) */
typedef struct { const otlp_generic_span_t *spans; size_t n; } gspans_ctx_t;

static bool enc_generic_spans(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const gspans_ctx_t *c = (const gspans_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++)
        if (!enc_generic_span_one(st, fld, &c->spans[i])) return false;
    return true;
}

long otlp_traces_generic_build_multi(uint8_t *buf, size_t cap,
                                     const char *service_name, const char *service_version,
                                     const char *scope_name,
                                     const otlp_generic_span_t *spans, size_t nspans) {
    otlp_resource_t rctx = { service_name, service_version };
    gspans_ctx_t gsctx = { spans, nspans };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_trace_v1_ScopeSpans ss =
        opentelemetry_proto_trace_v1_ScopeSpans_init_zero;
    ss.has_scope = true;
    ss.scope = scope;
    ss.spans.funcs.encode = enc_generic_spans;
    ss.spans.arg = &gsctx;

    opentelemetry_proto_trace_v1_ResourceSpans rs =
        opentelemetry_proto_trace_v1_ResourceSpans_init_zero;
    rs.has_resource = true;
    rs.resource = res;
    otlp_one_sub_t ss_sub = { opentelemetry_proto_trace_v1_ScopeSpans_fields, &ss };
    rs.scope_spans.funcs.encode = otlp_enc_one_sub;
    rs.scope_spans.arg = &ss_sub;

    otlp_one_sub_t rs_sub = { opentelemetry_proto_trace_v1_ResourceSpans_fields, &rs };
    opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest req =
        opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest_init_zero;
    req.resource_spans.funcs.encode = otlp_enc_one_sub;
    req.resource_spans.arg = &rs_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_trace_v1_ExportTraceServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}

/* 単一 span は nspans==1 の multi と byte 一致 (既存呼出元 otlp_httpspan.c 等はそのまま)。 */
long otlp_traces_generic_build(uint8_t *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name, const otlp_generic_span_t *span) {
    return otlp_traces_generic_build_multi(buf, cap, service_name, service_version,
                                           scope_name, span, 1);
}
