/*
 * otlp_json.c -- the OTLP/HTTP+JSON encoder (proto3 JSON mapping). See otlp_json.h.
 * It selects exactly the same data as the protobuf encoders do.
 */
#include "otlp_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int otlp_want_json(void) {
    const char *p = getenv("OTEL_EXPORTER_OTLP_PROTOCOL");
    return p && strcmp(p, "http/json") == 0;
}

int otlp_endpoint_is_grpc(const char *e) {
    return e && (strncmp(e, "grpc://", 7) == 0 || strncmp(e, "grpcs://", 8) == 0);
}

/* ---- a minimal JSON writer over a fixed buffer; overflow clears ok ---- */
typedef struct { char *p; size_t cap; size_t n; int ok; } jw_t;

static void jw_ch(jw_t *w, char c) { if (w->n < w->cap) w->p[w->n] = c; else w->ok = 0; w->n++; }
static void jw_raw(jw_t *w, const char *s) { for (; *s; s++) jw_ch(w, *s); }

/* A JSON string: quoted and escaped. */
static void jw_jstr(jw_t *w, const char *s) {
    jw_ch(w, '"');
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { jw_ch(w, '\\'); jw_ch(w, (char)c); }
        else if (c == '\n') jw_raw(w, "\\n");
        else if (c == '\r') jw_raw(w, "\\r");
        else if (c == '\t') jw_raw(w, "\\t");
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); jw_raw(w, b); }
        else jw_ch(w, (char)c);
    }
    jw_ch(w, '"');
}
/* The proto3 JSON mapping writes 64-bit integers as strings. */
static void jw_u64q(jw_t *w, uint64_t v) { char b[24]; snprintf(b, sizeof b, "\"%llu\"", (unsigned long long)v); jw_raw(w, b); }
static void jw_i64q(jw_t *w, int64_t v)  { char b[24]; snprintf(b, sizeof b, "\"%lld\"", (long long)v); jw_raw(w, b); }
static void jw_int(jw_t *w, long v)       { char b[24]; snprintf(b, sizeof b, "%ld", v); jw_raw(w, b); }
static void jw_dbl(jw_t *w, double v)     { char b[32]; snprintf(b, sizeof b, "%g", v); jw_raw(w, b); }
static void jw_hex(jw_t *w, const uint8_t *b, size_t n) {
    static const char *h = "0123456789abcdef";
    jw_ch(w, '"');
    for (size_t i = 0; i < n; i++) { jw_ch(w, h[b[i] >> 4]); jw_ch(w, h[b[i] & 0xf]); }
    jw_ch(w, '"');
}

/* Write one {"key":k,"value":{"stringValue":v}}, honouring the first flag. */
static void jw_res_kv(jw_t *w, int *first, const char *k, const char *v) {
    if (!v || !v[0]) return;
    if (!*first) jw_ch(w, ','); *first = 0;
    jw_raw(w, "{\"key\":"); jw_jstr(w, k);
    jw_raw(w, ",\"value\":{\"stringValue\":"); jw_jstr(w, v); jw_raw(w, "}}");
}
/* "resource":{"attributes":[...]}, matching the protobuf encoder exactly.
 * service.name (+ service.version) + service.instance.id + telemetry.sdk.{name,language,version}. */
static void jw_resource(jw_t *w, const char *name, const char *ver) {
    jw_raw(w, "\"resource\":{\"attributes\":[");
    int first = 1;
    jw_res_kv(w, &first, "service.name", name);
    jw_res_kv(w, &first, "service.version", ver);
    jw_res_kv(w, &first, "service.instance.id", otlp_service_instance_id());
    jw_res_kv(w, &first, "telemetry.sdk.name", "spinel-ebpf");
    jw_res_kv(w, &first, "telemetry.sdk.language", "ruby");
    jw_res_kv(w, &first, "telemetry.sdk.version", "0");
    /* OTEL_RESOURCE_ATTRIBUTES. The comment above says this writer matches
     * otlp_enc_resource_attrs, and it is the same shared parser and the same
     * last-position rule that keep that true -- the JSON path silently lacking a
     * resource attribute the protobuf path carries is exactly the divergence
     * this function was written to avoid. */
    otlp_kv_t ra[OTLP_ENV_RESOURCE_ATTRS_MAX];
    int nra = otlp_env_kv_list("OTEL_RESOURCE_ATTRIBUTES", ra, OTLP_ENV_RESOURCE_ATTRS_MAX);
    for (int i = 0; i < nra; i++) jw_res_kv(w, &first, ra[i].key, ra[i].val);
    jw_raw(w, "]}");
}
static void jw_scope(jw_t *w, const char *scope) {
    jw_raw(w, "\"scope\":{\"name\":"); jw_jstr(w, scope ? scope : "spinel-ebpf"); jw_raw(w, "}");
}
/* The code.function / code.filepath / code.lineno attribute array. */
static void jw_code_attrs(jw_t *w, const char *fn, const char *file, int32_t line) {
    jw_raw(w, "\"attributes\":[");
    jw_raw(w, "{\"key\":\"code.function\",\"value\":{\"stringValue\":"); jw_jstr(w, fn ? fn : ""); jw_raw(w, "}}");
    if (file && file[0]) { jw_raw(w, ",{\"key\":\"code.filepath\",\"value\":{\"stringValue\":"); jw_jstr(w, file); jw_raw(w, "}}"); }
    if (line > 0) { jw_raw(w, ",{\"key\":\"code.lineno\",\"value\":{\"intValue\":"); jw_i64q(w, line); jw_raw(w, "}}"); }
    jw_raw(w, "]");
}

/* Representative value for slot s, about 1.5 * 2^s -- the same midpoint the
 * protobuf encoder uses. */
static double slot_midpoint(int s) { return s <= 0 ? 1.0 : 1.5 * (double)((uint64_t)1 << s); }

/* One metric per request, split the same way the protobuf side
 * (otlp_metrics_method_build) splits it. The `part` numbering has to match:
 * fixing only one side would make the http/json path emit a different metric.
 * The declaration is otlp_method_part_t in otlp_metrics.h. */
_Static_assert(OTLP_MPART_CALLS == 0 && OTLP_MPART_LATENCY_EXP == 1 && OTLP_MPART_LATENCY_HIST == 2,
               "otlp_json_metrics_method_build's part numbering must match otlp_method_part_t");

long otlp_json_metrics_method_build(char *buf, size_t cap,
                                    const char *svc, const char *ver, const char *scope,
                                    int part,
                                    uint64_t t, uint64_t start,
                                    const otlp_method_metric_t *methods, size_t n) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceMetrics\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeMetrics\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"metrics\":[");

    if (part == OTLP_MPART_CALLS) {
        jw_raw(&w, "{\"name\":\"spnl_method_calls_total\",\"sum\":{\"dataPoints\":[");
        int first = 1;
        for (size_t i = 0; i < n; i++) {
            const otlp_method_metric_t *m = &methods[i];
            if (m->calls == 0) continue;
            if (!first) jw_ch(&w, ','); first = 0;
            jw_raw(&w, "{\"startTimeUnixNano\":"); jw_u64q(&w, start);
            jw_raw(&w, ",\"timeUnixNano\":"); jw_u64q(&w, t);
            jw_raw(&w, ",\"asInt\":"); jw_i64q(&w, (int64_t)m->calls);
            jw_ch(&w, ','); jw_code_attrs(&w, m->method, m->file, m->line);
            jw_ch(&w, '}');
        }
        jw_raw(&w, "],\"aggregationTemporality\":2,\"isMonotonic\":true}}");
    } else if (part == OTLP_MPART_LATENCY_EXP) {
        jw_raw(&w, "{\"name\":\"spnl_method_latency_ns\",\"unit\":\"ns\",\"exponentialHistogram\":{\"dataPoints\":[");
        int first = 1;
        for (size_t i = 0; i < n; i++) {
            const otlp_method_metric_t *m = &methods[i];
            if (m->calls == 0) continue;
            int fs = -1, ls = -1; uint64_t total = 0; double sum = 0.0;
            for (int s = 0; s < OTLP_HIST_SLOTS; s++) {
                uint64_t cnt = m->buckets[s];
                if (cnt == 0) continue;
                if (fs < 0) fs = s;
                ls = s; total += cnt; sum += (double)cnt * slot_midpoint(s);
            }
            if (!first) jw_ch(&w, ','); first = 0;
            jw_raw(&w, "{\"startTimeUnixNano\":"); jw_u64q(&w, start);
            jw_raw(&w, ",\"timeUnixNano\":"); jw_u64q(&w, t);
            jw_raw(&w, ",\"count\":"); jw_u64q(&w, total);
            jw_raw(&w, ",\"sum\":"); jw_dbl(&w, sum);
            jw_raw(&w, ",\"scale\":0,\"zeroCount\":\"0\"");
            if (fs >= 0) {
                jw_raw(&w, ",\"positive\":{\"offset\":"); jw_int(&w, fs);
                jw_raw(&w, ",\"bucketCounts\":[");
                for (int s = fs; s <= ls; s++) { if (s > fs) jw_ch(&w, ','); jw_u64q(&w, m->buckets[s]); }
                jw_raw(&w, "]}");
            }
            jw_ch(&w, ','); jw_code_attrs(&w, m->method, m->file, m->line);
            jw_ch(&w, '}');
        }
        jw_raw(&w, "],\"aggregationTemporality\":2}}");
    } else {
        jw_raw(&w, "{\"name\":\"spnl_method_latency_ns\",\"unit\":\"ns\",\"histogram\":{\"dataPoints\":[");
        int first = 1;
        for (size_t i = 0; i < n; i++) {
            const otlp_method_metric_t *m = &methods[i];
            if (m->calls == 0) continue;
            uint64_t bc[OTLP_LOG2_NBUCKETS]; uint64_t total = 0; double sum = 0.0;
            otlp_log2_fold(m->buckets, bc, &total, &sum);
            if (!first) jw_ch(&w, ','); first = 0;
            jw_raw(&w, "{\"startTimeUnixNano\":"); jw_u64q(&w, start);
            jw_raw(&w, ",\"timeUnixNano\":"); jw_u64q(&w, t);
            jw_raw(&w, ",\"count\":"); jw_u64q(&w, total);
            jw_raw(&w, ",\"sum\":"); jw_dbl(&w, sum);
            jw_raw(&w, ",\"bucketCounts\":[");
            for (int b = 0; b < OTLP_LOG2_NBUCKETS; b++) { if (b) jw_ch(&w, ','); jw_u64q(&w, bc[b]); }
            jw_raw(&w, "],\"explicitBounds\":[");
            for (int b = 0; b < OTLP_LOG2_NBOUNDS; b++) { if (b) jw_ch(&w, ','); jw_dbl(&w, otlp_log2_ns_bounds()[b]); }
            jw_raw(&w, "],");
            jw_code_attrs(&w, m->method, m->file, m->line);
            jw_ch(&w, '}');
        }
        jw_raw(&w, "],\"aggregationTemporality\":2}}");
    }

    jw_raw(&w, "]}]}]}");
    return w.ok ? (long)w.n : -1;
}

long otlp_json_traces_build(char *buf, size_t cap,
                            const char *svc, const char *ver, const char *scope,
                            const otlp_span_t *spans, size_t nspans,
                            const otlp_method_meta_t *metas, size_t nmetas) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceSpans\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeSpans\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"spans\":[");
    for (size_t i = 0; i < nspans; i++) {
        const otlp_span_t *s = &spans[i];
        const otlp_method_meta_t *m = NULL;
        for (size_t k = 0; k < nmetas; k++) if (metas[k].idx == s->method_idx) { m = &metas[k]; break; }
        if (i) jw_ch(&w, ',');
        jw_raw(&w, "{\"traceId\":"); jw_hex(&w, s->trace_id, 16);
        jw_raw(&w, ",\"spanId\":"); jw_hex(&w, s->span_id, 8);
        if (s->has_parent) { jw_raw(&w, ",\"parentSpanId\":"); jw_hex(&w, s->parent_span_id, 8); }
        jw_raw(&w, ",\"name\":"); jw_jstr(&w, (m && m->method) ? m->method : "?");
        jw_raw(&w, ",\"kind\":1");  /* SPAN_KIND_INTERNAL */
        jw_raw(&w, ",\"startTimeUnixNano\":"); jw_u64q(&w, s->start_unix_ns);
        jw_raw(&w, ",\"endTimeUnixNano\":"); jw_u64q(&w, s->end_unix_ns);
        if (m) { jw_ch(&w, ','); jw_code_attrs(&w, m->method, m->file, m->line); }
        jw_ch(&w, '}');
    }
    jw_raw(&w, "]}]}]}");
    return w.ok ? (long)w.n : -1;
}

long otlp_json_http_span_build(char *buf, size_t cap,
                               const char *svc, const char *ver, const char *scope,
                               const otlp_http_span_t *s) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceSpans\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeSpans\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"spans\":[{");
    jw_raw(&w, "\"traceId\":"); jw_hex(&w, s->trace_id, 16);
    jw_raw(&w, ",\"spanId\":"); jw_hex(&w, s->span_id, 8);
    if (s->has_parent) { jw_raw(&w, ",\"parentSpanId\":"); jw_hex(&w, s->parent_span_id, 8); }
    jw_raw(&w, ",\"name\":"); jw_jstr(&w, s->name ? s->name : "");
    jw_raw(&w, ",\"kind\":2");  /* SPAN_KIND_SERVER */
    jw_raw(&w, ",\"startTimeUnixNano\":"); jw_u64q(&w, s->start_unix_ns);
    jw_raw(&w, ",\"endTimeUnixNano\":"); jw_u64q(&w, s->end_unix_ns);
    jw_raw(&w, ",\"attributes\":[");
    int first = 1;
    jw_res_kv(&w, &first, "http.request.method", s->http_method);
    jw_res_kv(&w, &first, "url.path", s->url_path);
    if (s->status_code > 0) {
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"key\":\"http.response.status_code\",\"value\":{\"intValue\":"); jw_i64q(&w, s->status_code); jw_raw(&w, "}}");
    }
    /* The additional semconv attributes. */
    jw_res_kv(&w, &first, "server.address", s->server_address);
    if (s->server_port > 0) {
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"key\":\"server.port\",\"value\":{\"intValue\":"); jw_i64q(&w, s->server_port); jw_raw(&w, "}}");
    }
    jw_res_kv(&w, &first, "client.address", s->client_address);
    jw_res_kv(&w, &first, "url.scheme", s->url_scheme);
    jw_res_kv(&w, &first, "http.route", s->route);
    /* Cross-layer attributes: the application-level tenant, and the
     * connection-keyed TCP counters. */
    jw_res_kv(&w, &first, "tenant", s->tenant);
    if (s->tcp_established >= 0) {
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"key\":\"net.tcp.established\",\"value\":{\"intValue\":"); jw_i64q(&w, s->tcp_established); jw_raw(&w, "}}");
    }
    if (s->tcp_state_changes >= 0) {
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"key\":\"net.tcp.state_changes\",\"value\":{\"intValue\":"); jw_i64q(&w, s->tcp_state_changes); jw_raw(&w, "}}");
    }
    jw_raw(&w, "]");  /* close attributes */
    /* A status of 500 or above sets Span.status to ERROR (code 2); otherwise the
     * field is omitted, which means UNSET. */
    if (s->status_code >= 500) jw_raw(&w, ",\"status\":{\"code\":2}");
    /* Close it all out: span, spans, scopeSpans object, scopeSpans,
     * resourceSpans object, resourceSpans, and the top-level object. */
    jw_raw(&w, "}]}]}]}");
    return w.ok ? (long)w.n : -1;
}

/* An arbitrary label array, "attributes":[{key,stringValue}...]. */
static void jw_labels(jw_t *w, const otlp_kv_t *labels, int nlabels) {
    jw_raw(w, "\"attributes\":[");
    for (int i = 0; i < nlabels; i++) {
        if (i) jw_ch(w, ',');
        jw_raw(w, "{\"key\":"); jw_jstr(w, labels[i].key);
        jw_raw(w, ",\"value\":{\"stringValue\":"); jw_jstr(w, labels[i].val); jw_raw(w, "}}");
    }
    jw_raw(w, "]");
}
static void jw_series_attrs(jw_t *w, const otlp_series_t *s) { jw_labels(w, s->labels, s->nlabels); }

/* A Sum on its own; the protobuf twin is otlp_metrics_sum_build. It lives in both
 * encoders so that a counter cannot be declarable and yet unemittable over
 * http/json. */
long otlp_json_metrics_sum_build(char *buf, size_t cap,
                                 const char *svc, const char *ver, const char *scope,
                                 const char *name, const char *unit,
                                 uint64_t t, uint64_t start,
                                 const otlp_series_t *series, size_t n) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceMetrics\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeMetrics\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"metrics\":[");
    jw_raw(&w, "{\"name\":"); jw_jstr(&w, name);
    if (unit && unit[0]) { jw_raw(&w, ",\"unit\":"); jw_jstr(&w, unit); }
    jw_raw(&w, ",\"sum\":{\"dataPoints\":[");
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        const otlp_series_t *s = &series[i];
        if (s->count == 0) continue;
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"startTimeUnixNano\":"); jw_u64q(&w, start);
        jw_raw(&w, ",\"timeUnixNano\":"); jw_u64q(&w, t);
        jw_raw(&w, ",\"asInt\":"); jw_i64q(&w, (int64_t)s->count);
        jw_ch(&w, ','); jw_series_attrs(&w, s);
        jw_ch(&w, '}');
    }
    jw_raw(&w, "],\"aggregationTemporality\":2,\"isMonotonic\":true}}");
    jw_raw(&w, "]}]}]}");
    return w.ok ? (long)w.n : -1;
}

/* An ExponentialHistogram on its own; the protobuf twin is
 * otlp_metrics_exphist_build. There used to be only a builder that emitted it
 * paired with the Sum, which put two metric types in one request, so a backend
 * refusing one of them dropped the other as well. */
long otlp_json_metrics_exphist_build(char *buf, size_t cap,
                                     const char *svc, const char *ver, const char *scope,
                                     const char *name, const char *unit,
                                     uint64_t t, uint64_t start,
                                     const otlp_series_t *series, size_t n) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceMetrics\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeMetrics\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"metrics\":[");
    jw_raw(&w, "{\"name\":"); jw_jstr(&w, name);
    if (unit && unit[0]) { jw_raw(&w, ",\"unit\":"); jw_jstr(&w, unit); }
    jw_raw(&w, ",\"exponentialHistogram\":{\"dataPoints\":[");
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        const otlp_series_t *s = &series[i];
        if (s->count == 0) continue;
        int fs = -1, ls = -1; uint64_t total = 0; double sum = 0.0;
        for (int sl = 0; sl < OTLP_HIST_SLOTS; sl++) {
            uint64_t cnt = s->buckets[sl];
            if (cnt == 0) continue;
            if (fs < 0) fs = sl;
            ls = sl; total += cnt; sum += (double)cnt * slot_midpoint(sl);
        }
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"startTimeUnixNano\":"); jw_u64q(&w, start);
        jw_raw(&w, ",\"timeUnixNano\":"); jw_u64q(&w, t);
        jw_raw(&w, ",\"count\":"); jw_u64q(&w, total);
        jw_raw(&w, ",\"sum\":"); jw_dbl(&w, sum);
        jw_raw(&w, ",\"scale\":0,\"zeroCount\":\"0\"");
        if (fs >= 0) {
            jw_raw(&w, ",\"positive\":{\"offset\":"); jw_int(&w, fs);
            jw_raw(&w, ",\"bucketCounts\":[");
            for (int sl = fs; sl <= ls; sl++) { if (sl > fs) jw_ch(&w, ','); jw_u64q(&w, s->buckets[sl]); }
            jw_raw(&w, "]}");
        }
        jw_ch(&w, ','); jw_series_attrs(&w, s);
        jw_ch(&w, '}');
    }
    jw_raw(&w, "],\"aggregationTemporality\":2}}");
    jw_raw(&w, "]}]}]}");
    return w.ok ? (long)w.n : -1;
}

long otlp_json_logs_build(char *buf, size_t cap,
                          const char *svc, const char *ver, const char *scope,
                          const otlp_log_record_t *recs, size_t nrecs) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceLogs\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeLogs\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"logRecords\":[");
    for (size_t i = 0; i < nrecs; i++) {
        const otlp_log_record_t *r = &recs[i];
        if (i) jw_ch(&w, ',');
        jw_raw(&w, "{\"timeUnixNano\":"); jw_u64q(&w, r->time_unix_ns);
        jw_raw(&w, ",\"observedTimeUnixNano\":"); jw_u64q(&w, r->time_unix_ns);
        jw_raw(&w, ",\"severityNumber\":"); jw_int(&w, r->severity ? r->severity : 9);
        jw_raw(&w, ",\"severityText\":\"INFO\",\"body\":{");
        if (r->body_is_str) { jw_raw(&w, "\"stringValue\":"); jw_jstr(&w, r->body_str ? r->body_str : ""); }
        else { jw_raw(&w, "\"intValue\":"); jw_i64q(&w, r->body_int); }
        jw_ch(&w, '}');
        if (r->event_name && r->event_name[0]) { jw_raw(&w, ",\"eventName\":"); jw_jstr(&w, r->event_name); }
        jw_ch(&w, '}');
    }
    jw_raw(&w, "]}]}]}");
    return w.ok ? (long)w.n : -1;
}

long otlp_json_metrics_hist_build(char *buf, size_t cap,
                                  const char *svc, const char *ver, const char *scope,
                                  const char *name, const char *unit,
                                  const double *bounds, int nbounds,
                                  uint64_t t, uint64_t start,
                                  const otlp_hseries_t *series, size_t n) {
    jw_t w = { buf, cap, 0, 1 };
    jw_raw(&w, "{\"resourceMetrics\":[{");
    jw_resource(&w, svc, ver);
    jw_raw(&w, ",\"scopeMetrics\":[{");
    jw_scope(&w, scope);
    jw_raw(&w, ",\"metrics\":[{\"name\":"); jw_jstr(&w, name);
    if (unit && unit[0]) { jw_raw(&w, ",\"unit\":"); jw_jstr(&w, unit); }
    jw_raw(&w, ",\"histogram\":{\"dataPoints\":[");
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        const otlp_hseries_t *s = &series[i];
        if (s->count == 0) continue;
        if (!first) jw_ch(&w, ','); first = 0;
        jw_raw(&w, "{\"startTimeUnixNano\":"); jw_u64q(&w, start);
        jw_raw(&w, ",\"timeUnixNano\":"); jw_u64q(&w, t);
        jw_raw(&w, ",\"count\":"); jw_u64q(&w, s->count);
        jw_raw(&w, ",\"sum\":"); jw_dbl(&w, s->sum);
        jw_raw(&w, ",\"bucketCounts\":[");
        for (int b = 0; b <= nbounds; b++) { if (b) jw_ch(&w, ','); jw_u64q(&w, s->bucket_counts[b]); }
        jw_raw(&w, "],\"explicitBounds\":[");
        for (int b = 0; b < nbounds; b++) { if (b) jw_ch(&w, ','); jw_dbl(&w, bounds[b]); }
        jw_raw(&w, "],");
        jw_labels(&w, s->labels, s->nlabels);
        jw_ch(&w, '}');
    }
    jw_raw(&w, "],\"aggregationTemporality\":2}}]}]}]}");
    return w.ok ? (long)w.n : -1;
}
