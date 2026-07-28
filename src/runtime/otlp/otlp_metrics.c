/*
 * otlp_metrics.c -- encode per-method RED measurements as OTLP metrics.
 * See otlp_metrics.h; the shared nanopb helpers are in otlp_pbutil.h.
 */
#include "otlp_metrics.h"
#include "otlp_pbutil.h"  /* otlp_enc_string / otlp_put_kv_* / otlp_enc_one_sub / otlp_resource_t */
#include "otlp_http.h"
#include "otlp_grpc.h"    /* otlp_transport_send (http/grpc routing) */
#include "otlp_json.h"    /* otlp_want_json / otlp_endpoint_is_grpc / otlp_json_metrics_build */

#include <stdio.h>
#include <string.h>

#include <pb_encode.h>
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"

/* The code.* attributes; arg is a const otlp_method_metric_t*. */
static bool enc_code_attrs(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp_method_metric_t *m = (const otlp_method_metric_t *)(*arg);
    if (!otlp_put_kv_str(st, fld, "code.function", m->method)) return false;
    if (m->file && m->file[0] && !otlp_put_kv_str(st, fld, "code.filepath", m->file)) return false;
    if (m->line > 0 && !otlp_put_kv_int(st, fld, "code.lineno", m->line)) return false;
    return true;
}

/* ---- histograms ---- */

/* Representative value for slot s, which holds floor(log2(v)): about 1.5 * 2^s,
 * and about 1 for slot 0. */
static double slot_midpoint(int s) {
    if (s <= 0) return 1.0;
    return 1.5 * (double)((uint64_t)1 << s);
}

typedef struct {
    const uint64_t *buckets;
    int offset;
    int len;
} buckets_ctx_t;

/* repeated UINT64 bucket_counts, unpacked -- accepted by both protoc and nanopb. */
static bool enc_bucket_counts(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const buckets_ctx_t *b = (const buckets_ctx_t *)(*arg);
    for (int i = 0; i < b->len; i++) {
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_varint(st, b->buckets[b->offset + i])) return false;
    }
    return true;
}

/* ---- data points, looping over the methods array ---- */

typedef struct {
    const otlp_method_metric_t *methods;
    size_t n;
    uint64_t t;
    uint64_t start;
} dp_ctx_t;

/* The NumberDataPoints of spnl_method_calls_total. */
static bool enc_calls_dps(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const dp_ctx_t *c = (const dp_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_method_metric_t *m = &c->methods[i];
        if (m->calls == 0) continue;
        opentelemetry_proto_metrics_v1_NumberDataPoint dp =
            opentelemetry_proto_metrics_v1_NumberDataPoint_init_zero;
        dp.time_unix_nano = c->t;
        dp.start_time_unix_nano = c->start;
        dp.which_value = opentelemetry_proto_metrics_v1_NumberDataPoint_as_int_tag;
        dp.value.as_int = (int64_t)m->calls;
        dp.attributes.funcs.encode = enc_code_attrs;
        dp.attributes.arg = (void *)m;
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st,
                opentelemetry_proto_metrics_v1_NumberDataPoint_fields, &dp)) return false;
    }
    return true;
}

/* The ExponentialHistogramDataPoints of spnl_method_latency_ns. */
static bool enc_lat_dps(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const dp_ctx_t *c = (const dp_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_method_metric_t *m = &c->methods[i];
        if (m->calls == 0) continue;

        int first = -1, last = -1;
        uint64_t total = 0;
        double sum = 0.0;
        for (int s = 0; s < OTLP_HIST_SLOTS; s++) {
            uint64_t cnt = m->buckets[s];
            if (cnt == 0) continue;
            if (first < 0) first = s;
            last = s;
            total += cnt;
            sum += (double)cnt * slot_midpoint(s);
        }

        opentelemetry_proto_metrics_v1_ExponentialHistogramDataPoint dp =
            opentelemetry_proto_metrics_v1_ExponentialHistogramDataPoint_init_zero;
        dp.time_unix_nano = c->t;
        dp.start_time_unix_nano = c->start;
        dp.count = total;
        dp.has_sum = true;
        dp.sum = sum;
        dp.scale = 0;        /* base = 2 */
        dp.zero_count = 0;
        dp.attributes.funcs.encode = enc_code_attrs;
        dp.attributes.arg = (void *)m;

        buckets_ctx_t bctx = { m->buckets, 0, 0 };
        if (first >= 0) {
            bctx.offset = first;
            bctx.len = last - first + 1;
            dp.has_positive = true;
            dp.positive.offset = first;  /* slot s maps to positive bucket s */
            dp.positive.bucket_counts.funcs.encode = enc_bucket_counts;
            dp.positive.bucket_counts.arg = &bctx;
        }

        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st,
                opentelemetry_proto_metrics_v1_ExponentialHistogramDataPoint_fields, &dp))
            return false;
    }
    return true;
}

/* ScopeMetrics.metrics: [calls(Sum), latency(ExponentialHistogram)] */
static bool enc_metrics(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    dp_ctx_t *c = (dp_ctx_t *)(*arg);

    opentelemetry_proto_metrics_v1_Metric m_calls =
        opentelemetry_proto_metrics_v1_Metric_init_zero;
    m_calls.name.funcs.encode = otlp_enc_string;
    m_calls.name.arg = (void *)"spnl_method_calls_total";
    m_calls.which_data = opentelemetry_proto_metrics_v1_Metric_sum_tag;
    m_calls.data.sum.data_points.funcs.encode = enc_calls_dps;
    m_calls.data.sum.data_points.arg = c;
    m_calls.data.sum.aggregation_temporality =
        opentelemetry_proto_metrics_v1_AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE;
    m_calls.data.sum.is_monotonic = true;
    if (!pb_encode_tag_for_field(st, fld)) return false;
    if (!pb_encode_submessage(st, opentelemetry_proto_metrics_v1_Metric_fields, &m_calls))
        return false;

    opentelemetry_proto_metrics_v1_Metric m_lat =
        opentelemetry_proto_metrics_v1_Metric_init_zero;
    m_lat.name.funcs.encode = otlp_enc_string;
    m_lat.name.arg = (void *)"spnl_method_latency_ns";
    m_lat.unit.funcs.encode = otlp_enc_string;
    m_lat.unit.arg = (void *)"ns";
    m_lat.which_data = opentelemetry_proto_metrics_v1_Metric_exponential_histogram_tag;
    m_lat.data.exponential_histogram.data_points.funcs.encode = enc_lat_dps;
    m_lat.data.exponential_histogram.data_points.arg = c;
    m_lat.data.exponential_histogram.aggregation_temporality =
        opentelemetry_proto_metrics_v1_AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE;
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_submessage(st, opentelemetry_proto_metrics_v1_Metric_fields, &m_lat);
}

/* ---- top-level ---- */

long otlp_metrics_build(uint8_t *buf, size_t cap,
                        const char *service_name, const char *service_version,
                        const char *scope_name,
                        uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                        const otlp_method_metric_t *methods, size_t nmethods) {
    dp_ctx_t dpctx = { methods, nmethods, time_unix_nano, start_time_unix_nano };
    otlp_resource_t rctx = { service_name, service_version };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_metrics_v1_ScopeMetrics sm =
        opentelemetry_proto_metrics_v1_ScopeMetrics_init_zero;
    sm.has_scope = true;
    sm.scope = scope;
    sm.metrics.funcs.encode = enc_metrics;
    sm.metrics.arg = &dpctx;
    otlp_one_sub_t sm_sub = { opentelemetry_proto_metrics_v1_ScopeMetrics_fields, &sm };

    opentelemetry_proto_metrics_v1_ResourceMetrics rm =
        opentelemetry_proto_metrics_v1_ResourceMetrics_init_zero;
    rm.has_resource = true;
    rm.resource = res;
    rm.scope_metrics.funcs.encode = otlp_enc_one_sub;
    rm.scope_metrics.arg = &sm_sub;
    otlp_one_sub_t rm_sub = { opentelemetry_proto_metrics_v1_ResourceMetrics_fields, &rm };

    opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest req =
        opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_init_zero;
    req.resource_metrics.funcs.encode = otlp_enc_one_sub;
    req.resource_metrics.arg = &rm_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}

/* ---- generic keyed metrics: arbitrary labels, nothing to do with --instrument ---- */

static bool enc_series_attrs(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp_series_t *s = (const otlp_series_t *)(*arg);
    for (int i = 0; i < s->nlabels; i++)
        if (!otlp_put_kv_str(st, fld, s->labels[i].key, s->labels[i].val)) return false;
    return true;
}

typedef struct { const otlp_series_t *series; size_t n; uint64_t t; uint64_t start; } sdp_ctx_t;

static bool enc_series_calls(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const sdp_ctx_t *c = (const sdp_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_series_t *s = &c->series[i];
        if (s->count == 0) continue;
        opentelemetry_proto_metrics_v1_NumberDataPoint dp =
            opentelemetry_proto_metrics_v1_NumberDataPoint_init_zero;
        dp.time_unix_nano = c->t;
        dp.start_time_unix_nano = c->start;
        dp.which_value = opentelemetry_proto_metrics_v1_NumberDataPoint_as_int_tag;
        dp.value.as_int = (int64_t)s->count;
        dp.attributes.funcs.encode = enc_series_attrs;
        dp.attributes.arg = (void *)s;
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st,
                opentelemetry_proto_metrics_v1_NumberDataPoint_fields, &dp)) return false;
    }
    return true;
}

static bool enc_series_lat(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const sdp_ctx_t *c = (const sdp_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_series_t *s = &c->series[i];
        if (s->count == 0) continue;
        int first = -1, last = -1; uint64_t total = 0; double sum = 0.0;
        for (int sl = 0; sl < OTLP_HIST_SLOTS; sl++) {
            uint64_t cnt = s->buckets[sl];
            if (cnt == 0) continue;
            if (first < 0) first = sl;
            last = sl; total += cnt; sum += (double)cnt * slot_midpoint(sl);
        }
        opentelemetry_proto_metrics_v1_ExponentialHistogramDataPoint dp =
            opentelemetry_proto_metrics_v1_ExponentialHistogramDataPoint_init_zero;
        dp.time_unix_nano = c->t;
        dp.start_time_unix_nano = c->start;
        dp.count = total; dp.has_sum = true; dp.sum = sum; dp.scale = 0; dp.zero_count = 0;
        dp.attributes.funcs.encode = enc_series_attrs;
        dp.attributes.arg = (void *)s;
        buckets_ctx_t bctx = { s->buckets, 0, 0 };
        if (first >= 0) {
            bctx.offset = first; bctx.len = last - first + 1;
            dp.has_positive = true;
            dp.positive.offset = first;
            dp.positive.bucket_counts.funcs.encode = enc_bucket_counts;
            dp.positive.bucket_counts.arg = &bctx;
        }
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st,
                opentelemetry_proto_metrics_v1_ExponentialHistogramDataPoint_fields, &dp))
            return false;
    }
    return true;
}

typedef struct { sdp_ctx_t *dp; const char *name; const char *lat_name; const char *unit; } smetrics_ctx_t;

static bool enc_series_metrics(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    smetrics_ctx_t *c = (smetrics_ctx_t *)(*arg);

    opentelemetry_proto_metrics_v1_Metric m_calls =
        opentelemetry_proto_metrics_v1_Metric_init_zero;
    m_calls.name.funcs.encode = otlp_enc_string;
    m_calls.name.arg = (void *)c->name;
    m_calls.which_data = opentelemetry_proto_metrics_v1_Metric_sum_tag;
    m_calls.data.sum.data_points.funcs.encode = enc_series_calls;
    m_calls.data.sum.data_points.arg = c->dp;
    m_calls.data.sum.aggregation_temporality =
        opentelemetry_proto_metrics_v1_AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE;
    m_calls.data.sum.is_monotonic = true;
    if (!pb_encode_tag_for_field(st, fld)) return false;
    if (!pb_encode_submessage(st, opentelemetry_proto_metrics_v1_Metric_fields, &m_calls))
        return false;

    opentelemetry_proto_metrics_v1_Metric m_lat =
        opentelemetry_proto_metrics_v1_Metric_init_zero;
    m_lat.name.funcs.encode = otlp_enc_string;
    m_lat.name.arg = (void *)c->lat_name;
    if (c->unit && c->unit[0]) { m_lat.unit.funcs.encode = otlp_enc_string; m_lat.unit.arg = (void *)c->unit; }
    m_lat.which_data = opentelemetry_proto_metrics_v1_Metric_exponential_histogram_tag;
    m_lat.data.exponential_histogram.data_points.funcs.encode = enc_series_lat;
    m_lat.data.exponential_histogram.data_points.arg = c->dp;
    m_lat.data.exponential_histogram.aggregation_temporality =
        opentelemetry_proto_metrics_v1_AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE;
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_submessage(st, opentelemetry_proto_metrics_v1_Metric_fields, &m_lat);
}

long otlp_metrics_series_build(uint8_t *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name,
                               const char *name, const char *lat_name, const char *unit,
                               uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                               const otlp_series_t *series, size_t nseries) {
    sdp_ctx_t dpctx = { series, nseries, time_unix_nano, start_time_unix_nano };
    smetrics_ctx_t mctx = { &dpctx, name, lat_name, unit };
    otlp_resource_t rctx = { service_name, service_version };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_metrics_v1_ScopeMetrics sm =
        opentelemetry_proto_metrics_v1_ScopeMetrics_init_zero;
    sm.has_scope = true;
    sm.scope = scope;
    sm.metrics.funcs.encode = enc_series_metrics;
    sm.metrics.arg = &mctx;
    otlp_one_sub_t sm_sub = { opentelemetry_proto_metrics_v1_ScopeMetrics_fields, &sm };

    opentelemetry_proto_metrics_v1_ResourceMetrics rm =
        opentelemetry_proto_metrics_v1_ResourceMetrics_init_zero;
    rm.has_resource = true;
    rm.resource = res;
    rm.scope_metrics.funcs.encode = otlp_enc_one_sub;
    rm.scope_metrics.arg = &sm_sub;
    otlp_one_sub_t rm_sub = { opentelemetry_proto_metrics_v1_ResourceMetrics_fields, &rm };

    opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest req =
        opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_init_zero;
    req.resource_metrics.funcs.encode = otlp_enc_one_sub;
    req.resource_metrics.arg = &rm_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}

/* ---- explicit-bounds Histogram, as used by http.server.request.duration ---- */

/* repeated double explicit_bounds, unpacked -- accepted by both protoc and nanopb. */
typedef struct { const double *b; int n; } bounds_ctx_t;
static bool enc_explicit_bounds(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const bounds_ctx_t *b = (const bounds_ctx_t *)(*arg);
    for (int i = 0; i < b->n; i++) {
        double d = b->b[i];
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_fixed64(st, &d)) return false;  /* a double is 64-bit fixed */
    }
    return true;
}

/* HistogramDataPoint.bucket_counts is repeated *fixed64*, a different wire type
 * from the repeated uint64 of ExponentialHistogram. The tag is emitted as 64-bit
 * from the field descriptor, so the values go out as 8 bytes each too. */
static bool enc_hist_bucket_counts(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const buckets_ctx_t *b = (const buckets_ctx_t *)(*arg);
    for (int i = 0; i < b->len; i++) {
        uint64_t v = b->buckets[b->offset + i];
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_fixed64(st, &v)) return false;
    }
    return true;
}

/* A series' arbitrary labels; arg is a const otlp_hseries_t*. */
static bool enc_hseries_attrs(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp_hseries_t *s = (const otlp_hseries_t *)(*arg);
    for (int i = 0; i < s->nlabels; i++)
        if (!otlp_put_kv_str(st, fld, s->labels[i].key, s->labels[i].val)) return false;
    return true;
}

typedef struct {
    const otlp_hseries_t *series; size_t n;
    const double *bounds; int nbounds;
    uint64_t t; uint64_t start;
} hdp_ctx_t;

/* The HistogramDataPoints. */
static bool enc_hist_dps(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const hdp_ctx_t *c = (const hdp_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_hseries_t *s = &c->series[i];
        opentelemetry_proto_metrics_v1_HistogramDataPoint dp =
            opentelemetry_proto_metrics_v1_HistogramDataPoint_init_zero;
        dp.time_unix_nano = c->t;
        dp.start_time_unix_nano = c->start;
        dp.count = s->count;
        dp.has_sum = true;
        dp.sum = s->sum;
        buckets_ctx_t bc = { s->bucket_counts, 0, c->nbounds + 1 };
        dp.bucket_counts.funcs.encode = enc_hist_bucket_counts;
        dp.bucket_counts.arg = &bc;
        bounds_ctx_t bn = { c->bounds, c->nbounds };
        dp.explicit_bounds.funcs.encode = enc_explicit_bounds;
        dp.explicit_bounds.arg = &bn;
        dp.attributes.funcs.encode = enc_hseries_attrs;
        dp.attributes.arg = (void *)s;
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st,
                opentelemetry_proto_metrics_v1_HistogramDataPoint_fields, &dp)) return false;
    }
    return true;
}

typedef struct { hdp_ctx_t *dp; const char *name; const char *unit; } hmetric_ctx_t;

/* ScopeMetrics.metrics: [ Histogram(name, unit, CUMULATIVE) ] */
static bool enc_hist_metric(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    hmetric_ctx_t *c = (hmetric_ctx_t *)(*arg);
    opentelemetry_proto_metrics_v1_Metric m = opentelemetry_proto_metrics_v1_Metric_init_zero;
    m.name.funcs.encode = otlp_enc_string;
    m.name.arg = (void *)c->name;
    if (c->unit && c->unit[0]) { m.unit.funcs.encode = otlp_enc_string; m.unit.arg = (void *)c->unit; }
    m.which_data = opentelemetry_proto_metrics_v1_Metric_histogram_tag;
    m.data.histogram.data_points.funcs.encode = enc_hist_dps;
    m.data.histogram.data_points.arg = c->dp;
    m.data.histogram.aggregation_temporality =
        opentelemetry_proto_metrics_v1_AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE;
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_submessage(st, opentelemetry_proto_metrics_v1_Metric_fields, &m);
}

long otlp_metrics_hist_build(uint8_t *buf, size_t cap,
                             const char *service_name, const char *service_version,
                             const char *scope_name,
                             const char *name, const char *unit,
                             const double *bounds, int nbounds,
                             uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                             const otlp_hseries_t *series, size_t nseries) {
    hdp_ctx_t dpctx = { series, nseries, bounds, nbounds, time_unix_nano, start_time_unix_nano };
    hmetric_ctx_t mctx = { &dpctx, name, unit };
    otlp_resource_t rctx = { service_name, service_version };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_metrics_v1_ScopeMetrics sm =
        opentelemetry_proto_metrics_v1_ScopeMetrics_init_zero;
    sm.has_scope = true;
    sm.scope = scope;
    sm.metrics.funcs.encode = enc_hist_metric;
    sm.metrics.arg = &mctx;
    otlp_one_sub_t sm_sub = { opentelemetry_proto_metrics_v1_ScopeMetrics_fields, &sm };

    opentelemetry_proto_metrics_v1_ResourceMetrics rm =
        opentelemetry_proto_metrics_v1_ResourceMetrics_init_zero;
    rm.has_resource = true;
    rm.resource = res;
    rm.scope_metrics.funcs.encode = otlp_enc_one_sub;
    rm.scope_metrics.arg = &sm_sub;
    otlp_one_sub_t rm_sub = { opentelemetry_proto_metrics_v1_ResourceMetrics_fields, &rm };

    opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest req =
        opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_init_zero;
    req.resource_metrics.funcs.encode = otlp_enc_one_sub;
    req.resource_metrics.arg = &rm_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}

int otlp_metrics_export(const char *endpoint,
                        const char *service_name, const char *service_version,
                        const char *scope_name,
                        uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                        const otlp_method_metric_t *methods, size_t nmethods,
                        int *http_status, char *err, size_t errlen) {
    static uint8_t buf[1 << 18]; /* 256 KB, ample even for the ~1024-method ceiling */
    long n;
    const char *ct;
    const uint8_t *body;
    /* JSON when http/json was asked for and the endpoint is not gRPC; protobuf
     * otherwise, since gRPC always carries protobuf. */
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        static char jbuf[1 << 19];
        n = otlp_json_metrics_build(jbuf, sizeof jbuf, service_name, service_version, scope_name,
                                    time_unix_nano, start_time_unix_nano, methods, nmethods);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        n = otlp_metrics_build(buf, sizeof buf, service_name, service_version, scope_name,
                               time_unix_nano, start_time_unix_nano, methods, nmethods);
        body = buf; ct = "application/x-protobuf";
    }
    if (n < 0) {
        if (err && errlen) snprintf(err, errlen, "encode failed (buffer too small?)");
        return -1;
    }
    return otlp_transport_send(endpoint, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                               ct, body, (size_t)n, http_status, err, errlen);
}
