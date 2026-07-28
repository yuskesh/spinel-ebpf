/*
 * otlp_sample_metrics.h -- hand-built encoder for a test OTLP
 * ExportMetricsServiceRequest.
 *
 * Shared by the round-trip test and the HTTP send test. Strings and repeated fields
 * are supplied through nanopb CALLBACK fields, so nothing is malloc'd. This is also
 * the skeleton the real metrics exporter grew out of.
 *
 * Contents: 1 ResourceMetrics (resource.attributes=[service.name=spinel-app]) ->
 *           1 ScopeMetrics (scope.name=spinel-ebpf) -> 1 Metric (spnl_method_calls_total) ->
 *           Sum{CUMULATIVE, monotonic, dataPoints=[{as_int=500, time, code.function=fib}]}
 */
#ifndef OTLP_SAMPLE_METRICS_H
#define OTLP_SAMPLE_METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <pb_encode.h>
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"

/* encode callback for a string field (arg = const char *) */
static bool otlp__enc_string(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const char *s = (const char *)(*arg);
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_string(st, (const pb_byte_t *)s, strlen(s));
}

/* generic callback that encodes a single submessage (arg = otlp__one_sub_t *) */
typedef struct { const pb_msgdesc_t *fields; const void *msg; } otlp__one_sub_t;
static bool otlp__enc_one_sub(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const otlp__one_sub_t *o = (const otlp__one_sub_t *)(*arg);
    if (!pb_encode_tag_for_field(st, fld)) return false;
    return pb_encode_submessage(st, o->fields, o->msg);
}

/* Encode the sample ExportMetricsServiceRequest into buf. Returns the byte count
 * on success, -1 on failure. */
static inline long otlp_build_sample_metrics(uint8_t *buf, size_t cap) {
    /* Resource attribute: service.name = "spinel-app" */
    opentelemetry_proto_common_v1_AnyValue av_svc =
        opentelemetry_proto_common_v1_AnyValue_init_zero;
    av_svc.which_value = opentelemetry_proto_common_v1_AnyValue_string_value_tag;
    av_svc.value.string_value.funcs.encode = otlp__enc_string;
    av_svc.value.string_value.arg = (void *)"spinel-app";

    opentelemetry_proto_common_v1_KeyValue kv_svc =
        opentelemetry_proto_common_v1_KeyValue_init_zero;
    kv_svc.key.funcs.encode = otlp__enc_string;
    kv_svc.key.arg = (void *)"service.name";
    kv_svc.has_value = true;
    kv_svc.value = av_svc;
    otlp__one_sub_t sub_kv_svc = { opentelemetry_proto_common_v1_KeyValue_fields, &kv_svc };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp__enc_one_sub;
    res.attributes.arg = &sub_kv_svc;

    /* data point attribute: code.function = "fib" (standing in for a symbol-map entry) */
    opentelemetry_proto_common_v1_AnyValue av_fn =
        opentelemetry_proto_common_v1_AnyValue_init_zero;
    av_fn.which_value = opentelemetry_proto_common_v1_AnyValue_string_value_tag;
    av_fn.value.string_value.funcs.encode = otlp__enc_string;
    av_fn.value.string_value.arg = (void *)"fib";

    opentelemetry_proto_common_v1_KeyValue kv_fn =
        opentelemetry_proto_common_v1_KeyValue_init_zero;
    kv_fn.key.funcs.encode = otlp__enc_string;
    kv_fn.key.arg = (void *)"code.function";
    kv_fn.has_value = true;
    kv_fn.value = av_fn;
    otlp__one_sub_t sub_kv_fn = { opentelemetry_proto_common_v1_KeyValue_fields, &kv_fn };

    /* NumberDataPoint: as_int = 500 @ t */
    opentelemetry_proto_metrics_v1_NumberDataPoint dp =
        opentelemetry_proto_metrics_v1_NumberDataPoint_init_zero;
    dp.time_unix_nano = 1700000000000000000ULL;
    dp.which_value = opentelemetry_proto_metrics_v1_NumberDataPoint_as_int_tag;
    dp.value.as_int = 500;
    dp.attributes.funcs.encode = otlp__enc_one_sub;
    dp.attributes.arg = &sub_kv_fn;
    otlp__one_sub_t sub_dp = { opentelemetry_proto_metrics_v1_NumberDataPoint_fields, &dp };

    /* Sum (monotonic, CUMULATIVE) */
    opentelemetry_proto_metrics_v1_Sum sum = opentelemetry_proto_metrics_v1_Sum_init_zero;
    sum.data_points.funcs.encode = otlp__enc_one_sub;
    sum.data_points.arg = &sub_dp;
    sum.aggregation_temporality =
        opentelemetry_proto_metrics_v1_AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE;
    sum.is_monotonic = true;

    /* Metric: name = spnl_method_calls_total, data = sum */
    opentelemetry_proto_metrics_v1_Metric metric =
        opentelemetry_proto_metrics_v1_Metric_init_zero;
    metric.name.funcs.encode = otlp__enc_string;
    metric.name.arg = (void *)"spnl_method_calls_total";
    metric.which_data = opentelemetry_proto_metrics_v1_Metric_sum_tag;
    metric.data.sum = sum;
    otlp__one_sub_t sub_metric = { opentelemetry_proto_metrics_v1_Metric_fields, &metric };

    /* ScopeMetrics: scope.name = spinel-ebpf */
    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp__enc_string;
    scope.name.arg = (void *)"spinel-ebpf";

    opentelemetry_proto_metrics_v1_ScopeMetrics sm =
        opentelemetry_proto_metrics_v1_ScopeMetrics_init_zero;
    sm.has_scope = true;
    sm.scope = scope;
    sm.metrics.funcs.encode = otlp__enc_one_sub;
    sm.metrics.arg = &sub_metric;
    otlp__one_sub_t sub_sm = { opentelemetry_proto_metrics_v1_ScopeMetrics_fields, &sm };

    /* ResourceMetrics */
    opentelemetry_proto_metrics_v1_ResourceMetrics rm =
        opentelemetry_proto_metrics_v1_ResourceMetrics_init_zero;
    rm.has_resource = true;
    rm.resource = res;
    rm.scope_metrics.funcs.encode = otlp__enc_one_sub;
    rm.scope_metrics.arg = &sub_sm;
    otlp__one_sub_t sub_rm = { opentelemetry_proto_metrics_v1_ResourceMetrics_fields, &rm };

    /* top-level request */
    opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest req =
        opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_init_zero;
    req.resource_metrics.funcs.encode = otlp__enc_one_sub;
    req.resource_metrics.arg = &sub_rm;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_metrics_v1_ExportMetricsServiceRequest_fields, &req)) {
        return -1;
    }
    return (long)st.bytes_written;
}

#endif /* OTLP_SAMPLE_METRICS_H */
