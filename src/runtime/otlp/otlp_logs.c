/*
 * otlp_logs.c — emit イベント -> OTLP logs エンコーダ
 * 詳細は otlp_logs.h を参照。
 */
#include "otlp_logs.h"
#include "otlp_pbutil.h"  /* otlp_enc_string / otlp_enc_one_sub / otlp_resource_t */

#include <string.h>

#include <pb_encode.h>
#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"

typedef struct {
    const otlp_log_record_t *recs; size_t n;
} log_ctx_t;

/* ScopeLogs.log_records: LogRecord 群 (arg = log_ctx_t*) */
static bool enc_log_records(pb_ostream_t *st, const pb_field_iter_t *fld, void *const *arg) {
    const log_ctx_t *c = (const log_ctx_t *)(*arg);
    for (size_t i = 0; i < c->n; i++) {
        const otlp_log_record_t *r = &c->recs[i];
        opentelemetry_proto_logs_v1_LogRecord lr = opentelemetry_proto_logs_v1_LogRecord_init_zero;
        lr.time_unix_nano = r->time_unix_ns;
        lr.observed_time_unix_nano = r->time_unix_ns;
        lr.severity_number = (opentelemetry_proto_logs_v1_SeverityNumber)
            (r->severity ? r->severity
                         : opentelemetry_proto_logs_v1_SeverityNumber_SEVERITY_NUMBER_INFO);
        lr.severity_text.funcs.encode = otlp_enc_string;
        lr.severity_text.arg = (void *)"INFO";
        lr.has_body = true;
        if (r->body_is_str) {
            lr.body.which_value = opentelemetry_proto_common_v1_AnyValue_string_value_tag;
            lr.body.value.string_value.funcs.encode = otlp_enc_string;
            lr.body.value.string_value.arg = (void *)(r->body_str ? r->body_str : "");
        } else {
            lr.body.which_value = opentelemetry_proto_common_v1_AnyValue_int_value_tag;
            lr.body.value.int_value = r->body_int;
        }
        if (r->event_name && r->event_name[0]) {
            lr.event_name.funcs.encode = otlp_enc_string;
            lr.event_name.arg = (void *)r->event_name;
        }
        if (!pb_encode_tag_for_field(st, fld)) return false;
        if (!pb_encode_submessage(st, opentelemetry_proto_logs_v1_LogRecord_fields, &lr)) return false;
    }
    return true;
}

long otlp_logs_build(uint8_t *buf, size_t cap,
                     const char *service_name, const char *service_version,
                     const char *scope_name,
                     const otlp_log_record_t *recs, size_t nrecs) {
    log_ctx_t lctx = { recs, nrecs };
    otlp_resource_t rctx = { service_name, service_version };

    opentelemetry_proto_resource_v1_Resource res =
        opentelemetry_proto_resource_v1_Resource_init_zero;
    res.attributes.funcs.encode = otlp_enc_resource_attrs;
    res.attributes.arg = &rctx;

    opentelemetry_proto_common_v1_InstrumentationScope scope =
        opentelemetry_proto_common_v1_InstrumentationScope_init_zero;
    scope.name.funcs.encode = otlp_enc_string;
    scope.name.arg = (void *)(scope_name ? scope_name : "spinel-ebpf");

    opentelemetry_proto_logs_v1_ScopeLogs sl = opentelemetry_proto_logs_v1_ScopeLogs_init_zero;
    sl.has_scope = true;
    sl.scope = scope;
    sl.log_records.funcs.encode = enc_log_records;
    sl.log_records.arg = &lctx;
    otlp_one_sub_t sl_sub = { opentelemetry_proto_logs_v1_ScopeLogs_fields, &sl };

    opentelemetry_proto_logs_v1_ResourceLogs rl = opentelemetry_proto_logs_v1_ResourceLogs_init_zero;
    rl.has_resource = true;
    rl.resource = res;
    rl.scope_logs.funcs.encode = otlp_enc_one_sub;
    rl.scope_logs.arg = &sl_sub;
    otlp_one_sub_t rl_sub = { opentelemetry_proto_logs_v1_ResourceLogs_fields, &rl };

    opentelemetry_proto_collector_logs_v1_ExportLogsServiceRequest req =
        opentelemetry_proto_collector_logs_v1_ExportLogsServiceRequest_init_zero;
    req.resource_logs.funcs.encode = otlp_enc_one_sub;
    req.resource_logs.arg = &rl_sub;

    pb_ostream_t st = pb_ostream_from_buffer(buf, cap);
    if (!pb_encode(&st,
            opentelemetry_proto_collector_logs_v1_ExportLogsServiceRequest_fields, &req))
        return -1;
    return (long)st.bytes_written;
}
