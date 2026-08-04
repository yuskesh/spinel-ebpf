/*
 * otlp_json.h -- OTLP/HTTP+JSON encoder (proto3 JSON mapping), for debugging and interop
 *
 * Sends JSON instead of protobuf when OTEL_EXPORTER_OTLP_PROTOCOL=http/json.
 * HTTP only: gRPC always carries protobuf. These functions take the same input
 * structs as the protobuf encoders (otlp_metrics/traces/logs) and emit the same
 * data as JSON. Per the proto3 JSON mapping, 64-bit integers are written as
 * strings, trace and span ids as hex, and enums as numbers.
 */
#ifndef SPNL_OTLP_JSON_H
#define SPNL_OTLP_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "otlp_metrics.h"  /* otlp_method_metric_t */
#include "otlp_traces.h"   /* otlp_span_t / otlp_method_meta_t */
#include "otlp_logs.h"     /* otlp_log_record_t */

#ifdef __cplusplus
extern "C" {
#endif

/* True when OTEL_EXPORTER_OTLP_PROTOCOL is "http/json". */
int otlp_want_json(void);

/* True when endpoint is grpc:// or grpcs://, which always carry protobuf. */
int otlp_endpoint_is_grpc(const char *endpoint);

/* Write the OTLP/JSON form of each signal into buf. Returns the byte count, or
 * -1 if buf is too small or encoding failed. */
long otlp_json_metrics_build(char *buf, size_t cap,
                             const char *service_name, const char *service_version,
                             const char *scope_name,
                             uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                             const otlp_method_metric_t *methods, size_t nmethods);

long otlp_json_traces_build(char *buf, size_t cap,
                            const char *service_name, const char *service_version,
                            const char *scope_name,
                            const otlp_span_t *spans, size_t nspans,
                            const otlp_method_meta_t *metas, size_t nmetas);

long otlp_json_logs_build(char *buf, size_t cap,
                          const char *service_name, const char *service_version,
                          const char *scope_name,
                          const otlp_log_record_t *recs, size_t nrecs);

/* A single HTTP server span (kind=SERVER with http.* attributes), as JSON. */
long otlp_json_http_span_build(char *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name, const otlp_http_span_t *span);

/* Generic keyed metrics with arbitrary labels, as JSON. */
long otlp_json_metrics_series_build(char *buf, size_t cap,
                                    const char *service_name, const char *service_version,
                                    const char *scope_name,
                                    const char *name, const char *lat_name, const char *unit,
                                    uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                                    const otlp_series_t *series, size_t nseries);

/* A Sum on its own -- the counter of a record channel. Counterpart of
 * otlp_metrics_sum_build on the protobuf side. */
long otlp_json_metrics_sum_build(char *buf, size_t cap,
                                 const char *svc, const char *ver, const char *scope,
                                 const char *name, const char *unit,
                                 uint64_t t, uint64_t start,
                                 const otlp_series_t *series, size_t n);

/* An explicit-bucket Histogram (http.server.request.duration, say), as JSON. */
long otlp_json_metrics_hist_build(char *buf, size_t cap,
                                  const char *service_name, const char *service_version,
                                  const char *scope_name,
                                  const char *name, const char *unit,
                                  const double *bounds, int nbounds,
                                  uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                                  const otlp_hseries_t *series, size_t nseries);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_JSON_H */
