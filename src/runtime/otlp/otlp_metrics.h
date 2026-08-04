/*
 * otlp_metrics.h -- turn the per-method RED metrics of --instrument into OTLP metrics
 *
 * Takes one method as {method, file, line, calls, buckets[64]} and builds an
 * ExportMetricsServiceRequest:
 *   - spnl_method_calls_total : Sum (monotonic, CUMULATIVE), N data points
 *   - spnl_method_latency_ns  : ExponentialHistogram (scale=0), N data points
 * Each data point is attributed with code.function, code.filepath and code.lineno,
 * taken from the compiler's symbol map.
 *
 * buckets[s] is a histogram over floor(log2(ns)), as accumulated in the kernel's
 * keyed histogram map. It maps onto an OTLP ExponentialHistogram at scale 0, where
 * bucket i covers (2^i, 2^(i+1)], by sending slot s as positive bucket s; the
 * difference between an open and a closed bound is immaterial at nanosecond
 * resolution. The sum is approximated in userspace as the sum of count_s * 1.5 *
 * 2^s, because the kernel side deliberately does not accumulate one -- keeping the
 * kernel program unchanged is worth more than an exact sum.
 */
#ifndef SPNL_OTLP_METRICS_H
#define SPNL_OTLP_METRICS_H

#include <stddef.h>
#include <stdint.h>
#include "otlp_http.h"  /* otlp_kv_t, for arbitrary labels */

#ifdef __cplusplus
extern "C" {
#endif

#define OTLP_HIST_SLOTS 64

typedef struct {
    const char *method;   /* the Ruby name -> code.function */
    const char *file;     /* -> code.filepath; may be "" */
    int32_t     line;     /* -> code.lineno; omitted when not positive */
    uint64_t    calls;    /* call counter; a method with 0 calls is not emitted */
    uint64_t    buckets[OTLP_HIST_SLOTS]; /* log2 latency hist (floor(log2(ns))) */
} otlp_method_metric_t;

/* A generic series: any key, any labels. For measurements taken by a probe that
 * has nothing to do with --instrument. */
typedef struct {
    uint64_t         count;                    /* the rate; a series with 0 is not emitted */
    uint64_t         buckets[OTLP_HIST_SLOTS]; /* log2 latency hist */
    const otlp_kv_t *labels;                   /* arbitrary labels: function, pid, comm, ... */
    int              nlabels;
} otlp_series_t;

/* Generic keyed metrics: name as a Sum and lat_name as an ExponentialHistogram,
 * with each series carrying its own labels. Returns the byte count, or -1. */
long otlp_metrics_series_build(uint8_t *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name,
                               const char *name, const char *lat_name, const char *unit,
                               uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                               const otlp_series_t *series, size_t nseries);

/* A monotonic Sum on its own -- for the counter of a record channel, which has
 * no value to distribute, so unlike series_build there is no accompanying
 * ExponentialHistogram and the series' buckets are never read. Returns the byte
 * count on success, -1 on failure. */
long otlp_metrics_sum_build(uint8_t *buf, size_t cap,
                            const char *service_name, const char *service_version,
                            const char *scope_name,
                            const char *name, const char *unit,
                            uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                            const otlp_series_t *series, size_t nseries);

/* One series of an explicit-bucket Histogram, such as the semconv metric
 * http.server.request.duration. The bounds are shared by every series, so the
 * build function holds them and a series carries only bucket_counts (of length
 * nbounds + 1), sum, count and its labels. */
typedef struct {
    const otlp_kv_t *labels;
    int              nlabels;
    uint64_t         count;
    double           sum;
    const uint64_t  *bucket_counts; /* length is nbounds + 1 */
} otlp_hseries_t;

/* Build a cumulative explicit-bounds Histogram with the given name and unit. The
 * bounds must be ascending, and are shared by every series. Returns the byte
 * count, or -1. */
long otlp_metrics_hist_build(uint8_t *buf, size_t cap,
                             const char *service_name, const char *service_version,
                             const char *scope_name,
                             const char *name, const char *unit,
                             const double *bounds, int nbounds,
                             uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                             const otlp_hseries_t *series, size_t nseries);

/* Encode an ExportMetricsServiceRequest into buf. Returns the byte count, or -1. */
long otlp_metrics_build(uint8_t *buf, size_t cap,
                        const char *service_name, const char *service_version,
                        const char *scope_name,
                        uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                        const otlp_method_metric_t *methods, size_t nmethods);

/* Build and POST over OTLP/HTTP. endpoint is "http://host:port". Returns 0 on
 * an HTTP 200. */
int otlp_metrics_export(const char *endpoint,
                        const char *service_name, const char *service_version,
                        const char *scope_name,
                        uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                        const otlp_method_metric_t *methods, size_t nmethods,
                        int *http_status, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_METRICS_H */
