/*
 * otlp_metrics.h -- turn --instrument's per-method RED measurements into OTLP metrics.
 *
 * One method is {method, file, line, calls, buckets[64]}, and becomes two metrics,
 * each sent as its own ExportMetricsServiceRequest (see below for why):
 *   - spnl_method_calls_total : a monotonic CUMULATIVE Sum, N data points
 *   - spnl_method_latency_ns  : a histogram, N data points
 * Each data point carries code.function / code.filepath / code.lineno, resolved
 * from the compiler's symbol map.
 *
 * buckets[s] is the kernel's spnl_hist_log2 histogram, s = floor(log2(ns)). The
 * sum is a userspace approximation, sum(count_s * 1.5*2^s), because the kernel
 * does not keep one -- the kernel side stays untouched.
 */
#ifndef SPNL_OTLP_METRICS_H
#define SPNL_OTLP_METRICS_H

#include <stddef.h>
#include <stdint.h>
#include "otlp_http.h"  /* otlp_kv_t, for arbitrary labels */

/* The explicit-bucket boundaries are DECLARED (record_schema.h, bounds set
 * `log2_ns_31`). Only the macros are read here: the rest of the generated mirror
 * needs kernel types, and this header reaches translation units that are
 * deliberately libbpf-free (otlp_json.c among them).
 *
 * MACROS_ONLY is un-defined again only if it was defined here. The generated
 * header guards its boundaries block separately and gates the rest on
 * MACROS_ONLY being unset at include time; leaving it set would make a later
 * full include (otlp_agent.c, with SPNL_REC_CONSUME_IMPL) silently drop the
 * accessor definitions. */
#ifdef SPNL_RECORD_MIRROR_MACROS_ONLY
#  include "record_mirror_gen.h"
#else
#  define SPNL_RECORD_MIRROR_MACROS_ONLY 1
#  include "record_mirror_gen.h"
#  undef SPNL_RECORD_MIRROR_MACROS_ONLY
#endif

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

/* ---- one request, one metric ----------------------------------------------
 *
 * Generic keyed metrics used to bundle a Sum and an ExponentialHistogram into a
 * single request. An OTLP request carries one status for the whole body, so a
 * backend that refuses one of the two takes the other down with it -- measured:
 * Splunk Observability Cloud accepts the Sum with 200 and answers the
 * ExponentialHistogram with 500, and the counter never arrived. The bundling
 * builders are gone; callers build and send one metric at a time, which is what
 * the record-channel metrics in otlp_recmetric.c had always done. */

/* The log2 ruler for the explicit-bucket histogram. Not a copy: the declaration
 * read above. */
#define OTLP_LOG2_NBOUNDS  SPNL_BOUNDS_LOG2_NS_31_N
#define OTLP_LOG2_NBUCKETS (OTLP_LOG2_NBOUNDS + 1)

static inline const double *otlp_log2_ns_bounds(void) {
    static const double b[OTLP_LOG2_NBOUNDS] = SPNL_BOUNDS_LOG2_NS_31_INIT;
    return b;
}

/* Fold a 64-slot log2 histogram into the bucket_counts of the ruler above.
 *
 * log2 slot s counts the integer nanoseconds [2^s, 2^(s+1)-1] (slot 0 is v<=1),
 * and an OTLP explicit bucket j counts (bounds[j-1], bounds[j]]. Because every
 * boundary is 2^m - 1, a slot always lands wholly inside exactly one bucket, so
 * no count is ever split -- measured over three distributions and 600,000
 * samples with zero disagreement between the per-slot and per-bucket counts.
 * The sum is the same slot-midpoint approximation the ExponentialHistogram path
 * uses, so changing the representation does not move it.
 *
 * This lives in the header because both the protobuf side (with nanopb) and the
 * JSON side (without it) call it; two copies of the folding would mean two paths
 * emitting different histograms. */
static inline void otlp_log2_fold(const uint64_t slots[OTLP_HIST_SLOTS],
                                  uint64_t out_buckets[OTLP_LOG2_NBUCKETS],
                                  uint64_t *count_out, double *sum_out) {
    const double *bounds = otlp_log2_ns_bounds();
    uint64_t total = 0;
    double sum = 0.0;
    for (int j = 0; j < OTLP_LOG2_NBUCKETS; j++) out_buckets[j] = 0;
    for (int s = 0; s < OTLP_HIST_SLOTS; s++) {
        uint64_t c = slots[s];
        if (c == 0) continue;
        /* 2^64-1 does not fit in a uint64, so build the upper edge as a double
         * (safe even at s=63). */
        double edge = (double)((uint64_t)1 << s) * 2.0 - 1.0;
        int j = OTLP_LOG2_NBOUNDS;                     /* default: the overflow bucket */
        for (int k = 0; k < OTLP_LOG2_NBOUNDS; k++)
            if (bounds[k] >= edge) { j = k; break; }
        out_buckets[j] += c;
        total += c;
        sum += (double)c * (s <= 0 ? 1.0 : 1.5 * (double)((uint64_t)1 << s));
    }
    if (count_out) *count_out = total;
    if (sum_out)   *sum_out   = sum;
}

/* Which histogram type the latency goes out as. Reads the OpenTelemetry spec's
 * own OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION
 * (`explicit_bucket_histogram`, the spec default, or
 * `base2_exponential_bucket_histogram`). This is not sniffed from the
 * destination -- the operator declares it, and an unknown spelling is refused
 * loudly. */
typedef enum {
    OTLP_HIST_AGG_EXPLICIT    = 0,  /* explicit_bucket_histogram (the default) */
    OTLP_HIST_AGG_EXPONENTIAL = 1,  /* base2_exponential_bucket_histogram */
} otlp_hist_agg_t;
otlp_hist_agg_t otlp_hist_aggregation(void);

/* A monotonic Sum on its own -- for the counter of a record channel, which has
 * no value to distribute, so there is no accompanying ExponentialHistogram and
 * the series' buckets are never read. Returns the byte count, or -1. */
long otlp_metrics_sum_build(uint8_t *buf, size_t cap,
                            const char *service_name, const char *service_version,
                            const char *scope_name,
                            const char *name, const char *unit,
                            uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                            const otlp_series_t *series, size_t nseries);

/* A Gauge on its own: the series' count emitted as a non-monotonic instantaneous
 * value. Being able to build one payload per metric type is what made it possible
 * to tell which type a backend was refusing. Returns the byte count, or -1. */
long otlp_metrics_gauge_build(uint8_t *buf, size_t cap,
                              const char *service_name, const char *service_version,
                              const char *scope_name,
                              const char *name, const char *unit,
                              uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                              const otlp_series_t *series, size_t nseries);

/* An ExponentialHistogram on its own: the latency half, without the rate.
 * Returns the byte count, or -1. */
long otlp_metrics_exphist_build(uint8_t *buf, size_t cap,
                                const char *service_name, const char *service_version,
                                const char *scope_name,
                                const char *name, const char *unit,
                                uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                                const otlp_series_t *series, size_t nseries);

/* One series of an explicit-bucket Histogram (semconv http.server.request.duration
 * and friends). The boundaries are shared by every series, so the build function
 * holds them and a series carries only bucket_counts (nbounds+1 of them), sum,
 * count and its labels. */
typedef struct {
    const otlp_kv_t *labels;
    int              nlabels;
    uint64_t         count;
    double           sum;
    const uint64_t  *bucket_counts; /* length = nbounds + 1 */
} otlp_hseries_t;

/* Build an explicit-bounds Histogram (name, unit, CUMULATIVE). The boundaries are
 * ascending and shared by every series. Returns the byte count, or -1. */
long otlp_metrics_hist_build(uint8_t *buf, size_t cap,
                             const char *service_name, const char *service_version,
                             const char *scope_name,
                             const char *name, const char *unit,
                             const double *bounds, int nbounds,
                             uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                             const otlp_hseries_t *series, size_t nseries);

/* Encode --instrument's per-method RED as one metric per request. The previous
 * builder bundled calls (a Sum) and latency (an ExponentialHistogram), so a 500
 * on the latency took the rate with it. The caller chooses which part to emit;
 * otlp_hist_aggregation() supplies the default for the latency type, but the
 * choice is a parameter here so a test can build both. Returns the byte count,
 * or -1. */
typedef enum {
    OTLP_MPART_CALLS        = 0,  /* spnl_method_calls_total (Sum) */
    OTLP_MPART_LATENCY_EXP  = 1,  /* spnl_method_latency_ns (ExponentialHistogram) */
    OTLP_MPART_LATENCY_HIST = 2,  /* spnl_method_latency_ns (explicit-bucket Histogram) */
} otlp_method_part_t;

long otlp_metrics_method_build(uint8_t *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name, otlp_method_part_t part,
                               uint64_t time_unix_nano, uint64_t start_time_unix_nano,
                               const otlp_method_metric_t *methods, size_t nmethods);

/* Build and POST. endpoint is "http://host:port". Returns 0 on HTTP 200. */
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
