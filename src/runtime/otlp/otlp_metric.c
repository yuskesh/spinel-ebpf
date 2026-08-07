/*
 * otlp_metric.c -- the registry and OTLP push for generic keyed metrics.
 * See otlp_metric.h.
 */
#include "otlp_metric.h"
#include "otlp_metrics.h"   /* otlp_series_t, the per-type builders, otlp_log2_fold */
#include "otlp_json.h"      /* otlp_want_json / otlp_endpoint_is_grpc / otlp_json_metrics_*_build */
#include "otlp_grpc.h"      /* otlp_transport_send + OTLP_GRPC_PATH_METRICS */
#include "otlp_http.h"      /* otlp_kv_t */
#include "spnl_runtime.h"   /* spnl_log2_hist_count_keyed_obj / spnl_hist_buckets_keyed_obj / __u64 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTLP_METRIC_MAX_SERIES 256
#define OTLP_METRIC_MAX_LABELS 8

typedef struct {
    uint64_t  key;
    otlp_kv_t labels[OTLP_METRIC_MAX_LABELS];
    int       nlabels;
    int       used;
} series_reg_t;

static series_reg_t g_reg[OTLP_METRIC_MAX_SERIES];
static int g_nreg = 0;
static uint64_t g_start_ns = 0;

static uint64_t wall_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int spnl_otlp_series_label(uint64_t key, const char *lk, const char *lv) {
    series_reg_t *s = NULL;
    for (int i = 0; i < g_nreg; i++)
        if (g_reg[i].used && g_reg[i].key == key) { s = &g_reg[i]; break; }
    if (!s) {
        if (g_nreg >= OTLP_METRIC_MAX_SERIES) return -1;
        s = &g_reg[g_nreg++];
        s->key = key; s->nlabels = 0; s->used = 1;
    }
    if (s->nlabels >= OTLP_METRIC_MAX_LABELS) return -1;
    snprintf(s->labels[s->nlabels].key, sizeof s->labels[0].key, "%s", lk ? lk : "");
    snprintf(s->labels[s->nlabels].val, sizeof s->labels[0].val, "%s", lv ? lv : "");
    s->nlabels++;
    return 0;
}

/* One metric, one request: build it, send it, return the HTTP status (negative
 * means the send itself failed).
 *
 * The rate is a Sum and the latency is a histogram. Bundling the two into one
 * request was the defect: a backend answering 500 to the ExponentialHistogram
 * took the rate down with it. The latency's type comes from
 * otlp_hist_aggregation(), i.e. the OpenTelemetry spec's
 * OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION. */
static int metric_push_one(const char *endpoint, const char *name, int is_latency,
                           const char *svc, uint64_t now, uint64_t start,
                           const otlp_series_t *series, size_t n) {
    static uint8_t pbuf[1 << 18];
    static char    jbuf[1 << 18];
    static uint64_t bc[OTLP_METRIC_MAX_SERIES][OTLP_LOG2_NBUCKETS];
    static otlp_hseries_t hs[OTLP_METRIC_MAX_SERIES];
    long blen = -1;
    const char *ct;
    const uint8_t *body;
    const int explicit_hist = is_latency && otlp_hist_aggregation() == OTLP_HIST_AGG_EXPLICIT;

    if (explicit_hist) {
        for (size_t i = 0; i < n; i++) {
            uint64_t total = 0; double sum = 0.0;
            otlp_log2_fold(series[i].buckets, bc[i], &total, &sum);
            hs[i].labels = series[i].labels;
            hs[i].nlabels = series[i].nlabels;
            hs[i].count = total;
            hs[i].sum = sum;
            hs[i].bucket_counts = bc[i];
        }
    }

    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        blen = !is_latency
             ? otlp_json_metrics_sum_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                           name, "1", now, start, series, n)
             : explicit_hist
             ? otlp_json_metrics_hist_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                            name, "ns", otlp_log2_ns_bounds(), OTLP_LOG2_NBOUNDS,
                                            now, start, hs, n)
             : otlp_json_metrics_exphist_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                               name, "ns", now, start, series, n);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        blen = !is_latency
             ? otlp_metrics_sum_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                      name, "1", now, start, series, n)
             : explicit_hist
             ? otlp_metrics_hist_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                       name, "ns", otlp_log2_ns_bounds(), OTLP_LOG2_NBOUNDS,
                                       now, start, hs, n)
             : otlp_metrics_exphist_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                          name, "ns", now, start, series, n);
        body = pbuf; ct = "application/x-protobuf";
    }
    if (blen < 0) { fprintf(stderr, "[otlp] %s encode failed\n", name); return -1; }

    int status = 0; char err[256] = {0};
    int rc = otlp_transport_send(endpoint, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                                 ct, body, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] %s push error: %s\n", name, err); return -1; }
    if (status != 200)
        fprintf(stderr, "[otlp] %s -> HTTP %d (the other metric is sent separately and is "
                        "unaffected)\n", name, status);
    return status;
}

int spnl_otlp_metric_push_obj(struct bpf_object *obj, const char *hist_map,
                              const char *metric_name, const char *endpoint) {
    if (!obj || !hist_map || !metric_name || !endpoint) return -1;

    static otlp_series_t out[OTLP_METRIC_MAX_SERIES];
    size_t n = 0;
    for (int i = 0; i < g_nreg; i++) {
        if (!g_reg[i].used) continue;
        unsigned long long key = (unsigned long long)g_reg[i].key;
        __u64 count = 0;
        __u64 buckets[64] = {0};  /* __u64 and uint64_t are distinct types on Linux, so
                                   * receive into a temp and memcpy */
        spnl_log2_hist_count_keyed_obj(obj, hist_map, key, &count);
        spnl_hist_buckets_keyed_obj(obj, hist_map, key, buckets);
        memcpy(out[n].buckets, buckets, sizeof buckets);
        out[n].count = count;
        out[n].labels = g_reg[i].labels;
        out[n].nlabels = g_reg[i].nlabels;
        n++;
    }

    uint64_t now = wall_ns();
    if (g_start_ns == 0) g_start_ns = now;
    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = "spinel-ebpf";
    char latname[160];
    snprintf(latname, sizeof latname, "%s_latency_ns", metric_name);

    /* Two requests. One failure does not propagate to the other. The return is
     * 200 when both were 200, otherwise the first non-200; which one failed is
     * named on stderr by metric_push_one. */
    int rate = metric_push_one(endpoint, metric_name, 0, svc, now, g_start_ns, out, n);
    int lat  = metric_push_one(endpoint, latname,     1, svc, now, g_start_ns, out, n);
    if (rate < 0 || lat < 0) return -1;
    return (rate != 200) ? rate : lat;
}
