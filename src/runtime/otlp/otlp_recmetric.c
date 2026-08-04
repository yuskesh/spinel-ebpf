/*
 * otlp_recmetric.c -- aggregating and sending the metrics that come from a
 * record channel. See otlp_recmetric.h.
 *
 * The design turns on the runtime being allowed to trust what the declaration
 * proved: the series array is fixed at SPNL_RECMETRIC_MAX_SERIES, and the
 * generator stops the build when the series bounds of all declarations add up to
 * more than that. So this file has no policy for what to do on overflow --
 * overflow was settled upstream as impossible. If interning does fail anyway,
 * that is evidence the declaration and the implementation have drifted apart, so
 * it shouts once instead of dropping in silence.
 */
/* The generated header carries the record structs too, so __u16/__u32/__u64 have
 * to be in scope first (the contract of spnl/types.h). This translation unit is
 * part of the eBPF-side link, so libbpf is present -- the same source
 * otlp_agent.c draws them from. */
#include <bpf/libbpf.h>

#define SPNL_RECMETRIC_IMPL 1
#include "record_mirror_gen.h"   /* the generated spnl_recmetrics[] table, and the caps */

#include "otlp_recmetric.h"
#include "otlp_metrics.h"        /* otlp_series_t / otlp_hseries_t / *_build */
#include "otlp_json.h"           /* otlp_want_json / otlp_endpoint_is_grpc / json builders */
#include "otlp_grpc.h"           /* otlp_transport_send + OTLP_GRPC_PATH_METRICS */
#include "otlp_http.h"           /* otlp_kv_t */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int      metric;                                        /* index into spnl_recmetrics */
    char     val[SPNL_RECMETRIC_MAX_LABELS][SPNL_RECMETRIC_LABEL_VAL_MAX];
    uint64_t count;
    double   sum;
    uint64_t buckets[SPNL_RECMETRIC_MAX_BOUNDS + 1];
    int      used;
} recmetric_series_t;

static recmetric_series_t g_series[SPNL_RECMETRIC_MAX_SERIES];
static int      g_nseries = 0;
static uint64_t g_start_ns = 0;
static int      g_overflow_warned = 0;

/* The declaration proves the bound, so the array can never need to be bigger. */
_Static_assert(SPNL_RECMETRIC_TOTAL_SERIES_BOUND <= SPNL_RECMETRIC_MAX_SERIES,
               "declared metrics can produce more time series than the accumulator holds "
               "(the generator should have refused this build)");

static uint64_t wall_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Projection onto the declared set. This is the one place that actually bounds
 * cardinality: a value outside the set goes out as the fallback, while the span
 * carries on holding the exact value. A label with no set passes through, since
 * the generator has already confirmed it comes from a closed value map. */
static const char *project(const spnl_metric_label_t *l, const char *raw) {
    if (!raw) raw = "";
    if (!l->values) return raw;
    for (int i = 0; i < l->nvalues; i++)
        if (strcmp(l->values[i], raw) == 0) return l->values[i];
    return l->fallback;
}

static recmetric_series_t *intern(int metric, const char *const *proj, int nlabels) {
    for (int i = 0; i < g_nseries; i++) {
        recmetric_series_t *s = &g_series[i];
        int hit = 1;
        if (!s->used || s->metric != metric) continue;
        for (int k = 0; k < nlabels; k++)
            if (strcmp(s->val[k], proj[k]) != 0) { hit = 0; break; }
        if (hit) return s;
    }
    if (g_nseries >= SPNL_RECMETRIC_MAX_SERIES) {
        /* Unreachable, by the _Static_assert above. Getting here means the
         * declaration and the implementation disagree, so shout -- dropping in
         * silence is precisely the failure this arrangement exists to remove. */
        if (!g_overflow_warned) {
            g_overflow_warned = 1;
            fprintf(stderr,
                    "[otlp] BUG record metrics: series capacity (%d) exhausted although the "
                    "declared bound is %d -- the generated table and this runtime disagree\n",
                    SPNL_RECMETRIC_MAX_SERIES, SPNL_RECMETRIC_TOTAL_SERIES_BOUND);
        }
        return NULL;
    }
    {
        recmetric_series_t *s = &g_series[g_nseries++];
        memset(s, 0, sizeof *s);
        s->metric = metric;
        s->used = 1;
        for (int k = 0; k < nlabels; k++)
            snprintf(s->val[k], sizeof s->val[k], "%s", proj[k]);
        return s;
    }
}

void spnl_recmetric_observe(int metric, const char *const *label_values,
                            int nlabels, int has_value, double value) {
    const spnl_metric_desc_t *d;
    const char *proj[SPNL_RECMETRIC_MAX_LABELS];
    recmetric_series_t *s;

    if (metric < 0 || metric >= SPNL_RECMETRIC_COUNT) return;
    d = &spnl_recmetrics[metric];
    if (nlabels != d->nlabels || nlabels > SPNL_RECMETRIC_MAX_LABELS) return;
    for (int i = 0; i < nlabels; i++)
        proj[i] = project(&d->labels[i], label_values[i]);

    s = intern(metric, proj, nlabels);
    if (!s) return;
    if (g_start_ns == 0) g_start_ns = wall_ns();
    s->count++;
    if (d->is_hist && has_value) {
        int b = d->nbounds;                       /* past the last boundary: the +inf bucket */
        for (int i = 0; i < d->nbounds; i++)
            if (value <= d->bounds[i]) { b = i; break; }
        s->buckets[b]++;
        s->sum += value;
    }
}

int spnl_recmetric_series_count(void) { return g_nseries; }

static int push_one(const spnl_metric_desc_t *d, int mi, const char *endpoint,
                    uint64_t now, int *any) {
    static otlp_series_t  sum_s[SPNL_RECMETRIC_MAX_SERIES];
    static otlp_hseries_t hist_s[SPNL_RECMETRIC_MAX_SERIES];
    static otlp_kv_t      labels[SPNL_RECMETRIC_MAX_SERIES][SPNL_RECMETRIC_MAX_LABELS];
    size_t n = 0;
    int status = 0;
    char err[256] = {0};
    long blen;
    const char *ct;
    const uint8_t *body;

    for (int i = 0; i < g_nseries; i++) {
        recmetric_series_t *s = &g_series[i];
        if (!s->used || s->metric != mi || s->count == 0) continue;
        for (int k = 0; k < d->nlabels; k++) {
            snprintf(labels[n][k].key, sizeof labels[n][k].key, "%s", d->labels[k].key);
            snprintf(labels[n][k].val, sizeof labels[n][k].val, "%s", s->val[k]);
        }
        if (d->is_hist) {
            hist_s[n].labels = labels[n];
            hist_s[n].nlabels = d->nlabels;
            hist_s[n].count = s->count;
            hist_s[n].sum = s->sum;
            hist_s[n].bucket_counts = s->buckets;
        } else {
            memset(&sum_s[n], 0, sizeof sum_s[n]);
            sum_s[n].count = s->count;
            sum_s[n].labels = labels[n];
            sum_s[n].nlabels = d->nlabels;
        }
        n++;
    }
    if (n == 0) return 0;
    *any = 1;

    {
        const char *svc = getenv("OTEL_SERVICE_NAME");
        if (!svc || !svc[0]) svc = "spinel-ebpf";
        if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
            static char jbuf[1 << 18];
            blen = d->is_hist
                 ? otlp_json_metrics_hist_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                                d->name, d->unit, d->bounds, d->nbounds,
                                                now, g_start_ns, hist_s, n)
                 : otlp_json_metrics_sum_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                               d->name, d->unit, now, g_start_ns, sum_s, n);
            body = (const uint8_t *)jbuf; ct = "application/json";
        } else {
            static uint8_t pbuf[1 << 18];
            blen = d->is_hist
                 ? otlp_metrics_hist_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                           d->name, d->unit, d->bounds, d->nbounds,
                                           now, g_start_ns, hist_s, n)
                 : otlp_metrics_sum_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                          d->name, d->unit, now, g_start_ns, sum_s, n);
            body = pbuf; ct = "application/x-protobuf";
        }
    }
    if (blen < 0) {
        fprintf(stderr, "[otlp] record metric encode failed: %s\n", d->name);
        return -1;
    }
    if (otlp_transport_send(endpoint, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                            ct, body, (size_t)blen, &status, err, sizeof err) != 0) {
        fprintf(stderr, "[otlp] record metric push error (%s): %s\n", d->name, err);
        return -1;
    }
    fprintf(stderr, "[otlp] pushed metric %s: %zu series (HTTP %d) -> %s\n",
            d->name, n, status, endpoint);
    return status;
}

int spnl_otlp_record_metrics_push(const char *endpoint) {
    uint64_t now;
    int last = 0, any = 0;

    if (!endpoint || !endpoint[0]) return -1;
    if (g_start_ns == 0) g_start_ns = wall_ns();
    now = wall_ns();
    for (int mi = 0; mi < SPNL_RECMETRIC_COUNT; mi++) {
        int st = push_one(&spnl_recmetrics[mi], mi, endpoint, now, &any);
        if (st < 0) return -1;
        if (st) last = st;
    }
    return any ? last : 0;
}
