/*
 * otlp_metric.c — 汎用 keyed メトリクスの registry + OTLP push。詳細は otlp_metric.h。
 */
#include "otlp_metric.h"
#include "otlp_metrics.h"   /* otlp_series_t + otlp_metrics_series_build */
#include "otlp_json.h"      /* otlp_want_json / otlp_endpoint_is_grpc / otlp_json_metrics_series_build */
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

int spnl_otlp_metric_push_obj(struct bpf_object *obj, const char *hist_map,
                              const char *metric_name, const char *endpoint) {
    if (!obj || !hist_map || !metric_name || !endpoint) return -1;

    static otlp_series_t out[OTLP_METRIC_MAX_SERIES];
    size_t n = 0;
    for (int i = 0; i < g_nreg; i++) {
        if (!g_reg[i].used) continue;
        unsigned long long key = (unsigned long long)g_reg[i].key;
        __u64 count = 0;
        __u64 buckets[64] = {0};  /* __u64 vs uint64_t は Linux で別型なので temp + memcpy */
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

    int status = 0; char err[256] = {0};
    long blen; const char *ct; const uint8_t *body;
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        static char jbuf[1 << 18];
        blen = otlp_json_metrics_series_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                              metric_name, latname, "ns", now, g_start_ns, out, n);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        static uint8_t pbuf[1 << 18];
        blen = otlp_metrics_series_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                         metric_name, latname, "ns", now, g_start_ns, out, n);
        body = pbuf; ct = "application/x-protobuf";
    }
    if (blen < 0) { fprintf(stderr, "[otlp] series encode failed\n"); return -1; }
    int rc = otlp_transport_send(endpoint, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                                 ct, body, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] series push error: %s\n", err); return -1; }
    return status;
}
