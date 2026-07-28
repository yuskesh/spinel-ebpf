/*
 * otlp_metric_test.c -- verification of the general keyed-metrics path: arbitrary
 * labels, independent of --instrument.
 * Builds and sends two series (function=read/write, each carrying a pid label).
 * The check passes if the mock receiver recovers the metric names, the arbitrary
 * labels and the count/latency values. No libbpf dependency -- the build functions
 * are called directly.
 * Usage: otlp_metric_test <endpoint>
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "otlp_metrics.h"   /* otlp_series_t / otlp_metrics_series_build / otlp_kv_t */
#include "otlp_json.h"      /* otlp_want_json */
#include "otlp_grpc.h"      /* otlp_transport_send + OTLP_GRPC_PATH_METRICS */

int main(int argc, char **argv) {
    const char *ep = (argc > 1) ? argv[1] : "http://127.0.0.1:4318";

    otlp_kv_t l0[2] = { { "function", "read" }, { "pid", "100" } };
    otlp_kv_t l1[2] = { { "function", "write" }, { "pid", "100" } };
    otlp_series_t s[2];
    memset(s, 0, sizeof s);
    s[0].count = 5; s[0].buckets[10] = 3; s[0].buckets[11] = 2; s[0].labels = l0; s[0].nlabels = 2;
    s[1].count = 7; s[1].buckets[5]  = 7;                        s[1].labels = l1; s[1].nlabels = 2;

    uint64_t t = 1700000000000000000ULL, start = 1699999999000000000ULL;
    long n; const char *ct; const uint8_t *body;
    static uint8_t pbuf[1 << 16];
    static char    jbuf[1 << 16];
    if (otlp_want_json() && strncmp(ep, "grpc", 4) != 0) {
        n = otlp_json_metrics_series_build(jbuf, sizeof jbuf, "spinel-probe", NULL, "spinel-ebpf",
                                           "probe_calls", "probe_latency_ns", "ns", t, start, s, 2);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        n = otlp_metrics_series_build(pbuf, sizeof pbuf, "spinel-probe", NULL, "spinel-ebpf",
                                      "probe_calls", "probe_latency_ns", "ns", t, start, s, 2);
        body = pbuf; ct = "application/x-protobuf";
    }
    if (n < 0) { fprintf(stderr, "encode failed\n"); return 1; }

    int status = 0; char err[256] = {0};
    int rc = otlp_transport_send(ep, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                                 ct, body, (size_t)n, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[metric] transport error: %s\n", err); return 2; }
    fprintf(stderr, "[metric] %s -> status %d (%ld bytes)\n", ep, status, n);
    return status == 200 ? 0 : 3;
}
