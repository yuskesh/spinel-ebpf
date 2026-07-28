/*
 * otlp_http_duration_test.c -- verification of http.server.request.duration
 * (in seconds, using the same explicit bucket boundaries the OpenTelemetry eBPF
 * instrumentation uses).
 * Records spans with known durations (fd=-1, so the addresses are omitted), then
 * pushes the metrics. The check passes if the mock receiver can recover
 * name="http.server.request.duration", the explicit_bounds, the right buckets, and
 * the attributes (http.request.method / http.route / http.response.status_code).
 *
 * What is recorded:
 *   series A: route "/fast", 2 x 3ms   -> 2 in bucket index 1  ((0, 0.005])
 *   series B: route "/slow", 1 x 1.2s  -> 1 in bucket index 11 ((1, 2.5])
 *
 * Usage: otlp_http_duration_test <endpoint>
 */
#include <stdio.h>
#include <stdint.h>

#include "otlp_httpspan.h"

int main(int argc, char **argv) {
    const char *ep = (argc > 1) ? argv[1] : "http://127.0.0.1:4318";
    uint64_t t0 = spnl_otlp_now_unix_ns();

    /* series A: /fast x2, 3ms each */
    spnl_otlp_http_span_fd(-1, NULL, "GET", "/fast", "/fast", 200, t0, t0 + 3000000ULL, ep);
    spnl_otlp_http_span_fd(-1, NULL, "GET", "/fast", "/fast", 200, t0, t0 + 3000000ULL, ep);
    /* series B: /slow x1, 1.2s */
    spnl_otlp_http_span_fd(-1, NULL, "GET", "/slow", "/slow", 200, t0, t0 + 1200000000ULL, ep);

    int st = spnl_otlp_http_metrics_push(ep);
    fprintf(stderr, "[http-duration] %s -> metrics push %d\n", ep, st);
    return st == 200 ? 0 : 1;
}
