/*
 * otlp_metrics_test.c -- per-method RED -> OTLP metrics.
 *
 * Two methods' {calls, log2 buckets} go through otlp_metrics_method_build, one
 * file per part (one request = one metric). The runner (run_otlp_metrics.sh)
 * checks all three parts with `protoc --decode`.
 *
 * Expected, with slot s = floor(log2(ns)):
 *   calls        : a Sum of fib=177 and add=500, and *no* latency in the payload
 *   latency_exp  : an ExponentialHistogram (scale=0), slot s -> positive bucket s.
 *                  fib -> offset 9, bucket_counts [100,0,77], count 177,
 *                  sum = 100*768 + 77*3072 = 313344
 *   latency_hist : explicit buckets (the log2_ns_31 bounds set). Slot s maps to
 *                  bucket s for s<=26, so the same numbers appear in buckets
 *                  9 / 11 / 10 -- a fold never splits a count.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "otlp_metrics.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <outdir>\n", argv[0]); return 2; }
    const char *dir = argv[1];

    otlp_method_metric_t methods[2];
    memset(methods, 0, sizeof methods);
    methods[0].method = "fib"; methods[0].file = "app.rb"; methods[0].line = 1;
    methods[0].calls = 177; methods[0].buckets[9] = 100; methods[0].buckets[11] = 77;
    methods[1].method = "add"; methods[1].file = "app.rb"; methods[1].line = 19;
    methods[1].calls = 500; methods[1].buckets[10] = 500;

    static const struct { const char *file; otlp_method_part_t part; } P[] = {
        { "calls.pb",        OTLP_MPART_CALLS },
        { "latency_exp.pb",  OTLP_MPART_LATENCY_EXP },
        { "latency_hist.pb", OTLP_MPART_LATENCY_HIST },
    };
    for (size_t i = 0; i < sizeof P / sizeof P[0]; i++) {
        uint8_t buf[8192];
        long n = otlp_metrics_method_build(buf, sizeof buf,
                                           "spinel-app", "0.1.0", "spinel-ebpf", P[i].part,
                                           1700000000000000000ULL, 1699999999000000000ULL,
                                           methods, 2);
        if (n < 0) { fprintf(stderr, "build failed: %s\n", P[i].file); return 1; }
        char path[512];
        snprintf(path, sizeof path, "%s/%s", dir, P[i].file);
        FILE *fp = fopen(path, "wb");
        if (!fp) { perror("fopen"); return 1; }
        if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) { perror("fwrite"); fclose(fp); return 1; }
        fclose(fp);
        fprintf(stderr, "[otlp_metrics] %s: %ld bytes\n", P[i].file, n);
    }
    return 0;
}
