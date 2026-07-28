/*
 * otlp_metrics_test.c -- verifies the conversion from per-method RED counters to
 * OTLP metrics.
 *
 * Passes {calls, log2 buckets} for two methods to otlp_metrics_build and writes the
 * bytes to argv[1]. The runner (run_otlp_metrics.sh) then checks the Sum and the
 * ExponentialHistogram with `protoc --decode`.
 *
 * Expected (slot s = floor(log2(ns)) -> positive bucket index s,
 * sum = sum over s of count_s * 1.5*2^s):
 *   fib: calls=177, slot9=100 slot11=77 -> offset 9, bucket_counts [100,0,77], count 177,
 *        sum = 100*768 + 77*3072 = 313344
 *   add: calls=500, slot10=500        -> offset 10, bucket_counts [500],     count 500,
 *        sum = 500*1536 = 768000
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "otlp_metrics.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }

    otlp_method_metric_t methods[2];
    memset(methods, 0, sizeof methods);
    methods[0].method = "fib"; methods[0].file = "app.rb"; methods[0].line = 1;
    methods[0].calls = 177; methods[0].buckets[9] = 100; methods[0].buckets[11] = 77;
    methods[1].method = "add"; methods[1].file = "app.rb"; methods[1].line = 19;
    methods[1].calls = 500; methods[1].buckets[10] = 500;

    uint8_t buf[8192];
    long n = otlp_metrics_build(buf, sizeof buf,
                                "spinel-app", "0.1.0", "spinel-ebpf",
                                1700000000000000000ULL, 1699999999000000000ULL,
                                methods, 2);
    if (n < 0) { fprintf(stderr, "build failed\n"); return 1; }
    fprintf(stderr, "[otlp_metrics] encoded %ld bytes\n", n);

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) { perror("fwrite"); fclose(fp); return 1; }
    fclose(fp);
    return 0;
}
