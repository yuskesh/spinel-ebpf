/*
 * otlp_json_test.c -- unit check of the OTLP/JSON encoder (otlp_json.c).
 * argv[1] = metrics|traces|logs: builds that JSON from sample data and writes it
 * to stdout. The runner then checks validity and the expected fields with python
 * json.loads. No nanopb dependency.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "otlp_json.h"

int main(int argc, char **argv) {
    const char *which = (argc > 1) ? argv[1] : "metrics";
    static char buf[1 << 18];
    long n = -1;
    const char *svc = "spinel-app", *ver = "1.0", *scope = "spinel-ebpf";
    uint64_t t = 1700000000000000000ULL, start = 1699999999000000000ULL;

    if (strcmp(which, "metrics") == 0) {
        otlp_method_metric_t m[2];
        memset(m, 0, sizeof m);
        m[0].method = "add"; m[0].file = "app.rb"; m[0].line = 1; m[0].calls = 500;
        m[0].buckets[10] = 300; m[0].buckets[11] = 200;
        m[1].method = "fib"; m[1].file = "app.rb"; m[1].line = 3; m[1].calls = 10;
        m[1].buckets[5] = 10;
        n = otlp_json_metrics_build(buf, sizeof buf, svc, ver, scope, t, start, m, 2);
    } else if (strcmp(which, "logs") == 0) {
        otlp_log_record_t r[2];
        memset(r, 0, sizeof r);
        r[0].time_unix_ns = t; r[0].body_is_str = false; r[0].body_int = 42;
        r[1].time_unix_ns = t + 1; r[1].body_is_str = true; r[1].body_str = "hello"; r[1].event_name = "evt";
        n = otlp_json_logs_build(buf, sizeof buf, svc, ver, scope, r, 2);
    } else if (strcmp(which, "traces") == 0) {
        otlp_span_t s;
        memset(&s, 0, sizeof s);
        for (int i = 0; i < 16; i++) s.trace_id[i] = (uint8_t)(i + 1);
        for (int i = 0; i < 8; i++) s.span_id[i] = (uint8_t)(0xa0 + i);
        s.has_parent = false; s.method_idx = 0;
        s.start_unix_ns = t; s.end_unix_ns = t + 50000;
        otlp_method_meta_t meta = { 0, "add", "app.rb", 1 };
        n = otlp_json_traces_build(buf, sizeof buf, svc, ver, scope, &s, 1, &meta, 1);
    } else {
        fprintf(stderr, "usage: otlp_json_test metrics|traces|logs\n"); return 2;
    }

    if (n < 0) { fprintf(stderr, "build failed (buffer too small?)\n"); return 1; }
    fwrite(buf, 1, (size_t)n, stdout);
    return 0;
}
