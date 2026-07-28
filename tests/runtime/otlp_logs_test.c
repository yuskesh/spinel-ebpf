/*
 * otlp_logs_test.c -- host verification of emitted events -> OTLP logs (LogRecord).
 *
 * Builds three int-bodied log records plus one string-bodied one and writes the
 * bytes to argv[1]. The runner (run_otlp_logs.sh) then checks body, severity and
 * service with protoc --decode.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "otlp_logs.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }

    otlp_log_record_t recs[4];
    memset(recs, 0, sizeof recs);
    const uint64_t base = 1700000000000000000ULL;
    for (int i = 0; i < 3; i++) {
        recs[i].time_unix_ns = base + (uint64_t)i;
        recs[i].body_is_str = false;
        recs[i].body_int = (int64_t)(100 * (i + 1)); /* 100, 200, 300 */
    }
    recs[3].time_unix_ns = base + 3;
    recs[3].body_is_str = true;
    recs[3].body_str = "hello-from-emit";

    uint8_t buf[8192];
    long n = otlp_logs_build(buf, sizeof buf, "spinel-app", "0.1.0", "spinel-ebpf", recs, 4);
    if (n < 0) { fprintf(stderr, "build failed\n"); return 1; }
    fprintf(stderr, "[otlp_logs] encoded %ld bytes (4 records)\n", n);

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) { perror("fwrite"); fclose(fp); return 1; }
    fclose(fp);
    return 0;
}
