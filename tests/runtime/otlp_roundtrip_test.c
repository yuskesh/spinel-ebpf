/*
 * otlp_roundtrip_test.c -- round-trip smoke test for the protobuf toolchain.
 *
 * Hand-builds an OTLP ExportMetricsServiceRequest with nanopb, encodes it, and
 * writes the bytes to argv[1]. The runner (run_otlp_roundtrip.sh) feeds those to
 * `protoc --decode` and checks that the expected fields come back. Together this
 * proves the whole chain works: vendored otel-proto -> nanopb codegen -> C encode
 * -> decoded identically by stock protoc.
 *
 * The encoder itself lives in otlp_sample_metrics.h, shared with the send test.
 */
#include <stdio.h>
#include <stdint.h>

#include "otlp_sample_metrics.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }

    uint8_t buf[8192];
    long n = otlp_build_sample_metrics(buf, sizeof buf);
    if (n < 0) { fprintf(stderr, "encode failed\n"); return 1; }
    fprintf(stderr, "[otlp_roundtrip] encoded %ld bytes\n", n);

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) { perror("fwrite"); fclose(fp); return 1; }
    fclose(fp);
    return 0;
}
