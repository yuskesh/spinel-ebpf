/*
 * otlp_grpc_test.c -- host verification of the OTLP/gRPC transport.
 *
 * Encodes the same sample ExportMetricsServiceRequest the round-trip test uses
 * with nanopb, then sends it to MetricsService/Export through the hand-written
 * HTTP/2 gRPC client (otlp_grpc_export). If the grpcio mock answers 200 and can
 * decode the request, the framing is correct.
 *
 * Usage: otlp_grpc_test [host] [port]   (defaults 127.0.0.1 4317)
 */
#include <stdio.h>
#include <stdint.h>

#include "otlp_sample_metrics.h"
#include "otlp_grpc.h"

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char *port = (argc > 2) ? argv[2] : "4317";

    uint8_t buf[8192];
    long n = otlp_build_sample_metrics(buf, sizeof buf);
    if (n < 0) { fprintf(stderr, "encode failed\n"); return 1; }

    int ok = 0; char err[256] = {0};
    int rc = otlp_grpc_export(host, port, OTLP_GRPC_PATH_METRICS, buf, (size_t)n, 0 /*tls*/, 0 /*retries*/, &ok, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp_grpc] transport error: %s\n", err); return 2; }
    fprintf(stderr, "[otlp_grpc] export grpc://%s:%s%s -> ok=%d (%ld bytes)\n",
            host, port, OTLP_GRPC_PATH_METRICS, ok, n);
    return ok ? 0 : 3;
}
