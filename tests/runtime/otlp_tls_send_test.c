/*
 * otlp_tls_send_test.c -- sends OTLP/HTTP+protobuf straight over TLS with https://.
 *
 * Hands the sample metrics to otlp_transport_send with an https:// endpoint: the
 * scheme selects tls=1, and otlp_http_post then sends through mbedTLS. It holds if
 * the TLS mock answers 200 and can decode the payload.
 * Usage: otlp_tls_send_test <endpoint>   (default https://localhost:8443)
 */
#include <stdio.h>
#include <stdint.h>

#include "otlp_sample_metrics.h"
#include "otlp_grpc.h"   /* otlp_transport_send + OTLP_GRPC_PATH_METRICS */

int main(int argc, char **argv) {
    const char *ep = (argc > 1) ? argv[1] : "https://localhost:8443";

    uint8_t buf[8192];
    long n = otlp_build_sample_metrics(buf, sizeof buf);
    if (n < 0) { fprintf(stderr, "encode failed\n"); return 1; }

    int status = 0;
    char err[256] = {0};
    int rc = otlp_transport_send(ep, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                                 "application/x-protobuf", buf, (size_t)n, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[tls-send] transport error: %s\n", err); return 2; }
    fprintf(stderr, "[tls-send] %s -> status %d (%ld bytes)\n", ep, status, n);
    return (status == 200) ? 0 : 3;
}
