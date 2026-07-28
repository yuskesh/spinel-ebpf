/*
 * otlp_send_test.c -- sends OTLP/HTTP+protobuf over a real TCP connection.
 *
 * Encodes the same ExportMetricsServiceRequest the round-trip test uses with
 * nanopb and issues a `POST /v1/metrics` through otlp_http_post. It succeeds if
 * the receiver (the mock receiver, or a real Collector) answers 200.
 *
 * Usage: otlp_send_test [host] [port]   (defaults 127.0.0.1 4318)
 */
#include <stdio.h>
#include <stdint.h>

#include "otlp_sample_metrics.h"
#include "otlp_http.h"

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char *port = (argc > 2) ? argv[2] : "4318";

    uint8_t buf[8192];
    long n = otlp_build_sample_metrics(buf, sizeof buf);
    if (n < 0) { fprintf(stderr, "encode failed\n"); return 1; }

    int status = 0;
    char err[256] = {0};
    int rc = otlp_http_post(host, port, "/v1/metrics", "application/x-protobuf",
                            buf, (size_t)n, 0 /*tls*/, 0 /*retries*/, &status, err, sizeof err);
    if (rc != 0) {
        fprintf(stderr, "[otlp_send] transport error: %s\n", err);
        return 2;
    }
    fprintf(stderr, "[otlp_send] POST http://%s:%s/v1/metrics -> HTTP %d (%ld bytes body)\n",
            host, port, status, n);
    return (status == 200) ? 0 : 3;
}
