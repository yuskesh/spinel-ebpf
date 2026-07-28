/*
 * otlp_grpc.h — OTLP/gRPC transport
 *
 * A minimal HTTP/2 unary gRPC client, built on POSIX sockets alone -- it adds no
 * dependency. The protobuf on the wire is the same ExportXServiceRequest the HTTP
 * transport sends. gRPC runs over HTTP/2, so this
 *   HEADERS(:method/:path/:scheme/:authority + content-type: application/grpc) +
 *   DATA(1B compressed-flag=0 + 4B BE length + protobuf) + END_STREAM
 * The response is not HPACK-decoded: success is stream completion (END_STREAM),
 * and GOAWAY or RST means failure. What actually establishes correctness is that
 * the receiver -- a grpcio mock, or a real collector -- can decode the request.
 */
#ifndef SPNL_OTLP_GRPC_H
#define SPNL_OTLP_GRPC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OTLP_GRPC_PATH_METRICS "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
#define OTLP_GRPC_PATH_TRACES  "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
#define OTLP_GRPC_PATH_LOGS    "/opentelemetry.proto.collector.logs.v1.LogsService/Export"

/*
 * Send body (an ExportXServiceRequest protobuf) to grpc_path as a unary gRPC call.
 * Connection is retried up to max_retries times with exponential backoff; 0 means
 * the default of 5. On success (sent, and the stream completed) it returns 0 and
 * sets *ok=1; a GOAWAY or RST sets *ok=0. A transport failure -- name resolution,
 * connect, or send/receive -- returns -1 with a message in err.
 */
/* A non-zero tls means grpcs:// (HTTP/2 over TLS, which needs an OTLP_WITH_TLS
 * build); 0 means cleartext h2c. */
int otlp_grpc_export(const char *host, const char *port, const char *grpc_path,
                     const uint8_t *body, size_t body_len, int tls, int max_retries,
                     int *ok, char *err, size_t errlen);

/*
 * Pick the transport from the endpoint scheme: "grpc://..." goes out as OTLP/gRPC,
 * anything else as an OTLP/HTTP POST. status receives the HTTP status for the HTTP
 * path, or 200/0 for a gRPC call that did/did not complete. Returns 0 on success
 * and -1 on transport failure. This is the single exit point for metrics, traces
 * and logs alike.
 */
/* content_type is the Content-Type for the HTTP path (application/x-protobuf or
 * application/json, say). The gRPC path ignores it and always sends
 * application/grpc+proto. */
int otlp_transport_send(const char *endpoint, const char *http_path, const char *grpc_path,
                        const char *content_type,
                        const uint8_t *body, size_t body_len, int *status, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_GRPC_H */
