/*
 * otlp_tls.h -- TLS client for OTLP egress, backed by mbedTLS
 *
 * A thin layer that wraps TLS around an already-connected socket fd. Client side
 * only; it exists so telemetry can go straight to an https:// or grpcs:// endpoint
 * without a collector in between.
 *
 * Certificate verification is configured by environment:
 *   OTEL_EXPORTER_OTLP_CERTIFICATE            a custom CA file (PEM). Without it,
 *                                             the system CA bundle is used.
 *   OTEL_EXPORTER_OTLP_INSECURE_SKIP_VERIFY=1 disable verification. Development
 *                                             only; verification is on by default.
 */
#ifndef SPNL_OTLP_TLS_H
#define SPNL_OTLP_TLS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct otlp_tls otlp_tls_t;

/* Wrap a connected fd in a TLS client and perform the handshake, using hostname
 * for SNI and for certificate verification. When alpn is non-NULL it offers that
 * one protocol -- gRPC over TLS requires "h2"; pass NULL for HTTP/1.1. Returns a
 * handle, or NULL with a message in err. Ownership of fd does not transfer: the
 * caller still closes it. */
otlp_tls_t *otlp_tls_connect(int fd, const char *hostname, const char *alpn, char *err, size_t errlen);

/* Send all len bytes over TLS. Returns 0 on success, -1 on failure. */
int otlp_tls_write(otlp_tls_t *t, const void *buf, size_t len);

/* Receive over TLS. Returns the byte count read, 0 on close_notify, -1 on error. */
int otlp_tls_read(otlp_tls_t *t, void *buf, size_t len);

/* Send close_notify and release the handle. Does not close the fd. */
void otlp_tls_free(otlp_tls_t *t);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_TLS_H */
