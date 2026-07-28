/*
 * otlp_http.h -- OTLP/HTTP+protobuf transport
 *
 * A minimal HTTP/1.1 client for OTLP: it sends an already-encoded protobuf to a
 * collector as `POST <path>`. TLS and gRPC live in their own files. The only
 * dependency is POSIX sockets -- no libbpf, no socket runtime -- so it builds and
 * runs on a plain host as well.
 */
#ifndef SPNL_OTLP_HTTP_H
#define SPNL_OTLP_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return the service.instance.id resource attribute. Uses
 * OTEL_SERVICE_INSTANCE_ID when set; otherwise builds "<hostname>-<pid>" once and
 * caches it for the life of the process. Both resource encoders share this -- the
 * protobuf one in otlp_pbutil.h and the JSON one in otlp_json.c -- which it can do
 * because it needs only POSIX and never touches nanopb.
 */
static inline const char *otlp_service_instance_id(void) {
    static char cache[160];
    static int done = 0;
    if (!done) {
        const char *env = getenv("OTEL_SERVICE_INSTANCE_ID");
        if (env && env[0]) {
            snprintf(cache, sizeof cache, "%s", env);
        } else {
            char host[96];
            if (gethostname(host, sizeof host) != 0) snprintf(host, sizeof host, "unknown");
            host[sizeof host - 1] = 0;
            snprintf(cache, sizeof cache, "%s-%d", host, (int)getpid());
        }
        done = 1;
    }
    return cache;
}

/*
 * Split an endpoint of the form "http://host:port" into host and port, ignoring
 * any path. The scheme may be omitted; an absent port defaults to "4318".
 * Returns 0 on success, -1 on failure.
 */
int otlp_http_parse_endpoint(const char *endpoint,
                             char *host, size_t hostlen,
                             char *port, size_t portlen);

/*
 * Extract the path component of an endpoint URL, so "https://h/v2/trace/otlp"
 * yields "/v2/trace/otlp"; an endpoint without a path yields the empty string.
 * This exists so a per-signal endpoint can be used verbatim, as the
 * OpenTelemetry specification requires. Returns 0 on success.
 */
int otlp_http_endpoint_path(const char *endpoint, char *path, size_t pathlen);

/*
 * POST body to http://host:port<path> with the given Content-Type.
 *  - success (an HTTP response arrived): returns 0 and stores the status code in *status
 *  - transport failure (name resolution, connect, or send/receive): returns -1 and,
 *    when err is non-NULL, writes a message there
 * Connection is retried up to max_retries times with exponential backoff; 0 means
 * the default of 5.
 */
/* A non-zero tls sends over TLS (https://), which needs an OTLP_WITH_TLS build;
 * 0 sends in the clear. */
int otlp_http_post(const char *host, const char *port, const char *path,
                   const char *content_type,
                   const uint8_t *body, size_t body_len,
                   int tls,
                   int max_retries,
                   int *status, char *err, size_t errlen);

/* --- Enablers for sending straight to a backend, driven by environment
 *     variables so that nothing has to be recompiled. --- */

/* One header. HTTP writes "key: value"; gRPC writes an HPACK literal, with the
 * key lowercased. */
typedef struct { char key[128]; char val[512]; } otlp_kv_t;

/* Parse OTEL_EXPORTER_OTLP_HEADERS ("k1=v1,k2=v2") into out[] and return the
 * count. This is how an authentication header -- a vendor token, a Bearer
 * credential -- gets attached when sending straight to a backend. */
int otlp_env_headers(otlp_kv_t *out, int max);

/* When OTEL_EXPORTER_OTLP_COMPRESSION=gzip, compress in into out and return 1.
 * Returns 0 when compression is disabled or failed, and the caller then sends the
 * payload uncompressed. */
int otlp_gzip_if_enabled(const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t outcap, size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_HTTP_H */
