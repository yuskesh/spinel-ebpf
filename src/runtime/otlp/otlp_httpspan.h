/*
 * otlp_httpspan.h -- HTTP server spans, with W3C trace context propagation
 *
 * The FFI an HTTP server written in Ruby and compiled by spinel calls per request.
 * It picks up the incoming `traceparent` header, turns the request into one SERVER
 * span and sends it as OTLP traces. No libbpf dependency: it needs only the trace
 * encoders and the transport. The service name comes from OTEL_SERVICE_NAME.
 */
#ifndef SPNL_OTLP_HTTPSPAN_H
#define SPNL_OTLP_HTTPSPAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Current wall-clock time in unix nanoseconds, for span start and end. */
uint64_t spnl_otlp_now_unix_ns(void);

/*
 * Adopt the incoming traceparent (W3C "00-<32hex>-<16hex>-<2hex>"; a NULL, empty
 * or malformed value starts a new trace) and send one semconv-compatible SERVER
 * span to endpoint as OTLP traces.
 *
 *  - with fd >= 0, server.address and server.port are derived from getsockname on
 *    the accepted client socket, and client.address from getpeername (IPv4 or
 *    IPv6, via inet_ntop). With fd < 0 they are omitted.
 *  - url.scheme is always "http": this server speaks cleartext.
 *  - a non-empty route gives the span the name "<METHOD> <route>" and an
 *    http.route attribute; otherwise the name falls back to "<METHOD> <target>".
 *  - a status_code of 500 or above sets Span.status to ERROR.
 *
 * Returns the HTTP status on success, -1 on failure.
 */
int spnl_otlp_http_span_fd(int fd, const char *traceparent, const char *method,
                           const char *target, const char *route, int status_code,
                           uint64_t start_unix_ns, uint64_t end_unix_ns, const char *endpoint);

/*
 * A SERVER span that also carries cross-layer context. On top of what
 * spnl_otlp_http_span_fd records, it puts the application-level tenant and the
 * connection-keyed TCP counters onto the same span, as the attributes tenant,
 * net.tcp.established and net.tcp.state_changes. A negative counter omits its
 * attribute. Returns the HTTP status on success.
 */
int spnl_otlp_http_span_fd_x(int fd, const char *traceparent, const char *method,
                             const char *target, const char *route, int status_code,
                             uint64_t start_unix_ns, uint64_t end_unix_ns, const char *tenant,
                             long long tcp_established, long long tcp_state_changes,
                             const char *endpoint);

/*
 * Backward-compatible wrapper: calls spnl_otlp_http_span_fd with fd=-1 and
 * route=NULL, which is what the original API did.
 * SERVER span (name="<method> <target>"、http.request.method / url.path / http.response.status_code)。
 */
int spnl_otlp_http_span(const char *traceparent, const char *method, const char *target,
                        int status_code, uint64_t start_unix_ns, uint64_t end_unix_ns,
                        const char *endpoint);

/*
 * Send the accumulated http.server.request.duration as OTLP metrics: seconds, a
 * cumulative explicit-bucket Histogram over the same bounds the OpenTelemetry eBPF
 * instrumentation uses, [0, 0.005, ..., 10]. Every call to spnl_otlp_http_span_fd
 * or spnl_otlp_http_span adds its (t1 - t0) to the series. The attributes are
 * http.request.method, http.route when a route was given, and
 * http.response.status_code. Returns the HTTP status on success, -1 on failure.
 */
int spnl_otlp_http_metrics_push(const char *endpoint);

/*
 * Turn one audit event -- the verdict, the path, and the process lineage -- into a
 * single span and send it. Spans are used rather than logs because the backends
 * this targets accept OTLP traces directly but not OTLP logs.
 *   exe_path -> process.executable.path (semconv)、file_path -> file.path (semconv)、
 *   parent_exe_path becomes process.parent.executable.path and verdict becomes
 *   verdict; both are attribute names of our own, not semconv ones. A non-zero
 *   deny sets Span.status to ERROR so it stands out in an APM view, and an
 *   incoming traceparent is continued so the audit joins the surrounding trace.
 * The span is named "file_open <file_path>" and has kind INTERNAL. Returns the
 * HTTP status on success, -1 on failure.
 */
int spnl_otlp_audit_file_span(const char *traceparent,
                              const char *exe_path, const char *parent_exe_path,
                              const char *file_path, const char *verdict, int deny,
                              uint64_t start_unix_ns, uint64_t end_unix_ns,
                              const char *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_HTTPSPAN_H */
