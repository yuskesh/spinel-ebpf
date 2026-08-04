/*
 * otlp_httpspan.c -- HTTP server spans with W3C trace context propagation.
 * See otlp_httpspan.h. No libbpf dependency: just the span builder and transport.
 */
#include "otlp_httpspan.h"
#include "otlp_traces.h"   /* otlp_http_span_t + otlp_traces_http_build */
#include "otlp_json.h"     /* otlp_want_json / otlp_endpoint_is_grpc / otlp_json_http_span_build */
#include "otlp_grpc.h"     /* otlp_transport_send + OTLP_GRPC_PATH_TRACES/METRICS */
#include "otlp_metrics.h"  /* otlp_hseries_t + otlp_metrics_hist_build */
#include "otlp_http.h"     /* otlp_kv_t */
/* The bucket boundaries below are declared in src/codegen_c/record_schema.h, in
 * the bounds set `otel_duration_s`, and this translation unit reads that
 * declaration rather than keeping a copy. Macros only: this file deliberately
 * has no libbpf dependency, and the rest of the generated mirror needs kernel
 * types. */
#define SPNL_RECORD_MIRROR_MACROS_ONLY 1
#include "record_mirror_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

uint64_t spnl_otlp_now_unix_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int hexdec(const char *s, uint8_t *out, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

/* Parse a W3C traceparent, "VV-<32 hex trace id>-<16 hex span id>-<2 hex flags>".
 * On a valid value it fills the 16-byte trace id and 8-byte parent and returns 1;
 * otherwise 0. */
static int parse_traceparent(const char *tp, uint8_t trace_id[16], uint8_t parent[8]) {
    if (!tp) return 0;
    while (*tp == ' ' || *tp == '\t') tp++;
    if (strlen(tp) < 55) return 0;                  /* 2+1+32+1+16+1+2 */
    if (tp[2] != '-' || tp[35] != '-' || tp[52] != '-') return 0;
    if (hexval(tp[0]) < 0 || hexval(tp[1]) < 0) return 0;  /* the version is unused, but must be hex */
    if (!hexdec(tp + 3, trace_id, 16)) return 0;
    if (!hexdec(tp + 36, parent, 8)) return 0;
    int tz = 1; for (int i = 0; i < 16; i++) if (trace_id[i]) { tz = 0; break; }
    int pz = 1; for (int i = 0; i < 8; i++) if (parent[i]) { pz = 0; break; }
    if (tz || pz) return 0;                         /* an all-zero id is invalid per the spec */
    return 1;
}

static uint64_t splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void put_u64_be(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i)); }

/* Render a sockaddr_storage as text plus a host-order port, for IPv4 and IPv6.
 * A non-inet address yields an empty string. */
static void addr_to_str(const struct sockaddr_storage *ss, char *out, size_t outlen, int *port) {
    out[0] = '\0';
    if (port) *port = 0;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)(const void *)ss;
        inet_ntop(AF_INET, &s4->sin_addr, out, (socklen_t)outlen);
        if (port) *port = ntohs(s4->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)(const void *)ss;
        inet_ntop(AF_INET6, &s6->sin6_addr, out, (socklen_t)outlen);
        if (port) *port = ntohs(s6->sin6_port);
    }
}

/* ---- the http.server.request.duration accumulator, in seconds ---- */

#define HTTP_DUR_MAX_SERIES 64
#define HTTP_DUR_NBOUNDS    SPNL_BOUNDS_OTEL_DURATION_S_N
/* The same bucket boundaries the OpenTelemetry eBPF instrumentation uses (its
 * pkg/export/bucket.go), so the two are directly comparable. bucket_counts has
 * one more entry than boundaries. The numbers themselves now come from the
 * bounds set `otel_duration_s` in the record schema. They are the same fifteen
 * that used to be written out here, but with a single owner there is no longer a
 * way to change one copy and quietly make the two histograms incomparable. */
static const double g_http_dur_bounds[HTTP_DUR_NBOUNDS] = SPNL_BOUNDS_OTEL_DURATION_S_INIT;

typedef struct {
    char     method[16];
    char     route[128];      /* the route, or the target: this series' key */
    int      has_route;       /* true for a real route, false for the target fallback */
    int32_t  status;
    uint64_t count;
    double   sum;             /* seconds */
    uint64_t buckets[HTTP_DUR_NBOUNDS + 1];
    int      used;
} http_dur_series_t;

static http_dur_series_t g_http_dur[HTTP_DUR_MAX_SERIES];
static int      g_http_dur_n = 0;
static uint64_t g_http_dur_start = 0;

/* Add a duration, in seconds, to the series keyed by method, route-or-target and
 * status. An overflowing series is dropped with a warning. */
static void http_dur_record(const char *method, const char *route_or_target, int has_route,
                            int32_t status, double dur_s) {
    const char *m = method ? method : "";
    const char *r = route_or_target ? route_or_target : "";
    http_dur_series_t *s = NULL;
    for (int i = 0; i < g_http_dur_n; i++) {
        http_dur_series_t *c = &g_http_dur[i];
        if (c->used && c->status == status &&
            strcmp(c->method, m) == 0 && strcmp(c->route, r) == 0) { s = c; break; }
    }
    if (!s) {
        if (g_http_dur_n >= HTTP_DUR_MAX_SERIES) {
            fprintf(stderr, "[otlp] WARNING http.server.request.duration: series limit (%d) reached, "
                            "dropping %s %s %d\n", HTTP_DUR_MAX_SERIES, m, r, status);
            return;
        }
        s = &g_http_dur[g_http_dur_n++];
        memset(s, 0, sizeof *s);
        snprintf(s->method, sizeof s->method, "%s", m);
        snprintf(s->route,  sizeof s->route,  "%s", r);
        s->has_route = has_route;
        s->status = status;
        s->used = 1;
    }
    if (dur_s < 0) dur_s = 0;
    int b = HTTP_DUR_NBOUNDS;  /* above the last boundary: the +inf bucket */
    for (int i = 0; i < HTTP_DUR_NBOUNDS; i++) {
        if (dur_s <= g_http_dur_bounds[i]) { b = i; break; }
    }
    s->buckets[b]++;
    s->count++;
    s->sum += dur_s;
}

/* The internal core, which also carries the cross-layer attributes. The plain API
 * passes tenant=NULL and negative counters, so those attributes are omitted and its
 * output is unchanged; only the extended entry point passes real values. */
static int http_span_fd_core(int fd, const char *traceparent, const char *method,
                             const char *target, const char *route, int status_code,
                             uint64_t t0, uint64_t t1, const char *tenant,
                             int64_t tcp_established, int64_t tcp_state_changes,
                             const char *endpoint) {
    if (!endpoint) return -1;

    otlp_http_span_t s;
    memset(&s, 0, sizeof s);
    static uint64_t counter = 0;
    uint64_t seed = (t1 ? t1 : t0) ^ ((uint64_t)getpid() << 32) ^ (++counter * 0x100000001B3ULL);

    if (parse_traceparent(traceparent, s.trace_id, s.parent_span_id)) {
        s.has_parent = true;                        /* continue the incoming trace; its span is our parent */
    } else {
        put_u64_be(s.trace_id, splitmix64(&seed));  /* no context: start a new trace */
        put_u64_be(s.trace_id + 8, splitmix64(&seed));
        s.has_parent = false;
    }
    put_u64_be(s.span_id, splitmix64(&seed));
    s.start_unix_ns = t0;
    s.end_unix_ns = t1;
    s.http_method = method;
    s.url_path = target;
    s.status_code = status_code;

    /* Derive the server address from getsockname and the client from getpeername. */
    char srvaddr[INET6_ADDRSTRLEN] = {0}, cliaddr[INET6_ADDRSTRLEN] = {0};
    int srvport = 0;
    if (fd >= 0) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0)
            addr_to_str(&ss, srvaddr, sizeof srvaddr, &srvport);
        sl = sizeof ss;
        if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0)
            addr_to_str(&ss, cliaddr, sizeof cliaddr, NULL);
    }
    s.server_address = srvaddr[0] ? srvaddr : NULL;
    s.server_port = srvport;
    s.client_address = cliaddr[0] ? cliaddr : NULL;
    s.url_scheme = "http";                          /* this server speaks cleartext */
    s.route = (route && route[0]) ? route : NULL;
    /* The optional cross-layer attributes; the builder drops NULL and negatives. */
    s.tenant = (tenant && tenant[0]) ? tenant : NULL;
    s.tcp_established = tcp_established;
    s.tcp_state_changes = tcp_state_changes;

    /* Span name: "<METHOD> <route>" when a route is known, which keeps cardinality
     * low, and otherwise the request target. */
    int has_route = (route && route[0]) ? 1 : 0;
    const char *name_path = has_route ? route : target;
    static char namebuf[300];
    snprintf(namebuf, sizeof namebuf, "%s %s", method ? method : "", name_path ? name_path : "");
    s.name = namebuf;

    /* Accumulate http.server.request.duration, in seconds. */
    if (g_http_dur_start == 0) g_http_dur_start = spnl_otlp_now_unix_ns();
    double dur_s = (t1 > t0) ? (double)(t1 - t0) / 1e9 : 0.0;
    http_dur_record(method, name_path, has_route, status_code, dur_s);

    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = "spinel-ebpf-http";

    int status = 0; char err[256] = {0};
    long n; const char *ct; const uint8_t *body;
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        static char jbuf[8192];
        n = otlp_json_http_span_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf", &s);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        static uint8_t pbuf[8192];
        n = otlp_traces_http_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf", &s);
        body = pbuf; ct = "application/x-protobuf";
    }
    if (n < 0) { fprintf(stderr, "[otlp] http span encode failed\n"); return -1; }
    int rc = otlp_transport_send(endpoint, "/v1/traces", OTLP_GRPC_PATH_TRACES,
                                 ct, body, (size_t)n, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] http span send error: %s\n", err); return -1; }
    return status;
}

int spnl_otlp_http_span_fd(int fd, const char *traceparent, const char *method,
                           const char *target, const char *route, int status_code,
                           uint64_t t0, uint64_t t1, const char *endpoint) {
    return http_span_fd_core(fd, traceparent, method, target, route, status_code,
                             t0, t1, NULL, -1, -1, endpoint);
}

/* A SERVER span carrying cross-layer context: the application-level tenant and the
 * connection-keyed established / state-change counters, all on the one span. A
 * negative counter omits its attribute. */
int spnl_otlp_http_span_fd_x(int fd, const char *traceparent, const char *method,
                             const char *target, const char *route, int status_code,
                             uint64_t t0, uint64_t t1, const char *tenant,
                             long long tcp_established, long long tcp_state_changes,
                             const char *endpoint) {
    return http_span_fd_core(fd, traceparent, method, target, route, status_code,
                             t0, t1, tenant, (int64_t)tcp_established,
                             (int64_t)tcp_state_changes, endpoint);
}

int spnl_otlp_http_span(const char *traceparent, const char *method, const char *target,
                        int status_code, uint64_t t0, uint64_t t1, const char *endpoint) {
    return spnl_otlp_http_span_fd(-1, traceparent, method, target, NULL,
                                  status_code, t0, t1, endpoint);
}

/* Send one audit event -- the verdict, the path and the process lineage -- as a
 * single span. Spans rather than logs, because the backends this targets accept
 * OTLP traces directly but not OTLP logs, and traces put the event in front of the
 * same analysis tools as everything else.
 *   - exe_path        -> process.executable.path     (semconv v1.37.0)
 *   - file_path       -> file.path                   (semconv v1.37.0)
 *   - parent_exe_path -> process.parent.executable.path. This attribute name is
 *                        our own: semconv standardises process.parent_pid but has
 *                        nothing for the parent's executable path.
 *   - verdict         -> verdict, also ours, carrying allow or deny.
 * The span is named "file_open <file_path>" with kind INTERNAL, and continues an
 * incoming traceparent so the audit joins the surrounding trace. A deny sets the
 * span status to ERROR, which is what makes a refusal stand out. */
int spnl_otlp_audit_file_span(const char *traceparent,
                              const char *exe_path, const char *parent_exe_path,
                              const char *file_path, const char *verdict, int deny,
                              uint64_t t0, uint64_t t1, const char *endpoint) {
    if (!endpoint) return -1;

    otlp_generic_span_t s;
    memset(&s, 0, sizeof s);
    static uint64_t counter = 0;
    uint64_t seed = (t1 ? t1 : t0) ^ ((uint64_t)getpid() << 32) ^ (++counter * 0x100000001B3ULL);
    if (parse_traceparent(traceparent, s.trace_id, s.parent_span_id)) {
        s.has_parent = true;
    } else {
        put_u64_be(s.trace_id, splitmix64(&seed));
        put_u64_be(s.trace_id + 8, splitmix64(&seed));
        s.has_parent = false;
    }
    put_u64_be(s.span_id, splitmix64(&seed));
    s.start_unix_ns = t0;
    s.end_unix_ns = t1;
    s.kind = 0;   /* INTERNAL */

    static char namebuf[300];
    snprintf(namebuf, sizeof namebuf, "file_open %s", file_path ? file_path : "");
    s.name = namebuf;

    otlp_kv_t attrs[4];
    int n = 0;
    #define A(k,v) do { if ((v) && (v)[0]) { snprintf(attrs[n].key,sizeof attrs[n].key,"%s",k); \
                        snprintf(attrs[n].val,sizeof attrs[n].val,"%s",v); n++; } } while (0)
    A("process.executable.path",        exe_path);        /* semconv */
    A("process.parent.executable.path", parent_exe_path); /* an attribute name of our own */
    A("file.path",                      file_path);       /* semconv */
    A("verdict",                        verdict);         /* likewise */
    #undef A
    s.attrs = attrs;
    s.nattrs = n;
    s.is_error = (deny != 0);   /* a refused open surfaces as an error */

    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = "spinel-ebpf-audit";

    int status = 0; char err[256] = {0};
    long blen; const char *ct; const uint8_t *body;
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        /* The JSON exporter only covers HTTP spans; audit spans go out as protobuf. */
        static uint8_t pbuf[8192];
        blen = otlp_traces_generic_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf", &s);
        body = pbuf; ct = "application/x-protobuf";
    } else {
        static uint8_t pbuf[8192];
        blen = otlp_traces_generic_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf", &s);
        body = pbuf; ct = "application/x-protobuf";
    }
    if (blen < 0) { fprintf(stderr, "[otlp] audit span encode failed\n"); return -1; }
    int rc = otlp_transport_send(endpoint, "/v1/traces", OTLP_GRPC_PATH_TRACES,
                                 ct, body, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] audit span send error: %s\n", err); return -1; }
    return status;
}

int spnl_otlp_http_metrics_push(const char *endpoint) {
    if (!endpoint) return -1;
    if (g_http_dur_start == 0) g_http_dur_start = spnl_otlp_now_unix_ns();
    uint64_t now = spnl_otlp_now_unix_ns();

    static otlp_hseries_t hs[HTTP_DUR_MAX_SERIES];
    static otlp_kv_t      labels[HTTP_DUR_MAX_SERIES][3];  /* method / route? / status */
    size_t n = 0;
    for (int i = 0; i < g_http_dur_n; i++) {
        http_dur_series_t *s = &g_http_dur[i];
        if (!s->used || s->count == 0) continue;
        int nl = 0;
        snprintf(labels[n][nl].key, sizeof labels[n][nl].key, "http.request.method");
        snprintf(labels[n][nl].val, sizeof labels[n][nl].val, "%s", s->method); nl++;
        if (s->has_route) {
            snprintf(labels[n][nl].key, sizeof labels[n][nl].key, "http.route");
            snprintf(labels[n][nl].val, sizeof labels[n][nl].val, "%s", s->route); nl++;
        }
        snprintf(labels[n][nl].key, sizeof labels[n][nl].key, "http.response.status_code");
        snprintf(labels[n][nl].val, sizeof labels[n][nl].val, "%d", s->status); nl++;
        hs[n].labels = labels[n];
        hs[n].nlabels = nl;
        hs[n].count = s->count;
        hs[n].sum = s->sum;
        hs[n].bucket_counts = s->buckets;
        n++;
    }

    const char *svc = getenv("OTEL_SERVICE_NAME");
    if (!svc || !svc[0]) svc = "spinel-ebpf-http";

    int status = 0; char err[256] = {0};
    long blen; const char *ct; const uint8_t *body;
    if (otlp_want_json() && !otlp_endpoint_is_grpc(endpoint)) {
        static char jbuf[1 << 16];
        blen = otlp_json_metrics_hist_build(jbuf, sizeof jbuf, svc, NULL, "spinel-ebpf",
                                            "http.server.request.duration", "s",
                                            g_http_dur_bounds, HTTP_DUR_NBOUNDS,
                                            now, g_http_dur_start, hs, n);
        body = (const uint8_t *)jbuf; ct = "application/json";
    } else {
        static uint8_t pbuf[1 << 16];
        blen = otlp_metrics_hist_build(pbuf, sizeof pbuf, svc, NULL, "spinel-ebpf",
                                       "http.server.request.duration", "s",
                                       g_http_dur_bounds, HTTP_DUR_NBOUNDS,
                                       now, g_http_dur_start, hs, n);
        body = pbuf; ct = "application/x-protobuf";
    }
    if (blen < 0) { fprintf(stderr, "[otlp] http duration encode failed\n"); return -1; }
    int rc = otlp_transport_send(endpoint, "/v1/metrics", OTLP_GRPC_PATH_METRICS,
                                 ct, body, (size_t)blen, &status, err, sizeof err);
    if (rc != 0) { fprintf(stderr, "[otlp] http duration push error: %s\n", err); return -1; }
    return status;
}
