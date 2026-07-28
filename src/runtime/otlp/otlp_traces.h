/*
 * otlp_traces.h -- turn a method call tree into OTLP traces (spans)
 *
 * The kernel side emits enter and exit events as {kind, idx, ktime, tid} into a
 * ringbuf, from a uprobe and a uretprobe. Userspace then (1) reassembles them into
 * spans using a per-thread stack (otlp_traces_assemble) and (2) encodes an OTLP
 * ExportTraceServiceRequest with nanopb (otlp_traces_build).
 *
 * A span's parent has to be decided when the call *starts*, because exits arrive
 * innermost-first. So the span id is allocated on enter, the parent is whatever
 * sits below it on the stack, and the trace id is minted at depth 0.
 *
 * No libbpf dependency: the caller drains the ringbuf and passes an array of
 * events in, which also makes this unit-testable on any host.
 */
#ifndef SPNL_OTLP_TRACES_H
#define SPNL_OTLP_TRACES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "otlp_http.h"   /* otlp_kv_t, for arbitrary span attributes */

#ifdef __cplusplus
extern "C" {
#endif

#define OTLP_TRACE_MAX_TIDS  64
#define OTLP_TRACE_MAX_DEPTH 64

/* An enter or exit event decoded from the ringbuf; kind is 0 for enter, 1 for exit. */
typedef struct {
    int32_t  kind;
    int32_t  idx;
    uint64_t ktime_ns;
    uint64_t tid;
} otlp_span_event_t;

/* An assembled span. */
typedef struct {
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    int32_t  method_idx;
    uint64_t start_unix_ns;
    uint64_t end_unix_ns;
} otlp_span_t;

/* idx -> name, file and line, used for the code.* attributes and the span name. */
typedef struct {
    int32_t     idx;
    const char *method;
    const char *file;
    int32_t     line;
} otlp_method_meta_t;

/*
 * Assemble events, in execution order, into spans. off_ns is the offset added to
 * turn a monotonic ktime into unix nanoseconds (realtime minus monotonic). seed
 * seeds trace and span id generation: fixed in tests, something unpredictable such
 * as wall-clock XOR pid in production. Returns the number of spans assembled,
 * capped at max_out.
 */
int otlp_traces_assemble(const otlp_span_event_t *ev, size_t nev,
                         int64_t off_ns, uint64_t seed,
                         otlp_span_t *out, size_t max_out);

/* Build an OTLP ExportTraceServiceRequest from spans. Returns the byte count, or -1. */
long otlp_traces_build(uint8_t *buf, size_t cap,
                       const char *service_name, const char *service_version,
                       const char *scope_name,
                       const otlp_span_t *spans, size_t nspans,
                       const otlp_method_meta_t *metas, size_t nmetas);

/* An HTTP server span: kind SERVER, http.* attributes, and W3C trace context
 * propagation, plus the semconv server/client/scheme/route attributes. */
typedef struct {
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    uint64_t start_unix_ns;
    uint64_t end_unix_ns;
    const char *name;            /* span name, e.g. "GET /path" or "GET <route>" */
    const char *http_method;     /* http.request.method; may be NULL */
    const char *url_path;        /* url.path; may be NULL */
    int32_t     status_code;     /* http.response.status_code; omitted when not positive,
                                    and 500 or above sets Span.status to ERROR */
    const char *server_address;  /* server.address, from getsockname; omitted when empty */
    int32_t     server_port;     /* server.port; omitted when not positive */
    const char *client_address;  /* client.address, from getpeername; omitted when empty */
    const char *url_scheme;      /* url.scheme, always "http" here; omitted when empty */
    const char *route;           /* http.route, the low-cardinality path; omitted when empty */
    /* Optional cross-layer attributes. The plain span_fd path passes tenant=NULL
     * and negative counters, so all three are omitted and the output is unchanged. */
    const char *tenant;            /* application-level context; omitted when empty -> "tenant" */
    int64_t     tcp_established;   /* connection-keyed ESTABLISHED count; omitted when negative */
    int64_t     tcp_state_changes; /* connection-keyed state-transition count; omitted when negative */
} otlp_http_span_t;

/* Build one HTTP server span into an ExportTraceServiceRequest. Byte count, or -1. */
long otlp_traces_http_build(uint8_t *buf, size_t cap,
                            const char *service_name, const char *service_version,
                            const char *scope_name,
                            const otlp_http_span_t *span);

/* A generic span: a kind plus arbitrary key/value attributes. This is what lets an
 * audit event -- verdict, path, lineage -- be sent as a span, which matters because
 * the backends this targets accept OTLP traces directly but not OTLP logs. It is
 * the span-shaped counterpart of the generic keyed metrics. */
typedef struct {
    uint8_t  trace_id[16];
    uint8_t  span_id[8];
    uint8_t  parent_span_id[8];
    bool     has_parent;
    uint64_t start_unix_ns;
    uint64_t end_unix_ns;
    const char     *name;    /* span name */
    int32_t         kind;    /* OpenTelemetry SpanKind; 0 defaults to INTERNAL */
    bool            is_error;/* true sets Span.status to ERROR, so a denial stands out */
    const otlp_kv_t *attrs;  /* arbitrary attributes; an empty value is omitted */
    int             nattrs;
} otlp_generic_span_t;

/* Build one generic span into an ExportTraceServiceRequest. Byte count, or -1. */
long otlp_traces_generic_build(uint8_t *buf, size_t cap,
                               const char *service_name, const char *service_version,
                               const char *scope_name,
                               const otlp_generic_span_t *span);

/* Encode several generic spans into a single ResourceSpans/ScopeSpans, and so a
 * single request -- the encoding half of batching, which is what stops every
 * record becoming its own POST. The resource attributes (service.*) are shared by
 * all of them; per-pod facts like k8s.* are span attributes, so spans from
 * different pods may legitimately share one ResourceSpans. Returns the byte count,
 * or -1. With nspans == 1 the output is byte-identical to the single-span build. */
long otlp_traces_generic_build_multi(uint8_t *buf, size_t cap,
                                     const char *service_name, const char *service_version,
                                     const char *scope_name,
                                     const otlp_generic_span_t *spans, size_t nspans);

/* ---- Assembling a trace out of several spans ----
 * The id-generation primitives that turn related events -- a request window, an
 * off-CPU wait, a DNS lookup, a connect, an L7 round trip -- into a tree sharing
 * one trace id and linked by parent_span_id. seed is splitmix64 state and advances
 * on every call; production seeds it unpredictably, tests fix it. Nothing in the
 * probe or the generated code changes for this. */

/* Root span: allocate a new 16-byte trace id and 8-byte span id, with has_parent
 * false. The caller still fills in start, end, name, attributes and kind. */
void otlp_span_new_root(otlp_generic_span_t *s, uint64_t *seed);

/* Child span: same trace id as the parent, parent_span_id set to the parent's span
 * id, a fresh span id, and has_parent true. The caller fills in the rest, nesting
 * it inside the parent's window. */
void otlp_span_new_child(otlp_generic_span_t *child,
                         const otlp_generic_span_t *parent, uint64_t *seed);

/* If an incoming traceparent is present ("vv-<32hex>-<16hex>-ff"), adopt its trace
 * id as the root and set parent_span_id to the incoming span id -- so our span
 * nests inside the caller's distributed trace. A NULL or malformed value behaves
 * like otlp_span_new_root. The span id is always freshly allocated. Returns 1 when
 * the context was inherited, 0 when it was generated. */
int otlp_span_root_from_traceparent(otlp_generic_span_t *s, const char *traceparent,
                                    uint64_t *seed);

/* The predicate for correlating a child record with a parent one: 1 when the
 * child's thread group and timestamp fall inside the parent's request window,
 * [start_ktime, start_ktime + dur_ns], and the thread groups match. A
 * parent_start_ktime of 0 means the window is unknown -- an older record -- and
 * never correlates. Timestamps are compared as raw monotonic values, before any
 * conversion to unix time. This assumes a synchronous handler where one thread
 * serves one request; concurrent or asynchronous handlers are best-effort, and the
 * code prefers falling back to standalone spans over correlating wrongly. */
int otlp_child_in_window(uint32_t child_tgid, uint64_t child_ktime,
                         uint32_t parent_tgid, uint64_t parent_start_ktime,
                         uint64_t parent_dur_ns);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_TRACES_H */
