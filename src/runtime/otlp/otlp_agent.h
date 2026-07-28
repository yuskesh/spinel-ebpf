/*
 * otlp_agent.h -- the bridge that pushes OTLP metrics from an --instrument agent
 *
 * The Ruby agent cannot hand an array across the FFI boundary, so it registers
 * methods one at a time (spnl_otlp_add_method); at push time the C side reads the
 * keyed histogram map, encodes OTLP and POSTs it. Nothing here depends on the
 * generated skeleton type: the glue shim passes the bpf_object* in.
 */
#ifndef SPNL_OTLP_AGENT_H
#define SPNL_OTLP_AGENT_H

struct bpf_object;

#ifdef __cplusplus
extern "C" {
#endif

/* Resource attributes (service.name / service.version). FFI: [:str,:str] -> :int */
int spnl_otlp_set_service(const char *name, const char *version);

/* Register one instrumented method, where idx is its key in the keyed histogram
 * map. The ruby and file strings are copied internally.
 * FFI: [:str,:str,:long,:long] -> :int */
int spnl_otlp_add_method(const char *ruby, const char *file, long long line, long long idx);

/* For every registered method, read its count and buckets out of obj, encode OTLP
 * and POST it to endpoint. Returns the HTTP status; a transport failure is
 * negative. Called through the glue shim. */
int spnl_otlp_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint);

/* Drain enter/exit events from the emit4 ringbuf named map_name, assemble spans,
 * and POST them to endpoint as OTLP traces. Returns the HTTP status. Called
 * through the glue shim. */
int spnl_otlp_trace_push_obj(struct bpf_object *obj, const char *map_name, const char *endpoint);

/* Drain the emit ringbuf named map_name, turn each event into a LogRecord and
 * POST them to endpoint as OTLP logs. A non-zero is_str means the string ringbuf
 * (string body); 0 means the int ringbuf (integer body). */
int spnl_otlp_log_push_obj(struct bpf_object *obj, const char *map_name, int is_str,
                           const char *endpoint);

/* The three verbs behind a typed consumer (`on_emit :dns do |ev| ... end`). The
 * one-call form, spnl_otlp_dns_span_push_obj, collapses drain/to_span/send into a
 * single step; these split it apart. Both forms build spans through the same
 * builder, so attributes, span kind and timestamps are identical either way.
 *
 *   drain   -- read the ringbuf and return the record count. The handle Ruby holds
 *              is just an index in 0..n-1; fields are read through the generated
 *              accessors (spnl_rec_dns_*, in record_mirror_gen.h).
 *   to_span -- build one record into the span its egress declaration describes.
 *              0 means this record does not become a span.
 *   send    -- add a span to the send batch; a 0 handle is a no-op. The batch is
 *              flushed as one POST at the end of the cycle.
 *
 * Only drain needs a map name, so only drain goes through the glue shim; the rest
 * works off in-process state. */
int spnl_rec_dns_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms);
int spnl_rec_dns_to_span(int i);
/* The same three verbs for each channel that opts in. send/flush stay
 * channel-agnostic — one program may consume several channels and their spans all
 * go through one batch (`to_span` resolves the channel at compile time). */
int spnl_rec_l7_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms);
int spnl_rec_l7_to_span(int i);
int spnl_rec_http_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms);
int spnl_rec_http_to_span(int i);
/* Connection records. The peer address (`ev.peer`) picks v4 or v6 by looking at
 * the address family, so it is derived from the record as a whole rather than from
 * one field -- which is why it had to wait for the record-to-string derivation
 * form to exist. */
int spnl_rec_conn_drain_obj(struct bpf_object *obj, const char *map_name, int timeout_ms);
int spnl_rec_conn_to_span(int i);
int spnl_otlp_span_send(int handle, const char *endpoint);
int spnl_otlp_span_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_AGENT_H */
