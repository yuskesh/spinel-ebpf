/* record_schema.h -- declarative ringbuf record contracts.
 *
 * A packed-record emit builtin (emit_dns, emit_connect, ...) is one half of a
 * contract: the kernel producer writes a fixed struct into a per-unit ringbuf and
 * the userspace consumer (src/runtime/otlp/otlp_agent.c) reads those same bytes
 * back. Historically each layout was written twice by hand -- once as a
 * templates/<chan>.template.c struct, once as memcpy offsets in the runtime --
 * with only comments keeping the two in sync. That is the offset-desync risk
 * described in docs/research/ringbuf_data_contract.md.
 *
 * Here the layout becomes *data*: one table per channel, from which
 *   S1 generates the kernel record struct + its ringbuf map (spinel_ebpf_cc.c),
 *   S2 generates the userspace mirror (offsets computed, never hand-typed),
 *   S3 generates the egress attribute keys the runtime emits, plus the JSON the
 *      Ruby affordance surface (`capabilities --json` / `describe`) reads,
 *   S4 generates the typed-consumer accessors -- the `ev.<field>` a Ruby
 *      `on_emit :dns do |ev| ... end` block reads.
 * All four come out of tools/gen_record_mirror.c except S1, which #includes
 * this header directly; `make -C src/codegen_c mirror` refreshes the artifacts.
 *
 * Evolution rule (as in Cap'n Proto and SBE; it was applied by hand before it was enforced):
 * APPEND-ONLY -- existing entries never move and never change type; new fields go
 * at the end and read as zero on an older producer. The table order IS the record
 * order; padding is implied by `align`, exactly as the C compiler inserts it.
 * That rule is a *gate* rather than a convention: tools/record_gate.rb
 * diffs this table against tests/golden/record_schema.snapshot.json and fails a
 * change that moves, retypes, or removes anything already published.
 *
 * Scope: the packed channels below are declarative. Still outside:
 * the scalar emit channels (spnl_emit / _str / _pair / emit3 / emit4 -- payloads
 * are positional __s64 or a variable-length string, not a fixed record) and the
 * l7stream channel's glue-side reader (bin/spinel-ebpf emits its own C text).
 */
#ifndef SPNL_RECORD_SCHEMA_H
#define SPNL_RECORD_SCHEMA_H

/* One field of a ringbuf record.
 *
 * `ctype` is the element type spelled exactly as it must appear in the generated
 * kernel struct (the .bpf.c is compiled against vmlinux.h, so `__u32` etc.).
 * `count` is the array length, or 0 for a scalar. `size`/`align` describe ONE
 * element and exist for the consumers of this table (S2 computes byte offsets
 * from them); S1 itself only needs name/ctype/count.
 *
 * `expose` is the Ruby-visible type of this field when a typed
 * consumer reads it as `ev.<name>`:
 *   "int" -> Integer  (generated accessor returns C `long`, FFI `:long`)
 *   "str" -> String   (generated accessor returns `const char *`, FFI `:str`;
 *                      only valid for a NUL-terminated `char[]`)
 *   NULL  -> not exposed. Deliberate for `hdr` (a struct, not a value) and for
 *            `raw` (raw wire bytes -- what Ruby wants is the derived `qname`).
 * Exposure is declared, not inferred, so "which properties does `ev` have" has
 * exactly one author and an unknown `ev.foo` is a compile-time error listing the
 * real set instead of a link error or a silent zero. */
typedef struct {
  const char *name;    /* field name inside the record struct */
  const char *ctype;   /* element C type, verbatim */
  int         count;   /* array length; 0 = scalar */
  int         size;    /* sizeof(element), bytes */
  int         align;   /* _Alignof(element), bytes */
  const char *note;    /* provenance / meaning -- surfaced by S3 */
  const char *expose;  /* S4: Ruby-visible type ("int" | "str") or NULL */
} CcRecField;

/* --- Derived properties ---
 *
 * A record field is bytes; some of what a consumer wants is *derived* from those
 * bytes by userspace code. `dns raw[64] -> qname` is the motivating case: it is a
 * DNS wire parse (length-prefixed label walk), not a mapping, and keeps it
 * out of the kernel because the walk blows up verifier state.
 *
 * The judgement made here (left it open): the derivation's IMPLEMENTATION
 * stays in C, where the domain logic already lives and is tested -- re-declaring
 * a DNS parser in a schema table would be inventing a language. What is declared
 * is its EXISTENCE: name, Ruby type, source field, and the C function that
 * performs it. That is enough for the generator to emit the accessor and for the
 * affordance surface to list `ev.qname` beside the real fields, so the property
 * set still has a single author even though the parser does not live here.
 *
 * `impl_form` is how the generator calls it (the full list, with prototypes, is
 * in tools/gen_record_mirror.c: derived_form()). Two axes -- what it is handed,
 * what it returns -- so four spellings:
 *   "bytes_to_str"  / "bytes_to_int"   -- reads ONE field, named by `from`
 *   "record_to_str" / "record_to_int"  -- reads the WHOLE record; `from` is prose
 * The record_* forms exist because some derivations are not a parse of one field:
 * conn's `peer` has to look at `family` to know whether the address is in
 * `daddr` or in `daddr6_hi/lo`. Handing such a derivation the record --
 * rather than teaching Ruby the v4/v6 branch: the meaning is
 * layer 2's, and layer 1 just reads `ev.peer`.
 *
 * A derivation is also how a field gets *scaled* into the unit the span carries:
 * conn's srtt is on the wire in the kernel's 1/8 us and the span attribute is us,
 * so `ev.srtt_us` is declared "record_to_int" over the same function the span
 * builder calls. Exposing the field raw instead would make Ruby's value
 * and the span's value differ by a factor of 8 -- which is what had to warn
 * about in prose, and prose is not a contract.
 *
 * `cap` is the same idea one step further. found that "the same
 * function's output" is necessary but not sufficient: the same function handed a
 * different output capacity truncates at a different place, so `ev.method` was 64
 * characters where http.request.method was 15. fixed that by giving both
 * sides ONE number -- but one number for every derivation is nobody's bound, it
 * is just the value the generator happened to use. Here the capacity is declared
 * per derivation, with the rule:
 *
 *   cap >= the longest string this derivation can return, +1 for the NUL.
 *
 * i.e. a declared derivation never truncates, and `note` says why that bound
 * holds (a source field's width, an RFC limit, a closed set of literals). Both
 * ends -- the generated accessor and the runtime's span builder -- pass this one
 * number, so that guarantee is kept while each number now has a reason instead
 * of a provenance. A str derivation must declare a positive cap; an int one must
 * declare 0 (a capacity is meaningless for a `long`), and the generator dies
 * either way round. Widening a cap is additive; narrowing one truncates values
 * that used to arrive whole, so the record gate treats it as a breaking change. */
typedef struct {
  const char *name;      /* Ruby-visible property name (ev.<name>) */
  const char *expose;    /* "int" | "str" (same meaning as CcRecField.expose) */
  const char *from;      /* record field the derivation reads */
  const char *impl;      /* C function that performs it (defined in the runtime) */
  const char *impl_form; /* its calling convention; see tools/gen_record_mirror.c */
  int         cap;       /* output buffer size for a "str" derivation; 0 for "int" */
  const char *note;      /* provenance / caveats -- surfaced to Ruby */
} CcRecDerived;

/* --- The semantic half of the contract ---
 *
 * S1/S2 made the *physical* layout data: which bytes sit where. That says
 * nothing about what those bytes MEAN once they leave the process -- which
 * OpenTelemetry attributes the userspace consumer puts on the span it builds.
 * That binding lived as string literals inside src/runtime/otlp/otlp_agent.c,
 * so "write emit_dns -> get a span carrying dns.question.name" was only
 * discoverable by reading C. Declaring it here makes the runtime a *consumer*
 * of the declaration (it uses the generated SPNL_EGRESS_* macros) instead of
 * its author, so the affordance surface (`capabilities --json` / `describe`)
 * and the bytes on the wire cannot disagree.
 *
 * Deliberately NOT declared here: layer-2 enrichers (k8s/cri/peer,//
 *) own their own attributes and attach to *every* signal from env, so they
 * are named by id only -- their key lists live in otlp_enrich.c / the ENRICHERS
 * registry of src/spinel_ebpf/capabilities.rb (layer 2). */
typedef struct {
  const char *key;        /* attribute key, verbatim as emitted */
  const char *source;     /* which record field (or derivation) it comes from */
  const char *stability;  /* "semconv" = OTel registry key; "spinel" = project-specific */
  const char *condition;  /* when the attribute is present on the span */
  const char *note;       /* provenance (experiment) / caveats */
} CcEgressAttr;

/* The span one record turns into (the userspace consumer's output contract). */
typedef struct {
  const char         *push_fn;       /* userspace drain+push FFI (the companion) */
  const char         *span_name_fmt; /* span name, printf format with exactly one %s */
  const char         *span_name_arg; /* attribute key that fills the %s */
  const char         *span_kind;     /* OTLP SpanKind as emitted (kind=0 -> INTERNAL) */
  const char         *timing;        /* what start/end mean */
  const char         *note;          /* caveats: other consumers of the same record, etc. */
  const CcEgressAttr *attrs;
  int                 nattrs;
  const char *const  *enrichers;     /* layer-2 enrichers that also apply (ids) */
  int                 nenrichers;
} CcEgressSpan;

/* One typed channel: a record type plus the per-unit ringbuf map that carries it.
 * Names are suffixes appended to the unit prefix (`<unit>_dns_event`), matching
 * the per-unit naming convention of. */
typedef struct {
  const char         *id;            /* stable channel id ("dns"); S3 / consumer name */
  const char         *banner;        /* section comment emitted above the struct, or
                                      * NULL when the record sits inside a larger
                                      * section that already printed one (http/redis/
                                      * offcpu keep their pending/stash maps in a
                                      * template and the banner belongs to that). */
  const char         *struct_suffix; /* record struct  = <unit>_<struct_suffix> */
  const char         *map_suffix;    /* ringbuf map    = <unit>_<map_suffix> */
  const char         *ringbuf_size;  /* max_entries expression, verbatim */
  const CcRecField   *fields;
  int                 nfields;
  /* Append-only reading rule, made explicit: a producer built before
   * a field was appended writes a SHORTER record. `required_through` names the
   * last field every accepted record must carry; anything after it reads as zero
   * when absent. NULL = the whole record is required (the strict form S1 used for
   * DNS, and what every channel except offcpu does today). */
  const char         *required_through;
  /* S3: who writes this record, and what it becomes downstream. */
  const char *const  *producers;     /* emit builtins that fill this channel */
  int                 nproducers;
  const CcEgressSpan *egress;        /* NULL = record has no span binding (yet) */
  /* S4: properties a typed consumer sees that are not plain fields. */
  const CcRecDerived *derived;
  int                 nderived;
  /* S4 opt-in: 1 = publish the typed-consumer contract, so that
   * `on_emit :<id> do |ev|` lowers to the generated accessors. 0 = the channel is
   * declarative for S1-S3 only and `on_emit :<id>` keeps its named-event
   * meaning. Explicit rather than inferred from `expose`, because turning it on
   * changes what an existing Ruby program means. */
  int                 typed_consumer;
} CcRecSchema;

/* ================== DNS query/response record (emit_dns, dns_emit) ==
 *
 * Wire history, kept as evidence that the append-only rule has held:
 * {hdr, pid, comm[16], raw[64]}  -> appended cgid -> appended
 *   duration_ns. Nothing before an appended field ever moved (that invariant is
 *   what the userspace mirror's hard-coded +88 / +96 offsets depend on).
 *
 * `raw` is the first 64 bytes of the DNS payload, copied bounded in the kernel;
 * the QNAME label walk that turns it into `dns.question.name` runs in userspace
 * (an in-kernel walk blows up verifier state --). */
static const CcRecField cc_rec_dns_fields[] = {
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid (init-ns)", "int" },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str" },
  { "raw",         "unsigned char",        64,  1, 1, "first 64B of the DNS payload; QNAME parsed in userspace", NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int" },
  { "duration_ns", "__u64",                 0,  8, 8, "resolution RTT; 0 = query-only", "int" },
};

/* The one derived property of a DNS record: the dotted hostname. `raw` holds
 * length-prefixed labels, so `ev.qname` is a parse, and its implementation is
 * spnl_dns_qname() in src/runtime/otlp/otlp_agent.c -- the same function the
 * concise form uses to fill dns.question.name, so both forms see one hostname. */
static const CcRecDerived cc_rec_dns_derived[] = {
  { "qname", "str", "raw", "spnl_dns_qname", "bytes_to_str", 256,
    "length-prefixed DNS labels walked in userspace (an in-kernel walk blows up verifier state); "
    "empty when the record is not a parseable query. "
    "cap 256 = the domain bound: a DNS name is at most 255 bytes (RFC 1035 2.3.4), +1 for the NUL. "
    "Today's source bounds it far tighter -- the walk reads raw[12..60) and each label costs its length "
    "byte back as the dot, so the output cannot exceed 52 characters -- but the cap is stated against "
    "the protocol, so widening `raw` does not silently start truncating names" },
};

/* Both DNS emit builtins write this same ringbuf: emit_dns is query-only
 * (duration_ns stays 0) and dns_emit adds the resolution RTT. */
static const char *const cc_rec_dns_producers[] = { "emit_dns", "dns_emit" };

/* What spnl_otlp_dns_span_push makes of one record. Mirrors — and now *feeds* —
 * spnl_otlp_dns_span_push_obj() in src/runtime/otlp/otlp_agent.c. */
static const CcEgressAttr cc_rec_dns_egress_attrs[] = {
  { "dns.question.name", "raw[64] -> QNAME (length-prefixed labels walked in userspace)",
    "semconv", "always (a record whose QNAME does not parse is dropped, no span)",
    "the in-kernel label walk blows up verifier state, so the raw payload is copied bounded" },
  { "process.executable.name", "comm[16] (bpf_get_current_comm)",
    "semconv", "comm non-empty",
    "the resolving process, not the resolver library (socket-layer hook)" },
  { "spnl.dns.latency_ns", "duration_ns",
    "spinel", "duration_ns != 0",
    "dns_emit's txid-correlated RTT; emit_dns is query-only so the attribute is absent" },
};

static const char *const cc_rec_dns_enrichers[] = { "k8s", "cri" };

static const CcEgressSpan cc_rec_dns_egress = {
  "spnl_otlp_dns_span_push",
  "resolve %s",
  "dns.question.name",
  "INTERNAL",
  "start = hdr.timestamp (ktime -> unix); end = start + duration_ns (equal to start for emit_dns)",
  "The request-tree push (spnl_otlp_request_tree_push) consumes the same record and the "
  "same attribute keys, but nests it under a request span as a CLIENT child",
  cc_rec_dns_egress_attrs,
  (int)(sizeof cc_rec_dns_egress_attrs / sizeof cc_rec_dns_egress_attrs[0]),
  cc_rec_dns_enrichers,
  (int)(sizeof cc_rec_dns_enrichers / sizeof cc_rec_dns_enrichers[0]),
};

static const CcRecSchema cc_rec_dns = {
  .id             = "dns",
  .banner         = "/* === per-unit DNS-event channel === */",
  .struct_suffix  = "dns_event",
  .map_suffix     = "dns_events",
  .ringbuf_size   = "256 * 1024",
  .fields         = cc_rec_dns_fields,
  .nfields        = (int)(sizeof cc_rec_dns_fields / sizeof cc_rec_dns_fields[0]),
  .producers      = cc_rec_dns_producers,
  .nproducers     = (int)(sizeof cc_rec_dns_producers / sizeof cc_rec_dns_producers[0]),
  .egress         = &cc_rec_dns_egress,
  .derived        = cc_rec_dns_derived,
  .nderived       = (int)(sizeof cc_rec_dns_derived / sizeof cc_rec_dns_derived[0]),
  .typed_consumer = 1,
};

/* ================== TCP connect record (emit_connect, caps struct) ===
 *
 * Wire history: {hdr, pid, comm, daddr, dport, family, srtt_us} ->
 * appended cgid -> appended oldstate (direction) and daddr6_hi/lo (IPv6 as
 * two u64 halves, because a 5-argument BPF handler could not carry a 16-byte
 * address until the caps-struct change). Append-only throughout. */
static const CcRecField cc_rec_conn_fields[] = {
  { "hdr",       "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "pid",       "__u32",                 0,  4, 4, "producer tgid; sock_owner_set restores it when the ESTABLISHED transition fires in softirq", "int" },
  { "comm",      "char",                 16,  1, 1, "bpf_get_current_comm -- the connecting process, not the idle task", "str" },
  { "daddr",     "__u32",                 0,  4, 4, "remote IPv4 address, network byte order (valid when family == AF_INET)", NULL },
  { "dport",     "__u16",                 0,  2, 2, "remote port, host byte order", "int" },
  { "family",    "__u16",                 0,  2, 2, "address family (2 = AF_INET, 10 = AF_INET6)", NULL },
  { "srtt_us",   "__s64",                 0,  8, 8, "tcp_sock->srtt_us via CO-RE, on the wire in the kernel's 1/8 us scale. Not exposed raw: the us value is the derived property ev.srtt_us, which is the same function's output as the span attribute net.peer.srtt_us", NULL },
  { "cgid",      "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int" },
  { "oldstate",  "__u32",                 0,  4, 4, "TCP state before ESTABLISHED (2 = SYN_SENT -> active, 3 = SYN_RECV -> passive)", NULL },
  { "daddr6_hi", "__u64",                 0,  8, 8, "remote IPv6 address, bytes 0..7 (network order)", NULL },
  { "daddr6_lo", "__u64",                 0,  8, 8, "remote IPv6 address, bytes 8..15 (network order)", NULL },
};

/* The conn record's derived properties, and the reason this channel
 * waited for a third impl_form: what a consumer reasons about is "where did it
 * connect to" and "who initiated it", and NEITHER is a field. The destination
 * lives in `daddr` or in `daddr6_hi/lo` depending on `family`, and the direction
 * is a reading of `oldstate` -- both need the record, not a field, so they are
 * "record_to_str" ('s two forms both take one field's bytes).
 *
 * That is also why the raw address fields stay unexposed: handing Ruby `daddr`
 * (a be32) plus `family` would move the v4/v6 branch into layer 1, which is
 * exactly the meaning-leak D1 rules out. `ev.peer` is the address the
 * span carries; `ev.direction` is the string the span carries -- same code.
 *
 * moves `srtt_us` here for the same reason one step smaller: the field is
 * the kernel's 1/8 us and the span attribute is us, so exposing the field raw
 * made `ev.srtt_us` the ONE property whose value differed from the span's (* had to say "DIVIDE BY 8" in a note -- a warning, not a contract). As a
 * derivation it is the same function the span builder calls, so the two cannot
 * drift, and the unit lives in exactly one place. */
static const CcRecDerived cc_rec_conn_derived[] = {
  { "peer", "str", "family + daddr / daddr6_hi,daddr6_lo + dport", "spnl_conn_peer", "record_to_str", 64,
    "\"<address>:<port>\" with the v4/v6 choice already made. The address half is the same "
    "function's output as network.peer.address and the port half is network.peer.port, so ev.peer is "
    "exactly the span name's subject (\"connect <peer>\") -- including the fact that an IPv6 address is "
    "NOT bracketed (\"::1:19377\"), because that is how the span name has spelled it since. "
    "cap 64 >= the longest such string: inet_ntop writes at most INET6_ADDRSTRLEN-1 = 45 characters, "
    "plus \":\" and 5 port digits and the NUL = 52" },
  { "direction", "str", "oldstate", "spnl_conn_direction", "record_to_str", 16,
    "\"active\" (we initiated: SYN_SENT -> ESTABLISHED), \"passive\" (we accepted: SYN_RECV -> "
    "ESTABLISHED), \"other\". Byte-identical to the span attribute spnl.conn.direction (same function). "
    "cap 16 >= the longest of that closed set of literals (\"passive\", 7 + NUL)" },
  { "srtt_us", "int", "srtt_us (the kernel's 1/8 us scale)", "spnl_conn_srtt_us", "record_to_int", 0,
    "smoothed RTT in MICROSECONDS -- the same value the span attribute net.peer.srtt_us "
    "carries, because both are this one function's output. The >>3 that turns the kernel's 1/8 us "
    "into us is layer 2's business, so a consumer never divides by 8. Note it is the L4 smoothed RTT "
    "(a property of the connection), not an L7 round trip" },
};

static const char *const cc_rec_conn_producers[] = { "emit_connect" };

static const CcEgressAttr cc_rec_conn_egress_attrs[] = {
  { "network.peer.address", "daddr (AF_INET) or daddr6_hi/lo (AF_INET6) -> inet_ntop",
    "semconv", "always", " / (IPv6 halves rejoined in userspace)" },
  { "network.peer.port", "dport", "semconv", "always", "" },
  { "network.transport", "constant \"tcp\"", "semconv", "always",
    "the channel only observes TCP state transitions" },
  { "network.type", "family (AF_INET -> \"ipv4\", AF_INET6 -> \"ipv6\")", "semconv", "always", " /" },
  { "net.peer.srtt_us", "srtt_us >> 3 (spnl_conn_srtt_us -- the same function as the property ev.srtt_us)",
    "spinel", "always",
    "semconv has no smoothed-RTT key, so this is a project key; the value is L4 srtt, not an L7 "
    "round trip. the >>3 has one author, shared with the typed consumer" },
  { "spnl.conn.direction", "oldstate (SYN_SENT -> active, SYN_RECV -> passive, else other)",
    "spinel", "always", "semconv has no connection-direction key" },
  { "process.executable.name", "comm[16]", "semconv", "comm non-empty",
    "recovered from the sock->owner map when the transition fires in softirq context" },
};

/* conn is the one signal the peer enricher applies to: it is the only
 * record whose peer address is a *destination* the runtime can classify. */
static const char *const cc_rec_conn_enrichers[] = { "k8s", "cri", "peer" };

static const CcEgressSpan cc_rec_conn_egress = {
  "spnl_otlp_conn_span_push",
  "connect %s:%u",
  "network.peer.address, network.peer.port",
  "INTERNAL",
  "start = end = hdr.timestamp (ktime -> unix); a connect is a point event, so duration is 0",
  "The request-tree push consumes the same record and the same attribute keys, but nests it "
  "under a request span as a CLIENT child (and drops network.transport / network.type there)",
  cc_rec_conn_egress_attrs,
  (int)(sizeof cc_rec_conn_egress_attrs / sizeof cc_rec_conn_egress_attrs[0]),
  cc_rec_conn_enrichers,
  (int)(sizeof cc_rec_conn_enrichers / sizeof cc_rec_conn_enrichers[0]),
};

static const CcRecSchema cc_rec_conn = {
  .id            = "conn",
  .banner        = "/* === per-unit connect-event channel === */",
  .struct_suffix = "conn_event",
  .map_suffix    = "conn_events",
  .ringbuf_size  = "256 * 1024",
  .fields        = cc_rec_conn_fields,
  .nfields       = (int)(sizeof cc_rec_conn_fields / sizeof cc_rec_conn_fields[0]),
  .producers     = cc_rec_conn_producers,
  .nproducers    = (int)(sizeof cc_rec_conn_producers / sizeof cc_rec_conn_producers[0]),
  .egress        = &cc_rec_conn_egress,
  .derived       = cc_rec_conn_derived,
  .nderived      = (int)(sizeof cc_rec_conn_derived / sizeof cc_rec_conn_derived[0]),
  /* Publishes a typed consumer. This channel came last because `peer` has to be
   * derived from the record as a whole rather than from one field, and that form of
   * derivation had to exist first.
   * What is published is deliberately minimal: not the raw big-endian address, nor
   * the address family or previous socket state, but the values that already carry
   * meaning -- `peer`, `direction`, `srtt_us` in microseconds -- alongside the plain
   * scalars a decision can be made on: pid, comm, dport, cgid. Exposure can always
   * be added later; taking it away is a breaking change the record gate refuses, so
   * when in doubt, publish nothing. */
  .typed_consumer = 1,
};

/* ================== L7 round-trip record (emit_l7) ======================
 *
 * Protocol-independent send->recv latency: unlike the connect record (duration 0)
 * the duration IS the payload here. Wire history: -> appended cgid. */
static const CcRecField cc_rec_l7_fields[] = {
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid (the process that sent the request)", "int" },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str" },
  { "daddr",       "__u32",                 0,  4, 4, "remote IPv4 address, network byte order", NULL },
  { "dport",       "__u16",                 0,  2, 2, "remote port, host byte order", "int" },
  { "family",      "__u16",                 0,  2, 2, "address family (2 = AF_INET; IPv6 addresses are not carried on this channel)", NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "ktime of the first send on this socket (span start)", NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "send -> response-visible round trip (tcp_cleanup_rbuf), = span duration", "int" },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int" },
};

static const char *const cc_rec_l7_producers[] = { "emit_l7" };

static const CcEgressAttr cc_rec_l7_egress_attrs[] = {
  { "network.peer.address", "daddr -> inet_ntop", "semconv", "always",
    "AF_INET6 records render as \"(ipv6 not carried)\" -- this channel has no v6 field" },
  { "network.peer.port", "dport", "semconv", "always", "" },
  { "network.transport", "constant \"tcp\"", "semconv", "always", "" },
  { "network.type", "family (AF_INET -> \"ipv4\", AF_INET6 -> \"ipv6\")", "semconv", "always", "" },
  { "spnl.l7.latency_ns", "duration_ns", "spinel", "always",
    "the span duration is authoritative; this attribute is the same number, for querying" },
  { "process.executable.name", "comm[16]", "semconv", "comm non-empty", "" },
};

static const char *const cc_rec_l7_enrichers[] = { "k8s", "cri" };

static const CcEgressSpan cc_rec_l7_egress = {
  "spnl_otlp_l7_span_push",
  "request %s:%u",
  "network.peer.address, network.peer.port",
  "CLIENT",
  "start = start_ktime (ktime -> unix); end = start + duration_ns",
  "the earlier multiplexing guard suppresses records for sockets carrying overlapping requests, so a "
  "record on this channel is always one clean request/response pair",
  cc_rec_l7_egress_attrs,
  (int)(sizeof cc_rec_l7_egress_attrs / sizeof cc_rec_l7_egress_attrs[0]),
  cc_rec_l7_enrichers,
  (int)(sizeof cc_rec_l7_enrichers / sizeof cc_rec_l7_enrichers[0]),
};

static const CcRecSchema cc_rec_l7 = {
  .id            = "l7",
  .banner        = "/* === per-unit L7 latency-event channel === */",
  .struct_suffix = "l7_event",
  .map_suffix    = "l7_events",
  .ringbuf_size  = "256 * 1024",
  .fields        = cc_rec_l7_fields,
  .nfields       = (int)(sizeof cc_rec_l7_fields / sizeof cc_rec_l7_fields[0]),
  .producers     = cc_rec_l7_producers,
  .nproducers    = (int)(sizeof cc_rec_l7_producers / sizeof cc_rec_l7_producers[0]),
  .egress        = &cc_rec_l7_egress,
  /* Publishes a typed consumer. The raw address, the address family and the window
   * anchor are deliberately not exposed: what a probe decides on is who (comm, pid),
   * where to (dport), how long it waited (duration_ns) and which pod it belongs to
   * (cgid). Rendering the destination as text is the span builder's job, and needs
   * the family anyway. Exposure can be added later; withdrawing it is a breaking
   * change, so this starts minimal. */
  .typed_consumer = 1,
};

/* ================== HTTP RED record (http_emit, ssl_emit) ===========
 *
 * The record plus the two bounded byte copies the kernel makes of the wire:
 * the request head (method/path) and the response head (status). Parsing them is
 * userspace work (the pattern) -- the kernel only copies.
 *
 * Two producers share it: http_emit (plaintext TCP) and ssl_emit (the same
 * bytes read from an SSL_read/SSL_write plaintext buffer, where there is no sock
 * -> daddr/dport stay 0 and the consumer marks url.scheme=https). */
static const CcRecField cc_rec_http_fields[] = {
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid", "int" },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str" },
  { "daddr",       "__u32",                 0,  4, 4, "remote IPv4 address, network byte order; 0 on the TLS path (no sock)", NULL },
  { "dport",       "__u16",                 0,  2, 2, "remote port, host byte order; 0 on the TLS path", "int" },
  { "family",      "__u16",                 0,  2, 2, "address family (2 = AF_INET)", NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "ktime of the request send (span start)", NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "request -> response round trip, = span duration", "int" },
  { "req",         "unsigned char",        64,  1, 1, "first 64B of the request; \"METHOD path HTTP/x\" parsed in userspace", NULL },
  { "resp",        "unsigned char",        16,  1, 1, "first 16B of the response; \"HTTP/1.1 NNN\" status parsed in userspace", NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int" },
};

/* The HTTP record's derived properties: the three L7 values a consumer
 * actually reasons about are not fields but a parse of `req` / `resp` -- the same
 * parse the span builder runs (kept it in userspace; the kernel only copies
 * bounded bytes). Declaring them here means `ev.status` and the span's
 * http.response.status_code are literally the same function's output, exactly as
 * `ev.qname` and dns.question.name are.
 *
 * `status` is the first consumer property that is an Integer derived from bytes,
 * so it introduces the second impl_form, "bytes_to_int" (`long f(const unsigned
 * char *)`); the generator still dies on an unknown form, so a third one cannot
 * slip in silently. Like bytes_to_str, the implementation knows how wide its
 * source field is (the table does not pass a length) -- see the earlier convention. */
static const CcRecDerived cc_rec_http_derived[] = {
  { "method", "str", "req",  "spnl_http_method", "bytes_to_str", 65,
    "first token of the request head; empty when the head does not parse. "
    "cap 65 = req[64] + NUL, the bound had to reach for: the kernel-side filter only inspects the "
    "first 4 bytes, so a head with no space at all is reachable and the token is then the whole field" },
  { "path",   "str", "req",  "spnl_http_path",   "bytes_to_str", 65,
    "second token of the request head (path only -- no body, no headers). "
    "cap 65 = req[64] + NUL (same bound as `method`: the token cannot outgrow the field it is cut from)" },
  { "status", "int", "resp", "spnl_http_status", "bytes_to_int", 0,
    "status digits of the response head; 0 when the head does not parse. "
    ">= 500 is what sets Span.status = ERROR on the egress side" },
};

static const char *const cc_rec_http_producers[] = { "http_emit", "ssl_emit" };

static const CcEgressAttr cc_rec_http_egress_attrs[] = {
  { "http.request.method", "req[64] -> first token", "semconv", "the request head parses",
    "the kernel-side method filter already rejected non-HTTP sends" },
  { "url.path", "req[64] -> second token", "semconv", "the request head parses", "" },
  { "http.response.status_code", "resp[16] -> status digits", "semconv", "the response head parses",
    "status >= 500 also sets Span.status = ERROR (the RED error axis)" },
  { "url.scheme", "constant \"https\"", "semconv", "daddr == 0 && dport == 0 (the TLS path)",
    "an SSL uprobe sees plaintext but no socket, so peer attributes are omitted instead" },
  { "network.peer.address", "daddr -> inet_ntop", "semconv", "daddr/dport non-zero (the TCP path)", "" },
  { "network.peer.port", "dport", "semconv", "daddr/dport non-zero (the TCP path)", "" },
  { "network.transport", "constant \"tcp\"", "semconv", "always", "" },
  /* the l7 channel has carried spnl.l7.latency_ns since and this one did not,
   * although `ev.duration_ns` is an exposed property on BOTH -- so on http the number a
   * Ruby consumer filters on had no counterpart in the span except its length. Declared
   * with l7's condition ("always") and l7's source (duration_ns) so the two channels
   * answer the same query. The span duration remains authoritative; this is the same
   * number, for querying. */
  { "spnl.http.latency_ns", "duration_ns", "spinel", "always",
    "symmetric with spnl.l7.latency_ns -- the span duration is authoritative, "
    "this attribute is the same number, for querying. On the TLS path it is still the "
    "SSL_write -> SSL_read round trip" },
  { "process.executable.name", "comm[16]", "semconv", "comm non-empty", "" },
};

static const char *const cc_rec_http_enrichers[] = { "k8s", "cri" };

static const CcEgressSpan cc_rec_http_egress = {
  "spnl_otlp_http_span_push",
  "%s %s",
  "http.request.method, url.path",
  "CLIENT",
  "start = start_ktime (ktime -> unix); end = start + duration_ns",
  "the span carries no request body or headers -- only method, path and status leave the process",
  cc_rec_http_egress_attrs,
  (int)(sizeof cc_rec_http_egress_attrs / sizeof cc_rec_http_egress_attrs[0]),
  cc_rec_http_enrichers,
  (int)(sizeof cc_rec_http_enrichers / sizeof cc_rec_http_enrichers[0]),
};

static const CcRecSchema cc_rec_http = {
  .id            = "http",
  .banner        = NULL,   /* inside the "per-unit HTTP L7 RED" section */
  .struct_suffix = "http_event",
  .map_suffix    = "http_events",
  .ringbuf_size  = "256 * 1024",
  .fields        = cc_rec_http_fields,
  .nfields       = (int)(sizeof cc_rec_http_fields / sizeof cc_rec_http_fields[0]),
  .producers     = cc_rec_http_producers,
  .nproducers    = (int)(sizeof cc_rec_http_producers / sizeof cc_rec_http_producers[0]),
  .egress        = &cc_rec_http_egress,
  .derived       = cc_rec_http_derived,
  .nderived      = (int)(sizeof cc_rec_http_derived / sizeof cc_rec_http_derived[0]),
  /* Publishes a typed consumer. With `ev.status >= 500`, `ev.path` and
   * `ev.duration_ns` available, a probe can decide what to send before it sends it.
   * The raw request and response bytes are not exposed: what is wanted is the
   * method, the path and the status, not the wire -- the same judgement made for
   * the raw DNS packet. */
  .typed_consumer = 1,
};

/* ================== Redis RED record (redis_emit) =======================
 *
 * Byte-for-byte the same layout as the HTTP record -- what differs is the
 * userspace parse (a RESP array instead of a request line) and therefore the
 * egress attributes. It is declared separately rather than aliased so that the
 * two can evolve independently and so that `describe` tells the truth about
 * which struct a Redis probe actually writes. */
static const CcRecField cc_rec_redis_fields[] = {
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid", NULL },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", NULL },
  { "daddr",       "__u32",                 0,  4, 4, "remote IPv4 address, network byte order", NULL },
  { "dport",       "__u16",                 0,  2, 2, "remote port, host byte order", NULL },
  { "family",      "__u16",                 0,  2, 2, "address family (2 = AF_INET)", NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "ktime of the command send (span start)", NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "command -> reply round trip, = span duration", NULL },
  { "req",         "unsigned char",        64,  1, 1, "first 64B of the RESP request; command + first key parsed in userspace (values never read)", NULL },
  { "resp",        "unsigned char",        16,  1, 1, "first 16B of the reply; a leading '-' marks a RESP error", NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", NULL },
};

static const char *const cc_rec_redis_producers[] = { "redis_emit" };

static const CcEgressAttr cc_rec_redis_egress_attrs[] = {
  { "db.system", "constant \"redis\"", "semconv", "always", "" },
  { "db.operation.name", "req[64] -> first RESP bulk string, upper-cased", "semconv", "the command parses", "" },
  { "db.query.text", "req[64] -> command + first key", "semconv", "the command parses",
    "deliberately command + key only -- RESP values are never copied into the span" },
  { "error.type", "constant \"redis_error\"", "semconv", "resp[0] == '-' (RESP error reply)",
    "also sets Span.status = ERROR (the RED error axis)" },
  { "network.peer.address", "daddr -> inet_ntop", "semconv", "always", "" },
  { "network.peer.port", "dport", "semconv", "always", "" },
  { "network.transport", "constant \"tcp\"", "semconv", "always", "" },
  { "process.executable.name", "comm[16]", "semconv", "comm non-empty", "" },
};

static const char *const cc_rec_redis_enrichers[] = { "k8s", "cri" };

static const CcEgressSpan cc_rec_redis_egress = {
  "spnl_otlp_redis_span_push",
  "%s",
  "db.operation.name",
  "CLIENT",
  "start = start_ktime (ktime -> unix); end = start + duration_ns",
  "the record layout is identical to the http channel, which is why one drain used to serve both; "
  "each now unpacks through its own generated mirror",
  cc_rec_redis_egress_attrs,
  (int)(sizeof cc_rec_redis_egress_attrs / sizeof cc_rec_redis_egress_attrs[0]),
  cc_rec_redis_enrichers,
  (int)(sizeof cc_rec_redis_enrichers / sizeof cc_rec_redis_enrichers[0]),
};

static const CcRecSchema cc_rec_redis = {
  .id            = "redis",
  .banner        = NULL,   /* inside the "per-unit Redis L7 RED" template section */
  .struct_suffix = "redis_event",
  .map_suffix    = "redis_events",
  .ringbuf_size  = "256 * 1024",
  .fields        = cc_rec_redis_fields,
  .nfields       = (int)(sizeof cc_rec_redis_fields / sizeof cc_rec_redis_fields[0]),
  .producers     = cc_rec_redis_producers,
  .nproducers    = (int)(sizeof cc_rec_redis_producers / sizeof cc_rec_redis_producers[0]),
  .egress        = &cc_rec_redis_egress,
};

/* ================== off-CPU request-window record (offcpu_emit) =========
 *
 * "Why was this request slow": an HTTP request window (recv -> send) plus how
 * much of it was spent off-CPU and the kernel stack of the wait.
 *
 * This is the one channel where the append-only READING rule is load-bearing
 * rather than historical: appended start_ktime and hdr_ext, and the runtime
 * deliberately keeps accepting the shorter pre- record (zero-filling the two
 * new fields) instead of dropping it. `required_through = "cgid"` is that rule,
 * declared -- everything after cgid reads as zero when the producer is older. */
static const CcRecField cc_rec_offcpu_fields[] = {
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid (the request handler)", "int" },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str" },
  { "duration_ns", "__u64",                 0,  8, 8, "whole request window (recv -> send), = parent span duration", "int" },
  { "offcpu_ns",   "__u64",                 0,  8, 8, "voluntary off-CPU time accumulated inside the window. Not exposed raw: what the span carries is min(offcpu_ns, duration_ns) -- the accumulation and the window are measured by different hooks, so a record where the sum overshoots the window is expressible. The clamped value is the derived property ev.offcpu_ns, the same function's output as spnl.offcpu_ns", NULL },
  { "wait_stack",  "__s32",                 0,  4, 4, "bpf_get_stackid of the last wait; -1 = none. Classified against kallsyms in userspace. Not exposed: a stack id is an index into a per-unit BPF map, meaningless as a number in Ruby -- the reading of it is the derived property ev.wait_kind", NULL },
  { "req",         "unsigned char",        64,  1, 1, "first 64B of the request; \"METHOD path HTTP/x\" parsed in userspace", NULL },
  { "resp",        "unsigned char",        16,  1, 1, "first 16B of the response; \"HTTP/1.1 NNN\" status parsed in userspace", NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int" },
  { "start_ktime", "__u64",                 0,  8, 8, "real window start (span anchor + child correlation); 0 on a pre- producer. Not exposed: a raw ktime is an anchor for span assembly (layer 2), not something a consumer can judge on", NULL },
  { "hdr_ext",     "unsigned char",       128,  1, 1, "first 128B of the request head, scanned for a W3C traceparent in userspace; zero on a pre- producer. Not exposed: raw header bytes, like dns `raw` -- what a consumer wants from them (the trace context) is layer 2's, and the request line is already ev.method / ev.path", NULL },
};

/* The off-CPU record's derived properties. Three of them are the HTTP
 * head read (the SAME functions the http channel declares -- already made
 * both span paths call them, this publishes them to Ruby too), and three are the
 * reason this channel could not simply expose its fields:
 *
 *   ev.offcpu_ns  is NOT the field: the span carries min(offcpu_ns, duration_ns).
 *                 Exposing the field raw would repeat the earlier srtt mistake in a
 *                 nastier form -- the two numbers agree on every ordinary record
 *                 and differ exactly on the pathological ones a consumer would
 *                 want to filter for.
 *   ev.oncpu_ns   is not a field AT ALL: it is duration - clamped off-CPU, i.e.
 *                 the attribute spnl.oncpu_ns. A property the span has and Ruby
 *                 cannot read is the same half-answer removed from http.
 *   ev.wait_kind  is the reading of `wait_stack` against kallsyms -- the one
 *                 derivation whose input is not entirely inside the record (it
 *                 also reads the stack map of the object the drain came from).
 *                 It still fits "record_to_str": the record names the stack, and
 *                 the ambient map is the same one the concise push already uses.
 *                 See spnl_offcpu_wait_kind() for why that is not a new form. */
static const CcRecDerived cc_rec_offcpu_derived[] = {
  { "method", "str", "req", "spnl_http_method", "bytes_to_str", 65,
    "first token of the request head -- the http channel's derivation, verbatim "
    "(offcpu.req is the same bounded copy of the same wire, pinned by a _Static_assert). "
    "cap 65 = req[64] + NUL, the same bound as http.method for the same reason" },
  { "path",   "str", "req", "spnl_http_path",   "bytes_to_str", 65,
    "second token of the request head (path only). Shares http's derivation and bound" },
  { "status", "int", "resp", "spnl_http_status", "bytes_to_int", 0,
    "status digits of the response head; 0 when it does not parse. "
    ">= 500 is what sets Span.status = ERROR on the egress side" },
  { "offcpu_ns", "int", "offcpu_ns clamped to duration_ns", "spnl_offcpu_offcpu_ns", "record_to_int", 0,
    "nanoseconds of the request window spent NOT running -- the same value the span "
    "attribute spnl.offcpu_ns carries, because both are this one function's output. The clamp is "
    "not cosmetic: offcpu_ns is accumulated by sched_switch while duration_ns is measured by the "
    "recv/send pair, so a record whose sum exceeds its window is expressible, and the span has "
    "always reported the clamped number. A consumer filtering on `ev.offcpu_ns > x` therefore "
    "filters on exactly what it would see on the span" },
  { "oncpu_ns", "int", "duration_ns - min(offcpu_ns, duration_ns)", "spnl_offcpu_oncpu_ns", "record_to_int", 0,
    "nanoseconds of the window spent running = the span attribute spnl.oncpu_ns. Not a "
    "field: the record carries the window and the wait, and this is their difference (so "
    "ev.oncpu_ns + ev.offcpu_ns == ev.duration_ns by construction)" },
  { "wait_kind", "str", "wait_stack -> kallsyms scan of the captured frames", "spnl_offcpu_wait_kind", "record_to_str", 16,
    "what the request was waiting ON, byte-identical to the span attribute spnl.wait.kind "
    "(same function): \"io\" / \"lock\" / \"sleep\" / \"net\" / \"other\" (a wait whose frames match no "
    "signature) / \"none\" (wait_stack < 0, i.e. the window contained no voluntary off-CPU) / "
    "\"unknown\" (the stack map or /proc/kallsyms could not be read). Best-effort by construction: "
    " classifies the LAST wait's top frames, not every wait in the window. "
    "cap 16 >= the longest of that closed set of literals (\"unknown\", 7 + NUL)" },
};

static const char *const cc_rec_offcpu_producers[] = { "offcpu_emit" };

static const CcEgressAttr cc_rec_offcpu_egress_attrs[] = {
  { "http.request.method", "req[64] -> first token", "semconv", "the request head parses", "" },
  { "url.path", "req[64] -> second token", "semconv", "the request head parses", "" },
  { "http.response.status_code", "resp[16] -> status digits", "semconv", "the response head parses",
    "status >= 500 also sets Span.status = ERROR" },
  { "spnl.offcpu_ns", "min(offcpu_ns, duration_ns)", "spinel", "always",
    "eBPF-specific -- how much of the request was spent not running" },
  { "spnl.oncpu_ns", "duration_ns - offcpu_ns", "spinel", "always", "" },
  { "spnl.wait.kind", "wait_stack -> kallsyms scan (io / lock / sleep / net / other / none / unknown)",
    "spinel", "always",
    "best-effort classification of the last wait's top frames. \"none\" = no voluntary "
    "off-CPU in the window (wait_stack < 0); \"unknown\" = the stack map or /proc/kallsyms could "
    "not be read. Same function as the typed consumer's ev.wait_kind" },
  { "process.executable.name", "comm[16]", "semconv", "comm non-empty", "" },
};

static const char *const cc_rec_offcpu_enrichers[] = { "k8s", "cri" };

static const CcEgressSpan cc_rec_offcpu_egress = {
  "spnl_otlp_offcpu_span_push",
  "%s %s",
  "http.request.method, url.path",
  "SERVER",
  "start = now - duration_ns (the push path) or start_ktime (the request-tree path); "
  "end = start + duration_ns",
  "one record renders as TWO spans: the request window plus, when offcpu_ns > 0, a nested "
  "\"off-CPU wait (<kind>)\" child carrying spnl.wait.kind and spnl.offcpu_ns. The typed "
  "consumer's to_span(ev) builds the request-window span (the parent, which carries all the "
  "attributes above); nesting the wait child is the concise push's rendering of the same values",
  cc_rec_offcpu_egress_attrs,
  (int)(sizeof cc_rec_offcpu_egress_attrs / sizeof cc_rec_offcpu_egress_attrs[0]),
  cc_rec_offcpu_enrichers,
  (int)(sizeof cc_rec_offcpu_enrichers / sizeof cc_rec_offcpu_enrichers[0]),
};

static const CcRecSchema cc_rec_offcpu = {
  .id               = "offcpu",
  .banner           = NULL,   /* inside the "per-unit off-CPU L7 correlation" section */
  .struct_suffix    = "offcpu_event",
  .map_suffix       = "offcpu_events",
  .ringbuf_size     = "256 * 1024",
  .fields           = cc_rec_offcpu_fields,
  .nfields          = (int)(sizeof cc_rec_offcpu_fields / sizeof cc_rec_offcpu_fields[0]),
  .required_through = "cgid",   /* the earlier start_ktime / hdr_ext read as zero on an older producer */
  .producers        = cc_rec_offcpu_producers,
  .nproducers       = (int)(sizeof cc_rec_offcpu_producers / sizeof cc_rec_offcpu_producers[0]),
  .egress           = &cc_rec_offcpu_egress,
  .derived          = cc_rec_offcpu_derived,
  .nderived         = (int)(sizeof cc_rec_offcpu_derived / sizeof cc_rec_offcpu_derived[0]),
  /* Publishes a typed consumer. This channel was the last to get one because three
   * of its seven egress attributes would disagree with the span if the underlying
   * fields were published raw: one is clamped, one is a value no field holds, and
   * one is a classification that reads state outside the record entirely. Only once
   * all three are derivations does "what Ruby sees is what the span says" hold.
   *
   * Exposure stays minimal: the plain scalars a decision can be made on (pid, comm,
   * duration_ns, cgid) and the six derived values that already carry meaning. The
   * stack id, the window anchor and the captured header bytes are not published --
   * none of them is something a probe can act on, and withdrawing exposure later is
   * a breaking change the record gate refuses. */
  .typed_consumer   = 1,
};

/* ================== sock-keyed L7 stream record (emit_tcp_stream) =======
 *
 * Raw per-connection bytes for userspace reassembly. No egress span: the current
 * consumer is the glue-side drain in bin/spinel-ebpf, which prints one hex line
 * per record. Declaring it here makes the kernel struct derive from the table
 * like the others; the glue reader is still hand-written (S5 boundary). */
static const CcRecField cc_rec_l7stream_fields[] = {
  { "hdr",  "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL },
  { "sock", "__u64",                 0,  8, 8, "sock pointer -- the reassembly key (one stream per connection)", NULL },
  { "len",  "__u32",                 0,  4, 4, "valid bytes in raw (raw is length-bounded, NOT NUL-terminated)", NULL },
  { "raw",  "char",                128,  1, 1, "up to 128B of stream payload; the consumer reads exactly len bytes", NULL },
};

static const char *const cc_rec_l7stream_producers[] = { "emit_tcp_stream", "emit_tcp_payload" };

static const CcRecSchema cc_rec_l7stream = {
  .id            = "l7stream",
  .banner        = "/* === per-unit sock-keyed L7 stream channel === */",
  .struct_suffix = "l7stream_event",
  .map_suffix    = "l7stream_events",
  .ringbuf_size  = "256 * 1024",
  .fields        = cc_rec_l7stream_fields,
  .nfields       = (int)(sizeof cc_rec_l7stream_fields / sizeof cc_rec_l7stream_fields[0]),
  .producers     = cc_rec_l7stream_producers,
  .nproducers    = (int)(sizeof cc_rec_l7stream_producers / sizeof cc_rec_l7stream_producers[0]),
};

/* Every declared channel, in publication order (the order `capabilities --json`
 * and the append-only gate see). A static inline accessor rather than a bare
 * array so that a TU which only needs one channel does not carry an unused
 * static (the codegen names its channels directly; the generator walks them). */
static inline const CcRecSchema *const *cc_rec_all(int *n) {
  static const CcRecSchema *const v[] = {
    &cc_rec_dns, &cc_rec_conn, &cc_rec_l7, &cc_rec_http,
    &cc_rec_redis, &cc_rec_offcpu, &cc_rec_l7stream,
  };
  *n = (int)(sizeof v / sizeof v[0]);
  return v;
}

#endif /* SPNL_RECORD_SCHEMA_H */
