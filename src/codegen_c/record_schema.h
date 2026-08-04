/* record_schema.h -- declarative ringbuf record contracts.
 *
 * A packed-record emit builtin (emit_dns, emit_connect, ...) is one half of a
 * contract: the kernel producer writes a fixed struct into a per-unit ringbuf and
 * the userspace consumer (src/runtime/otlp/otlp_agent.c) reads those same bytes
 * back. Historically each layout was written twice by hand -- once as a
 * templates/<chan>.template.c struct, once as memcpy offsets in the runtime --
 * with only comments keeping the two in sync. That is the offset-desync risk
 * described below.
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
 * There is a fifth reading of the same records: what they AGGREGATE into. A
 * span answers "what happened once"; a metric answers "how often, and how long",
 * and declaring that here means the generator can compute -- before any data
 * exists -- the ceiling on how many time series a probe can create. That number
 * is the one property of this contract with no local symptom when it is wrong,
 * which is why it is computed rather than asserted. See the CcRecMetric block.
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
  /* The `filter_by` key that selects on THE SAME VALUE in the kernel, or NULL
   * when no kernel key does.
   *
   * A userspace consumer filter (`keep_if :<chan>, <prop>: :eq`) and the
   * in-kernel common filter can express the same narrowing -- but only where the
   * record's field really is the value `bpf_get_current_*()` returns in the
   * handler that emits it. Where it is, the kernel's is strictly better (the
   * record is never created, so the ringbuf, the drain and the send are all
   * saved) and declaring the correspondence here is what lets the consumer
   * transform refuse the redundant spelling and name the replacement.
   *
   * WHY THIS IS PER FIELD AND NOT PER KEY NAME. "The record's pid" and "the
   * current task's pid" are the same number in some channels and different in
   * others, and the difference is invisible from the field's name:
   *
   *   dns    -- every producer (emit_dns, dns_emit) fills pid/comm/cgid from
   *             bpf_get_current_*() in the same task the record is about, and
   *             the request/response pair runs in that one task. Same value.
   *   conn   -- sock_owner_set OVERWRITES pid/comm/cgid with the stashed
   *             connecting task, precisely because the ESTABLISHED transition
   *             fires in softirq where the current task is swapper/0. The kernel
   *             key would test swapper.
   *   l7 /   -- filled from the entry stashed at send time, correlated by sock.
   *   http      The emit runs in the receiving path; the record is about the
   *             earlier one.
   *   offcpu -- the emit does read the current task, but the channel needs its
   *             sched_switch handler to see EVERY task: offcpu_account keys on
   *             the tracepoint's prev_pid/next_pid, so gating that handler on
   *             the current task would silently drop the "coming back" half of
   *             the accounting (current is still prev when next is scheduled in).
   *
   * So a channel that correlates across tasks -- which is most of them -- has no
   * kernel equivalent for its identity fields, and that is a fact about its
   * producers, not about the word "pid". Declaring it is the only way the
   * affordance surface can answer "why is this filter in userspace" with
   * something other than prose.
   *
   * The value must be one of CommonFilter::KEYS (src/spinel_ebpf/common_filter.rb);
   * tests/spinel_ebpf/keep_filter_test.rb checks the join, since the generator
   * has no view of the Ruby-side vocabulary. */
  const char *kfilter;
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
  const char *impl;      /* C function that performs it (defined in the runtime), or,
                          * for impl_form "code_to_name", the id of a CcValueMap below */
  const char *impl_form; /* its calling convention; see tools/gen_record_mirror.c */
  int         cap;       /* output buffer size for a "str" derivation; 0 for "int" */
  const char *note;      /* provenance / caveats -- surfaced to Ruby */
} CcRecDerived;

/* --- Type-driven derivations: a value map ---------------------------------
 *
 * Everything above declares a derivation's EXISTENCE and leaves its body in C,
 * because a DNS QNAME walk or an HTTP request-line parse is domain logic. One
 * shape of derivation is not domain logic at all: a CODE -- a value drawn from a
 * closed set whose members have names. `oldstate == 2` is TCP_SYN_SENT and
 * nothing else; there is no algorithm, only the table. Written as C, that table
 * is a hand-typed switch that nothing checks, which is how the codegen's own
 * TCP_STATE_* list came to be three enumerators behind the kernel, measured
 * against its BTF, without anybody noticing: a missing name does not fail, it
 * just stops naming.
 *
 * So for codes the declaration IS the implementation. A CcValueMap is the whole
 * mapping; tools/gen_record_mirror.c generates the lookup function, and a
 * derivation opts in by naming the map in `impl` with impl_form "code_to_name".
 * That is the layer this adds: a code gets a name because its TYPE was
 * declared, not because somebody wrote the switch again.
 *
 * WHY EVERY MAP MUST DECLARE ITS AUTHORITY, AND WHY ONE IS REFUSED OUTRIGHT
 *
 * A wrong entry in such a table cannot be caught downstream. `error=2` rendered
 * as "EPERM" is a plausible errno; `oldstate=2` rendered as "SYN_RECV" is a
 * plausible state. This is the same silent-failure class the kernel-side string
 * and namespace builtins attack -- so the map does not just carry names, it
 * carries where the names come FROM, in a form a test can go and check
 * (tests/spinel_ebpf/value_map_test.rb reads `btf_*` and asks the running
 * kernel's BTF).
 *
 * `arch_invariant` is the harder half, and it is why the generator has a refusal
 * rather than a warning. A syscall number is a code with names, and it is the
 * one shape of code that MUST NOT be baked into a committed artifact: measured
 * with `ausyscall`, the number 2 is `io_submit` on aarch64, `open` on x86_64 and
 * `fork` on i386/arm/ppc/s390x. All four are real syscalls, so a table baked on
 * one architecture renders a plausible wrong name on the next -- exactly the
 * failure this file exists to make inexpressible, and exactly the seam the
 * portability contract has to name. A map that cannot say `arch_invariant = 1`
 * therefore does not compile: it must either be resolved at RUNTIME on the
 * machine that produced the record (glibc's strerrorname_np / sigabbrev_np are
 * that answer for errno and signal, and were measured present here) or carry the
 * architecture in the contract. */
typedef struct {
  long        value;
  const char *name;   /* the name this value has -- never a guess, never a range */
} CcValueName;

typedef struct {
  const char *id;             /* stable map id, named by a derivation's `impl` */
  const char *authority;      /* where the truth lives, in prose (surfaced to Ruby) */
  /* Rendering for a value the table does not name. Either a plain literal (a
   * closed reading whose fallback is itself a documented answer, like conn's
   * "other") or a format with EXACTLY ONE `%ld`, which keeps the number the
   * reader would otherwise lose. The generator rejects any other conversion:
   * an unnamed code must not come out looking like a name. */
  const char *unknown;
  /* 1 = one table for every architecture spinel-ebpf targets. 0 does not compile
   * (see the block comment above); the field exists so that the refusal is a
   * declared property rather than a convention nobody wrote down. */
  int         arch_invariant;
  /* Machine-checkable authority. `btf_anchor` names one enumerator of the kernel
   * BTF enum this map is drawn from and `btf_prefix` is what gets stripped from
   * the enumerator to yield the map's name. `btf_mode`:
   *   "names" -- the map IS the enum: every enumerator (minus `btf_omit`) must
   *              appear here with the same value and the stripped name
   *   "keys"  -- only the VALUES are the enum's; the names are this project's own
   *              reading of it, so the check is that no key is a number the
   *              kernel never produces
   *   NULL    -- not drawn from a kernel enum (no machine check is possible) */
  const char *btf_mode;
  const char *btf_anchor;
  const char *btf_prefix;
  const char *btf_omit;       /* space-separated enumerators legitimately absent */
  const CcValueName *values;
  int         nvalues;
  const char *note;
} CcValueMap;

/* --- tcp_state: the kernel's TCP state enum, by name ----------------------
 *
 * The consumer is conn's `oldstate`, which reaches userspace as a bare number.
 * The only thing the span used to say about it was spnl.conn.direction, and
 * that reading answers one question ("who opened this?") by collapsing ten of the
 * thirteen states into "other" -- so a record from a probe that does not filter
 * on ESTABLISHED left the process with its state erased. This map is the other
 * reading: the state's own name, which is what the kernel calls it.
 *
 * TCP_MAX_STATES is omitted because it is the enum's bound, not a state; a sock
 * is never in it. Everything else is named, including TCP_BOUND_INACTIVE (13),
 * which the codegen's hand-typed TCP_STATE_* table still does not know about
 * -- the difference between a table nothing checks and one that is checked
 * against the kernel it describes. */
static const CcValueName cc_valmap_tcp_state_values[] = {
  {  1, "ESTABLISHED"    }, {  2, "SYN_SENT"    }, {  3, "SYN_RECV"  },
  {  4, "FIN_WAIT1"      }, {  5, "FIN_WAIT2"   }, {  6, "TIME_WAIT" },
  {  7, "CLOSE"          }, {  8, "CLOSE_WAIT"  }, {  9, "LAST_ACK"  },
  { 10, "LISTEN"         }, { 11, "CLOSING"     }, { 12, "NEW_SYN_RECV" },
  { 13, "BOUND_INACTIVE" },
};

static const CcValueMap cc_valmap_tcp_state = {
  .id        = "tcp_state",
  .authority = "the kernel's own TCP state enum (include/net/tcp_states.h; the same values are "
               "frozen into the uapi enum BPF_TCP_* in include/uapi/linux/bpf.h). Both are in "
               "vmlinux BTF, so the declaration below is checked against the running kernel "
               "rather than trusted",
  /* A state this kernel has and the table does not name keeps its number rather
   * than borrowing a neighbour's name: a newer kernel appends states (13 is
   * itself an appended one), and "an unnamed 14" is true where "CLOSING" is not. */
  .unknown        = "unnamed(%ld)",
  /* TCP state numbering lives in one generic header. No architecture defines its
   * own -- unlike the syscall table, which is why that one is refused. */
  .arch_invariant = 1,
  .btf_mode       = "names",
  .btf_anchor     = "TCP_ESTABLISHED",
  .btf_prefix     = "TCP_",
  .btf_omit       = "TCP_MAX_STATES",
  .values         = cc_valmap_tcp_state_values,
  .nvalues        = (int)(sizeof cc_valmap_tcp_state_values / sizeof cc_valmap_tcp_state_values[0]),
  .note           = "the state a sock was in, spelled as the kernel spells it (without the TCP_ "
                    "prefix, which is the enum's namespace and not part of the name of the state)",
};

/* --- conn_direction: this project's READING of the same enum ---------------
 *
 * The "who opened this connection" answer, which used to be three lines of C
 * in otlp_agent.c (`oldstate == 2 ? "active" : oldstate == 3 ? "passive" :
 * "other"`) with the two numbers written as numbers. As a declared map the same
 * output is byte-identical, but the two keys are now checkable: `btf_mode =
 * "keys"` makes the test assert that 2 and 3 are values the kernel's TCP state
 * enum actually produces, which is the half of "did I write the right number"
 * that a name map can decide on its own.
 *
 * The names are NOT the kernel's (the kernel has no notion of active/passive), so
 * this is deliberately a different mode from tcp_state: what is borrowed from the
 * kernel is the key space, not the vocabulary. Its "other" fallback stays a plain
 * literal -- it is a published attribute value with a documented meaning ("some
 * transition that is neither a client nor a server opening"), not a value the
 * table failed to name. That is why both readings are now published: `direction`
 * answers the question it was built for and `tcp_state` keeps the fact. */
static const CcValueName cc_valmap_conn_direction_values[] = {
  { 2, "active"  },   /* TCP_SYN_SENT -> ESTABLISHED: we opened it (client) */
  { 3, "passive" },   /* TCP_SYN_RECV -> ESTABLISHED: we accepted it (server) */
};

static const CcValueMap cc_valmap_conn_direction = {
  .id             = "conn_direction",
  .authority      = "this project's reading of the pre-ESTABLISHED TCP state. The names are this "
                    "project's (semconv has no connection-direction key); only the two keys "
                    "come from the kernel enum, and those are checked against its BTF",
  .unknown        = "other",
  .arch_invariant = 1,
  .btf_mode       = "keys",
  .btf_anchor     = "TCP_ESTABLISHED",
  .btf_prefix     = "TCP_",
  .btf_omit       = "",
  .values         = cc_valmap_conn_direction_values,
  .nvalues        = (int)(sizeof cc_valmap_conn_direction_values / sizeof cc_valmap_conn_direction_values[0]),
  .note           = "\"active\" = we initiated, \"passive\" = we accepted, \"other\" = a transition "
                    "into ESTABLISHED from neither (and, on a probe that emits every transition, "
                    "any transition at all -- which is what spnl.conn.tcp_state is for)",
};

/* Every declared value map. Same shape as cc_rec_all() below: the generator, the
 * affordance surface and the authority test all walk one registry. */
static inline const CcValueMap *const *cc_valmap_all(int *n) {
  static const CcValueMap *const v[] = { &cc_valmap_tcp_state, &cc_valmap_conn_direction };
  *n = (int)(sizeof v / sizeof v[0]);
  return v;
}

/* --- Metrics from a record channel ----------------------------------------
 *
 * A channel already declares what one record MEANS as a span (CcEgressSpan). A
 * span is the right shape for "what happened once"; it is the wrong shape for
 * "how often, and how long" across millions of records. That second reading is a
 * metric, and until now the only way to get one was to write the aggregation in
 * C by hand (otlp_httpspan.c does exactly that for the native HTTP server).
 *
 * THE TRAP THIS DECLARATION EXISTS TO CLOSE
 *
 * A metric's cost is not its value, it is its LABELS: one time series per
 * distinct combination, forever, in the backend. Put `url.path` on a metric and
 * a probe that was fine in test bankrupts a tenant in production -- and it does
 * so at exit 0, with every span still correct, because nothing in the process
 * ever sees the bill. That is the same shape as a ring-full sample the kernel
 * dropped, or a map that silently filled: a loss with no local symptom.
 *
 * The obvious defences do not work, and both were measured:
 *
 *   - "measure it first" cannot establish a label. Over one workload `pid`
 *     showed 1 distinct value and looked as safe as anything here; over a second
 *     workload -- same probe, same field, 30 client processes instead of 1 -- it
 *     showed 30. Measurement refutes a label (a candidate that grows 1:1 with
 *     traffic is settled: `url.path` did, and so did `dport`, which is a __u16
 *     and still reached 101 distinct values in 200 records because the peer of an
 *     inbound record is an ephemeral port). It cannot certify one, because the
 *     next workload is not the one that was measured.
 *   - "let the author declare a bound" is a claim about data nobody has seen.
 *
 * So the rule here is neither: a label must have a bound the GENERATOR can
 * compute from a declaration, before any data exists, and there are exactly two
 * ways to give it one:
 *
 *   (1) `values` + `fallback` -- the permitted set is written here and ENFORCED
 *       when the metric is emitted: a value outside the set is emitted as
 *       `fallback`, never as itself. The bound is then a fact about the METRIC
 *       (nvalues + 1), not a claim about the data, and it holds for traffic
 *       nobody has seen. This is also what OpenTelemetry itself does for
 *       http.request.method, whose registry value is `_OTHER` for any method
 *       outside the known set -- same problem, same answer.
 *   (2) a `code_to_name` derivation whose value map renders unnamed codes
 *       as a LITERAL. Then the map is already a closed set and the bound is its
 *       size + 1, computed from the map. A map whose `unknown` carries `%ld` is
 *       NOT closed -- it renders each unnamed code as its own string -- so it is
 *       refused here even though it is perfectly good for a span attribute.
 *       (`tcp_state` is exactly that map: a fine span attribute, not a label.)
 *
 * Anything else does not compile. `url.path`, `dns.question.name`, `peer`,
 * `comm`, `pid`, `cgid` have no declaration that bounds them, so they cannot be
 * named as a label at all -- the refusal names the property and says where the
 * value is still available, which is the span (`ev.path` is not lost; it just
 * is not a label). The generator then multiplies the label bounds into a series
 * bound per metric, sums them, and refuses the whole file if the total exceeds
 * the runtime's series capacity -- so a declaration that could not be exported
 * is not expressible, and the accumulator array cannot overflow at runtime
 * because the declaration already proved it cannot.
 *
 * RELATION TO THE SPAN. A metric never invents a value. `value_from` and
 * every label's `from` must name a PUBLISHED property of the channel -- the same
 * field or derivation the typed consumer reads and the span builder calls -- so
 * the number in the histogram is the number in the span, by construction and for
 * the same reason `ev.srtt_us` and net.peer.srtt_us cannot drift. Where a
 * label's declared set collapses a value to `fallback`, the span still carries
 * the exact one: the metric is a declared COARSENING of the span, and the
 * affordance surface prints it as such rather than leaving a reader to discover
 * that `_OTHER` in a dashboard. */
typedef struct {
  const char *key;        /* attribute key, verbatim as emitted */
  const char *from;       /* published property of the channel that supplies it */
  const char *stability;  /* "semconv" = OTel registry key; "spinel" = project-specific */
  /* Bound, route (1): the permitted set, enforced at emit time. NULL = route (2),
   * in which case `from` must be a code_to_name derivation over a closed map. */
  const char *const *values;
  int         nvalues;
  const char *fallback;   /* what a value outside `values` is emitted as */
  const char *note;
} CcMetricLabel;

/* Explicit histogram bucket boundaries, declared once and shared. Bucket layout
 * is an interop decision, not a local one: a consumer that re-buckets loses the
 * ability to compare, so the boundaries live here with the authority that chose
 * them (OBI's were adopted for exactly that reason, and this is that same array,
 * now with one author instead of two). */
typedef struct {
  const char   *id;
  const char   *unit;       /* the unit the boundaries below are expressed in */
  const char   *authority;
  const double *values;     /* ascending */
  int           nvalues;
  const char   *note;
} CcBoundsSet;

/* OBI's default duration boundaries (pkg/export/bucket.go), in seconds -- the
 * same 15 numbers http.server.request.duration was aligned to so that a
 * spinel-ebpf probe and an OBI agent land in comparable buckets. Declared here so
 * that a second duration metric cannot quietly choose a different ruler; the
 * runtime's own copy in otlp_httpspan.c is now this array. */
static const double cc_bounds_otel_duration_s_values[] =
  { 0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10 };

static const CcBoundsSet cc_bounds_otel_duration_s = {
  .id        = "otel_duration_s",
  .unit      = "s",
  .authority = "OpenTelemetry eBPF Instrumentation (OBI, ex-Beyla) pkg/export/bucket.go -- the "
               "default duration buckets its HTTP/RPC duration metrics use. They were adopted for "
               "http.server.request.duration so that the two agents' histograms are comparable, and "
               "the array itself is now the declaration both sides read",
  .values    = cc_bounds_otel_duration_s_values,
  .nvalues   = (int)(sizeof cc_bounds_otel_duration_s_values / sizeof cc_bounds_otel_duration_s_values[0]),
  .note      = "seconds. A record carries nanoseconds, so a metric over a *_ns property declares "
               "value_unit \"ns\" and the generator emits the ns -> s conversion; the pair of units "
               "is checked against a closed list, so an unconverted nanosecond value cannot be "
               "silently bucketed against second boundaries",
};

static inline const CcBoundsSet *const *cc_bounds_all(int *n) {
  static const CcBoundsSet *const v[] = { &cc_bounds_otel_duration_s };
  *n = (int)(sizeof v / sizeof v[0]);
  return v;
}

/* One metric derived from a channel's records.
 *
 * `kind`:
 *   "counter"   -- monotonic Sum of records matching the label combination. No
 *                  value is read; `value_from`/`value_unit`/`bounds` must be NULL.
 *   "histogram" -- explicit-bounds Histogram of `value_from` over `bounds`. Its
 *                  data points also carry `count`, so a histogram already answers
 *                  the rate question and a channel does not need both.
 * Both spellings exist because both are exportable: the runtime encodes a Sum and
 * an explicit-bounds Histogram, in protobuf and in JSON. A third kind would have
 * to bring its encoder with it -- the generator refuses any other word. */
typedef struct {
  const char *id;          /* stable id within the channel (affordance + gate key) */
  const char *name;        /* OTel metric name, verbatim as emitted */
  const char *kind;        /* "counter" | "histogram" */
  const char *unit;        /* UCUM unit of the metric as exported */
  const char *value_from;  /* histogram: published int property supplying the value */
  const char *value_unit;  /* histogram: the unit that property is already in */
  const char *bounds;      /* histogram: id of a CcBoundsSet */
  const CcMetricLabel *labels;
  int         nlabels;
  const char *note;
} CcRecMetric;

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
  /* Metrics this channel's records aggregate into. Every `from` names a
   * published property, so a channel declaring metrics must also publish its
   * typed consumer (`typed_consumer = 1`); the generator enforces that rather
   * than letting a metric read a property nobody can see. */
  const CcRecMetric  *metrics;
  int                 nmetrics;
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
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid (init-ns)", "int", "pid" },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str", "comm" },
  { "raw",         "unsigned char",        64,  1, 1, "first 64B of the DNS payload; QNAME parsed in userspace", NULL, NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int", "cgroup_id" },
  { "duration_ns", "__u64",                 0,  8, 8, "resolution RTT; 0 = query-only", "int", NULL },
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

/* What spnl_otlp_dns_span_push makes of one record. Mirrors -- and now *feeds* --
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
  { "hdr",       "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "pid",       "__u32",                 0,  4, 4, "producer tgid; sock_owner_set restores it when the ESTABLISHED transition fires in softirq", "int", NULL },
  { "comm",      "char",                 16,  1, 1, "bpf_get_current_comm -- the connecting process, not the idle task", "str", NULL },
  { "daddr",     "__u32",                 0,  4, 4, "remote IPv4 address, network byte order (valid when family == AF_INET)", NULL, NULL },
  { "dport",     "__u16",                 0,  2, 2, "remote port, host byte order", "int", NULL },
  { "family",    "__u16",                 0,  2, 2, "address family (2 = AF_INET, 10 = AF_INET6)", NULL, NULL },
  { "srtt_us",   "__s64",                 0,  8, 8, "tcp_sock->srtt_us via CO-RE, on the wire in the kernel's 1/8 us scale. Not exposed raw: the us value is the derived property ev.srtt_us, which is the same function's output as the span attribute net.peer.srtt_us", NULL, NULL },
  { "cgid",      "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int", NULL },
  { "oldstate",  "__u32",                 0,  4, 4, "TCP state before ESTABLISHED (2 = SYN_SENT -> active, 3 = SYN_RECV -> passive)", NULL, NULL },
  { "daddr6_hi", "__u64",                 0,  8, 8, "remote IPv6 address, bytes 0..7 (network order)", NULL, NULL },
  { "daddr6_lo", "__u64",                 0,  8, 8, "remote IPv6 address, bytes 8..15 (network order)", NULL, NULL },
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
  { "direction", "str", "oldstate", "conn_direction", "code_to_name", 16,
    "\"active\" (we initiated: SYN_SENT -> ESTABLISHED), \"passive\" (we accepted: SYN_RECV -> "
    "ESTABLISHED), \"other\". Byte-identical to the span attribute spnl.conn.direction (same function). "
    "cap 16 >= the longest of that closed set of literals (\"passive\", 7 + NUL). "
    "The three-line switch this used to be is now the declared value map `conn_direction`, so "
    "the two state numbers it keys on are checked against the kernel's enum instead of trusted" },
  { "tcp_state", "str", "oldstate", "tcp_state", "code_to_name", 24,
    "the pre-transition TCP state under its own name (\"SYN_SENT\", \"CLOSE\", ...) = the span "
    "attribute spnl.conn.tcp_state, from the declared value map `tcp_state` checked against the "
    "kernel's BTF enum. `direction` answers who opened the connection and collapses ten of the "
    "thirteen states into \"other\"; this keeps the state. A state this kernel has but the map does "
    "not name reads as \"unnamed(<n>)\" -- the number survives rather than borrowing a name. "
    "cap 24 >= both bounds, and unlike every other cap in this file the generator COMPUTES them "
    "rather than taking the note's word for it: the longest name (\"BOUND_INACTIVE\" = 14 + NUL) and "
    "the widest unnamed rendering of the source field (`oldstate` is a __u32, so "
    "\"unnamed(4294967295)\" = 19 + NUL). A closed set is the one derivation whose bound is a fact" },
  { "srtt_us", "int", "srtt_us (the kernel's 1/8 us scale)", "spnl_conn_srtt_us", "record_to_int", 0,
    "smoothed RTT in MICROSECONDS -- the same value the span attribute net.peer.srtt_us "
    "carries, because both are this one function's output. The >>3 that turns the kernel's 1/8 us "
    "into us is layer 2's business, so a consumer never divides by 8. Note it is the L4 smoothed RTT "
    "(a property of the connection), not an L7 round trip" },
};

/* --- conn's metric: route (2), a bound taken from an existing value map -------
 *
 * `direction` is a code_to_name derivation over `conn_direction`, whose unknown
 * rendering is the plain literal "other" -- so the set of strings that derivation
 * can EVER return is {active, passive, other} and the generator can count it: 3.
 * Nothing is declared twice here; the label just names the property, and the
 * value map (already checked against the kernel's BTF) supplies the bound.
 *
 * The contrast worth keeping in view is `tcp_state`, the sibling derivation over
 * the same field. Its map renders an unnamed code as "unnamed(%ld)", which is the
 * right answer for a span (the number survives rather than borrowing a
 * name) and disqualifies it as a label, because "closed except for a counter" is
 * not closed. Same record, same byte, two readings, and only one of them is a
 * safe label -- which is why this is a property of the DECLARATION and not of
 * the field. */
static const CcMetricLabel cc_metric_conn_count_labels[] = {
  { "spnl.conn.direction", "direction", "spinel", NULL, 0, NULL,
    "the same string the span attribute spnl.conn.direction carries (same value map, "
    "same function). Bound 3 = the map's two names plus its literal fallback \"other\", computed "
    "from `conn_direction` rather than declared here" },
};

static const CcRecMetric cc_rec_conn_metrics[] = {
  { "count", "spnl.conn.count", "counter", "{connection}", NULL, NULL, NULL,
    cc_metric_conn_count_labels,
    (int)(sizeof cc_metric_conn_count_labels / sizeof cc_metric_conn_count_labels[0]),
    "how many connect records the probe emitted, split by who opened the connection. A "
    "counter rather than a histogram because this channel has no duration -- a connect is a point "
    "event and its span duration is 0. semconv has no key for \"connections a probe "
    "observed\", so the name is a project key, for the same reason spnl.conn.direction is" },
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
    "spinel", "always",
    "semconv has no connection-direction key. The mapping is the declared value map "
    "`conn_direction`, shared with the typed consumer's ev.direction" },
  { "spnl.conn.tcp_state", "oldstate -> value map `tcp_state` (the kernel's enum, by name)",
    "spinel", "always",
    "semconv has no TCP-state key. spnl.conn.direction answers who opened the connection and "
    "says \"other\" for every state that is neither SYN_SENT nor SYN_RECV -- which is most of them on "
    "a probe that emits transitions other than ESTABLISHED. This is the same byte read as the state "
    "it is, and it is the same function's output as the typed consumer's ev.tcp_state" },
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
  .metrics       = cc_rec_conn_metrics,
  .nmetrics      = (int)(sizeof cc_rec_conn_metrics / sizeof cc_rec_conn_metrics[0]),
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
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid (the process that sent the request)", "int", NULL },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str", NULL },
  { "daddr",       "__u32",                 0,  4, 4, "remote IPv4 address, network byte order", NULL, NULL },
  { "dport",       "__u16",                 0,  2, 2, "remote port, host byte order", "int", NULL },
  { "family",      "__u16",                 0,  2, 2, "address family (2 = AF_INET; IPv6 addresses are not carried on this channel)", NULL, NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "ktime of the first send on this socket (span start)", NULL, NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "send -> response-visible round trip (tcp_cleanup_rbuf), = span duration", "int", NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int", NULL },
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
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid", "int", NULL },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str", NULL },
  { "daddr",       "__u32",                 0,  4, 4, "remote IPv4 address, network byte order; 0 on the TLS path (no sock)", NULL, NULL },
  { "dport",       "__u16",                 0,  2, 2, "remote port, host byte order; 0 on the TLS path", "int", NULL },
  { "family",      "__u16",                 0,  2, 2, "address family (2 = AF_INET)", NULL, NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "ktime of the request send (span start)", NULL, NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "request -> response round trip, = span duration", "int", NULL },
  { "req",         "unsigned char",        64,  1, 1, "first 64B of the request; \"METHOD path HTTP/x\" parsed in userspace", NULL, NULL },
  { "resp",        "unsigned char",        16,  1, 1, "first 16B of the response; \"HTTP/1.1 NNN\" status parsed in userspace", NULL, NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int", NULL },
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

/* --- http's metric: route (1), a bound the declaration ENFORCES ---------------
 *
 * Both labels here are properties whose value set is, in the data, not closed at
 * all: `method` is the first token of a 64-byte bounded copy of the wire (the
 * kernel-side filter only inspects 4 bytes, so a head with no space at all
 * reaches userspace and the token is then the whole field), and `status` is up
 * to three digits, i.e. 0..999. Neither could be a label on the strength of what
 * the data happens to contain.
 *
 * They are labels because the SET IS WRITTEN HERE and the emitter enforces it:
 * anything outside it is emitted as `_OTHER`, so however hostile the traffic,
 * this metric has at most 10 x 18 = 180 series. The bound is a fact about the
 * metric rather than a hope about the wire -- which is the whole difference
 * between this and "we looked and it seemed fine".
 *
 * `_OTHER` is not invented here: it is the value OpenTelemetry's own registry
 * gives http.request.method for any method outside its known set, which is the
 * same problem with the same answer. Reusing the spelling for `status` keeps one
 * word for one meaning ("outside the declared set"), following the rule that a
 * standard spelling is for when you mean the standard thing.
 *
 * WHY THE NAME IS PROJECT-SCOPED. The buckets, the unit and both attribute keys
 * are the standard ones (the OBI-aligned boundaries; semconv's
 * http.request.method / http.response.status_code), so these histograms are
 * directly comparable with an OBI or SDK-produced one. The NAME is not
 * http.client.request.duration, because a consumer reading that name is entitled
 * to assume the attribute values are the real ones -- and here two of them are
 * declared coarsenings and the peer dimensions are absent by refusal. Taking the
 * standard name for a deliberately reduced metric is the misleading half of the
 * rule that says to take it when you mean it. */
static const char *const cc_metric_http_method_values[] = {
  /* OpenTelemetry's known-method set (semconv http.request.method registry). */
  "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
};

static const char *const cc_metric_http_status_values[] = {
  "200", "201", "202", "204", "301", "302", "304",
  "400", "401", "403", "404", "409", "429",
  "500", "502", "503", "504",
};

static const CcMetricLabel cc_metric_http_duration_labels[] = {
  { "http.request.method", "method", "semconv",
    cc_metric_http_method_values,
    (int)(sizeof cc_metric_http_method_values / sizeof cc_metric_http_method_values[0]),
    "_OTHER",
    "the same token spnl_http_method() gives the span attribute http.request.method, but "
    "projected onto OTel's known-method set. A request whose method is not in that set still gets "
    "a span carrying the exact token; only the metric label collapses. Bound 10 = 9 methods + _OTHER" },
  { "http.response.status_code", "status", "semconv",
    cc_metric_http_status_values,
    (int)(sizeof cc_metric_http_status_values / sizeof cc_metric_http_status_values[0]),
    "_OTHER",
    "spnl_http_status() parses at most three digits, so the property alone admits 0..999 -- "
    "180 000 series once multiplied by the method label. This declared set is what makes it a "
    "label: 17 codes worth a dashboard, everything else _OTHER. The RED error axis survives the "
    "collapse (500/502/503/504 are named), and the span still carries the exact code. Bound 18" },
};

static const CcRecMetric cc_rec_http_metrics[] = {
  { "duration", "spnl.http.client.request.duration", "histogram", "s",
    "duration_ns", "ns", "otel_duration_s",
    cc_metric_http_duration_labels,
    (int)(sizeof cc_metric_http_duration_labels / sizeof cc_metric_http_duration_labels[0]),
    "RED for the HTTP channel. The value is the SAME property the span's duration is built "
    "from (duration_ns), so a rate/latency dashboard and a trace waterfall cannot disagree about "
    "how long a request took; the data point's `count` is the rate axis, so no separate counter is "
    "declared. Buckets are the OBI-aligned `otel_duration_s` set and the record's "
    "nanoseconds are converted once, by the generator, against a checked unit pair" },
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
  .metrics       = cc_rec_http_metrics,
  .nmetrics      = (int)(sizeof cc_rec_http_metrics / sizeof cc_rec_http_metrics[0]),
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
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid", NULL, NULL },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", NULL, NULL },
  { "daddr",       "__u32",                 0,  4, 4, "remote IPv4 address, network byte order", NULL, NULL },
  { "dport",       "__u16",                 0,  2, 2, "remote port, host byte order", NULL, NULL },
  { "family",      "__u16",                 0,  2, 2, "address family (2 = AF_INET)", NULL, NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "ktime of the command send (span start)", NULL, NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "command -> reply round trip, = span duration", NULL, NULL },
  { "req",         "unsigned char",        64,  1, 1, "first 64B of the RESP request; command + first key parsed in userspace (values never read)", NULL, NULL },
  { "resp",        "unsigned char",        16,  1, 1, "first 16B of the reply; a leading '-' marks a RESP error", NULL, NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", NULL, NULL },
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
  { "hdr",         "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "pid",         "__u32",                 0,  4, 4, "producer tgid (the request handler)", "int", NULL },
  { "comm",        "char",                 16,  1, 1, "bpf_get_current_comm -> process.executable.name", "str", NULL },
  { "duration_ns", "__u64",                 0,  8, 8, "whole request window (recv -> send), = parent span duration", "int", NULL },
  { "offcpu_ns",   "__u64",                 0,  8, 8, "voluntary off-CPU time accumulated inside the window. Not exposed raw: what the span carries is min(offcpu_ns, duration_ns) -- the accumulation and the window are measured by different hooks, so a record where the sum overshoots the window is expressible. The clamped value is the derived property ev.offcpu_ns, the same function's output as spnl.offcpu_ns", NULL, NULL },
  { "wait_stack",  "__s32",                 0,  4, 4, "bpf_get_stackid of the last wait; -1 = none. Classified against kallsyms in userspace. Not exposed: a stack id is an index into a per-unit BPF map, meaningless as a number in Ruby -- the reading of it is the derived property ev.wait_kind", NULL, NULL },
  { "req",         "unsigned char",        64,  1, 1, "first 64B of the request; \"METHOD path HTTP/x\" parsed in userspace", NULL, NULL },
  { "resp",        "unsigned char",        16,  1, 1, "first 16B of the response; \"HTTP/1.1 NNN\" status parsed in userspace", NULL, NULL },
  { "cgid",        "__u64",                 0,  8, 8, "cgroup id -> k8s.* pod attribution", "int", NULL },
  { "start_ktime", "__u64",                 0,  8, 8, "real window start (span anchor + child correlation); 0 on a pre- producer. Not exposed: a raw ktime is an anchor for span assembly (layer 2), not something a consumer can judge on", NULL, NULL },
  { "hdr_ext",     "unsigned char",       128,  1, 1, "first 128B of the request head, scanned for a W3C traceparent in userspace; zero on a pre- producer. Not exposed: raw header bytes, like dns `raw` -- what a consumer wants from them (the trace context) is layer 2's, and the request line is already ev.method / ev.path", NULL, NULL },
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
  { "wait_stack_trace", "str", "wait_stack -> the same frames wait_kind classifies, symbolised",
    "spnl_offcpu_wait_stack", "record_to_str", 448,
    "WHERE the wait happened -- the frames themselves, \";\"-joined, INNERMOST FIRST, as "
    "kallsyms names without offsets. Named for the field it reads (`wait_stack` is a stack id and "
    "stays unexposed; this is the reading of it) but deliberately not the same word, because an "
    "index and a call stack are not the same value. "
    "Same-source guarantee: wait_kind and this property are two readings of ONE frame fetch "
    "-- spnl_offcpu_wait_stack() and spnl_offcpu_wait_kind() both call the same _oc_frames(), so a "
    "kind of \"io\" is always explained by a frame that is actually in this string. Innermost-first "
    "is that guarantee made visible: the classifier scans frames in this order and stops at the "
    "first match, so the reason is the leftmost matching frame. (The folded stack output this "
    "project also emits is the other way round -- outermost first -- because a flame graph is "
    "drawn from the root. This is not paste-compatible with it.) "
    "Empty unless the operator sets SPNL_STACK_FRAMES > 0 (default 0): a stack is the one property "
    "here that costs real bytes on every span, so it is off until somebody asks. The SAME number "
    "bounds both this string and the span attribute, so the two never differ in depth. "
    "cap 448 = the declared maximum depth, exactly: 8 frames x 55 characters (the symbol width the "
    "userspace kallsyms table stores, _oc_sym.n[56]) + 7 separators + NUL. A declared derivation "
    "never truncates, so the depth cap and the byte cap are one statement" },
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
  { "spnl.wait.stack", "wait_stack -> the same frames spnl.wait.kind classifies, symbolised "
    "(\";\"-joined, innermost first, at most SPNL_STACK_FRAMES of them)",
    "spinel", "SPNL_STACK_FRAMES > 0 and the frames could be read (default 0 = attribute absent)",
    "WHERE the request waited, beside WHAT it waited on. Same function's output as the typed "
    "consumer's ev.wait_stack_trace, and the same frame fetch spnl.wait.kind classifies -- so the "
    "kind is always explained by a frame in this value. "
    "Why not semconv `code.stacktrace`: that key is the stack of the INSTRUMENTED code, and the "
    "instrumented code here is the Ruby probe -- these frames belong to the OBSERVED task, in the "
    "kernel. Naming them spnl.wait.* keeps them beside spnl.wait.kind (their sibling reading) and "
    "leaves code.stacktrace free for the case it actually describes, a user-space stack, which no "
    "record carries today. "
    "Opt-in because it is the one attribute here whose size is unbounded by the record: up to 448 "
    "bytes per span, on both the request-window span and its off-CPU wait child, inside batches of "
    "up to SPNL_OTLP_BATCH_MAX spans" },
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
  { "hdr",  "struct spnl_event_hdr", 0, 16, 8, "the 16-byte common event header (type/version/reserved/timestamp)", NULL, NULL },
  { "sock", "__u64",                 0,  8, 8, "sock pointer -- the reassembly key (one stream per connection)", NULL, NULL },
  { "len",  "__u32",                 0,  4, 4, "valid bytes in raw (raw is length-bounded, NOT NUL-terminated)", NULL, NULL },
  { "raw",  "char",                128,  1, 1, "up to 128B of stream payload; the consumer reads exactly len bytes", NULL, NULL },
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
