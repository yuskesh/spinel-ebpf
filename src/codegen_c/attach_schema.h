/* attach_schema.h -- the attach vocabulary, declared once.
 *
 * Before this header the vocabulary lived twice: as a 31-branch else-if chain in
 * cc_detect_attach() (spinel_ebpf_cc.c) and as the hand-written ATTACH_KINDS
 * array in src/spinel_ebpf/capabilities.rb. Measuring the two spellings against
 * each other showed what that costs: the axes with a lockstep gate (the d_path
 * hook table) had zero drift, and the axes without one had two, both in the
 * "claim narrower than the implementation" direction, which hides legal moves
 * from an author. This header is the single declaration; cc_detect_attach()
 * walks it, and tools/gen_attach_schema.c renders it as
 * src/spinel_ebpf/attach_schema_gen.json for the Ruby side (regenerate with
 * `make -C src/codegen_c attach-schema`, commit the JSON; tools/attach_gate.rb
 * refuses a stale artifact).
 *
 * RULES
 *  - Table order IS match order. cc_detect_attach() takes the FIRST prefix row
 *    that matches, so a row whose prefix extends an earlier row's prefix is
 *    unreachable -- the false-negative class where "present" is answered from
 *    the shorter prefix. tools/attach_gate.rb refuses such a shadowed row; the
 *    load-bearing orderings today are xdp__tcp_slice__ before xdp__
 *    (overlapping) and kprobe_multi__ before kprobe__ (non-overlapping, kept
 *    adjacent for reading).
 *  - `sec_pattern` is the display spelling (identical bytes to the Ruby side's
 *    `sec:`); the machine behaviour is DERIVED from it -- no '<' means the SEC
 *    is the pattern verbatim, a single "<...>" placeholder means everything
 *    before '<' is prefixed to the method-name rest, and the tracepoint's two
 *    placeholders name the <cat>__<event> split that cc_detect_attach() keeps
 *    as code. `sec_mode` states the derivation so a reader does not re-derive
 *    it; attach_gate recomputes it from the pattern and refuses a mismatch.
 *  - CC_AD_CLASS rows (struct_ops) are NOT consulted by cc_detect_attach() --
 *    class-based lowering has its own post-pass. They are declared here so the
 *    vocabulary has one inventory: the Ruby ATTACH_KINDS and the completeness
 *    gates count 34 kinds, not 31.
 *  - The affordance prose (args_convention / context_note) deliberately stays
 *    in capabilities.rb: it is documentation for authors, not a machine axis,
 *    and none of the measured drifts were in prose. The machine half (kind set,
 *    sec, ctx_type, kname, facets) is what this header owns -- the same split
 *    loader_contract.h states for map names ("truly single-source on one half,
 *    mirror + gate on the other").
 */
#ifndef SPNL_ATTACH_SCHEMA_H
#define SPNL_ATTACH_SCHEMA_H

/* attach kinds -- moved verbatim from spinel_ebpf_cc.c. Declared here so both
 * the codegen and the schema generator see one definition. */
typedef enum { AK_NONE, AK_KPROBE, AK_KRETPROBE, AK_TRACEPOINT, AK_FENTRY, AK_FEXIT, AK_XDP, AK_TC,
               AK_SK_VERDICT, AK_UPROBE, AK_URETPROBE, AK_USDT, AK_LSM, AK_FMOD_RET,
               AK_ITER_TASK, AK_RAW_TP, AK_PERF_EVENT, AK_SOCK_OPS,
               AK_KPROBE_MULTI, AK_TIMER,
               AK_USER_RINGBUF } AttachKind;

typedef enum {
  CC_AD_PREFIX = 0,   /* recognized by cc_detect_attach() from the method-name prefix */
  CC_AD_CLASS,        /* struct_ops: recognized by the class post-pass, not by prefix */
} CcAttachDetect;

typedef enum {
  CC_SEC_FIXED = 0,   /* sec_pattern has no placeholder: SEC(sec_pattern) verbatim */
  CC_SEC_TEMPLATE,    /* one "<...>": SEC = pattern-up-to-'<' + method-name rest */
  CC_SEC_SPLIT2,      /* tracepoint: rest is <cat>__<event>, split kept as code */
  CC_SEC_NONE,        /* user_ringbuf: no SEC at all (a callback, not a program) */
} CcSecMode;

typedef struct {
  const char *ruby_kind;   /* ATTACH_KINDS' :kind -- the JSON merge key */
  CcAttachDetect detect;
  const char *prefix;      /* CC_AD_PREFIX: literal method-name prefix; NULL for class rows */
  AttachKind kind;         /* AK_NONE on class rows (the post-pass never asks) */
  CcSecMode sec_mode;
  const char *sec_pattern; /* display spelling, byte-identical to Ruby `sec:`; NULL = no SEC */
  const char *ctx_type;    /* NULL where there is no ctx (user_ringbuf, class rows) */
  const char *kname;       /* attach-KIND name the gates compare (not a kernel symbol) */
  int ctx_prefixed;        /* inner takes the kernel ctx as its first arg (pkt_*) */
  int verdict;             /* wrapper propagates the inner's int return */
  int iter_guard;          /* emit `if (!ctx->task) return 0;` (the bpf_iter terminator) */
  int usdt;                /* bpf_usdt_arg prologue + usdt.bpf.h */
  int xdp_tail;            /* tail-call target (loader-only difference) */
  int tcp_slice;           /* body-discarded slice marker */
  int rest_needs_sep;      /* the rest must contain "__" or this row does NOT match
                            * (usdt__<provider>__<probe>; a bare usdt__foo falls
                            * through to later rows exactly as the old chain did) */
  const char *rest_excludes; /* the rest must NOT start with this; matching it stops
                              * detection with AK_NONE. Second line of defence for
                              * xdp__ vs xdp__tcp_slice__ -- order handles it, this
                              * survives a reorder (the false-negative class). */
  const char *note;        /* rationale worth keeping next to the row */
} CcAttachDecl;

static const CcAttachDecl cc_attach_decls[] = {
  /* `on :kprobe, %w[...]` -- ONE body, N symbols. The SEC named here is the
   * multi lowering's; when the codegen picks expansion the wrapper loop emits
   * SEC("kprobe/<sym>") per symbol instead and never consults this field. Before
   * "kprobe__" only for reading order -- the prefixes do not overlap. */
  { .ruby_kind = "kprobe_multi", .detect = CC_AD_PREFIX, .prefix = "kprobe_multi__",
    .kind = AK_KPROBE_MULTI, .sec_mode = CC_SEC_FIXED, .sec_pattern = "kprobe.multi",
    .ctx_type = "struct pt_regs *", .kname = "kprobe_multi" },
  { .ruby_kind = "kprobe", .detect = CC_AD_PREFIX, .prefix = "kprobe__",
    .kind = AK_KPROBE, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "kprobe/<func>",
    .ctx_type = "struct pt_regs *", .kname = "kprobe" },
  { .ruby_kind = "kretprobe", .detect = CC_AD_PREFIX, .prefix = "kretprobe__",
    .kind = AK_KRETPROBE, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "kretprobe/<func>",
    .ctx_type = "struct pt_regs *", .kname = "kretprobe" },
  { .ruby_kind = "fentry", .detect = CC_AD_PREFIX, .prefix = "fentry__",
    .kind = AK_FENTRY, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "fentry/<func>",
    .ctx_type = "__u64 *", .kname = "fentry" },
  { .ruby_kind = "fexit", .detect = CC_AD_PREFIX, .prefix = "fexit__",
    .kind = AK_FEXIT, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "fexit/<func>",
    .ctx_type = "__u64 *", .kname = "fexit" },
  { .ruby_kind = "tc_ingress", .detect = CC_AD_PREFIX, .prefix = "tc__ingress__",
    .kind = AK_TC, .sec_mode = CC_SEC_FIXED, .sec_pattern = "tcx/ingress",
    .ctx_type = "struct __sk_buff *", .kname = "tc_ingress", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "tc_egress", .detect = CC_AD_PREFIX, .prefix = "tc__egress__",
    .kind = AK_TC, .sec_mode = CC_SEC_FIXED, .sec_pattern = "tcx/egress",
    .ctx_type = "struct __sk_buff *", .kname = "tc_egress", .ctx_prefixed = 1, .verdict = 1 },
  /* verdict-style socket programs (SK_PASS/SK_DROP), ctx-prefixed inner. All
   * AK_SK_VERDICT rows share one AttachKind across nine SECs with different ctx
   * structs, which is why every gate on this family compares `kname`. */
  { .ruby_kind = "sk_reuseport", .detect = CC_AD_PREFIX, .prefix = "sk_reuseport__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "sk_reuseport",
    .ctx_type = "struct sk_reuseport_md *", .kname = "sk_reuseport", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "sk_msg", .detect = CC_AD_PREFIX, .prefix = "sk_msg__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "sk_msg",
    .ctx_type = "struct sk_msg_md *", .kname = "sk_msg", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "sk_skb_verdict", .detect = CC_AD_PREFIX, .prefix = "sk_skb__verdict__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "sk_skb/stream_verdict",
    .ctx_type = "struct __sk_buff *", .kname = "sk_skb_verdict", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "sk_skb_parser", .detect = CC_AD_PREFIX, .prefix = "sk_skb__parser__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "sk_skb/stream_parser",
    .ctx_type = "struct __sk_buff *", .kname = "sk_skb_parser", .ctx_prefixed = 1, .verdict = 1 },
  /* socket_filter / flow_dissector / sk_lookup -- verdict + ctx-prefixed. */
  { .ruby_kind = "socket_filter", .detect = CC_AD_PREFIX, .prefix = "socket_filter__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "socket",
    .ctx_type = "struct __sk_buff *", .kname = "socket_filter", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "flow_dissector", .detect = CC_AD_PREFIX, .prefix = "flow_dissector__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "flow_dissector",
    .ctx_type = "struct __sk_buff *", .kname = "flow_dissector", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "sk_lookup", .detect = CC_AD_PREFIX, .prefix = "sk_lookup__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "sk_lookup",
    .ctx_type = "struct bpf_sk_lookup *", .kname = "sk_lookup", .ctx_prefixed = 1, .verdict = 1 },
  /* cgroup/connect4 / bind4 (sock_addr) -- verdict (1=allow/0=deny). */
  { .ruby_kind = "cgroup_connect4", .detect = CC_AD_PREFIX, .prefix = "cgroup__connect4__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "cgroup/connect4",
    .ctx_type = "struct bpf_sock_addr *", .kname = "cgroup_connect4", .ctx_prefixed = 1, .verdict = 1 },
  { .ruby_kind = "cgroup_bind4", .detect = CC_AD_PREFIX, .prefix = "cgroup__bind4__",
    .kind = AK_SK_VERDICT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "cgroup/bind4",
    .ctx_type = "struct bpf_sock_addr *", .kname = "cgroup_bind4", .ctx_prefixed = 1, .verdict = 1 },
  /* uprobe / uretprobe -- pt_regs args (like kprobe), SEC is the bare kind. */
  { .ruby_kind = "uprobe", .detect = CC_AD_PREFIX, .prefix = "uprobe__",
    .kind = AK_UPROBE, .sec_mode = CC_SEC_FIXED, .sec_pattern = "uprobe",
    .ctx_type = "struct pt_regs *", .kname = "uprobe" },
  { .ruby_kind = "uretprobe", .detect = CC_AD_PREFIX, .prefix = "uretprobe__",
    .kind = AK_URETPROBE, .sec_mode = CC_SEC_FIXED, .sec_pattern = "uretprobe",
    .ctx_type = "struct pt_regs *", .kname = "uretprobe" },
  /* USDT -- usdt__<provider>__<probe>; without the second "__" the name is NOT a
   * USDT method and falls through, exactly as the old chain's compound condition
   * did. */
  { .ruby_kind = "usdt", .detect = CC_AD_PREFIX, .prefix = "usdt__",
    .kind = AK_USDT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "usdt",
    .ctx_type = "struct pt_regs *", .kname = "usdt", .usdt = 1, .rest_needs_sep = 1 },
  /* LSM / fmod_ret -- ctx[i] args (like fexit) + verdict propagate. */
  { .ruby_kind = "lsm", .detect = CC_AD_PREFIX, .prefix = "lsm__",
    .kind = AK_LSM, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "lsm/<hook>",
    .ctx_type = "__u64 *", .kname = "lsm", .verdict = 1 },
  { .ruby_kind = "fmod_ret", .detect = CC_AD_PREFIX, .prefix = "fmod_ret__",
    .kind = AK_FMOD_RET, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "fmod_ret/<func>",
    .ctx_type = "__u64 *", .kname = "fmod_ret", .verdict = 1 },
  /* bpf_iter over tasks -- ctx-prefixed, NULL-terminator guard. */
  { .ruby_kind = "iter_task", .detect = CC_AD_PREFIX, .prefix = "iter__task__",
    .kind = AK_ITER_TASK, .sec_mode = CC_SEC_FIXED, .sec_pattern = "iter/task",
    .ctx_type = "struct bpf_iter__task *", .kname = "iter_task", .ctx_prefixed = 1, .iter_guard = 1 },
  /* SOCK_OPS -- cgroup-scoped TCP state observation. ctx-prefixed, NOT
   * verdict-propagating: a sockops return is not a policy decision, so the
   * wrapper returns 0 (the Ruby oracle's propagating_retval list agreed). The
   * glue (_spnl_sockops_attach_all) survived the port to the C codegen; only the
   * detection line was missing, so the whole kind degraded to a plain
   * SEC("syscall") wrapper that nothing ever attached. */
  { .ruby_kind = "sock_ops", .detect = CC_AD_PREFIX, .prefix = "sock_ops__",
    .kind = AK_SOCK_OPS, .sec_mode = CC_SEC_FIXED, .sec_pattern = "sockops",
    .ctx_type = "struct bpf_sock_ops *", .kname = "sock_ops", .ctx_prefixed = 1 },
  /* raw tracepoint -- ctx->args[i] extraction, auto-attach. */
  { .ruby_kind = "raw_tp", .detect = CC_AD_PREFIX, .prefix = "raw_tp__",
    .kind = AK_RAW_TP, .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "raw_tp/<event>",
    .ctx_type = "struct bpf_raw_tracepoint_args *", .kname = "raw_tp" },
  /* perf_event sampling -- ctx-prefixed (sample data + regs), non-verdict. */
  { .ruby_kind = "perf_event", .detect = CC_AD_PREFIX, .prefix = "perf_event__",
    .kind = AK_PERF_EVENT, .sec_mode = CC_SEC_FIXED, .sec_pattern = "perf_event",
    .ctx_type = "struct bpf_perf_event_data *", .kname = "perf_event", .ctx_prefixed = 1 },
  /* the reactor's `on :timer` handler (a synthesized method name). Named here
   * even though the emit loop short-circuits it, because every context gate asks
   * cc_detect_attach who it is lowering into: left AK_NONE, has_cap would read
   * whatever task the softirq landed on and `filter_by` would skip it -- the
   * "looks narrowed and is not" artefact the common filter refuses. `sec` is
   * what the arm program actually carries; the callback has no SEC at all. */
  { .ruby_kind = "timer", .detect = CC_AD_PREFIX, .prefix = "spnl_timer__",
    .kind = AK_TIMER, .sec_mode = CC_SEC_FIXED, .sec_pattern = "syscall",
    .ctx_type = "__u64 *", .kname = "timer" },
  /* the USER_RINGBUF callback -- the ONE attach kind that emits no program at
   * all (no SEC, no ctx, no userspace-visible name); the per-method loop
   * short-circuits on this kind before anything reads sec. Still an AttachKind
   * rather than AK_NONE for the same reason the timer is; unlike the timer it
   * DOES run in the draining program's context, so it is deliberately NOT on the
   * "not process context" lists (see cc_ak_process_ctx). */
  { .ruby_kind = "user_ringbuf", .detect = CC_AD_PREFIX, .prefix = "user_ringbuf__",
    .kind = AK_USER_RINGBUF, .sec_mode = CC_SEC_NONE, .sec_pattern = 0,
    .ctx_type = 0, .kname = "user_ringbuf" },
  /* a tail-call target. Deliberately AK_XDP (see the xdp_tail note on struct
   * Attach): the emitted program is an ordinary SEC("xdp") one, and only the
   * loader treats it differently -- _spnl_prog_array_populate writes it into
   * `spnl_prog_array` and _spnl_xdp_attach_all skips it, both keyed on this
   * literal prefix. `kname` names the surface the author wrote. The prefix does
   * not overlap "xdp__" ("xdp_t" vs "xdp__"), so its position is for reading,
   * not correctness. */
  { .ruby_kind = "xdp_tail", .detect = CC_AD_PREFIX, .prefix = "xdp_tail__",
    .kind = AK_XDP, .sec_mode = CC_SEC_FIXED, .sec_pattern = "xdp",
    .ctx_type = "struct xdp_md *", .kname = "xdp_tail", .ctx_prefixed = 1, .verdict = 1, .xdp_tail = 1 },
  /* the pure-XDP TCP slice. AK_XDP for the same reason xdp_tail is; what differs
   * is that the METHOD BODY is discarded (the marker is replaced by the
   * generated state machine), so the per-method loop short-circuits on
   * `tcp_slice`. This row MUST come before the plain "xdp__" row -- the prefix
   * overlaps ("xdp__tcp_slice__health" starts with "xdp__"), which is exactly
   * the false negative that lets an unported attach kind look present; the plain
   * row below also keeps rest_excludes as a second line of defence rather than
   * relying on order alone. */
  { .ruby_kind = "xdp_tcp_slice", .detect = CC_AD_PREFIX, .prefix = "xdp__tcp_slice__",
    .kind = AK_XDP, .sec_mode = CC_SEC_FIXED, .sec_pattern = "xdp",
    .ctx_type = "struct xdp_md *", .kname = "xdp_tcp_slice", .ctx_prefixed = 1, .verdict = 1, .tcp_slice = 1 },
  { .ruby_kind = "xdp", .detect = CC_AD_PREFIX, .prefix = "xdp__",
    .kind = AK_XDP, .sec_mode = CC_SEC_FIXED, .sec_pattern = "xdp",
    .ctx_type = "struct xdp_md *", .kname = "xdp", .ctx_prefixed = 1, .verdict = 1,
    .rest_excludes = "tcp_slice__" },
  /* tracepoint__<cat>__<event>. The <cat>/<event> split and the syscalls
   * sys_enter_/sys_exit_ -> trace_event_raw_* struct rule stay as code in
   * cc_detect_attach() -- the one genuinely irregular branch. A name without the
   * second "__" stops detection with AK_NONE, as the old chain did. */
  { .ruby_kind = "tracepoint", .detect = CC_AD_PREFIX, .prefix = "tracepoint__",
    .kind = AK_TRACEPOINT, .sec_mode = CC_SEC_SPLIT2, .sec_pattern = "tracepoint/<cat>/<event>",
    .ctx_type = "void *", .kname = "tracepoint" },
  /* class-based struct_ops. Recognized by the class post-pass (`class N <
   * BPF::TcpCC` and the like), never by method-name prefix, so
   * cc_detect_attach() skips these rows. Declared for inventory completeness:
   * the vocabulary is 34 kinds, and the Ruby side merges its prose onto these. */
  { .ruby_kind = "tcp_cc", .detect = CC_AD_CLASS, .prefix = 0, .kind = AK_NONE,
    .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "struct_ops/<member>", .ctx_type = 0, .kname = "tcp_cc" },
  { .ruby_kind = "sched_ext", .detect = CC_AD_CLASS, .prefix = 0, .kind = AK_NONE,
    .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "struct_ops/<member>", .ctx_type = 0, .kname = "sched_ext" },
  { .ruby_kind = "qdisc", .detect = CC_AD_CLASS, .prefix = 0, .kind = AK_NONE,
    .sec_mode = CC_SEC_TEMPLATE, .sec_pattern = "struct_ops/<member>", .ctx_type = 0, .kname = "qdisc" },
};
#define CC_N_ATTACH_DECLS ((int)(sizeof(cc_attach_decls) / sizeof(cc_attach_decls[0])))

#endif /* SPNL_ATTACH_SCHEMA_H */
