# frozen_string_literal: true
#
# spinel-ebpf — eBPF C (.bpf.c) codegen for ebpf-tagged methods.
#
# Scope (MVP):
#   - Input: IR + AST + Partition::Result (from partition.classify)
#   - Output: a single .bpf.c text containing:
#       * license declaration
#       * one BPF_MAP_TYPE_HASH per class ivar (key=__u32 singleton, value=mapped type)
#       * one SEC("syscall") int <unit>_<method>(void *ctx) per ebpf-tagged method
#   - Lowered AST forms:
#       * IntegerNode               -> int literal
#       * InstanceVariableReadNode  -> map lookup, default 0
#       * InstanceVariableWriteNode -> map update from RHS
#       * InstanceVariableOperatorWriteNode (binary_operator "+", "-", "*") -> lookup+op+update
#       * StatementsNode            -> sequence; last expression is return value (for int methods)
#       * Method with return "void" -> always returns 0 (SEC("syscall") ABI is int)
#
# Naming convention:
#   class Counter ivar @count  -> map  counter_at_count
#   class Counter method incr   -> func counter_incr
#
# Anything else (calls, conditionals, loops, etc.) raises UnsupportedNode so
# the CLI can surface a precise error instead of emitting silently-wrong C.

require_relative "parse_spinel_ir"
require_relative "parse_spinel_ast"
require_relative "partition"
require_relative "kernel_cache"
require_relative "btf_schema"
require_relative "c_ast"
require "set"

module SpinelEbpf
  module CodegenBpf
    class UnsupportedNode < StandardError; end

    # Map a spinel inferred-type string to a C type. Conservative: only the
    # subset we know how to lower in the MVP.
    SPINEL_TYPE_TO_C = {
      "int"  => "__s64",
      "bool" => "__s32",
      "void" => "void",
    }.freeze

    # C type for a *local variable* declaration, keyed by spinel's
    # inferred type (sourced from the IR scope records — see IR#scope_locals).
    # Deliberately conservative: every scalar maps to __s64 so the generated
    # .bpf.c stays byte-identical with the earlier blanket-__s64 behaviour
    # (spinel's `int` is signed 64-bit and has no unsigned variant, and locals
    # were always declared __s64). The point of Step 1 is to thread the type
    # through the plumbing without changing output; Step 2 extends this table
    # with `ptr` / `obj_<Class>` -> typed pointers (the actual unlock). Anything
    # not listed falls back to __s64 via #local_c_type.
    LOCAL_TYPE_TO_C = {
      "int"  => "__s64",
      "bool" => "__s64",
      "nil"  => "__s64",
      "void" => "__s64",
    }.freeze

    DEFAULT_VALUE_FOR_TYPE = {
      "int"  => "0",
      "bool" => "0",
    }.freeze

    # nil-returning methods (from spinel @meth_return_types "nil") are treated
    # as void for codegen purposes (SEC("syscall") ABI is always int, we
    # synthesize "return 0;").
    NIL_TYPE_MAP = { "nil" => "void" }.freeze

    # Names that the codegen treats as built-in eBPF intrinsics rather than
    # ordinary method calls. spnl_emit(x) -> ringbuf reserve/submit/return 0.
    # pkt_* builtins access XDP packet headers and require an
    # implicit `ctx` (struct xdp_md *) in scope — emit_method passes ctx
    # into the inner function for :xdp attaches.
    # IPv6 address builtins added (hi/lo split since __s64 can't hold a
    # full 128bit value). pkt_l4_proto / pkt_l4_sport / pkt_l4_dport /
    # pkt_tcp_flags / pkt_l4_payload_len are extended below to also walk
    # ETH_P_IPV6 (0x86DD) packets. Extension headers (Hop-by-Hop, Routing,
    # Fragment, ...) are out of scope — if ip6h->nexthdr is not TCP/UDP
    # directly, builtins return 0 (caller-visible signal: "not L4 we know").
    PKT_BUILTINS = %w[
      pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst
      pkt_l4_sport pkt_l4_dport
      pkt_tcp_flags pkt_l4_payload_len
      pkt_ip6_src_hi pkt_ip6_src_lo pkt_ip6_dst_hi pkt_ip6_dst_lo
      pkt_tcp_seq pkt_tcp_ack
    ].freeze

    # chain accessor map. `pkt.l4.proto` reads through a 3-element
    # CallNode chain that bottoms out in `pkt` (no receiver, no args).
    # Mapping the chain back to the flat builtin lets us share the existing
    # pkt_builtin_call implementation — only the surface syntax changes.
    # `pkt.byte_at(off)` is handled separately since it takes an argument.
    # `pkt.ip6.src_hi` etc. for IPv6.
    PKT_CHAIN_MAP = {
      %w[pkt len]               => "pkt_len",
      %w[pkt eth proto]         => "pkt_eth_proto",
      %w[pkt l4 proto]          => "pkt_l4_proto",
      %w[pkt l4 sport]          => "pkt_l4_sport",
      %w[pkt l4 dport]          => "pkt_l4_dport",
      %w[pkt l4 payload_len]    => "pkt_l4_payload_len",
      %w[pkt ip4 src]           => "pkt_ip4_src",
      %w[pkt ip4 dst]           => "pkt_ip4_dst",
      %w[pkt ip6 src_hi]        => "pkt_ip6_src_hi",
      %w[pkt ip6 src_lo]        => "pkt_ip6_src_lo",
      %w[pkt ip6 dst_hi]        => "pkt_ip6_dst_hi",
      %w[pkt ip6 dst_lo]        => "pkt_ip6_dst_lo",
      %w[pkt tcp flags]         => "pkt_tcp_flags",
      %w[pkt tcp seq]           => "pkt_tcp_seq",
      %w[pkt tcp ack]           => "pkt_tcp_ack",
    }.freeze
    # blocklist_match(ip_host_order) — checks a HASH map populated from
    # userspace via sp_bpf_blocklist_add() / _del(). Returns 1 if the IP is in
    # the blocklist, 0 otherwise. Use inside :ebpf methods (typically TC/XDP).
    # path_counter_inc(key) — increments bpf_path_counts[key] atomically.
    # Designed for L7 metrics (key = path enum/hash, value = hit count).
    # reuseport_hash / worker_select(idx) — for SO_REUSEPORT BPF programs.
    # reuseport_hash returns ctx->hash (kernel-computed 5-tuple hash) as int;
    # worker_select(idx) calls bpf_sk_select_reuseport to pick the socket at
    # bpf_worker_sockets[idx]. Use only inside sk_reuseport__<name> methods.
    # xdp_match_health / xdp_reply_health — kernel-side static
    # response fast path. xdp_match_health returns 1 when the XDP frame is an
    # IPv4/TCP packet whose payload starts with "GET /health "; xdp_reply_health
    # rewrites the same packet in place to be a 200 OK response and returns
    # XDP_TX (3) on success or XDP_PASS (2) on any failure.
    # tcp_sock_* / inet_sock_* field accessors. Each maps to a
    # `BPF_CORE_READ(tcp_sk(sk_as_ptr), <field>)` and is only valid inside
    # tcp_cc__<member> methods (where the kernel hands us a real `struct
    # sock *`). The Ruby side passes `sk` as a normal __s64 — we cast back
    # to the typed pointer at the call site. Add-style helpers
    # (`tcp_sock_snd_cwnd_add`) write to the same fields.
    TCP_SOCK_READERS = {
      "tcp_sock_snd_cwnd"        => "snd_cwnd",
      "tcp_sock_snd_ssthresh"    => "snd_ssthresh",
      "tcp_sock_snd_nxt"         => "snd_nxt",
      "tcp_sock_snd_una"         => "snd_una",
      "tcp_sock_packets_out"     => "packets_out",
      "tcp_sock_delivered"       => "delivered",
      "tcp_sock_snd_cwnd_cnt"    => "snd_cwnd_cnt",
      "tcp_sock_snd_cwnd_clamp"  => "snd_cwnd_clamp",
      "tcp_sock_prior_cwnd"      => "prior_cwnd",
    }.freeze
    TCP_SOCK_WRITERS = {
      "tcp_sock_snd_cwnd_set"      => "snd_cwnd",
      "tcp_sock_snd_ssthresh_set"  => "snd_ssthresh",
      "tcp_sock_snd_cwnd_cnt_set"  => "snd_cwnd_cnt",
    }.freeze
    TCP_SOCK_ADDERS = {
      "tcp_sock_snd_cwnd_add"      => "snd_cwnd",
      "tcp_sock_snd_cwnd_cnt_add"  => "snd_cwnd_cnt",
    }.freeze
    TCP_SOCK_BUILTINS = (TCP_SOCK_READERS.keys + TCP_SOCK_WRITERS.keys + TCP_SOCK_ADDERS.keys).freeze

    # bare field names (without the "tcp_sock_" prefix). Used by the
    # dot-form sugar — `sk.snd_cwnd` looks up `snd_cwnd` directly.
    TCP_SOCK_FIELDS = (
      TCP_SOCK_READERS.values + TCP_SOCK_WRITERS.values + TCP_SOCK_ADDERS.values
    ).uniq.to_set.freeze

    BUILTIN_NAMES = (
      %w[spnl_emit spnl_emit_str spnl_emit_pair spnl_emit3 spnl_emit4 emit_argv
         blocklist_match cidr_blocklist_match path_counter_inc
         reuseport_hash worker_select
         xdp_match_health xdp_reply_health
         pkt_dynptr_byte_at user_ringbuf_drain
         tail_call_to sock_ops_op sock_ops_state
         sock_addr_ip4 sock_addr_port
         iter_task
         cpumap_redirect xsk_redirect dev_redirect
         hist_observe hist_observe_by hist_observe_linear
         ktime_ns pid tgid tid latency_start latency_end
         task_load task_store task_incr
         mim_inc mim_get
         fifo_push fifo_pop lifo_push lifo_pop
         divu comm_hash emit_comm
         stack_id user_stack_id
         off_cpu_start off_cpu_observe
         scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq
         qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
         qdisc_watchdog_schedule qdisc_bstats_update
         queue_push queue_pop
         leak_record leak_forget
         task_swap lock_edge
         lat_start lat_end cpu_id
         depth_inc depth_dec
         field_exists
         flow_get flow_set flow_del
         tcp_syncookie_gen tcp_syncookie_check
         tcp_reply_header tcp_reply_synack tcp_synack_cookie tcp_reply_data payload_starts
         kfield kptr fib_lookup fib_lookup6 sk_lookup_tcp sk_assign_tcp redirect
         skb_load_byte skb_store_byte l3_csum_replace l4_csum_replace
         skb_load_u32 skb_store_u32 l3_csum_replace_ip l4_csum_replace_ip
         skb_load_u16 skb_store_u16 l4_offset
         arena_set arena_get arena_hash_set arena_hash_get arena_hash_del
         arena_list_push arena_list_sum] +
      TCP_SOCK_BUILTINS + PKT_BUILTINS
    ).freeze

    # bpf_dynptr-backed XDP byte access. Use this builtin to read a
    # single byte from the XDP frame at a runtime offset, with verifier
    # bounds-checking handled by bpf_dynptr_slice. Returns the byte value
    # (0-255) on success, or -1 if the offset is out of bounds.
    DYNPTR_BUILTINS = %w[pkt_dynptr_byte_at].freeze

    # fixed length for spnl_emit_str payload buffer. Per-event size
    # = sizeof(spnl_event_hdr) + SPNL_STR_MAX. Tuned for typical filename /
    # short label use; longer strings get truncated by bpf_probe_read_user_str.
    SPNL_STR_MAX = 256

    module_function

    # Top-level entry: returns a String containing the full .bpf.c text.
    #
    # base_name -- used for header comment (e.g. "04_class_with_ivars" -> the
    # file the Ruby source came from) AND for the per-unit ringbuf map name
    # (e.g. "12_spnl_emit_events"). It is sanitized (non-alnum -> "_").
    # plugin_sections: additive section hook. Array of
    # [predicate(ctx)->bool, emitter(ctx)->String] spliced after the core registry,
    # letting a plugin add maps/helpers without editing the emission code.
    def emit(ir, ast, partition_result, base_name: "spinel_ebpf_unit", plugin_sections: [])
      ebpf_methods = partition_result.methods.select { |m| m.tag == :ebpf }
      classes_used = collect_classes_used(ir, ebpf_methods)
      top_ivars   = collect_toplevel_ivars_used(ast, ebpf_methods)

      # name-indexed lookup for BPF-to-BPF call resolution. If two
      # :ebpf methods share a bare name (Foo#bar / Baz#bar), the later wins.
      # MVP accepts this over-approximation.
      ctx = EmitContext.new(
        ir: ir, ast: ast, partition: partition_result,
        base_name: base_name, unit_name: sanitize_identifier(base_name),
        uses_ringbuf: false,
        uses_str_ringbuf: false,
        uses_pair_ringbuf: false,
        uses_emit3_ringbuf: false,
        uses_emit4_ringbuf: false,
        ebpf_methods_by_name: ebpf_methods.to_h { |mi| [mi.method_name, mi] },
        loop_counter: 0,
        deferred_functions: [],
        pkt_builtins_used: {},
        uses_blocklist: false,
        uses_cidr_blocklist: false,
        uses_path_counter: false,
        uses_reuseport_sockarray: false,
        uses_xdp_health_match: false,
        uses_xdp_health_reply: false,
        uses_tcp_slice: false,
        uses_dynptr: false,
        uses_user_ringbuf: false,
        user_ringbuf_cb_name: nil,
        uses_tail_call: false,
        tail_targets: [],
        uses_cpumap: false,
        uses_xskmap: false,
        uses_devmap: false,
        uses_tcp_cc: false,
        tcp_cc_members: [],
        uses_sched_ext: false,
        sched_ext_members: [],
        uses_qdisc: false,
        qdisc_members: [],
        uses_timer: false,
        timer_interval_ns: nil,
        timer_handler_name: nil,
        uses_pt_regs_parm: false,
        uses_usdt: false,
        uses_histogram: false,
        uses_latency: false,
        uses_histogram_keyed: false,
        uses_histogram_linear: false,
        uses_stack_trace: false,
        uses_off_cpu: false,
        uses_qdisc_fifo: false,
        uses_kfield: false,
        uses_fib: false,
        uses_csum: false,
        uses_arena: false,
        uses_task_storage: false,
        uses_map_in_map: false,
        uses_fifo: false,
        uses_lifo: false,
        uses_leak_track: false,
        uses_lock_edge: false,
        uses_keyed_lat: false,
        uses_depth: false,
        flow_maps: collect_flow_maps(ast, ebpf_methods),
        flow_map_kinds: {},
        syncookie_used: Set.new,
        uses_tcp_reply: false,
        uses_tcp_synack: false,
        uses_synack_cookie: false,
        payload_matchers: [],
        reply_bodies: [],
        plugin_sections: plugin_sections,
      )

      # pre-scan bodies for `stack_id` / `user_stack_id` calls so the
      # ctx-forwarding decision in emit_method sees the flag before it
      # computes ctx_prefix / params_decl. This is the only flag that
      # needs pre-knowledge — other flags (uses_ringbuf etc.) only affect
      # post-body section emission, which happens after method_blocks.
      ctx.uses_stack_trace = ebpf_methods.any? { |mi| stack_trace_referenced?(ast, mi) }

      # First pass: lower each method body into a string (this may set
      # ctx.uses_ringbuf as a side effect if spnl_emit is encountered).
      method_blocks = ebpf_methods.map { |mi| emit_method(ctx, mi) }

      sections = []
      sections << header(base_name, ebpf_methods.length, classes_used.length)
      sections << license_and_includes(ctx)
      sections << emit_event_types_and_map(ctx) if ctx.uses_ringbuf
      sections << emit_str_event_types_and_map(ctx) if ctx.uses_str_ringbuf
      sections << emit_pair_event_types_and_map(ctx) if ctx.uses_pair_ringbuf
      sections << emit_n_tuple_event_types_and_map(ctx, 3) if ctx.uses_emit3_ringbuf
      sections << emit_n_tuple_event_types_and_map(ctx, 4) if ctx.uses_emit4_ringbuf
      classes_used.each { |cls| sections << emit_ivar_maps(ctx, cls) }
      sections << emit_toplevel_ivar_maps(ctx, top_ivars) unless top_ivars.empty?
      # bpf_arena — sparse mmap-able shared memory backing arena_set/get.
      sections << emit_arena_map(ctx) if ctx.uses_arena
      # pkt_* header-access helpers (only what was used).
      sections << emit_pkt_helpers(ctx) unless ctx.pkt_builtins_used.empty?
      # Roadmap #2: flow-state maps (4-tuple key + struct value) + key-extract
      # helpers. Must precede the method bodies that call flow_get/set/del.
      sections << emit_flow_maps(ctx) unless ctx.flow_maps.empty?
      # Roadmap #3: TCP SYN-cookie helpers (parse + raw syncookie kfunc).
      sections << emit_syncookie_helpers(ctx) unless ctx.syncookie_used.empty?
      # Roadmap #4/#4b/#5b: shared IP/TCP checksum helpers (when a reply is built).
      sections << emit_reply_csum_helpers if ctx.uses_tcp_reply || ctx.uses_tcp_synack || ctx.uses_synack_cookie || !ctx.reply_bodies.empty?
      # Roadmap #4: tcp_reply_header — turn the packet into a header-only TCP reply
      # (swap endpoints, set seq/ack/flags, recompute checksums) for XDP_TX.
      sections << emit_tcp_reply_helper if ctx.uses_tcp_reply
      # Roadmap #4b: tcp_reply_synack — SYN-ACK with the MSS option (syncookie).
      sections << emit_tcp_synack_helper if ctx.uses_tcp_synack
      # Roadmap #4b': integrated SYN -> SYN-ACK+cookie (bundle sequence).
      sections << emit_synack_cookie_helper if ctx.uses_synack_cookie
      # Roadmap #5b: tcp_reply_data — data response (adjust_tail + body + csum).
      sections << emit_tcp_reply_data(ctx) unless ctx.reply_bodies.empty?
      # Roadmap #5a: payload_starts(prefix) — per-prefix TCP payload matcher.
      sections << emit_payload_matchers(ctx) unless ctx.payload_matchers.empty?
      # Drive section emission from a data-driven registry.
      # Replaces the old hardcoded `sections << emit_X(ctx) if ctx.uses_X` chain with SECTION_REGISTRY +
      # ctx.plugin_sections. Plugins can splice in sections without editing the core.
      SECTION_REGISTRY.each do |gate, emitter|
        active = gate.is_a?(Proc) ? gate.call(ctx) : ctx[gate]
        sections << send(emitter, ctx) if active
      end
      (ctx.plugin_sections || []).each do |gate, emitter|
        next unless gate.call(ctx)
        sections << (emitter.is_a?(Proc) ? emitter.call(ctx) : send(emitter, ctx))
      end
      # per-method ctx struct (one per method that has params).
      ebpf_methods.each { |mi| s = emit_ctx_struct(ctx, mi); sections << s if s }
      # loop callback functions must appear before the inner functions
      # that bpf_loop()-reference them (no forward declarations otherwise).
      sections.concat(ctx.deferred_functions)
      sections.concat(method_blocks)
      # sched_ext kfunc externs + SCX_* constant defines must be
      # emitted BEFORE any struct_ops member function that calls them.
      # Insert at the very top by prepending to sections[1] (after header).
      if ctx.uses_sched_ext
        sections.insert(2, emit_sched_ext_preamble(ctx))
      end
      # real FIFO qdisc preamble — bpf_list_head + spin_lock +
      # skb_node wrapper struct + bpf_obj_new / bpf_list_push_back macros.
      # Must come before the Qdisc_ops member bodies that reference them.
      if ctx.uses_qdisc_fifo
        sections.insert(2, emit_qdisc_fifo_preamble(ctx))
      end
      # struct_ops bundles must come AFTER the SEC("struct_ops/<m>")
      # functions are defined (they take function-pointer initializers).
      sections << emit_struct_ops_bundle(ctx, :tcp_cc)    if ctx.uses_tcp_cc
      sections << emit_struct_ops_bundle(ctx, :sched_ext) if ctx.uses_sched_ext
      sections << emit_struct_ops_bundle(ctx, :qdisc)     if ctx.uses_qdisc
      sections.compact.join("\n")
    end

    # walk a method body AST looking for `stack_id` / `user_stack_id`
    # CallNodes. Skip nested DefNode bodies (those are separate methods).
    # `off_cpu_start` also requires ctx (it calls bpf_get_stackid
    # internally), so include it in the scan.
    def stack_trace_referenced?(ast, mi)
      bid = mi.body_id
      return false if !bid || bid < 0
      found = false
      visit = lambda do |nid|
        return if found || nid < 0
        n = ast.node(nid)
        return unless n
        return if %w[DefNode ClassNode ModuleNode].include?(n.type)
        if n.type == "CallNode"
          nm = n.attrs.fetch("name", "")
          if nm == "stack_id" || nm == "user_stack_id" || nm == "off_cpu_start"
            found = true
            return
          end
        end
        n.refs.each_value { |c| visit.call(c) if c.is_a?(Integer) }
        n.arrays.each_value { |a| a.each { |c| visit.call(c) if c.is_a?(Integer) } }
      end
      visit.call(bid)
      found
    end

    def sanitize_identifier(s)
      out = s.gsub(/[^A-Za-z0-9_]/, "_")
      out = "u_#{out}" if out =~ /\A\d/   # C identifiers must not start with digit
      out
    end

    # C11 reserved words. If a Ruby identifier (local var / param /
    # top-level method) happens to match one, we suffix `_` to keep the
    # emitted .bpf.c compile-clean. Ruby allows e.g. `def add(double); end`
    # — without sanitization that becomes `__s64 add(__s64 double)` and
    # clang refuses. C99/C11 additions (_Bool, restrict, inline) included.
    # NOT included: typedefs from vmlinux.h (size_t etc.) since they're not
    # keywords — they just shadow if reused. C++ keywords (class, new,
    # delete, ...) are also out of scope: we compile with `-x c`.
    C_KEYWORDS = %w[
      auto break case char const continue default do double else enum extern
      float for goto if inline int long register restrict return short signed
      sizeof static struct switch typedef union unsigned void volatile while
      _Bool _Complex _Imaginary _Atomic _Static_assert _Thread_local
      _Alignas _Alignof _Generic _Noreturn
    ].to_set.freeze

    # pass-through unless the name collides with a C keyword. Suffix
    # `_` on collision. Idempotent (since `double_` isn't a keyword).
    def c_safe(name)
      return name unless name.is_a?(String)
      return name if name.empty?
      C_KEYWORDS.include?(name) ? "#{name}_" : name
    end

    # ---------- internal helpers ----------

    EmitContext = Struct.new(
      :ir, :ast, :partition, :base_name, :unit_name, :uses_ringbuf,
      :uses_str_ringbuf,     # separate ringbuf for spnl_emit_str
      :uses_pair_ringbuf,    # separate ringbuf for spnl_emit_pair
      :uses_emit3_ringbuf,   # spnl_emit3(a, b, c) — 3-tuple ringbuf
      :uses_emit4_ringbuf,   # spnl_emit4(a, b, c, d) — 4-tuple ringbuf
      :ebpf_methods_by_name,
      :loop_counter,         # monotonically growing id for callback names
      :deferred_functions,   # array of "static int <cb>(__u32 i, void *_raw) {...}"
      :pkt_builtins_used,    # Hash<name, Set<:xdp|:tc>> of pkt_* by attach context
      :uses_blocklist,       # true if any :ebpf method calls blocklist_match
      :uses_cidr_blocklist,  # true if any :ebpf method calls cidr_blocklist_match (LPM_TRIE)
      :uses_path_counter,    # true if any :ebpf method calls path_counter_inc
      :uses_reuseport_sockarray,  # true if any sk_reuseport method calls worker_select
      :uses_xdp_health_match,     # true if any xdp method calls xdp_match_health
      :uses_xdp_health_reply,     # true if any xdp method calls xdp_reply_health
      :uses_tcp_slice,            # true if any xdp__tcp_slice__<name> method exists
      :uses_dynptr,               # true if any :ebpf method uses pkt_dynptr_* builtins
      :uses_user_ringbuf,         # true if any user_ringbuf__<name> callback exists
      :user_ringbuf_cb_name,      # the cb name (m[1]) — used by drain builtin to reference it
      :uses_tail_call,            # true if PROG_ARRAY + tail_call should be emitted
      :tail_targets,              # Array of xdp_tail__<name> in declaration order
      :uses_cpumap,               # true if any :ebpf method calls cpumap_redirect
      :uses_xskmap,               # any :ebpf method calls xsk_redirect (AF_XDP XSKMAP)
      :uses_devmap,               # any :ebpf method calls dev_redirect (DEVMAP)
      :uses_tcp_cc,               # true if any tcp_cc__<member> is declared
      :tcp_cc_members,            # Array of member names emitted (init / ssthresh / ...)
      :uses_sched_ext,            # any sched_ext__<member> declared
      :sched_ext_members,         # Array of declared sched_ext members
      :uses_qdisc,                # any qdisc__<member> declared
      :qdisc_members,             # Array of declared qdisc members
      :uses_timer,                # true if any on :timer handler exists
      :timer_interval_ns,         # interval set at handler declaration time
      :timer_handler_name,        # codegen-fixed name suffix ("main" in MVP)
      :uses_pt_regs_parm,         # any kprobe/kretprobe with >=1 param exists
      :uses_usdt,                 # any usdt__<prov>__<name> method exists
      :uses_histogram,            # any :ebpf method calls hist_observe
      :uses_latency,              # any :ebpf method calls latency_start/end
      :uses_histogram_keyed,      # any :ebpf method calls hist_observe_by
      :uses_histogram_linear,     # any :ebpf method calls hist_observe_linear
      :uses_stack_trace,          # any :ebpf method calls stack_id / user_stack_id
      :uses_off_cpu,              # any :ebpf method calls off_cpu_start / observe
      :uses_qdisc_fifo,           # any :ebpf method calls queue_push / queue_pop
      :uses_kfield,               # any :ebpf method calls kfield / a kptr dot accessor (needs BPF_CORE_READ)
      :uses_fib,                  # any :ebpf method calls fib_lookup (struct bpf_fib_lookup stack local + bpf_fib_lookup; needs bpf_endian.h)
      :uses_csum,                 # any :ebpf method calls l3_csum_replace / l4_csum_replace (bpf_htons → needs bpf_endian.h)
      :uses_arena,                # any :ebpf method calls arena_set / arena_get (BPF_MAP_TYPE_ARENA + __arena global; needs clang -mcpu=v3)
      :uses_task_storage,         # any :ebpf method calls task_load / task_store (TASK_STORAGE map)
      :uses_map_in_map,           # any :ebpf method calls mim_inc / mim_get (ARRAY_OF_MAPS)
      :uses_fifo,                 # any :ebpf method calls fifo_push / fifo_pop (QUEUE)
      :uses_lifo,                 # any :ebpf method calls lifo_push / lifo_pop (STACK)
      :uses_leak_track,           # any :ebpf method calls leak_record / leak_forget (bpf_allocs HASH)
      :uses_lock_edge,            # any :ebpf method calls lock_edge (bpf_lock_edges HASH — deadlock)
      :uses_keyed_lat,            # any :ebpf method calls lat_start / lat_end (arbitrary-key latency)
      :uses_depth,                # any :ebpf method calls depth_inc / depth_dec (instrument depth-collapse)
      :flow_maps,                 # Roadmap #2: Hash<name(String) => [field(String)]> declared via flow_map.
      :flow_map_kinds,            # Roadmap #2: Hash<name => Set<:xdp|:tc>> — which ctx each flow map is used in.
      :syncookie_used,            # Roadmap #3: Set of :gen/:check tcp_syncookie_* builtins used.
      :uses_tcp_reply,            # Roadmap #4: true if any method calls tcp_reply_header.
      :uses_tcp_synack,           # Roadmap #4b: true if any method calls tcp_reply_synack (MSS option).
      :uses_synack_cookie,        # Roadmap #4b': true if any method calls tcp_synack_cookie (integrated SYN sequence).
      :payload_matchers,          # Roadmap #5a: Array of distinct payload_starts prefixes (bytes); index = helper id.
      :reply_bodies,              # Roadmap #5b: Array of distinct tcp_reply_data response payloads (bytes); index = id.
      :plugin_sections,           # additive section hook.
                                  # Array of [predicate(ctx)->bool, emitter(ctx)->String]
                                  # appended by plugins; emitted after the core registry.
      keyword_init: true,
    )

    # Data-driven section registry.
    # Replaces the old hardcoded `sections << emit_X(ctx) if ctx.uses_X` chain of section output with
    # an ordered [gate, emitter] table. The gate is a flag symbol (Struct member)
    # or a `->(ctx){...}` predicate, and the emitter is an emit_* method name. Plugins can splice in
    # sections by adding [predicate, emitter] to `ctx.plugin_sections` without editing the core (additive composition).
    SECTION_REGISTRY = [
      [:uses_blocklist,          :emit_blocklist_map_and_helper],
      [:uses_cidr_blocklist,     :emit_cidr_blocklist_map_and_helper],     # LPM_TRIE
      [:uses_path_counter,       :emit_path_counter_map_and_helper],
      [:uses_leak_track,         :emit_leak_track_map_and_helper],         # memleak
      [:uses_lock_edge,          :emit_lock_edge_map_and_helper],          # deadlock
      [:uses_keyed_lat,          :emit_keyed_lat_map_and_helper],          # keyed latency
      [:uses_depth,              :emit_depth_map_and_helper],              # depth-collapse
      [:uses_histogram,          :emit_histogram_map_and_helper],
      [:uses_latency,            :emit_latency_map_and_helper],
      [:uses_task_storage,       :emit_task_storage_map_and_helper],
      [:uses_map_in_map,         :emit_map_in_map_maps_and_helper],
      [->(c) { c.uses_fifo || c.uses_lifo }, :emit_queue_stack_maps_and_helper],
      [:uses_histogram_keyed,    :emit_histogram_keyed_map_and_helper],
      [:uses_histogram_linear,   :emit_histogram_linear_map_and_helper],
      [:uses_stack_trace,        :emit_stack_trace_map],
      [:uses_off_cpu,            :emit_off_cpu_map_and_helper],
      [:uses_reuseport_sockarray, :emit_reuseport_sockarray_map],
      [:uses_xdp_health_match,   :emit_xdp_health_match_helper],
      [:uses_xdp_health_reply,   :emit_xdp_health_reply_helper],
      [:uses_tcp_slice,          :emit_tcp_slice_bundle],
      [:uses_dynptr,             :emit_dynptr_helpers],
      [:uses_user_ringbuf,       :emit_user_ringbuf_map],
      [:uses_tail_call,          :emit_prog_array_map],
      [:uses_cpumap,             :emit_cpumap_map],
      [:uses_xskmap,             :emit_xskmap],
      [:uses_devmap,             :emit_devmap],
      [:uses_timer,              :emit_timer_map],
    ].freeze

    def header(base_name, n_methods, n_classes)
      <<~HDR
        // SPDX-License-Identifier: GPL-2.0 OR MIT
        //
        // GENERATED by spinel-ebpf codegen. Do not edit by hand.
        // Source unit: #{base_name}.rb
        // ebpf-eligible methods: #{n_methods}, classes touched: #{n_classes}
      HDR
    end

    def license_and_includes(ctx)
      extras = []
      extras << '#include "spnl/types.h"' if ctx.uses_ringbuf || ctx.uses_str_ringbuf ||
                                              ctx.uses_pair_ringbuf || ctx.uses_emit3_ringbuf || ctx.uses_emit4_ringbuf
      need_endian = (ctx.pkt_builtins_used && !ctx.pkt_builtins_used.empty?) ||
                    ctx.uses_xdp_health_match || ctx.uses_xdp_health_reply ||
                    ctx.uses_tcp_slice || ctx.uses_fib || ctx.uses_csum
      extras << "#include <bpf/bpf_endian.h>" if need_endian
      # struct_ops wrappers use the BPF_PROG macro from
      # bpf_tracing.h to bridge `__u64 *ctx` → typed kernel-struct args.
      # kprobe/kretprobe with params lowers each to PT_REGS_PARM<i>(ctx)
      # which is also declared in bpf_tracing.h. The include was previously
      # skipped for plain probes so kprobes with 3+ params failed to compile.
      need_tracing = ctx.uses_tcp_cc || ctx.uses_sched_ext || ctx.uses_qdisc ||
                     ctx.uses_pt_regs_parm || ctx.uses_usdt
      extras << "#include <bpf/bpf_tracing.h>" if need_tracing
      # USDT (User Statically-Defined Tracing) helpers. libbpf provides
      # `bpf_usdt_arg()` in <bpf/usdt.bpf.h> for unpacking USDT arg encodings.
      extras << "#include <bpf/usdt.bpf.h>" if ctx.uses_usdt
      # bpf_core_type_id_local() (used by the bpf_obj_new macro) lives
      # in <bpf/bpf_core_read.h>. Only pulled in when the FIFO qdisc helper
      # machinery is needed.
      extras << "#include <bpf/bpf_core_read.h>" if ctx.uses_qdisc_fifo || ctx.uses_kfield
      <<~INC
        #include "vmlinux.h"
        #include <bpf/bpf_helpers.h>
        #{extras.join("\n")}
        char LICENSE[] SEC("license") = "Dual MIT/GPL";
      INC
    end

    # per-unit ringbuf map + event struct. Emitted only when at least
    # one ebpf method uses spnl_emit. Per the host/kernel protocol, every event
    # carries a 16-byte spnl_event_hdr in its first field.
    def emit_event_types_and_map(ctx)
      <<~RB
        /* === per-unit int-event channel === */
        struct #{ctx.unit_name}_event {
            struct spnl_event_hdr hdr;
            __s64 value;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_RINGBUF);
            __uint(max_entries, 256 * 1024);
        } #{ctx.unit_name}_events SEC(".maps");
      RB
    end

    # per-unit string-event channel. Separate ringbuf so int events and
    # string events stay disambiguated by map (no shared union/discriminator).
    def emit_str_event_types_and_map(ctx)
      <<~RB
        /* === per-unit string-event channel === */
        struct #{ctx.unit_name}_str_event {
            struct spnl_event_hdr hdr;
            char str[#{SPNL_STR_MAX}];
        };

        struct {
            __uint(type, BPF_MAP_TYPE_RINGBUF);
            __uint(max_entries, 256 * 1024);
        } #{ctx.unit_name}_str_events SEC(".maps");
      RB
    end

    # per-unit pair-event channel (two __s64 values per event).
    def emit_pair_event_types_and_map(ctx)
      <<~RB
        /* === per-unit pair-event channel === */
        struct #{ctx.unit_name}_pair_event {
            struct spnl_event_hdr hdr;
            __s64 a;
            __s64 b;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_RINGBUF);
            __uint(max_entries, 256 * 1024);
        } #{ctx.unit_name}_pair_events SEC(".maps");
      RB
    end

    # per-unit N-tuple event channel. n in {3, 4}. The struct field
    # names match the host parse contract: 3-tuple = (a, b, c), 4-tuple =
    # (a, b, c, d). Anything beyond 4 is deferred for now — by then
    # users will have hit the limits of fixed-arity emit and a variadic
    # design will be motivated by concrete need.
    def emit_n_tuple_event_types_and_map(ctx, n)
      raise ArgumentError, "emit_n_tuple n must be 3 or 4, got #{n}" unless [3, 4].include?(n)
      field_names = %w[a b c d].first(n)
      fields = field_names.map { |fn| "    __s64 #{fn};" }.join("\n")
      <<~RB
        /* === per-unit #{n}-tuple-event channel === */
        struct #{ctx.unit_name}_emit#{n}_event {
            struct spnl_event_hdr hdr;
        #{fields}
        };

        struct {
            __uint(type, BPF_MAP_TYPE_RINGBUF);
            __uint(max_entries, 256 * 1024);
        } #{ctx.unit_name}_emit#{n}_events SEC(".maps");
      RB
    end

    # Find classes that own at least one ebpf method (or that those methods
    # reference via ivar). For MVP we just take owning classes; ivar access
    # by other classes would need cross-class type info.
    def collect_classes_used(ir, ebpf_methods)
      names = ebpf_methods.select { |m| m.scope == :class }.map(&:class_name).uniq
      cls_names = ir.sa("@cls_names") || []
      names.compact.map do |name|
        idx = cls_names.index(name)
        next nil unless idx
        { name: name, idx: idx }
      end.compact
    end

    # Emit one HASH map per ivar of the given class.
    def emit_ivar_maps(ctx, cls)
      ir = ctx.ir
      ivar_names_pipe = ir.sa("@cls_ivar_names") || []
      ivar_types_pipe = ir.sa("@cls_ivar_types") || []
      names = (ivar_names_pipe[cls[:idx]] || "").split(";", -1).reject(&:empty?)
      types = (ivar_types_pipe[cls[:idx]] || "").split(";", -1)
      return nil if names.empty?

      blocks = names.zip(types).map do |ivar, t|
        c_type = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "ivar #{ivar}: type #{t.inspect} not supported")
        map_name = ivar_map_name(cls[:name], ivar)
        <<~MAP
          /* class #{cls[:name]} ivar #{ivar} : #{t} */
          struct {
              __uint(type, BPF_MAP_TYPE_HASH);
              __type(key, __u32);
              __type(value, #{c_type});
              __uint(max_entries, 1);
          } #{map_name} SEC(".maps");
        MAP
      end
      blocks.join("\n")
    end

    # XDP packet-header access helpers. One static __always_inline
    # function per pkt_* builtin actually used. Each does a self-contained
    # set of `data + N > data_end` bounds checks (the verifier requires this
    # phrasing) and returns a sentinel 0 on any out-of-bounds path. ETH_P_IP
    # is compared in network order via bpf_htons() (compile-time constant),
    # but the returned values (ip4_src etc.) are converted to host order so
    # Ruby comparisons against KNOWN_CONSTANTS work naturally.
    # emit one __noinline helper per (builtin name, attach kind)
    # pair that was referenced from a method body. struct xdp_md and
    # struct __sk_buff both expose data/data_end at the same field names with
    # PTR_TO_PACKET / PTR_TO_PACKET_END verifier semantics, so the C body is
    # bit-for-bit identical — only the signature (ctx type and helper name)
    # differs between XDP and TC variants.
    def emit_pkt_helpers(ctx)
      blocks = []
      ctx.pkt_builtins_used.each do |name, kinds|
        kinds.each do |kind|
          blocks << emit_pkt_helper(name, kind)
        end
      end
      blocks.join("\n")
    end

    def emit_pkt_helper(name, kind)
      ctx_decl  = kind == :xdp ? "struct xdp_md *ctx" : "struct __sk_buff *ctx"
      fn_prefix = kind == :xdp ? "spnl"               : "spnl_tc"
      case name
      when "pkt_len"
        <<~LEN
          /* total packet length (data_end - data). Always safe.
           * The intermediate unsigned-long conversion forces the verifier to
           * see both sides as scalars before the subtraction — otherwise pkt_end
           * leaks into downstream arithmetic. */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              unsigned long e = (unsigned long)(long)ctx->data_end;
              unsigned long d = (unsigned long)(long)ctx->data;
              return (__s64)(e - d);
          }
        LEN
      when "pkt_eth_proto"
        <<~PROTO
          /* EtherType in host byte order, or 0 if frame too short. */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              return (__s64)bpf_ntohs(eth->h_proto);
          }
        PROTO
      when "pkt_l4_proto"
        <<~L4P
          /* L4 protocol (TCP=6, UDP=17, ICMP=1, ICMPv6=58), or 0 if not
           * IPv4 nor IPv6 / truncated.
           * For IPv6 we return ip6h->nexthdr directly — if it's an
           * extension header (Hop-by-Hop=0, Routing=43, Fragment=44, ...)
           * the caller sees that value as-is (extension header walking is
           * out of scope for this builtin). */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              if (eth->h_proto == bpf_htons(0x0800)) {  /* ETH_P_IP */
                  struct iphdr *iph = (void *)(eth + 1);
                  if ((void *)(iph + 1) > data_end) return 0;
                  return (__s64)iph->protocol;
              }
              if (eth->h_proto == bpf_htons(0x86DD)) {  /* ETH_P_IPV6 */
                  struct ipv6hdr *ip6h = (void *)(eth + 1);
                  if ((void *)(ip6h + 1) > data_end) return 0;
                  return (__s64)ip6h->nexthdr;
              }
              return 0;
          }
        L4P
      when "pkt_ip4_src"
        <<~SRC
          /* IPv4 source address in host byte order, or 0 if not IPv4. */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              if (eth->h_proto != bpf_htons(0x0800)) return 0;
              struct iphdr *iph = (void *)(eth + 1);
              if ((void *)(iph + 1) > data_end) return 0;
              return (__s64)bpf_ntohl(iph->saddr);
          }
        SRC
      when "pkt_ip4_dst"
        <<~DST
          /* IPv4 destination address in host byte order, or 0 if not IPv4. */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              if (eth->h_proto != bpf_htons(0x0800)) return 0;
              struct iphdr *iph = (void *)(eth + 1);
              if ((void *)(iph + 1) > data_end) return 0;
              return (__s64)bpf_ntohl(iph->daddr);
          }
        DST
      when "pkt_l4_sport"
        pkt_l4_port_helper("sport", 0, ctx_decl, fn_prefix)
      when "pkt_l4_dport"
        pkt_l4_port_helper("dport", 2, ctx_decl, fn_prefix)
      when "pkt_tcp_flags"
        <<~FLG
          /* TCP flag byte (host-order), 0 if not TCP or truncated.
           * RFC 793 §3.1: flags live in the 13th byte of the TCP header
           * (offset of data_offset|reserved|flags). We mask off the data
           * offset upper nibble so the caller sees a clean 8-bit field.
           * IPv6 branch added (extension headers out of scope). */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              if (eth->h_proto == bpf_htons(0x0800)) {
                  struct iphdr *iph = (void *)(eth + 1);
                  if ((void *)(iph + 1) > data_end) return 0;
                  if (iph->protocol != 6) return 0;  /* IPPROTO_TCP */
                  __u32 ihl = iph->ihl * 4;
                  if (ihl < sizeof(*iph)) return 0;
                  char *l4 = (char *)iph + ihl;
                  if (l4 + 14 > (char *)data_end) return 0;
                  __u8 flags = (__u8)l4[13];
                  return (__s64)flags;
              }
              if (eth->h_proto == bpf_htons(0x86DD)) {
                  struct ipv6hdr *ip6h = (void *)(eth + 1);
                  if ((void *)(ip6h + 1) > data_end) return 0;
                  if (ip6h->nexthdr != 6) return 0;  /* IPPROTO_TCP */
                  char *l4 = (char *)(ip6h + 1);
                  if (l4 + 14 > (char *)data_end) return 0;
                  __u8 flags = (__u8)l4[13];
                  return (__s64)flags;
              }
              return 0;
          }
        FLG
      when "pkt_tcp_seq"
        # Roadmap (Ruby tcp_slice) #1: TCP sequence number. Needed for ack/seq
        # arithmetic in the state machine. Offset 4 in the TCP header.
        pkt_tcp_u32_field_helper("pkt_tcp_seq", 4, ctx_decl, fn_prefix)
      when "pkt_tcp_ack"
        # Roadmap #1: TCP acknowledgement number. Offset 8 in the TCP header.
        pkt_tcp_u32_field_helper("pkt_tcp_ack", 8, ctx_decl, fn_prefix)
      when "pkt_l4_payload_len"
        <<~PLEN
          /* TCP/UDP payload length in bytes (IP total length minus IP
           * and L4 header sizes). 0 if not IPv4/IPv6 TCP/UDP or truncated.
           * Useful for distinguishing "empty ACK" packets (kernel-generated
           * spurious control packets) from data carriers.
           * For IPv6, ip6h->payload_len already excludes
           * the IPv6 header (unlike IPv4 tot_len), so we just subtract the
           * L4 header size. Extension headers are out of scope. */
          static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              if (eth->h_proto == bpf_htons(0x0800)) {
                  struct iphdr *iph = (void *)(eth + 1);
                  if ((void *)(iph + 1) > data_end) return 0;
                  __u32 ihl = iph->ihl * 4;
                  if (ihl < sizeof(*iph)) return 0;
                  __u32 ip_tot = bpf_ntohs(iph->tot_len);
                  __u32 l4_total = (ip_tot > ihl) ? (ip_tot - ihl) : 0;
                  if (iph->protocol == 6) {  /* IPPROTO_TCP */
                      char *l4 = (char *)iph + ihl;
                      if (l4 + 13 > (char *)data_end) return 0;
                      __u32 doff = (((__u8)l4[12]) >> 4) * 4;
                      if (doff < 20) return 0;
                      return (__s64)((l4_total > doff) ? (l4_total - doff) : 0);
                  } else if (iph->protocol == 17) {  /* IPPROTO_UDP */
                      return (__s64)((l4_total > 8) ? (l4_total - 8) : 0);
                  }
                  return 0;
              }
              if (eth->h_proto == bpf_htons(0x86DD)) {
                  struct ipv6hdr *ip6h = (void *)(eth + 1);
                  if ((void *)(ip6h + 1) > data_end) return 0;
                  __u32 l4_total = bpf_ntohs(ip6h->payload_len);
                  if (ip6h->nexthdr == 6) {  /* IPPROTO_TCP */
                      char *l4 = (char *)(ip6h + 1);
                      if (l4 + 13 > (char *)data_end) return 0;
                      __u32 doff = (((__u8)l4[12]) >> 4) * 4;
                      if (doff < 20) return 0;
                      return (__s64)((l4_total > doff) ? (l4_total - doff) : 0);
                  } else if (ip6h->nexthdr == 17) {  /* IPPROTO_UDP */
                      return (__s64)((l4_total > 8) ? (l4_total - 8) : 0);
                  }
                  return 0;
              }
              return 0;
          }
        PLEN
      when "pkt_ip6_src_hi"
        pkt_ip6_addr_helper("src", "hi", ctx_decl, fn_prefix)
      when "pkt_ip6_src_lo"
        pkt_ip6_addr_helper("src", "lo", ctx_decl, fn_prefix)
      when "pkt_ip6_dst_hi"
        pkt_ip6_addr_helper("dst", "hi", ctx_decl, fn_prefix)
      when "pkt_ip6_dst_lo"
        pkt_ip6_addr_helper("dst", "lo", ctx_decl, fn_prefix)
      else
        raise UnsupportedNode, "emit_pkt_helper: unknown builtin #{name.inspect}"
      end
    end

    # IPv6 address half (hi=upper 64 bits / lo=lower 64 bits) in host
    # byte order. __s64 return is consistent with pkt_ip4_src/dst even though
    # the high bit may make values appear "negative" in Ruby — that's a
    # consequence of the 64-bit signed return, not a bug.
    # `in6_u.u6_addr32[i]` is the portable vmlinux.h path (anonymous union
    # member). bpf_ntohl on each 32-bit half then combined into one __u64
    # so the receiver gets host-byte-order values.
    def pkt_ip6_addr_helper(which, half, ctx_decl, fn_prefix)
      ip6_field = which == "src" ? "saddr" : "daddr"
      i0, i1 = half == "hi" ? [0, 1] : [2, 3]
      <<~ADDR
        /* IPv6 #{which} address #{half} half (host byte order), 0 if not IPv6. */
        static __noinline __s64 #{fn_prefix}_pkt_ip6_#{which}_#{half}(#{ctx_decl})
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return 0;
            if (eth->h_proto != bpf_htons(0x86DD)) return 0;  /* ETH_P_IPV6 */
            struct ipv6hdr *ip6h = (void *)(eth + 1);
            if ((void *)(ip6h + 1) > data_end) return 0;
            __be32 a0 = ip6h->#{ip6_field}.in6_u.u6_addr32[#{i0}];
            __be32 a1 = ip6h->#{ip6_field}.in6_u.u6_addr32[#{i1}];
            __u64 v = ((__u64)bpf_ntohl(a0) << 32) | (__u64)bpf_ntohl(a1);
            return (__s64)v;
        }
      ADDR
    end

    # emit the per-unit blocklist HASH map + a __noinline matcher.
    # Key is the IPv4 address in host byte order (matches what pkt_ip4_src
    # returns), value is a 1-byte presence flag. Map name is intentionally
    # short (15-char kernel cap) so bpftool can list it cleanly: "bpf_blocklist".
    BLOCKLIST_MAP_NAME = "bpf_blocklist"
    BLOCKLIST_MAX_ENTRIES = 8192

    def emit_blocklist_map_and_helper(ctx)
      <<~BLK
        /* per-unit blocklist. Populated from userspace via
         * sp_bpf_blocklist_add(uint32_t) / sp_bpf_blocklist_del(uint32_t),
         * read from BPF via spnl_blocklist_match(ip_host_order). */
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u32);
            __type(value, __u8);
            __uint(max_entries, #{BLOCKLIST_MAX_ENTRIES});
        } #{BLOCKLIST_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_blocklist_match(__s64 ip_host_order)
        {
            __u32 k = (__u32)ip_host_order;
            __u8 *v = bpf_map_lookup_elem(&#{BLOCKLIST_MAP_NAME}, &k);
            return v ? 1 : 0;
        }
      BLK
    end

    # per-unit CIDR blocklist. Same shape as the exact-match blocklist but a BPF_MAP_TYPE_LPM_TRIE
    # so userspace can insert prefixes (10.0.0.0/8) and the kernel does
    # longest-prefix matching. Name kept <=15 chars for the kernel cap so
    # bpf_object__find_map_by_name in glue.c matches: "bpf_cidr_block".
    CIDR_BLOCKLIST_MAP_NAME = "bpf_cidr_block"
    CIDR_BLOCKLIST_MAX_ENTRIES = 8192

    def emit_cidr_blocklist_map_and_helper(ctx)
      <<~CBLK
        /* per-unit CIDR blocklist (LPM_TRIE). Populated from userspace via
         * sp_bpf_cidr_blocklist_add(ip_host_order, prefixlen) / _del, read from
         * BPF via spnl_cidr_blocklist_match(ip_host_order). The key's data[] is
         * big-endian (network order) — the trie matches bits MSB-first. */
        struct spnl_cidr_key {
            __u32 prefixlen;
            __u8  data[4];
        };
        struct {
            __uint(type, BPF_MAP_TYPE_LPM_TRIE);
            __type(key, struct spnl_cidr_key);
            __type(value, __u8);
            __uint(max_entries, #{CIDR_BLOCKLIST_MAX_ENTRIES});
            __uint(map_flags, BPF_F_NO_PREALLOC);
        } #{CIDR_BLOCKLIST_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_cidr_blocklist_match(__s64 ip_host_order)
        {
            struct spnl_cidr_key k;
            __u32 ip = (__u32)ip_host_order;
            k.prefixlen = 32;
            k.data[0] = (__u8)((ip >> 24) & 0xff);
            k.data[1] = (__u8)((ip >> 16) & 0xff);
            k.data[2] = (__u8)((ip >> 8) & 0xff);
            k.data[3] = (__u8)(ip & 0xff);
            __u8 *v = bpf_map_lookup_elem(&#{CIDR_BLOCKLIST_MAP_NAME}, &k);
            return v ? 1 : 0;
        }
      CBLK
    end

    # per-unit path-hit counter map. Key is a host-order int (typically
    # a path enum or hash from userspace), value is a 64-bit counter updated
    # atomically with __sync_fetch_and_add so concurrent BPF programs across
    # CPUs don't lose updates. Map name "bpf_path_counts" fits the 15-char
    # kernel cap so bpftool listings stay clean.
    PATH_COUNTER_MAP_NAME = "bpf_path_counts"
    PATH_COUNTER_MAX_ENTRIES = 128

    def emit_path_counter_map_and_helper(ctx)
      <<~PCM
        /* per-unit path hit counter map.
         * Populated from :ebpf method via path_counter_inc(key); read from
         * userspace with bpftool map dump or via a future spnl_runtime API. */
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u32);
            __type(value, __s64);
            __uint(max_entries, #{PATH_COUNTER_MAX_ENTRIES});
        } #{PATH_COUNTER_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_path_counter_inc(__s64 key)
        {
            __u32 k = (__u32)key;
            __s64 *v = bpf_map_lookup_elem(&#{PATH_COUNTER_MAP_NAME}, &k);
            if (v) {
                __sync_fetch_and_add(v, 1);
            } else {
                __s64 init = 1;
                bpf_map_update_elem(&#{PATH_COUNTER_MAP_NAME}, &k, &init, BPF_NOEXIST);
            }
            return 0;
        }
      PCM
    end

    # outstanding-allocation tracking map (bcc memleak). Keyed by the
    # allocation pointer; the value records the size + the stack id that made
    # the allocation. leak_record(ptr, size, stack_id) inserts/overwrites,
    # leak_forget(ptr) deletes on free. At report time every surviving entry is
    # an allocation that was never freed; the host groups them by stack id.
    LEAK_TRACK_MAP_NAME = "bpf_allocs"
    LEAK_TRACK_MAX_ENTRIES = 262144

    def emit_leak_track_map_and_helper(_ctx)
      <<~LK
        /* per-unit outstanding-allocation map for memleak-style tools.
         * key = allocation pointer, value = {size, stack_id}. Host reads the
         * surviving entries (= un-freed allocations) and groups by stack_id. */
        struct spnl_alloc_info {
            __s64 size;
            __s64 stack_id;
        };
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u64);
            __type(value, struct spnl_alloc_info);
            __uint(max_entries, #{LEAK_TRACK_MAX_ENTRIES});
        } #{LEAK_TRACK_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_leak_record(__s64 ptr, __s64 size, __s64 stack_id)
        {
            __u64 k = (__u64)ptr;
            struct spnl_alloc_info info = {};
            info.size = size;
            info.stack_id = stack_id;
            bpf_map_update_elem(&#{LEAK_TRACK_MAP_NAME}, &k, &info, BPF_ANY);
            return 0;
        }

        static __noinline __s64 spnl_leak_forget(__s64 ptr)
        {
            __u64 k = (__u64)ptr;
            bpf_map_delete_elem(&#{LEAK_TRACK_MAP_NAME}, &k);
            return 0;
        }
      LK
    end

    # lock-order edge map for deadlock detection (bcc deadlock). Keyed by
    # an ordered pair of lock addresses (a held before b was acquired), value =
    # how many times that order was observed. Userspace builds the graph and
    # flags cycles (a->b AND b->a) as potential lock-order inversions.
    LOCK_EDGE_MAP_NAME = "bpf_lock_edges"
    LOCK_EDGE_MAX_ENTRIES = 65536

    def emit_lock_edge_map_and_helper(_ctx)
      <<~LE
        /* per-unit lock-order edge map for deadlock detection.
         * key = {lock_a, lock_b} (a was held when b was acquired). */
        struct spnl_lock_edge {
            __u64 a;
            __u64 b;
        };
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, struct spnl_lock_edge);
            __type(value, __u64);
            __uint(max_entries, #{LOCK_EDGE_MAX_ENTRIES});
        } #{LOCK_EDGE_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_lock_edge(__s64 a, __s64 b)
        {
            struct spnl_lock_edge k = {};
            k.a = (__u64)a;
            k.b = (__u64)b;
            __u64 *v = bpf_map_lookup_elem(&#{LOCK_EDGE_MAP_NAME}, &k);
            if (v) {
                __sync_fetch_and_add(v, 1);
            } else {
                __u64 one = 1;
                bpf_map_update_elem(&#{LOCK_EDGE_MAP_NAME}, &k, &one, BPF_NOEXIST);
            }
            return 0;
        }
      LE
    end

    # arbitrary-key latency map. Generalizes the tid-keyed latency to
    # any caller-chosen key (a request pointer for biolatency, a pid for
    # runqlat, ...). lat_start(key) stamps the entry time; lat_end(key) returns
    # now - entry (ns) and deletes the entry (0 if no matching start).
    KEYED_LAT_MAP_NAME = "bpf_keyed_lat"
    KEYED_LAT_MAX_ENTRIES = 65536

    def emit_keyed_lat_map_and_helper(_ctx)
      <<~KL
        /* per-unit arbitrary-key latency map (bcc biolatency / runqlat).
         * key = any u64 id; value = entry ktime. */
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u64);
            __type(value, __u64);
            __uint(max_entries, #{KEYED_LAT_MAX_ENTRIES});
        } #{KEYED_LAT_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_lat_start_key(__s64 key)
        {
            __u64 k = (__u64)key;
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&#{KEYED_LAT_MAP_NAME}, &k, &now, BPF_ANY);
            return 0;
        }

        static __noinline __s64 spnl_lat_end_key(__s64 key)
        {
            __u64 k = (__u64)key;
            __u64 *t = bpf_map_lookup_elem(&#{KEYED_LAT_MAP_NAME}, &k);
            if (!t) return 0;
            __u64 d = bpf_ktime_get_ns() - *t;
            bpf_map_delete_elem(&#{KEYED_LAT_MAP_NAME}, &k);
            return (__s64)d;
        }
      KL
    end

    # per-(tid,method) recursion depth for --instrument depth-collapse.
    # Mirrors templates/depth.template.c (the production path is the C codegen).
    DEPTH_MAP_NAME = "bpf_depth"

    def emit_depth_map_and_helper(_ctx)
      <<~DEPTH
        /* per-(tid,method) recursion depth for --instrument depth-collapse.
         * key = any u64 id (the agent uses (tid<<8)|method_idx); value = current depth.
         * depth_inc returns the depth AFTER incrementing (1 == outermost entry);
         * depth_dec returns the depth AFTER decrementing (0 == outermost exit, key freed).
         * Same-thread recursion runs on one CPU at a time, so the read-modify-write is
         * race-free for these per-thread keys. */
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u64);
            __type(value, __s64);
            __uint(max_entries, 65536);
        } #{DEPTH_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_depth_inc(__s64 key)
        {
            __u64 k = (__u64)key;
            __s64 *d = bpf_map_lookup_elem(&#{DEPTH_MAP_NAME}, &k);
            if (d) { *d += 1; return *d; }
            __s64 one = 1;
            bpf_map_update_elem(&#{DEPTH_MAP_NAME}, &k, &one, BPF_ANY);
            return 1;
        }

        static __noinline __s64 spnl_depth_dec(__s64 key)
        {
            __u64 k = (__u64)key;
            __s64 *d = bpf_map_lookup_elem(&#{DEPTH_MAP_NAME}, &k);
            if (!d) return 0;
            *d -= 1;
            __s64 nv = *d;
            if (nv <= 0) bpf_map_delete_elem(&#{DEPTH_MAP_NAME}, &k);
            return nv;
        }
      DEPTH
    end

    # per-unit log2 histogram. ARRAY of 64 buckets (covers 2^0 to 2^63).
    # Callers use `hist_observe(value)` to bin a value by floor(log2(value));
    # the helper does the bucketing + __sync_fetch_and_add atomically. Host
    # side dumps via `spnl_runtime_print_log2_hist(rt, "bpf_hist")` for an
    # ASCII art histogram (bcc-compatible format).
    HISTOGRAM_MAP_NAME = "bpf_hist"
    HISTOGRAM_SLOTS    = 64

    def emit_histogram_map_and_helper(_ctx)
      <<~HIST
        /* per-unit log2 histogram (#{HISTOGRAM_SLOTS} buckets). */
        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __type(key, __u32);
            __type(value, __u64);
            __uint(max_entries, #{HISTOGRAM_SLOTS});
        } #{HISTOGRAM_MAP_NAME} SEC(".maps");

        /* Verifier-safe integer log2: returns floor(log2(v)) clamped to
         * [0, HISTOGRAM_SLOTS-1]. v<=0 maps to slot 0 so callers don't have
         * to guard against zero observations (it just over-reports the
         * smallest bucket). All comparisons are against compile-time
         * constants so the verifier sees a bounded computation. */
        static __noinline __s64 spnl_hist_log2(__s64 v)
        {
            __s64 r = 0;
            if (v <= 1) return 0;
            if (v >= (1LL << 32)) { v >>= 32; r += 32; }
            if (v >= (1   << 16)) { v >>= 16; r += 16; }
            if (v >= (1   << 8))  { v >>= 8;  r += 8;  }
            if (v >= (1   << 4))  { v >>= 4;  r += 4;  }
            if (v >= (1   << 2))  { v >>= 2;  r += 2;  }
            if (v >= (1   << 1))  { v >>= 1;  r += 1;  }
            if (r > #{HISTOGRAM_SLOTS - 1}) r = #{HISTOGRAM_SLOTS - 1};
            return r;
        }

        static __noinline __s64 spnl_hist_observe(__s64 v)
        {
            __u32 slot = (__u32)spnl_hist_log2(v);
            if (slot >= #{HISTOGRAM_SLOTS}) return 0;  /* verifier hand-holding */
            __u64 *cur = bpf_map_lookup_elem(&#{HISTOGRAM_MAP_NAME}, &slot);
            if (cur) __sync_fetch_and_add(cur, 1);
            return 0;
        }
      HIST
    end

    # per-unit latency entry-timestamp map. key = TID (lower 32 bits of
    # bpf_get_current_pid_tgid), value = bpf_ktime_get_ns() captured at
    # latency_start. latency_end reads/deletes and returns the delta in ns.
    # 10240 max_entries supports high concurrency; on overflow new starts
    # silently fail (BPF_ANY would have replaced an older entry — accept that).
    LATENCY_MAP_NAME = "bpf_lat_starts"
    LATENCY_MAX_ENTRIES = 10240

    def emit_latency_map_and_helper(_ctx)
      <<~LAT
        /* per-unit kprobe→kretprobe latency timing.
         * key=tid (current_pid_tgid lower 32), value=entry ktime_ns. */
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u32);
            __type(value, __u64);
            __uint(max_entries, #{LATENCY_MAX_ENTRIES});
        } #{LATENCY_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_latency_start(void)
        {
            __u32 tid = (__u32)bpf_get_current_pid_tgid();
            __u64 t   = bpf_ktime_get_ns();
            bpf_map_update_elem(&#{LATENCY_MAP_NAME}, &tid, &t, BPF_ANY);
            return 0;
        }

        static __noinline __s64 spnl_latency_end(void)
        {
            __u32 tid = (__u32)bpf_get_current_pid_tgid();
            __u64 *t0 = bpf_map_lookup_elem(&#{LATENCY_MAP_NAME}, &tid);
            if (!t0) return 0;
            __u64 delta = bpf_ktime_get_ns() - *t0;
            bpf_map_delete_elem(&#{LATENCY_MAP_NAME}, &tid);
            return (__s64)delta;
        }
      LAT
    end

    # per-task local storage (BPF_MAP_TYPE_TASK_STORAGE). Keyed
    # implicitly by the current task; the value persists across hook calls for
    # the same task and is freed automatically when the task exits. Works in
    # tracing contexts (kprobe / tracepoint / fentry / LSM / perf_event) where a
    # current task exists. bcc's BPF_TASK_STORAGE equivalent.
    #
    # IMPORTANT (verified): on this kernel, two separate
    # bpf_task_storage_get() calls in ONE program execution return DIFFERENT
    # storage objects — so task_load() followed by task_store() in the SAME
    # handler does NOT round-trip. Each op below does a SINGLE get, so use:
    #   - task_incr(delta) for per-task accumulation (counter), and
    #   - task_store / task_load in SEPARATE probes (e.g. fentry stores an entry
    #     timestamp, fexit loads it) — the classic BEGIN/END pattern.
    TASK_STORAGE_MAP_NAME = "bpf_task_store"

    def emit_task_storage_map_and_helper(_ctx)
      <<~TS
        /* per-task local storage. task_store(v) / task_load() read+write
         * a value scoped to the current task_struct (no explicit key). */
        struct {
            __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, __s64);
        } #{TASK_STORAGE_MAP_NAME} SEC(".maps");

        /* __always_inline: the PTR_TRUSTED task from bpf_get_current_task_btf()
         * must reach bpf_task_storage_get in the program's own context, not
         * across a __noinline sub-prog boundary (where it degrades and the
         * storage silently fails to persist). */
        static __always_inline __s64 spnl_task_load(void)
        {
            struct task_struct *t = bpf_get_current_task_btf();
            __s64 *v = bpf_task_storage_get(&#{TASK_STORAGE_MAP_NAME}, t, 0, 0);
            return v ? *v : 0;
        }

        static __always_inline __s64 spnl_task_store(__s64 value)
        {
            struct task_struct *t = bpf_get_current_task_btf();
            __s64 *v = bpf_task_storage_get(&#{TASK_STORAGE_MAP_NAME}, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (v) { *v = value; }
            return value;
        }

        static __always_inline __s64 spnl_task_incr(__s64 delta)
        {
            struct task_struct *t = bpf_get_current_task_btf();
            __s64 *v = bpf_task_storage_get(&#{TASK_STORAGE_MAP_NAME}, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (!v) return 0;
            *v += delta;
            return *v;
        }

        /* single-get read-modify-write — store `value`, return the prior
         * value. One bpf_task_storage_get so it stays clear of the two-get
         * aliasing quirk. */
        static __always_inline __s64 spnl_task_swap(__s64 value)
        {
            struct task_struct *t = bpf_get_current_task_btf();
            __s64 *v = bpf_task_storage_get(&#{TASK_STORAGE_MAP_NAME}, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (!v) return 0;
            __s64 old = *v;
            *v = value;
            return old;
        }
      TS
    end

    # map-in-map (BPF_MAP_TYPE_ARRAY_OF_MAPS). The outer map holds inner
    # map fds; libbpf auto-creates the inner maps and wires them into the outer
    # at load time via the `.values = { &inner... }` initializer, so no host
    # code is needed. mim_inc(g, k) / mim_get(g, k) do a 2-level lookup
    # (outer[g] -> inner, then inner[k]). bcc BPF_ARRAY_OF_MAPS equivalent.
    MIM_OUTER_MAP_NAME  = "bpf_mim_outer"
    MIM_INNER_SLOTS     = 4      # number of inner maps
    MIM_INNER_ENTRIES   = 64     # entries per inner ARRAY map

    def emit_map_in_map_maps_and_helper(_ctx)
      inners = (0...MIM_INNER_SLOTS).map { |i| "bpf_mim_inner#{i}" }
      decls  = inners.map do |nm|
        <<~INNER
          struct {
              __uint(type, BPF_MAP_TYPE_ARRAY);
              __type(key, __u32);
              __type(value, __s64);
              __uint(max_entries, #{MIM_INNER_ENTRIES});
          } #{nm} SEC(".maps");
        INNER
      end.join("\n")
      refs = inners.map { |nm| "&#{nm}" }.join(", ")
      <<~MIM
        /* map-in-map. #{MIM_INNER_SLOTS} inner ARRAY maps + an
         * ARRAY_OF_MAPS outer that libbpf populates with them at load time. */
        #{decls.rstrip}

        struct mim_inner_t {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __type(key, __u32);
            __type(value, __s64);
            __uint(max_entries, #{MIM_INNER_ENTRIES});
        };
        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
            __uint(max_entries, #{MIM_INNER_SLOTS});
            __type(key, __u32);
            __array(values, struct mim_inner_t);
        } #{MIM_OUTER_MAP_NAME} SEC(".maps") = {
            .values = { #{refs} },
        };

        static __always_inline __s64 spnl_mim_at(__s64 g, __s64 k)
        {
            __u32 gi = (__u32)g;
            void *inner = bpf_map_lookup_elem(&#{MIM_OUTER_MAP_NAME}, &gi);
            if (!inner) return 0;
            __u32 ki = (__u32)k;
            return (__s64)(unsigned long)bpf_map_lookup_elem(inner, &ki);
        }
        static __always_inline __s64 spnl_mim_inc(__s64 g, __s64 k)
        {
            __s64 *v = (__s64 *)(unsigned long)spnl_mim_at(g, k);
            if (!v) return 0;
            __sync_fetch_and_add(v, 1);
            return *v;
        }
        static __always_inline __s64 spnl_mim_get(__s64 g, __s64 k)
        {
            __s64 *v = (__s64 *)(unsigned long)spnl_mim_at(g, k);
            return v ? *v : 0;
        }
      MIM
    end

    # QUEUE (FIFO) / STACK (LIFO) maps. Keyless value containers with
    # bpf_map_push_elem / pop_elem. fifo_* uses the QUEUE map (oldest out first),
    # lifo_* uses the STACK map (newest out first). bcc BPF_QUEUE / BPF_STACK.
    QUEUE_MAP_NAME    = "bpf_fifo"
    STACK_MAP_NAME    = "bpf_lifo"
    QUEUE_STACK_DEPTH = 1024

    def emit_queue_stack_maps_and_helper(ctx)
      parts = []
      if ctx.uses_fifo
        parts << <<~FIFO
          /* QUEUE (FIFO) map. fifo_push(v) / fifo_pop(). */
          struct {
              __uint(type, BPF_MAP_TYPE_QUEUE);
              __uint(max_entries, #{QUEUE_STACK_DEPTH});
              __type(value, __s64);
          } #{QUEUE_MAP_NAME} SEC(".maps");

          static __always_inline __s64 spnl_fifo_push(__s64 v)
          {
              return (__s64)bpf_map_push_elem(&#{QUEUE_MAP_NAME}, &v, BPF_ANY);
          }
          static __always_inline __s64 spnl_fifo_pop(void)
          {
              __s64 v = 0;
              return bpf_map_pop_elem(&#{QUEUE_MAP_NAME}, &v) == 0 ? v : 0;
          }
        FIFO
      end
      if ctx.uses_lifo
        parts << <<~LIFO
          /* STACK (LIFO) map. lifo_push(v) / lifo_pop(). */
          struct {
              __uint(type, BPF_MAP_TYPE_STACK);
              __uint(max_entries, #{QUEUE_STACK_DEPTH});
              __type(value, __s64);
          } #{STACK_MAP_NAME} SEC(".maps");

          static __always_inline __s64 spnl_lifo_push(__s64 v)
          {
              return (__s64)bpf_map_push_elem(&#{STACK_MAP_NAME}, &v, BPF_ANY);
          }
          static __always_inline __s64 spnl_lifo_pop(void)
          {
              __s64 v = 0;
              return bpf_map_pop_elem(&#{STACK_MAP_NAME}, &v) == 0 ? v : 0;
          }
        LIFO
      end
      parts.join("\n")
    end

    # keyed log2 histogram. One struct per key, 64 buckets per struct.
    # bcc's `BPF_HISTOGRAM(name, key_t)` equivalent. Up to 1024 distinct keys
    # per unit (tunable). Re-uses spnl_hist_log2 from the log2 histogram, so the unit must
    # also set uses_histogram.
    HISTOGRAM_KEYED_MAP_NAME = "bpf_hist_keyed"
    HISTOGRAM_KEYED_MAX_KEYS = 1024

    def emit_histogram_keyed_map_and_helper(_ctx)
      <<~HISTK
        /* keyed log2 histogram (#{HISTOGRAM_KEYED_MAX_KEYS} keys * #{HISTOGRAM_SLOTS} slots).
         * The value struct is #{HISTOGRAM_SLOTS * 8} bytes — too large to put on the BPF
         * stack (512B limit). We stash a pre-zeroed template in a per-CPU
         * ARRAY of size 1 and use it for new-key initialization. */
        struct spnl_hist_struct { __u64 buckets[#{HISTOGRAM_SLOTS}]; };

        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u64);
            __type(value, struct spnl_hist_struct);
            __uint(max_entries, #{HISTOGRAM_KEYED_MAX_KEYS});
        } #{HISTOGRAM_KEYED_MAP_NAME} SEC(".maps");

        struct {
            __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
            __type(key, __u32);
            __type(value, struct spnl_hist_struct);
            __uint(max_entries, 1);
        } #{HISTOGRAM_KEYED_MAP_NAME}_zero SEC(".maps");

        static __noinline __s64 spnl_hist_observe_by(__s64 key, __s64 v)
        {
            __u64 k = (__u64)key;
            struct spnl_hist_struct *cur = bpf_map_lookup_elem(&#{HISTOGRAM_KEYED_MAP_NAME}, &k);
            if (!cur) {
                __u32 zk = 0;
                struct spnl_hist_struct *zero =
                    bpf_map_lookup_elem(&#{HISTOGRAM_KEYED_MAP_NAME}_zero, &zk);
                if (!zero) return 0;
                bpf_map_update_elem(&#{HISTOGRAM_KEYED_MAP_NAME}, &k, zero, BPF_NOEXIST);
                cur = bpf_map_lookup_elem(&#{HISTOGRAM_KEYED_MAP_NAME}, &k);
                if (!cur) return 0;
            }
            __u32 slot = (__u32)spnl_hist_log2(v);
            if (slot >= #{HISTOGRAM_SLOTS}) return 0;
            __sync_fetch_and_add(&cur->buckets[slot], 1);
            return 0;
        }
      HISTK
    end

    # linear histogram. Caller supplies a pre-bucketed slot directly
    # (no log2). Useful when buckets are domain-specific (e.g., ms granularity:
    # divide the value by 1_000_000 in Ruby, pass slot). Max slots 256 keeps
    # the ARRAY map small; OOB values clamp to the last slot.
    HISTOGRAM_LINEAR_MAP_NAME = "bpf_hist_lin"
    HISTOGRAM_LINEAR_SLOTS    = 256

    def emit_histogram_linear_map_and_helper(_ctx)
      <<~HISTL
        /* linear histogram (#{HISTOGRAM_LINEAR_SLOTS} caller-bucketed slots). */
        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __type(key, __u32);
            __type(value, __u64);
            __uint(max_entries, #{HISTOGRAM_LINEAR_SLOTS});
        } #{HISTOGRAM_LINEAR_MAP_NAME} SEC(".maps");

        static __noinline __s64 spnl_hist_observe_linear(__s64 slot_arg)
        {
            if (slot_arg < 0) return 0;
            __u32 slot = (__u32)slot_arg;
            if (slot >= #{HISTOGRAM_LINEAR_SLOTS}) slot = #{HISTOGRAM_LINEAR_SLOTS - 1};
            __u64 *cur = bpf_map_lookup_elem(&#{HISTOGRAM_LINEAR_MAP_NAME}, &slot);
            if (cur) __sync_fetch_and_add(cur, 1);
            return 0;
        }
      HISTL
    end

    # per-unit BPF_MAP_TYPE_STACK_TRACE for stack_id() / user_stack_id().
    # PERF_MAX_STACK_DEPTH = 127 is the kernel-default cap; each entry is a
    # __u64 array of that many PCs. 16384 max_entries (~16M when full) is
    # the bcc convention. Host symbolicates via /proc/kallsyms (kernel)
    # or /proc/<pid>/maps + ELF (user — userspace responsibility for MVP).
    STACK_TRACE_MAP_NAME    = "bpf_stacks"
    STACK_TRACE_MAX_ENTRIES = 16384
    PERF_MAX_STACK_DEPTH    = 127

    def emit_stack_trace_map(_ctx)
      <<~ST
        /* per-unit stack-trace map (#{STACK_TRACE_MAX_ENTRIES} unique stacks * #{PERF_MAX_STACK_DEPTH} frames each).
         * stack_id() returns the kernel stack id, user_stack_id() returns the
         * userspace one. Host code reads the map by stack id to get the PCs. */
        struct {
            __uint(type, BPF_MAP_TYPE_STACK_TRACE);
            __uint(key_size, sizeof(__u32));
            __uint(value_size, #{PERF_MAX_STACK_DEPTH} * sizeof(__u64));
            __uint(max_entries, #{STACK_TRACE_MAX_ENTRIES});
        } #{STACK_TRACE_MAP_NAME} SEC(".maps");
      ST
    end

    # off-CPU tracking. key = pid (lower 32 of bpf_get_current_pid_tgid),
    # value = (entry timestamp, captured kernel stack id). Used together with
    # bpf_hist_keyed (keyed histogram) + bpf_stacks (stack trace) — when a task comes back
    # on-CPU we look up its entry, compute delta ns, and bin
    # hist_observe_by(stack_id, delta) so the keyed-hist row for that stack
    # accumulates total off-CPU time. Map name ≤ 15 chars.
    OFF_CPU_MAP_NAME    = "bpf_off_cpu"
    OFF_CPU_MAX_ENTRIES = 10240

    def emit_off_cpu_map_and_helper(_ctx)
      <<~OC
        /* per-unit off-CPU tracking (ts + stack id per pid).
         * off_cpu_start(pid) records when a task goes off-CPU; off_cpu_observe(pid)
         * fires when it comes back, bins (stack_id -> total off-CPU ns) via
         * the keyed hist. */
        struct spnl_off_cpu_entry {
            __u64 ts;
            __u32 stack_id;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __type(key, __u32);
            __type(value, struct spnl_off_cpu_entry);
            __uint(max_entries, #{OFF_CPU_MAX_ENTRIES});
        } #{OFF_CPU_MAP_NAME} SEC(".maps");

        /* off_cpu_start: capture (ktime_ns, stack_id) for the going-off task.
         * ctx must be the program's bpf_get_stackid-compatible context. */
        static __noinline __s64 spnl_off_cpu_start(__u32 pid, void *ctx)
        {
            struct spnl_off_cpu_entry e;
            e.ts       = bpf_ktime_get_ns();
            e.stack_id = (__u32)bpf_get_stackid(ctx, &#{STACK_TRACE_MAP_NAME}, 0);
            bpf_map_update_elem(&#{OFF_CPU_MAP_NAME}, &pid, &e, BPF_ANY);
            return 0;
        }

        /* off_cpu_observe: if pid has a stored entry, compute delta = now - ts,
         * bin into the keyed log2 hist under key=stack_id, then drop the
         * entry. Returns delta ns (or 0 if no entry). */
        static __noinline __s64 spnl_off_cpu_observe(__u32 pid)
        {
            struct spnl_off_cpu_entry *e =
                bpf_map_lookup_elem(&#{OFF_CPU_MAP_NAME}, &pid);
            if (!e) return 0;
            __u64 delta    = bpf_ktime_get_ns() - e->ts;
            __u32 stack_id = e->stack_id;
            bpf_map_delete_elem(&#{OFF_CPU_MAP_NAME}, &pid);

            /* Inline hist_observe_by(stack_id, delta) — keyed log2 hist. */
            __u64 k = (__u64)stack_id;
            struct spnl_hist_struct *cur =
                bpf_map_lookup_elem(&#{HISTOGRAM_KEYED_MAP_NAME}, &k);
            if (!cur) {
                __u32 zk = 0;
                struct spnl_hist_struct *zero =
                    bpf_map_lookup_elem(&#{HISTOGRAM_KEYED_MAP_NAME}_zero, &zk);
                if (!zero) return (__s64)delta;
                bpf_map_update_elem(&#{HISTOGRAM_KEYED_MAP_NAME}, &k, zero, BPF_NOEXIST);
                cur = bpf_map_lookup_elem(&#{HISTOGRAM_KEYED_MAP_NAME}, &k);
                if (!cur) return (__s64)delta;
            }
            __u32 slot = (__u32)spnl_hist_log2((__s64)delta);
            if (slot >= #{HISTOGRAM_SLOTS}) return (__s64)delta;
            __sync_fetch_and_add(&cur->buckets[slot], 1);
            return (__s64)delta;
        }
      OC
    end

    # SO_REUSEPORT worker sockarray. Each entry holds a listening socket
    # from a worker process (userspace populates via bpf_map_update_elem with
    # the socket fd). The sk_reuseport program uses bpf_sk_select_reuseport
    # to pick which entry handles an incoming SYN — consistent hashing on
    # ctx->hash is the typical lookup. Map name fits the 15-char cap.
    REUSEPORT_SOCKARRAY_NAME = "bpf_worker_socks"
    REUSEPORT_SOCKARRAY_MAX  = 64

    def emit_reuseport_sockarray_map(ctx)
      <<~SR
        /* SO_REUSEPORT worker sockarray. Populated from userspace via
         * sp_bpf_reuseport_register(listen_fd, idx). The sk_reuseport program
         * calls bpf_sk_select_reuseport(ctx, &this_map, &idx, 0) to pick a
         * worker socket; if the slot is empty, kernel falls back to its
         * default 5-tuple distribution. */
        struct {
            __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
            __type(key, __u32);
            __type(value, __u64);
            __uint(max_entries, #{REUSEPORT_SOCKARRAY_MAX});
        } #{REUSEPORT_SOCKARRAY_NAME} SEC(".maps");
      SR
    end

    # fast-path constants. The request prefix is 12 bytes (no path
    # variability) so we can unroll the byte-by-byte compare; the response is
    # fixed at 41 bytes (HTTP/1.0 200 OK + Content-Length: 3 + body "OK\n").
    HEALTH_REQUEST_PREFIX  = "GET /health "
    HEALTH_RESPONSE_BODY   = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n"

    # Partial TCP-checksum contribution of the response payload, computed at
    # codegen time so the BPF program can just += a constant instead of
    # looping over packet bytes. Reads as host-order u16 + trailing odd byte
    # to match how the kernel-side helper would have summed memory:
    #   each u16 word = bytes[i] | (bytes[i+1] << 8)
    #   trailing byte (if length is odd) added as a raw __u16 byte value.
    HEALTH_RESPONSE_CSUM_PARTIAL = begin
      bytes = HEALTH_RESPONSE_BODY.bytes
      sum = 0
      i = 0
      while i + 1 < bytes.length
        sum += bytes[i] | (bytes[i + 1] << 8)
        i += 2
      end
      sum += bytes[bytes.length - 1] if bytes.length.odd?
      sum
    end

    def emit_xdp_health_match_helper(_ctx)
      compares = HEALTH_REQUEST_PREFIX.each_char.each_with_index.map do |c, i|
        "if (payload[#{i}] != '#{c == "\\" ? '\\\\' : c == "'" ? "\\'" : c}') return 0;"
      end.join("\n            ")
      <<~MATCH
        /* returns 1 iff the XDP frame is IPv4/TCP with a payload starting
         * with "GET /health ". Verifier-safe bounds checks at every header step. */
        static __noinline __s64 spnl_xdp_match_health(struct xdp_md *ctx)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;

            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return 0;
            if (eth->h_proto != bpf_htons(0x0800)) return 0;     /* ETH_P_IP */

            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return 0;
            if (iph->protocol != 6) return 0;                    /* IPPROTO_TCP */
            __u32 ihl = iph->ihl * 4;
            if (ihl < sizeof(*iph)) return 0;

            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + ihl);
            if ((void *)(tcp + 1) > data_end) return 0;
            __u32 thl = tcp->doff * 4;
            if (thl < sizeof(*tcp)) return 0;

            char *payload = (char *)tcp + thl;
            if (payload + #{HEALTH_REQUEST_PREFIX.length} > (char *)data_end) return 0;

            #{compares}
            return 1;
        }
      MATCH
    end

    def emit_xdp_health_reply_helper(_ctx)
      response_len = HEALTH_RESPONSE_BODY.length
      # Emit body as a brace-enclosed initializer of unsigned char (bytes), since
      # we'll memcpy this into the payload region.
      body_init = HEALTH_RESPONSE_BODY.bytes.map { |b| sprintf("0x%02x", b) }.each_slice(8).map { |s| s.join(", ") }.join(",\n                ")
      <<~REPLY
        /* hand-craft a 200 OK response packet in place and return XDP_TX.
         * Returns XDP_PASS on any error so kernel falls back to the userspace path.
         * Designed for /health (41-byte response) — fits within MSS without splitting. */
        static __noinline __s64 spnl_xdp_reply_health(struct xdp_md *ctx)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;

            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return 2;          /* XDP_PASS */
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return 2;
            __u32 ihl = iph->ihl * 4;
            if (ihl < sizeof(*iph)) return 2;
            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + ihl);
            if ((void *)(tcp + 1) > data_end) return 2;
            __u32 thl = tcp->doff * 4;
            if (thl < sizeof(*tcp)) return 2;

            __u32 incoming_ip_tot = bpf_ntohs(iph->tot_len);
            if (incoming_ip_tot < ihl + thl) return 2;
            __u32 incoming_payload_len = incoming_ip_tot - ihl - thl;
            __u32 response_len = #{response_len};

            /* Swap MAC addresses */
            __u8 mac_tmp[6];
            __builtin_memcpy(mac_tmp, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, mac_tmp, 6);

            /* Swap IPv4 addresses */
            __u32 ip_tmp = iph->saddr;
            iph->saddr = iph->daddr;
            iph->daddr = ip_tmp;

            /* Swap TCP ports */
            __u16 port_tmp = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest   = port_tmp;

            /* Compute new SEQ/ACK: ack the request, advance seq by ack we had */
            __u32 incoming_seq = bpf_ntohl(tcp->seq);
            __u32 incoming_ack = bpf_ntohl(tcp->ack_seq);
            tcp->seq     = bpf_htonl(incoming_ack);
            tcp->ack_seq = bpf_htonl(incoming_seq + incoming_payload_len);

            /* Flags: ACK + PSH + FIN so client transitions to CLOSE_WAIT */
            tcp->ack = 1;
            tcp->psh = 1;
            tcp->fin = 1;
            tcp->syn = 0;
            tcp->rst = 0;
            tcp->urg = 0;

            /* Adjust packet tail to match response_len */
            int tail_delta = (int)response_len - (int)incoming_payload_len;
            if (bpf_xdp_adjust_tail(ctx, tail_delta) != 0) return 2;

            /* Re-acquire pointers (adjust_tail invalidates them) */
            data     = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) return 2;
            iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return 2;
            tcp = (struct tcphdr *)((char *)iph + ihl);
            if ((void *)(tcp + 1) > data_end) return 2;
            char *payload = (char *)tcp + thl;
            if (payload + response_len > (char *)data_end) return 2;

            /* Write the 41-byte response body */
            static const unsigned char body[#{response_len}] = {
                #{body_init}
            };
            __builtin_memcpy(payload, body, #{response_len});

            /* Update IP total length */
            iph->tot_len = bpf_htons(ihl + thl + response_len);

            /* Recompute IPv4 header checksum */
            iph->check = 0;
            __u32 ip_csum = 0;
            __u16 *ip_words = (__u16 *)iph;
            #pragma clang loop unroll(full)
            for (int i = 0; i < (int)(sizeof(struct iphdr) / 2); i++) {
                ip_csum += ip_words[i];
            }
            while (ip_csum >> 16) ip_csum = (ip_csum & 0xffff) + (ip_csum >> 16);
            iph->check = (__u16)~ip_csum;

            /* Recompute TCP checksum: pseudo header + TCP header + payload */
            tcp->check = 0;
            __u32 tcp_csum = 0;
            __u16 *sa = (__u16 *)&iph->saddr;
            __u16 *da = (__u16 *)&iph->daddr;
            tcp_csum += sa[0]; tcp_csum += sa[1];
            tcp_csum += da[0]; tcp_csum += da[1];
            tcp_csum += bpf_htons(6);                            /* IPPROTO_TCP */
            tcp_csum += bpf_htons(thl + response_len);

            /* Support TCP headers with options. Linux loopback always
             * carries the TS option (thl=32). A plain `thl != 20` check would
             * silently return XDP_PASS for almost every real packet, which is
             * the dominant cause of the static-response reliability ceiling.
             * Accept thl in {20, 32}; for thl=32 the verifier needs a fresh
             * bounds check that establishes accessible-prefix length, not just
             * `pointer < data_end`. */
            if (thl != 20 && thl != 32) return 2;
            __u16 *tcp_words = (__u16 *)tcp;
            tcp_csum += tcp_words[0]; tcp_csum += tcp_words[1];
            tcp_csum += tcp_words[2]; tcp_csum += tcp_words[3];
            tcp_csum += tcp_words[4]; tcp_csum += tcp_words[5];
            tcp_csum += tcp_words[6]; tcp_csum += tcp_words[7];
            tcp_csum += tcp_words[8]; tcp_csum += tcp_words[9];
            if (thl == 32) {
                /* Fresh, constant-sized bounds check so the verifier learns
                 * "32 bytes from tcp are accessible". Pointer-plus-thl checks
                 * only constrain the comparison value, not the readable range. */
                if ((char *)tcp + 32 > (char *)data_end) return 2;
                __u16 *opts = (__u16 *)((char *)tcp + 20);
                tcp_csum += opts[0]; tcp_csum += opts[1];
                tcp_csum += opts[2]; tcp_csum += opts[3];
                tcp_csum += opts[4]; tcp_csum += opts[5];
            }

            /* Payload checksum is fixed (we just wrote a constant body), so
             * use a codegen-time precomputed partial sum instead of looping
             * over packet bytes — the verifier rejects pointer arithmetic on
             * the in-packet u16 pointer. */
            tcp_csum += 0x#{HEALTH_RESPONSE_CSUM_PARTIAL.to_s(16)}; /* precomputed payload partial csum (#{HEALTH_RESPONSE_BODY.length} bytes) */
            while (tcp_csum >> 16) tcp_csum = (tcp_csum & 0xffff) + (tcp_csum >> 16);
            tcp->check = (__u16)~tcp_csum;

            return 3;   /* XDP_TX */
        }
      REPLY
    end

    # emit the full pure-XDP TCP slice — maps (bpf_conntab + counters),
    # all helpers (csum/swap_mac/build_*), and the state machine entry
    # `spnl_tcp_slice_main(ctx)`. The per-method wrapper (emitted from
    # emit_method when attach kind is :xdp_tcp_slice) is a thin SEC("xdp")
    # function that just tail-calls this entry.
    #
    # Currently hardcoded to port 8080 and the `/health` endpoint. Future
    # Future work will lift this into Ruby-DSL-configurable form.
    TCP_SLICE_PORT          = 8080
    TCP_SLICE_REQUEST_MATCH = "GET /health "
    TCP_SLICE_RESPONSE      = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n"

    # kernel_cache responses live in a BPF map (bpf_kc_resp),
    # populated by userspace (literal bodies at startup, runtime bodies via the
    # sp_kc_set glue). The wire response is always this many bytes (the body is
    # zero-padded; the client reads only Content-Length), which keeps every
    # length in the TCP state machine a compile-time constant = verifier-simple.
    KERNEL_CACHE_RESP_CAP   = 256

    def emit_tcp_slice_bundle(ctx)
      # when `kernel_cache "/path","body"` declarations exist, serve the
      # first one from the slice (single-route MVP). Otherwise keep the
      # /health defaults so existing xdp__tcp_slice__ programs are byte-identical.
      # kernel_cache turns this slice into a multi-route cache —
      # each declared path is a slot (declaration order) served from bpf_kc_resp.
      # With no declaration the slice keeps the /health default.
      kc_decls       = ctx && ctx.ast ? KernelCache.declarations(ctx.ast) : []
      kc_entry       = kc_decls.first
      port           = TCP_SLICE_PORT
      default_path   = TCP_SLICE_REQUEST_MATCH[/\AGET (.*) \z/, 1]
      route_paths    = kc_decls.empty? ? [default_path] : kc_decls.map(&:path)
      n_routes       = route_paths.length
      match_str      = "GET #{route_paths.first} "   # for the bundle header comment
      esc_c          = ->(c) { c == "\\" ? '\\\\' : c == "'" ? "\\'" : c }
      # match_route(): return the slot whose "GET <path> " prefix matches, else -1.
      match_routes_code = route_paths.each_with_index.map do |rp, slot|
        m = "GET #{rp} "
        conds = m.each_char.each_with_index.map { |c, i| "p[#{i}] == '#{esc_c.call(c)}'" }.join(" && ")
        "if (len >= #{m.length} && (void *)(p + #{m.length}) <= data_end &&\n                #{conds}) return #{slot};"
      end.join("\n            ")
      # kernel_cache => response served from the bpf_kc_resp map
      # (runtime-populated, fixed CAP on the wire). Hand-written xdp__tcp_slice__
      # (no declaration) keeps the compile-time const-array path (byte-identical).
      response       = TCP_SLICE_RESPONSE
      resp_len       = kc_entry ? KERNEL_CACHE_RESP_CAP : response.length
      resp_init      = response.bytes.map { |b| sprintf("0x%02x", b) }.each_slice(8).map { |s| s.join(", ") }.join(",\n            ")
      resp_decl =
        if kc_entry
          <<~MAP.chomp
            /* kernel_cache response cache (#{n_routes} route slot(s)). userspace
             * populates each slot with the full HTTP response, zero-padded to
             * #{resp_len} bytes (sp_kc_set glue). The wire response is always #{resp_len}
             * bytes; the client reads only Content-Length, so the padding is ignored. */
            struct spnl_kc_resp { __u8 bytes[#{resp_len}]; };
            struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, __u32);
                __type(value, struct spnl_kc_resp);
                __uint(max_entries, #{n_routes});
            } bpf_kc_resp SEC(".maps");
            /* per-slot actual response length + precomputed payload checksum
             * (sp_kc_set sets both). The slice sizes the wire frame to 54+len (a
             * SHRINK for real clients, so native XDP_TX works on NICs like nxp_enetc4
             * that drop adjust_tail-GROWN frames), and checksums the variable-length
             * payload via this precomputed partial sum + a FIXED 20-byte header
             * bpf_csum_diff — avoiding a variable-length bpf_csum_diff (which the
             * verifier rejects after a variable adjust_tail). 0/unset => CAP fallback. */
            struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, __u32);
                __type(value, __u32);
                __uint(max_entries, #{n_routes});
            } bpf_kc_resp_len SEC(".maps");
            struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, __u32);
                __type(value, __u32);
                __uint(max_entries, #{n_routes});
            } bpf_kc_resp_csum SEC(".maps");
          MAP
        else
          "static const __u8 spnl_tcp_slice_resp_body[#{resp_len}] = {\n            #{resp_init}\n        };"
        end
      resp_copy =
        if kc_entry
          # copy exactly rlen bytes (runtime, <= CAP). Bounded loop is
          # verifier-safe: _i < CAP bounds the map read, out+_i+1>data_end bounds
          # the packet write. (Was a fixed CAP memcpy that always grew the frame.)
          "__u32 _kcz = (kc_slot >= 0) ? (__u32)kc_slot : 0;\n" \
          "            struct spnl_kc_resp *_kc = bpf_map_lookup_elem(&bpf_kc_resp, &_kcz);\n" \
          "            if (!_kc) return -1;\n" \
          "            for (__u32 _i = 0; _i < #{resp_len}; _i++) {\n" \
          "                if (_i >= rlen) break;\n" \
          "                if ((void *)(out + _i + 1) > data_end) break;\n" \
          "                out[_i] = _kc->bytes[_i];\n" \
          "            }"
        else
          "(void)kc_slot;\n            __builtin_memcpy(out, spnl_tcp_slice_resp_body, #{resp_len});"
        end
      # a CAP-sized cache response usually exceeds the request
      # payload, so the frame must be grown BEFORE build_response writes into it
      # (the /health response fit in-place over the GET payload; a cache response won't).
      # Mirrors the SYN path: adjust_tail then re-fetch+revalidate eth/iph/tcp.
      # Seqs are computed from the original packet just above, so this is safe.
      pregrow =
        if kc_entry
          <<-PG.chomp
{
                        int _c0 = (long)data_end - (long)data;
                        int _w0 = sizeof(*eth) + 20 + 20 + (int)_rlen;
                        if (_c0 != _w0 && bpf_xdp_adjust_tail(ctx, _w0 - _c0) != 0) {
                            spnl_tcp_slice_inc(12); return XDP_ABORTED;
                        }
                        data = (void *)(long)ctx->data; data_end = (void *)(long)ctx->data_end;
                        eth = data; if ((void *)(eth + 1) > data_end) return XDP_ABORTED;
                        iph = (void *)(eth + 1); if ((void *)iph + 20 > data_end) return XDP_ABORTED;
                        /* re-derive tcp at the FIXED offset iph+20 (response has
                         * ihl=5; real requests carry no IP options) so later fixed-size
                         * accesses sit at a constant offset for the verifier. */
                        tcp = (void *)iph + 20;
                        if ((void *)tcp + 20 > data_end) return XDP_ABORTED;
                    }
PG
        else
          ""
        end
      # response-length expr in the data path (runtime _rlen for kernel_cache,
      # compile-time const otherwise) + build_response plumbing for the runtime len.
      rl          = kc_entry ? "_rlen" : resp_len.to_s
      br_extra    = kc_entry ? ", __u32 rlen" : ""
      brl         = kc_entry ? "rlen" : resp_len.to_s
      br_clamp    = kc_entry ? "if (rlen > #{resp_len}) return -1;\n            " : ""
      br_call_arg = kc_entry ? ", _rlen" : ""
      csum_call   = kc_entry ?
        "spnl_tcp_slice_recompute_csums_pc(iph, tcp, _rlen, _pc, data_end)" :
        "spnl_tcp_slice_recompute_csums(iph, tcp, 20 + #{resp_len}, data_end)"
      # Runtime length + precomputed payload csum lookups (injected into the data path).
      rlen_lookup =
        if kc_entry
          "__u32 _lz = (kc_slot >= 0) ? (__u32)kc_slot : 0;\n" \
          "                    __u32 *_lp = bpf_map_lookup_elem(&bpf_kc_resp_len, &_lz);\n" \
          "                    __u32 _rlen = (_lp && *_lp > 0 && *_lp <= #{resp_len}) ? *_lp : #{resp_len};\n" \
          "                    __u32 *_pcp = bpf_map_lookup_elem(&bpf_kc_resp_csum, &_lz);\n" \
          "                    __u32 _pc = _pcp ? *_pcp : 0;"
        else
          ""
        end
      # TCP/IP csum for a variable-length payload WITHOUT a variable-length
      # bpf_csum_diff (the verifier rejects that after a variable adjust_tail): the
      # fixed 20-byte TCP header is csum'd with the userspace-precomputed payload
      # partial sum as the seed; payload_len only feeds the pseudo-header length
      # (pure arithmetic). All packet reads are fixed-size => verifier-safe.
      csum_pc_fn =
        if kc_entry
          <<-PCFN.chomp

        static __always_inline int spnl_tcp_slice_recompute_csums_pc(struct iphdr *iph,
                                                                     struct tcphdr *tcp,
                                                                     __u32 payload_len,
                                                                     __u32 payload_csum,
                                                                     void *data_end)
        {
            __s64 v;
            iph->check = 0;
            v = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
            if (v < 0) return -1;
            iph->check = spnl_tcp_slice_csum_fold((__u32)v);
            tcp->check = 0;
            if ((void *)tcp + 20 > data_end) return -1;
            v = bpf_csum_diff(0, 0, (void *)tcp, 20, payload_csum);
            if (v < 0) return -1;
            tcp->check = spnl_tcp_slice_csum_tcpudp(iph->saddr, iph->daddr, 20 + payload_len, 6, (__u32)v);
            return 0;
        }
PCFN
        else
          ""
        end
      <<~SLICE
        /* === pure-XDP TCP slice (port #{port}, prefix #{match_str.inspect}) === */
        /* === + bpf_timer state cleanup + client-retransmit handling      === */

        /* conn_state stored per 4-tuple. state: 1=ESTAB, 2=RESP_SENT, 3=CLOSED.
         * bpf_timer embedded for per-state TTL cleanup. */
        struct spnl_tcp_slice_key {
            __be32 saddr;
            __be32 daddr;
            __be16 sport;
            __be16 dport;
        };

        struct spnl_tcp_slice_state {
            __u32 server_seq;
            __u32 client_seq;
            __u16 mss;
            __u8  state;
            __u8  pad;
            struct bpf_timer timer;   /* per-conn cleanup timer */
        };

        struct {
            __uint(type, BPF_MAP_TYPE_LRU_HASH);
            __type(key, struct spnl_tcp_slice_key);
            __type(value, struct spnl_tcp_slice_state);
            __uint(max_entries, 65536);
        } bpf_conntab SEC(".maps");

        /* Observability counters. */
        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __type(key, __u32);
            __type(value, __u64);
            __uint(max_entries, 17);
        } bpf_ts_counters SEC(".maps");

        /* per-state TTL (nanoseconds). Once the timer fires, the
         * map entry is deleted by spnl_tcp_slice_timeout_cb. State
         * transitions re-arm the timer with the new state's TTL. */
        #define SPNL_TS_NS_PER_SEC 1000000000ULL
        #define SPNL_TS_TTL_ESTAB  ( 30ULL * SPNL_TS_NS_PER_SEC)
        #define SPNL_TS_TTL_RESP   ( 30ULL * SPNL_TS_NS_PER_SEC)
        #define SPNL_TS_TTL_CLOSED ( 60ULL * SPNL_TS_NS_PER_SEC)

        static __always_inline void spnl_tcp_slice_inc(int k)
        {
            __u32 key = k;
            __u64 *v = bpf_map_lookup_elem(&bpf_ts_counters, &key);
            if (v) __sync_fetch_and_add(v, 1);
        }

        static __always_inline __u16 spnl_tcp_slice_csum_fold(__u32 csum)
        {
            csum = (csum & 0xffff) + (csum >> 16);
            csum = (csum & 0xffff) + (csum >> 16);
            return ~csum;
        }

        static __always_inline __u16 spnl_tcp_slice_csum_tcpudp(__be32 saddr, __be32 daddr,
                                                                __u32 len, __u8 proto, __u32 csum)
        {
            __u64 s = csum;
            s += (__u32)saddr;
            s += (__u32)daddr;
            s += bpf_htons(proto + len);
            while (s >> 32) s = (s & 0xffffffff) + (s >> 32);
            return spnl_tcp_slice_csum_fold((__u32)s);
        }

        static __always_inline int spnl_tcp_slice_recompute_csums(struct iphdr *iph,
                                                                  struct tcphdr *tcp,
                                                                  __u32 seglen, void *data_end)
        {
            __s64 v;
            iph->check = 0;
            v = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
            if (v < 0) return -1;
            iph->check = spnl_tcp_slice_csum_fold((__u32)v);
            tcp->check = 0;
            if ((void *)tcp + seglen > data_end) return -1;
            v = bpf_csum_diff(0, 0, (void *)tcp, seglen, 0);
            if (v < 0) return -1;
            tcp->check = spnl_tcp_slice_csum_tcpudp(iph->saddr, iph->daddr, seglen, 6, (__u32)v);
            return 0;
        }
#{csum_pc_fn}
        static __always_inline void spnl_tcp_slice_swap_mac(struct ethhdr *eth)
        {
            __u8 buf[6];
            __builtin_memcpy(buf, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, buf, 6);
        }

        /* bpf_timer callback. Fires when a conn_state has been idle
         * for its state-specific TTL; deletes the entry so the LRU slot can
         * be reused by a fresh connection. (The verifier requires the
         * callback signature to match: (void *map, key*, value*).) */
        static int spnl_tcp_slice_timeout_cb(void *map,
                                             struct spnl_tcp_slice_key *key,
                                             struct spnl_tcp_slice_state *val)
        {
            __u32 ck = 15; /* CNT_TIMER_FIRED */
            __u64 *v = bpf_map_lookup_elem(&bpf_ts_counters, &ck);
            if (v) __sync_fetch_and_add(v, 1);
            bpf_map_delete_elem(map, key);
            return 0;
        }

        /* (Re-)arm the per-conn cleanup timer. bpf_timer_init is idempotent
         * (-EEXIST on second call) so we always call it; the verifier then
         * lets us set_callback + start. Calling start on an already-armed
         * timer replaces the timeout, which is exactly what we want on each
         * state transition. */
        static __always_inline void spnl_tcp_slice_arm(struct spnl_tcp_slice_state *st,
                                                       __u64 ttl_ns)
        {
            bpf_timer_init(&st->timer, &bpf_conntab, 1 /* CLOCK_MONOTONIC */);
            bpf_timer_set_callback(&st->timer, spnl_tcp_slice_timeout_cb);
            bpf_timer_start(&st->timer, ttl_ns, 0);
        }

        static __always_inline int spnl_tcp_slice_build_synack(struct ethhdr *eth,
                                                               struct iphdr *iph,
                                                               struct tcphdr *tcp,
                                                               __u32 cookie, __u16 mss,
                                                               void *data_end)
        {
            spnl_tcp_slice_swap_mac(eth);
            __be32 t = iph->saddr; iph->saddr = iph->daddr; iph->daddr = t;
            __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;
            __u32 client_seq = bpf_ntohl(tcp->seq);
            tcp->ack_seq = bpf_htonl(client_seq + 1);
            tcp->seq = bpf_htonl(cookie);
            tcp->fin = 0; tcp->syn = 1; tcp->rst = 0;
            tcp->psh = 0; tcp->ack = 1; tcp->urg = 0;
            tcp->ece = 0; tcp->cwr = 0;
            tcp->doff = 6;
            tcp->window = bpf_htons(65535);
            tcp->urg_ptr = 0;
            __u8 *o = (void *)tcp + 20;
            if ((void *)(o + 4) > data_end) return -1;
            o[0] = 2;          /* TCPOPT_MSS */
            o[1] = 4;          /* TCPOLEN_MSS */
            o[2] = (mss >> 8) & 0xff;
            o[3] = mss & 0xff;
            return 0;
        }

        #{resp_decl}

        static __always_inline int spnl_tcp_slice_build_response(struct ethhdr *eth,
                                                                 struct iphdr *iph,
                                                                 struct tcphdr *tcp,
                                                                 __u32 srv_seq, __u32 cli_seq,
                                                                 int kc_slot#{br_extra}, void *data_end)
        {
            spnl_tcp_slice_swap_mac(eth);
            __be32 t = iph->saddr; iph->saddr = iph->daddr; iph->daddr = t;
            __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;
            tcp->seq = bpf_htonl(srv_seq);
            tcp->ack_seq = bpf_htonl(cli_seq);
            tcp->fin = 1; tcp->syn = 0; tcp->rst = 0;
            tcp->psh = 1; tcp->ack = 1; tcp->urg = 0;
            tcp->ece = 0; tcp->cwr = 0;
            tcp->doff = 5;
            tcp->window = bpf_htons(65535);
            tcp->urg_ptr = 0;
            __u8 *out = (void *)tcp + 20;
            #{br_clamp}if ((void *)(out + #{brl}) > data_end) return -1;
            #{resp_copy}
            iph->ihl = 5;
            iph->tot_len = bpf_htons(20 + 20 + #{brl});
            iph->ttl = 64;
            iph->id = 0;
            return 0;
        }

        static __always_inline int spnl_tcp_slice_build_finack(struct ethhdr *eth,
                                                               struct iphdr *iph,
                                                               struct tcphdr *tcp,
                                                               __u32 srv_seq, __u32 cli_seq,
                                                               void *data_end)
        {
            spnl_tcp_slice_swap_mac(eth);
            __be32 t = iph->saddr; iph->saddr = iph->daddr; iph->daddr = t;
            __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;
            tcp->seq = bpf_htonl(srv_seq);
            tcp->ack_seq = bpf_htonl(cli_seq);
            tcp->fin = 0; tcp->syn = 0; tcp->rst = 0;
            tcp->psh = 0; tcp->ack = 1; tcp->urg = 0;
            tcp->ece = 0; tcp->cwr = 0;
            tcp->doff = 5;
            tcp->window = bpf_htons(65535);
            tcp->urg_ptr = 0;
            iph->ihl = 5;
            iph->tot_len = bpf_htons(20 + 20);
            iph->ttl = 64;
            iph->id = 0;
            return 0;
        }

        /* Return the cache slot whose "GET <path> " prefix matches, or -1. */
        static __always_inline int spnl_tcp_slice_match_route(const char *p,
                                                              __u32 len, void *data_end)
        {
            #{match_routes_code}
            return -1;
        }

        /* Main state machine entry. Returns XDP_PASS/DROP/TX/ABORTED. */
        static __noinline int spnl_tcp_slice_main(struct xdp_md *ctx)
        {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;

            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            if (eth->h_proto != bpf_htons(0x0800)) {
                spnl_tcp_slice_inc(11); /* CNT_PASS */
                return XDP_PASS;
            }
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return XDP_PASS;
            if (iph->protocol != 6) {
                spnl_tcp_slice_inc(11);
                return XDP_PASS;
            }
            __u32 ihl = iph->ihl * 4;
            if (ihl < sizeof(*iph) || (void *)iph + ihl > data_end) return XDP_PASS;
            struct tcphdr *tcp = (void *)iph + ihl;
            if ((void *)(tcp + 1) > data_end) return XDP_PASS;
            if (tcp->dest != bpf_htons(#{port})) {
                spnl_tcp_slice_inc(11);
                return XDP_PASS;
            }

            /* RST: clean up state. Cancel the timer too — map_delete
             * implicitly cancels but explicit cancel is safer when both
             * paths (XDP and timer callback) race on the same value. */
            if (tcp->rst) {
                spnl_tcp_slice_inc(13); /* CNT_RST_RX */
                struct spnl_tcp_slice_key kr = {
                    .saddr = iph->saddr, .daddr = iph->daddr,
                    .sport = tcp->source, .dport = tcp->dest,
                };
                struct spnl_tcp_slice_state *st_rst =
                    bpf_map_lookup_elem(&bpf_conntab, &kr);
                if (st_rst) bpf_timer_cancel(&st_rst->timer);
                bpf_map_delete_elem(&bpf_conntab, &kr);
                spnl_tcp_slice_inc(10); /* CNT_DROP */
                return XDP_DROP;
            }

            /* ---- SYN: generate cookie, send SYN-ACK ---- */
            if (tcp->syn && !tcp->ack) {
                spnl_tcp_slice_inc(0); /* CNT_SYN_RX */
                __u32 thl_in = tcp->doff * 4;
                if (thl_in < sizeof(*tcp) || (void *)tcp + thl_in > data_end)
                    return XDP_DROP;

                int delta = 60 - thl_in;
                if (bpf_xdp_adjust_tail(ctx, delta) != 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;
                eth = data;
                if ((void *)(eth + 1) > data_end) return XDP_ABORTED;
                iph = (void *)(eth + 1);
                if ((void *)iph + 60 > data_end) return XDP_ABORTED;
                tcp = (void *)iph + iph->ihl * 4;
                if ((void *)tcp + 60 > data_end) return XDP_ABORTED;

                __s64 cookie = bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl_in);
                if (cookie < 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
                __u32 cookie_seq = (__u32)cookie;
                __u16 mss = cookie >> 32;
                if (mss == 0) mss = 1460;

                if (spnl_tcp_slice_build_synack(eth, iph, tcp, cookie_seq, mss, data_end) < 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
                iph->ihl = 5;
                iph->tot_len = bpf_htons(20 + 24);
                iph->ttl = 64;
                iph->id = 0;
                if (spnl_tcp_slice_recompute_csums(iph, tcp, 24, data_end) < 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
                int cur = (long)data_end - (long)data;
                int want = sizeof(*eth) + 20 + 24;
                if (cur != want) {
                    if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
                        spnl_tcp_slice_inc(12);
                        return XDP_ABORTED;
                    }
                }
                spnl_tcp_slice_inc(1); /* CNT_SYNACK_TX */
                return XDP_TX;
            }

            if (!(tcp->ack)) return XDP_PASS;

            __u32 thl = tcp->doff * 4;
            if (thl < sizeof(*tcp) || (void *)tcp + thl > data_end) return XDP_DROP;
            __u32 ip_tot = bpf_ntohs(iph->tot_len);
            if (ip_tot < ihl + thl) return XDP_DROP;
            __u32 payload_len = ip_tot - ihl - thl;

            struct spnl_tcp_slice_key k = {
                .saddr = iph->saddr, .daddr = iph->daddr,
                .sport = tcp->source, .dport = tcp->dest,
            };
            struct spnl_tcp_slice_state *st = bpf_map_lookup_elem(&bpf_conntab, &k);

            if (!st) {
                /* Validate cookie and create state. */
                __s64 r = bpf_tcp_raw_check_syncookie_ipv4(iph, tcp);
                if (r < 0) {
                    spnl_tcp_slice_inc(3); /* CNT_ACK_INVALID */
                    return XDP_PASS;
                }
                spnl_tcp_slice_inc(2); /* CNT_ACK_VALID */
                struct spnl_tcp_slice_state new_st = {
                    .server_seq = bpf_ntohl(tcp->ack_seq),
                    .client_seq = bpf_ntohl(tcp->seq),
                    .mss = 1460, .state = 1, .pad = 0,
                };
                if (bpf_map_update_elem(&bpf_conntab, &k, &new_st, BPF_ANY) == 0)
                    spnl_tcp_slice_inc(4); /* CNT_CONN_CREATED */
                st = bpf_map_lookup_elem(&bpf_conntab, &k);
                if (!st) {
                    spnl_tcp_slice_inc(10);
                    return XDP_DROP;
                }
                /* arm idle-timer for ESTABLISHED state */
                spnl_tcp_slice_arm(st, SPNL_TS_TTL_ESTAB);
            }

            /* FIN from client.
             *  - state==2 (RESP_SENT): first FIN → build FIN-ACK, transition
             *    to CLOSED.
             *  - state==3 (CLOSED):   retransmit → rebuild same FIN-ACK
             *    using the stored seqs (client_seq already advanced by FIN).
             *
             * In both cases we send the same packet shape (eth+ip+tcp ACK,
             * doff=5, no payload, no FIN). The client's TCP layer keeps
             * retransmitting its FIN until it sees our ACK or gives up. */
            if (tcp->fin && (st->state == 2 || st->state == 3)) {
                __u32 cli_seq_for_ack;
                if (st->state == 2) {
                    spnl_tcp_slice_inc(8); /* CNT_FIN_RX */
                    cli_seq_for_ack = bpf_ntohl(tcp->seq) + payload_len + 1;
                } else {
                    /* CLOSED → retransmit. state.client_seq already includes
                     * the +1 for the original FIN slot. */
                    spnl_tcp_slice_inc(16); /* CNT_FIN_RETX */
                    cli_seq_for_ack = st->client_seq;
                }
                __u32 srv_seq = st->server_seq;
                if (spnl_tcp_slice_build_finack(eth, iph, tcp, srv_seq,
                                                cli_seq_for_ack, data_end) < 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
                if (spnl_tcp_slice_recompute_csums(iph, tcp, 20, data_end) < 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
                int cur = (long)data_end - (long)data;
                int want = sizeof(*eth) + 20 + 20;
                if (cur != want) {
                    if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
                        spnl_tcp_slice_inc(12);
                        return XDP_ABORTED;
                    }
                }
                if (st->state == 2) {
                    st->state = 3;
                    st->client_seq = cli_seq_for_ack;
                }
                /* re-arm cleanup timer with CLOSED TTL */
                spnl_tcp_slice_arm(st, SPNL_TS_TTL_CLOSED);
                spnl_tcp_slice_inc(9); /* CNT_FINACK_TX */
                return XDP_TX;
            }

            /* Data path. Two cases handle the same packet shape:
             *  - state==1 (ESTABLISHED): first GET → send response, advance state
             *  - state==2 (RESP_SENT)  : GET retransmit → re-send response
             *                            using the seqs we already saved
             */
            if (payload_len > 0 && (st->state == 1 || st->state == 2)) {
                const char *payload = (const char *)tcp + thl;
                int kc_slot = spnl_tcp_slice_match_route(payload, payload_len, data_end);
                if (kc_slot >= 0) {
                    #{rlen_lookup}
                    __u32 srv_seq_to_send, cli_seq_after;
                    if (st->state == 1) {
                        spnl_tcp_slice_inc(5); /* CNT_DATA_GET */
                        srv_seq_to_send = st->server_seq;
                        cli_seq_after   = bpf_ntohl(tcp->seq) + payload_len;
                    } else {
                        /* RESP_SENT retransmit: reuse the same seqs we sent
                         * the first time. server_seq was post-incremented by
                         * (#{rl} + 1 for FIN); roll it back to the original.
                         * client_seq was advanced by payload_len. (#{rl} is the
                         * same map-derived value as the first send.) */
                        spnl_tcp_slice_inc(14); /* CNT_RESP_RETX */
                        srv_seq_to_send = st->server_seq - #{rl} - 1;
                        cli_seq_after   = st->client_seq;
                    }
                    #{pregrow}
                    if (spnl_tcp_slice_build_response(eth, iph, tcp, srv_seq_to_send,
                                                      cli_seq_after, kc_slot#{br_call_arg}, data_end) < 0) {
                        spnl_tcp_slice_inc(12);
                        return XDP_ABORTED;
                    }
                    if (#{csum_call} < 0) {
                        spnl_tcp_slice_inc(12);
                        return XDP_ABORTED;
                    }
                    int cur = (long)data_end - (long)data;
                    int want = sizeof(*eth) + 20 + 20 + #{rl};
                    if (cur != want) {
                        if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
                            spnl_tcp_slice_inc(12);
                            return XDP_ABORTED;
                        }
                    }
                    if (st->state == 1) {
                        st->server_seq = srv_seq_to_send + #{rl} + 1;
                        st->client_seq = cli_seq_after;
                        st->state = 2;
                    }
                    /* re-arm cleanup timer with RESP_SENT TTL */
                    spnl_tcp_slice_arm(st, SPNL_TS_TTL_RESP);
                    spnl_tcp_slice_inc(7); /* CNT_RESPONSE_TX */
                    return XDP_TX;
                }
                spnl_tcp_slice_inc(6); /* CNT_DATA_OTHER */
                spnl_tcp_slice_inc(10);
                return XDP_DROP;
            }

            spnl_tcp_slice_inc(10);
            return XDP_DROP;
        }
      SLICE
    end

    # bpf_dynptr-backed packet byte access. The kernel keeps a
    # verifier-safe representation of the XDP frame (incl. multi-buf
    # fragments). `bpf_dynptr_slice` returns either a direct pointer to
    # the frame bytes OR a pointer to the caller-supplied buffer if the
    # bytes are split across fragments — either way the verifier knows
    # `len` bytes are accessible. This decouples the codegen from the
    # manual `pkt + N > data_end` dance used by the older packet helpers.
    #
    # `pkt_dynptr_byte_at(offset)` from Ruby lowers to a call to this
    # helper, returning the byte value (0-255) on success or -1 if `off`
    # is out of bounds.
    # USER_RINGBUF (BPF_MAP_TYPE_USER_RINGBUF, kernel 6.1+).
    # Per-unit map named `bpf_user_cmds`. Userspace writes records via
    # libbpf's `bpf_user_ringbuf__reserve` / `_submit` (or `bpftool map
    # update` for testing); kernel consumes them with
    # `bpf_user_ringbuf_drain(map, callback, ctx, 0)`. The callback is
    # whatever method matches `user_ringbuf__<name>` (emitted as a static
    # `long cb(struct bpf_dynptr *, void *)`).
    USER_RINGBUF_MAP_NAME = "bpf_user_cmds"
    USER_RINGBUF_SIZE_BYTES = 256 * 1024  # 256 KB

    # tcp_congestion_ops member signatures (subset). Keys are member
    # names matched by the `tcp_cc__<member>` attach pattern. Each entry
    # gives the C return type, BPF_PROG-style typed parameter list, and a
    # default-return literal for void members (used to compile the bridging
    # wrapper). Extend as needed; the kernel struct exposes more members.
    TCP_CC_MEMBERS = {
      "init"        => { ret: "void", typed_params: "struct sock *sk" },
      "release"     => { ret: "void", typed_params: "struct sock *sk" },
      "ssthresh"    => { ret: "__u32", typed_params: "struct sock *sk" },
      "cong_avoid"  => { ret: "void", typed_params: "struct sock *sk, __u32 ack, __u32 acked" },
      "undo_cwnd"   => { ret: "__u32", typed_params: "struct sock *sk" },
      "set_state"   => { ret: "void", typed_params: "struct sock *sk, __u8 new_state" },
      "min_tso_segs"=> { ret: "__u32", typed_params: "struct sock *sk" },
    }.freeze

    # sched_ext_ops member signatures (subset — the most common
    # ones for a basic CPU scheduler like scx_simple). `sleepable: true`
    # forces SEC("struct_ops.s/<m>") so the member can call sleepable
    # kfuncs (e.g. scx_bpf_create_dsq in init). The hot-path ops
    # (enqueue / dispatch / tick / ...) are non-sleepable for performance.
    SCHED_EXT_MEMBERS = {
      "select_cpu"  => { ret: "__s32", typed_params: "struct task_struct *p, __s32 prev_cpu, __u64 wake_flags" },
      "enqueue"     => { ret: "void",  typed_params: "struct task_struct *p, __u64 enq_flags" },
      "dequeue"     => { ret: "void",  typed_params: "struct task_struct *p, __u64 deq_flags" },
      "dispatch"    => { ret: "void",  typed_params: "__s32 cpu, struct task_struct *prev" },
      "tick"        => { ret: "void",  typed_params: "struct task_struct *p" },
      "runnable"    => { ret: "void",  typed_params: "struct task_struct *p, __u64 enq_flags" },
      "running"     => { ret: "void",  typed_params: "struct task_struct *p" },
      "stopping"    => { ret: "void",  typed_params: "struct task_struct *p, bool runnable" },
      "init"        => { ret: "__s32", typed_params: "void", sleepable: true },
      "exit"        => { ret: "void",  typed_params: "struct scx_exit_info *info", sleepable: true },
    }.freeze

    # Qdisc_ops member signatures (subset for a BPF qdisc).
    # init / reset / destroy run in process context and call sleepable
    # kfuncs (bpf_qdisc_init_prologue, bpf_qdisc_reset_destroy_epilogue),
    # so they need SEC("struct_ops.s/<m>"). enqueue / dequeue / peek are
    # hot-path callbacks.
    QDISC_MEMBERS = {
      "enqueue"     => { ret: "int",
                         typed_params: "struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free" },
      "dequeue"     => { ret: "struct sk_buff *",
                         typed_params: "struct Qdisc *sch" },
      "peek"        => { ret: "struct sk_buff *",
                         typed_params: "struct Qdisc *sch" },
      # Note: although bpf_qdisc_init_prologue / _reset_destroy_epilogue
      # appear "sleepable-ish", the kernel registers them against the
      # NON-sleepable `struct_ops/<m>` SEC for Qdisc_ops member filtering.
      # Using `struct_ops.s/<m>` causes the verifier to refuse the kfunc
      # call ("calling kernel function ... is not allowed").
      "init"        => { ret: "int",
                         typed_params: "struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack" },
      "reset"       => { ret: "void",
                         typed_params: "struct Qdisc *sch" },
      "destroy"     => { ret: "void",
                         typed_params: "struct Qdisc *sch" },
    }.freeze

    # The struct_ops.link map name (= the CC algorithm identifier from
    # libbpf's point of view; the kernel-visible CC name is set via the
    # `.name` field in TCP_CC_NAME).
    TCP_CC_DEFAULT_NAME    = "spnl_cc"
    SCHED_EXT_DEFAULT_NAME = "spnl_sx"      # 15-char limit for sched_ext name
    QDISC_DEFAULT_ID       = "spnl_qdisc"   # 15-char limit for Qdisc_ops.id

    # struct_ops registry — drives both the per-method emission path
    # (member function wrappers) and the bundle-level emission path
    # (`SEC(".struct_ops") struct <type> <symbol> = { ... };`).
    STRUCT_OPS_REGISTRY = {
      tcp_cc: {
        members:     TCP_CC_MEMBERS,
        struct_type: "tcp_congestion_ops",
        symbol:      "spnl_tcp_cc_ops",
        name_field:  :name,
        default_name: TCP_CC_DEFAULT_NAME,
        section:     ".struct_ops",
      },
      sched_ext: {
        members:     SCHED_EXT_MEMBERS,
        struct_type: "sched_ext_ops",
        symbol:      "spnl_sched_ext_ops",
        name_field:  :name,
        default_name: SCHED_EXT_DEFAULT_NAME,
        # sched_ext requires the linkable form so libbpf can manage
        # lifetime (enable on attach, disable on bpf_link__destroy).
        section:     ".struct_ops.link",
      },
      qdisc: {
        members:     QDISC_MEMBERS,
        struct_type: "Qdisc_ops",
        symbol:      "spnl_qdisc_ops",
        name_field:  :id,
        default_name: QDISC_DEFAULT_ID,
        # same reasoning as sched_ext — link form is required so
        # libbpf can manage the qdisc type lifetime (register on attach,
        # unregister on bpf_link__destroy). tc instances refer to this
        # type by its id ("spnl_qdisc") via `tc qdisc add dev <dev> root
        # handle 1: spnl_qdisc`.
        section:     ".struct_ops.link",
      },
    }.freeze

    # emit a single struct_ops member function (tcp_cc__<m>,
    # sched_ext__<m>, qdisc__<m>) and register it in the appropriate ctx
    # array. `attach[:kind]` selects the per-kind member signature table
    # and the prefix used in the function name.
    def emit_struct_ops_member(ctx, mi, attach)
      kind   = attach[:kind]
      member = attach[:member]
      reg    = STRUCT_OPS_REGISTRY[kind] || raise("missing registry for #{kind}")
      info   = reg[:members][member]
      raise UnsupportedNode, "#{kind}__#{member}: unsupported member (extend #{kind.upcase}_MEMBERS)" unless info

      case kind
      when :tcp_cc
        ctx.uses_tcp_cc = true
        ctx.tcp_cc_members ||= []
        ctx.tcp_cc_members << member unless ctx.tcp_cc_members.include?(member)
      when :sched_ext
        ctx.uses_sched_ext = true
        ctx.sched_ext_members ||= []
        ctx.sched_ext_members << member unless ctx.sched_ext_members.include?(member)
      when :qdisc
        ctx.uses_qdisc = true
        ctx.qdisc_members ||= []
        ctx.qdisc_members << member unless ctx.qdisc_members.include?(member)
      end

      params = method_params(ctx, mi)
      body_emitter = MethodEmitter.new(ctx: ctx, mi: mi, return_type: "int", params: params)
      body_lines = body_emitter.emit
      inner_params = if params.empty?
                       "void"
                     else
                       params.map do |n, t|
                         ct = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param #{n}: type #{t.inspect} not supported")
                         "#{ct} #{n}"
                       end.join(", ")
                     end
      ret_c = info[:ret]
      casts = params.map { |n, _| "(__s64)(unsigned long)#{n}" }.join(", ")
      func_name = "#{kind}__#{member}"
      wrapper_body = if ret_c == "void"
                       "    (void)#{func_name}_inner(#{casts});"
                     elsif ret_c.end_with?("*")
                       # struct sk_buff *, etc. — caller expects pointer
                       "    return (#{ret_c})(unsigned long)#{func_name}_inner(#{casts});"
                     else
                       "    return (#{ret_c})#{func_name}_inner(#{casts});"
                     end
      # BPF_PROG macro chokes on a literal `void` arg list — it must be
      # absent entirely when there are no kernel-supplied parameters.
      bpf_prog_args = info[:typed_params] == "void" ? "" : ", #{info[:typed_params]}"
      # sched_ext init/exit need ".s" (sleepable) so they can call
      # sleepable kfuncs like scx_bpf_create_dsq / scx_bpf_destroy_dsq.
      sec_suffix = info[:sleepable] ? ".s" : ""
      <<~CC
        /* impl: #{func_name} */
        static __noinline __s64 #{func_name}_inner(#{inner_params})
        {
        #{body_lines.map { |ln| "    " + ln }.join("\n")}
        }

        /* entry: SEC("struct_ops#{sec_suffix}/#{member}") for #{reg[:struct_type]} */
        SEC("struct_ops#{sec_suffix}/#{member}")
        #{ret_c} BPF_PROG(#{func_name}#{bpf_prog_args})
        {
        #{wrapper_body}
        }
      CC
    end

    # generic struct_ops bundle emit. Reads STRUCT_OPS_REGISTRY
    # and uses the per-kind member array stored in ctx. The SEC name varies
    # by kind — sched_ext uses ".struct_ops.link" for lifetime-managed
    # registration; tcp_cc / qdisc use plain ".struct_ops".
    def emit_struct_ops_bundle(ctx, kind)
      reg = STRUCT_OPS_REGISTRY[kind] || raise("unknown struct_ops kind #{kind}")
      members = case kind
                when :tcp_cc    then ctx.tcp_cc_members
                when :sched_ext then ctx.sched_ext_members
                when :qdisc     then ctx.qdisc_members
                end
      prefix = "#{kind}__"
      assigns = members.map { |m| "    .#{m} = (void *)#{prefix}#{m}," }.join("\n")
      name_kv = "    .#{reg[:name_field]} = \"#{reg[:default_name]}\","
      sec = reg[:section] || ".struct_ops"
      <<~SO
        /* struct_ops registration for #{reg[:struct_type]}. */
        SEC("#{sec}")
        struct #{reg[:struct_type]} #{reg[:symbol]} = {
        #{assigns}
        #{name_kv}
        };
      SO
    end

    # Back-compat alias retained so the existing emit() call site doesn't break.
    def emit_tcp_cc_struct_ops(ctx)
      emit_struct_ops_bundle(ctx, :tcp_cc)
    end

    # sched_ext kfunc externs + SCX_* constant defines. Emitted at
    # the top of the .bpf.c (right after license + includes) when the unit
    # has any `def sched_ext__<m>` / `class X < BPF::SchedExt` method, so
    # that the struct_ops member bodies can reference scx_bpf_dispatch /
    # scx_bpf_consume / SCX_DSQ_GLOBAL / SCX_SLICE_DFL etc. directly.
    #
    # The kfunc externs use `__weak` so the loader doesn't fail when the
    # running kernel lacks an entry — we surface as a runtime "operation
    # not supported" rather than a load error.
    def emit_sched_ext_preamble(_ctx)
      <<~PRE
        /* sched_ext constant macros. scx_bpf_* kfunc declarations
         * already live in vmlinux.h (BTF-generated, marked __weak __ksym),
         * so we don't redeclare them here. */

        /* SCX DSQ id helpers (see kernel: include/linux/sched/ext.h). */
        #ifndef SCX_DSQ_FLAG_BUILTIN
        #define SCX_DSQ_FLAG_BUILTIN (1ULL << 63)
        #endif
        #ifndef SCX_DSQ_GLOBAL
        #define SCX_DSQ_GLOBAL   (SCX_DSQ_FLAG_BUILTIN | 1ULL)
        #endif
        #ifndef SCX_DSQ_LOCAL
        #define SCX_DSQ_LOCAL    (SCX_DSQ_FLAG_BUILTIN | 0ULL)
        #endif
        #ifndef SCX_SLICE_DFL
        #define SCX_SLICE_DFL    20000000ULL    /* 20 ms */
        #endif
        #ifndef SCX_SLICE_INF
        #define SCX_SLICE_INF    (~0ULL)
        #endif
        #ifndef SCX_KICK_PREEMPT
        #define SCX_KICK_PREEMPT (1U << 0)
        #endif
        #ifndef SCX_ENQ_PREEMPT
        #define SCX_ENQ_PREEMPT  (1ULL << 32)
        #endif
      PRE
    end

    # real FIFO qdisc preamble — bpf_list_head + spin_lock +
    # wrapper struct used by queue_push / queue_pop builtins to actually
    # queue packets (not just drop them as the earlier drop-only qdisc did).
    #
    # The dance is:
    #   1. enqueue: bpf_obj_new an skb_node, bpf_kptr_xchg the skb into it,
    #      lock + bpf_list_push_back, unlock.
    #   2. dequeue: lock + bpf_list_pop_front + unlock, kptr_xchg(NULL) to
    #      reclaim the skb, bpf_obj_drop the wrapper, return the skb.
    #
    # All the verifier-pleasing rituals (kptr ownership transfer,
    # bpf_obj_drop on every error path) are hidden in the builtin
    # expansions; the Ruby DSL only sees `queue_push(skb, to_free)` /
    # `queue_pop()`.
    def emit_qdisc_fifo_preamble(_ctx)
      <<~PRE
        /* bpf_list/bpf_obj/kptr helper machinery for BPF qdiscs. */
        #ifndef __contains
        #define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))
        #endif
        #ifndef __kptr
        #define __kptr __attribute__((btf_type_tag("kptr")))
        #endif
        #ifndef private
        #define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
        #endif
        #ifndef bpf_obj_new
        #define bpf_obj_new(type)              ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
        #endif
        #ifndef bpf_obj_drop
        #define bpf_obj_drop(kptr)             bpf_obj_drop_impl(kptr, NULL)
        #endif
        #ifndef bpf_list_push_back
        #define bpf_list_push_back(head, node) bpf_list_push_back_impl(head, node, NULL, 0)
        #endif
        #ifndef container_of
        #define container_of(ptr, type, member) ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
        #endif

        /* Wrapper struct holding one skb in a bpf_list. The __kptr tag
         * tells the verifier that this field owns a kernel sk_buff that
         * must be released via bpf_kptr_xchg before the wrapper is freed. */
        struct spnl_qdisc_skb_node {
            struct bpf_list_node node;
            struct sk_buff __kptr *skb;
        };

        /* Per-unit single queue (spin_lock + list_head pair). The
         * __contains tag wires the list head to skb_node.node so the
         * verifier knows which container type the list holds. */
        private(A) struct bpf_spin_lock spnl_qdisc_q_lock;
        private(A) struct bpf_list_head spnl_qdisc_q_head __contains(spnl_qdisc_skb_node, node);
      PRE
    end

    # CPUMAP for XDP per-CPU fanout. Each entry holds
    # `struct bpf_cpumap_val { __u32 qsize; union { fd, id } bpf_prog; }`
    # which the kernel reads on bpf_redirect_map to enqueue the packet
    # onto the target CPU's NAPI ring (and optionally tail-call a second
    # XDP prog on the chosen CPU).
    CPUMAP_MAP_NAME = "spnl_cpumap"
    CPUMAP_MAX_ENTRIES = 64

    def emit_cpumap_map(_ctx)
      <<~CM
        /* CPUMAP for XDP per-CPU fanout. Entries are populated from
         * userspace (e.g. via bpftool map update or libbpf). Value is a
         * 64-bit `bpf_cpumap_val { __u32 qsize; __u32 prog_id; }` — userspace
         * supplies a `qsize` (typically 192) and optionally a secondary
         * XDP prog id to run on the destination CPU. */
        struct {
            __uint(type, BPF_MAP_TYPE_CPUMAP);
            __uint(key_size, sizeof(__u32));
            __uint(value_size, sizeof(struct bpf_cpumap_val));
            __uint(max_entries, #{CPUMAP_MAX_ENTRIES});
        } #{CPUMAP_MAP_NAME} SEC(".maps");
      CM
    end

    # AF_XDP XSKMAP — XDP redirects matched frames to user-space AF_XDP
    # (XSK) sockets. Slots are populated from userspace (bind an XSK to a
    # queue, then update the map). Apple container is single-queue so real
    # redirect isn't measurable here, but the codegen + verifier path are
    # established (cf. CPUMAP). bcc BPF_XSKMAP equivalent.
    XSKMAP_MAP_NAME = "bpf_xskmap"
    DEVMAP_MAP_NAME = "bpf_devmap"
    REDIRECT_MAX_ENTRIES = 64

    def emit_xskmap(_ctx)
      <<~XSK
        /* XSKMAP for AF_XDP zero-copy redirect to user sockets. */
        struct {
            __uint(type, BPF_MAP_TYPE_XSKMAP);
            __uint(key_size, sizeof(__u32));
            __uint(value_size, sizeof(__u32));
            __uint(max_entries, #{REDIRECT_MAX_ENTRIES});
        } #{XSKMAP_MAP_NAME} SEC(".maps");
      XSK
    end

    def emit_devmap(_ctx)
      <<~DEV
        /* DEVMAP for XDP redirect to another net device (ifindex). */
        struct {
            __uint(type, BPF_MAP_TYPE_DEVMAP);
            __uint(key_size, sizeof(__u32));
            __uint(value_size, sizeof(__u32));
            __uint(max_entries, #{REDIRECT_MAX_ENTRIES});
        } #{DEVMAP_MAP_NAME} SEC(".maps");
      DEV
    end

    # PROG_ARRAY for tail-callable XDP sub-programs.
    # Slot i corresponds to `xdp_tail__<name>` declared at index i in the
    # unit. The loader populates the map at attach time
    # (`bpf_map_update_elem(prog_array_fd, &i, &prog_fd, BPF_ANY)`).
    PROG_ARRAY_MAP_NAME = "spnl_prog_array"
    PROG_ARRAY_MAX_ENTRIES = 32

    def emit_prog_array_map(ctx)
      n = (ctx.tail_targets || []).length
      n = 1 if n < 1
      <<~PA
        /* PROG_ARRAY for bpf_tail_call dispatch. */
        struct {
            __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
            __uint(key_size, sizeof(__u32));
            __uint(value_size, sizeof(__u32));
            __uint(max_entries, #{[n, PROG_ARRAY_MAX_ENTRIES].max});
        } #{PROG_ARRAY_MAP_NAME} SEC(".maps");
      PA
    end

    def emit_user_ringbuf_map(ctx)
      cb = ctx.user_ringbuf_cb_name
      forward_decl =
        if cb
          "static long spnl_user_ringbuf_cb_#{cb}(struct bpf_dynptr *dynptr, void *_uctx);"
        else
          ""
        end
      <<~UCMD
        /* USER_RINGBUF for host→kernel command channel.
         * Records are __u64 commands (interpretation up to the user). */
        struct {
            __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
            __uint(max_entries, #{USER_RINGBUF_SIZE_BYTES});
        } #{USER_RINGBUF_MAP_NAME} SEC(".maps");

        #{forward_decl}
      UCMD
    end

    def emit_timer_map(ctx)
      name = ctx.timer_handler_name || "main"
      <<~TM
        /* bpf_timer-backed periodic callback. Single ARRAY slot
         * holding the timer struct. The arm prog (also emitted) is fired
         * once by userspace at load time via bpf_prog_test_run.
         * Interval: #{ctx.timer_interval_ns} ns (compile-time constant). */
        struct spnl_timer_value {
            struct bpf_timer t;
        };

        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(max_entries, 1);
            __type(key, __u32);
            __type(value, struct spnl_timer_value);
        } spnl_timer_map SEC(".maps");

        /* forward decl for the callback so the arm prog can reference it
         * before the body is emitted (codegen emits cb after the map). */
        static int spnl_timer_cb_#{name}(void *map, int *key, struct spnl_timer_value *v);
      TM
    end

    def emit_dynptr_helpers(_ctx)
      <<~DYNP
        /* bpf_dynptr-backed XDP byte access. vmlinux.h (CO-RE BTF)
         * already declares bpf_dynptr_from_xdp / bpf_dynptr_slice as
         * `__weak __ksym` externs with `u64 offset`, so we don't redeclare
         * them here — just use them.
         *
         * Read a single byte from an XDP frame at runtime offset. The
         * verifier validates the 1-byte access via the dynptr — no manual
         * `data + off > data_end` check needed in the caller. */
        static __noinline __s64 spnl_pkt_dynptr_byte_at(struct xdp_md *ctx, __s64 off)
        {
            if (off < 0) return -1;
            struct bpf_dynptr dp;
            if (bpf_dynptr_from_xdp(ctx, 0, &dp) < 0) return -1;
            __u8 buf;
            __u8 *p = bpf_dynptr_slice(&dp, (__u64)off, &buf, 1);
            if (!p) return -1;
            return (__s64)*p;
        }
      DYNP
    end

    # Helper for {sport,dport}: ports live at offset 0 / 2 of the L4 header
    # (true for both TCP and UDP). Returns 0 if not TCP/UDP or truncated.
    # IPv6 branch added. Extension headers (nexthdr != TCP/UDP directly)
    # are out of scope — we return 0 in that case.
    # Roadmap (Ruby tcp_slice) #1: read a 32-bit TCP header field (seq at offset 4,
    # ack_seq at offset 8) in host byte order, 0 if not TCP / truncated. TCP-only
    # (seq/ack are meaningless for UDP). IPv4 + IPv6 branches, each with its own
    # bounds check (the always-inline pkt_end leak class). Mirrors pkt_l4_port_helper but reads __be32.
    def pkt_tcp_u32_field_helper(name, offset, ctx_decl, fn_prefix)
      field = name.sub("pkt_tcp_", "")
      end_off = offset + 4
      <<~TCPU32
        /* TCP #{field} (host byte order), 0 if not TCP or truncated. */
        static __noinline __s64 #{fn_prefix}_#{name}(#{ctx_decl})
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return 0;
            if (eth->h_proto == bpf_htons(0x0800)) {
                struct iphdr *iph = (void *)(eth + 1);
                if ((void *)(iph + 1) > data_end) return 0;
                if (iph->protocol != 6) return 0;  /* IPPROTO_TCP */
                __u32 ihl = iph->ihl * 4;
                if (ihl < sizeof(*iph)) return 0;
                char *l4 = (char *)iph + ihl;
                if (l4 + #{end_off} > (char *)data_end) return 0;
                __be32 *p = (__be32 *)(l4 + #{offset});
                return (__s64)bpf_ntohl(*p);
            }
            if (eth->h_proto == bpf_htons(0x86DD)) {
                struct ipv6hdr *ip6h = (void *)(eth + 1);
                if ((void *)(ip6h + 1) > data_end) return 0;
                if (ip6h->nexthdr != 6) return 0;  /* IPPROTO_TCP */
                char *l4 = (char *)(ip6h + 1);
                if (l4 + #{end_off} > (char *)data_end) return 0;
                __be32 *p = (__be32 *)(l4 + #{offset});
                return (__s64)bpf_ntohl(*p);
            }
            return 0;
        }
      TCPU32
    end

    def pkt_l4_port_helper(suffix, offset, ctx_decl, fn_prefix)
      <<~PORT
        /* L4 #{suffix} (TCP or UDP, IPv4 or IPv6) in host byte order, 0 otherwise. */
        static __noinline __s64 #{fn_prefix}_pkt_l4_#{suffix}(#{ctx_decl})
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return 0;
            if (eth->h_proto == bpf_htons(0x0800)) {
                struct iphdr *iph = (void *)(eth + 1);
                if ((void *)(iph + 1) > data_end) return 0;
                if (iph->protocol != 6 && iph->protocol != 17) return 0;
                __u32 ihl = iph->ihl * 4;
                if (ihl < sizeof(*iph)) return 0;
                char *l4 = (char *)iph + ihl;
                if (l4 + 4 > (char *)data_end) return 0;
                __be16 *p = (__be16 *)(l4 + #{offset});
                return (__s64)bpf_ntohs(*p);
            }
            if (eth->h_proto == bpf_htons(0x86DD)) {
                struct ipv6hdr *ip6h = (void *)(eth + 1);
                if ((void *)(ip6h + 1) > data_end) return 0;
                if (ip6h->nexthdr != 6 && ip6h->nexthdr != 17) return 0;
                char *l4 = (char *)(ip6h + 1);
                if (l4 + 4 > (char *)data_end) return 0;
                __be16 *p = (__be16 *)(l4 + #{offset});
                return (__s64)bpf_ntohs(*p);
            }
            return 0;
        }
      PORT
    end

    # method-name convention for kernel-event attach points.
    # `kprobe__<target>`   -> SEC("kprobe/<target>"), ctx = struct pt_regs *
    # `kretprobe__<target>` -> SEC("kretprobe/<target>"), ctx = struct pt_regs *
    # `tracepoint__<cat>__<name>` -> SEC("tracepoint/<cat>/<name>"), ctx = void *
    # `xdp__<name>` -> SEC("xdp"), ctx = struct xdp_md *
    #   - body's last expr must evaluate to one of XDP_PASS / XDP_DROP / XDP_TX / XDP_REDIRECT
    #   - attach is done by glue.c reading $SPNL_XDP_IFACE (interface name) at startup
    # `tc__ingress__<name>` / `tc__egress__<name>` -> SEC("tcx/ingress|egress"),
    #   ctx = struct __sk_buff *. Body returns TC_ACT_OK / TC_ACT_SHOT / TC_ACT_*.
    #   Glue.c attaches via bpf_program__attach_tcx() reading $SPNL_TCX_IFACE.
    # `sk_reuseport__<name>` -> SEC("sk_reuseport"), ctx = struct sk_reuseport_md *.
    #   Body returns SK_PASS / SK_DROP. Used for SO_REUSEPORT worker selection
    #   (multi-worker HTTP server). Attach is application-specific
    #   (setsockopt(SO_ATTACH_REUSEPORT_EBPF)) so the libbpf skeleton's
    #   default __attach() is a no-op for these programs — that's expected.
    # sockmap / sk_msg / sk_skb (kernel-side static-response building block).
    #   `sk_msg__<name>`           -> SEC("sk_msg"),               ctx = struct sk_msg_md *
    #   `sk_skb__verdict__<name>`  -> SEC("sk_skb/stream_verdict"), ctx = struct __sk_buff *
    #   `sk_skb__parser__<name>`   -> SEC("sk_skb/stream_parser"),  ctx = struct __sk_buff *
    #   Bodies return SK_PASS / SK_DROP. Attach requires bpf_prog_attach() with
    #   a BPF_MAP_TYPE_SOCKMAP or BPF_MAP_TYPE_SOCKHASH map fd (deferred to
    #   the fast-path response demo for the actual response handling).
    ATTACH_PATTERNS = [
      [/\Akprobe__(.+)\z/,              :kprobe],
      [/\Akretprobe__(.+)\z/,           :kretprobe],
      # userspace probes. Target binary path is provided via env
      # ($SPNL_UPROBE_BINARY for uprobe/uretprobe, $SPNL_USDT_BINARY for usdt)
      # since `:` and `/` aren't valid in Ruby method names. PID via env too
      # ($SPNL_UPROBE_PID / $SPNL_USDT_PID, default -1 = all processes).
      # The usdt pattern uses `provider__probe` (no underscore in provider).
      [/\Auprobe__(.+)\z/,              :uprobe],
      [/\Auretprobe__(.+)\z/,           :uretprobe],
      [/\Ausdt__([^_]+)__(.+)\z/,       :usdt],
      [/\Atracepoint__([^_]+)__(.+)\z/, :tracepoint],
      # BPF-trampoline fentry/fexit — a more capable alternative to kprobe (direct call,
      # ~50ns vs ~1μs). fentry__<func>(arg1, ...) and fexit__<func>(arg1, ..., ret).
      [/\Afentry__(.+)\z/,              :fentry],
      [/\Afexit__(.+)\z/,               :fexit],
      # BPF_PROG_TYPE_LSM — security hook (needs CONFIG_BPF_LSM + the bpf
      # LSM active). `def lsm__<hook>(args..., ret)`; return 0 to allow, a
      # negative errno to deny. Args/ret arrive like fexit (ctx[i]).
      [/\Alsm__(.+)\z/,                 :lsm],
      # BPF_MODIFY_RETURN (fmod_ret) — override a function's return value
      # (error injection). `def fmod_ret__<func>(args..., ret)`; the handler's
      # return value replaces the function's. Target must be fmod-able
      # (ALLOW_ERROR_INJECTION / security_* hooks).
      [/\Afmod_ret__(.+)\z/,            :fmod_ret],
      # USER_RINGBUF host→kernel command channel. The Ruby method is
      # treated as a static callback (no SEC), invoked by
      # `bpf_user_ringbuf_drain` for each pending record.
      [/\Auser_ringbuf__(.+)\z/,        :user_ringbuf],
      # BPF_PROG_TYPE_SOCK_OPS — TCP socket state observation. Attach
      # is cgroup-scoped (BPF_CGROUP_SOCK_OPS), so glue.c will attach to
      # $SPNL_CGROUP_PATH (default /sys/fs/cgroup) when set.
      [/\Asock_ops__(.+)\z/,            :sock_ops],
      # cgroup/connect4 / bind4 (BPF_PROG_TYPE_CGROUP_SOCK_ADDR). Hook
      # outbound connect / bind from a cgroup; return 1 to allow, 0 to deny.
      # ctx is `struct bpf_sock_addr *` (sock_addr_ip4 / sock_addr_port read it).
      [/\Acgroup__connect4__(.+)\z/,    :cgroup_connect4],
      [/\Acgroup__bind4__(.+)\z/,       :cgroup_bind4],
      # BPF_ITER over kernel tasks. SEC("iter/task"); the program is
      # invoked once per task (ctx->task) plus a final NULL terminator. Driven
      # from userspace (glue.c create+read). `iter_task()` yields the task ptr.
      [/\Aiter__task__(.+)\z/,          :iter_task],
      # niche program types.
      # raw_tracepoint: lower-overhead tracepoint w/ raw args (ctx->args[i]).
      [/\Araw_tp__(.+)\z/,              :raw_tp],
      # socket_filter: classic SO_ATTACH_BPF packet filter (return = bytes kept).
      [/\Asocket_filter__(.+)\z/,       :socket_filter],
      # flow_dissector: programmable flow keying (return BPF_OK / BPF_DROP).
      [/\Aflow_dissector__(.+)\z/,      :flow_dissector],
      # sk_lookup: pick the listening socket for an incoming conn (SK_PASS/DROP).
      [/\Ask_lookup__(.+)\z/,           :sk_lookup],
      # struct_ops/tcp_congestion_ops member (init / ssthresh / ...).
      # All declared members are bundled into the `.struct_ops`
      # section and registered together as a CC algorithm.
      [/\Atcp_cc__(.+)\z/,              :tcp_cc],
      # struct_ops/sched_ext_ops member — a custom CPU
      # scheduler from a Ruby DSL. sched_ext attach is already proven; here we add codegen.
      [/\Asched_ext__(.+)\z/,           :sched_ext],
      # struct_ops/Qdisc_ops member — packet
      # scheduling policy via a BPF qdisc, written in a Ruby DSL.
      [/\Aqdisc__(.+)\z/,               :qdisc],
      # pure-XDP TCP slice for /health (must come before the generic
      # xdp__ pattern so the longer prefix wins).
      [/\Axdp__tcp_slice__(.+)\z/,      :xdp_tcp_slice],
      # tail-callable XDP sub-program (registered into a per-unit
      # PROG_ARRAY at load time; entry XDPs reach them via `tail_call_to`).
      [/\Axdp_tail__(.+)\z/,            :xdp_tail],
      [/\Axdp__(.+)\z/,                 :xdp],
      [/\Atc__ingress__(.+)\z/,         :tc_ingress],
      [/\Atc__egress__(.+)\z/,          :tc_egress],
      [/\Ask_reuseport__(.+)\z/,        :sk_reuseport],
      [/\Ask_msg__(.+)\z/,              :sk_msg],
      [/\Ask_skb__verdict__(.+)\z/,     :sk_skb_verdict],
      [/\Ask_skb__parser__(.+)\z/,      :sk_skb_parser],
      # `on :timer, every: N.<unit> do ... end` -> bpf_timer-backed
      # periodic callback. The DSL synthesizes `spnl_timer__main` as the
      # method name and threads the interval through `MethodInfo#dsl_timer_interval_ns`.
      [/\Aspnl_timer__(.+)\z/,          :timer],
      # perf_event sampling. `def perf_event__<name>` or
      # `on :perf_event, hz: 99 do ... end` synthesizes this prog name.
      # glue.c opens a per-CPU PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK
      # event at N Hz and attaches via bpf_program__attach_perf_event.
      # Bodies typically pair with stack_id() + hist_observe_by() for
      # on-CPU profiling (bcc `profile.py` equivalent).
      [/\Aperf_event__(.+)\z/,          :perf_event],
    ].freeze

    # Linux kernel constants that the codegen recognizes as ConstantReadNode
    # and lowers to their integer values. Initial set covers XDP retval enum.
    # IPPROTO_* / ETH_P_* added so packet-classification Ruby reads
    # naturally (`if pkt_l4_proto == IPPROTO_TCP ...`).
    KNOWN_CONSTANTS = {
      "XDP_ABORTED"  => 0,
      "XDP_DROP"     => 1,
      "XDP_PASS"     => 2,
      "XDP_TX"       => 3,
      "XDP_REDIRECT" => 4,
      # IP protocols (host-order ints, match what pkt_l4_proto returns)
      "IPPROTO_IP"     => 0,
      "IPPROTO_ICMP"   => 1,
      "IPPROTO_TCP"    => 6,
      "IPPROTO_UDP"    => 17,
      "IPPROTO_ICMPV6" => 58,
      # Ethertypes (host-order ints, match what pkt_eth_proto returns)
      "ETH_P_IP"   => 0x0800,
      "ETH_P_IPV6" => 0x86DD,
      "ETH_P_ARP"  => 0x0806,
      # TC action codes (return values for tc__ingress / tc__egress methods)
      "TC_ACT_OK"          => 0,
      "TC_ACT_RECLASSIFY"  => 1,
      "TC_ACT_SHOT"        => 2,
      "TC_ACT_PIPE"        => 3,
      "TC_ACT_STOLEN"      => 4,
      "TC_ACT_QUEUED"      => 5,
      "TC_ACT_REPEAT"      => 6,
      "TC_ACT_REDIRECT"    => 7,
      "TC_ACT_TRAP"        => 8,
      # SK_REUSEPORT return values (used by sk_reuseport__<name>).
      # Kernel <linux/bpf.h>: enum sk_action { SK_DROP = 0, SK_PASS = 1 }.
      # Returning SK_DROP drops the SYN; SK_PASS uses bpf_sk_select_reuseport's
      # selection (or kernel default when no selection was made).
      "SK_DROP"            => 0,
      "SK_PASS"            => 1,
      # sk_msg / sk_skb redirection helpers are looked up by name via
      # bpf_msg_redirect_map / bpf_sk_redirect_map at runtime; the BPF program
      # still returns SK_PASS to accept the (re-targeted) socket selection.
      # TCP flag bits (host-order, returned by pkt_tcp_flags). Standard
      # set from RFC 793 + ECN. Use with bitwise & to test individual flags.
      "TCP_FLAG_FIN" => 0x01,
      "TCP_FLAG_SYN" => 0x02,
      "TCP_FLAG_RST" => 0x04,
      "TCP_FLAG_PSH" => 0x08,
      "TCP_FLAG_ACK" => 0x10,
      "TCP_FLAG_URG" => 0x20,
      "TCP_FLAG_ECE" => 0x40,
      "TCP_FLAG_CWR" => 0x80,
      # BPF_SOCK_OPS_* event codes — selectable by `sock_ops_op` inside
      # a `def sock_ops__<name>(skops)` callback.
      "BPF_SOCK_OPS_TIMEOUT_INIT"           => 1,
      "BPF_SOCK_OPS_RWND_INIT"              => 2,
      "BPF_SOCK_OPS_TCP_CONNECT_CB"         => 3,
      "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB"  => 4,
      "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB" => 5,
      "BPF_SOCK_OPS_NEEDS_ECN"              => 6,
      "BPF_SOCK_OPS_BASE_RTT"               => 7,
      "BPF_SOCK_OPS_RTO_CB"                 => 8,
      "BPF_SOCK_OPS_RETRANS_CB"             => 9,
      "BPF_SOCK_OPS_STATE_CB"               => 10,
      "BPF_SOCK_OPS_TCP_LISTEN_CB"          => 11,
      "BPF_SOCK_OPS_RTT_CB"                 => 12,
      # TCP state codes (returned by skops->args[1] during STATE_CB)
      "TCP_STATE_ESTABLISHED"   => 1,
      "TCP_STATE_SYN_SENT"      => 2,
      "TCP_STATE_SYN_RECV"      => 3,
      "TCP_STATE_FIN_WAIT1"     => 4,
      "TCP_STATE_FIN_WAIT2"     => 5,
      "TCP_STATE_TIME_WAIT"     => 6,
      "TCP_STATE_CLOSE"         => 7,
      "TCP_STATE_CLOSE_WAIT"    => 8,
      "TCP_STATE_LAST_ACK"      => 9,
      "TCP_STATE_LISTEN"        => 10,
      "TCP_STATE_CLOSING"       => 11,
    }.freeze

    # module-style aliases for KNOWN_CONSTANTS. Each entry maps a
    # flat C-ish name prefix to a chain of Ruby Module names. We derive
    # the full path -> flat-name table from KNOWN_CONSTANTS at load time
    # by matching the longest applicable prefix, so adding a new flat
    # constant automatically gets a Module-style alias as well.
    #
    # Examples:
    #   XDP::PASS              -> XDP_PASS
    #   TCP::Flag::RST         -> TCP_FLAG_RST
    #   IP::Proto::TCP         -> IPPROTO_TCP
    #   BPF::SockOps::STATE_CB -> BPF_SOCK_OPS_STATE_CB
    CONSTANT_PATH_PREFIXES = [
      # Longest prefixes first so e.g. BPF_SOCK_OPS_* wins over BPF_*.
      ["BPF_SOCK_OPS_", %w[BPF SockOps]],
      ["TCP_FLAG_",     %w[TCP Flag]],
      ["TCP_STATE_",    %w[TCP State]],
      ["IPPROTO_",      %w[IP Proto]],
      ["TC_ACT_",       %w[TC Act]],
      ["ETH_P_",        %w[Eth P]],
      ["XDP_",          %w[XDP]],
      ["SK_",           %w[SK]],
    ].freeze

    KNOWN_CONSTANT_PATHS = KNOWN_CONSTANTS.keys.each_with_object({}) do |flat, h|
      match = CONSTANT_PATH_PREFIXES.find { |prefix, _| flat.start_with?(prefix) }
      next unless match
      prefix, mod_path = match
      suffix = flat[prefix.length..]
      next if suffix.empty?
      h[mod_path + [suffix]] = flat
    end.freeze

    # macro-valued constants (paths that resolve to C macro names rather
    # than integer literals — useful when the value is bigger than __s64 can
    # express, like SCX_DSQ_GLOBAL = (1ULL << 63) | 1). Lowering emits the
    # macro name verbatim; the macro itself is provided by emit_sched_ext_preamble.
    MACRO_PATHS = {
      %w[SCX DSQ GLOBAL]      => "SCX_DSQ_GLOBAL",
      %w[SCX DSQ LOCAL]       => "SCX_DSQ_LOCAL",
      %w[SCX SLICE_DFL]       => "SCX_SLICE_DFL",
      %w[SCX SLICE_INF]       => "SCX_SLICE_INF",
      %w[SCX KICK_PREEMPT]    => "SCX_KICK_PREEMPT",
      %w[SCX ENQ_PREEMPT]     => "SCX_ENQ_PREEMPT",
    }.freeze

    def detect_attach(method_name)
      ATTACH_PATTERNS.each do |re, kind|
        m = re.match(method_name)
        next unless m
        case kind
        when :kprobe, :kretprobe
          return { kind: kind, sec: "#{kind}/#{m[1]}",   ctx_type: "struct pt_regs *" }
        when :uprobe, :uretprobe
          # SEC name is just "uprobe" / "uretprobe" — libbpf reads the
          # SEC to set program type; binary path + func offset are supplied
          # at attach time via bpf_program__attach_uprobe_opts() in glue.c.
          return { kind: kind, sec: kind.to_s,
                   up_func: m[1], ctx_type: "struct pt_regs *" }
        when :usdt
          # SEC("usdt") + bpf_program__attach_usdt() in glue.c. Args
          # are read via bpf_usdt_arg(ctx, i, &val) — see extract_attach_args.
          return { kind: kind, sec: "usdt",
                   usdt_provider: m[1], usdt_name: m[2],
                   ctx_type: "struct pt_regs *" }
        when :tracepoint
          return { kind: kind, sec: "tracepoint/#{m[1]}/#{m[2]}",
                   tp_category: m[1], tp_event: m[2], ctx_type: "void *" }
        when :fentry, :fexit
          # BPF trampoline fentry/fexit programs. The wrapper
          # signature is `int <name>(__u64 *ctx)`; each arg is read as
          # `ctx[i]`. For fexit the implicit final ctx[N] is the return
          # value of the traced function.
          return { kind: kind, sec: "#{kind}/#{m[1]}",
                   tgt_func: m[1], ctx_type: "__u64 *" }
        when :lsm
          # BPF_PROG_TYPE_LSM. SEC("lsm/<hook>"); args (and the trailing
          # prior-verdict `ret`) read as ctx[i] like fexit. Return value is the
          # access decision (0 = allow, negative errno = deny) — propagated.
          return { kind: kind, sec: "lsm/#{m[1]}", lsm_hook: m[1], ctx_type: "__u64 *" }
        when :fmod_ret
          # BPF_MODIFY_RETURN. SEC("fmod_ret/<func>"); args + trailing
          # `ret` read as ctx[i] like fexit. The handler's return value
          # replaces the traced function's return — propagated.
          return { kind: kind, sec: "fmod_ret/#{m[1]}", fmod_func: m[1], ctx_type: "__u64 *" }
        when :user_ringbuf
          # USER_RINGBUF callback. Not a SEC entrypoint — emitted as
          # a static fn called by bpf_user_ringbuf_drain. The "ctx_type"
          # field is unused (emit_method short-circuits this kind).
          return { kind: kind, cb_name: m[1], sec: nil, ctx_type: nil }
        when :sock_ops
          # sock_ops program attached via BPF_CGROUP_SOCK_OPS.
          return { kind: kind, sec: "sockops", so_name: m[1], ctx_type: "struct bpf_sock_ops *" }
        when :cgroup_connect4
          # cgroup_sock_addr connect4 hook. cgroup-attached (glue.c).
          return { kind: kind, sec: "cgroup/connect4", cg_name: m[1], ctx_type: "struct bpf_sock_addr *" }
        when :cgroup_bind4
          return { kind: kind, sec: "cgroup/bind4", cg_name: m[1], ctx_type: "struct bpf_sock_addr *" }
        when :iter_task
          # BPF_ITER/task. Driven from userspace (glue.c create+read).
          return { kind: kind, sec: "iter/task", iter_name: m[1], ctx_type: "struct bpf_iter__task *" }
        when :raw_tp
          # raw tracepoint. Auto-attached by libbpf; args via ctx->args[i].
          return { kind: kind, sec: "raw_tp/#{m[1]}", rtp_event: m[1], ctx_type: "struct bpf_raw_tracepoint_args *" }
        when :socket_filter
          # SOCKET_FILTER. SEC("socket"); attach is via setsockopt on a raw
          # socket (application-specific), so the skeleton's __attach is a no-op.
          return { kind: kind, sec: "socket", sf_name: m[1], ctx_type: "struct __sk_buff *" }
        when :flow_dissector
          return { kind: kind, sec: "flow_dissector", fd_name: m[1], ctx_type: "struct __sk_buff *" }
        when :sk_lookup
          # libbpf recognises the bare "sk_lookup" section (no sub-name).
          return { kind: kind, sec: "sk_lookup", skl_name: m[1], ctx_type: "struct bpf_sk_lookup *" }
        when :tcp_cc, :sched_ext, :qdisc
          # struct_ops member function. emit_method special-cases
          # the kind to emit a BPF_PROG-wrapped function and collect the
          # member into the unit-level `.struct_ops` block.
          return { kind: kind, member: m[1], sec: "struct_ops/#{m[1]}", ctx_type: nil }
        when :xdp
          # SEC("xdp") is the canonical name; libbpf also accepts "xdp/<name>"
          # but plain "xdp" matches BPF_PROG_TYPE_XDP unambiguously.
          return { kind: kind, sec: "xdp", xdp_name: m[1], ctx_type: "struct xdp_md *" }
        when :xdp_tcp_slice
          # pure-XDP TCP slice. The Ruby method body is treated as a
          # marker — codegen emits a complete state-machine + helpers.
          return { kind: kind, sec: "xdp", ts_name: m[1], ctx_type: "struct xdp_md *" }
        when :xdp_tail
          # tail-callable XDP sub-program. Same SEC("xdp") as a
          # regular xdp__ entry but the loader **doesn't** auto-attach
          # (the program is reached via bpf_tail_call from a dispatcher).
          # The codegen assigns it a slot in `spnl_prog_array` based on
          # the unit-order it's declared in.
          return { kind: kind, sec: "xdp", xt_name: m[1], ctx_type: "struct xdp_md *" }
        when :tc_ingress
          # TCX ingress. libbpf attaches via bpf_program__attach_tcx().
          return { kind: kind, sec: "tcx/ingress", tc_name: m[1], ctx_type: "struct __sk_buff *" }
        when :tc_egress
          return { kind: kind, sec: "tcx/egress",  tc_name: m[1], ctx_type: "struct __sk_buff *" }
        when :sk_reuseport
          # SO_REUSEPORT BPF selection program. Attach is application-
          # specific (setsockopt SO_ATTACH_REUSEPORT_EBPF on a listening
          # socket), so glue.c's default __attach is a no-op here.
          return { kind: kind, sec: "sk_reuseport", sr_name: m[1], ctx_type: "struct sk_reuseport_md *" }
        when :sk_msg
          # sk_msg programs run on socket-level message events for sockets
          # added to a BPF_MAP_TYPE_SOCKMAP/SOCKHASH. Attach via bpf_prog_attach
          # with BPF_SK_MSG_VERDICT against a sockmap fd (deferred to the attach step).
          return { kind: kind, sec: "sk_msg", sm_name: m[1], ctx_type: "struct sk_msg_md *" }
        when :sk_skb_verdict
          return { kind: kind, sec: "sk_skb/stream_verdict", sm_name: m[1], ctx_type: "struct __sk_buff *" }
        when :sk_skb_parser
          return { kind: kind, sec: "sk_skb/stream_parser",  sm_name: m[1], ctx_type: "struct __sk_buff *" }
        when :timer
          # bpf_timer-backed periodic callback. The "name" suffix
          # (`spnl_timer__<name>`) is reserved for future multi-timer
          # support; MVP uses "main". The handler body becomes the timer
          # callback, and a small SEC("syscall") arm prog is auto-emitted
          # so libbpf can fire it once at load time via bpf_prog_test_run.
          return { kind: kind, name: m[1], sec: "syscall", ctx_type: "void *" }
        when :perf_event
          # SEC("perf_event") + per-CPU perf_event_open() driven by
          # glue.c. Body usually doesn't take typed params — perf_event
          # callbacks receive `struct bpf_perf_event_data *` (the sample's
          # registers), which we forward as ctx when stack_id() is used.
          return { kind: kind, pe_name: m[1], sec: "perf_event",
                   ctx_type: "struct bpf_perf_event_data *" }
        end
      end
      nil
    end

    # produce per-param C expressions that pull each declared param
    # out of the kernel-supplied attach context.
    #   kprobe:    PT_REGS_PARM<N>(ctx) for N=1..  (bpf_tracing.h)
    #   tracepoint syscalls/sys_enter_*: positional args[i]
    #   tracepoint syscalls/sys_exit_*:  positional args[i]
    # named-field tracepoints (sched/sched_switch etc.) are matched by
    # param name to struct field name via TRACEPOINT_FIELDS table.
    def extract_attach_args(attach, params, ctx = nil)
      case attach[:kind]
      when :kprobe, :kretprobe, :uprobe, :uretprobe
        # signal license_and_includes() that we need bpf_tracing.h
        # for the PT_REGS_PARM<N> macros. Caller passes ctx so we can set
        # the flag — for callers that don't (legacy code paths), the
        # macros may still be in scope via another include but this is
        # the supported route.
        # uprobe/uretprobe use the same pt_regs-based arg extraction
        # as kprobe — userspace function args are in the same registers.
        ctx.uses_pt_regs_parm = true if ctx && !params.empty?
        # kprobe entry params are the kernel function's
        # arguments — resolve them by name from BTF when possible (kretprobe's
        # param is the return value, and uprobe/uretprobe are userspace, so
        # those stay positional).
        kp_idxs = attach[:kind] == :kprobe ? btf_arg_indices(kprobe_target_func(attach), params) : nil
        params.each_with_index.map do |(_n, t), i|
          c_type = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param type #{t.inspect} not supported")
          pos = (kp_idxs ? kp_idxs[i] : i) + 1
          "(#{c_type})PT_REGS_PARM#{pos}(ctx)"
        end
      when :fentry, :fexit, :lsm, :fmod_ret
        # fentry / fexit. The wrapper receives `__u64 *ctx`, and
        # each arg is `ctx[i]` (libbpf's BPF_PROG-equivalent layout). For
        # fexit the trailing param is the return value of the traced
        # function and we read it from the SAME zero-based slot since
        # ctx is laid out as <arg0, arg1, ..., argN-1, ret>. The user
        # decides naming via the Ruby method signature.
        # LSM (ctx = <hook args..., prior verdict>) and fmod_ret
        # (ctx = <func args..., ret>) share the exact same ctx[i] layout.
        # for plain fentry every declared param is a
        # function arg, so resolve by name from BTF when possible. fexit/lsm/
        # fmod_ret carry a trailing ret/verdict slot, so they stay positional.
        fe_idxs = attach[:kind] == :fentry ? btf_arg_indices(attach[:tgt_func], params) : nil
        params.each_with_index.map do |(_n, t), i|
          c_type = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param type #{t.inspect} not supported")
          slot = fe_idxs ? fe_idxs[i] : i
          "(#{c_type})ctx[#{slot}]"
        end
      when :raw_tp
        # raw tracepoint. Args are the raw tracepoint fields in
        # ctx->args[i] (struct bpf_raw_tracepoint_args).
        params.each_with_index.map do |(_n, t), i|
          c_type = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param type #{t.inspect} not supported")
          "(#{c_type})ctx->args[#{i}]"
        end
      when :usdt
        # USDT args come from bpf_usdt_arg(ctx, i, &val) (<bpf/usdt.bpf.h>).
        # The helper writes to a long*, so we declare a temporary, call the
        # helper, then cast/forward to the user's typed param. The actual
        # statements get emitted as a "prologue" by extract_attach_prologue;
        # the values returned here are just the temp-var references.
        ctx.uses_usdt = true if ctx
        params.each_with_index.map do |(_n, t), i|
          c_type = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param type #{t.inspect} not supported")
          "(#{c_type})_usdt_arg#{i}"
        end
      when :tracepoint
        cat = attach[:tp_category]
        ev  = attach[:tp_event]
        if cat == "syscalls" && (ev.start_with?("sys_enter_") || ev.start_with?("sys_exit_"))
          struct_name = ev.start_with?("sys_enter_") ? "trace_event_raw_sys_enter" : "trace_event_raw_sys_exit"
          params.each_with_index.map do |(_n, t), i|
            c_type = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param type #{t.inspect} not supported")
            "(#{c_type})((struct #{struct_name} *)ctx)->args[#{i}]"
          end
        else
          extract_named_tracepoint_args(cat, ev, params)
        end
      when :xdp
        # no per-param extraction yet. Packet length / header bytes
        # will arrive via dedicated builtins (e.g. pkt_len) in a follow-up.
        unless params.empty?
          raise UnsupportedNode,
                "xdp__#{attach[:xdp_name]}: parameters not supported " \
                "(use top-level ivars + builtins for packet access)"
        end
        []
      when :tc_ingress, :tc_egress
        # same policy as XDP — no per-param extraction.
        # pkt_* builtins receive ctx (struct __sk_buff *) implicitly.
        unless params.empty?
          raise UnsupportedNode,
                "tc__*__#{attach[:tc_name]}: parameters not supported"
        end
        []
      when :sk_reuseport
        # sk_reuseport programs see ctx (sk_reuseport_md *) implicitly.
        # Per-param extraction would need a new family of builtins (e.g.
        # reuseport_hash for ctx->hash); not in the MVP.
        unless params.empty?
          raise UnsupportedNode,
                "sk_reuseport__#{attach[:sr_name]}: parameters not supported"
        end
        []
      when :sk_msg, :sk_skb_verdict, :sk_skb_parser
        # sockmap programs see ctx (sk_msg_md or __sk_buff) implicitly.
        unless params.empty?
          raise UnsupportedNode,
                "#{attach[:sec]} prog #{attach[:sm_name]}: parameters not supported"
        end
        []
      else
        []
      end
    end

    # prologue statements (`long _usdt_argN; bpf_usdt_arg(ctx, N, &_);`)
    # to emit BEFORE calling _inner. Empty for non-USDT attach kinds. Returns
    # an Array<String> (one C statement per element).
    def extract_attach_prologue(attach, params)
      case attach[:kind]
      when :usdt
        params.each_with_index.map do |(_n, _t), i|
          # bpf_usdt_arg returns 0 on success, -1 if the argument index is
          # out of range. We don't bail on -1 — the temporary remains 0,
          # which is a reasonable fallback for missing args.
          "long _usdt_arg#{i} = 0; (void)bpf_usdt_arg(ctx, #{i}, &_usdt_arg#{i});"
        end
      else
        []
      end
    end

    # hardcoded mapping of tracepoint event -> available field names + types.
    # Extending this requires adding entries (eventually we'd lookup via BTF at
    # codegen time). Field names must match the kernel's trace_event_raw_<event>
    # struct. Param matching is **by name** — declare Ruby block params with the
    # same name as the struct field you want.
    TRACEPOINT_FIELDS = {
      "sched/sched_switch" => {
        "prev_pid" => "int", "prev_prio" => "int", "prev_state" => "int",
        "next_pid" => "int", "next_prio" => "int",
      },
      "sched/sched_wakeup" => {
        "pid" => "int", "prio" => "int", "target_cpu" => "int",
      },
      "sched/sched_process_exit" => {
        "pid" => "int", "prio" => "int",
      },
      # kernel slab allocation tracepoints (bcc memleak). ptr / sizes are
      # 8-byte fields read as __s64; a pointer fits losslessly in a signed 64.
      "kmem/kmalloc" => {
        "call_site" => "int", "ptr" => "int", "bytes_req" => "int",
        "bytes_alloc" => "int", "gfp_flags" => "int", "node" => "int",
      },
      "kmem/kfree" => {
        "call_site" => "int", "ptr" => "int",
      },
      # slab cache allocation (bcc slabratetop). bytes_alloc = object size;
      # the `name` field is __data_loc (a string) and is skipped.
      "kmem/kmem_cache_alloc" => {
        "call_site" => "int", "ptr" => "int", "bytes_req" => "int",
        "bytes_alloc" => "int", "gfp_flags" => "int", "node" => "int",
      },
      # TCP state transitions (bcc tcplife / tcpconnect / tcpaccept).
      # skaddr is the sock pointer (a stable per-connection key); saddr/daddr are
      # __u8[4] arrays read as a u32 (network byte order) via the "ipv4" type.
      "sock/inet_sock_set_state" => {
        "skaddr" => "int", "oldstate" => "int", "newstate" => "int",
        "sport" => "int", "dport" => "int", "family" => "int", "protocol" => "int",
        "saddr" => "ipv4", "daddr" => "ipv4",
      },
      # hard/soft IRQ handlers (bcc hardirqs / softirqs). entry/exit pairs;
      # the handler runs to completion on one CPU, so cpu_id() keys the latency.
      "irq/irq_handler_entry" => { "irq" => "int" },
      "irq/irq_handler_exit"  => { "irq" => "int", "ret" => "int" },
      "irq/softirq_entry"     => { "vec" => "int" },
      "irq/softirq_exit"      => { "vec" => "int" },
    }.freeze

    # a few tracepoints are declared via DECLARE_EVENT_CLASS, so their BTF
    # struct is named after the *class*, not the event (e.g. sched_wakeup,
    # sched_wakeup_new and sched_waking all share trace_event_raw_sched_wakeup_template).
    # When the event name doesn't match its struct, map it here; otherwise the
    # default `trace_event_raw_<event>` is used.
    TRACEPOINT_STRUCT_OVERRIDE = {
      "sched/sched_wakeup" => "trace_event_raw_sched_wakeup_template",
      # softirq_entry and softirq_exit share DECLARE_EVENT_CLASS(softirq).
      "irq/softirq_entry"  => "trace_event_raw_softirq",
      "irq/softirq_exit"   => "trace_event_raw_softirq",
    }.freeze

    # lazily-memoized BTF schema reader (best-effort; no-op when
    # BTF/bpftool is unavailable, e.g. the host macOS unit-test run).
    def btf_schema
      @btf_schema ||= BtfSchema.new
    end

    # resolve declared kprobe/fentry params to the kernel
    # function's argument positions by NAME via BTF. Returns an array of
    # zero-based arg indices (same length/order as `params`) when BTF knows the
    # function AND every declared name is a real parameter; otherwise nil so the
    # caller falls back to positional extraction (so approximate names / no-BTF
    # hosts are unchanged). This lets `def kprobe__tcp_sendmsg(size)` resolve to
    # the real 3rd arg instead of silently reading PARM1.
    def btf_arg_indices(func, params)
      return nil if func.nil? || func.empty? || params.empty?
      names = btf_schema.func_params(func)
      return nil unless names
      idxs = params.map { |(n, _t)| names.index(n) }
      return nil if idxs.any?(&:nil?)
      idxs
    end

    # The kprobe/kretprobe target function name (sec is "kprobe/<func>").
    def kprobe_target_func(attach)
      sec = attach[:sec].to_s
      sec.include?("/") ? sec.split("/", 2).last : nil
    end

    def extract_named_tracepoint_args(cat, ev, params)
      key = "#{cat}/#{ev}"
      table_fields = TRACEPOINT_FIELDS[key]      # hand-written fallback
      btf = btf_schema

      # Struct to cast ctx to: a *complete* trace_event_raw_<event> from BTF wins;
      # otherwise the template-override table (DECLARE_EVENT_CLASS cases); else the
      # default name. (BTF auto-derivation, tables as fallback.)
      struct_name = (btf.available? ? btf.tracepoint_struct(ev) : nil) ||
                    TRACEPOINT_STRUCT_OVERRIDE[key] ||
                    "trace_event_raw_#{ev}"

      btf_fields = btf.available? ? btf.struct_fields(struct_name) : nil
      unless table_fields || btf_fields
        raise UnsupportedNode,
              "tracepoint #{key} field schema unknown — add it to TRACEPOINT_FIELDS or use sys_enter_*/sys_exit_* " \
              "(BTF auto-derivation found no complete struct for #{struct_name.inspect})"
      end

      params.map do |(name, _t)|
        # BTF-derived type wins; fall back to the hand-written table entry.
        field_type = (btf_fields && btf_fields[name]) || (table_fields && table_fields[name])
        unless field_type
          avail = (btf_fields || table_fields || {}).keys.join(", ")
          raise UnsupportedNode,
                "tracepoint #{key} has no field #{name.inspect} (available: #{avail})"
        end
        if field_type == "ipv4"
          # a 4-byte address array (e.g. saddr[4]/daddr[4]) read as a
          # single u32 (network byte order). The tracepoint ctx fields are
          # directly accessible, so a plain reinterpret-load is verifier-safe.
          "(__s64)(*(__u32 *)(((struct #{struct_name} *)ctx)->#{name}))"
        else
          c_type = SPINEL_TYPE_TO_C[field_type] ||
                   raise(UnsupportedNode, "param #{name}: type #{field_type.inspect} not supported")
          "(#{c_type})((struct #{struct_name} *)ctx)->#{name}"
        end
      end
    end

    def emit_method(ctx, mi)
      func_name = method_func_name(mi)

      # pure-XDP TCP slice. The Ruby body is treated as a marker — the
      # entire state machine + maps + helpers are emitted via
      # emit_tcp_slice_bundle (sections-level). Here we just emit the SEC("xdp")
      # entry that calls into spnl_tcp_slice_main.
      ts_attach = mi.scope == :top_level ? detect_attach(mi.method_name) : nil
      if ts_attach && ts_attach[:kind] == :xdp_tcp_slice
        ctx.uses_tcp_slice = true
        return <<~ENTRY
          /* pure-XDP TCP slice attach for xdp__tcp_slice__#{ts_attach[:ts_name]} */
          SEC("xdp")
          int #{func_name}(struct xdp_md *ctx)
          {
              return spnl_tcp_slice_main(ctx);
          }
        ENTRY
      end

      # struct_ops member functions (tcp_cc / sched_ext / qdisc).
      # The Ruby method body is lowered into an `_inner` function taking
      # `__s64` versions of all kernel-pointer args, then a typed
      # BPF_PROG-wrapped entry-point is emitted with SEC("struct_ops/<m>").
      if ts_attach && STRUCT_OPS_REGISTRY.key?(ts_attach[:kind])
        return emit_struct_ops_member(ctx, mi, ts_attach)
      end

      # xdp_tail__<name> — track this method as a tail-call target.
      # The wrapper is still SEC("xdp") (so libbpf loads it as an XDP
      # prog), but glue.c will skip auto-attach and instead insert the
      # prog into spnl_prog_array at the slot matching declaration order.
      if ts_attach && ts_attach[:kind] == :xdp_tail
        ctx.uses_tail_call = true
        ctx.tail_targets ||= []
        ctx.tail_targets << ts_attach[:xt_name] unless ctx.tail_targets.include?(ts_attach[:xt_name])
        # fall through to standard XDP wrapper emission
      end

      # `on :timer, every: N.<unit> do ... end` -> bpf_timer-backed
      # periodic callback. Emit:
      #   - struct spnl_timer_value { struct bpf_timer t; } in spnl_timer_map
      #   - static int spnl_timer_cb_<name>(...) callback (handler body + re-arm)
      #   - SEC("syscall") int spnl_timer_arm_<name>(void *ctx) that initializes
      #     the timer and starts it once at load time (libbpf bpf_prog_test_run)
      if ts_attach && ts_attach[:kind] == :timer
        ctx.uses_timer = true
        ctx.timer_handler_name = ts_attach[:name]
        ctx.timer_interval_ns = mi.dsl_timer_interval_ns ||
          raise(UnsupportedNode, "timer handler #{mi.method_name} missing interval")
        # void return — verifier requires bpf_timer callbacks to return
        # literal 0, so we emit our own `return 0;` after the body and
        # don't want MethodEmitter to insert a `return <last_expr>;`.
        body_emitter = MethodEmitter.new(ctx: ctx, mi: mi, return_type: "void", params: [])
        body_lines = body_emitter.emit
        interval = ctx.timer_interval_ns
        name = ts_attach[:name]
        return <<~TIMER
          /* bpf_timer callback for on :timer, every: #{interval} ns.
           * The verifier requires bpf_timer callbacks to return literal 0
           * (the body's return value is ignored, which matches the Ruby
           * semantic of `on :timer do ... end` having no return value). */
          static int spnl_timer_cb_#{name}(void *map, int *key, struct spnl_timer_value *v)
          {
              (void)map; (void)key;
          #{body_lines.map { |ln| "    " + ln }.join("\n")}
              bpf_timer_start(&v->t, #{interval}ULL, 0);
              return 0;
          }

          /* arm prog — fired once by userspace at load time via
           * bpf_prog_test_run. SEC("syscall") requires `__u64 *ctx` so
           * libbpf can size the arg from BTF. */
          SEC("syscall")
          int spnl_timer_arm_#{name}(__u64 *ctx)
          {
              __u32 _k = 0;
              struct spnl_timer_value *_v = bpf_map_lookup_elem(&spnl_timer_map, &_k);
              if (!_v) return 0;
              bpf_timer_init(&_v->t, &spnl_timer_map, 1 /* CLOCK_MONOTONIC */);
              bpf_timer_set_callback(&_v->t, spnl_timer_cb_#{name});
              bpf_timer_start(&_v->t, #{interval}ULL, 0);
              (void)ctx;
              return 0;
          }
        TIMER
      end

      # USER_RINGBUF callback. The Ruby method becomes a static
      # `long cb(struct bpf_dynptr *, void *)` invoked by
      # bpf_user_ringbuf_drain — no SEC, no userspace-visible name. The
      # body sees the first dynptr-read u64 as the param value.
      if ts_attach && ts_attach[:kind] == :user_ringbuf
        ctx.uses_user_ringbuf = true
        ctx.user_ringbuf_cb_name = ts_attach[:cb_name]
        params = method_params(ctx, mi)
        raise UnsupportedNode, "user_ringbuf__#{ts_attach[:cb_name]} expects 1 param (the value)" if params.length != 1
        pname, ptype = params[0]
        c_type = SPINEL_TYPE_TO_C[ptype] || raise(UnsupportedNode, "user_ringbuf param type #{ptype.inspect} not supported")
        # void return — verifier requires bpf_user_ringbuf_drain callbacks
        # to return literal 0/1, so we emit our own `return 0;` after the
        # body and don't want MethodEmitter to insert `return <last_expr>;`.
        # (an earlier demo worked because its last stmt was `spnl_emit(value)`
        # which already returns the literal "0".)
        body_emitter = MethodEmitter.new(ctx: ctx, mi: mi, return_type: "void", params: params)
        body_lines = body_emitter.emit
        return <<~CB
          /* user_ringbuf callback for user_ringbuf__#{ts_attach[:cb_name]} */
          static long spnl_user_ringbuf_cb_#{ts_attach[:cb_name]}(struct bpf_dynptr *dynptr, void *_uctx)
          {
              #{c_type} #{pname} = 0;
              bpf_dynptr_read(&#{pname}, sizeof(#{pname}), dynptr, 0, 0);
              (void)_uctx;
          #{body_lines.map { |ln| "    " + ln }.join("\n")}
              return 0;
          }
        CB
      end

      return_type_ruby = method_return_type(ctx, mi)
      # spinel widens the return to nullable (`int?`) whenever a value can
      # be nil — most commonly when the body is `if … end` without an `else`
      # (the implicit nil branch), which is the canonical attach-handler shape
      # (`if cond; spnl_emit(x); end`). Nullability is irrelevant to lowering
      # (nil -> 0 / __s64). Strip the `?` first so the base type drives both the
      # inner C signature and MethodEmitter#finalize_return; otherwise
      # SPINEL_TYPE_TO_C falls back to "void" for the signature while the
      # emitter still emits `return <if-value>;` -> a void/non-void mismatch
      # that clang rejects with -Wreturn-mismatch.
      return_type_ruby = return_type_ruby[0..-2] if return_type_ruby.end_with?("?")
      return_type = NIL_TYPE_MAP[return_type_ruby] || return_type_ruby
      c_inner_ret = SPINEL_TYPE_TO_C[return_type] || "void"

      params = method_params(ctx, mi)
      # for XDP and TC, prepend an implicit `<ctx_type> ctx` so
      # pkt_* builtins inside the body can read packet headers. Other attach
      # kinds (kprobe / tracepoint / syscall) don't need this.
      pre_attach = mi.scope == :top_level ? detect_attach(mi.method_name) : nil
      ctx_kind   = pre_attach && pre_attach[:kind]
      ctx_prefix =
        case ctx_kind
        when :xdp, :xdp_tail         then "struct xdp_md *ctx"
        when :tc_ingress, :tc_egress then "struct __sk_buff *ctx"
        when :sk_reuseport           then "struct sk_reuseport_md *ctx"
        when :sk_msg                 then "struct sk_msg_md *ctx"
        when :sk_skb_verdict, :sk_skb_parser then "struct __sk_buff *ctx"
        when :sock_ops               then "struct bpf_sock_ops *ctx"
        when :cgroup_connect4, :cgroup_bind4 then "struct bpf_sock_addr *ctx"
        when :iter_task              then "struct bpf_iter__task *ctx"
        # raw_tp uses arg extraction (ctx->args[i]) like kprobe/fentry,
        # so it is NOT in ctx_prefix — the inner takes the extracted values.
        when :socket_filter, :flow_dissector then "struct __sk_buff *ctx"
        when :sk_lookup              then "struct bpf_sk_lookup *ctx"
        end
      # stack_id() / user_stack_id() call bpf_get_stackid(ctx, ...) inside
      # the inner function, but kprobe/uprobe/USDT/tracepoint/fentry/fexit
      # normally extract typed args from ctx in the wrapper and pass values to
      # the inner — ctx itself isn't forwarded. When the unit uses stack_id,
      # forward ctx to the inner so the helper can call bpf_get_stackid.
      # perf_event programs receive `struct bpf_perf_event_data *` and
      # the typical body uses stack_id() — forward ctx unconditionally for
      # this kind so the perf-sample callbacks can capture stacks.
      if !ctx_prefix && (ctx_kind == :perf_event ||
         (ctx.uses_stack_trace &&
          [:kprobe, :kretprobe, :uprobe, :uretprobe,
           :usdt, :tracepoint, :fentry, :fexit].include?(ctx_kind)))
        ct = pre_attach[:ctx_type].to_s
        ctx_prefix = "#{ct}ctx" unless ct.empty?
      end

      params_decl =
        if params.empty? && !ctx_prefix
          "void"
        else
          declared = params.map do |n, t|
            ct = SPINEL_TYPE_TO_C[t] || raise(UnsupportedNode, "param #{n}: type #{t.inspect} not supported")
            "#{ct} #{n}"
          end
          [ctx_prefix, *declared].compact.join(", ")
        end

      # emit the implementation as a static __noinline function. Both
      # the SEC("syscall") wrapper and any BPF-to-BPF caller dispatch into
      # this same function.
      body_emitter = MethodEmitter.new(ctx: ctx, mi: mi, return_type: return_type, params: params)
      body_lines = body_emitter.emit

      inner = <<~INNER
        /* impl: #{mi.qualified_name} : #{return_type}#{params.empty? ? "" : "  params: #{params.map { |n, t| "#{n}: #{t}" }.join(", ")}"} */
        static __noinline #{c_inner_ret} #{func_name}_inner(#{params_decl})
        {
        #{body_lines.map { |ln| "    " + ln }.join("\n")}
        }
      INNER

      # SEC + signature depend on method-name attach convention.
      # attach methods can declare params; codegen extracts them from
      # the kernel-supplied context (pt_regs for kprobe, args[] for tracepoint).
      attach = mi.scope == :top_level ? detect_attach(mi.method_name) : nil
      if attach
        # ensure usdt.bpf.h is included even when the USDT handler has
        # zero params (extract_attach_args wouldn't be called in that case).
        ctx.uses_usdt = true if attach[:kind] == :usdt
        sec_line = %Q(SEC("#{attach[:sec]}"))
        wrapper_sig = "int #{func_name}(#{attach[:ctx_type]}ctx)"

        extractors =
          if params.empty?
            []
          else
            extract_attach_args(attach, params, ctx)
          end
        # USDT needs prologue statements (bpf_usdt_arg calls) before
        # the inner call. Other kinds return [].
        prologue = params.empty? ? [] : extract_attach_prologue(attach, params)

        # XDP / TC / sk_reuseport / sk_msg / sk_skb inner
        # has an implicit ctx prefix; forward it.
        # same for kprobe-family when uses_stack_trace (so bpf_get_stackid
        # can be called inside the inner).
        # perf_event inner always receives ctx (sample data + regs).
        call_args = []
        if [:xdp, :xdp_tail, :tc_ingress, :tc_egress, :sk_reuseport,
            :sk_msg, :sk_skb_verdict, :sk_skb_parser, :sock_ops,
            :cgroup_connect4, :cgroup_bind4, :iter_task,
            :socket_filter, :flow_dissector, :sk_lookup,
            :perf_event].include?(attach[:kind]) ||
           (ctx.uses_stack_trace &&
            [:kprobe, :kretprobe, :uprobe, :uretprobe,
             :usdt, :tracepoint, :fentry, :fexit].include?(attach[:kind]))
          call_args << "ctx"
        end
        call_args.concat(extractors)
        inner_call =
          if call_args.empty?
            "#{func_name}_inner()"
          else
            "#{func_name}_inner(#{call_args.join(", ")})"
          end

        propagating_retval = [
          :xdp, :xdp_tail, :tc_ingress, :tc_egress, :sk_reuseport,
          :sk_msg, :sk_skb_verdict, :sk_skb_parser,
          # LSM returns the access decision (0 allow / -errno deny) and
          # fmod_ret returns the (modified) function result — both propagated.
          :lsm, :fmod_ret,
          # cgroup connect4/bind4 return 1 (allow) / 0 (deny).
          :cgroup_connect4, :cgroup_bind4,
          # socket_filter (bytes kept), flow_dissector (BPF_OK/DROP),
          # sk_lookup (SK_PASS/SK_DROP) all propagate their verdict.
          :socket_filter, :flow_dissector, :sk_lookup
        ].include?(attach[:kind])

        wrapper_body = ["(void)ctx;"] + prologue
        # bpf_iter is called once per object + a final NULL terminator;
        # skip the body on that terminator so counters don't over-count.
        wrapper_body << "if (!ctx->task) return 0;" if attach && attach[:kind] == :iter_task
        if propagating_retval
          # XDP wrapper propagates XDP_PASS / DROP / etc.
          # TC wrapper propagates TC_ACT_OK / TC_ACT_SHOT / etc.
          # sk_reuseport / sk_msg / sk_skb wrapper propagates SK_PASS / SK_DROP.
          if c_inner_ret == "void"
            label =
              case attach[:kind]
              when :xdp                                              then "xdp__#{attach[:xdp_name]}"
              when :sk_reuseport                                     then "sk_reuseport__#{attach[:sr_name]}"
              when :sk_msg                                           then "sk_msg__#{attach[:sm_name]}"
              when :sk_skb_verdict                                   then "sk_skb__verdict__#{attach[:sm_name]}"
              when :sk_skb_parser                                    then "sk_skb__parser__#{attach[:sm_name]}"
              when :lsm                                              then "lsm__#{attach[:lsm_hook]}"
              when :fmod_ret                                         then "fmod_ret__#{attach[:fmod_func]}"
              when :socket_filter                                    then "socket_filter__#{attach[:sf_name]}"
              when :flow_dissector                                   then "flow_dissector__#{attach[:fd_name]}"
              when :sk_lookup                                        then "sk_lookup__#{attach[:skl_name]}"
              else                                                        "tc__*__#{attach[:tc_name]}"
              end
            allowed =
              case attach[:kind]
              when :xdp                                              then "XDP_PASS / XDP_DROP / XDP_TX / XDP_REDIRECT"
              when :sk_reuseport, :sk_msg, :sk_skb_verdict, :sk_skb_parser then "SK_PASS / SK_DROP"
              when :cgroup_connect4, :cgroup_bind4                   then "1 (allow) / 0 (deny)"
              when :lsm                                              then "0 (allow) / negative errno (deny)"
              when :fmod_ret                                         then "the (modified) return value"
              when :socket_filter                                    then "the number of bytes to keep (0 = drop)"
              when :flow_dissector                                   then "BPF_OK / BPF_DROP"
              when :sk_lookup                                        then "SK_PASS / SK_DROP"
              else                                                        "TC_ACT_OK / TC_ACT_SHOT / TC_ACT_*"
              end
            raise UnsupportedNode, "#{label}: body must return an int (#{allowed})"
          end
          wrapper_body << "return (int)#{inner_call};"
        else
          if c_inner_ret == "void"
            wrapper_body << "#{inner_call};"
          else
            wrapper_body << "(void)#{inner_call};"
          end
          wrapper_body << "return 0;"
        end
      else
        sec_line = 'SEC("syscall")'
        wrapper_sig = params.empty? ? "int #{func_name}(void *ctx)" : "int #{func_name}(struct #{func_name}_ctx *ctx)"
        call_args = params.map { |n, _| "ctx->#{n}" }.join(", ")
        wrapper_body =
          if c_inner_ret == "void"
            ["#{func_name}_inner(#{call_args});", "return 0;"]
          else
            ["return (int)#{func_name}_inner(#{call_args});"]
          end
      end

      wrapper = <<~WR
        /* entry wrapper: #{mi.qualified_name}#{attach ? " [#{attach[:kind]} -> #{attach[:sec]}]" : ""} */
        #{sec_line}
        #{wrapper_sig}
        {
        #{wrapper_body.map { |ln| "    " + ln }.join("\n")}
        }
      WR

      inner + "\n" + wrapper
    end

    # emit `struct <func>_ctx { __s64 a; __s64 b; ... };` for a method
    # with parameters; return nil if the method has no params.
    def emit_ctx_struct(ctx, mi)
      params = method_params(ctx, mi)
      return nil if params.empty?
      func_name = method_func_name(mi)
      fields = params.map do |name, type|
        c_type = SPINEL_TYPE_TO_C[type] || raise(UnsupportedNode, "param #{name}: type #{type.inspect} not supported")
        "    #{c_type} #{name};"
      end
      <<~STRUCT
        /* ctx for #{mi.qualified_name} — userspace fills before bpf_prog_test_run */
        struct #{func_name}_ctx {
        #{fields.join("\n")}
        };
      STRUCT
    end

    # Return [[name, type], ...] for the method's params, or [].
    # names are c_safe-wrapped so C keywords get suffix `_`. All
    # downstream emit sites (the `_inner` signature, ctx struct, ctx[i]
    # extractors, MethodEmitter's @param_names) see the same sanitized name,
    # and MethodEmitter's local_read/write sanitize on AST extraction so the
    # name comparisons remain consistent.
    def method_params(ctx, mi)
      raw = raw_method_params(ctx, mi)
      raw.map { |n, t| [c_safe(n), t] }
    end

    def raw_method_params(ctx, mi)
      ir = ctx.ir
      case mi.scope
      when :top_level
        # methods synthesized from a `class Foo < BPF::Bar` block
        # have their params in @cls_meth_params, not the top-level
        # @meth_param_names table. Detect by dsl_class_idx and route the
        # lookup through the class arrays.
        if mi.respond_to?(:dsl_class_idx) && mi.dsl_class_idx
          ci = mi.dsl_class_idx
          m_names  = ((ir.sa("@cls_meth_names")  || [])[ci] || "").split(";", -1)
          m_pnames = ((ir.sa("@cls_meth_params") || [])[ci] || "").split("|", -1)
          m_ptypes = ((ir.sa("@cls_meth_ptypes") || [])[ci] || "").split("|", -1)
          mi_idx = m_names.index(mi.dsl_orig_name)
          return [] unless mi_idx
          pn = (m_pnames[mi_idx] || "").split(",", -1)
          pt = (m_ptypes[mi_idx] || "").split(",", -1)
          return pn.zip(pt).reject { |n, _| n.nil? || n.empty? }
        end

        # methods from a `module Foo; include BPF::Bar; end` block
        # aren't in spinel's IR at all — walk the AST DefNode directly.
        # All params default to int (the only type spinel-ebpf currently
        # passes through anyway); future work could infer from body refs.
        # also handle BlockNode (from `on :kind do |arg| ... end`).
        # BlockNode wraps params in a BlockParametersNode, so we hop one
        # extra ref to reach the inner ParametersNode whose requireds[]
        # carries the RequiredParameterNode list.
        if mi.respond_to?(:dsl_ast_def_id) && mi.dsl_ast_def_id
          ast = ctx.ast
          params_id = ast.ref(mi.dsl_ast_def_id, "parameters", default: -1)
          return [] if params_id < 0
          params_node = ast.node(params_id)
          if params_node && params_node.type == "BlockParametersNode"
            params_id = ast.ref(params_id, "parameters", default: -1)
            return [] if params_id < 0
          end
          pn = ast.array(params_id, "requireds", default: []).map do |pid|
            ast.str_attr(pid, "name", default: "")
          end.reject(&:empty?)
          return pn.map { |n| [n, "int"] }
        end

        # See partition.rb#signature_types: ir.sa already splits on "|" and
        # pads empties. A second flat_map(split("|", -1)) would drop the
        # empties (Ruby's "".split("|", -1) == []) and misalign idx.
        meth_names = ir.sa("@meth_names") || []
        idx = meth_names.index(mi.method_name)
        return [] unless idx
        names = ir.sa("@meth_param_names") || []
        types = ir.sa("@meth_param_types") || []
        return [] if names[idx].nil? || names[idx].empty?
        pn = names[idx].split(",", -1)
        pt = (types[idx] || "").split(",", -1)
        pn.zip(pt).reject { |n, _| n.nil? || n.empty? }
      when :class
        cls_names = ir.sa("@cls_names") || []
        ci = cls_names.index(mi.class_name)
        return [] unless ci
        # NOTE: @cls_meth_names / _bodies / _returns use ";" between methods;
        # @cls_meth_params / _ptypes use "|" instead (wart in spinel's IR,
        # documented inline so future hands don't repeat the mistake).
        m_names  = ((ir.sa("@cls_meth_names")  || [])[ci] || "").split(";", -1)
        m_pnames = ((ir.sa("@cls_meth_params") || [])[ci] || "").split("|", -1)
        m_ptypes = ((ir.sa("@cls_meth_ptypes") || [])[ci] || "").split("|", -1)
        mi_idx = m_names.index(mi.method_name)
        return [] unless mi_idx
        pn = (m_pnames[mi_idx] || "").split(",", -1)
        pt = (m_ptypes[mi_idx] || "").split(",", -1)
        pn.zip(pt).reject { |n, _| n.nil? || n.empty? }
      else
        []
      end
    end

    # scan all top-level :ebpf methods' bodies for instance-variable
    # references; return the set of ivar names found (e.g. {"@open_count"}).
    # Only top-level ivars are eligible — class methods' ivars belong to the
    # class instance and are handled by emit_ivar_maps.
    def collect_toplevel_ivars_used(ast, ebpf_methods)
      ivars = Set.new
      ebpf_methods.each do |mi|
        next unless mi.scope == :top_level
        next if mi.body_id < 0
        walk = lambda do |nid|
          return if nid < 0
          n = ast.node(nid)
          return unless n
          return if %w[DefNode ClassNode ModuleNode].include?(n.type)
          if %w[InstanceVariableReadNode InstanceVariableWriteNode InstanceVariableOperatorWriteNode].include?(n.type)
            nm = n.attrs.fetch("name", nil)
            ivars << nm if nm
          end
          n.refs.each_value   { |c| walk.call(c) if c.is_a?(Integer) }
          n.arrays.each_value { |a| a.each { |c| walk.call(c) if c.is_a?(Integer) } }
        end
        walk.call(mi.body_id)
      end
      ivars
    end

    def emit_toplevel_ivar_maps(ctx, ivars)
      blocks = ivars.sort.map do |ivar|
        map = top_ivar_map_name(ctx.unit_name, ivar)
        <<~MAP
          /* top-level ivar #{ivar} : int */
          struct {
              __uint(type, BPF_MAP_TYPE_HASH);
              __type(key, __u32);
              __type(value, __s64);
              __uint(max_entries, 1);
          } #{map} SEC(".maps");
        MAP
      end
      blocks.join("\n")
    end

    # bpf_arena map + an arena-resident u64[512] array (= 1 page) backing
    # arena_set/arena_get. Unlike a HASH/ARRAY map, the arena is a sparse,
    # mmap-able shared-memory region: the array lives in the arena address space
    # (__arena), so the BPF program reads/writes it through normal pointer
    # dereferences (no bpf_map_*_elem helper) and userspace can mmap the same
    # bytes. libbpf places the global into the arena's pages at load time, so no
    # runtime bpf_arena_alloc_pages is needed. Requires clang -mcpu=v3 (added by
    # the build when the .bpf.c references address_space(1)).
    ARENA_SLOTS = 512 # one 4 KiB page / sizeof(__u64)
    def emit_arena_map(ctx)
      <<~ARENA
        /* bpf_arena — sparse, mmap-able shared memory backing arena_set/get. */
        #ifndef __arena
        #define __arena __attribute__((address_space(1)))
        #endif

        struct {
            __uint(type, BPF_MAP_TYPE_ARENA);
            __uint(map_flags, BPF_F_MMAPABLE);
            __uint(max_entries, 1); /* pages; 1 page = #{ARENA_SLOTS} u64 slots */
        #if defined(__TARGET_ARCH_arm64)
            __ulong(map_extra, (1ull << 32)); /* user mmap base (arm64) */
        #else
            __ulong(map_extra, (1ull << 44)); /* user mmap base (x86-64) */
        #endif
        } #{ctx.unit_name}_arena SEC(".maps");

        /* Lives in the arena (placed at load time); index masked to stay in-page. */
        __u64 __arena #{ctx.unit_name}_arena_data[#{ARENA_SLOTS}];
      ARENA
    end

    # ---------- Roadmap #2: flow-state maps ----------

    # Infer flow maps from usage: scan :ebpf method bodies for
    # flow_get(:name, :field) / flow_set(:name, :field, v) / flow_del(:name)
    # CallNodes. Returns Hash<name(String) => [field(String) sorted]>.
    # (Explicit `flow_map :name, [...]` declaration is a future addition pending
    #  confirmation of the ArrayNode .ast representation in a built spinel.)
    def collect_flow_maps(ast, ebpf_methods)
      maps = {}
      ebpf_methods.each do |mi|
        next if mi.body_id < 0
        walk = lambda do |nid|
          return if nid < 0
          n = ast.node(nid)
          return unless n
          return if %w[DefNode ClassNode ModuleNode].include?(n.type)
          if n.type == "CallNode" && FLOW_BUILTINS.include?(n.attrs.fetch("name", "")) &&
             n.refs.fetch("receiver", -1) < 0
            nm, fld = flow_call_name_and_field(ast, n)
            if nm
              (maps[nm] ||= [])
              maps[nm] << fld if fld && !maps[nm].include?(fld)
            end
          end
          n.refs.each_value   { |c| walk.call(c) if c.is_a?(Integer) }
          n.arrays.each_value { |a| a.each { |c| walk.call(c) if c.is_a?(Integer) } }
        end
        walk.call(mi.body_id)
      end
      maps.transform_values(&:sort)
    end

    FLOW_BUILTINS = %w[flow_get flow_set flow_del].freeze

    # [name, field] from a flow_* CallNode. field is nil for flow_del / when absent.
    def flow_call_name_and_field(ast, call_node)
      args_id = call_node.refs.fetch("arguments", -1)
      return [nil, nil] if args_id < 0
      an = ast.node(args_id)
      return [nil, nil] unless an && an.type == "ArgumentsNode"
      args = an.arrays.fetch("arguments", [])
      return [nil, nil] if args.empty?
      name_node = ast.node(args[0])
      return [nil, nil] unless name_node && name_node.type == "SymbolNode"
      name = name_node.attrs.fetch("value", "")
      return [nil, nil] if name.empty?
      field = nil
      if args.length >= 2
        fn = ast.node(args[1])
        v = (fn && fn.type == "SymbolNode") ? fn.attrs.fetch("value", "") : ""
        field = v unless v.empty?
      end
      [name, field]
    end

    def flow_key_struct_name(unit, name) = "spnl_flow_#{unit}_#{name}_k"
    def flow_val_struct_name(unit, name) = "spnl_flow_#{unit}_#{name}_v"
    def flow_map_var_name(unit, name)    = "spnl_flow_#{unit}_#{name}"
    def flow_key_fn_name(unit, name, kind) = "spnl_flow_#{unit}_#{name}_key_#{kind}"

    FLOW_MAP_MAX_ENTRIES = 65536

    # Section emitter: for each flow map, emit key struct + value struct + the
    # LRU_HASH map, then a key-extraction helper for each ctx kind it's used in.
    def emit_flow_maps(ctx)
      ctx.flow_maps.sort.map do |name, fields|
        u = ctx.unit_name
        vfields = fields.map { |f| "    __u64 #{f};" }.join("\n")
        vfields = "    __u64 _unused;" if vfields.empty?
        decl = <<~MAP
          /* Roadmap #2: per-flow state map :#{name} (4-tuple key, u64 fields). */
          struct #{flow_key_struct_name(u, name)} {
              __be32 saddr;
              __be32 daddr;
              __be16 sport;
              __be16 dport;
          };
          struct #{flow_val_struct_name(u, name)} {
          #{vfields}
          };
          struct {
              __uint(type, BPF_MAP_TYPE_LRU_HASH);
              __type(key, struct #{flow_key_struct_name(u, name)});
              __type(value, struct #{flow_val_struct_name(u, name)});
              __uint(max_entries, #{FLOW_MAP_MAX_ENTRIES});
          } #{flow_map_var_name(u, name)} SEC(".maps");
        MAP
        kinds = (ctx.flow_map_kinds[name] || []).to_a.sort
        extracts = kinds.map { |k| emit_flow_key_extract(u, name, k) }
        ([decl] + extracts).join("\n")
      end.join("\n")
    end

    # Key-extraction helper: fills the 4-tuple key from the packet (IPv4/TCP).
    # Returns 0 on success, -1 otherwise. One per ctx kind (xdp / tc).
    def emit_flow_key_extract(unit, name, kind)
      ctx_decl = kind == :xdp ? "struct xdp_md *ctx" : "struct __sk_buff *ctx"
      <<~EX
        /* Fill :#{name} flow key (saddr,daddr,sport,dport) from the packet. */
        static __noinline int #{flow_key_fn_name(unit, name, kind)}(#{ctx_decl}, struct #{flow_key_struct_name(unit, name)} *k)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return -1;
            if (eth->h_proto != bpf_htons(0x0800)) return -1;
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return -1;
            if (iph->protocol != 6) return -1;  /* IPPROTO_TCP */
            __u32 ihl = iph->ihl * 4;
            if (ihl < sizeof(*iph)) return -1;
            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + ihl);
            if ((void *)(tcp + 1) > data_end) return -1;
            k->saddr = iph->saddr;
            k->daddr = iph->daddr;
            k->sport = tcp->source;
            k->dport = tcp->dest;
            return 0;
        }
      EX
    end

    # ---------- Roadmap #3: TCP SYN-cookie helpers ----------

    # Emit the used tcp_syncookie_* helpers. Each parses eth/ip/tcp (IPv4) and
    # calls the raw syncookie kfunc. The kfuncs (bpf_tcp_raw_*_syncookie_ipv4)
    # are resolved from the unit's vmlinux.h (spinel kernel BTF) — like the TCP-slice
    # bundle, we do not redeclare them.
    def emit_syncookie_helpers(ctx)
      ctx.syncookie_used.to_a.sort.map { |which| emit_syncookie_helper(which) }.join("\n")
    end

    # `gen` -> bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl); `check` ->
    # bpf_tcp_raw_check_syncookie_ipv4(iph, tcp). Returns the kfunc result as
    # __s64 (negative on error / non-IPv4-TCP). Bounds mirror the TCP-slice bundle.
    def emit_syncookie_helper(which)
      gen = which == :gen
      fn  = gen ? "spnl_tcp_syncookie_gen" : "spnl_tcp_syncookie_check"
      call = if gen
               "bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, tcp->doff * 4)"
             else
               "bpf_tcp_raw_check_syncookie_ipv4(iph, tcp)"
             end
      <<~SC
        /* Roadmap #3: #{gen ? 'generate' : 'validate'} a TCP SYN cookie for the
         * current packet (IPv4/TCP). Returns the kfunc result (>=0) or negative
         * on error / non-TCP. kfunc resolved from vmlinux.h (spinel kernel BTF).
         * Bounds use the ACTUAL TCP header length: a typical SYN is ~74B, so
         * a fixed +60 tcp bound wrongly rejects it; the TCP-slice bundle uses +60
         * only after adjust_tail-growing the packet first. */
        static __noinline __s64 #{fn}(struct xdp_md *ctx)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return -1;
            if (eth->h_proto != bpf_htons(0x0800)) return -1;
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return -1;
            if (iph->protocol != 6) return -1;           /* IPPROTO_TCP */
            if (iph->ihl != 5) return -1;                /* standard 20-byte IP header */
            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
            if ((void *)(tcp + 1) > data_end) return -1;
            __u32 thl = tcp->doff * 4;
            if (thl < 20 || thl > 60) return -1;
            if ((char *)tcp + thl > (char *)data_end) return -1;
            return (__s64)#{call};
        }
      SC
    end

    # ---------- Roadmap #5a: payload_starts (request prefix match) ----------

    # StringNode `content` is URL-encoded in the .ast (space -> %20, CR -> %0D ...).
    # Decode %XX back to raw bytes; leave everything else verbatim.
    def url_decode(s)
      s.to_s.gsub(/%([0-9A-Fa-f]{2})/) { Regexp.last_match(1).to_i(16).chr }
    end

    PAYLOAD_PREFIX_MAX = 64

    # One matcher helper per distinct prefix (index = id). Parses eth/ip/tcp,
    # locates the TCP payload, and compares each prefix byte. Returns 1 on match,
    # 0 otherwise (non-IPv4-TCP / short payload / mismatch).
    def emit_payload_matchers(ctx)
      ctx.payload_matchers.each_with_index.map do |prefix, id|
        bytes = prefix.bytes
        cmp = bytes.each_with_index.map { |b, i| "if (p[#{i}] != #{b}) return 0;" }.join("\n            ")
        <<~PM
          /* Roadmap #5a: TCP payload starts with #{prefix.inspect[0, 40]} ? */
          static __noinline __s64 spnl_payload_match#{id}(struct xdp_md *ctx)
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return 0;
              if (eth->h_proto != bpf_htons(0x0800)) return 0;
              struct iphdr *iph = (void *)(eth + 1);
              if ((void *)(iph + 1) > data_end) return 0;
              if (iph->protocol != 6) return 0;  /* IPPROTO_TCP */
              __u32 ihl = iph->ihl * 4;
              if (ihl < sizeof(*iph)) return 0;
              struct tcphdr *tcp = (struct tcphdr *)((char *)iph + ihl);
              if ((void *)(tcp + 1) > data_end) return 0;
              __u32 thl = tcp->doff * 4;
              if (thl < 20) return 0;
              const char *p = (const char *)tcp + thl;
              if ((void *)(p + #{bytes.length}) > data_end) return 0;
              #{cmp}
              return 1;
          }
        PM
      end.join("\n")
    end

    # ---------- Roadmap #4: tcp_reply_header (packet-write + checksum) ----------

    # Emit the tcp_reply_header helper + its checksum helpers. Turns the current
    # packet into a header-only TCP reply: swap MAC/IP/ports, set seq/ack/flags
    # (host order), normalise to a 20-byte IP header with no payload, recompute IP
    # + TCP checksums. Returns 0 on success, -1 on error (non-IPv4/TCP, IP options,
    # bounds). The caller returns XDP_TX. Mirrors the TCP-slice bundle's swap/csum.
    # IP/TCP checksum helpers shared by tcp_reply_header (#4) and tcp_reply_data
    # (#5b). Emitted once when either is used.
    def emit_reply_csum_helpers
      <<~CSUM
        /* Roadmap #4/#5b: fold a 32-bit ones-complement sum to 16 bits. */
        static __always_inline __u16 spnl_reply_csum_fold(__u32 csum)
        {
            csum = (csum & 0xffff) + (csum >> 16);
            csum = (csum & 0xffff) + (csum >> 16);
            return ~csum;
        }
        static __always_inline __u16 spnl_reply_csum_tcp(__be32 saddr, __be32 daddr,
                                                         __u32 len, __u32 csum)
        {
            __u64 s = csum;
            s += (__u32)saddr;
            s += (__u32)daddr;
            s += bpf_htons(6 + len);  /* IPPROTO_TCP */
            while (s >> 32) s = (s & 0xffffffff) + (s >> 32);
            return spnl_reply_csum_fold((__u32)s);
        }
      CSUM
    end

    def emit_tcp_reply_helper
      <<~REPLY
        /* Turn the current packet into a header-only TCP reply (seq/ack in host
         * order; flags = TCP flag byte, e.g. TCP_FLAG_SYN|TCP_FLAG_ACK). XDP only.
         * Returns 0 on success, -1 on error. Caller returns XDP_TX. */
        static __noinline __s64 spnl_tcp_reply_header(struct xdp_md *ctx, __u32 seq, __u32 ack, __u8 flags)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return -1;
            if (eth->h_proto != bpf_htons(0x0800)) return -1;
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return -1;
            if (iph->protocol != 6) return -1;     /* IPPROTO_TCP */
            if (iph->ihl != 5) return -1;          /* standard 20-byte IP header only */
            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
            if ((void *)(tcp + 1) > data_end) return -1;  /* 20 bytes available */

            /* swap MAC */
            __u8 mac[6];
            __builtin_memcpy(mac, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, mac, 6);
            /* swap IP + ports */
            __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
            __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;
            /* normalise to a 20-byte TCP header (no options) so the checksum length
             * is CONSTANT — a variable bpf_csum_diff length is rejected by the
             * verifier (it bounds-checks the max, but only the min is validated). */
            tcp->doff = 5;
            tcp->seq     = bpf_htonl(seq);
            tcp->ack_seq = bpf_htonl(ack);
            ((__u8 *)tcp)[13] = flags;
            tcp->window  = bpf_htons(65535);
            tcp->urg_ptr = 0;
            iph->tot_len = bpf_htons(20 + 20);
            iph->ttl = 64;
            iph->id  = 0;

            /* IP checksum (constant 20 bytes) */
            iph->check = 0;
            __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
            if (v < 0) return -1;
            iph->check = spnl_reply_csum_fold((__u32)v);
            /* TCP checksum (constant 20-byte header, no payload) */
            tcp->check = 0;
            v = bpf_csum_diff(0, 0, (void *)tcp, 20, 0);
            if (v < 0) return -1;
            tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 20, (__u32)v);
            return 0;
        }
      REPLY
    end

    # Roadmap #4b': INTEGRATED SYN -> SYN-ACK+cookie, mirroring the TCP-slice bundle
    # exactly: grow the SYN to a 60-byte TCP header FIRST (bpf_tcp_raw_gen_syncookie_
    # ipv4 needs the room — a short SYN makes it return < 0, confirmed in practice.
    # @ck=-1), re-acquire ctx, generate the cookie, build a doff=6 SYN-ACK with the
    # MSS option from the cookie, recompute checksums, shrink to eth+20+24. One
    # builtin = one entry-subprog sequence (the bundle's structure).
    def emit_synack_cookie_helper
      <<~SAC
        /* Build the SYN-ACK (swap, seq=cookie, ack=client_seq+1, MSS option, csums)
         * into the grown packet. Kept as a separate __always_inline helper taking
         * the re-bounded pointers — like the TCP-slice bundle's build_synack/recompute_
         * csums — so the heavy build/csum register pressure does NOT push the
         * compiler to materialise `ctx+4` for the post-grow data_end re-read
         * (verifier "modified ctx ptr"). */
        static __always_inline int spnl_synack_build(struct ethhdr *eth, struct iphdr *iph,
                                                     struct tcphdr *tcp, __u32 cookie_seq,
                                                     __u16 mss, __u32 client_seq)
        {
            __u8 mac[6];
            __builtin_memcpy(mac, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, mac, 6);
            __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
            __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;
            tcp->seq     = bpf_htonl(cookie_seq);
            tcp->ack_seq = bpf_htonl(client_seq + 1);
            tcp->doff = 6;
            ((__u8 *)tcp)[13] = 0x12;   /* SYN|ACK */
            tcp->window  = bpf_htons(65535);
            tcp->urg_ptr = 0;
            __u8 *o = (__u8 *)tcp + 20;
            o[0] = 2; o[1] = 4;          /* TCPOPT_MSS, len 4 */
            o[2] = (mss >> 8) & 0xff;
            o[3] = mss & 0xff;
            iph->tot_len = bpf_htons(20 + 24);
            iph->ttl = 64;
            iph->id  = 0;
            iph->check = 0;
            __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
            if (v < 0) return -1;
            iph->check = spnl_reply_csum_fold((__u32)v);
            tcp->check = 0;
            v = bpf_csum_diff(0, 0, (void *)tcp, 24, 0);
            if (v < 0) return -1;
            tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 24, (__u32)v);
            return 0;
        }

        /* Roadmap #4b': SYN -> SYN-ACK with a SYN cookie + MSS option, the
         * grow-to-60 / gen / build / shrink sequence. Returns 0/-1. */
        static __noinline __s64 spnl_tcp_synack_cookie(struct xdp_md *ctx)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return -1;
            if (eth->h_proto != bpf_htons(0x0800)) return -1;
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return -1;
            if (iph->protocol != 6) return -1;
            if (iph->ihl != 5) return -1;
            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
            if ((void *)(tcp + 1) > data_end) return -1;
            __u32 thl_in = tcp->doff * 4;
            if (thl_in < 20 || (char *)tcp + thl_in > (char *)data_end) return -1;

            /* grow to a 60-byte TCP header (the kfunc needs the room) */
            int delta = 60 - (int)thl_in;
            if (delta != 0 && bpf_xdp_adjust_tail(ctx, delta) != 0) return -1;
            /* compiler barrier so clang re-reads ctx->data_end with a clean
             * LDX `*(u32*)(ctx+4)` instead of materialising `r2 = ctx+4; *r2` (which
             * the verifier rejects after adjust_tail as a "modified ctx ptr"). The
             * cheap C-level workarounds (constant shrink / __always_inline build
             * split / data_end-first reorder) did NOT help; this barrier — the
             * standard idiom for post-adjust_tail re-validation — is what makes the
             * grow path load, with the existing __noinline structure untouched. */
            asm volatile("" ::: "memory");
            data     = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) return -1;
            iph = (void *)(eth + 1);
            if ((char *)iph + 60 > (char *)data_end) return -1;
            tcp = (struct tcphdr *)((char *)iph + 20);
            if ((char *)tcp + 60 > (char *)data_end) return -1;

            __s64 cookie = bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl_in);
            if (cookie < 0) return -1;
            __u16 mss = (__u16)(cookie >> 32);
            if (mss == 0) mss = 1460;
            if (spnl_synack_build(eth, iph, tcp, (__u32)cookie, mss, bpf_ntohl(tcp->seq)) < 0) return -1;

            /* shrink: after the grow the (payload-less) SYN is EXACTLY
             * eth(14)+ip(20)+tcp(60) = 94 bytes, so the delta is constant 58-94. */
            if (bpf_xdp_adjust_tail(ctx, (int)(14 + 20 + 24) - (int)(14 + 20 + 60)) != 0) return -1;
            return 0;
        }
      SAC
    end

    # Roadmap #4b: SYN-ACK with the TCP MSS option (doff=6). The SYN cookie from
    # tcp_syncookie_gen encodes the MSS in its high 32 bits; the SYN-ACK must carry
    # it so the client's return ACK validates against the cookie. seq = cookie_seq,
    # ack = client_seq + 1. Writes into the existing SYN packet (which has option
    # space), then resizes LAST (no post-adjust_tail ctx re-read).
    def emit_tcp_synack_helper
      <<~SA
        /* Roadmap #4b: turn the SYN into a SYN-ACK with the MSS option (syncookie).
         * cookie = (__s64)tcp_syncookie_gen. Returns 0/-1; caller returns XDP_TX. */
        static __noinline __s64 spnl_tcp_reply_synack(struct xdp_md *ctx, __s64 cookie)
        {
            void *data     = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return -1;
            if (eth->h_proto != bpf_htons(0x0800)) return -1;
            struct iphdr *iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end) return -1;
            if (iph->protocol != 6) return -1;
            if (iph->ihl != 5) return -1;
            struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
            if ((void *)(tcp + 1) > data_end) return -1;
            /* need 24 bytes of TCP (20 header + 4 MSS option) — SYN packets have it */
            __u8 *o = (__u8 *)tcp + 20;
            if ((void *)(o + 4) > data_end) return -1;

            __u32 cookie_seq = (__u32)cookie;
            __u16 mss = (__u16)(cookie >> 32);
            if (mss == 0) mss = 1460;
            __u32 client_seq = bpf_ntohl(tcp->seq);

            /* swap endpoints */
            __u8 mac[6];
            __builtin_memcpy(mac, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, mac, 6);
            __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
            __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;

            tcp->seq     = bpf_htonl(cookie_seq);
            tcp->ack_seq = bpf_htonl(client_seq + 1);
            tcp->doff = 6;                 /* 24-byte TCP header */
            ((__u8 *)tcp)[13] = 0x12;      /* SYN|ACK */
            tcp->window  = bpf_htons(65535);
            tcp->urg_ptr = 0;
            o[0] = 2; o[1] = 4;            /* TCPOPT_MSS, len 4 */
            o[2] = (mss >> 8) & 0xff;
            o[3] = mss & 0xff;

            iph->tot_len = bpf_htons(20 + 24);
            iph->ttl = 64;
            iph->id  = 0;

            /* checksums: IP 20 bytes, TCP 24 bytes (constant) */
            iph->check = 0;
            __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
            if (v < 0) return -1;
            iph->check = spnl_reply_csum_fold((__u32)v);
            tcp->check = 0;
            v = bpf_csum_diff(0, 0, (void *)tcp, 24, 0);
            if (v < 0) return -1;
            tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 24, (__u32)v);

            /* resize to 14 + 20 + 24 LAST (usually a shrink); no ctx re-read */
            __u32 want = sizeof(struct ethhdr) + 20 + 24;
            __u32 cur  = (__u32)((long)data_end - (long)data);
            if (cur != want && bpf_xdp_adjust_tail(ctx, (int)want - (int)cur) != 0) return -1;
            return 0;
        }
      SA
    end

    # Roadmap #5b: one data-response builder per distinct response payload. Resizes
    # the packet (bpf_xdp_adjust_tail) to eth+20+20+resp_len, RE-ACQUIRES the packet
    # pointers (adjust_tail invalidates them — the verifier crux), swaps endpoints,
    # sets seq/ack + FIN|PSH|ACK, memcpys the (compile-time) response, and recomputes
    # IP + TCP checksums (over the payload). Returns 0/-1; caller returns XDP_TX.
    def emit_tcp_reply_data(ctx)
      ctx.reply_bodies.each_with_index.map do |body, id|
        bytes = body.bytes
        rlen = bytes.length
        init = bytes.map { |b| format("0x%02x", b) }.each_slice(12).map { |s| s.join(", ") }.join(",\n            ")
        <<~RD
          /* Roadmap #5b: response payload ##{id} (#{rlen} bytes). */
          static const __u8 spnl_reply_body#{id}[#{rlen}] = {
              #{init}
          };
          /* Write the response INTO the existing packet (overwriting the
           * request payload), recompute checksums, and resize LAST. We never re-read
           * ctx->data/data_end after bpf_xdp_adjust_tail (the verifier rejects that:
           * "modified ctx ptr") — exactly the TCP-slice bundle's order. The incoming
           * request must have room for the response payload (GET lines normally do). */
          static __noinline __s64 spnl_tcp_reply_data#{id}(struct xdp_md *ctx, __u32 seq, __u32 ack)
          {
              void *data     = (void *)(long)ctx->data;
              void *data_end = (void *)(long)ctx->data_end;
              struct ethhdr *eth = data;
              if ((void *)(eth + 1) > data_end) return -1;
              if (eth->h_proto != bpf_htons(0x0800)) return -1;
              struct iphdr *iph = (void *)(eth + 1);
              if ((void *)(iph + 1) > data_end) return -1;
              if (iph->protocol != 6) return -1;
              if (iph->ihl != 5) return -1;
              struct tcphdr *tcp = (struct tcphdr *)((char *)iph + 20);
              if ((void *)(tcp + 1) > data_end) return -1;

              /* the response must fit in the current packet (we resize down after) */
              __u8 *out = (__u8 *)tcp + 20;
              if ((void *)(out + #{rlen}) > data_end) return -1;

              /* swap endpoints */
              __u8 mac[6];
              __builtin_memcpy(mac, eth->h_dest, 6);
              __builtin_memcpy(eth->h_dest, eth->h_source, 6);
              __builtin_memcpy(eth->h_source, mac, 6);
              __be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;
              __be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;

              /* header: seq/ack, FIN|PSH|ACK, doff=5, window */
              tcp->seq     = bpf_htonl(seq);
              tcp->ack_seq = bpf_htonl(ack);
              tcp->doff = 5;
              ((__u8 *)tcp)[13] = 0x19;  /* FIN|PSH|ACK */
              tcp->window  = bpf_htons(65535);
              tcp->urg_ptr = 0;

              /* payload into the existing packet space */
              __builtin_memcpy(out, spnl_reply_body#{id}, #{rlen});
              iph->tot_len = bpf_htons(20 + 20 + #{rlen});
              iph->ttl = 64;
              iph->id  = 0;

              /* checksums (constant lengths) */
              iph->check = 0;
              __s64 v = bpf_csum_diff(0, 0, (void *)iph, 20, 0);
              if (v < 0) return -1;
              iph->check = spnl_reply_csum_fold((__u32)v);
              tcp->check = 0;
              v = bpf_csum_diff(0, 0, (void *)tcp, 20 + #{rlen}, 0);
              if (v < 0) return -1;
              tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 20 + #{rlen}, (__u32)v);

              /* resize to the final length LAST (usually a shrink); no ctx re-read */
              __u32 want = sizeof(struct ethhdr) + 20 + 20 + #{rlen};
              __u32 cur  = (__u32)((long)data_end - (long)data);
              if (cur != want && bpf_xdp_adjust_tail(ctx, (int)want - (int)cur) != 0) return -1;
              return 0;
          }
        RD
      end.join("\n")
    end

    # ---------- naming ----------

    def ivar_map_name(class_name, ivar)
      # @count -> at_count, then prefix with class lowercase
      "#{class_name.downcase}_at_#{ivar.sub(/\A@/, "")}"
    end

    # top-level ivars live in per-unit maps so all attach handlers in
    # the same compilation unit share them.
    def top_ivar_map_name(unit_name, ivar)
      "#{unit_name}_top_#{ivar.sub(/\A@/, "")}"
    end

    def method_func_name(mi)
      case mi.scope
      when :class     then "#{mi.class_name.downcase}_#{c_safe(mi.method_name)}"
      when :top_level then c_safe(mi.method_name)
      when :main      then "main_entry"
      end
    end

    # Look up declared return type for a class method.
    def method_return_type(ctx, mi)
      ir = ctx.ir
      case mi.scope
      when :class
        cls_names = ir.sa("@cls_names") || []
        idx = cls_names.index(mi.class_name)
        return "void" unless idx
        meth_names = (ir.sa("@cls_meth_names") || [])[idx] || ""
        returns    = (ir.sa("@cls_meth_returns") || [])[idx] || ""
        m_idx = meth_names.split(";", -1).index(mi.method_name)
        return "void" unless m_idx
        rt = returns.split(";", -1)[m_idx]
        rt && !rt.empty? ? rt : "void"
      when :top_level
        # DSL-synthesized methods inherit return type from the
        # original class slot in @cls_meth_returns.
        if mi.respond_to?(:dsl_class_idx) && mi.dsl_class_idx
          ci = mi.dsl_class_idx
          meth_names = (ir.sa("@cls_meth_names") || [])[ci] || ""
          returns    = (ir.sa("@cls_meth_returns") || [])[ci] || ""
          m_idx = meth_names.split(";", -1).index(mi.dsl_orig_name)
          return "void" unless m_idx
          rt = returns.split(";", -1)[m_idx]
          return rt && !rt.empty? ? rt : "void"
        end

        # methods from `module Foo; include BPF::Bar; end` aren't in
        # the IR. Default to "int" so the wrapper propagates a return
        # value (XDP_PASS / TC_ACT_OK / 0 etc.) instead of being typed void.
        if mi.respond_to?(:dsl_ast_def_id) && mi.dsl_ast_def_id
          return "int"
        end
        meth_names = ir.sa("@meth_names") || []
        idx = meth_names.index(mi.method_name)
        return "void" unless idx
        returns = ir.sa("@meth_return_types") || []
        rt = returns[idx]
        rt && !rt.empty? ? rt : "void"
      else
        "void"
      end
    end

    # ---------- per-method lowering ----------

    class MethodEmitter
      # list of CallNode method names that we treat as binary
      # operators on integers and lower to inline C.
      # bitwise & | ^ added to support flag tests like
      # `(pkt_tcp_flags & TCP_FLAG_RST) != 0` in TC egress filters.
      # << and >> added. Note that >> on __s64 emits BPF_ARSH (arithmetic
      # right shift) which preserves sign — fine for positive values like
      # latency deltas and counters. For true unsigned shift, caller would
      # need to cast first, but there's no DSL surface for that yet.
      BINARY_OPS = %w[+ - * / % == != < > <= >= & | ^ << >>].freeze

      # Marker for a side-effecting statement (a builtin that emits `@lines << "stmt"`)
      # that has no value as an expression. The old code returned a fake value `"0"`
      # (the `"0"` hack conflated expressions and statements). As a String subclass its value stays "0",
      # so even when it flows into a value position (return / branch value / operand) the output is byte-identical (it emits "0").
      # Meanwhile `no_value?` lets us **explicitly** tell "this is a statement with no value".
      class NoValueStr < String; end
      STMT_NO_VALUE = NoValueStr.new("0").freeze

      def no_value
        STMT_NO_VALUE
      end

      def no_value?(v)
        v.is_a?(NoValueStr)
      end

      attr_reader :lines

      def initialize(ctx:, mi:, return_type:, params: [], captured_locals: {})
        @ctx = ctx
        @mi = mi
        @return_type = return_type
        @params = params                # Array<[name, type]>
        @param_names = params.map(&:first).to_set
        @declared_locals = Set.new
        # outer locals visible by pointer through `_lc` (set in callback prologue).
        @captured_locals = captured_locals  # Hash<name, c_type>
        # locals bound via `t = kptr(ptr, "struct")`; maps local name ->
        # kernel struct name so `t.field` reads lower to BPF_CORE_READ.
        @kptr_locals = {}
        @tmp_n = 0
        @lines = []
      end

      def emit
        declare_locals(@mi.body_id)
        last_expr = lower_body(@mi.body_id)
        finalize_return(last_expr)
        @lines
      end

      # pre-scan a body subtree for local-var writes and emit
      # `<ctype> <name> = 0;` declarations at function top. Idempotent w.r.t.
      # already-declared names. Exposed so loop-callback emission can reuse it.
      #
      # the C type is now resolved from spinel's inferred type for
      # the local (IR scope records) instead of a hardcoded __s64. With the
      # current LOCAL_TYPE_TO_C (all scalars -> __s64) this is byte-identical;
      # Step 2 flips ptr/obj_ locals to typed pointers.
      def declare_locals(bid)
        collect_locals(bid).each do |name|
          next if @param_names.include?(name)
          next if @captured_locals.key?(name)  # captured -> reach via *_lc->name
          next if @declared_locals.include?(name)
          c_type = local_c_type(scope_local_type(bid, name))
          # Structure declaration statements as CStmt (CDecl) (byte-identical).
          @lines << CAst.decl(c_type, name, CAst.lit("0")).to_c
          @declared_locals << name
        end
      end

      # spinel-inferred type string for the local named `c_name`
      # (already c_safe-wrapped) within the scope identified by `bid`. The IR
      # scope records (SN/ST) are keyed by the *method body* node id, so this
      # resolves for the method-level declare_locals call; nested block bodies
      # (loop callbacks) have no record and return nil -> __s64 fallback. Returns
      # nil when the IR carries no scope info (e.g. unit tests with bare ASTs).
      def scope_local_type(bid, c_name)
        @scope_type_idx ||= {}
        idx = (@scope_type_idx[bid] ||= begin
          ir = @ctx.respond_to?(:ir) ? @ctx.ir : nil
          list = (ir && ir.respond_to?(:scope_locals)) ? (ir.scope_locals[bid] || []) : []
          list.each_with_object({}) do |(name, type), h|
            h[SpinelEbpf::CodegenBpf.c_safe(name)] = type
          end
        end)
        idx[c_name]
      end

      # map a spinel local type to its C declaration type. Falls
      # back to __s64 for unknown/missing types (Step 1 maps every scalar to
      # __s64 anyway; the fallback keeps unmapped types — e.g. a `string` local
      # in an int-signature method — behaving exactly as before).
      def local_c_type(spinel_type)
        LOCAL_TYPE_TO_C[spinel_type] || "__s64"
      end

      # Append the function return statement (or skip for void). Exposed so
      # callers can drive lifecycle when emitting non-method bodies.
      def finalize_return(last_expr)
        return if @return_type == "void"
        # Structure the return statement as CStmt (CReturn).
        # If the last statement is side-effecting (no_value), there is no value, so return the type's default explicitly
        # (the old code had the builtin return a fake "0"; the default is also "0", so byte-identical).
        if last_expr.nil? || no_value?(last_expr) || last_expr == "(void)0"
          @lines << CAst.ret(CAst.raw(DEFAULT_VALUE_FOR_TYPE[@return_type] || "0")).to_c
        else
          @lines << CAst.ret(CAst.raw(last_expr)).to_c
        end
      end

      # public (intentionally — sub-emitters from times_call drive these directly):
      # lower_body, lower_stmt — these used to be private but the loop callback
      # sub-emitter (loop lowering) calls lower_body across instances.

      # Returns the C expression string for the LAST statement's value
      # (or nil if there isn't one). Side effect: appends statement lines
      # to @lines.
      #
      # Build the body as a **structured CBlock** and expand it into @lines via CPrinter's
      # structural indentation. `if` becomes a CIf (then/else = CBlock),
      # dropping the old `emit_branch_lines` after-the-fact `"    " + @lines[i]` indentation.
      # Statements other than `if` are captured per-statement from the existing leaf emitters (@lines append)
      # and wrapped as CRawStmt (leaf emitters unchanged). Output is byte-identical.
      def lower_body(bid)
        block, last = build_block(bid)
        @lines.concat(CAst.render_block(block, 0))
        last
      end

      # Structural builder for a body/branch. Returns [CBlock, last_value].
      def build_block(bid)
        node = @ctx.ast.node(bid)
        return [CAst.block([]), nil] unless node

        unless node.type == "StatementsNode"
          items, last = build_stmt_items(bid)
          return [CAst.block(items), last]
        end

        stmts = @ctx.ast.array(bid, "body", default: [])
        items = []
        last = nil
        stmts.each_with_index do |sid, i|
          sub_items, val = build_stmt_items(sid)
          is_last = (i == stmts.length - 1)
          # A non-last pure expression that produced no statement is kept as a (void) statement (so a bare side effect isn't dropped).
          if !is_last && sub_items.empty? && val && !val.to_s.empty?
            items << CAst.expr_stmt(CAst.raw("(void)(#{val})"))
          else
            items.concat(sub_items)
          end
          last = val
        end
        [CAst.block(items), last]
      end

      # Turn one statement into [items(Array<CStmt>), value]. IfNode becomes a structural CIf; otherwise
      # capture the @lines append from the existing lower_stmt and wrap it as CRawStmt.
      def build_stmt_items(sid)
        snode = @ctx.ast.node(sid)
        if snode && snode.type == "IfNode"
          build_cif(sid, snode)
        else
          captured, val = capture_lines { lower_stmt(sid) }
          [captured.map { |s| CAst.raw_stmt(s) }, val]
        end
      end

      # Turn an IfNode into [items, value]. items = [predicate lookup lines..., __s64 tmp = 0;, CIf].
      # The value is tmp. No after-the-fact indentation needed (CIf indents structurally).
      def build_cif(nid, node)
        pred_id = node.refs.fetch("predicate", -1)
        raise UnsupportedNode, "IfNode missing predicate" if pred_id < 0
        then_id = node.refs.fetch("statements", -1)
        else_id = node.refs.fetch("subsequent", -1)

        pred_lines, cond = capture_lines { lower_stmt(pred_id) }
        tmp = fresh("if")
        then_block = build_branch(then_id, tmp)
        else_block = else_id >= 0 ? build_branch(else_id, tmp) : nil

        items = pred_lines.map { |s| CAst.raw_stmt(s) }
        items << CAst.decl("__s64", tmp, CAst.lit("0"))
        items << CAst.cif(CAst.raw(cond), then_block, else_block, nid: nid)
        [items, tmp]
      end

      # Turn an if branch into a CBlock. Append `tmp = <last>;` at the end (to fix the branch value).
      # ElseNode becomes the inner StatementsNode; an IfNode (elsif) becomes a CIf via build_block.
      def build_branch(bid, result_var)
        return CAst.block([]) if bid < 0
        node = @ctx.ast.node(bid)
        inner = (node && node.type == "ElseNode") ? node.refs.fetch("statements", -1) : bid
        return CAst.block([]) if inner < 0

        block, last = build_block(inner)
        items = block.stmts.dup
        # If the branch's last statement is side-effecting (no_value), the branch value is the type default (="0").
        # Byte-identical to the old builtin's fake "0".
        if last
          branch_val = no_value?(last) ? "0" : last
          items << CAst.expr_stmt(CAst.raw("#{result_var} = #{branch_val}"))
        end
        CAst.block(items)
      end

      # Capture the appends to @lines made during a yielded block and return them (scratch swap).
      def capture_lines
        saved = @lines
        @lines = []
        val = yield
        captured = @lines
        @lines = saved
        [captured, val]
      end

      # Lower a single statement node. Returns the expression string for
      # its value (last expression in a block becomes the return value).
      def lower_stmt(nid)
        node = @ctx.ast.node(nid)
        raise UnsupportedNode, "missing node #{nid}" unless node

        case node.type
        when "DefNode", "ClassNode", "ModuleNode"
          # Definitions inside main's body are no-ops at the statement level
          # (their bodies are emitted as separate methods). Return nil so
          # they don't show up as expression values.
          nil
        when "IntegerNode"
          # Build the expression via lower_expr (recursive C-AST) and stringify with .to_c.
          lower_expr(nid).to_c
        when "ConstantReadNode"
          # only the known-constant table is recognized for now (XDP_PASS
          # etc.). Unrelated user-defined Ruby constants raise UnsupportedNode.
          name = node.attrs.fetch("name")
          val  = KNOWN_CONSTANTS[name]
          # fall back to a BTF enumerator value for any
          # kernel enum constant not in the hand-written table (XDP_*, SK_*,
          # IPPROTO_*, TCP states, BPF_SOCK_OPS_* are enums). Macros like
          # TCP_FLAG_* / ETH_P_* / TC_ACT_* aren't in BTF and stay table-driven.
          val = CodegenBpf.btf_schema.enum_value(name) if val.nil?
          unless val
            raise UnsupportedNode,
                  "constant #{name} not lowerable (not in KNOWN_CONSTANTS and not a BTF enumerator)"
          end
          val.to_s
        when "ConstantPathNode"
          # module-style constants like XDP::PASS / TCP::Flag::RST.
          # Walks the parent chain to build a path array, looks up the
          # flat name in KNOWN_CONSTANT_PATHS, then resolves to the same
          # integer value as the flat constant.
          # macro-valued paths (SCX::DSQ::GLOBAL etc.) emit the C
          # macro name verbatim — needed for u64 constants that exceed
          # __s64 range like (1ULL << 63) | 1.
          path = collect_constant_path(nid)
          raise UnsupportedNode, "ConstantPathNode chain root must be a ConstantReadNode" unless path
          # MACRO_PATHS short-circuit: emit C macro name verbatim.
          macro = CodegenBpf::MACRO_PATHS[path]
          if macro
            return macro
          end
          flat = KNOWN_CONSTANT_PATHS[path]
          unless flat
            raise UnsupportedNode,
                  "constant path #{path.join("::")} not known (try the flat alias, e.g. #{path.last})"
          end
          KNOWN_CONSTANTS.fetch(flat).to_s
        when "InstanceVariableReadNode"
          ivar_read(node)
        when "InstanceVariableWriteNode"
          ivar_write(node)
        when "InstanceVariableOperatorWriteNode"
          ivar_opwrite(node)
        when "LocalVariableReadNode"
          local_read(node)
        when "LocalVariableWriteNode"
          local_write(node)
        when "CallNode"
          call_node(nid, node)
        when "CallOperatorWriteNode"
          # `recv.field += value` form. prism emits a CallOperatorWriteNode
          # distinct from a regular CallNode. We currently desugar this only
          # for tcp_sock_* fields in tcp_cc context; other receivers raise.
          call_op_write_node(nid, node)
        when "OrNode", "AndNode"
          # short-circuit boolean operators. spinel-ebpf only deals in
          # int/bool values inside :ebpf methods, so direct C `||` / `&&` is
          # safe — verifier accepts the short-circuit pattern.
          # Build a recursive C-AST via lower_expr.
          lower_expr(nid).to_c
        when "IfNode"
          if_node(nid, node)
        when "ElseNode"
          # ElseNode wraps a StatementsNode under refs[:statements]
          inner = node.refs.fetch("statements", -1)
          inner < 0 ? nil : lower_stmt(inner)
        when "StatementsNode"
          lower_body(nid)
        when "ParenthesesNode"
          # explicit parens — needed for bitwise precedence in
          # `(flags & TCP_FLAG_RST) != 0`. Body is a single expression or a
          # StatementsNode; wrap the result in C parens to preserve grouping.
          # Build a CParen via lower_expr.
          lower_expr(nid).to_c
        else
          raise UnsupportedNode, "node type #{node.type} (id=#{nid}) not lowerable in MVP"
        end
      end

      # Recursively lower an expression into a **true CExpr tree**.
      # Pure-expression nodes (integer / binary op / short-circuit logic / explicit parens) return a CExpr;
      # everything else (local / ivar / constant / builtin / if, etc., including those with @lines
      # side effects) wraps the string returned by `lower_stmt` in a `CRaw` leaf.
      # Because operands become CExpr rather than CRaw, a later phase can remove
      # redundant parens based on CPrinter's precedence. At the time this method was added,
      # CParen is kept as-is so the output stays byte-identical.
      def lower_expr(nid)
        node = @ctx.ast.node(nid)
        raise UnsupportedNode, "missing node #{nid}" unless node

        case node.type
        when "IntegerNode"
          CAst.lit(int_lit(node), nid: nid)
        when "OrNode", "AndNode"
          lhs = node.refs.fetch("left",  -1)
          rhs = node.refs.fetch("right", -1)
          raise UnsupportedNode, "#{node.type} missing operand" if lhs < 0 || rhs < 0
          op = node.type == "OrNode" ? "||" : "&&"
          # (2b): don't add a defensive outer paren; defer to CPrinter's precedence
          # (minimal parens only where needed). Every leaf has prec >= CAST_PREC, so it's safe (audited).
          CAst.binop(op, lower_expr(lhs), lower_expr(rhs), nid: nid)
        when "ParenthesesNode"
          inner = node.refs.fetch("body", -1)
          inner < 0 ? CAst.raw("0", nid: nid) : CAst.paren(lower_expr(inner), nid: nid)
        when "CallNode"
          parts = binop_callnode_parts(node)
          if parts
            binop_cexpr(parts[0], parts[1], parts[2], nid: nid)
          else
            # Non-binary CallNodes (builtin / BPF-to-BPF / dot accessor, etc.) are
            # delegated to the existing dispatch, and the returned string is treated as a leaf.
            CAst.raw(call_node(nid, node), nid: nid)
          end
        else
          # Non-pure-expression nodes are delegated to lower_stmt (with @lines side effects), and the string becomes a leaf.
          CAst.raw(lower_stmt(nid), nid: nid)
        end
      end

      # Build the CExpr for `lhs <op> rhs`, including recursive operands. (2b):
      # don't add a defensive outer paren; defer to CPrinter's precedence (minimal parens only when needed).
      # Every CRaw leaf has prec >= CAST_PREC(80) > all binary ops (<=70), so treating a leaf as primary
      # still gives correct paren decisions for binop operands (audited).
      def binop_cexpr(op, recv_id, arg_id, nid: nil)
        CAst.binop(op, lower_expr(recv_id), lower_expr(arg_id), nid: nid)
      end

      # If the CallNode is a "plain binary op" (receiver + 1 argument + operator name),
      # return [op, recv_id, arg_id]. Otherwise nil (builtins, etc. go to dispatch).
      # Operator names don't collide with builtins / dot accessors, so this alone
      # matches the reachability condition for call_node's binop branch (byte-identical).
      def binop_callnode_parts(node)
        name = node.attrs.fetch("name", "")
        return nil unless BINARY_OPS.include?(name)
        recv = node.refs.fetch("receiver", -1)
        return nil if recv < 0
        args_id = node.refs.fetch("arguments", -1)
        return nil if args_id < 0
        args_node = @ctx.ast.node(args_id)
        return nil unless args_node && args_node.type == "ArgumentsNode"
        args = args_node.arrays.fetch("arguments", [])
        return nil unless args.length == 1
        [name, recv, args[0]]
      end

      # lower
      #   if pred ; then_stmts ; else else_stmts ; end
      # to
      #   __s64 _ifN = 0;
      #   if (pred_expr) { ...then_lines; _ifN = then_last; }
      #   else            { ...else_lines; _ifN = else_last; }
      # and return "_ifN" as the expression. Branch body lines accumulated by
      # lower_stmt are post-indented so they sit inside the C block.
      #
      # A statement-position if is handled by build_cif (structural CIf).
      # if_node stays as a fallback for an **expression-position if** via lower_stmt(IfNode) (`x = if ... end`, etc.).
      # The after-the-fact indentation is also correctly composed in expression position via capture + structural render
      # (proven byte-identical).
      def if_node(nid, node)
        pred_id = node.refs.fetch("predicate", -1)
        raise UnsupportedNode, "IfNode missing predicate" if pred_id < 0
        then_id = node.refs.fetch("statements", -1)
        else_id = node.refs.fetch("subsequent", -1)

        pred_expr = lower_stmt(pred_id)
        tmp = fresh("if")
        @lines << "__s64 #{tmp} = 0;"
        @lines << "if (#{pred_expr}) {"
        emit_branch_lines(then_id, tmp)
        if else_id >= 0
          @lines << "} else {"
          emit_branch_lines(else_id, tmp)
        end
        @lines << "}"
        tmp
      end

      # Lower a sub-tree (StatementsNode / ElseNode / single expr) into
      # @lines, then assign its last expression to result_var and indent the
      # newly appended lines by 4 spaces so they sit inside the if-block.
      def emit_branch_lines(bid, result_var)
        return if bid < 0
        before = @lines.length
        last = lower_stmt(bid)
        @lines << "#{result_var} = #{last};" if last
        (before...@lines.length).each { |i| @lines[i] = "    " + @lines[i] }
      end

      # a CallNode whose name is a binary op and whose receiver+arg are
      # both lowerable -> emit "(lhs op rhs)".
      # built-in spnl_emit(x) -> ringbuf reserve / write / submit block.
      # a CallNode targeting another :ebpf method in the same unit
      #       -> BPF-to-BPF call to <name>_inner(args).
      # Otherwise UnsupportedNode.
      def call_node(nid, node)
        name = node.attrs.fetch("name", "")

        # receiver-aware desugar. `sk.snd_cwnd` / `sk.snd_cwnd = v`
        # arrive as CallNode with a non-nil receiver — try the dot-form
        # dispatcher first. Returns nil if the receiver/name combo is not
        # a known tcp_sock dot accessor, in which case we fall through to
        # the existing flat-builtin dispatch table below.
        recv_id_for_dot = node.refs.fetch("receiver", -1)
        if recv_id_for_dot >= 0
          args_id_for_dot = node.refs.fetch("arguments", -1)
          args_for_dot = if args_id_for_dot >= 0
                          @ctx.ast.node(args_id_for_dot).arrays.fetch("arguments", [])
                        else
                          []
                        end
          # `t.field` where `t` was bound via kptr(ptr, "struct") — read
          # an arbitrary kernel struct field via BPF_CORE_READ. Checked first
          # since it keys off the per-method kptr-local registry.
          if (kf = try_kptr_dot_call(name, recv_id_for_dot, args_for_dot))
            return kf
          end
          if (dot = try_tcp_sock_dot_call(name, recv_id_for_dot, args_for_dot))
            return dot
          end
          # pkt.l4.proto / pkt.ip4.src / pkt.byte_at(off) — chain
          # accessor over the existing pkt_* flat builtins.
          if (chain = try_pkt_chain_dispatch(name, recv_id_for_dot, args_for_dot, node))
            return chain
          end
        end

        return spnl_emit_call(nid, node) if name == "spnl_emit"
        return spnl_emit_str_call(nid, node) if name == "spnl_emit_str"
        return spnl_emit_argv_call(nid, node) if name == "emit_argv"
        return spnl_emit_pair_call(nid, node) if name == "spnl_emit_pair"
        return spnl_emit_n_call(nid, node, 3) if name == "spnl_emit3"
        return spnl_emit_n_call(nid, node, 4) if name == "spnl_emit4"
        return kfield_call(nid, node) if name == "kfield"
        return field_exists_call(nid, node) if name == "field_exists"
        return kptr_call(nid, node) if name == "kptr"
        return blocklist_match_call(nid, node) if name == "blocklist_match"
        return cidr_blocklist_match_call(nid, node) if name == "cidr_blocklist_match"
        return path_counter_inc_call(nid, node) if name == "path_counter_inc"
        return leak_record_call(nid, node) if name == "leak_record"
        return leak_forget_call(nid, node) if name == "leak_forget"
        return hist_observe_call(nid, node) if name == "hist_observe"
        return hist_observe_by_call(nid, node) if name == "hist_observe_by"
        return hist_observe_linear_call(nid, node) if name == "hist_observe_linear"
        return divu_call(nid, node)        if name == "divu"
        return comm_hash_call(node)        if name == "comm_hash"
        return cpu_id_call(node)           if name == "cpu_id"
        return emit_comm_call(node)        if name == "emit_comm"
        return stack_id_call(node, user: false) if name == "stack_id"
        return stack_id_call(node, user: true)  if name == "user_stack_id"
        return off_cpu_start_call(nid, node)    if name == "off_cpu_start"
        return off_cpu_observe_call(nid, node)  if name == "off_cpu_observe"
        return scx_kfunc_call(nid, node, name)  if %w[scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq].include?(name)
        return qdisc_kfunc_call(nid, node, name) if %w[qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue qdisc_watchdog_schedule qdisc_bstats_update].include?(name)
        return queue_push_call(nid, node) if name == "queue_push"
        return queue_pop_call(nid, node)  if name == "queue_pop"
        return ktime_ns_call(node)        if name == "ktime_ns"
        return pid_call(node)             if name == "pid"
        return tgid_call(node)            if name == "tgid"
        return tid_call(node)             if name == "tid"
        return latency_start_call(node)   if name == "latency_start"
        return latency_end_call(node)     if name == "latency_end"
        return task_load_call(node)       if name == "task_load"
        return task_store_call(nid, node) if name == "task_store"
        return task_incr_call(nid, node)  if name == "task_incr"
        return task_swap_call(nid, node)  if name == "task_swap"
        return lock_edge_call(nid, node)  if name == "lock_edge"
        return lat_start_key_call(nid, node) if name == "lat_start"
        return lat_end_key_call(nid, node)   if name == "lat_end"
        return depth_inc_call(nid, node)     if name == "depth_inc"
        return depth_dec_call(nid, node)     if name == "depth_dec"
        return mim_inc_call(nid, node)    if name == "mim_inc"
        return mim_get_call(nid, node)    if name == "mim_get"
        return fifo_push_call(nid, node)  if name == "fifo_push"
        return fifo_pop_call(node)        if name == "fifo_pop"
        return lifo_push_call(nid, node)  if name == "lifo_push"
        return lifo_pop_call(node)        if name == "lifo_pop"
        return reuseport_hash_call(nid, node) if name == "reuseport_hash"
        return worker_select_call(nid, node) if name == "worker_select"
        return xdp_match_health_call(nid, node) if name == "xdp_match_health"
        return xdp_reply_health_call(nid, node) if name == "xdp_reply_health"
        return pkt_dynptr_byte_at_call(nid, node) if name == "pkt_dynptr_byte_at"
        return user_ringbuf_drain_call(nid, node) if name == "user_ringbuf_drain"
        return tail_call_to_call(nid, node) if name == "tail_call_to"
        return fib_lookup_call(nid, node) if name == "fib_lookup"
        return fib_lookup6_call(nid, node) if name == "fib_lookup6"
        return sk_lookup_tcp_call(nid, node) if name == "sk_lookup_tcp"
        return sk_assign_tcp_call(nid, node) if name == "sk_assign_tcp"
        return redirect_call(nid, node)      if name == "redirect"
        return skb_load_byte_call(nid, node)  if name == "skb_load_byte"
        return skb_store_byte_call(nid, node) if name == "skb_store_byte"
        return csum_replace_call(nid, node, layer: 3) if name == "l3_csum_replace"
        return csum_replace_call(nid, node, layer: 4) if name == "l4_csum_replace"
        return skb_load_u32_call(nid, node)  if name == "skb_load_u32"
        return skb_store_u32_call(nid, node) if name == "skb_store_u32"
        return csum_replace_ip_call(nid, node, layer: 3) if name == "l3_csum_replace_ip"
        return csum_replace_ip_call(nid, node, layer: 4) if name == "l4_csum_replace_ip"
        return skb_load_u16_call(nid, node)  if name == "skb_load_u16"
        return skb_store_u16_call(nid, node) if name == "skb_store_u16"
        return l4_offset_call(nid, node)     if name == "l4_offset"
        return arena_set_call(nid, node) if name == "arena_set"
        return arena_get_call(nid, node) if name == "arena_get"
        return arena_hash_set_call(nid, node) if name == "arena_hash_set"
        return arena_hash_get_call(nid, node) if name == "arena_hash_get"
        return arena_hash_del_call(nid, node) if name == "arena_hash_del"
        return arena_list_push_call(nid, node) if name == "arena_list_push"
        return arena_list_sum_call(nid, node)  if name == "arena_list_sum"
        return cpumap_redirect_call(nid, node) if name == "cpumap_redirect"
        return xsk_redirect_call(nid, node) if name == "xsk_redirect"
        return dev_redirect_call(nid, node) if name == "dev_redirect"
        return sock_ops_field_call(name) if name == "sock_ops_op" || name == "sock_ops_state"
        return sock_addr_field_call(name) if name == "sock_addr_ip4" || name == "sock_addr_port"
        return iter_task_call(node) if name == "iter_task"
        return flow_get_call(nid, node) if name == "flow_get"
        return flow_set_call(nid, node) if name == "flow_set"
        return flow_del_call(nid, node) if name == "flow_del"
        return syncookie_call(name) if name == "tcp_syncookie_gen" || name == "tcp_syncookie_check"
        return tcp_reply_header_call(node) if name == "tcp_reply_header"
        return tcp_reply_synack_call(node) if name == "tcp_reply_synack"
        return tcp_synack_cookie_call(node) if name == "tcp_synack_cookie"
        return tcp_reply_data_call(node) if name == "tcp_reply_data"
        return payload_starts_call(node) if name == "payload_starts"
        return tcp_sock_builtin_call(name, node) if CodegenBpf::TCP_SOCK_BUILTINS.include?(name)
        return pkt_builtin_call(name) if CodegenBpf::PKT_BUILTINS.include?(name)
        return times_call(nid, node) if name == "times" && node.refs.fetch("block", -1) >= 0

        callee = @ctx.ebpf_methods_by_name[name]
        return bpf_to_bpf_call(callee, node) if callee && !callee.equal?(@mi)

        raise UnsupportedNode, "call to #{name.inspect} (nid=#{nid}) not lowerable" unless BINARY_OPS.include?(name)

        recv = node.refs.fetch("receiver", -1)
        raise UnsupportedNode, "binary op #{name} needs receiver" if recv < 0
        args_id = node.refs.fetch("arguments", -1)
        raise UnsupportedNode, "binary op #{name} needs arguments" if args_id < 0

        args_node = @ctx.ast.node(args_id)
        raise UnsupportedNode, "ArgumentsNode missing" unless args_node && args_node.type == "ArgumentsNode"
        args = args_node.arrays.fetch("arguments", [])
        raise UnsupportedNode, "binary op #{name} expects 1 arg, got #{args.length}" unless args.length == 1

        # Recursively turn a binary op into a C-AST via lower_expr (operands are also
        # true CExprs). The defensive outer paren is kept for byte-identical output; redundant removal is a later phase.
        binop_cexpr(name, recv, args[0]).to_c
      end

      # lower `bound.times { |i| <body> }` to a generated callback +
      # `bpf_loop(bound, cb, NULL, 0)`. MVP supports blocks that reference
      # only the block param + ivars + builtin (spnl_emit) + arithmetic —
      # no outer-local capture.
      def times_call(nid, node)
        recv = node.refs.fetch("receiver", -1)
        raise UnsupportedNode, "times needs receiver" if recv < 0
        block_id = node.refs.fetch("block")
        block = @ctx.ast.node(block_id)
        raise UnsupportedNode, "expected BlockNode" unless block && block.type == "BlockNode"

        # Extract single block param name; only RequiredParameterNode is
        # supported (`{ |i| ... }`). Skip splat / keyword / optional for MVP.
        bp_id = block.refs.fetch("parameters", -1)
        block_param_name = extract_single_block_param(bp_id)
        raise UnsupportedNode, "n.times block must have single required param" unless block_param_name

        body_id = block.refs.fetch("body", -1)
        raise UnsupportedNode, "block body missing" if body_id < 0

        # open-coded iterator fast-path. When the receiver is an
        # integer literal we can lower the loop INLINE using `bpf_iter_num_*`
        # kfuncs (kernel 6.4+). This avoids the callback function, the
        # capture struct, and the extra BPF-to-BPF call. Captures Just Work
        # because the body emits in the same scope.
        recv_node = @ctx.ast.node(recv)
        if recv_node && recv_node.type == "IntegerNode"
          return times_call_open_coded(recv_node, block_param_name, body_id)
        end

        # Allocate a unique callback function name.
        @ctx.loop_counter += 1
        cb_name = "#{SpinelEbpf::CodegenBpf.method_func_name(@mi)}_loop#{@ctx.loop_counter}_cb"

        # detect outer-scope locals (and params) referenced in the
        # block body. They will be passed by pointer through a generated
        # capture struct so the callback can read/write them.
        captures = collect_captures(body_id, block_param_name)

        captured_locals_h = captures.to_h { |n| [n, "__s64"] }

        # Lower the block body as if it were a separate function whose only
        # param is the block index (typed __s64). The sub-emitter shares
        # @ctx (so spnl_emit etc. still work), but uses its own @lines.
        sub = MethodEmitter.new(
          ctx: @ctx, mi: @mi, return_type: "void",
          params: [[block_param_name, "int"]],
          captured_locals: captured_locals_h,
        )
        sub.declare_locals(body_id)
        sub.lower_body(body_id)
        sub.lines << "return 0;"  # bpf_loop callback contract: 0 = continue

        cb_body = sub.lines.map { |ln| "    " + ln }.join("\n")

        # ctx struct + prologue + invocation site
        if captures.empty?
          cb_prologue = "    (void)_raw_ctx;"
          cb_ctx_arg = "NULL"
        else
          caps_struct = "#{cb_name}_caps"
          fields = captures.map { |n| "    __s64 *#{n};" }.join("\n")
          @ctx.deferred_functions << <<~ST
            /* loop captures for #{@mi.qualified_name} */
            struct #{caps_struct} {
            #{fields}
            };
          ST
          cb_prologue = "    struct #{caps_struct} *_lc = (struct #{caps_struct} *)_raw_ctx;"
          # Emit the capture-instance on the caller's stack and pass its address.
          inits = captures.map { |n| ".#{n} = &#{n}" }.join(", ")
          instance = "_loop#{@ctx.loop_counter}_caps"
          @lines << "struct #{caps_struct} #{instance} = { #{inits} };"
          cb_ctx_arg = "&#{instance}"
        end

        @ctx.deferred_functions << <<~CB
          /* loop callback: emitted for #{@mi.qualified_name} */
          static int #{cb_name}(__u32 _raw_index, void *_raw_ctx)
          {
              __s64 #{block_param_name} = (__s64)_raw_index;
          #{cb_prologue}
          #{cb_body}
          }
        CB

        bound_expr = lower_stmt(recv)
        @lines << "bpf_loop(#{bound_expr}, &#{cb_name}, #{cb_ctx_arg}, 0);"
        no_value  # n.times: side-effecting (bpf_loop), no expression value
      end

      # open-coded iterator for `N.times { |i| ... }` where N is an
      # integer literal. Emits `bpf_iter_num_*` directly in the caller's
      # function — no callback, no captures struct, no BPF-to-BPF call.
      # Counters / ivars / outer locals are visible naturally because the
      # body is lowered in the same scope.
      def times_call_open_coded(recv_node, block_param_name, body_id)
        n = int_lit(recv_node).to_i
        raise UnsupportedNode, "n.times open-coded: n must be >= 0" if n < 0
        @ctx.loop_counter += 1
        iter_var = "_it#{@ctx.loop_counter}"
        ptr_var  = "_itp#{@ctx.loop_counter}"
        @lines << "{"
        @lines << "    struct bpf_iter_num #{iter_var};"
        @lines << "    bpf_iter_num_new(&#{iter_var}, 0, #{n});"
        @lines << "    int *#{ptr_var};"
        @lines << "    while ((#{ptr_var} = bpf_iter_num_next(&#{iter_var}))) {"
        @lines << "        __s64 #{block_param_name} = (__s64)*#{ptr_var};"
        # Capture parent state, lower body inline with the loop variable
        # exposed as a regular param. Captures: nothing special — the
        # inline body sees the parent's locals directly through @lines.
        saved_params = @param_names.dup
        @param_names.add(block_param_name)
        sub_lines = []
        old_lines = @lines
        @lines = sub_lines
        declare_locals(body_id)
        lower_body(body_id)
        @lines = old_lines
        @param_names = saved_params
        sub_lines.each { |ln| @lines << "        " + ln }
        @lines << "    }"
        @lines << "    bpf_iter_num_destroy(&#{iter_var});"
        @lines << "}"
        no_value
      end

      # walk the block body and return outer-scope locals (or method
      # params) that the block reads or writes. A name is considered a
      # capture iff it appears in the outer's already-declared locals or
      # params, regardless of whether the block also assigns to it (Ruby
      # has no block-only shadow — `x = ...` inside a block writes the
      # outer `x` if one exists).
      def collect_captures(body_id, block_param_name)
        outer_accessible = (@declared_locals | @param_names).to_set
        return [] if outer_accessible.empty?

        refs = Set.new
        visit = lambda do |nid|
          return if nid < 0
          n = @ctx.ast.node(nid)
          return unless n
          return if %w[DefNode ClassNode ModuleNode].include?(n.type)
          if %w[LocalVariableReadNode LocalVariableWriteNode].include?(n.type)
            nm = n.attrs.fetch("name", nil)
            # sanitize so intersection with outer_accessible (also sanitized) matches.
            refs << SpinelEbpf::CodegenBpf.c_safe(nm) if nm
          end
          n.refs.each_value { |c| visit.call(c) if c.is_a?(Integer) }
          n.arrays.each_value { |a| a.each { |c| visit.call(c) if c.is_a?(Integer) } }
        end
        visit.call(body_id)

        captures = (refs & outer_accessible).to_a
        captures.delete(block_param_name)
        captures
      end

      # ParametersNode | BlockParametersNode -> first required param name, or nil.
      # sanitized so e.g. `n.times { |double| ... }` lowers to
      # `__s64 double_ = (__s64)_raw_index;` (clang accepts).
      def extract_single_block_param(bp_id)
        return nil if bp_id < 0
        bp = @ctx.ast.node(bp_id)
        return nil unless bp
        params_id =
          case bp.type
          when "BlockParametersNode" then bp.refs.fetch("parameters", -1)
          when "ParametersNode"      then bp_id
          else return nil
          end
        return nil if params_id < 0
        params = @ctx.ast.node(params_id)
        return nil unless params && params.type == "ParametersNode"
        req = params.arrays.fetch("requireds", [])
        return nil if req.length != 1
        req_param = @ctx.ast.node(req[0])
        return nil unless req_param && req_param.type == "RequiredParameterNode"
        nm = req_param.attrs.fetch("name", nil)
        nm.nil? ? nil : SpinelEbpf::CodegenBpf.c_safe(nm)
      end

      # lower a CallNode that targets another :ebpf method in this unit
      # to a BPF-to-BPF call. We call the static __noinline _inner version of
      # the target, so verifier sees a typed C function (not a SEC entry).
      def bpf_to_bpf_call(callee_mi, node)
        target_func = SpinelEbpf::CodegenBpf.method_func_name(callee_mi) + "_inner"
        args_id = node.refs.fetch("arguments", -1)
        args = if args_id >= 0
          an = @ctx.ast.node(args_id)
          an && an.type == "ArgumentsNode" ? an.arrays.fetch("arguments", []) : []
        else
          []
        end
        arg_exprs = args.map { |aid| lower_stmt(aid) }
        "#{target_func}(#{arg_exprs.join(", ")})"
      end

      # spnl_emit_pair(a, b) lowering — two int values per event.
      def spnl_emit_pair_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "spnl_emit_pair expects 2 args, got #{args.length}" unless args.length == 2
        a_expr = lower_stmt(args[0])
        b_expr = lower_stmt(args[1])

        @ctx.uses_pair_ringbuf = true
        evar = fresh("pe")
        @lines << "{"
        @lines << "    struct #{@ctx.unit_name}_pair_event *#{evar} = bpf_ringbuf_reserve(&#{@ctx.unit_name}_pair_events, sizeof(*#{evar}), 0);"
        @lines << "    if (#{evar}) {"
        @lines << "        #{evar}->hdr.type = SPNL_EVT_USER_BASE;"
        @lines << "        #{evar}->hdr.version = SPNL_EVENT_HDR_VERSION;"
        @lines << "        #{evar}->hdr.reserved = 0;"
        @lines << "        #{evar}->hdr.timestamp = bpf_ktime_get_ns();"
        @lines << "        #{evar}->a = #{a_expr};"
        @lines << "        #{evar}->b = #{b_expr};"
        @lines << "        bpf_ringbuf_submit(#{evar}, 0);"
        @lines << "    }"
        @lines << "}"
        no_value
      end

      # spnl_emit3(a, b, c) / spnl_emit4(a, b, c, d) lowering. Fixed-arity
      # cousins of spnl_emit_pair — each writes N int values to a per-unit
      # ringbuf named `<unit>_emit<N>_events`. Host parse uses the same
      # 16B header and reads N consecutive __s64 fields.
      def spnl_emit_n_call(nid, node, n)
        raise UnsupportedNode, "spnl_emit_n_call: n must be 3 or 4 (got #{n})" unless [3, 4].include?(n)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "spnl_emit#{n} expects #{n} args, got #{args.length}" unless args.length == n

        field_names = %w[a b c d].first(n)
        exprs = args.map { |aid| lower_stmt(aid) }

        if n == 3
          @ctx.uses_emit3_ringbuf = true
        else
          @ctx.uses_emit4_ringbuf = true
        end
        evar = fresh("ne")
        ringbuf_name = "#{@ctx.unit_name}_emit#{n}_events"
        struct_name = "#{@ctx.unit_name}_emit#{n}_event"
        @lines << "{"
        @lines << "    struct #{struct_name} *#{evar} = bpf_ringbuf_reserve(&#{ringbuf_name}, sizeof(*#{evar}), 0);"
        @lines << "    if (#{evar}) {"
        @lines << "        #{evar}->hdr.type = SPNL_EVT_USER_BASE;"
        @lines << "        #{evar}->hdr.version = SPNL_EVENT_HDR_VERSION;"
        @lines << "        #{evar}->hdr.reserved = 0;"
        @lines << "        #{evar}->hdr.timestamp = bpf_ktime_get_ns();"
        field_names.zip(exprs).each do |fn, expr|
          @lines << "        #{evar}->#{fn} = #{expr};"
        end
        @lines << "        bpf_ringbuf_submit(#{evar}, 0);"
        @lines << "    }"
        @lines << "}"
        no_value
      end

      # spnl_emit_str(ptr) lowering.
      # ptr is treated as a userspace const char *; we copy at most SPNL_STR_MAX
      # bytes into a stack-allocated event via bpf_probe_read_user_str (which
      # is verifier-safe and NUL-truncates on overflow).
      # blocklist_match(ip_host_order) lowering. Sets ctx.uses_blocklist
      # so the module-level emit pass declares the bpf_blocklist HASH map and
      # the spnl_blocklist_match() __noinline helper. Returns the helper call
      # expression.
      # extract a CallNode's positional argument node-ids (or []).
      def call_args(node)
        args_id = node.refs.fetch("arguments", -1)
        return [] if args_id < 0
        an = @ctx.ast.node(args_id)
        an && an.type == "ArgumentsNode" ? an.arrays.fetch("arguments", []) : []
      end

      # read a StringNode literal arg as a C identifier (struct or field
      # name for kfield/kptr). Rejects non-literals; allows a dotted path of
      # identifiers (embedded-struct access like "__sk_common.skc_daddr",
      # which BPF_CORE_READ reads in one hop) but nothing else user-controlled.
      def string_literal_arg(arg_id, label)
        n = @ctx.ast.node(arg_id)
        raise UnsupportedNode, "#{label} must be a string literal" unless n && n.type == "StringNode"
        s = n.attrs.fetch("content", "")
        unless s =~ /\A[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\z/
          raise UnsupportedNode, "#{label} #{s.inspect} must be a C identifier (optionally a dotted embedded-field path)"
        end
        s
      end

      # kfield(ptr, "struct", "field", ...) -> BPF_CORE_READ. Reads an
      # arbitrary kernel struct field (CO-RE relocated, BTF-driven) from any
      # pointer — works in both trusted (fentry/lsm/struct_ops) and untrusted
      # (kprobe PT_REGS arg) contexts, where a direct deref would be rejected.
      # Chains follow BPF_CORE_READ semantics: kfield(skb,"sk_buff","sk","sk_state").
      def kfield_call(_nid, node)
        args = call_args(node)
        if args.length < 3
          raise UnsupportedNode, "kfield expects (ptr, \"struct\", \"field\", ...), got #{args.length} args"
        end
        ptr_expr = lower_stmt(args[0])
        struct_name = string_literal_arg(args[1], "kfield struct name")
        fields = args[2..].map { |a| string_literal_arg(a, "kfield field name") }
        @ctx.uses_kfield = true
        "((__s64)BPF_CORE_READ((struct #{struct_name} *)(unsigned long)(#{ptr_expr}), #{fields.join(', ')}))"
      end

      # field_exists(ptr, "struct", "field") -> 1 if the
      # field exists in the *running* kernel's BTF, else 0. bpf_core_field_exists
      # is resolved to a constant at load time (CO-RE), so this is verifier-safe
      # and lets a probe branch on kernel-version field differences. The dotted
      # embedded-path form (e.g. "__sk_common.skc_daddr") is accepted too.
      def field_exists_call(_nid, node)
        args = call_args(node)
        unless args.length == 3
          raise UnsupportedNode, "field_exists expects (ptr, \"struct\", \"field\"), got #{args.length} args"
        end
        ptr_expr = lower_stmt(args[0])
        struct_name = string_literal_arg(args[1], "field_exists struct name")
        field = string_literal_arg(args[2], "field_exists field name")
        @ctx.uses_kfield = true   # pulls in <bpf/bpf_core_read.h>
        "((__s64)bpf_core_field_exists(((struct #{struct_name} *)(unsigned long)(#{ptr_expr}))->#{field}))"
      end

      # kptr(ptr, "struct") -> the raw pointer value (as __s64). The
      # struct binding is captured at the local-write site (local_write) so a
      # later `local.field` read dispatches to BPF_CORE_READ (try_kptr_dot_call).
      def kptr_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "kptr expects (ptr, \"struct\"), got #{args.length} args" unless args.length == 2
        string_literal_arg(args[1], "kptr struct name") # validate the name literal
        @ctx.uses_kfield = true
        "((__s64)(#{lower_stmt(args[0])}))"
      end

      # pull the struct name out of a kptr(ptr, "struct") CallNode, or nil.
      def kptr_struct_name(call_node)
        args = call_args(call_node)
        return nil unless args.length == 2
        n = @ctx.ast.node(args[1])
        return nil unless n && n.type == "StringNode"
        s = n.attrs.fetch("content", "")
        s =~ /\A[A-Za-z_][A-Za-z0-9_]*\z/ ? s : nil
      end

      # `t.field` where `t` was bound via kptr(ptr, "struct"). Reader only
      # (a setter would write kernel memory). Returns nil for non-kptr receivers
      # so the dot dispatcher falls through to other accessors.
      def try_kptr_dot_call(name, recv_id, args)
        return nil unless recv_id >= 0
        recv = @ctx.ast.node(recv_id)
        return nil unless recv && recv.type == "LocalVariableReadNode"
        local = SpinelEbpf::CodegenBpf.c_safe(recv.attrs.fetch("name"))
        struct_name = @kptr_locals[local]
        return nil unless struct_name
        if name.end_with?("=")
          raise UnsupportedNode, "kptr dot-setter #{local}.#{name} (kernel write) not supported"
        end
        unless args.empty?
          raise UnsupportedNode, "kptr field read #{local}.#{name} takes no args (got #{args.length})"
        end
        unless name =~ /\A[A-Za-z_][A-Za-z0-9_]*\z/
          raise UnsupportedNode, "kptr field name #{name.inspect} must be a bare C identifier"
        end
        @ctx.uses_kfield = true
        "((__s64)BPF_CORE_READ((struct #{struct_name} *)(unsigned long)(#{lower_stmt(recv_id)}), #{name}))"
      end

      # fib_lookup(dst_ip) — look up the IPv4 route for `dst_ip`
      # (host byte order, matching pkt_ip4_dst) in the kernel forwarding table.
      #
      # This is the first *consumer* that genuinely needs a typed local: it emits
      # a `struct bpf_fib_lookup` STACK local, fills family + destination, and
      # hands &local to the bpf_fib_lookup helper. The verifier tracks that local
      # as PTR_TO_STACK across the helper call — exactly the typed-local capability
      # Step 2 set out to unlock (the prior kfield/kptr pattern only ever round-
      # tripped a pointer *value* through an __s64 slot; it never passed a typed
      # local to a helper). Returns the egress ifindex on a successful lookup
      # (BPF_FIB_LKUP_RET_SUCCESS == 0), else -1.
      #
      # The struct lives inside a GCC/clang statement-expression so the call
      # composes in expression position, e.g. `@oif = fib_lookup(pkt_ip4_dst)`.
      # XDP/TC only (needs the packet ctx). IPv4-only MVP; IPv6 (family AF_INET6 +
      # ipv6_dst) is a follow-up.
      def fib_lookup_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        kind = attach && attach[:kind]
        unless [:xdp, :tc_ingress, :tc_egress].include?(kind)
          raise UnsupportedNode, "fib_lookup is only available inside xdp__ or tc__* methods (needs the packet ctx)"
        end
        args = call_args(node)
        raise UnsupportedNode, "fib_lookup expects 1 arg (ipv4 dst, host order), got #{args.length}" unless args.length == 1
        dst = lower_stmt(args[0])
        @ctx.uses_fib = true
        n   = (@tmp_n += 1)
        fib = "_spnl_fib_#{n}"
        ret = "_spnl_fibret_#{n}"
        <<~FIB.chomp
          ({
              struct bpf_fib_lookup #{fib} = {};
              #{fib}.family = 2; /* AF_INET */
              #{fib}.ipv4_dst = bpf_htonl((__u32)(#{dst}));
              __s64 #{ret} = bpf_fib_lookup(ctx, &#{fib}, sizeof(#{fib}), 0);
              (__s64)(#{ret} == 0 ? #{fib}.ifindex : (__s64)-1);
          })
        FIB
      end

      # fib_lookup6(dst_hi, dst_lo) — IPv6 route lookup. dst_hi/dst_lo are
      # the high/low 64 bits of the destination address in host byte order (like
      # the pkt.ip6.* accessors); the builtin packs them into the network-
      # order ipv6_dst[4] field. Returns the egress ifindex on success, else -1.
      # XDP/TC only. The IPv6 counterpart of fib_lookup.
      def fib_lookup6_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        kind = attach && attach[:kind]
        unless [:xdp, :tc_ingress, :tc_egress].include?(kind)
          raise UnsupportedNode, "fib_lookup6 is only available inside xdp__ or tc__* methods (needs the packet ctx)"
        end
        args = call_args(node)
        raise UnsupportedNode, "fib_lookup6 expects 2 args (dst_hi, dst_lo), got #{args.length}" unless args.length == 2
        hi = lower_stmt(args[0])
        lo = lower_stmt(args[1])
        @ctx.uses_fib = true
        n   = (@tmp_n += 1)
        fib = "_spnl_fib6_#{n}"
        ret = "_spnl_fib6ret_#{n}"
        <<~FIB6.chomp
          ({
              struct bpf_fib_lookup #{fib} = {};
              #{fib}.family = 10; /* AF_INET6 */
              #{fib}.ipv6_dst[0] = bpf_htonl((__u32)((__u64)(#{hi}) >> 32));
              #{fib}.ipv6_dst[1] = bpf_htonl((__u32)(#{hi}));
              #{fib}.ipv6_dst[2] = bpf_htonl((__u32)((__u64)(#{lo}) >> 32));
              #{fib}.ipv6_dst[3] = bpf_htonl((__u32)(#{lo}));
              __s64 #{ret} = bpf_fib_lookup(ctx, &#{fib}, sizeof(#{fib}), 0);
              (__s64)(#{ret} == 0 ? #{fib}.ifindex : (__s64)-1);
          })
        FIB6
      end

      # sk_lookup_tcp(saddr, daddr, sport, dport) — find an established or
      # listening TCP socket for the 4-tuple (host byte order args) in the current
      # netns. Returns the socket's TCP state (e.g. TCP_LISTEN=10) or -1 if no
      # socket matches. The returned bpf_sock reference is released on every path
      # (verifier reference tracking), so it cannot leak. XDP/TC only.
      def sk_lookup_tcp_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        kind = attach && attach[:kind]
        unless [:xdp, :tc_ingress, :tc_egress].include?(kind)
          raise UnsupportedNode, "sk_lookup_tcp is only available inside xdp__ or tc__* methods (needs the packet ctx)"
        end
        args = call_args(node)
        raise UnsupportedNode, "sk_lookup_tcp expects 4 args (saddr, daddr, sport, dport), got #{args.length}" unless args.length == 4
        sa = lower_stmt(args[0]); da = lower_stmt(args[1]); sp = lower_stmt(args[2]); dp = lower_stmt(args[3])
        @ctx.uses_csum = true # bpf_htonl/htons → needs bpf_endian.h
        n  = (@tmp_n += 1)
        t  = "_spnl_sktup_#{n}"; sk = "_spnl_sk_#{n}"; r = "_spnl_skr_#{n}"
        <<~SK.chomp
          ({
              struct bpf_sock_tuple #{t} = {};
              #{t}.ipv4.saddr = bpf_htonl((__u32)(#{sa}));
              #{t}.ipv4.daddr = bpf_htonl((__u32)(#{da}));
              #{t}.ipv4.sport = bpf_htons((__u16)(#{sp}));
              #{t}.ipv4.dport = bpf_htons((__u16)(#{dp}));
              struct bpf_sock *#{sk} = bpf_sk_lookup_tcp(ctx, &#{t}, sizeof(#{t}.ipv4), -1, 0);
              __s64 #{r} = -1;
              if (#{sk}) { #{r} = (__s64)#{sk}->state; bpf_sk_release(#{sk}); }
              #{r};
          })
        SK
      end

      # sk_assign_tcp(saddr, daddr, sport, dport) — look up the TCP socket
      # for the 4-tuple and STEER the current skb to it via bpf_sk_assign (then
      # release the reference). Completes the socket-lookup story: a packet
      # can be delivered to a chosen socket (transparent proxy / socket steering).
      # Returns 0 if assigned, -1 if no socket matched. TC ingress only.
      def sk_assign_tcp_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :tc_ingress
          raise UnsupportedNode, "sk_assign_tcp is only available inside tc__ingress__ methods"
        end
        args = call_args(node)
        raise UnsupportedNode, "sk_assign_tcp expects 4 args (saddr, daddr, sport, dport), got #{args.length}" unless args.length == 4
        sa = lower_stmt(args[0]); da = lower_stmt(args[1]); sp = lower_stmt(args[2]); dp = lower_stmt(args[3])
        @ctx.uses_csum = true # bpf_htonl/htons
        n  = (@tmp_n += 1)
        t  = "_spnl_aktup_#{n}"; sk = "_spnl_ask_#{n}"; r = "_spnl_akr_#{n}"
        <<~AK.chomp
          ({
              struct bpf_sock_tuple #{t} = {};
              #{t}.ipv4.saddr = bpf_htonl((__u32)(#{sa}));
              #{t}.ipv4.daddr = bpf_htonl((__u32)(#{da}));
              #{t}.ipv4.sport = bpf_htons((__u16)(#{sp}));
              #{t}.ipv4.dport = bpf_htons((__u16)(#{dp}));
              struct bpf_sock *#{sk} = bpf_sk_lookup_tcp(ctx, &#{t}, sizeof(#{t}.ipv4), -1, 0);
              __s64 #{r} = -1;
              if (#{sk}) { #{r} = (__s64)bpf_sk_assign(ctx, #{sk}, 0); bpf_sk_release(#{sk}); }
              #{r};
          })
        AK
      end

      # redirect(ifindex) — forward the packet out interface `ifindex` via
      # bpf_redirect (egress). Returns TC_ACT_REDIRECT / XDP_REDIRECT, which the
      # method must return. Combined with fib_lookup this builds a real L3
      # router: look up the egress ifindex for the dst, then redirect to it.
      # XDP/TC only.
      def redirect_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        kind = attach && attach[:kind]
        unless [:xdp, :tc_ingress, :tc_egress].include?(kind)
          raise UnsupportedNode, "redirect is only available inside xdp__ or tc__* methods"
        end
        args = call_args(node)
        raise UnsupportedNode, "redirect expects 1 arg (ifindex), got #{args.length}" unless args.length == 1
        oif = lower_stmt(args[0])
        "(__s64)bpf_redirect((__u32)(#{oif}), 0)"
      end

      # skb-rewrite builtins (TC only — they mutate the live skb, which
      # XDP has no concept of). These are the second family of typed-local-to-
      # helper builtins after fib_lookup: bpf_skb_{load,store}_bytes both
      # take a pointer to a stack buffer, so each emits a typed `__u8` stack
      # local and hands &local to the helper.

      # assert the current method is a TC classifier (skb context).
      def require_tc_context!(name)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        kind = attach && attach[:kind]
        unless [:tc_ingress, :tc_egress].include?(kind)
          raise UnsupportedNode,
                "#{name} is only available inside tc__ingress__/tc__egress__ methods (mutates struct __sk_buff)"
        end
      end

      # skb_load_byte(off) -> read one packet byte at `off` via
      # bpf_skb_load_bytes into a typed __u8 stack local. Returns the byte (0-255)
      # or -1 if the load failed (offset past the linear+paged data).
      def skb_load_byte_call(_nid, node)
        require_tc_context!("skb_load_byte")
        args = call_args(node)
        raise UnsupportedNode, "skb_load_byte expects 1 arg (offset), got #{args.length}" unless args.length == 1
        off = lower_stmt(args[0])
        n = (@tmp_n += 1)
        b = "_spnl_lb_#{n}"
        "({ __u8 #{b} = 0; __s64 _r#{n} = bpf_skb_load_bytes(ctx, (#{off}), &#{b}, 1); (__s64)(_r#{n} < 0 ? (__s64)-1 : (__s64)#{b}); })"
      end

      # skb_store_byte(off, val) -> write one packet byte at `off` via
      # bpf_skb_store_bytes from a typed __u8 stack local. Returns 0 on success,
      # negative on error. flags=0 (caller fixes checksums via l3/l4_csum_replace).
      def skb_store_byte_call(_nid, node)
        require_tc_context!("skb_store_byte")
        args = call_args(node)
        raise UnsupportedNode, "skb_store_byte expects 2 args (offset, value), got #{args.length}" unless args.length == 2
        off = lower_stmt(args[0])
        val = lower_stmt(args[1])
        n = (@tmp_n += 1)
        b = "_spnl_sb_#{n}"
        "({ __u8 #{b} = (__u8)(#{val}); (__s64)bpf_skb_store_bytes(ctx, (#{off}), &#{b}, 1, 0); })"
      end

      # l3_csum_replace(off, from, to) / l4_csum_replace(off, from, to) —
      # incrementally fix the L3 (IP) or L4 (TCP/UDP) checksum at `off` after a
      # 16-bit field changed from `from` to `to`. `from`/`to` are the old/new
      # 16-bit field values in *host* order; the builtin htons-es them to the
      # network-order representation the one's-complement update expects. size=2
      # (16-bit). (Wider fields / pseudo-header L4 updates are a follow-up.)
      def csum_replace_call(_nid, node, layer:)
        fn = layer == 3 ? "bpf_l3_csum_replace" : "bpf_l4_csum_replace"
        nm = layer == 3 ? "l3_csum_replace" : "l4_csum_replace"
        require_tc_context!(nm)
        args = call_args(node)
        raise UnsupportedNode, "#{nm} expects 3 args (offset, from, to), got #{args.length}" unless args.length == 3
        off  = lower_stmt(args[0])
        from = lower_stmt(args[1])
        to   = lower_stmt(args[2])
        @ctx.uses_csum = true # bpf_htons → needs bpf_endian.h
        "(__s64)#{fn}(ctx, (#{off}), bpf_htons((__u16)(#{from})), bpf_htons((__u16)(#{to})), 2)"
      end

      # NAT family — 32-bit (IPv4 address) packet read/write + checksum
      # repair across both the L3 (IP) header and the L4 (TCP/UDP) pseudo-header.
      # All values are HOST byte order at the DSL surface (intuitive for the Ruby
      # author); the builtins htonl them to the network-order representation the
      # packet and the csum helpers expect. TC only.

      # skb_load_u32(off) -> read a 4-byte field (e.g. an IPv4 address) at
      # `off` and return it in host byte order, or -1 on load failure.
      def skb_load_u32_call(_nid, node)
        require_tc_context!("skb_load_u32")
        args = call_args(node)
        raise UnsupportedNode, "skb_load_u32 expects 1 arg (offset), got #{args.length}" unless args.length == 1
        off = lower_stmt(args[0])
        @ctx.uses_csum = true # bpf_ntohl
        n = (@tmp_n += 1)
        b = "_spnl_l4r_#{n}"
        "({ __u32 #{b} = 0; __s64 _r#{n} = bpf_skb_load_bytes(ctx, (#{off}), &#{b}, 4); (__s64)(_r#{n} < 0 ? (__s64)-1 : (__s64)(__u32)bpf_ntohl(#{b})); })"
      end

      # skb_store_u32(off, val) -> write `val` (host order) as a 4-byte
      # network-order field at `off`. Returns 0 on success.
      def skb_store_u32_call(_nid, node)
        require_tc_context!("skb_store_u32")
        args = call_args(node)
        raise UnsupportedNode, "skb_store_u32 expects 2 args (offset, value), got #{args.length}" unless args.length == 2
        off = lower_stmt(args[0])
        val = lower_stmt(args[1])
        @ctx.uses_csum = true # bpf_htonl
        n = (@tmp_n += 1)
        b = "_spnl_su_#{n}"
        "({ __u32 #{b} = bpf_htonl((__u32)(#{val})); (__s64)bpf_skb_store_bytes(ctx, (#{off}), &#{b}, 4, 0); })"
      end

      # l3_csum_replace_ip(off, from, to) / l4_csum_replace_ip(off, from, to)
      # — incremental checksum repair after a 32-bit IPv4 address changed from
      # `from` to `to` (host order). The L4 variant sets BPF_F_PSEUDO_HDR (0x10)
      # because the address lives in the TCP/UDP pseudo-header, and size=4.
      def csum_replace_ip_call(_nid, node, layer:)
        fn = layer == 3 ? "bpf_l3_csum_replace" : "bpf_l4_csum_replace"
        nm = layer == 3 ? "l3_csum_replace_ip" : "l4_csum_replace_ip"
        require_tc_context!(nm)
        args = call_args(node)
        raise UnsupportedNode, "#{nm} expects 3 args (offset, from, to), got #{args.length}" unless args.length == 3
        off  = lower_stmt(args[0])
        from = lower_stmt(args[1])
        to   = lower_stmt(args[2])
        @ctx.uses_csum = true
        # L3: size 4. L4: BPF_F_PSEUDO_HDR (1<<4) | size 4 — the IPv4 address is
        # part of the L4 pseudo-header, so the helper must fold the change in.
        flags = layer == 3 ? "4" : "((1 << 4) | 4)"
        "(__s64)#{fn}(ctx, (#{off}), bpf_htonl((__u32)(#{from})), bpf_htonl((__u32)(#{to})), #{flags})"
      end

      # skb_load_u16(off) / skb_store_u16(off, val) — 16-bit (e.g. a TCP/UDP
      # port) packet read/write. Host byte order at the DSL surface (ntohs on
      # load, htons on store). Pairs with l4_csum_replace (size 2, no
      # pseudo-header) for port rewrites — a port lives in the L4 header, not the
      # pseudo-header, so only the L4 checksum needs fixing. TC only.
      def skb_load_u16_call(_nid, node)
        require_tc_context!("skb_load_u16")
        args = call_args(node)
        raise UnsupportedNode, "skb_load_u16 expects 1 arg (offset), got #{args.length}" unless args.length == 1
        off = lower_stmt(args[0])
        @ctx.uses_csum = true # bpf_ntohs
        n = (@tmp_n += 1)
        b = "_spnl_l2r_#{n}"
        "({ __u16 #{b} = 0; __s64 _r#{n} = bpf_skb_load_bytes(ctx, (#{off}), &#{b}, 2); (__s64)(_r#{n} < 0 ? (__s64)-1 : (__s64)(__u16)bpf_ntohs(#{b})); })"
      end

      def skb_store_u16_call(_nid, node)
        require_tc_context!("skb_store_u16")
        args = call_args(node)
        raise UnsupportedNode, "skb_store_u16 expects 2 args (offset, value), got #{args.length}" unless args.length == 2
        off = lower_stmt(args[0])
        val = lower_stmt(args[1])
        @ctx.uses_csum = true # bpf_htons
        n = (@tmp_n += 1)
        b = "_spnl_s2_#{n}"
        "({ __u16 #{b} = bpf_htons((__u16)(#{val})); (__s64)bpf_skb_store_bytes(ctx, (#{off}), &#{b}, 2, 0); })"
      end

      # l4_offset() — byte offset where the L4 (TCP/UDP) header starts,
      # accounting for IPv4 options. = 14 (Ethernet) + IHL*4. Reads the
      # version/IHL byte at offset 14 and uses the low nibble. Lets NAT/LB code be
      # robust to IP options instead of assuming a fixed 34 (IHL=5). TC only.
      def l4_offset_call(_nid, node)
        require_tc_context!("l4_offset")
        args = call_args(node)
        raise UnsupportedNode, "l4_offset expects 0 args, got #{args.length}" unless args.empty?
        n = (@tmp_n += 1)
        b = "_spnl_lo#{n}"
        "({ __u8 #{b} = 0; bpf_skb_load_bytes(ctx, 14, &#{b}, 1); (__s64)(14 + (#{b} & 0x0f) * 4); })"
      end

      # arena_set(idx, val) / arena_get(idx) — read/write a u64 slot in the
      # bpf_arena-backed array (sparse, mmap-able shared memory; see emit_arena_map).
      # The access is a plain dereference through an __arena pointer — no map
      # helper — and the index is masked to the in-page slot count so the verifier
      # is happy. Works in any program type (the arena global is not ctx-bound).
      def arena_set_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_set expects 2 args (index, value), got #{args.length}" unless args.length == 2
        idx = lower_stmt(args[0])
        val = lower_stmt(args[1])
        @ctx.uses_arena = true
        data = "#{@ctx.unit_name}_arena_data"
        "({ #{data}[(__u64)(#{idx}) & #{ARENA_SLOTS - 1}] = (__u64)(#{val}); (__s64)0; })"
      end

      def arena_get_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_get expects 1 arg (index), got #{args.length}" unless args.length == 1
        idx = lower_stmt(args[0])
        @ctx.uses_arena = true
        data = "#{@ctx.unit_name}_arena_data"
        "((__s64)#{data}[(__u64)(#{idx}) & #{ARENA_SLOTS - 1}])"
      end

      # arena_hash_set(key, val) / arena_hash_get(key) — an open-addressing
      # hash table living IN the arena. A real data structure (not just a flat
      # array) backed by arena memory: the 512-slot arena array is treated as
      # #{ARENA_HASH_BUCKETS} (key, value) pairs, indexed by a multiplicative hash
      # of the key with 8-way linear probing (fully unrolled — no runtime loop).
      # key 0 is reserved as the empty marker. Same value is mmap-able by
      # userspace, so this is a kernel/user shared hash map. set returns 1 if the
      # entry was stored (0 if all 8 probe slots were taken); get returns the
      # value or 0 if absent. Shares the arena array with arena_set/get, so a
      # program should pick one interpretation.
      ARENA_HASH_BUCKETS = 256 # ARENA_SLOTS / 2 (key,val) pairs
      ARENA_HASH_PROBES  = 8
      def arena_hash_set_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_hash_set expects 2 args (key, value), got #{args.length}" unless args.length == 2
        key = lower_stmt(args[0])
        val = lower_stmt(args[1])
        @ctx.uses_arena = true
        n = (@tmp_n += 1)
        d = "#{@ctx.unit_name}_arena_data"
        k = "_hk#{n}"; v = "_hv#{n}"; h = "_hh#{n}"; ok = "_hok#{n}"; i = "_hi#{n}"; s = "_hs#{n}"; ek = "_hek#{n}"
        <<~HS.chomp
          ({
              __u64 #{k} = (__u64)(#{key}); __u64 #{v} = (__u64)(#{val}); __s64 #{ok} = 0;
              __u32 #{h} = ((__u32)#{k} * 2654435761U) & #{ARENA_HASH_BUCKETS - 1}U;
              #pragma unroll
              for (int #{i} = 0; #{i} < #{ARENA_HASH_PROBES}; #{i}++) {
                  __u32 #{s} = (#{h} + (__u32)#{i}) & #{ARENA_HASH_BUCKETS - 1}U;
                  __u64 #{ek} = #{d}[2U * #{s}];
                  if (!#{ok} && (#{ek} == 0 || #{ek} == #{k})) {
                      #{d}[2U * #{s}] = #{k}; #{d}[2U * #{s} + 1] = #{v}; #{ok} = 1;
                  }
              }
              #{ok};
          })
        HS
      end

      def arena_hash_get_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_hash_get expects 1 arg (key), got #{args.length}" unless args.length == 1
        key = lower_stmt(args[0])
        @ctx.uses_arena = true
        n = (@tmp_n += 1)
        d = "#{@ctx.unit_name}_arena_data"
        k = "_hk#{n}"; r = "_hr#{n}"; f = "_hf#{n}"; h = "_hh#{n}"; i = "_hi#{n}"; s = "_hs#{n}"; ek = "_hek#{n}"
        <<~HG.chomp
          ({
              __u64 #{k} = (__u64)(#{key}); __s64 #{r} = 0; __s64 #{f} = 0;
              __u32 #{h} = ((__u32)#{k} * 2654435761U) & #{ARENA_HASH_BUCKETS - 1}U;
              #pragma unroll
              for (int #{i} = 0; #{i} < #{ARENA_HASH_PROBES}; #{i}++) {
                  __u32 #{s} = (#{h} + (__u32)#{i}) & #{ARENA_HASH_BUCKETS - 1}U;
                  __u64 #{ek} = #{d}[2U * #{s}];
                  if (!#{f} && #{ek} == #{k}) { #{r} = (__s64)#{d}[2U * #{s} + 1]; #{f} = 1; }
              }
              #{r};
          })
        HG
      end

      # arena_hash_del(key) — delete a key from the arena hash table by
      # marking its slot as a tombstone (~0ULL). get/set skip tombstones (they
      # are neither 0 nor a real key), so probe chains stay intact; the slot is
      # not reclaimed (documented limitation). Returns 1 if a key was removed,
      # 0 if it was absent. key ~0 is reserved (the tombstone marker), like key 0.
      def arena_hash_del_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_hash_del expects 1 arg (key), got #{args.length}" unless args.length == 1
        key = lower_stmt(args[0])
        @ctx.uses_arena = true
        n = (@tmp_n += 1)
        d = "#{@ctx.unit_name}_arena_data"
        k = "_hk#{n}"; del = "_hd#{n}"; h = "_hh#{n}"; i = "_hi#{n}"; s = "_hs#{n}"; ek = "_hek#{n}"
        <<~HD.chomp
          ({
              __u64 #{k} = (__u64)(#{key}); __s64 #{del} = 0;
              __u32 #{h} = ((__u32)#{k} * 2654435761U) & #{ARENA_HASH_BUCKETS - 1}U;
              #pragma unroll
              for (int #{i} = 0; #{i} < #{ARENA_HASH_PROBES}; #{i}++) {
                  __u32 #{s} = (#{h} + (__u32)#{i}) & #{ARENA_HASH_BUCKETS - 1}U;
                  __u64 #{ek} = #{d}[2U * #{s}];
                  if (!#{del} && #{ek} == #{k}) { #{d}[2U * #{s}] = ~0ULL; #{d}[2U * #{s} + 1] = 0; #{del} = 1; }
              }
              #{del};
          })
        HD
      end

      # arena_list_push(value) / arena_list_sum() — a singly-linked list
      # living IN the arena, demonstrating pointer-like references (here: indices)
      # in arena memory without a runtime allocator. Layout over the 512-slot
      # arena array: slot 0 = head node index (0 = nil), slot 1 = bump pointer
      # (next free node). Node i (i>=1) is the pair (data[2*i] = value,
      # data[2*i+1] = next index). push prepends (LIFO); sum walks the list
      # (bounded to #{ARENA_LIST_WALK} nodes, fully unrolled) and totals the
      # values. Up to #{ARENA_HASH_BUCKETS - 1} nodes. Shares the arena array, so
      # a program uses one structure (list / hash / flat).
      ARENA_LIST_WALK = 16
      def arena_list_push_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_list_push expects 1 arg (value), got #{args.length}" unless args.length == 1
        val = lower_stmt(args[0])
        @ctx.uses_arena = true
        n = (@tmp_n += 1)
        d = "#{@ctx.unit_name}_arena_data"
        v = "_lv#{n}"; i = "_li#{n}"; ok = "_lok#{n}"
        <<~LP.chomp
          ({
              __u64 #{v} = (__u64)(#{val});
              __u64 #{i} = #{d}[1];          /* bump pointer */
              if (#{i} == 0) #{i} = 1;       /* node indices start at 1 */
              __s64 #{ok} = 0;
              if (#{i} < #{ARENA_HASH_BUCKETS}) {
                  #{d}[(2U * #{i}) & #{ARENA_SLOTS - 1}] = #{v};
                  #{d}[(2U * #{i} + 1) & #{ARENA_SLOTS - 1}] = #{d}[0]; /* next = head */
                  #{d}[0] = #{i};            /* head = new node */
                  #{d}[1] = #{i} + 1;        /* bump++ */
                  #{ok} = 1;
              }
              #{ok};
          })
        LP
      end

      def arena_list_sum_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "arena_list_sum expects 0 args, got #{args.length}" unless args.empty?
        @ctx.uses_arena = true
        n = (@tmp_n += 1)
        d = "#{@ctx.unit_name}_arena_data"
        sum = "_ls#{n}"; cur = "_lc#{n}"; j = "_lj#{n}"
        <<~LS.chomp
          ({
              __u64 #{sum} = 0, #{cur} = #{d}[0];   /* head */
              #pragma unroll
              for (int #{j} = 0; #{j} < #{ARENA_LIST_WALK}; #{j}++) {
                  if (#{cur} != 0 && #{cur} < #{ARENA_HASH_BUCKETS}) {
                      #{sum} += #{d}[(2U * #{cur}) & #{ARENA_SLOTS - 1}];
                      #{cur} = #{d}[(2U * #{cur} + 1) & #{ARENA_SLOTS - 1}];
                  }
              }
              (__s64)#{sum};
          })
        LS
      end

      def blocklist_match_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "blocklist_match expects 1 arg (ip), got #{args.length}" unless args.length == 1
        @ctx.uses_blocklist = true
        "spnl_blocklist_match(#{lower_stmt(args[0])})"
      end

      # cidr_blocklist_match(ip_host_order) -> 1 if ip falls under any
      # blocked prefix (LPM_TRIE longest match), else 0. Populated from
      # userspace via sp_bpf_cidr_blocklist_add(ip, prefixlen).
      def cidr_blocklist_match_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "cidr_blocklist_match expects 1 arg (ip), got #{args.length}" unless args.length == 1
        @ctx.uses_cidr_blocklist = true
        "spnl_cidr_blocklist_match(#{lower_stmt(args[0])})"
      end

      # path_counter_inc(key) lowering. Marks ctx.uses_path_counter so
      # the bpf_path_counts map + spnl_path_counter_inc helper are emitted.
      # Pushes the call to @lines as a side-effecting statement (same pattern
      # as spnl_emit_call) so it isn't dropped when the call's return value
      # is unused. Returns "0" as the expression value.
      def path_counter_inc_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "path_counter_inc expects 1 arg (key), got #{args.length}" unless args.length == 1
        @ctx.uses_path_counter = true
        key_expr = lower_stmt(args[0])
        @lines << CAst.expr_stmt(CAst.call("spnl_path_counter_inc", CAst.raw(key_expr))).to_c
        no_value
      end

      # leak_record(ptr, size, stack_id) — record an outstanding
      # allocation keyed by its pointer (bcc memleak). Pair with leak_forget on
      # free; surviving entries at report time are leaks.
      def leak_record_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "leak_record expects 3 args (ptr, size, stack_id), got #{args.length}" unless args.length == 3
        @ctx.uses_leak_track = true
        ptr_expr = lower_stmt(args[0])
        size_expr = lower_stmt(args[1])
        sid_expr = lower_stmt(args[2])
        @lines << CAst.expr_stmt(CAst.call("spnl_leak_record", CAst.raw(ptr_expr), CAst.raw(size_expr), CAst.raw(sid_expr))).to_c
        no_value
      end

      # leak_forget(ptr) — drop a tracked allocation on free.
      def leak_forget_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "leak_forget expects 1 arg (ptr), got #{args.length}" unless args.length == 1
        @ctx.uses_leak_track = true
        ptr_expr = lower_stmt(args[0])
        @lines << CAst.expr_stmt(CAst.call("spnl_leak_forget", CAst.raw(ptr_expr))).to_c
        no_value
      end

      # hist_observe(value) lowering. Marks ctx.uses_histogram so the
      # bpf_hist ARRAY + spnl_hist_log2 + spnl_hist_observe helpers are
      # emitted. Side-effecting statement (same pattern as path_counter_inc);
      # the call's return value is `0` and usually discarded.
      def hist_observe_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "hist_observe expects 1 arg (value), got #{args.length}" unless args.length == 1
        @ctx.uses_histogram = true
        val_expr = lower_stmt(args[0])
        @lines << CAst.expr_stmt(CAst.call("spnl_hist_observe", CAst.raw(val_expr))).to_c
        no_value
      end

      # hist_observe_by(key, value) lowering. The keyed-hist helper
      # internally calls spnl_hist_log2 from the log2 histogram, so we also flag
      # uses_histogram to make sure the log2 helper is emitted.
      def hist_observe_by_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "hist_observe_by expects 2 args (key, value), got #{args.length}" unless args.length == 2
        @ctx.uses_histogram = true
        @ctx.uses_histogram_keyed = true
        key_expr = lower_stmt(args[0])
        val_expr = lower_stmt(args[1])
        @lines << CAst.expr_stmt(CAst.call("spnl_hist_observe_by", CAst.raw(key_expr), CAst.raw(val_expr))).to_c
        no_value
      end

      # hist_observe_linear(slot) lowering. Caller pre-buckets the
      # value (e.g. `hist_observe_linear(latency_end / 1000)` for µs).
      def hist_observe_linear_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "hist_observe_linear expects 1 arg (slot), got #{args.length}" unless args.length == 1
        @ctx.uses_histogram_linear = true
        slot_expr = lower_stmt(args[0])
        @lines << CAst.expr_stmt(CAst.call("spnl_hist_observe_linear", CAst.raw(slot_expr))).to_c
        no_value
      end

      # zero-arg kernel context builtins. Each lowers to a 1-line C
      # expression with no side effects (no map manipulation), so they're
      # safe to call anywhere lower_stmt can appear (including inside ivar
      # writes, arithmetic, hist_observe arguments, etc.).
      def expect_no_args(node, name)
        args_id = node.refs.fetch("arguments", -1)
        return if args_id < 0
        args_node = @ctx.ast.node(args_id)
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "#{name} takes no arguments, got #{args.length}" unless args.empty?
      end

      # Build pure-expression builtins via the C-AST and stringify with `.to_c`
      # (downstream still receives a string as before). Output is byte-identical
      # (each string is pinned in c_ast_test.rb). CParen is the explicit model for the current code's
      # defensive outer parens; a later phase drops the redundant ones based on precedence.
      def ktime_ns_call(node)
        expect_no_args(node, "ktime_ns")
        CAst.s64(CAst.call("bpf_ktime_get_ns")).to_c
      end

      def tgid_call(node)
        expect_no_args(node, "tgid")
        # upper 32 bits of bpf_get_current_pid_tgid() — what userspace calls "pid"
        pid_tgid_high.to_c
      end

      def pid_call(node)
        # Alias for tgid() — bcc convention is `bpf_get_current_pid_tgid() >> 32`
        # is the userspace PID. We expose both names; users pick by taste.
        expect_no_args(node, "pid")
        pid_tgid_high.to_c
      end

      def tid_call(node)
        expect_no_args(node, "tid")
        # lower 32 bits — kernel-side thread id
        CAst.s64(CAst.cast("__u32", CAst.call("bpf_get_current_pid_tgid"))).to_c
      end

      # ((__s64)(bpf_get_current_pid_tgid() >> 32)) — shared expression tree for tgid/pid.
      def pid_tgid_high
        CAst.s64(CAst.paren(CAst.binop(">>", CAst.call("bpf_get_current_pid_tgid"), CAst.lit("32"))))
      end

      # latency_start / latency_end — bcc's BEGIN()/END() pattern. The
      # generated helpers (emit_latency_map_and_helper) handle the per-tid
      # HASH map; here we just emit the side-effecting call.
      def latency_start_call(node)
        expect_no_args(node, "latency_start")
        @ctx.uses_latency = true
        # Structure the side-effecting statement as CStmt (CExprStmt) (byte-identical).
        @lines << CAst.expr_stmt(CAst.call("spnl_latency_start")).to_c
        no_value
      end

      def latency_end_call(node)
        expect_no_args(node, "latency_end")
        @ctx.uses_latency = true
        # Returns the delta as an expression value so callers can do e.g.
        #   hist_observe(latency_end)
        CAst.call("spnl_latency_end").to_c
      end

      # task_load() -> current task's stored value (0 if none).
      def task_load_call(node)
        expect_no_args(node, "task_load")
        @ctx.uses_task_storage = true
        CAst.call("spnl_task_load").to_c
      end

      # task_store(v) -> store v in the current task's local storage
      # (creating the entry if absent); returns v.
      def task_store_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "task_store expects 1 arg (value), got #{args.length}" unless args.length == 1
        @ctx.uses_task_storage = true
        CAst.call("spnl_task_store", CAst.raw(lower_stmt(args[0]))).to_c
      end

      # task_incr(delta) -> single-get read-modify-write on the current
      # task's storage; returns the new total.
      def task_incr_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "task_incr expects 1 arg (delta), got #{args.length}" unless args.length == 1
        @ctx.uses_task_storage = true
        CAst.call("spnl_task_incr", CAst.raw(lower_stmt(args[0]))).to_c
      end

      # task_swap(v) — single-get read-modify-write on per-task storage:
      # store v, return the previous value. The atomic RMW the deadlock detector
      # needs (record the previously-held lock + remember the new one) without
      # tripping the two-get quirk (two storage gets in one execution alias
      # to different objects).
      def task_swap_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "task_swap expects 1 arg (value), got #{args.length}" unless args.length == 1
        @ctx.uses_task_storage = true
        CAst.call("spnl_task_swap", CAst.raw(lower_stmt(args[0]))).to_c
      end

      # lock_edge(a, b) — record a lock-acquisition-order edge a->b (thread
      # held a, then acquired b) into the bpf_lock_edges HASH (keyed by the pair).
      # Userspace detects cycles (a->b and b->a) = potential deadlock.
      def lock_edge_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "lock_edge expects 2 args (a, b), got #{args.length}" unless args.length == 2
        @ctx.uses_lock_edge = true
        a = lower_stmt(args[0])
        b = lower_stmt(args[1])
        @lines << CAst.expr_stmt(CAst.call("spnl_lock_edge", CAst.raw(a), CAst.raw(b))).to_c
        no_value
      end

      # lat_start(key) — stamp entry time keyed by an arbitrary id.
      def lat_start_key_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "lat_start expects 1 arg (key), got #{args.length}" unless args.length == 1
        @ctx.uses_keyed_lat = true
        CAst.call("spnl_lat_start_key", CAst.raw(lower_stmt(args[0]))).to_c
      end

      # lat_end(key) — return now - entry (ns) for `key` and clear it.
      def lat_end_key_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "lat_end expects 1 arg (key), got #{args.length}" unless args.length == 1
        @ctx.uses_keyed_lat = true
        CAst.call("spnl_lat_end_key", CAst.raw(lower_stmt(args[0]))).to_c
      end

      # depth_inc(key) / depth_dec(key) — per-(tid,method) recursion depth
      # for --instrument depth-collapse. Returns the depth after the operation.
      def depth_inc_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "depth_inc expects 1 arg (key), got #{args.length}" unless args.length == 1
        @ctx.uses_depth = true
        CAst.call("spnl_depth_inc", CAst.raw(lower_stmt(args[0]))).to_c
      end

      def depth_dec_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "depth_dec expects 1 arg (key), got #{args.length}" unless args.length == 1
        @ctx.uses_depth = true
        CAst.call("spnl_depth_dec", CAst.raw(lower_stmt(args[0]))).to_c
      end

      # mim_inc(group, key) -> increment the map-in-map cell
      # outer[group][key], returns the new total. mim_get reads it.
      def mim_inc_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "mim_inc expects 2 args (group, key), got #{args.length}" unless args.length == 2
        @ctx.uses_map_in_map = true
        CAst.call("spnl_mim_inc", CAst.raw(lower_stmt(args[0])), CAst.raw(lower_stmt(args[1]))).to_c
      end

      def mim_get_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "mim_get expects 2 args (group, key), got #{args.length}" unless args.length == 2
        @ctx.uses_map_in_map = true
        CAst.call("spnl_mim_get", CAst.raw(lower_stmt(args[0])), CAst.raw(lower_stmt(args[1]))).to_c
      end

      # QUEUE/STACK push/pop. push(v) returns 0 on success; pop() returns
      # the dequeued value (0 if empty).
      def fifo_push_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "fifo_push expects 1 arg (value), got #{args.length}" unless args.length == 1
        @ctx.uses_fifo = true
        CAst.call("spnl_fifo_push", CAst.raw(lower_stmt(args[0]))).to_c
      end

      def fifo_pop_call(node)
        expect_no_args(node, "fifo_pop")
        @ctx.uses_fifo = true
        CAst.call("spnl_fifo_pop").to_c
      end

      def lifo_push_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "lifo_push expects 1 arg (value), got #{args.length}" unless args.length == 1
        @ctx.uses_lifo = true
        CAst.call("spnl_lifo_push", CAst.raw(lower_stmt(args[0]))).to_c
      end

      def lifo_pop_call(node)
        expect_no_args(node, "lifo_pop")
        @ctx.uses_lifo = true
        CAst.call("spnl_lifo_pop").to_c
      end

      # divu(a, b) — unsigned 64bit division. BPF verifier rejects
      # signed div on __s64 operands; the spinel-ebpf default for `/` is
      # signed. This builtin gives users a clean way to opt into unsigned
      # division when the operand range guarantees positivity.
      def divu_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "divu expects 2 args (a, b), got #{args.length}" unless args.length == 2
        # Cast to unsigned first; result re-cast to __s64 for type uniformity.
        # Turn the operand into a true CExpr via lower_expr (byte-identical).
        CAst.s64(
          CAst.paren(
            CAst.binop("/",
                       CAst.cast("__u64", CAst.paren(lower_expr(args[0]))),
                       CAst.cast("__u64", CAst.paren(lower_expr(args[1]))))
          )
        ).to_c
      end

      # comm_hash() — return the first 8 bytes of the current task's
      # `comm` (process name, TASK_COMM_LEN=16) as a __s64. Useful for
      # grouping by process name without emitting strings. Short names
      # (<=8 chars) are unique; longer names alias by their prefix.
      def comm_hash_call(node)
        expect_no_args(node, "comm_hash")
        # Inline rather than a static helper — comm[16] on stack is only
        # 16 bytes, fits trivially within the 512B BPF stack limit. The
        # statement-expression is emitted as a side-effecting block then
        # an expression hands the value back.
        tmp = fresh("ch")
        @lines << "char #{tmp}[16] = {0};"
        @lines << "bpf_get_current_comm(#{tmp}, sizeof(#{tmp}));"
        "((__s64)(*((__u64 *)#{tmp})))"
      end

      # cpu_id() — the current CPU index (bpf_get_smp_processor_id). Used
      # to key per-CPU state (e.g. hardirqs/softirqs latency, where one handler
      # runs per CPU at a time so the CPU id is a collision-free key).
      def cpu_id_call(node)
        expect_no_args(node, "cpu_id")
        # Via the C-AST (byte-identical; pinned in c_ast_test.rb).
        CAst.s64(CAst.call("bpf_get_smp_processor_id")).to_c
      end

      # stack_id() / user_stack_id() — capture a stack trace, return
      # its id (non-negative). Host code looks up the id in bpf_stacks
      # to retrieve the PCs. Negative return means the verifier rejected
      # the capture (typically stack too deep) — callers should guard.
      # `user_stack_id` uses BPF_F_USER_STACK (1 << 8) for the flags arg.
      def stack_id_call(node, user:)
        expect_no_args(node, user ? "user_stack_id" : "stack_id")
        @ctx.uses_stack_trace = true
        flags = user ? "(1ULL << 8)" : "0"
        # bpf_get_stackid requires the original program ctx — XDP, kprobe,
        # etc. all pass the same `ctx` argument we already have in scope.
        "((__s64)bpf_get_stackid(ctx, &#{STACK_TRACE_MAP_NAME}, #{flags}))"
      end

      # off_cpu_start(pid) / off_cpu_observe(pid) — bcc offcputime.py
      # pattern. start() captures (ktime, current kernel stack id) under
      # `pid` in bpf_off_cpu; observe() picks it back up when the task
      # comes back on-CPU, computes the delta ns, bins (stack_id, delta)
      # into the keyed hist, and deletes the entry. Setting all four
      # flags (off_cpu/histogram/keyed/stack_trace) ensures every map and
      # log2 helper the observe() body references is also emitted.
      def off_cpu_start_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "off_cpu_start expects 1 arg (pid), got #{args.length}" unless args.length == 1
        @ctx.uses_off_cpu = true
        @ctx.uses_histogram = true
        @ctx.uses_histogram_keyed = true
        @ctx.uses_stack_trace = true
        pid_expr = lower_stmt(args[0])
        @lines << CAst.expr_stmt(CAst.call("spnl_off_cpu_start", CAst.raw("(__u32)(#{pid_expr})"), CAst.raw("ctx"))).to_c
        no_value
      end

      # scx_bpf_* kfunc family. Each Ruby builtin maps to a kernel
      # kfunc declared as `__weak __ksym` in emit_sched_ext_preamble. The
      # first arg of scx_dispatch is `struct task_struct *p` — Ruby passes
      # the bare `p` (a __s64 from inner sig) and we cast it back to the
      # kernel pointer type here.
      # Kernel-side names changed in recent sched_ext API:
      #   scx_bpf_dispatch       -> scx_bpf_dsq_insert
      #   scx_bpf_consume        -> scx_bpf_dsq_move_to_local
      # We keep the spinel-side Ruby names short + stable (scx_dispatch /
      # scx_consume) and route them to whichever kernel symbol is current.
      SCX_KFUNC_TABLE = {
        "scx_dispatch"      => { kfunc: "scx_bpf_dsq_insert",        arity: 4, cast0: "(struct task_struct *)(unsigned long)" },
        "scx_consume"       => { kfunc: "scx_bpf_dsq_move_to_local", arity: 1 },
        "scx_kick_cpu"      => { kfunc: "scx_bpf_kick_cpu",          arity: 2 },
        "scx_pick_idle_cpu" => { kfunc: "scx_bpf_pick_idle_cpu",     arity: 2, cast0: "(const struct cpumask *)(unsigned long)" },
        "scx_create_dsq"    => { kfunc: "scx_bpf_create_dsq",        arity: 2 },
      }.freeze

      def scx_kfunc_call(nid, node, name)
        info = SCX_KFUNC_TABLE[name] or raise UnsupportedNode, "scx kfunc #{name} unknown"
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "#{name} expects #{info[:arity]} args, got #{args.length}" unless args.length == info[:arity]
        exprs = args.each_with_index.map do |aid, i|
          e = lower_stmt(aid)
          c = (i == 0) ? info[:cast0] : nil
          c ? "#{c}(#{e})" : e
        end
        # Side-effecting calls (dispatch/kick/create) are emitted as @lines
        # statements so the verifier sees a definite call point; the
        # expression value (0) is rarely meaningful. consume/pick_idle_cpu
        # return useful values so we emit them as expressions.
        case name
        when "scx_consume", "scx_pick_idle_cpu"
          "((__s64)#{info[:kfunc]}(#{exprs.join(", ")}))"
        else
          # Structure the kfunc call statement as CExprStmt (byte-identical).
          @lines << CAst.expr_stmt(CAst.call(info[:kfunc], *exprs.map { |e| CAst.raw(e) })).to_c
          no_value
        end
      end

      # BPF qdisc kfuncs. Same shape as SCX_KFUNC_TABLE but with the
      # casts appropriate to Qdisc_ops member signatures (skb / sch /
      # to_free / extack are kernel pointers passed as __s64 to the inner).
      QDISC_KFUNC_TABLE = {
        "qdisc_skb_drop"               => { kfunc: "bpf_qdisc_skb_drop",
                                            arity: 2,
                                            casts: ["(struct sk_buff *)(unsigned long)",
                                                    "(struct bpf_sk_buff_ptr *)(unsigned long)"] },
        "qdisc_init_prologue"          => { kfunc: "bpf_qdisc_init_prologue",
                                            arity: 2,
                                            casts: ["(struct Qdisc *)(unsigned long)",
                                                    "(struct netlink_ext_ack *)(unsigned long)"] },
        "qdisc_reset_destroy_epilogue" => { kfunc: "bpf_qdisc_reset_destroy_epilogue",
                                            arity: 1,
                                            casts: ["(struct Qdisc *)(unsigned long)"] },
        "qdisc_watchdog_schedule"      => { kfunc: "bpf_qdisc_watchdog_schedule",
                                            arity: 3,
                                            casts: ["(struct Qdisc *)(unsigned long)"] },
        "qdisc_bstats_update"          => { kfunc: "bpf_qdisc_bstats_update",
                                            arity: 2,
                                            casts: ["(struct Qdisc *)(unsigned long)",
                                                    "(const struct sk_buff *)(unsigned long)"] },
      }.freeze

      def qdisc_kfunc_call(nid, node, name)
        info = QDISC_KFUNC_TABLE[name] or raise UnsupportedNode, "qdisc kfunc #{name} unknown"
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "#{name} expects #{info[:arity]} args, got #{args.length}" unless args.length == info[:arity]
        casts = info[:casts] || []
        exprs = args.each_with_index.map do |aid, i|
          e = lower_stmt(aid)
          c = casts[i]
          c ? "#{c}(#{e})" : e
        end
        # All qdisc kfuncs are side-effecting / void-ish; the only one we
        # might want a return for is init_prologue (returns int) — emit as
        # statement uniformly and let Ruby get "0" back.
        # Structure the kfunc call statement as CExprStmt (byte-identical).
        @lines << CAst.expr_stmt(CAst.call(info[:kfunc], *exprs.map { |e| CAst.raw(e) })).to_c
        no_value
      end

      # queue_push(skb, to_free) — try to push skb onto the per-unit
      # BPF list. Returns NET_XMIT_SUCCESS (0) or NET_XMIT_DROP (1) on
      # allocation/lock/list failure (with skb already cleaned up).
      # We emit the entire enqueue dance as a `do { ... } while (0)` block
      # that assigns to a temp; the temp's name is the expression value.
      def queue_push_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "queue_push expects 2 args (skb, to_free), got #{args.length}" unless args.length == 2
        @ctx.uses_qdisc_fifo = true
        skb_expr = lower_stmt(args[0])
        tf_expr  = lower_stmt(args[1])
        ret_var  = fresh("qp_ret")
        skb_c    = "(struct sk_buff *)(unsigned long)(#{skb_expr})"
        tf_c     = "(struct bpf_sk_buff_ptr *)(unsigned long)(#{tf_expr})"
        # Verifier note: after bpf_list_push_back_impl, the verifier always
        # releases the wrapper reference (ref_obj_id) regardless of return
        # value. So we MUST NOT call bpf_obj_drop(_qpn) on the push failure
        # path — that triggers "R1 must be referenced or trusted". Since
        # push_back only fails when the node is already in a list (it isn't
        # in our usage), this is effectively unreachable; treat it as
        # NET_XMIT_SUCCESS so the verifier accepts the prog. The skb is
        # already lodged in _qpn->skb via kptr_xchg, so it won't leak in
        # practice — even if we somehow reached this path the kernel
        # would GC the wrapper.
        @lines << "__s64 #{ret_var} = 1;  /* NET_XMIT_DROP unless we make it through */"
        @lines << "do {"
        @lines << "    struct spnl_qdisc_skb_node *_qpn = bpf_obj_new(typeof(*_qpn));"
        @lines << "    if (!_qpn) {"
        @lines << "        bpf_qdisc_skb_drop(#{skb_c}, #{tf_c});"
        @lines << "        break;"
        @lines << "    }"
        @lines << "    struct sk_buff *_swap = bpf_kptr_xchg(&_qpn->skb, #{skb_c});"
        @lines << "    if (_swap) {"
        @lines << "        bpf_qdisc_skb_drop(_swap, #{tf_c});"
        @lines << "        bpf_obj_drop(_qpn);"
        @lines << "        break;"
        @lines << "    }"
        @lines << "    bpf_spin_lock(&spnl_qdisc_q_lock);"
        @lines << "    bpf_list_push_back(&spnl_qdisc_q_head, &_qpn->node);"
        @lines << "    bpf_spin_unlock(&spnl_qdisc_q_lock);"
        @lines << "    #{ret_var} = 0;  /* NET_XMIT_SUCCESS */"
        @lines << "} while (0);"
        ret_var
      end

      # queue_pop — pop one skb from the per-unit BPF list. Returns
      # the skb pointer cast to __s64 (or 0 if the queue was empty).
      def queue_pop_call(nid, node)
        expect_no_args(node, "queue_pop")
        @ctx.uses_qdisc_fifo = true
        ret_var = fresh("qpop_ret")
        @lines << "__s64 #{ret_var} = 0;"
        @lines << "do {"
        @lines << "    struct bpf_list_node *_qpn = NULL;"
        @lines << "    struct sk_buff *_qpr = NULL;"
        @lines << "    bpf_spin_lock(&spnl_qdisc_q_lock);"
        @lines << "    _qpn = bpf_list_pop_front(&spnl_qdisc_q_head);"
        @lines << "    bpf_spin_unlock(&spnl_qdisc_q_lock);"
        @lines << "    if (!_qpn) break;"
        @lines << "    struct spnl_qdisc_skb_node *_qps = container_of(_qpn, struct spnl_qdisc_skb_node, node);"
        @lines << "    _qpr = bpf_kptr_xchg(&_qps->skb, NULL);"
        @lines << "    bpf_obj_drop(_qps);"
        @lines << "    #{ret_var} = (__s64)(unsigned long)_qpr;"
        @lines << "} while (0);"
        ret_var
      end

      def off_cpu_observe_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "off_cpu_observe expects 1 arg (pid), got #{args.length}" unless args.length == 1
        @ctx.uses_off_cpu = true
        @ctx.uses_histogram = true
        @ctx.uses_histogram_keyed = true
        @ctx.uses_stack_trace = true
        pid_expr = lower_stmt(args[0])
        # Returns delta as an expression value so callers can chain
        # `hist_observe(off_cpu_observe(pid))` for a non-keyed time hist.
        "spnl_off_cpu_observe((__u32)(#{pid_expr}))"
      end

      # emit_comm() — write the current task's comm (16 bytes) to
      # the per-unit string ringbuf (the <unit>_str_events channel). Userspace
      # drains via spnl_runtime_ringbuf_drain like any other str event.
      def emit_comm_call(node)
        expect_no_args(node, "emit_comm")
        @ctx.uses_str_ringbuf = true
        evar = fresh("se")
        @lines << "{"
        @lines << "    struct #{@ctx.unit_name}_str_event *#{evar} = bpf_ringbuf_reserve(&#{@ctx.unit_name}_str_events, sizeof(*#{evar}), 0);"
        @lines << "    if (#{evar}) {"
        @lines << "        #{evar}->hdr.type = SPNL_EVT_USER_BASE;"
        @lines << "        #{evar}->hdr.version = SPNL_EVENT_HDR_VERSION;"
        @lines << "        #{evar}->hdr.reserved = 0;"
        @lines << "        #{evar}->hdr.timestamp = bpf_ktime_get_ns();"
        # bpf_get_current_comm writes TASK_COMM_LEN=16 bytes max. Our str
        # buffer is SPNL_STR_MAX=256, plenty of headroom.
        @lines << "        bpf_get_current_comm(#{evar}->str, sizeof(#{evar}->str));"
        @lines << "        bpf_ringbuf_submit(#{evar}, 0);"
        @lines << "    }"
        @lines << "}"
        no_value
      end

      # reuseport_hash returns the kernel-computed 5-tuple hash of the
      # incoming SYN (sk_reuseport_md->hash). Use it to build a consistent-
      # hash worker index. Valid only inside sk_reuseport__<name> methods.
      def reuseport_hash_call(_nid, _node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :sk_reuseport
          raise UnsupportedNode,
                "reuseport_hash is only valid inside sk_reuseport__<name> methods"
        end
        "((__s64)ctx->hash)"
      end

      # worker_select(idx) → bpf_sk_select_reuseport(ctx, &bpf_worker_socks,
      # &idx, 0). Side-effecting (pushes to @lines like spnl_emit_call) because
      # the return value is consumed via the surrounding SK_PASS path.
      def worker_select_call(nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :sk_reuseport
          raise UnsupportedNode,
                "worker_select is only valid inside sk_reuseport__<name> methods"
        end
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "worker_select expects 1 arg (idx), got #{args.length}" unless args.length == 1
        @ctx.uses_reuseport_sockarray = true
        idx_expr = lower_stmt(args[0])
        tmp = fresh("ws_idx")
        @lines << "__u32 #{tmp} = (__u32)(#{idx_expr});"
        @lines << "(void)bpf_sk_select_reuseport(ctx, &#{CodegenBpf::REUSEPORT_SOCKARRAY_NAME}, &#{tmp}, 0);"
        no_value
      end

      # xdp_match_health() and xdp_reply_health() are simple no-arg helper
      # calls that lower to spnl_xdp_match_health(ctx) / spnl_xdp_reply_health(ctx).
      # Valid only inside xdp__<name> methods.
      def xdp_match_health_call(_nid, _node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :xdp
          raise UnsupportedNode, "xdp_match_health is only valid inside xdp__<name> methods"
        end
        @ctx.uses_xdp_health_match = true
        "spnl_xdp_match_health(ctx)"
      end

      def xdp_reply_health_call(_nid, _node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :xdp
          raise UnsupportedNode, "xdp_reply_health is only valid inside xdp__<name> methods"
        end
        @ctx.uses_xdp_health_reply = true
        "spnl_xdp_reply_health(ctx)"
      end

      # tcp_sock_* field accessors. Valid inside tcp_cc__<member>
      # methods (where `sk` is the kernel-supplied `struct sock *`).
      # Read accessors return the field value as __s64; setters and adders
      # are emitted as side-effect statements with placeholder "0" expr.
      def tcp_sock_builtin_call(name, node)
        require_tcp_cc_context!(name)
        args_id = node.refs.fetch("arguments", -1)
        args = args_id >= 0 ? @ctx.ast.node(args_id).arrays.fetch("arguments", []) : []

        if (field = CodegenBpf::TCP_SOCK_READERS[name])
          raise UnsupportedNode, "#{name}(sk) expects 1 arg" unless args.length == 1
          return emit_tcp_sock_read(field, lower_stmt(args[0]))
        end
        if (field = CodegenBpf::TCP_SOCK_WRITERS[name])
          raise UnsupportedNode, "#{name}(sk, value) expects 2 args" unless args.length == 2
          return emit_tcp_sock_assign(field, lower_stmt(args[0]), lower_stmt(args[1]))
        end
        if (field = CodegenBpf::TCP_SOCK_ADDERS[name])
          raise UnsupportedNode, "#{name}(sk, delta) expects 2 args" unless args.length == 2
          return emit_tcp_sock_compound(field, "+=", lower_stmt(args[0]), lower_stmt(args[1]))
        end
        raise UnsupportedNode, "#{name}: unknown tcp_sock builtin"
      end

      # dot-form sugar. When the user writes `sk.snd_cwnd` /
      # `sk.snd_cwnd = v` / `sk.snd_cwnd += v` inside a tcp_cc__<member>
      # method, prism gives us a CallNode whose receiver expression evaluates
      # to the kernel `struct sock *` and whose method name matches a known
      # tcp_sock_* field. We desugar to the same C as the flat builtin —
      # no semantic difference, only surface syntax.
      #
      # Returns the lowered C expression on success, or nil to signal
      # "this is not a tcp_sock dot accessor, fall through to other dispatch".
      def try_tcp_sock_dot_call(name, recv_id, args)
        return nil unless recv_id >= 0
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        return nil unless attach && attach[:kind] == :tcp_cc

        # Setter: `sk.snd_cwnd = v` arrives as name="snd_cwnd=" with 1 arg.
        if name.end_with?("=")
          field = name.chomp("=")
          return nil unless CodegenBpf::TCP_SOCK_FIELDS.include?(field)
          raise UnsupportedNode, "sk.#{field}= expects 1 arg" unless args.length == 1
          return emit_tcp_sock_assign(field, lower_stmt(recv_id), lower_stmt(args[0]))
        end

        # Reader: `sk.snd_cwnd` arrives as name="snd_cwnd" with no args.
        return nil unless CodegenBpf::TCP_SOCK_FIELDS.include?(name)
        unless args.empty?
          raise UnsupportedNode, "sk.#{name} reader takes no args (got #{args.length})"
        end
        emit_tcp_sock_read(name, lower_stmt(recv_id))
      end

      # `recv.field op= value` (CallOperatorWriteNode). Currently
      # routed to tcp_sock_* when in tcp_cc context; other receivers will
      # be handled when we generalize the receiver-type registry in a
      # later.
      def call_op_write_node(_nid, node)
        recv_id = node.refs.fetch("receiver", -1)
        raise UnsupportedNode, "CallOperatorWriteNode missing receiver" if recv_id < 0
        read_name = node.attrs.fetch("read_name", nil) ||
                    node.attrs.fetch("name", nil)
        op = node.attrs.fetch("binary_operator", nil)
        val_id = node.refs.fetch("value", -1)
        raise UnsupportedNode, "CallOperatorWriteNode missing value" if val_id < 0
        raise UnsupportedNode, "CallOperatorWriteNode missing operator/name" unless read_name && op

        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :tcp_cc && CodegenBpf::TCP_SOCK_FIELDS.include?(read_name)
          raise UnsupportedNode, "#{read_name} #{op}= : op-write only supported on tcp_sock fields in tcp_cc context"
        end

        c_op = case op
               when "+" then "+="
               when "-" then "-="
               else
                 raise UnsupportedNode, "tcp_sock #{read_name} #{op}= : only += / -= supported"
               end

        emit_tcp_sock_compound(read_name, c_op, lower_stmt(recv_id), lower_stmt(val_id))
      end

      def require_tcp_cc_context!(label)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        return if attach && attach[:kind] == :tcp_cc
        raise UnsupportedNode, "#{label}: only valid inside tcp_cc__<member> methods"
      end

      def emit_tcp_sock_read(field, recv_expr)
        "((__s64)((struct tcp_sock *)(unsigned long)(#{recv_expr}))->#{field})"
      end

      def emit_tcp_sock_assign(field, recv_expr, val_expr)
        @lines << "((struct tcp_sock *)(unsigned long)(#{recv_expr}))->#{field} = (__u32)(#{val_expr});"
        no_value
      end

      def emit_tcp_sock_compound(field, c_op, recv_expr, val_expr)
        @lines << "((struct tcp_sock *)(unsigned long)(#{recv_expr}))->#{field} #{c_op} (__u32)(#{val_expr});"
        no_value
      end

      # sock_ops_op  → ctx->op (BPF_SOCK_OPS_* code)
      # sock_ops_state → ctx->args[1] (new state in STATE_CB)
      def sock_ops_field_call(name)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :sock_ops
          raise UnsupportedNode, "#{name} is only valid inside sock_ops__<name> methods"
        end
        case name
        when "sock_ops_op"    then "(__s64)ctx->op"
        when "sock_ops_state" then "(__s64)ctx->args[1]"
        end
      end

      # iter_task() -> the current task_struct* (as __s64) inside an
      # iter/task program. Combine with kfield(iter_task(), "task_struct", ...)
      # to read arbitrary fields of each iterated task.
      def iter_task_call(node)
        expect_no_args(node, "iter_task")
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :iter_task
          raise UnsupportedNode, "iter_task() is only valid inside iter__task__<name> methods"
        end
        "((__s64)(unsigned long)ctx->task)"
      end

      # sock_addr_ip4 / sock_addr_port — read the target address of a
      # cgroup/connect4 (or bind4) hook in HOST byte order. ctx is
      # `struct bpf_sock_addr *`. user_ip4 / user_port are network order, so
      # byteswap with __builtin_bswap (no bpf_endian.h needed).
      def sock_addr_field_call(name)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && (attach[:kind] == :cgroup_connect4 || attach[:kind] == :cgroup_bind4)
          raise UnsupportedNode, "#{name} is only valid inside cgroup__connect4__/cgroup__bind4__ methods"
        end
        case name
        when "sock_addr_ip4"  then "((__s64)(__u32)__builtin_bswap32(ctx->user_ip4))"
        when "sock_addr_port" then "((__s64)(__u32)__builtin_bswap16((__u16)ctx->user_port))"
        end
      end

      # cpumap_redirect(cpu) — redirect the current XDP frame to
      # `spnl_cpumap[cpu]` for processing on a different CPU. The frame
      # is enqueued on that CPU's NAPI ring; the original XDP returns
      # the value of bpf_redirect_map (XDP_REDIRECT on success, XDP_PASS
      # if the map slot is empty or invalid). Caller writes:
      #   `return cpumap_redirect(2)`  → packet handed to CPU 2
      def cpumap_redirect_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && (attach[:kind] == :xdp || attach[:kind] == :xdp_tail)
          raise UnsupportedNode, "cpumap_redirect: only valid inside xdp__/xdp_tail__ methods"
        end
        args_id = node.refs.fetch("arguments", -1)
        args = args_id >= 0 ? @ctx.ast.node(args_id).arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "cpumap_redirect(cpu) expects 1 arg" unless args.length == 1
        @ctx.uses_cpumap = true
        cpu_expr = lower_stmt(args[0])
        "(__s64)bpf_redirect_map(&#{CPUMAP_MAP_NAME}, (__u32)(#{cpu_expr}), 0)"
      end

      # xsk_redirect(qid) — redirect the XDP frame to the AF_XDP socket in
      # XSKMAP slot `qid` (XDP_PASS fallback if the slot is empty).
      def xsk_redirect_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && (attach[:kind] == :xdp || attach[:kind] == :xdp_tail)
          raise UnsupportedNode, "xsk_redirect: only valid inside xdp__/xdp_tail__ methods"
        end
        args = call_args(node)
        raise UnsupportedNode, "xsk_redirect(qid) expects 1 arg" unless args.length == 1
        @ctx.uses_xskmap = true
        "(__s64)bpf_redirect_map(&#{XSKMAP_MAP_NAME}, (__u32)(#{lower_stmt(args[0])}), XDP_PASS)"
      end

      # dev_redirect(idx) — redirect the XDP frame out the net device in
      # DEVMAP slot `idx`.
      def dev_redirect_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && (attach[:kind] == :xdp || attach[:kind] == :xdp_tail)
          raise UnsupportedNode, "dev_redirect: only valid inside xdp__/xdp_tail__ methods"
        end
        args = call_args(node)
        raise UnsupportedNode, "dev_redirect(idx) expects 1 arg" unless args.length == 1
        @ctx.uses_devmap = true
        "(__s64)bpf_redirect_map(&#{DEVMAP_MAP_NAME}, (__u32)(#{lower_stmt(args[0])}), 0)"
      end

      # tail_call_to(slot) — tail-call into the spnl_prog_array.
      # Accepts either an integer literal (compile-time slot) or any other
      # int-typed expression. If `bpf_tail_call` succeeds the current
      # program never returns (control transfers to the target); on
      # failure we fall through and the caller's body continues.
      def tail_call_to_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && (attach[:kind] == :xdp || attach[:kind] == :xdp_tail)
          raise UnsupportedNode,
                "tail_call_to: only callable from xdp__<name> or xdp_tail__<name> methods"
        end
        args_id = node.refs.fetch("arguments", -1)
        args = args_id >= 0 ? @ctx.ast.node(args_id).arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "tail_call_to(slot) expects 1 arg" unless args.length == 1
        @ctx.uses_tail_call = true
        slot_expr = lower_stmt(args[0])
        @lines << "bpf_tail_call(ctx, &#{PROG_ARRAY_MAP_NAME}, (__u32)(#{slot_expr}));"
        no_value
      end

      # user_ringbuf_drain — drain pending records from the per-unit
      # USER_RINGBUF, invoking the static callback emitted from
      # `def user_ringbuf__<name>(value)`. Must be called from inside a
      # BPF program (XDP / TC / kprobe / etc.) — it's a no-op if no
      # records are pending.
      #
      # spnl_emit-style: emit as a side-effect statement (so it survives
      # even when the call sits at non-final position in the body), and
      # return "0" as the placeholder expression value.
      def user_ringbuf_drain_call(_nid, _node)
        cb_name = @ctx.user_ringbuf_cb_name
        unless cb_name
          raise UnsupportedNode,
                "user_ringbuf_drain: declare a `def user_ringbuf__<name>(value)` callback first"
        end
        @ctx.uses_user_ringbuf = true
        @lines << "(void)bpf_user_ringbuf_drain(&#{USER_RINGBUF_MAP_NAME}, " \
                  "spnl_user_ringbuf_cb_#{cb_name}, NULL, 0);"
        no_value
      end

      # pkt_dynptr_byte_at(offset) — dynptr-backed XDP byte read.
      # Verifier-safe random access (no manual bounds-check at call site).
      # Returns the byte value (0-255) or -1 on out-of-bounds.
      def pkt_dynptr_byte_at_call(_nid, node)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        unless attach && attach[:kind] == :xdp
          raise UnsupportedNode,
                "pkt_dynptr_byte_at is only valid inside xdp__<name> methods"
        end
        args_id = node.refs.fetch("arguments", -1)
        raise UnsupportedNode, "pkt_dynptr_byte_at(offset) expects 1 arg" if args_id < 0
        args = @ctx.ast.node(args_id).arrays.fetch("arguments", [])
        raise UnsupportedNode, "pkt_dynptr_byte_at(offset) expects 1 arg" unless args.length == 1
        @ctx.uses_dynptr = true
        "spnl_pkt_dynptr_byte_at(ctx, #{lower_stmt(args[0])})"
      end

      # pkt_* builtin in expression position. Records (name, attach kind)
      # so the module-level emit pass appends a context-specific helper definition.
      # Returns either `spnl_pkt_<name>(ctx)` (XDP) or `spnl_tc_pkt_<name>(ctx)` (TC)
      # — the function bodies differ only in the ctx struct type they dereference.
      def pkt_builtin_call(name)
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        kind = attach && attach[:kind]
        unless [:xdp, :tc_ingress, :tc_egress].include?(kind)
          raise UnsupportedNode,
                "#{name}: pkt_* builtins are only available inside xdp__ or tc__* methods"
        end
        tag = kind == :xdp ? :xdp : :tc
        (@ctx.pkt_builtins_used[name] ||= Set.new) << tag
        tag == :xdp ? "spnl_#{name}(ctx)" : "spnl_tc_#{name}(ctx)"
      end

      # Roadmap #2: flow-state map ctx kind (xdp/tc); flow maps need ctx + packet.
      def flow_kind
        attach = @mi.scope == :top_level ? CodegenBpf.detect_attach(@mi.method_name) : nil
        case attach && attach[:kind]
        when :xdp then :xdp
        when :tc_ingress, :tc_egress then :tc
        else raise UnsupportedNode, "flow_get/set/del are only available inside xdp__ or tc__* methods"
        end
      end

      # Resolve + validate a flow_* call: returns [name, field]. Records the ctx
      # kind so emit_flow_maps emits the right key-extract helper.
      def flow_dispatch_common(node, need_field:)
        name, field = CodegenBpf.flow_call_name_and_field(@ctx.ast, node)
        raise UnsupportedNode, "flow_* needs a map name symbol, e.g. flow_get(:conn, :state)" unless name
        fields = @ctx.flow_maps[name]
        raise UnsupportedNode, "unknown flow map :#{name}" unless fields
        if need_field
          raise UnsupportedNode, "flow_get/flow_set need a field symbol" unless field
          raise UnsupportedNode, "flow map :#{name} has no field :#{field}" unless fields.include?(field)
        end
        (@ctx.flow_map_kinds[name] ||= Set.new) << flow_kind
        [name, field]
      end

      # flow_get(:name, :field) — read a u64 field for the current packet's flow.
      # Emits key + guarded lookup, returns the field value (0 if no entry).
      def flow_get_call(_nid, node)
        name, field = flow_dispatch_common(node, need_field: true)
        u = @ctx.unit_name
        kfn = CodegenBpf.flow_key_fn_name(u, name, flow_kind)
        map = CodegenBpf.flow_map_var_name(u, name)
        ks  = CodegenBpf.flow_key_struct_name(u, name)
        vs  = CodegenBpf.flow_val_struct_name(u, name)
        kv = fresh("fk")
        pv = fresh("fp")
        @lines << "struct #{ks} #{kv} = {};"
        @lines << "struct #{vs} *#{pv} = (#{kfn}(ctx, &#{kv}) == 0) ? bpf_map_lookup_elem(&#{map}, &#{kv}) : NULL;"
        "(#{pv} ? (__s64)#{pv}->#{field} : 0)"
      end

      # flow_set(:name, :field, value) — insert-or-update: set field for the
      # current packet's flow. Verifier-safe lookup-or-insert (no loops, guarded
      # derefs). Returns no_value (side-effecting statement).
      def flow_set_call(_nid, node)
        name, field = flow_dispatch_common(node, need_field: true)
        args = call_args(node)
        raise UnsupportedNode, "flow_set(:#{name}, :#{field}, value) expects 3 args" unless args.length == 3
        val = lower_stmt(args[2])
        u = @ctx.unit_name
        kfn = CodegenBpf.flow_key_fn_name(u, name, flow_kind)
        map = CodegenBpf.flow_map_var_name(u, name)
        ks  = CodegenBpf.flow_key_struct_name(u, name)
        vs  = CodegenBpf.flow_val_struct_name(u, name)
        kv = fresh("fk"); zv = fresh("fz"); ok = fresh("fok"); pv = fresh("fp")
        @lines << "struct #{ks} #{kv} = {};"
        @lines << "struct #{vs} #{zv} = {};"
        @lines << "int #{ok} = #{kfn}(ctx, &#{kv});"
        @lines << "struct #{vs} *#{pv} = #{ok} == 0 ? bpf_map_lookup_elem(&#{map}, &#{kv}) : NULL;"
        @lines << "if (#{ok} == 0 && !#{pv}) bpf_map_update_elem(&#{map}, &#{kv}, &#{zv}, BPF_ANY);"
        @lines << "if (#{ok} == 0 && !#{pv}) #{pv} = bpf_map_lookup_elem(&#{map}, &#{kv});"
        @lines << "if (#{pv}) #{pv}->#{field} = (__u64)(#{val});"
        no_value
      end

      # Roadmap #3: tcp_syncookie_gen / tcp_syncookie_check — parse the current
      # packet and call the raw SYN-cookie kfunc. xdp-only (the kfuncs operate on
      # XDP packet pointers). Returns the cookie / validity (negative on error).
      def syncookie_call(name)
        unless flow_kind == :xdp
          raise UnsupportedNode, "#{name} is only available inside xdp__ methods"
        end
        which = name == "tcp_syncookie_gen" ? :gen : :check
        @ctx.syncookie_used << which
        which == :gen ? "spnl_tcp_syncookie_gen(ctx)" : "spnl_tcp_syncookie_check(ctx)"
      end

      # Roadmap #4: tcp_reply_header(seq, ack, flags) — turn the current packet
      # into a header-only TCP reply (swap endpoints, set seq/ack/flags, recompute
      # checksums). Returns 0 on success / -1 on error; caller returns XDP_TX.
      def tcp_reply_header_call(node)
        raise UnsupportedNode, "tcp_reply_header is only available inside xdp__ methods" unless flow_kind == :xdp
        args = call_args(node)
        raise UnsupportedNode, "tcp_reply_header(seq, ack, flags) expects 3 args, got #{args.length}" unless args.length == 3
        @ctx.uses_tcp_reply = true
        seq = lower_stmt(args[0])
        ack = lower_stmt(args[1])
        flags = lower_stmt(args[2])
        "((__s64)spnl_tcp_reply_header(ctx, (__u32)(#{seq}), (__u32)(#{ack}), (__u8)(#{flags})))"
      end

      # Roadmap #4b: tcp_reply_synack(cookie) — SYN-ACK with the MSS option.
      # cookie comes from tcp_syncookie_gen; the helper extracts the MSS, computes
      # ack = client_seq + 1, and builds a doff=6 SYN-ACK. Returns 0/-1.
      def tcp_reply_synack_call(node)
        raise UnsupportedNode, "tcp_reply_synack is only available inside xdp__ methods" unless flow_kind == :xdp
        args = call_args(node)
        raise UnsupportedNode, "tcp_reply_synack(cookie) expects 1 arg, got #{args.length}" unless args.length == 1
        @ctx.uses_tcp_synack = true
        cookie = lower_stmt(args[0])
        "((__s64)spnl_tcp_reply_synack(ctx, (__s64)(#{cookie})))"
      end

      # Roadmap #4b': tcp_synack_cookie() — integrated SYN -> SYN-ACK+cookie (the
      # bundle sequence: grow-to-60, gen_syncookie, build SYN-ACK with MSS,
      # shrink). No args (reads the SYN from ctx). Returns 0/-1; caller XDP_TX.
      def tcp_synack_cookie_call(node)
        raise UnsupportedNode, "tcp_synack_cookie is only available inside xdp__ methods" unless flow_kind == :xdp
        expect_no_args(node, "tcp_synack_cookie")
        @ctx.uses_synack_cookie = true
        "((__s64)spnl_tcp_synack_cookie(ctx))"
      end

      # Roadmap #5b: tcp_reply_data(seq, ack, "<payload>") — turn the packet into a
      # data response: resize, swap, set seq/ack + FIN|PSH|ACK, write the payload,
      # recompute checksums. Returns 0/-1; caller returns XDP_TX. xdp-only.
      def tcp_reply_data_call(node)
        raise UnsupportedNode, "tcp_reply_data is only available inside xdp__ methods" unless flow_kind == :xdp
        args = call_args(node)
        raise UnsupportedNode, "tcp_reply_data(seq, ack, payload) expects 3 args, got #{args.length}" unless args.length == 3
        body = string_literal_bytes(args[2], "tcp_reply_data payload")
        raise UnsupportedNode, "tcp_reply_data payload must be non-empty" if body.empty?
        raise UnsupportedNode, "tcp_reply_data payload too long (max 1024 bytes)" if body.bytesize > 1024
        id = @ctx.reply_bodies.index(body)
        unless id
          @ctx.reply_bodies << body
          id = @ctx.reply_bodies.length - 1
        end
        seq = lower_stmt(args[0])
        ack = lower_stmt(args[1])
        "((__s64)spnl_tcp_reply_data#{id}(ctx, (__u32)(#{seq}), (__u32)(#{ack})))"
      end

      # Extract a string-literal arg as raw bytes (URL-decoded .ast content).
      def string_literal_bytes(arg_id, label)
        n = @ctx.ast.node(arg_id)
        raise UnsupportedNode, "#{label} must be a string literal" unless n && n.type == "StringNode"
        CodegenBpf.url_decode(n.attrs.fetch("content", ""))
      end

      # Roadmap #5a: payload_starts("GET /hello ") — does the current packet's TCP
      # payload start with the (compile-time) prefix? Returns 1 / 0. xdp-only.
      def payload_starts_call(node)
        raise UnsupportedNode, "payload_starts is only available inside xdp__ methods" unless flow_kind == :xdp
        args = call_args(node)
        raise UnsupportedNode, "payload_starts(prefix) expects 1 string arg, got #{args.length}" unless args.length == 1
        prefix = string_literal_bytes(args[0], "payload_starts prefix")
        raise UnsupportedNode, "payload_starts prefix must be non-empty" if prefix.empty?
        if prefix.bytesize > CodegenBpf::PAYLOAD_PREFIX_MAX
          raise UnsupportedNode, "payload_starts prefix too long (max #{CodegenBpf::PAYLOAD_PREFIX_MAX} bytes)"
        end
        id = @ctx.payload_matchers.index(prefix)
        unless id
          @ctx.payload_matchers << prefix
          id = @ctx.payload_matchers.length - 1
        end
        "spnl_payload_match#{id}(ctx)"
      end

      # flow_del(:name) — delete the current packet's flow entry.
      def flow_del_call(_nid, node)
        name, = flow_dispatch_common(node, need_field: false)
        u = @ctx.unit_name
        kfn = CodegenBpf.flow_key_fn_name(u, name, flow_kind)
        map = CodegenBpf.flow_map_var_name(u, name)
        ks  = CodegenBpf.flow_key_struct_name(u, name)
        kv = fresh("fk")
        @lines << "struct #{ks} #{kv} = {};"
        @lines << "if (#{kfn}(ctx, &#{kv}) == 0) bpf_map_delete_elem(&#{map}, &#{kv});"
        no_value
      end

      # receiver-chain dispatch. Walks a CallNode receiver chain
      # bottoming out at `pkt` (a CallNode with no receiver / args) and
      # matches the resulting path against PKT_CHAIN_MAP. Returns the
      # lowered C expression on success, or nil so call_node can fall
      # through to other dispatch.
      #
      # Special case: `pkt.byte_at(off)` matches the chain ["pkt", "byte_at"]
      # but takes 1 argument, so we route it to the existing
      # pkt_dynptr_byte_at_call which already handles the arg lowering.
      def try_pkt_chain_dispatch(name, recv_id, args, node_for_call)
        return nil if recv_id < 0
        chain = collect_pkt_chain(name, recv_id)
        return nil unless chain

        # 1-arg form: pkt.byte_at(off)
        if chain == %w[pkt byte_at]
          raise UnsupportedNode, "pkt.byte_at(off) expects 1 arg" unless args.length == 1
          synth = Struct.new(:refs).new(node_for_call.refs)
          return pkt_dynptr_byte_at_call(nil, synth)
        end

        # No-arg readers
        if (builtin = CodegenBpf::PKT_CHAIN_MAP[chain])
          unless args.empty?
            raise UnsupportedNode, "#{chain.join('.')} reader takes no args (got #{args.length})"
          end
          return pkt_builtin_call(builtin)
        end

        nil
      end

      # walk a ConstantPathNode chain bottom-up. Each ConstantPathNode
      # has `name` (its own segment) and `parent` (either another
      # ConstantPathNode or a ConstantReadNode root). Returns the full
      # path as a string array (root first), or nil if the chain ends in
      # something other than ConstantReadNode (e.g. `::Foo` absolute paths
      # which spinel doesn't currently parse this way).
      def collect_constant_path(nid)
        path = []
        cur_id = nid
        8.times do
          return nil if cur_id < 0
          cur = @ctx.ast.node(cur_id)
          return nil unless cur
          case cur.type
          when "ConstantPathNode"
            path.unshift(cur.attrs.fetch("name", ""))
            cur_id = cur.refs.fetch("parent", -1)
          when "ConstantReadNode"
            path.unshift(cur.attrs.fetch("name", ""))
            return path
          else
            return nil
          end
        end
        nil
      end

      # Recursively walk a CallNode receiver chain. Returns a string array
      # of method names (e.g. ["pkt", "l4", "proto"]) when the chain
      # bottoms out at a `pkt` CallNode with no receiver/args, otherwise nil.
      # Bails out fast for chains that obviously aren't pkt-rooted.
      def collect_pkt_chain(leaf_name, leaf_recv_id)
        chain = [leaf_name.to_s]
        cur_id = leaf_recv_id
        # Cap chain length so a deep / cyclic receiver tree can't loop.
        8.times do
          return nil if cur_id < 0
          cur = @ctx.ast.node(cur_id)
          return nil unless cur && cur.type == "CallNode"
          # Intermediate / root must take no arguments and no block — chain
          # accessors are pure field reads.
          return nil if cur.refs.fetch("arguments", -1) >= 0
          return nil if cur.refs.fetch("block",    -1) >= 0
          link_name = cur.attrs.fetch("name", "")
          chain.unshift(link_name)
          next_recv = cur.refs.fetch("receiver", -1)
          if next_recv < 0
            return chain.first == "pkt" ? chain : nil
          end
          cur_id = next_recv
        end
        nil
      end

      def spnl_emit_str_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "spnl_emit_str expects 1 arg, got #{args.length}" unless args.length == 1
        ptr_expr = lower_stmt(args[0])

        @ctx.uses_str_ringbuf = true
        evar = fresh("se")
        @lines << "{"
        @lines << "    struct #{@ctx.unit_name}_str_event *#{evar} = bpf_ringbuf_reserve(&#{@ctx.unit_name}_str_events, sizeof(*#{evar}), 0);"
        @lines << "    if (#{evar}) {"
        @lines << "        #{evar}->hdr.type = SPNL_EVT_USER_BASE;"
        @lines << "        #{evar}->hdr.version = SPNL_EVENT_HDR_VERSION;"
        @lines << "        #{evar}->hdr.reserved = 0;"
        @lines << "        #{evar}->hdr.timestamp = bpf_ktime_get_ns();"
        @lines << "        bpf_probe_read_user_str(#{evar}->str, sizeof(#{evar}->str), (const void *)(#{ptr_expr}));"
        @lines << "        bpf_ringbuf_submit(#{evar}, 0);"
        @lines << "    }"
        @lines << "}"
        no_value
      end

      # emit_argv(argv) — read a NUL-terminated array of user string
      # pointers (e.g. execve's argv) and emit each element as a str event.
      # Reuses the str ringbuf. The trip count is a compile-time bound so the
      # verifier can fully unroll; the early `break` on a NULL pointer stops at
      # the real arg count. bcc execsnoop reads argv the same way.
      EMIT_ARGV_MAX = 20

      def spnl_emit_argv_call(_nid, node)
        args = call_args(node)
        raise UnsupportedNode, "emit_argv expects 1 arg (argv pointer), got #{args.length}" unless args.length == 1
        argv_expr = lower_stmt(args[0])
        @ctx.uses_str_ringbuf = true
        iv = fresh("ai"); pv = fresh("ap"); ev = fresh("ae")
        @lines << "{"
        @lines << "    #pragma unroll"
        @lines << "    for (int #{iv} = 0; #{iv} < #{EMIT_ARGV_MAX}; #{iv}++) {"
        @lines << "        const char *#{pv} = 0;"
        @lines << "        bpf_probe_read_user(&#{pv}, sizeof(#{pv}), &((const char *const *)(unsigned long)(#{argv_expr}))[#{iv}]);"
        @lines << "        if (!#{pv}) break;"
        @lines << "        struct #{@ctx.unit_name}_str_event *#{ev} = bpf_ringbuf_reserve(&#{@ctx.unit_name}_str_events, sizeof(*#{ev}), 0);"
        @lines << "        if (#{ev}) {"
        @lines << "            #{ev}->hdr.type = SPNL_EVT_USER_BASE;"
        @lines << "            #{ev}->hdr.version = SPNL_EVENT_HDR_VERSION;"
        @lines << "            #{ev}->hdr.reserved = 0;"
        @lines << "            #{ev}->hdr.timestamp = bpf_ktime_get_ns();"
        @lines << "            bpf_probe_read_user_str(#{ev}->str, sizeof(#{ev}->str), #{pv});"
        @lines << "            bpf_ringbuf_submit(#{ev}, 0);"
        @lines << "        }"
        @lines << "    }"
        @lines << "}"
        no_value
      end

      # spnl_emit(value) lowering.
      def spnl_emit_call(nid, node)
        args_id = node.refs.fetch("arguments", -1)
        args_node = args_id >= 0 ? @ctx.ast.node(args_id) : nil
        args = args_node && args_node.type == "ArgumentsNode" ? args_node.arrays.fetch("arguments", []) : []
        raise UnsupportedNode, "spnl_emit expects 1 arg, got #{args.length}" unless args.length == 1
        value_expr = lower_stmt(args[0])

        @ctx.uses_ringbuf = true
        evar = fresh("e")
        unit = @ctx.unit_name
        # Build the ringbuf scope as structured CStmt (CBraceBlock + CDecl + CIf).
        # Drop the baked indentation and put the reserve->submit discipline **into the structure**.
        block = CAst.brace_block(CAst.block([
          CAst.decl("struct #{unit}_event", "*#{evar}",
                    CAst.call("bpf_ringbuf_reserve",
                              CAst.raw("&#{unit}_events"), CAst.raw("sizeof(*#{evar})"), CAst.raw("0"))),
          CAst.cif(CAst.raw(evar), CAst.block([
            CAst.expr_stmt(CAst.raw("#{evar}->hdr.type = SPNL_EVT_USER_BASE")),
            CAst.expr_stmt(CAst.raw("#{evar}->hdr.version = SPNL_EVENT_HDR_VERSION")),
            CAst.expr_stmt(CAst.raw("#{evar}->hdr.reserved = 0")),
            CAst.expr_stmt(CAst.raw("#{evar}->hdr.timestamp = bpf_ktime_get_ns()")),
            CAst.expr_stmt(CAst.raw("#{evar}->value = #{value_expr}")),
            CAst.expr_stmt(CAst.call("bpf_ringbuf_submit", CAst.raw(evar), CAst.raw("0"))),
          ]), nil, nid: nid),
        ]), nid: nid)
        # A structure-consuming linear-use check. Verifies from the structure that a reserved entry is
        # submitted/discarded (cf. aya #[must_use] / the BPF-list leak class).
        check_ringbuf_linear_use!(block, nid)
        @lines.concat(CAst.render_stmt(block, 0))
        no_value  # spnl_emit: side-effecting (ringbuf), no expression value
      end

      # (foundation for the boundary ABI): consume the C-AST structure to verify bpf_ringbuf's
      # reserve->submit linear-use discipline. If there is a leak, error out at codegen time
      # (no silent fallback).
      def check_ringbuf_linear_use!(stmt, nid)
        leaks = CAst.ringbuf_leaks(stmt)
        return if leaks.empty?

        raise UnsupportedNode,
              "ringbuf entry #{leaks.join(', ')} reserved but never submitted/discarded " \
              "(linear-use violation, nid=#{nid})"
      end

      def local_read(node)
        # sanitize once at AST extraction so all sets (@captured_locals,
        # @param_names, @declared_locals) stay aligned with what local_write
        # / collect_locals / method_params recorded.
        name = SpinelEbpf::CodegenBpf.c_safe(node.attrs.fetch("name"))
        # outer-scope local captured in a loop callback.
        return "(*_lc->#{name})" if @captured_locals.key?(name)
        # inside the _inner function, params are bare C args, not ctx->name.
        return name if @param_names.include?(name)
        return name if @declared_locals.include?(name)
        raise UnsupportedNode, "read of undeclared local #{name.inspect}"
      end

      # collect local-variable names written anywhere in the body
      # subtree. Skip nested DefNode (their bodies are separate methods)
      # to mirror partition.walk.
      # sanitize so `def foo; double = 1; double; end` lowers to
      # `__s64 double_ = 0; ...; return double_;`.
      def collect_locals(bid)
        names = Set.new
        visit = ->(nid) {
          return if nid < 0
          node = @ctx.ast.node(nid)
          return unless node
          return if %w[DefNode ClassNode ModuleNode].include?(node.type)
          if node.type == "LocalVariableWriteNode"
            names << SpinelEbpf::CodegenBpf.c_safe(node.attrs.fetch("name"))
          end
          node.refs.each_value { |c| visit.call(c) if c.is_a?(Integer) }
          node.arrays.each_value { |arr| arr.each { |c| visit.call(c) if c.is_a?(Integer) } }
        }
        visit.call(bid)
        names
      end

      # LocalVariableWriteNode lowering. The local was already declared
      # at function top by `emit`, so this is just an assignment.
      # captured locals are written through the *_lc->name pointer.
      def local_write(node)
        name = SpinelEbpf::CodegenBpf.c_safe(node.attrs.fetch("name"))
        # `t = kptr(ptr, "struct")` records the local's kernel type so a
        # later `t.field` read dispatches to BPF_CORE_READ (see try_kptr_dot_call).
        vnode = @ctx.ast.node(node.refs.fetch("value"))
        if vnode && vnode.type == "CallNode" && vnode.attrs.fetch("name", "") == "kptr"
          sn = kptr_struct_name(vnode)
          @kptr_locals[name] = sn if sn
        end
        value_expr = lower_stmt(node.refs.fetch("value"))
        if @captured_locals.key?(name)
          @lines << "*_lc->#{name} = #{value_expr};"
          return "(*_lc->#{name})"
        end
        raise UnsupportedNode, "local #{name.inspect} not pre-declared" unless @declared_locals.include?(name)
        @lines << "#{name} = #{value_expr};"
        name
      end

      def int_lit(node)
        v = node.attrs.fetch("value", 0)
        v.to_s
      end

      # Pick the right HASH-map name for an ivar depending on scope:
      # class method → ivar_map_name(class), top-level method → top_ivar_map_name(unit).
      def ivar_map_for(ivar)
        case @mi.scope
        when :class
          SpinelEbpf::CodegenBpf.ivar_map_name(@mi.class_name, ivar)
        when :top_level
          SpinelEbpf::CodegenBpf.top_ivar_map_name(@ctx.unit_name, ivar)
        else
          raise UnsupportedNode, "ivar access in #{@mi.scope} scope not supported"
        end
      end

      # (leaf-emitter optimization): collect the boilerplate of ivar map-access into CStmt-
      # based helpers (the `__u32 k=0;` + lookup/update duplicated across
      # ivar_read/write/opwrite is now DRY). Output is byte-identical.

      # Emit `__u32 <kv> = 0;` (singleton key).
      def emit_map_key_zero(kv)
        @lines << CAst.decl("__u32", kv, CAst.lit("0")).to_c
      end

      # Emit `__s64 *<pv> = bpf_map_lookup_elem(&<map>, &<kv>);`.
      def emit_map_lookup(pv, map, kv)
        @lines << CAst.decl("__s64", "*#{pv}",
                            CAst.call("bpf_map_lookup_elem", CAst.raw("&#{map}"), CAst.raw("&#{kv}"))).to_c
      end

      # Emit `bpf_map_update_elem(&<map>, &<kv>, &<vv>, BPF_ANY);`.
      def emit_map_update(map, kv, vv)
        @lines << CAst.expr_stmt(CAst.call("bpf_map_update_elem",
                                           CAst.raw("&#{map}"), CAst.raw("&#{kv}"),
                                           CAst.raw("&#{vv}"), CAst.raw("BPF_ANY"))).to_c
      end

      def ivar_read(node)
        ivar = node.attrs.fetch("name")
        map = ivar_map_for(ivar)
        kv = fresh("k")
        pv = fresh("p")
        emit_map_key_zero(kv)
        emit_map_lookup(pv, map, kv)
        "(#{pv} ? *#{pv} : 0)"
      end

      def ivar_write(node)
        ivar = node.attrs.fetch("name")
        map = ivar_map_for(ivar)
        rhs = lower_stmt(node.refs.fetch("value"))
        kv = fresh("k")
        vv = fresh("v")
        emit_map_key_zero(kv)
        @lines << CAst.decl("__s64", vv, CAst.raw(rhs)).to_c
        emit_map_update(map, kv, vv)
        vv
      end

      def ivar_opwrite(node)
        ivar = node.attrs.fetch("name")
        op   = node.attrs.fetch("binary_operator") # "+", "-", "*", etc.
        raise UnsupportedNode, "operator #{op.inspect} not supported in MVP" unless %w[+ - *].include?(op)
        map = ivar_map_for(ivar)
        rhs = lower_stmt(node.refs.fetch("value"))
        kv = fresh("k")
        pv = fresh("p")
        vv = fresh("v")
        emit_map_key_zero(kv)
        emit_map_lookup(pv, map, kv)
        @lines << CAst.decl("__s64", vv, CAst.raw("(#{pv} ? *#{pv} : 0) #{op} (#{rhs})")).to_c
        emit_map_update(map, kv, vv)
        vv
      end

      def fresh(prefix)
        @tmp_n += 1
        "_#{prefix}#{@tmp_n}"
      end
    end
  end
end
