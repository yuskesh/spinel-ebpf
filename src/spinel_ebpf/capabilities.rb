# frozen_string_literal: true
#
# The capability registry: what a probe can do, grouped by domain.
#
# The probe DSL's builtins -- the ones that run in the kernel -- are classified
# here into domains: observability, enforcement, networking and L7. This is
# metadata about the language, not part of it.
#
# What it is for:
#   * Builtins stay flat. They are deliberately not renamed into dotted
#     namespaces, because that would cost the ergonomics of writing a probe in one
#     sitting. This module adds no language mechanism; it is data that classifies
#     what already exists, plus the introspection wired on top of it.
#   * Discoverability: which builtins and which attach kinds go together.
#   * One authority for the context contracts. Some builtins are only valid under
#     certain hooks and the compiler refuses them elsewhere; that allowlist lives
#     here once, so the generator, the catalogue and the introspection all read the
#     same truth.
#
# What it is not: it changes nothing about how an existing probe behaves or what
# code is generated for it. The rejection logic itself lives in the generators;
# this module owns only the values they consult.
#
# It has no dependencies -- it does not require the generator -- so the builtin
# names appear here as literals. That the two lists agree is enforced by the unit
# tests: a new builtin that nobody classified makes them fail, which is the point.

module SpinelEbpf
  module Capabilities
    module_function

    # The measured allowlist for the d_path gate, and the single authority for it.
    # bpf_d_path is gated by the kernel, and the gate is not a simple name list: only
    # the hooks below were observed to load. The Ruby generator reads this constant;
    # the production C generator carries its own copy, and the golden tests keep the
    # two in agreement.
    DPATH_OK_SECS = %w[
      lsm/file_open
      fmod_ret/security_file_open
      fmod_ret/security_file_permission
    ].freeze

    # The domain registry. Each domain is {summary, builtins, attach_kinds}, with
    # builtin names left flat. attach_kinds records which attach kinds a domain's
    # builtins typically ride on; it is loose metadata, not a constraint.
    DOMAINS = {
      observability: {
        summary: "General observation: histograms, latency, stacks, profiles, emit and task storage -- the ground bcc's tools cover",
        builtins: %w[
          spnl_emit spnl_emit_str spnl_emit_pair spnl_emit3 spnl_emit4
          emit_argv emit_comm comm_hash
          hist_observe hist_observe_by hist_observe_linear
          ktime_ns latency_start latency_end lat_start lat_end
          stack_id user_stack_id off_cpu_start off_cpu_observe
          task_load task_store task_incr task_swap
          leak_record leak_forget lock_edge
          mim_inc mim_get fifo_push fifo_pop lifo_push lifo_pop
          iter_task depth_inc depth_dec path_counter_inc
          kfield kptr
        ].freeze,
        attach_kinds: %i[
          kprobe kretprobe tracepoint raw_tp fentry fexit
          uprobe uretprobe usdt perf_event timer user_ringbuf iter_task
        ].freeze,
      }.freeze,
      enforcement: {
        summary: "Blocking, auditing and lineage: deny by return value from an LSM or fmod_ret hook, with path and parent-path selectors",
        builtins: %w[
          emit_path emit_parent_path path_eq path_starts_with path_contains parent_path_eq ppid
        ].freeze,
        attach_kinds: %i[lsm fmod_ret kprobe tracepoint].freeze,
      }.freeze,
      net: {
        summary: "The packet and socket datapath: packet access, XDP, TC, load balancing, NAT, connection tracking, qdiscs, congestion control and network spans",
        builtins: %w[
          pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst
          pkt_l4_sport pkt_l4_dport pkt_tcp_flags pkt_l4_payload_len
          pkt_ip6_src_hi pkt_ip6_src_lo pkt_ip6_dst_hi pkt_ip6_dst_lo
          pkt_tcp_seq pkt_tcp_ack pkt_dynptr_byte_at
          emit_connect sock_owner_set
          blocklist_match cidr_blocklist_match
          reuseport_hash worker_select
          xdp_match_health xdp_reply_health
          tail_call_to sock_ops_op sock_ops_state sock_addr_ip4 sock_addr_port
          cpumap_redirect xsk_redirect dev_redirect
          fib_lookup fib_lookup6 sk_lookup_tcp sk_assign_tcp redirect
          skb_load_byte skb_load_u16 skb_load_u32
          skb_store_byte skb_store_u16 skb_store_u32
          l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip l4_offset
          flow_get flow_set flow_del
          tcp_syncookie_gen tcp_syncookie_check tcp_reply_header tcp_reply_synack
          tcp_synack_cookie tcp_reply_data payload_starts
          arena_set arena_get arena_hash_set arena_hash_get arena_hash_del
          arena_list_push arena_list_sum
          tcp_sock_snd_cwnd tcp_sock_snd_ssthresh tcp_sock_snd_nxt tcp_sock_snd_una
          tcp_sock_packets_out tcp_sock_delivered tcp_sock_snd_cwnd_cnt
          tcp_sock_snd_cwnd_clamp tcp_sock_prior_cwnd
          tcp_sock_snd_cwnd_set tcp_sock_snd_ssthresh_set tcp_sock_snd_cwnd_cnt_set
          tcp_sock_snd_cwnd_add tcp_sock_snd_cwnd_cnt_add
          qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
          qdisc_watchdog_schedule qdisc_bstats_update
          queue_push queue_pop
        ].freeze,
        attach_kinds: %i[
          xdp xdp_tail xdp_tcp_slice tc_ingress tc_egress
          sk_reuseport sk_msg sk_skb_verdict sk_skb_parser sock_ops
          cgroup_connect4 cgroup_bind4 sk_lookup socket_filter flow_dissector
          tcp_cc qdisc
        ].freeze,
      }.freeze,
      l7: {
        summary: "Application-protocol observation: HTTP, Redis, TLS plaintext and DNS spans, L7 latency, and correlation with off-CPU time",
        builtins: %w[
          http_req_start http_resp_stash http_emit
          redis_req_start redis_resp_stash redis_emit
          ssl_req_start ssl_resp_stash ssl_emit
          go_tls_write go_tls_req go_tls_resp_stash go_tls_emit
          dns_req_start dns_resp_stash dns_emit emit_dns emit_tcp_payload emit_tcp_stream
          req_start emit_l7
          offcpu_recv_stash offcpu_begin offcpu_account offcpu_emit
        ].freeze,
        attach_kinds: %i[kprobe kretprobe uprobe uretprobe tracepoint].freeze,
      }.freeze,
      core: {
        summary: "Domain-independent primitives: arithmetic, process identity, cgroup ids, the control channel, and the scheduler",
        builtins: %w[
          divu i32 pid tgid tid cpu_id cgroup_id field_exists user_ringbuf_drain
          scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq
        ].freeze,
        attach_kinds: %i[sched_ext].freeze,
      }.freeze,
    }.freeze

    # Context gates: these builtins are refused at compile time unless the attach
    # section is one of their valid ones. The refusal itself lives in the generator;
    # what lives here is the authority on which builtin requires which context.
    CONTEXT_GATES = {
      "emit_path"        => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "emit_parent_path" => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_eq"          => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_starts_with" => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "path_contains"    => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
      "parent_path_eq"   => { domain: :enforcement, valid_secs: DPATH_OK_SECS }.freeze,
    }.freeze

    # How the ready-made probes (--probe dns|file|l7|net) map onto these domains:
    # file auditing is enforcement, dns and l7 are both L7 (DNS being an L7
    # protocol), and net is networking.
    KREW_PROBE_DOMAINS = {
      "dns"  => :l7,
      "file" => :enforcement,
      "l7"   => :l7,
      "net"  => :net,
    }.freeze

    # ===================================================================
    # Publish the record contracts as part of the affordances.
    #
    # A packed-record emit builtin such as emit_dns is only one end of a contract:
    # how many bytes it writes into a ringbuf, and which OTLP attributes those bytes
    # eventually become. Both the physical layout and that meaning are data, and this
    # is where the meaning is read. The chain is:
    #
    #   src/codegen_c/record_schema.h   -- the one declaration: fields and egress
    #     -> the kernel's record struct   (read directly by the C generator)
    #     -> the userspace mirror and the SPNL_EGRESS_* macros (used by the runtime)
    #     -> record_schema_gen.json       (read by this Ruby)
    #
    # Offsets are *read* here, never computed. The alignment rules are implemented in
    # exactly one place, the layout function of the mirror generator; reimplementing
    # them in Ruby would be the third hand-written copy of the same rule, which is
    # how the offsets drifted in the first place. Regenerate with
    # `make -C src/codegen_c mirror`, which produces the header and the JSON
    # together.
    # ===================================================================

    RECORD_SCHEMA_JSON = File.expand_path("record_schema_gen.json", __dir__).freeze

    # ===================================================================
    # The vocabulary of the userspace consumer DSL, in machine-readable form.
    #
    # Where the record contracts above say what can be read, this says how to write
    # it: `on_emit :<ch>`, `to_span`, `send_otlp`, `consume_records` -- and the rule
    # by which `to_span` resolves. That rule ("`to_span` resolves inside an
    # `on_emit :<ch>` block; where the handle crosses out of that scope, write
    # `<ch>_span(ev)`") is published as a context note rather than left in prose,
    # exactly as the context gates on other builtins are.
    #
    # These verbs are deliberately generic. What a span contains is owned by its
    # egress declaration, not by the probe, which is why `to_span` has no argument
    # for adding attributes. The freedom a probe has is whether to send, when, and
    # how often -- not what the span says.
    # ===================================================================
    CONSUMER_DSL = [
      { name: "on_emit :<channel>",
        form: "on_emit :<channel> do |ev| ... end",
        layer: 1,
        summary: "A typed record consumer. The block runs once per record, and `ev` is an " \
                 "opaque handle into that drain. Which `ev.<prop>` names exist comes from the " \
                 "channel's own declaration (channels[<id>].consumer.properties).",
        context_note: "<channel> must be the id of a channel that publishes a typed consumer. " \
                      "An id that does not is treated as a named event instead, which is what " \
                      "existing programs expect. A same-named `emit :<channel>, v` in the same " \
                      "program is a compile error.",
        gotcha: "`ev` is valid only within the current drain cycle. To keep a value beyond it, " \
                "copy the property into a Ruby variable." }.freeze,
      { name: "to_span",
        form: "to_span(ev)",
        layer: 1,
        summary: "Build one record into the span its egress declaration describes " \
                 "(channels[<id>].egress is the authority). Returns a span handle; 0 means this " \
                 "record does not become a span.",
        context_note: "It resolves when written inside an `on_emit :<channel>` block and applied " \
                      "to that block's own parameter. In a program consuming several channels, " \
                      "applying it outside the block, or to a handle copied into another " \
                      "variable, is a compile error -- use the explicit `<channel>_span(ev)` " \
                      "there. A program with a single typed channel resolves it anywhere.",
        gotcha: "There is no way to add to a span from Ruby: the egress declaration decides what " \
                "it contains. What a probe controls is whether to send, when, and how often." }.freeze,
      { name: "<channel>_span",
        form: "dns_span(ev)",
        layer: 1,
        summary: "The explicit form of `to_span`, naming its channel. For the cases the scope " \
                 "rule cannot reach.",
        context_note: "An escape hatch, not the usual way: normally write `to_span(ev)` inside an " \
                      "`on_emit :<channel>` block. Naming a channel the program does not consume " \
                      "is a compile error." }.freeze,
      { name: "send_otlp",
        form: "send_otlp(to_span(ev), endpoint)",
        layer: 1,
        summary: "Add a span to the send batch. Handle 0 is a no-op, so a probe need not branch " \
                 "on it.",
        context_note: "The endpoint is taken from the first call of the cycle. The generated " \
                      "driver flushes once at the end of it, so consuming several channels still " \
                      "produces a single batched POST." }.freeze,
      { name: "consume_records",
        form: "st = consume_records(timeout_ms)",
        layer: 1,
        summary: "Drain, dispatch each record to its on_emit block, then flush the send batch. " \
                 "Returns the HTTP status of the last POST.",
        context_note: "Without it the handler never runs at all -- the program compiles, the " \
                      "verifier is happy, and no span comes out. Call it periodically from a " \
                      "loop. One call drains every channel the program consumes." }.freeze,
    ].freeze

    def self.deep_freeze(o)
      case o
      when Hash  then o.each_value { |v| deep_freeze(v) }; o.freeze
      when Array then o.each { |v| deep_freeze(v) }; o.freeze
      else o.freeze
      end
    end
    private_class_method :deep_freeze

    # The channels from the generated JSON, read lazily and memoised. A missing file
    # is a loud failure: returning an empty set silently would make "this probe has
    # no contract" indistinguishable from "somebody forgot to regenerate".
    def record_channels
      @record_channels ||= begin
        require "json"
        unless File.exist?(RECORD_SCHEMA_JSON)
          raise "record schema artifact missing: #{RECORD_SCHEMA_JSON} " \
                "(regenerate with `make -C src/codegen_c mirror`)"
        end
        doc = JSON.parse(File.read(RECORD_SCHEMA_JSON), symbolize_names: true)
        deep_freeze(doc[:channels] || [])
      end
    end

    # A channel id such as "dns" to its hash, or nil.
    def record_channel(id)
      record_channels.find { |c| c[:id] == id.to_s }
    end

    # Only the channels that publish a typed consumer -- the ones carrying a
    # `consumer` block. A channel can be fully declarative without changing what
    # `on_emit :<id>` means; for those it must keep meaning a named event, or an
    # existing program would quietly become a different program. "Has a declaration"
    # and "has a Ruby-side receiver" are separate facts, so they get separate sets.
    def typed_record_channels
      record_channels.select { |c| c[:consumer] }
    end

    # The channel ids with a typed consumer: the set for which `on_emit :<id>` means
    # a typed record.
    def typed_record_channel_ids
      typed_record_channels.map { |c| c[:id] }
    end

    # An emit builtin to the channel it writes, or nil when it is not a producer.
    def record_channel_for(builtin)
      record_channels.find { |c| Array(c[:producers]).include?(builtin) }
    end

    # Every builtin that writes a packed record, sorted.
    def record_producers
      record_channels.flat_map { |c| Array(c[:producers]) }.sort.freeze
    end

    # A channel id to the properties its typed consumer can read.
    # ([{name:, kind:, expose:, ffi:, ffi_ret:, source:, note:}])。
    # This is the authority on which `ev.<name>` exist, and the consumer transform
    # rejects any name absent from it at compile time.
    def record_properties(id)
      c = record_channel(id)
      Array(c && c.dig(:consumer, :properties))
    end

    # --- the query API used by introspection ---

    # Every classified builtin, sorted.
    def all_builtins
      DOMAINS.values.flat_map { |d| d[:builtins] }.sort.freeze
    end

    # A builtin name to its domain symbol, or nil when it is unclassified.
    def domain_of(name)
      DOMAINS.each { |dom, spec| return dom if spec[:builtins].include?(name) }
      nil
    end

    def builtins_for(domain)
      DOMAINS.dig(domain, :builtins) || []
    end

    # A gated builtin to {domain:, valid_secs:}, or nil when it is not gated.
    def gate_for(name)
      CONTEXT_GATES[name]
    end

    # Given a set of builtin names, return {domain => [names]} for the domains they
    # touch, with the names sorted.
    def domains_used(names)
      seen = names.to_a.uniq
      DOMAINS.each_key.filter_map do |dom|
        hit = builtins_for(dom) & seen
        [dom, hit.sort] unless hit.empty?
      end.to_h
    end

    # A human-readable dump of the packed-record channels: what writing a given
    # builtin puts into a ringbuf, and which span attributes those bytes become.
    def record_channels_report
      out = +"record channels (the bytes on the ringbuf, the typed consumer, and the span):\n"
      record_channels.each do |c|
        out << format("  %-6s %s (%d B) <- %s\n",
                      c[:id], c[:record_struct], c[:record_bytes], Array(c[:producers]).join(" / "))
        c[:fields].each do |f|
          type = f[:count].to_i > 0 ? "#{f[:ctype]}[#{f[:count]}]" : f[:ctype]
          out << format("    @%-4d %-14s %-22s %s\n", f[:offset], f[:name], type, f[:note])
        end
        cons = c[:consumer]
        if cons
          # The typed consumer: the same record, received in Ruby so a probe's own
          # logic can sit in front of it. properties is the authority on which
          # `ev.<name>` exist; anything else is a compile error.
          out << format("    consumer: %s   (drain %s / to_span %s / send %s)\n",
                        cons[:form], cons[:drain_fn], cons[:to_span_fn], cons[:send_fn])
          Array(cons[:properties]).each do |p|
            # For a derived string property the output capacity is part of the
            # declaration too, so the accessor and the span builder are handed the
            # same width. Since the declared capacity is at least the longest value
            # it can return, "how many bytes can this be" is readable from here. A
            # property that comes straight from a field reads the record's bytes, so
            # its width is the field's own, shown on the line above.
            # What is printed is the largest value in bytes, one less than the
            # declared capacity, which includes the terminator.
            width = p[:cap].to_i > 1 ? format(" (<=%dB)", p[:cap].to_i - 1) : ""
            out << format("      ev.%-12s %-4s %-8s <- %s%s\n",
                          p[:name], p[:expose], p[:kind], p[:source], width)
          end
        end
        e = c[:egress]
        next unless e
        out << format("    egress: %s -> span \"%s\" (SpanKind %s)\n", e[:push_fn], e[:span_name], e[:span_kind])
        e[:attributes].each do |a|
          out << format("      %-24s %-8s <- %s  [%s]\n", a[:key], a[:stability], a[:source], a[:condition])
        end
        out << format("      + enrichers (environment-gated, no probe change): %s\n", Array(e[:enrichers]).join(", ")) unless Array(e[:enrichers]).empty?
      end
      out << "\n"
      out << consumer_dsl_report
      out
    end

    # A human-readable dump of the consumer DSL's vocabulary and the rule by which
    # `to_span` resolves.
    def consumer_dsl_report
      ids = typed_record_channel_ids
      out = +"userspace consumer DSL (receiving a ringbuf in Ruby):\n"
      out << format("  typed channels (ids for which `on_emit :<id>` is a typed record): %s\n",
                    ids.empty? ? "(none)" : ids.join(", "))
      out << "  any other id keeps meaning a named event\n"
      CONSUMER_DSL.each do |v|
        out << format("  %-22s %s\n", v[:name], v[:form])
        out << format("      %s\n", v[:summary])
        out << format("      context: %s\n", v[:context_note])
        out << format("      note: %s\n", v[:gotcha]) if v[:gotcha]
      end
      out << "\n"
      out
    end

    # The human-readable dump of the whole registry, behind `spinel-ebpf capabilities`.
    def catalog_report
      out = +"spinel-ebpf capabilities -- the probe DSL, by domain\n\n"
      DOMAINS.each do |dom, spec|
        out << format("%-14s (%d builtins)\n", dom, spec[:builtins].length)
        out << "  #{spec[:summary]}\n"
        out << "  attach: #{spec[:attach_kinds].join(', ')}\n" unless spec[:attach_kinds].empty?
        out << "  builtins: #{spec[:builtins].sort.join(' ')}\n\n"
      end
      unless CONTEXT_GATES.empty?
        out << "context gates (refused at compile time outside these hooks):\n"
        CONTEXT_GATES.each do |name, g|
          out << format("  %-16s [%s] valid: %s\n", name, g[:domain], g[:valid_secs].join(" | "))
        end
        out << "\n"
      end
      out << "required sets (calls that produce no span on their own; enforced at compile time):\n"
      REQUIRED_SETS.each do |rule|
        if rule[:mode] == :all
          out << format("  %s (all-or-none)\n", rule[:members].join(" + "))
        else
          out << format("  %s requires %s\n", rule[:trigger], rule[:requires].join(", "))
        end
      end
      out << "\n"
      out << "builtin groups (related builtins -- pairs and families -- with call examples):\n"
      BUILTIN_GROUPS.each do |g|
        forms = g[:members].map { |m| example_for(m) || m }
        out << format("  %s\n", g[:name])
        out << "    #{forms.join('  ')}\n"
        out << "    #{g[:note]}\n"
      end
      out << "\n"
      out << record_channels_report
      out << "ready-made probe -> domain:\n"
      KREW_PROBE_DOMAINS.each { |p, d| out << format("  --probe %-5s -> %s\n", p, d) }
      out << "\nattach kinds (#{ATTACH_KINDS.length}) -- `spinel-ebpf capabilities --json` lists them with their conventions:\n"
      out << "  #{ATTACH_KINDS.map { |a| a[:kind] }.join(' ')}\n"
      out << "\nmachine-readable authoring contract: spinel-ebpf capabilities --json\n"
      out
    end

    # ===================================================================
    # The machine-readable authoring contract: publish what can be done.
    #
    # Builtin signatures (arity and parameter names), the conventions of each attach
    # kind, what the Ruby subset does and does not accept, and the enrichers are all
    # held here as plain data and emitted as one JSON document by
    # `capabilities --json`. An author -- often a program -- can then read the legal
    # moves rather than guess at them.
    #
    # That this is complete -- every builtin and attach kind appears -- and that its
    # arities have not drifted from the generator's is enforced by the unit tests.
    #
    # The authority on a signature is the generator's own `expects N` and
    # `expect_no_args` checks. This module cannot require the generator -- the
    # generator reads the gate allowlist from here, so it would be circular -- so the
    # arities are mirrored, and a test parses the generator's source to detect drift.
    # A builtin whose parameter names cannot be extracted mechanically is marked
    # opaque rather than guessed at.
    # ===================================================================

    # Structural groups, holding the same name sets the generator does; a test keeps
    # them from drifting apart.
    PKT_FIELD_BUILTINS = %w[
      pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst
      pkt_l4_sport pkt_l4_dport pkt_tcp_flags pkt_l4_payload_len
      pkt_ip6_src_hi pkt_ip6_src_lo pkt_ip6_dst_hi pkt_ip6_dst_lo
      pkt_tcp_seq pkt_tcp_ack
    ].freeze
    TCP_SOCK_READER_BUILTINS = %w[
      tcp_sock_snd_cwnd tcp_sock_snd_ssthresh tcp_sock_snd_nxt tcp_sock_snd_una
      tcp_sock_packets_out tcp_sock_delivered tcp_sock_snd_cwnd_cnt
      tcp_sock_snd_cwnd_clamp tcp_sock_prior_cwnd
    ].freeze
    TCP_SOCK_WRITER_BUILTINS = %w[
      tcp_sock_snd_cwnd_set tcp_sock_snd_ssthresh_set tcp_sock_snd_cwnd_cnt_set
    ].freeze
    TCP_SOCK_ADDER_BUILTINS = %w[
      tcp_sock_snd_cwnd_add tcp_sock_snd_cwnd_cnt_add
    ].freeze
    OPAQUE_KFUNC_BUILTINS = %w[
      scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq
      qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
      qdisc_watchdog_schedule qdisc_bstats_update
    ].freeze

    # The explicit signature table. Each value is [arity, params or nil, summary];
    # a nil params means the builtin is opaque.
    #   arity  : Integer | :variadic
    #   params : the argument names, taken from the generator's own checks; nil when opaque
    # The generator is the single authority for arity and parameter names, and a test
    # detects drift. The pkt_* and tcp_sock_* families are generated below.
    SIG_TABLE = {
      # --- observability: emit / hist / latency / task / stack / etc. ---
      "spnl_emit"        => [1, %w[value],            "emit one __s64 into the ringbuf, behind the 16-byte header"],
      "spnl_emit_str"    => [1, %w[ptr],              "read a string from a user pointer and emit it into the string ringbuf"],
      "spnl_emit_pair"   => [2, %w[a b],              "emit two values as one event"],
      "spnl_emit3"       => [3, %w[a b c],            "emit three values as one event"],
      "spnl_emit4"       => [4, %w[a b c d],          "emit four values as one event"],
      "emit_argv"        => [1, %w[argv],             "walk an execve argv[] and emit each entry into the string ringbuf"],
      "emit_comm"        => [0, [],                   "emit the current process's comm into the string ringbuf"],
      "comm_hash"        => [0, [],                   "return the first 8 bytes of comm as an __s64, for grouping"],
      "hist_observe"     => [1, %w[value],            "add one sample to a log2 histogram"],
      "hist_observe_by"  => [2, %w[key value],        "add one sample to a keyed log2 histogram"],
      "hist_observe_linear" => [1, %w[slot],          "add to a linear histogram; the caller has already chosen the bucket"],
      "ktime_ns"         => [0, [],                   "bpf_ktime_get_ns()"],
      "latency_start"    => [0, [],                   "begin: record the entry time, keyed by thread id"],
      "latency_end"      => [0, [],                   "end: return the elapsed nanoseconds and drop the entry"],
      "lat_start"        => [1, %w[key],              "begin a latency measurement under any key"],
      "lat_end"          => [1, %w[key],              "end a latency measurement under any key, returning the elapsed time"],
      "task_load"        => [0, [],                   "read this task's storage"],
      "task_store"       => [1, %w[value],            "write this task's storage"],
      "task_incr"        => [1, %w[delta],            "add to this task's storage in a single read-modify-write"],
      "task_swap"        => [1, %w[value],            "swap this task's storage, a general read-modify-write"],
      "stack_id"         => [0, [],                   "kernel stack id (STACK_TRACE map)"],
      "user_stack_id"    => [0, [],                   "user stack id (STACK_TRACE map)"],
      "off_cpu_start"    => [1, %w[pid],              "start an off-CPU measurement, stashing the time and stack by pid"],
      "off_cpu_observe"  => [1, %w[pid],              "on return, bin the elapsed off-CPU time into a keyed histogram"],
      "leak_record"      => [3, %w[ptr size stack_id],"record an allocation, for leak tracking"],
      "leak_forget"      => [1, %w[ptr],              "drop the record on free, for leak tracking"],
      "lock_edge"        => [2, %w[a b],              "record a lock-ordering edge, for deadlock detection"],
      "mim_inc"          => [2, %w[group key],        "map-in-map: add to inner[key]"],
      "mim_get"          => [2, %w[group key],        "map-in-map: read inner[key]"],
      "fifo_push"        => [1, %w[value],            "push onto a queue map"],
      "fifo_pop"         => [0, [],                   "pop from a queue map"],
      "lifo_push"        => [1, %w[value],            "push onto a stack map"],
      "lifo_pop"         => [0, [],                   "pop from a stack map"],
      "depth_inc"        => [1, %w[key],              "increment the recursion-depth counter"],
      "depth_dec"        => [1, %w[key],              "decrement the recursion-depth counter"],
      "path_counter_inc" => [1, %w[key],              "atomically increment a general keyed counter"],
      "kfield"           => [:variadic, %w[ptr struct field], "read a kernel struct field safely through CO-RE, following any number of hops"],
      "kptr"             => [2, %w[ptr struct],       "bind a local to a struct type, so that .field accessors work on it"],
      # --- enforcement: audit / lineage / deny selector ---
      "emit_path"        => [1, %w[file],             "emit a file's full path into the string ringbuf; gated to certain hooks"],
      "emit_parent_path" => [0, [],                   "emit the parent executable's full path; gated to certain hooks"],
      "path_eq"          => [2, %w[file path_literal], "a use-neutral predicate: whether a file's full path equals a literal. It is an expression and is gated to certain hooks. It only decides -- what happens next is the handler's return value"],
      "path_starts_with" => [2, %w[file path_literal_prefix], "a use-neutral predicate: whether a file's full path starts with a literal prefix. An expression, gated to certain hooks; the handler's return value decides what happens. It uses per-CPU scratch space, so it compares correctly up to the full path length"],
      "path_contains"    => [2, %w[file path_literal_substr], "a use-neutral predicate: whether a literal appears anywhere in a file's full path, at any offset. An expression, gated to certain hooks; the handler's return value decides what happens. It sweeps the whole path with a sliding window, so no offset slips past it"],
      "parent_path_eq"   => [1, %w[path_literal],     "a use-neutral predicate: whether the parent executable's path equals a literal. An expression, gated to certain hooks; the handler's return value decides what happens"],
      "ppid"             => [0, [],                   "the parent thread-group id, as numbered in the init namespace"],
      # --- L7: HTTP, TLS and DNS spans, L7 latency, and off-CPU correlation ---
      "http_req_start"   => [2, %w[sk msg],           "read the send buffer and, if it is an HTTP request, record it by socket"],
      "http_resp_stash"  => [2, %w[sk msg],           "stash the receive buffer by thread id"],
      "http_emit"        => [1, %w[ret],              "read the stash, correlate by socket, and emit one HTTP span"],
      "redis_req_start"  => [3, %w[sk msg size],      "read the first size bytes of the send buffer and, if it is a RESP command, record it by socket"],
      "redis_resp_stash" => [2, %w[sk msg],           "stash the receive buffer by thread id, for Redis"],
      "redis_emit"       => [1, %w[ret],              "read the stash, correlate by socket, and emit one Redis span with its command, error and duration"],
      "ssl_req_start"    => [2, %w[ssl buf],          "read the plaintext handed to SSL_write and, if it is HTTP, record it by SSL handle"],
      "ssl_resp_stash"   => [2, %w[ssl buf],          "stash the buffer by thread id on entry to SSL_read"],
      "ssl_emit"         => [1, %w[ret],              "correlate the decrypted buffer by SSL handle and emit a span for the plaintext"],
      "go_tls_write"     => [3, %w[conn ptr len],     "read the plaintext slice handed to Go's TLS write and emit an HTTP request span. There is no socket here, so the scheme is https"],
      "go_tls_req"       => [3, %w[conn ptr len],     "read that plaintext within its length bound and stash it by connection -- the request half of a full RED measurement"],
      "go_tls_resp_stash"=> [2, %w[conn ptr],         "stash the receive buffer on entry to Go's TLS read, keyed by goroutine rather than thread: a blocking read can move between threads"],
      "go_tls_emit"      => [1, %w[ret],              "on return from that read, find the stash by goroutine, correlate it with the request by connection, and emit a full RED span"],
      "dns_req_start"    => [2, %w[sk msg],           "begin correlating a DNS query"],
      "dns_resp_stash"   => [2, %w[sk msg],           "stash the DNS response buffer"],
      "dns_emit"         => [1, %w[ret],              "DNS span emit"],
      "emit_dns"         => [1, %w[msg],              "emit a DNS query seen on port 53 as a packed record, independent of any resolver library"],
      "emit_tcp_payload" => [1, %w[msg],              "emit the first 128 bytes of a send buffer as a string, for protocol-independent parsing in userspace"],
      "emit_tcp_stream"  => [3, %w[sk msg size],      "emit a send buffer as a packed record keyed by socket, so userspace can accumulate per connection and reassemble a stream across many of them"],
      "req_start"        => [1, %w[sk],               "record the start of an L7 round trip in tcp_sendmsg"],
      "emit_l7"          => [1, %w[sk],               "emit an L7 round-trip latency span once the data has reached the application"],
      "offcpu_recv_stash"=> [2, %w[sk msg],           "open an off-CPU window for this thread on an HTTP request"],
      "offcpu_begin"     => [1, %w[ret],              "open the off-CPU window, on return"],
      "offcpu_account"   => [3, %w[prev_pid prev_state next_pid], "accumulate the voluntary off-CPU stacks seen within the window"],
      "offcpu_emit"      => [2, %w[sk msg],           "close the window and emit a span carrying the off-CPU breakdown"],
      # --- net: connect / L4 / datapath / conntrack / arena / tcp slice ---
      "emit_connect"     => [7, %w[skaddr daddr dport family oldstate daddr6_hi daddr6_lo], "emit a connection as one packed record, carrying the process, the peer and the round-trip time together"],
      "sock_owner_set"   => [1, %w[sk],               "record socket to {pid, comm} at connect time, so the process can be recovered in softirq context"],
      "blocklist_match"  => [1, %w[ip],               "a use-neutral predicate: whether an address is in an exact-match set, in host order. A match means deny for a blocklist or allow for an allowlist; the return value decides. Seed the set from userspace by declaring `ffi_func :sp_bpf_blocklist_add, [:uint32], :int` in a `module` (a class will not do) and calling `M.sp_bpf_blocklist_add(0x0a000001)` at top level with an integer literal"],
      "cidr_blocklist_match" => [1, %w[ip],           "a use-neutral predicate: whether an address falls in a set of CIDRs, by longest-prefix match, in host order. It is likewise use-neutral -- a match means deny for a blocklist or allow for an allowlist; the return value decides. Seed the set from userspace by declaring `ffi_func :sp_bpf_cidr_blocklist_add, [:uint32,:uint32], :int` in a `module` (a class will not do) and calling `M.sp_bpf_cidr_blocklist_add(0x7f000000, 8)` at top level with an integer address and prefix length. Calling it again at run time updates the set, and `_del` works the same way"],
      "reuseport_hash"   => [0, [],                   "ctx->hash (kernel 5-tuple hash)"],
      "worker_select"    => [1, %w[idx],              "choose a worker socket with bpf_sk_select_reuseport"],
      "cpumap_redirect"  => [1, %w[cpu],              "redirect into a CPU map"],
      "xsk_redirect"     => [1, %w[qid],              "redirect into an AF_XDP socket map"],
      "dev_redirect"     => [1, %w[idx],              "redirect into a device map"],
      "tail_call_to"     => [1, %w[slot],             "tail-call into a program-array slot"],
      "sock_ops_op"      => [0, [],                   "ctx->op (sock_ops)"],
      "sock_ops_state"   => [0, [],                   "ctx->args[1] (sock_ops state)"],
      "sock_addr_ip4"    => [0, [],                   "the destination IPv4 address of a connect or bind, in host order"],
      "sock_addr_port"   => [0, [],                   "the destination port of a connect or bind, in host order"],
      "iter_task"        => [0, [],                   "the current task_struct pointer while iterating tasks"],
      "xdp_match_health" => [0, [],                   "whether this XDP frame is a GET /health request"],
      "xdp_reply_health" => [0, [],                   "rewrite the frame into a 200 OK response and transmit it"],
      "pkt_dynptr_byte_at" => [1, %w[offset],         "read the byte at any offset through a dynptr, safely for the verifier"],
      "fib_lookup"       => [1, %w[dst],              "an IPv4 route lookup, yielding the egress interface index"],
      "fib_lookup6"      => [2, %w[dst_hi dst_lo],    "an IPv6 route lookup"],
      "sk_lookup_tcp"    => [4, %w[saddr daddr sport dport], "look up a TCP socket by 4-tuple"],
      "sk_assign_tcp"    => [4, %w[saddr daddr sport dport], "look a socket up and steer the packet to it"],
      "redirect"         => [1, %w[ifindex],          "bpf_redirect (L3 forwarding)"],
      "skb_load_byte"    => [1, %w[offset],           "read one byte from the packet"],
      "skb_load_u16"     => [1, %w[offset],           "read a 16-bit value from the packet"],
      "skb_load_u32"     => [1, %w[offset],           "read a 32-bit value from the packet"],
      "skb_store_byte"   => [2, %w[offset value],     "write one byte into the packet"],
      "skb_store_u16"    => [2, %w[offset value],     "write a 16-bit value into the packet"],
      "skb_store_u32"    => [2, %w[offset value],     "write a 32-bit value into the packet"],
      "l3_csum_replace"  => [3, %w[offset from to],   "patch the L3 checksum for a 16-bit change"],
      "l3_csum_replace_ip" => [3, %w[offset from to], "patch the L3 checksum for a 32-bit address change"],
      "l4_csum_replace"  => [3, %w[offset from to],   "patch the L4 checksum for a 16-bit change"],
      "l4_csum_replace_ip" => [3, %w[offset from to], "patch the L4 checksum for a 32-bit change, including the pseudo-header"],
      "l4_offset"        => [0, [],                   "the offset where L4 begins, accounting for IP options"],
      "flow_get"         => [2, %w[map_name field],   "connection tracking: read a field of the current flow; the field is named by a symbol"],
      "flow_set"         => [3, %w[map_name field value], "connection tracking: write a field of the current flow; the field is named by a symbol"],
      "flow_del"         => [1, %w[map_name],         "connection tracking: delete the current flow's entry"],
      "tcp_syncookie_gen"=> [0, [],                   "generate a raw SYN cookie"],
      "tcp_syncookie_check" => [0, [],                "verify a raw SYN cookie"],
      "tcp_reply_header" => [3, %w[seq ack flags],    "turn the packet into a header-only TCP reply"],
      "tcp_reply_synack" => [1, %w[cookie],           "build a SYN-ACK, with an MSS option"],
      "tcp_synack_cookie"=> [0, [],                   "turn a SYN into a SYN-ACK carrying a cookie, in one step"],
      "tcp_reply_data"   => [3, %w[seq ack payload_literal], "turn the packet into a data response; the payload is a literal"],
      "payload_starts"   => [1, %w[prefix_literal],   "whether the TCP payload starts with a literal prefix, compared at compile time"],
      "queue_push"       => [2, %w[skb to_free],      "enqueue a packet onto a BPF list"],
      "queue_pop"        => [0, [],                   "dequeue a packet from a BPF list"],
      "arena_set"        => [2, %w[index value],      "write to a flat array in the arena"],
      "arena_get"        => [1, %w[index],            "read from a flat array in the arena"],
      "arena_hash_set"   => [2, %w[key value],        "write to a hash table in the arena"],
      "arena_hash_get"   => [1, %w[key],              "read from a hash table in the arena"],
      "arena_hash_del"   => [1, %w[key],              "delete from a hash table in the arena"],
      "arena_list_push"  => [1, %w[value],            "push onto a linked list in the arena"],
      "arena_list_sum"   => [0, [],                   "sum a linked list in the arena"],
      # --- core: identity / cgroup / control channel ---
      "divu"             => [2, %w[a b],              "unsigned 64-bit division, which the verifier accepts where signed division is refused"],
      "i32"              => [1, %w[x],                "truncate a 32-bit kernel argument and sign-extend it, since the upper half holds garbage on arm64"],
      "pid"              => [0, [],                   "the pid as userspace means it: the upper half of the pid/tgid pair"],
      "tgid"             => [0, [],                   "thread group id"],
      "tid"              => [0, [],                   "kernel thread id"],
      "cpu_id"           => [0, [],                   "bpf_get_smp_processor_id()"],
      "cgroup_id"        => [0, [],                   "the current cgroup id, which is the cgroup directory's inode and the key to Kubernetes pod attribution"],
      "field_exists"     => [3, %w[ptr struct field], "whether BTF says this struct has this field"],
      "user_ringbuf_drain" => [0, [],                 "drain the user ring buffer, the channel by which userspace sends commands to the kernel"],
    }.freeze

    # Assemble every builtin's signature, from the explicit table plus the generated families.
    SIGNATURES = begin
      sigs = {}
      SIG_TABLE.each do |name, (arity, params, summary)|
        sigs[name] = { arity: arity, params: params, opaque: params.nil?, summary: summary }.freeze
      end
      PKT_FIELD_BUILTINS.each do |name|
        field = name.sub(/\Apkt_/, "")
        sigs[name] = { arity: 0, params: [], opaque: false,
                       summary: "packet field #{field} (xdp/tc, host order)" }.freeze
      end
      TCP_SOCK_READER_BUILTINS.each do |name|
        f = name.sub(/\Atcp_sock_/, "")
        sigs[name] = { arity: 1, params: %w[sk], opaque: false,
                       summary: "read tcp_sock->#{f} (tcp_cc)" }.freeze
      end
      TCP_SOCK_WRITER_BUILTINS.each do |name|
        f = name.sub(/\Atcp_sock_/, "").sub(/_set\z/, "")
        sigs[name] = { arity: 2, params: %w[sk value], opaque: false,
                       summary: "set tcp_sock->#{f} (tcp_cc)" }.freeze
      end
      TCP_SOCK_ADDER_BUILTINS.each do |name|
        f = name.sub(/\Atcp_sock_/, "").sub(/_add\z/, "")
        sigs[name] = { arity: 2, params: %w[sk delta], opaque: false,
                       summary: "tcp_sock->#{f} += delta (tcp_cc)" }.freeze
      end
      # An opaque kfunc: its arity is known from the generator's table, but the Ruby
      # parameter names come from a struct_ops member signature and cannot be
      # extracted mechanically. Marked opaque rather than guessed at.
      { "scx_dispatch" => 4, "scx_consume" => 1, "scx_kick_cpu" => 2,
        "scx_pick_idle_cpu" => 2, "scx_create_dsq" => 2,
        "qdisc_skb_drop" => 2, "qdisc_init_prologue" => 2,
        "qdisc_reset_destroy_epilogue" => 1, "qdisc_watchdog_schedule" => 3,
        "qdisc_bstats_update" => 2 }.each do |name, arity|
        sigs[name] = { arity: arity, params: nil, opaque: true,
                       summary: "a kfunc passthrough: hands a kernel struct pointer through from a struct_ops member" }.freeze
      end
      sigs.freeze
    end

    # A builtin to the context it requires -- the hooks the generator enforces at
    # compile time.
    #   { secs: [SEC...] }   d_path gate
    #   { kinds: [attach kind...] }  attach-kind gate
    # A builtin absent from this table is not enforced; it gets a best-effort note
    # instead.
    CONTEXT_REQUIREMENTS = begin
      reqs = {
        "emit_path"        => { secs: DPATH_OK_SECS },
        "emit_parent_path" => { secs: DPATH_OK_SECS },
        "path_eq"          => { secs: DPATH_OK_SECS },
        "path_starts_with" => { secs: DPATH_OK_SECS },
        "path_contains"    => { secs: DPATH_OK_SECS },
        "parent_path_eq"   => { secs: DPATH_OK_SECS },
        "reuseport_hash"   => { kinds: %i[sk_reuseport] },
        "worker_select"    => { kinds: %i[sk_reuseport] },
        "xdp_match_health" => { kinds: %i[xdp] },
        "xdp_reply_health" => { kinds: %i[xdp] },
        "pkt_dynptr_byte_at" => { kinds: %i[xdp] },
        "cpumap_redirect"  => { kinds: %i[xdp xdp_tail] },
        "xsk_redirect"     => { kinds: %i[xdp xdp_tail] },
        "dev_redirect"     => { kinds: %i[xdp xdp_tail] },
        "tail_call_to"     => { kinds: %i[xdp xdp_tail] },
        "sock_ops_op"      => { kinds: %i[sock_ops] },
        "sock_ops_state"   => { kinds: %i[sock_ops] },
        "sock_addr_ip4"    => { kinds: %i[cgroup_connect4 cgroup_bind4] },
        "sock_addr_port"   => { kinds: %i[cgroup_connect4 cgroup_bind4] },
        "iter_task"        => { kinds: %i[iter_task] },
        "tcp_syncookie_gen" => { kinds: %i[xdp] },
        "tcp_syncookie_check" => { kinds: %i[xdp] },
        "tcp_reply_header" => { kinds: %i[xdp] },
        "tcp_reply_synack" => { kinds: %i[xdp] },
        "tcp_synack_cookie" => { kinds: %i[xdp] },
        "tcp_reply_data"   => { kinds: %i[xdp] },
        "payload_starts"   => { kinds: %i[xdp] },
        "flow_get"         => { kinds: %i[xdp tc_ingress tc_egress] },
        "flow_set"         => { kinds: %i[xdp tc_ingress tc_egress] },
        "flow_del"         => { kinds: %i[xdp tc_ingress tc_egress] },
      }
      PKT_FIELD_BUILTINS.each { |b| reqs[b] = { kinds: %i[xdp tc_ingress tc_egress] } }
      (TCP_SOCK_READER_BUILTINS + TCP_SOCK_WRITER_BUILTINS + TCP_SOCK_ADDER_BUILTINS)
        .each { |b| reqs[b] = { kinds: %i[tcp_cc] } }
      %w[scx_dispatch scx_consume scx_kick_cpu scx_pick_idle_cpu scx_create_dsq]
        .each { |b| reqs[b] = { kinds: %i[sched_ext] } }
      %w[qdisc_skb_drop qdisc_init_prologue qdisc_reset_destroy_epilogue
         qdisc_watchdog_schedule qdisc_bstats_update]
        .each { |b| reqs[b] = { kinds: %i[qdisc] } }
      reqs.each_value(&:freeze)
      reqs.freeze
    end

    # Best-effort context notes for the ungated builtins. These are advisory: the
    # generator does not enforce them.
    DOMAIN_CONTEXT_NOTE = {
      observability: "process-context probe (kprobe/kretprobe/tracepoint/fentry/fexit/perf_event/uprobe/usdt); not enforced by the generator",
      enforcement:   "process-context security hook; not enforced by the generator",
      net:           "packet/socket datapath prog (xdp/tc/sk_*); not enforced by the generator",
      l7:            "a process-context kprobe or uprobe on the tcp_* or SSL_* entry points; not enforced by the generator",
      core:          "any eBPF method; not enforced by the generator",
    }.freeze

    # Per-builtin overrides, for where the domain's note would be wrong for a family.
    # The DNS builtins belong to the L7 domain, but their transport is UDP on port
    # 53, so their hooks are udp_sendmsg and udp_recvmsg. The domain note's mention
    # of the TCP and TLS entry points is not merely vague for DNS, it actively points
    # the wrong way. These notes name the hooks each family was designed around --
    # not the whole kernel catalogue, just the intended ones.
    CONTEXT_NOTE_OVERRIDES = {
      "dns_req_start"  => "kprobe/udp_sendmsg -- begin correlating when a port 53 query is sent; process-context; not enforced by the generator",
      "dns_resp_stash" => "kprobe/udp_recvmsg on entry -- stash the response buffer; the copied bytes are read on return; process-context; not enforced by the generator",
      "dns_emit"       => "kretprobe/udp_recvmsg -- correlate the response and emit the span; process-context; not enforced by the generator",
      "emit_dns"       => "kprobe/udp_sendmsg -- emit a port 53 query as a packed record, independent of any resolver; process-context; not enforced by the generator",
    }.freeze

    # ===================================================================
    # Call examples, and the links between related builtins.
    #
    # A clean-room test -- giving a model nothing but these affordances -- showed the
    # catalogue was sufficient to write a working probe, but that two things were
    # being supplied from prior knowledge rather than from here:
    #   (1) no Ruby example anywhere: signatures, but never the calling syntax
    #   (2) no indication of how related builtins relate -- which of pid, tgid and
    #       tid is per-process, for instance
    # These two additions close exactly that, and nothing more.
    #
    # Where the line sits: affordances cover the bridge, the ABI and what is legal.
    # The logic is the author's.
    #   * an example is one line of syntax, not advice on use. How to pick a
    #     threshold, or which algorithm to run, is Ruby logic and belongs to whoever
    #     is writing the probe.
    #   * a note on related builtins states the one fact needed to choose between
    #     them -- granularity, whether they are a pair, whether they are a family --
    #     and does not say when to use them.
    # ===================================================================

    # Call examples. Most are generated below:
    #   * a builtin with known parameters becomes `name(p1, p2, ...)`, using the
    #     parameter names as placeholders
    #   * a zero-argument builtin becomes a bare `name`, which is the dominant idiom
    #     and shows that no parentheses are needed
    #   * an opaque builtin gets none, rather than an invented one
    # Only the builtins whose parameter names alone do not yield valid syntax are
    # written by hand: the ones taking a symbol, a compile-time string literal, or a
    # struct name as a string.
    EXAMPLE_OVERRIDES = {
      # connection tracking: the map and the field are passed as symbols
      "flow_get"       => "flow_get(:conn, :backend_ip)",
      "flow_set"       => "flow_set(:conn, :state, 1)",
      "flow_del"       => "flow_del(:conn)",
      # CO-RE: the struct and field names are passed as strings
      "kfield"         => 'kfield(sk, "sock", "sk_sndbuf")',
      "kptr"           => 'kptr(sk, "sock")',
      "field_exists"   => 'field_exists(sk, "tcp_sock", "bytes_acked")',
      # arguments that must be string literals, so the compiler can unroll the bytes
      "path_eq"        => 'path_eq(file, "/usr/bin/curl")',
      "path_starts_with" => 'path_starts_with(file, "/etc/secret/")',
      "path_contains"  => 'path_contains(file, "/.ssh/")',
      "parent_path_eq" => 'parent_path_eq("/usr/bin/curl")',
      "payload_starts" => 'payload_starts("GET ")',
      "tcp_reply_data" => 'tcp_reply_data(seq, ack, "HTTP/1.0 200 OK")',
    }.freeze

    # Cross-links between related builtins. Each group is {name, members, note}, and
    # the per-builtin links are derived from here so there is one authority. A note
    # states the fact needed to choose -- granularity, pairing, family -- and not when
    # to use them. Multi-hook required sets live in their own table and are not
    # duplicated here; the L7 round trip is the exception, since it reads as a pair,
    # and it cross-references that table.
    BUILTIN_GROUPS = [
      { name: "process_thread_identity",
        members: %w[pid tgid tid],
        note: "pid() and tgid() are the same value and carry process granularity, taken from the upper half of the pid/tgid pair; tid() carries thread granularity, from the lower half. Choose by whether the grouping key should be a process or a thread." }.freeze,
      { name: "latency_tid_pair",
        members: %w[latency_start latency_end],
        note: "A begin/end pair keyed by thread. The first records the entry time in a kprobe; the second returns the elapsed nanoseconds and clears the entry, in a kretprobe. Use them together." }.freeze,
      { name: "latency_keyed_pair",
        members: %w[lat_start lat_end],
        note: "The same begin/end pair, under a key of your choosing." }.freeze,
      { name: "histogram",
        members: %w[hist_observe hist_observe_by hist_observe_linear],
        note: "Three forms of log2 histogram: hist_observe takes no key, hist_observe_by is keyed, and hist_observe_linear takes a slot the caller has already chosen." }.freeze,
      { name: "str_emit",
        members: %w[emit_comm emit_path emit_parent_path emit_argv spnl_emit_str],
        note: "Emitting into the string ringbuf: comm, a full path (gated), the parent executable path (gated), argv, or a string behind any user pointer." }.freeze,
      { name: "scalar_emit",
        members: %w[spnl_emit spnl_emit_pair spnl_emit3 spnl_emit4],
        note: "Scalar ringbuf emits: one, two, three or four values per event, behind the common 16-byte header." }.freeze,
      { name: "stack_trace",
        members: %w[stack_id user_stack_id],
        note: "Ids into the stack-trace map: stack_id for the kernel stack, user_stack_id for the userspace one." }.freeze,
      { name: "off_cpu_profile",
        members: %w[off_cpu_start off_cpu_observe],
        note: "An off-CPU profiling pair: the first stashes the time and stack when the scheduler switches away, the second bins the elapsed time into a keyed histogram on return. Distinct from the multi-hook offcpu_* span builtins." }.freeze,
      { name: "task_storage",
        members: %w[task_load task_store task_incr task_swap],
        note: "Per-task storage: load, store, increment as a read-modify-write, or swap. It is freed when the task exits, and needs no explicit key." }.freeze,
      { name: "l7_roundtrip",
        members: %w[req_start emit_l7],
        note: "The L7 round-trip pair: the first records the start on send, the second emits the round-trip span once the data has reached the application. See required_sets.l7_latency." }.freeze,
      { name: "pkt_fields",
        members: PKT_FIELD_BUILTINS,
        note: "Packet field accessors for XDP and TC: no arguments, host order. The pkt.* chain accessors, such as pkt.l4.proto, yield the same values." }.freeze,
      { name: "tcp_sock_accessors",
        members: (TCP_SOCK_READER_BUILTINS + TCP_SOCK_WRITER_BUILTINS + TCP_SOCK_ADDER_BUILTINS),
        note: "tcp_sock fields inside a congestion-control context: a reader takes the socket, a writer takes a socket and a value, an adder a socket and a delta. The dot accessors, such as sk.snd_cwnd, yield the same values." }.freeze,
      { name: "arena",
        members: %w[arena_set arena_get arena_hash_set arena_hash_get arena_hash_del arena_list_push arena_list_sum],
        note: "Data structures in the shared arena: a flat array, a hash table, and a linked list. The arena is shared with userspace through mmap." }.freeze,
      { name: "skb_rewrite",
        members: %w[skb_load_byte skb_load_u16 skb_load_u32 skb_store_byte skb_store_u16 skb_store_u32 l3_csum_replace l3_csum_replace_ip l4_csum_replace l4_csum_replace_ip l4_offset],
        note: "Reading and writing packets in TC, and repairing the checksums: byte, 16-bit and 32-bit loads and stores, the L3 and L4 checksum patches, and the offset where L4 begins (accounting for IP options). These are the pieces NAT is built from." }.freeze,
    ].freeze

    # The conventions of each attach kind, one for one with the generator's own attach
    # patterns; a test enforces that the two sets match. args_convention says which
    # ABI the declared parameters are extracted from in the attach context.
    ATTACH_KINDS = [
      { kind: :kprobe,        method_prefix: "kprobe__<func>",           sec: "kprobe/<func>",         ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx) -- the kernel function's arguments, named through BTF", context_note: "the entry of a kernel function" },
      { kind: :kretprobe,     method_prefix: "kretprobe__<func>",        sec: "kretprobe/<func>",      ctx_type: "struct pt_regs *", args_convention: "a single parameter, the return value (PT_REGS_RC)", context_note: "the return of a kernel function" },
      { kind: :uprobe,        method_prefix: "uprobe__<func>",           sec: "uprobe",                ctx_type: "struct pt_regs *", args_convention: "PT_REGS_PARM<N>(ctx); the target binary and pid come from the environment (SPNL_UPROBE_*)", context_note: "the entry of a userspace function" },
      { kind: :uretprobe,     method_prefix: "uretprobe__<func>",        sec: "uretprobe",             ctx_type: "struct pt_regs *", args_convention: "a return parameter; the target comes from the environment (SPNL_UPROBE_*)", context_note: "the return of a userspace function" },
      { kind: :usdt,          method_prefix: "usdt__<provider>__<probe>", sec: "usdt",                 ctx_type: "struct pt_regs *", args_convention: "bpf_usdt_arg(ctx, i, &v); the target comes from the environment (SPNL_USDT_*)", context_note: "USDT static probe" },
      { kind: :tracepoint,    method_prefix: "tracepoint__<cat>__<event>", sec: "tracepoint/<cat>/<event>", ctx_type: "void *", args_convention: "for the syscall tracepoints, positional arguments in ctx->args[i]; for a named-field tracepoint, the parameter name selects the struct field", context_note: "kernel tracepoint" },
      { kind: :fentry,        method_prefix: "fentry__<func>",           sec: "fentry/<func>",         ctx_type: "__u64 *", args_convention: "ctx[i] holds the function's arguments, named through BTF", context_note: "BPF trampoline entry (~50ns)" },
      { kind: :fexit,         method_prefix: "fexit__<func>",            sec: "fexit/<func>",          ctx_type: "__u64 *", args_convention: "ctx[i] holds the function's arguments; the last parameter is the return value", context_note: "BPF trampoline exit" },
      { kind: :lsm,           method_prefix: "lsm__<hook>",              sec: "lsm/<hook>",            ctx_type: "__u64 *", args_convention: "ctx[i] holds the hook's arguments; the last parameter is the verdict so far", context_note: "An LSM security hook. To deny, return a negative errno; to allow, return the last parameter, which carries the prior verdict, rather than a literal 0. Note that an LSM hook only fires when the kernel was booted with BPF LSM enabled (lsm=...,bpf on the command line) -- otherwise it attaches and is a silent no-op, which is why fmod_ret on the matching security_* function is the portable way to enforce." },
      { kind: :fmod_ret,      method_prefix: "fmod_ret__<func>",         sec: "fmod_ret/<func>",       ctx_type: "__u64 *", args_convention: "ctx[i] holds the function's arguments and the last parameter is the return value, so a handler takes one more argument than the hook does. security_file_open takes one argument, hence `def fmod_ret__security_file_open(file, ret)`", context_note: "BPF_MODIFY_RETURN: replaces the target function's return value. Return a negative errno to deny, or return the last parameter unchanged to allow. Attaching to a security_* function gives a portable denial that does not depend on the kernel's boot-time LSM configuration -- an LSM hook that was never enabled is a silent no-op -- which is why this is the default way to enforce" },
      { kind: :user_ringbuf,  method_prefix: "user_ringbuf__<name>(value)", sec: "(a callback; no section)", ctx_type: nil, args_convention: "value is the one record that was drained", context_note: "the drain callback for the user ring buffer, by which userspace sends to the kernel" },
      { kind: :sock_ops,      method_prefix: "sock_ops__<name>",         sec: "sockops",               ctx_type: "struct bpf_sock_ops *", args_convention: "no declared parameters; read the context with sock_ops_op and sock_ops_state", context_note: "observing TCP state; attached to a cgroup ($SPNL_CGROUP_PATH)" },
      { kind: :cgroup_connect4, method_prefix: "cgroup__connect4__<name>", sec: "cgroup/connect4",     ctx_type: "struct bpf_sock_addr *", args_convention: "no declared parameters; read the context with sock_addr_ip4 and sock_addr_port", context_note: "controls outbound connect; return 1 to allow, 0 to deny" },
      { kind: :cgroup_bind4,  method_prefix: "cgroup__bind4__<name>",    sec: "cgroup/bind4",          ctx_type: "struct bpf_sock_addr *", args_convention: "no declared parameters; read the context with the sock_addr_* builtins", context_note: "controls bind; return 1 to allow, 0 to deny" },
      { kind: :iter_task,     method_prefix: "iter__task__<name>",       sec: "iter/task",             ctx_type: "struct bpf_iter__task *", args_convention: "no declared parameters; iter_task() yields the task pointer", context_note: "enumerating tasks, driven from userspace by the generated glue" },
      { kind: :raw_tp,        method_prefix: "raw_tp__<event>",          sec: "raw_tp/<event>",        ctx_type: "struct bpf_raw_tracepoint_args *", args_convention: "ctx->args[i]", context_note: "a raw tracepoint, with lower overhead" },
      { kind: :socket_filter, method_prefix: "socket_filter__<name>",    sec: "socket",                ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "the classic SO_ATTACH_BPF filter; the return value is how many bytes to keep" },
      { kind: :flow_dissector, method_prefix: "flow_dissector__<name>",  sec: "flow_dissector",        ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "returns BPF_OK or BPF_DROP" },
      { kind: :sk_lookup,     method_prefix: "sk_lookup__<name>",        sec: "sk_lookup",             ctx_type: "struct bpf_sk_lookup *", args_convention: "no declared parameters", context_note: "selects a listener. The section name takes no sub-name. Returns SK_PASS or SK_DROP" },
      { kind: :tcp_cc,        method_prefix: "class <N> < BPF::TcpCC (def <member>)", sec: "struct_ops/<member>",   ctx_type: nil, args_convention: "A struct_ops implementation is written as a class -- `class N < BPF::TcpCC` with `def init(sk)`, `def cong_avoid(sk, ack, acked)` and so on -- which is the idiomatic Ruby form. The flat `def tcp_cc__<member>` also registers. Member arguments are declared positionally.", context_note: "a tcp_congestion_ops member. The class form is preferred; the flat form also works" },
      { kind: :sched_ext,     method_prefix: "class <N> < BPF::SchedExt (def <member>)", sec: "struct_ops/<member>", ctx_type: nil, args_convention: "A struct_ops implementation is written as a class -- `class N < BPF::SchedExt` with a `def` per member. The flat `def sched_ext__<member>` also registers. Member arguments, such as the task, are declared positionally.", context_note: "a sched_ext_ops member -- a CPU scheduler. The class form is preferred; the flat form also works" },
      { kind: :qdisc,         method_prefix: "class <N> < BPF::Qdisc (def <member>)", sec: "struct_ops/<member>",   ctx_type: nil, args_convention: "A struct_ops implementation is written as a class -- `class N < BPF::Qdisc` with a `def` per member. The flat `def qdisc__<member>` also registers. The required members and their signatures are init(sch, opt, extack), enqueue(skb, sch, to_free), dequeue(sch), reset(sch) and destroy(sch). Note that enqueue MUST release the skb reference: call qdisc_skb_drop(skb, to_free) to drop it, or queue_push(skb, to_free) to forward it. Without that the verifier rejects the program for leaking a reference.", context_note: "a Qdisc_ops member, attached through tc as spnl_qdisc. The class form is preferred; the flat form also works" },
      { kind: :xdp_tcp_slice, method_prefix: "xdp__tcp_slice__<name>",   sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "the body is a marker; the state machine is generated", context_note: "a pure-XDP TCP slice; it takes precedence over a plain xdp__ handler" },
      { kind: :xdp_tail,      method_prefix: "xdp_tail__<name>",         sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "no declared parameters; use the pkt_* builtins and tail_call_to", context_note: "a tail-callable sub-program: not auto-attached, but placed in a program-array slot" },
      { kind: :xdp,           method_prefix: "xdp__<name>",              sec: "xdp",                   ctx_type: "struct xdp_md *", args_convention: "no declared parameters; use the pkt_* builtins or the pkt.* accessors", context_note: "returns XDP_PASS, XDP_DROP, XDP_TX or XDP_REDIRECT; the interface comes from SPNL_XDP_IFACE" },
      { kind: :tc_ingress,    method_prefix: "tc__ingress__<name>",      sec: "tcx/ingress",           ctx_type: "struct __sk_buff *", args_convention: "no declared parameters; use the pkt_* and skb_* builtins", context_note: "returns one of the TC_ACT_* values; the interface comes from SPNL_TCX_IFACE" },
      { kind: :tc_egress,     method_prefix: "tc__egress__<name>",       sec: "tcx/egress",            ctx_type: "struct __sk_buff *", args_convention: "no declared parameters; use the pkt_* and skb_* builtins", context_note: "returns one of the TC_ACT_* values; the interface comes from SPNL_TCX_IFACE" },
      { kind: :sk_reuseport,  method_prefix: "sk_reuseport__<name>",     sec: "sk_reuseport",          ctx_type: "struct sk_reuseport_md *", args_convention: "no declared parameters; use reuseport_hash and worker_select", context_note: "selects among SO_REUSEPORT sockets; returns SK_PASS or SK_DROP" },
      { kind: :sk_msg,        method_prefix: "sk_msg__<name>",           sec: "sk_msg",                ctx_type: "struct sk_msg_md *", args_convention: "no declared parameters", context_note: "a sockmap program, attached with BPF_SK_MSG_VERDICT" },
      { kind: :sk_skb_verdict, method_prefix: "sk_skb__verdict__<name>", sec: "sk_skb/stream_verdict", ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "sockmap stream verdict" },
      { kind: :sk_skb_parser, method_prefix: "sk_skb__parser__<name>",   sec: "sk_skb/stream_parser",  ctx_type: "struct __sk_buff *", args_convention: "no declared parameters", context_note: "sockmap stream parser" },
      { kind: :timer,         method_prefix: "on :timer, every: N.<unit> (spnl_timer__<name>)", sec: "syscall", ctx_type: "void *", args_convention: "no declared parameters; it is a periodic callback", context_note: "a bpf_timer. The method name is synthesised by the DSL, and the generated glue arms it at load time" },
      { kind: :perf_event,    method_prefix: "perf_event__<name> / on :perf_event, hz: N", sec: "perf_event", ctx_type: "struct bpf_perf_event_data *", args_convention: "no declared parameters; pair it with stack_id()", context_note: "per-CPU sampling profiler" },
    ].freeze

    # What the Ruby subset does and does not accept. The rejected list mirrors the
    # loud failures partitioning raises, and the flag names match the ones it uses;
    # a test keeps them in step.
    RUBY_SUBSET = {
      supported: [
        "integer literals, arithmetic (+ - * / %), and comparison (== != < > <= >=)",
        "Underscores in integer literals (5_000_000 == 5000000): readability only, the value is unchanged",
        "if / elsif / else, including as an expression; short-circuit || and &&; bitwise & | ^ << >>; parentheses",
        "local variables; method definitions with arguments and return values; BPF-to-BPF calls",
        "n.times { |i| ... }, including closure capture. A literal count is unrolled; a dynamic one lowers to bpf_loop",
        "integer instance variables, including at top level, each backed by a per-unit hash map (@x += n, @x = n)",
        "attach handlers: def <prefix>__<name>, for any of the attach kinds listed above",
        "an attach handler may declare any number of arguments from none upwards: kernel arguments it does not use can simply be left out, and a kprobe taking none is perfectly legal. Whatever is declared maps positionally onto the calling convention for that kind",
        "class inheritance (class C < BPF::XDP), module inclusion (include BPF::TcpCC), and the reactor form (include BPF::EventLoop; on :kind)",
        "namespaced constants such as XDP::PASS and IP::Proto::TCP, resolved to their integer values",
        "calls to the builtins listed above, by their flat names",
        "comparison against a compile-time string literal, as in path_eq, payload_starts and tcp_reply_data",
        "reading kernel fields with kfield and kptr, and the dot accessors (sk.snd_cwnd, pkt.l4.proto)",
        "binary-safe FFI (:binstr), which tolerates embedded NULs -- enough to write something like WebSocket framing in Ruby",
      ].freeze,
      # Each flag corresponds to one of the ineligibility flags partitioning raises,
    # every one of which is an immediate error.
      rejected: [
        { flag: :uses_float,               construct: "floating-point arithmetic",            reason: "no FPU in BPF" },
        { flag: :uses_regex,               construct: "regular expressions",              reason: "no regex helper in BPF" },
        { flag: :uses_io,                  construct: "any I/O",            reason: "host side only" },
        { flag: :uses_thread,              construct: "creating a thread",           reason: "the kernel side cannot create threads" },
        { flag: :uses_fiber,               construct: "Fiber",                 reason: "BPF has no notion of a fiber" },
        { flag: :uses_closure,             construct: "a closure capturing an outer variable, other than the supported form", reason: "only n.times is supported" },
        { flag: :uses_recursion,           construct: "recursion",          reason: "a BPF call graph must be acyclic" },
        { flag: :uses_bignum,              construct: "bignum",                reason: "BPF integers are 64 bits" },
        { flag: :uses_unbounded_loop,      construct: "an unbounded loop",        reason: "the verifier requires a bound" },
        { flag: :uses_unsupported_type,    construct: "a signature naming a non-integer type (string, array, hash, ...)", reason: "only integer types are eligible for eBPF" },
      ].freeze,
      note: "A partitioning failure is an immediate error; there is no silent fallback. Ineligibility propagates to any method that calls an ineligible one.",
    }.freeze

    # The enrichers, for reference. Without changing the probe at all, they
    # add attributes at run time, gated by environment variables. This is where an
    # author can see that pod attribution comes from the environment, not the probe.
    ENRICHERS = [
      { name: "k8s", layer: 2, signal_scope: "all",
        attributes: %w[k8s.pod.name k8s.namespace.name k8s.pod.uid k8s.container.name],
        gate: "the cgroup_id() builtin, plus resolving the cgroup against kubepods",
        note: "pod attribution appears without changing the probe; unset, it does nothing" },
      { name: "cri", layer: 2, signal_scope: "all",
        attributes: %w[k8s.container.name],
        gate: "CRIMAP (env)",
        note: "replaces the container id with the real container name, last writer winning; unset, it does nothing" },
      { name: "peer", layer: 2, signal_scope: "conn",
        attributes: %w[peer.address peer.pod peer.service peer.external],
        gate: "resolving the destination address",
        note: "connection spans only -- the ones that have a destination" },
    ].freeze

    # ===================================================================
    # The required sets: calls that only mean something together.
    # the contract.
    #
    # Some builtins mean nothing on their own: they only produce a span together with
    # a counterpart, usually in a different attach section. Write one half and the
    # program is quietly broken -- records accumulate, nobody reads them, no span
    # appears, and it still exits 0. That is
    # A program missing one of them is the worst kind of failure -- quiet. The
    # contract is held here as plain data so that
    #   * the compile-time check reads it and rejects the program,
    #   * it appears in the affordances (`--json`, under `required_sets`), so an
    #     author can see what the other half is,
    # so both hold at once.
    #
    # mode:
    #   :all      -- using any member makes all of them required; they are mutually dependent.
    #   :requires -- using the trigger makes everything it requires mandatory, in one
    #                direction only: the others remain valid on their own.
    #
    # The contract is deliberately no tighter than reality:
    #   * emit_connect and emit_dns are valid alone, so they are not listed here.
    #   * sock_owner_set means nothing unless emit_connect reads what it records, so
    #     it requires that one, in one direction.
    #   Every complete probe under examples/observability/otlp satisfies this.
    #
    # There is another half to every span-producing set. The members above are the
    # kernel-side builtins, and they only accumulate records in a map; nothing is
    # exported until userspace declares the FFI and runs a drain loop.
    # That half used to be invisible here, and it showed: given only these
    # affordances, two different models wrote a correct kernel probe, omitted the
    # drain, and produced a program that compiled, verified, and emitted no spans --
    # exactly the kernel/userspace bridge bug this project exists to make
    # impossible. So each set now carries a `userspace_export` companion as data:
    # the FFI name of its counterpart, and one line of drain-loop syntax. The
    # interval is the author's decision; this shows the syntax, not the policy. The
    # push functions themselves are defined in bin/spinel-ebpf, and all take just an
    # endpoint.
    # Reading the endpoint from the OTLP_ENDPOINT environment variable is the
    # convention here: given a bare placeholder, an author tends to hard-code it,
    # get the port wrong, and see zero spans. Choosing the value is still theirs;
    # this is portability syntax, not advice.
    REQUIRED_SETS = [
      { name: "http_span", mode: :all,
        members: %w[http_req_start http_resp_stash http_emit],
        why: "The first records the request, the second stashes the receive buffer, and the third correlates them into a span. Omit any one and no span appears.",
        userspace_export: {
          fn: "spnl_otlp_http_span_push",
          ffi_decl: "ffi_func :spnl_otlp_http_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_http_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_http_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "redis_span", mode: :all,
        members: %w[redis_req_start redis_resp_stash redis_emit],
        why: "The first records the request, the second stashes the receive buffer, and the third correlates them into a span carrying the command, any error, and the duration. Omit any one and no span appears.",
        userspace_export: {
          fn: "spnl_otlp_redis_span_push",
          ffi_decl: "ffi_func :spnl_otlp_redis_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_redis_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_redis_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "ssl_span", mode: :all,
        members: %w[ssl_req_start ssl_resp_stash ssl_emit],
        why: "Three hooks over the TLS plaintext -- request, response, emit -- make one span. Omit one and no plaintext span appears.",
        userspace_export: {
          fn: "spnl_otlp_http_span_push",
          ffi_decl: "ffi_func :spnl_otlp_http_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_http_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_http_span_push(ep) }",
          why: "The TLS path reuses the HTTP push; there is no separate one for it. The kernel-side builtins only accumulate records in a map, and nothing is exported until userspace drains them through this FFI.",
        }.freeze }.freeze,
      { name: "dns_span", mode: :all,
        members: %w[dns_req_start dns_resp_stash dns_emit],
        why: "Three hooks -- request, response, emit -- make one DNS span, with its latency.",
        userspace_export: {
          fn: "spnl_otlp_dns_span_push",
          ffi_decl: "ffi_func :spnl_otlp_dns_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_dns_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_dns_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "l7_latency", mode: :all,
        members: %w[req_start emit_l7],
        why: "The first records the send time and the second reads the round trip and makes the span. With only one of them there is no duration.",
        userspace_export: {
          fn: "spnl_otlp_l7_span_push",
          ffi_decl: "ffi_func :spnl_otlp_l7_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_l7_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_l7_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "offcpu_span", mode: :all,
        members: %w[offcpu_recv_stash offcpu_begin offcpu_account offcpu_emit],
        why: "The first two open the off-CPU window, the third accumulates what was waited on, and the fourth closes the window and makes the span. Four hooks, one set.",
        userspace_export: {
          fn: "spnl_otlp_offcpu_span_push",
          ffi_decl: "ffi_func :spnl_otlp_offcpu_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_offcpu_span_push, [:str], :int\nend\n# ... kernel handlers (members) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_offcpu_span_push(ep) }",
          why: "The kernel-side builtins only accumulate span records in a map. Nothing is exported until userspace drains them through this FFI. Leave it out and the program compiles, the verifier is happy, and not one span comes out.",
        }.freeze }.freeze,
      { name: "sock_owner_correlation", mode: :requires,
        trigger: "sock_owner_set", requires: %w[emit_connect],
        why: "sock_owner_set only records which process owns a socket; the correlation happens when emit_connect looks the same socket up.",
        userspace_export: {
          fn: "spnl_otlp_conn_span_push",
          ffi_decl: "ffi_func :spnl_otlp_conn_span_push, [:str], :int",
          pattern: "module Otlp\n  ffi_func :spnl_otlp_conn_span_push, [:str], :int\nend\n# ... kernel handlers (sock_owner_set + emit_connect) ...\nep = ENV[\"OTLP_ENDPOINT\"] || \"http://127.0.0.1:4318\"\nloop { sleep n; Otlp.spnl_otlp_conn_span_push(ep) }",
          why: "This correlation is exported on the connection span emit_connect produces; there is no separate push for it. The kernel-side builtins only accumulate records in a map, and nothing is exported until userspace drains them through this FFI.",
        }.freeze }.freeze,
    ].freeze

    # --- the machine-readable affordance queries ---

    # builtin -> signature hash ({arity:, params:, opaque:, summary:})。
    def signature_for(name)
      SIGNATURES[name] || { arity: nil, params: nil, opaque: true, summary: nil }
    end

    # A builtin to its context requirement, or nil when the generator does not enforce one.
    def context_for(name)
      CONTEXT_REQUIREMENTS[name]
    end

    # A builtin to the list of contexts it is valid in, for the JSON output; nil when ungated.
    def context_strings(name)
      req = CONTEXT_REQUIREMENTS[name]
      return nil unless req
      return req[:secs] if req[:secs]
      req[:kinds].map(&:to_s)
    end

    # A builtin to a human-readable note about its context: enforced when gated,
    # best-effort otherwise.
    def context_note(name)
      return "enforced at compile time; using it outside these hooks is an error" if CONTEXT_REQUIREMENTS[name]
      CONTEXT_NOTE_OVERRIDES[name] || DOMAIN_CONTEXT_NOTE[domain_of(name)] || "not enforced by the generator"
    end

    # A builtin to one line of Ruby showing how it is called. An opaque builtin gets
    # nil: its parameters are unknown, and omitting the example is more honest than
    # inventing one.
    def example_for(name)
      sig = signature_for(name)
      return nil if sig[:opaque]              # deliberately absent: nil exactly when opaque
      ov = EXAMPLE_OVERRIDES[name]
      return ov if ov
      params = sig[:params]
      return name if params.nil? || params.empty?   # no arguments: a bare call, the usual idiom
      "#{name}(#{params.join(', ')})"
    end

    # A builtin to the others in its group, sorted; empty when it belongs to none.
    # The groups table is the single authority.
    def related_for(name)
      BUILTIN_GROUPS.each_with_object([]) do |g, acc|
        acc.concat(g[:members] - [name]) if g[:members].include?(name)
      end.uniq.sort
    end

    # The complete affordance entry for one builtin.
    def builtin_entry(name)
      sig = signature_for(name)
      chan = record_channel_for(name)   # non-nil only for a builtin that writes a packed record
      {
        name: name,
        domain: domain_of(name),
        arity: sig[:arity],
        params: sig[:params],
        opaque: sig[:opaque],
        example: example_for(name),   # one line of calling syntax; null when opaque
        related: related_for(name),   # the other builtins in its group
        gated: !CONTEXT_REQUIREMENTS[name].nil?,
        valid_contexts: context_strings(name),
        context_note: context_note(name),
        summary: sig[:summary],
        # The record this builtin writes into a ringbuf, and the span those bytes
        # become. The fields and offsets come from the generator's layout; the
        # attributes from the egress declaration.
        record_channel: chan && chan[:id],
        record_schema: chan,
      }
    end

    # The whole affordance document as a Ruby hash; the CLI renders it as JSON.
    def affordance
      {
        schema: "spinel-ebpf.affordance/1",
        note: "The authoring contract, published for introspection. It does not affect " \
              "generated code. Builtin names stay flat; they are deliberately not " \
              "namespaced into dotted forms.",
        summary: {
          builtin_count: all_builtins.length,
          opaque_builtins: all_builtins.count { |b| signature_for(b)[:opaque] },
          attach_kind_count: ATTACH_KINDS.length,
          domains: DOMAINS.keys,
          record_channel_count: record_channels.length,
        },
        domains: DOMAINS.each_with_object({}) { |(d, s), h|
          h[d] = { summary: s[:summary], attach_kinds: s[:attach_kinds] }
        },
        builtins: all_builtins.map { |b| builtin_entry(b) },
        # Cross-links between related builtins -- pairings and families -- with the
      # facts needed to choose between them.
        builtin_groups: BUILTIN_GROUPS,
        attach_kinds: ATTACH_KINDS,
        context_gates: CONTEXT_GATES.map { |n, g|
          { builtin: n, domain: g[:domain], valid_secs: g[:valid_secs] }
        },
        ruby_subset: RUBY_SUBSET,
        enrichers: ENRICHERS,
        krew_probes: KREW_PROBE_DOMAINS,
        # The multi-hook required sets: builtins that produce no span alone. The
        # compile-time check enforces them loudly.
        required_sets: REQUIRED_SETS,
        # The packed-record channel contracts: the bytes written into a ringbuf and
        # the OTLP attributes they become. This only reads what the generator
        # produced from the record declaration; no offset is computed here, because
        # there is exactly one implementation of that layout.
        record_channels: record_channels,
        # The consumer DSL's vocabulary and the rule by which `to_span` resolves.
        # typed_channels lists the ids for which `on_emit :<id>` is a typed consumer;
        # any other id is a named event.
        consumer_dsl: { typed_channels: typed_record_channel_ids, verbs: CONSUMER_DSL },
      }
    end

    # The affordance document as pretty-printed JSON.
    def affordance_json
      require "json"
      JSON.pretty_generate(affordance)
    end

    # --- the required-set queries ---

    # Given the set of builtin names in use, return the missing counterpart of each
    # required-set contract.
    # Returns: [ { name:, mode:, present: [...], missing: [...], why: }, ... ]
    # A satisfied set is omitted. Both the compile-time check and the affordances
    # use this.
    def missing_companions(used_names)
      used = used_names.to_a.to_set
      REQUIRED_SETS.filter_map do |rule|
        case rule[:mode]
        when :all
          present = rule[:members].select { |m| used.include?(m) }
          next if present.empty?
          missing = rule[:members] - present
          next if missing.empty?
          { name: rule[:name], mode: :all, experiment: rule[:experiment],
            present: present, missing: missing, why: rule[:why] }
        when :requires
          next unless used.include?(rule[:trigger])
          missing = rule[:requires].reject { |m| used.include?(m) }
          next if missing.empty?
          { name: rule[:name], mode: :requires, experiment: rule[:experiment],
            trigger: rule[:trigger], present: [rule[:trigger]], missing: missing, why: rule[:why] }
        end
      end
    end
  end
end
