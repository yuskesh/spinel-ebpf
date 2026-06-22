# frozen_string_literal: true
#
# Partition algorithm — Phase 2 (per-method walk + flags) and Phase 3
# (call-graph fix-point + tag decision).
#
# Per design in docs/research/partition_algorithm_design.md.
# Consumes the parsed IR and AST.

require_relative "parse_spinel_ir"
require_relative "parse_spinel_ast"
require_relative "kernel_cache"

module SpinelEbpf
  module Partition
    # Raised when a construct *names* the BPF plugin namespace
    # — `class Foo < BPF::X`, `include BPF::X`, or reactor `on :kind` — but the
    # specific member is unknown. The BPF namespace is declarative (the tables
    # below ARE its definition); an unrecognised member is a hard error rather
    # than a silent native fallback or a dropped handler (the "no silent
    # fallback" policy). A name OUTSIDE the BPF:: namespace is not our
    # concern and is left untouched (stays native, behaviour unchanged).
    class PartitionError < StandardError; end

    # BPF DSL base classes. A class whose superclass matches one of
    # these names is treated as a namespace for attach methods — every
    # method in the class body is enumerated as if it were a flat
    # `<prefix>__<method_name>` top-level method, so the existing
    # detect_attach + codegen pipeline works unchanged. Spinel flattens
    # `BPF::TcpCC` to `BPF_TcpCC` in @cls_parents, so we match on the
    # underscore-joined form.
    #
    # Only attach kinds without target-name arguments are supported here.
    # Patterns like `kprobe__sys_open` or `tracepoint__sched__sched_switch`
    # need the target as part of the SEC, which doesn't fit the simple
    # `class Foo < BPF::Bar` shape — those keep their flat-prefix form.
    BPF_DSL_PARENT_TO_PREFIX = {
      "BPF_XDP"         => "xdp__",
      "BPF_TcpCC"       => "tcp_cc__",
      "BPF_SchedExt"    => "sched_ext__",
      "BPF_Qdisc"       => "qdisc__",
      "BPF_SockOps"     => "sock_ops__",
      "BPF_TcIngress"   => "tc__ingress__",
      "BPF_TcEgress"    => "tc__egress__",
      "BPF_SkReuseport" => "sk_reuseport__",
      "BPF_SkMsg"       => "sk_msg__",
    }.freeze

    # Same lookup but keyed on the constant-path array form
    # (so `include BPF::TcpCC` produces `%w[BPF TcpCC]` -> "tcp_cc__").
    # Derived once at load time so adding a new BPF DSL parent in
    # BPF_DSL_PARENT_TO_PREFIX also gets the module form for free.
    BPF_DSL_INCLUDE_TO_PREFIX = BPF_DSL_PARENT_TO_PREFIX.each_with_object({}) do |(flat, prefix), h|
      h[flat.split("_")] = prefix
    end.freeze

    # BPF::EventLoop is a *marker* include — instead of binding the
    # whole module to one attach kind (like BPF::XDP does), it tells the
    # partition to scan the module body for `on :kind do ... end` calls
    # and synthesize one handler per `on`. Each kind maps to the same
    # flat-prefix form the rest of the pipeline already understands.
    #
    # MVP supports the no-target-arg attach kinds (xdp / sock_ops /
    # tc_ingress / tc_egress). Adding kprobe/tracepoint/fentry/etc.
    # requires extending the `on` form to take a target string.
    BPF_EVENT_LOOP_PATH = %w[BPF EventLoop].freeze

    # Per-`on :kind` description. `arity` is the number of extra **string**
    # arguments expected after the symbol; the synthesized method name is
    # `<prefix>` for arity 0 (already includes "main") or
    # `<prefix><target>` / `<prefix><target1>__<target2>` for arity 1/2.
    #
    # Besides the 4 arity-0 kinds there are the per-target attach kinds
    # (kprobe/kretprobe/fentry/fexit/tracepoint), which need a target function
    # or tracepoint name encoded into the SEC().
    EventLoopKind = Struct.new(:prefix, :arity, :joiner, keyword_init: true)

    BPF_EVENT_LOOP_KINDS = {
      "xdp"        => EventLoopKind.new(prefix: "xdp__main",         arity: 0),
      "sock_ops"   => EventLoopKind.new(prefix: "sock_ops__main",    arity: 0),
      "tc_ingress" => EventLoopKind.new(prefix: "tc__ingress__main", arity: 0),
      "tc_egress"  => EventLoopKind.new(prefix: "tc__egress__main",  arity: 0),
      "kprobe"     => EventLoopKind.new(prefix: "kprobe__",          arity: 1),
      "kretprobe"  => EventLoopKind.new(prefix: "kretprobe__",       arity: 1),
      "fentry"     => EventLoopKind.new(prefix: "fentry__",          arity: 1),
      "fexit"      => EventLoopKind.new(prefix: "fexit__",           arity: 1),
      "tracepoint" => EventLoopKind.new(prefix: "tracepoint__",      arity: 2, joiner: "__"),
      # `on :user_cmd do |cmd| ... end` -> single user_ringbuf callback
      # with the codegen's expected naming. MVP supports 1 callback per
      # module (fixed name `cmd_handler`); multi-callback would need
      # arity 1 with target = callback name.
      "user_cmd"   => EventLoopKind.new(prefix: "user_ringbuf__cmd_handler", arity: 0),
      # `on :timer, every: N.seconds do ... end` -> bpf_timer.
      # arity is 0 string-arg-wise; the interval is parsed separately from
      # the call's KeywordHashNode (every:). 1 module 1 timer (MVP).
      "timer"      => EventLoopKind.new(prefix: "spnl_timer__main", arity: 0),
      # Reactor form of the userspace probes. Target binary path
      # contains '/' and ':' that aren't valid in Ruby method names, so we
      # synthesize names like `uprobe__react<N>` and stash the real target
      # in MethodInfo (dsl_uprobe_binary etc.). glue.c reads a per-prog
      # target table to issue the correct bpf_program__attach_uprobe call.
      #
      # `on :uprobe,    "/usr/bin/bash:readline" do |prompt| ... end`
      # `on :uretprobe, "/usr/bin/bash:readline" do |ret|    ... end`
      # `on :usdt,      "/path/to/libfoo.so", "libfoo", "throw" do |a, b, c| ... end`
      #
      # arity:nil signals "variable arity / parsed by custom logic" — the
      # enumerator's main loop short-circuits these kinds.
      "uprobe"     => EventLoopKind.new(prefix: "uprobe__react",    arity: 1),
      "uretprobe"  => EventLoopKind.new(prefix: "uretprobe__react", arity: 1),
      "usdt"       => EventLoopKind.new(prefix: "usdt__react__",    arity: 3),
      # perf_event sampling. `on :perf_event, hz: 99 do … end`. arity 0
      # for the symbol args; frequency is parsed from a trailing
      # KeywordHashNode (hz:) and stashed in MethodInfo.dsl_perf_event_hz.
      "perf_event" => EventLoopKind.new(prefix: "perf_event__main", arity: 0),
    }.freeze

    # Parse the `every: N.<unit>` keyword in `on :timer, every: 5.seconds do…`.
    # Returns nanoseconds at compile time, or nil if the AST shape doesn't
    # match (e.g. wrong unit / non-literal interval).
    BPF_TIMER_UNIT_NS = {
      "seconds"      => 1_000_000_000,
      "second"       => 1_000_000_000,
      "milliseconds" => 1_000_000,
      "millisecond"  => 1_000_000,
      "ms"           => 1_000_000,
      "microseconds" => 1_000,
      "microsecond"  => 1_000,
      "us"           => 1_000,
      "nanoseconds"  => 1,
      "nanosecond"   => 1,
      "ns"           => 1,
    }.freeze

    # Back-compat alias — older tests read this map directly. Holds
    # only the arity-0 attach kinds whose prefix is `<attach_prefix>main`
    # AND whose bare prefix is one of the BPF_DSL_PARENT_TO_PREFIX values
    # (so xdp / sock_ops / tc_*). The user_cmd kind has its own unique
    # method name (`user_ringbuf__cmd_handler`) and the timer kind is also
    # a special-shape kind; both are excluded.
    BPF_EVENT_LOOP_KIND_TO_PREFIX = BPF_EVENT_LOOP_KINDS.each_with_object({}) do |(k, info), h|
      next unless info.arity == 0 && info.prefix.end_with?("main")
      bare = info.prefix.sub(/main\z/, "")
      next unless BPF_DSL_PARENT_TO_PREFIX.value?(bare)
      h[k] = bare
    end.freeze
    # ---------- Data structures ----------

    # Per-method analysis flags. All booleans default false.
    MethodFlags = Struct.new(
      :uses_float,
      :uses_regex,
      :uses_io,
      :uses_thread,
      :uses_fiber,
      :uses_closure,
      :uses_recursion,                 # filled in Phase 3
      :uses_bignum,
      :uses_unbounded_loop,
      :uses_dynamic_string_concat,
      :uses_dynamic_array_grow,
      :uses_unsupported_type,          # signature mentions string/array/hash/...
      :calls,                          # Array<String> callee names from AST
      :inherits_unsupported,           # filled in Phase 3
      keyword_init: true,
    ) do
      def self.default
        new(
          uses_float: false,
          uses_regex: false,
          uses_io: false,
          uses_thread: false,
          uses_fiber: false,
          uses_closure: false,
          uses_recursion: false,
          uses_bignum: false,
          uses_unbounded_loop: false,
          uses_dynamic_string_concat: false,
          uses_dynamic_array_grow: false,
          uses_unsupported_type: false,
          calls: [],
          inherits_unsupported: false,
        )
      end

      def ebpf_impossible?
        uses_float ||
          uses_regex ||
          uses_io ||
          uses_thread ||
          uses_fiber ||
          uses_closure ||
          uses_recursion ||
          uses_bignum ||
          uses_unbounded_loop ||
          uses_unsupported_type ||
          inherits_unsupported
      end

      def reasons
        r = []
        r << "uses Float arithmetic (no FPU in BPF)"                if uses_float
        r << "uses regex (no regex helper in BPF)"                  if uses_regex
        r << "performs I/O (host-side only)"                        if uses_io
        r << "creates Thread (kernel cannot create threads)"        if uses_thread
        r << "uses Fiber (no fiber concept in BPF)"                 if uses_fiber
        r << "uses closure with captured outer vars"                if uses_closure
        r << "calls itself recursively (BPF call graph is a DAG)"   if uses_recursion
        r << "uses bignum (BPF integers are 64-bit max)"            if uses_bignum
        r << "has loop without static upper bound"                  if uses_unbounded_loop
        r << "signature uses non-int type (string/array/hash/...)"  if uses_unsupported_type
        r << "calls another method that is eBPF-impossible"         if inherits_unsupported
        r
      end
    end

    # The unit of partition decision.
    MethodInfo = Struct.new(
      :scope,           # :top_level | :class | :main
      :class_name,      # String or nil
      :method_name,     # String (or "<main>" for main)
      :body_id,         # Integer (AST node id)
      :flags,           # MethodFlags
      :tag,             # :ebpf | :native | :error  (filled in Phase 3)
      # When a method came from a `class Foo < BPF::Bar` block we
      # synthesize a top-level entry with method_name = "<prefix>__<orig>".
      # These hints let method_params look up the original spinel
      # @cls_meth_params slot (params live in the class table, not the
      # top-level table) without touching the rest of the pipeline.
      :dsl_class_idx,   # Integer index into @cls_names, or nil
      :dsl_orig_name,   # Original (unprefixed) method name, or nil
      # Same idea for `module Foo; include BPF::Bar; end`. spinel's
      # IR doesn't track module-defined methods (@cls_* arrays are empty
      # for them), so we point straight at the DefNode in the AST and
      # codegen falls back to AST-driven param extraction.
      :dsl_ast_def_id,  # Integer AST node id of the DefNode, or nil
      # bpf_timer interval in nanoseconds. Set for `on :timer, every:
      # N.seconds do ... end` blocks; the codegen reads it to emit the
      # timer arm prog with the right interval and to bake the re-arm
      # constant into the callback. nil for non-timer methods.
      :dsl_timer_interval_ns,
      # Reactor-form uprobe/USDT target info. For uprobe / uretprobe
      # the binary + func come from a single colon-separated string arg
      # (`"/usr/bin/bash:readline"`); for USDT three string args
      # (binary, provider, probe). glue.c reads these from a per-prog
      # target table to call bpf_program__attach_uprobe / _usdt with the
      # right parameters.
      :dsl_uprobe_binary,   # String — binary path for any reactor uprobe/USDT
      :dsl_uprobe_func,     # String — function name for uprobe/uretprobe
      :dsl_uprobe_retprobe, # Boolean — true for uretprobe
      :dsl_usdt_provider,   # String — for usdt
      :dsl_usdt_name,       # String — for usdt
      # Per-handler PID for reactor uprobe/USDT (`on :uprobe, "...",
      # pid: 12345`). nil = system-wide (libbpf attach with pid=-1). Falls
      # through to env $SPNL_*_PID if also unset there.
      :dsl_attach_pid,
      # Sampling frequency (Hz) for `on :perf_event, hz: 99 do ... end`.
      # nil for flat-form (def perf_event__<name>) — glue.c uses $SPNL_PERF_HZ
      # (default 49). Integer for reactor form.
      :dsl_perf_event_hz,
      keyword_init: true,
    ) do
      def qualified_name
        case scope
        when :main      then "<main>"
        when :top_level then method_name
        when :class     then "#{class_name}##{method_name}"
        end
      end
    end

    # Whole-program partition result.
    Result = Struct.new(:methods, :program_warnings, keyword_init: true) do
      def by_qualified_name
        methods.to_h { |m| [m.qualified_name, m] }
      end
    end

    # ---------- Phase 1: program-wide warnings ----------
    #
    # Look at IR's program-wide @needs_* flags; emit advisory strings.
    # These do not fail the partition by themselves — methods are still
    # evaluated individually.
    PROGRAM_WARNING_FLAGS = {
      "@needs_fiber"   => "fiber usage detected program-wide",
      "@needs_bigint"  => "bignum literal/computation detected program-wide",
      "@needs_regexp"  => "regex usage detected program-wide",
      "@needs_lambda"  => "lambda/proc usage detected program-wide",
      "@needs_file_io" => "file I/O detected program-wide",
      "@needs_rand"    => "random detected program-wide",
    }.freeze

    module_function

    # ---------- BPF plugin namespace rule ----------
    # The single place that resolves a namespace member to its attach prefix /
    # event kind. Each returns the mapping for a known member, nil for a name
    # OUTSIDE the BPF:: namespace (caller proceeds as before), and raises
    # PartitionError for a name that IS in the namespace but is unknown.

    def bpf_namespace_names
      BPF_DSL_PARENT_TO_PREFIX.keys.map { |k| k.sub("_", "::") }.join(", ")
    end

    # Flattened class-parent form ("BPF_XDP"). `class Foo < BPF::Bar`.
    def dsl_prefix_for_parent!(parent)
      return BPF_DSL_PARENT_TO_PREFIX[parent] if BPF_DSL_PARENT_TO_PREFIX.key?(parent)
      return nil unless parent.start_with?("BPF_")

      raise PartitionError,
            "unknown BPF DSL base class `#{parent.sub('_', '::')}` " \
            "(valid: #{bpf_namespace_names})"
    end

    # Constant-path array form (%w[BPF TcpCC]). `include BPF::Bar`.
    # BPF::EventLoop is handled by the caller before this is reached.
    def dsl_prefix_for_include!(path)
      return BPF_DSL_INCLUDE_TO_PREFIX[path] if BPF_DSL_INCLUDE_TO_PREFIX.key?(path)
      return nil unless path.first == "BPF"

      raise PartitionError,
            "unknown BPF DSL module `#{path.join('::')}` " \
            "(valid: include BPF::EventLoop, #{bpf_namespace_names})"
    end

    # Reactor `on :kind`. Inside an EventLoop module every `on :sym` is a
    # handler, so an unknown kind is a hard error (was a silent drop).
    def event_loop_kind!(kind)
      info = BPF_EVENT_LOOP_KINDS[kind]
      return info if info

      raise PartitionError,
            "unknown reactor event kind `on :#{kind}` " \
            "(valid: #{BPF_EVENT_LOOP_KINDS.keys.map { |k| ":#{k}" }.join(', ')})"
    end

    def program_warnings(ir)
      PROGRAM_WARNING_FLAGS.filter_map do |ivar, msg|
        (ir.int(ivar) || 0) != 0 ? msg : nil
      end
    end

    # ---------- Method enumeration ----------

    # Yields MethodInfo objects (without filling :flags / :tag yet).
    def enumerate_methods(ir, ast)
      results = []

      # Top-level methods
      names_arr   = (ir.sa("@meth_names") || []).flat_map { |s| s.split(";", -1) }.reject(&:empty?)
      bodies_arr  = ir.ia("@meth_body_ids") || []
      names_arr.zip(bodies_arr).each do |name, bid|
        next if bid.nil? || bid < 0
        results << MethodInfo.new(
          scope: :top_level, class_name: nil, method_name: name,
          body_id: bid, flags: MethodFlags.default, tag: nil,
        )
      end

      # Class instance methods. @cls_meth_names uses "|" between classes,
      # ";" between methods of a class. @cls_meth_bodies same shape.
      # @cls_parents (same pipe layout) carries the flattened
      # superclass name. When a class extends one of the BPF DSL bases
      # (BPF::XDP / BPF::TcpCC / ...), each method inside is enumerated
      # as if it were `def <prefix>__<name>` at top-level so the existing
      # detect_attach / codegen pipeline picks it up unchanged.
      cls_names = ir.sa("@cls_names") || []
      cls_parents = ir.sa("@cls_parents") || []
      cls_meth_names_pipe = ir.sa("@cls_meth_names") || []
      cls_meth_bodies_pipe = ir.sa("@cls_meth_bodies") || []
      cls_names.each_with_index do |cname, ci|
        next if cname.empty?
        m_names_str  = cls_meth_names_pipe[ci]  || ""
        m_bodies_str = cls_meth_bodies_pipe[ci] || ""
        m_names  = m_names_str.split(";", -1).reject(&:empty?)
        m_bodies = m_bodies_str.split(";", -1).map { |s| s.empty? ? -1 : Integer(s) }
        parent = (cls_parents[ci] || "").strip
        dsl_prefix = dsl_prefix_for_parent!(parent)

        m_names.zip(m_bodies).each do |name, bid|
          next if bid.nil? || bid < 0
          if dsl_prefix
            results << MethodInfo.new(
              scope: :top_level, class_name: nil,
              method_name: "#{dsl_prefix}#{name}",
              body_id: bid, flags: MethodFlags.default, tag: nil,
              dsl_class_idx: ci, dsl_orig_name: name,
            )
          else
            results << MethodInfo.new(
              scope: :class, class_name: cname, method_name: name,
              body_id: bid, flags: MethodFlags.default, tag: nil,
            )
          end
        end
      end

      # Top-level `module Foo; include BPF::Bar; def ...; end; end`.
      # spinel does not surface module-defined methods in @cls_*, so we
      # walk the AST directly. Append results before the <main> scope so
      # ordering with class-derived methods is roughly source-order.
      results.concat(enumerate_module_methods(ast))

      # Implicit main scope: top-level statements rooted at AST root.
      root = ast.root_id
      if root && ast.type_of(root) == "ProgramNode"
        stmts_id = ast.attr(root, "statements", default: -1)
        if stmts_id >= 0
          results << MethodInfo.new(
            scope: :main, class_name: nil, method_name: "<main>",
            body_id: stmts_id, flags: MethodFlags.default, tag: nil,
          )
        end
      end

      results
    end

    # Walk the AST root for top-level `module Foo; include BPF::Bar;
    # def name(...); ...; end; end` blocks and synthesize MethodInfo
    # entries with `<prefix>__<name>` so the rest of the pipeline treats
    # them as flat-prefix top-level methods. spinel's IR doesn't expose
    # module bodies in @cls_*, so we have to read the AST directly.
    #
    # Recognised shape:
    #   ModuleNode
    #     constant_path -> ConstantReadNode("Foo")    (only single-segment names)
    #     body          -> StatementsNode
    #       body[*] (CallNode with name="include" or "extend",
    #               arguments -> ArgumentsNode with one ConstantPathNode
    #               matching BPF::<kind>)
    #       body[*] DefNode -> becomes a MethodInfo
    def enumerate_module_methods(ast)
      out = []
      root = ast.root_id
      return out unless root
      stmts_id = ast.attr(root, "statements", default: -1)
      return out if stmts_id < 0
      ast.array(stmts_id, "body", default: []).each do |sid|
        n = ast.node(sid)
        next unless n && n.type == "ModuleNode"
        body_id = n.refs.fetch("body", -1)
        next if body_id < 0
        prefix = nil
        event_loop = false
        defs   = []
        on_calls = []
        ast.array(body_id, "body", default: []).each do |bid|
          bn = ast.node(bid)
          next unless bn
          case bn.type
          when "CallNode"
            cname = bn.attrs.fetch("name", "")
            if cname == "include" || cname == "extend"
              args_id = bn.refs.fetch("arguments", -1)
              next if args_id < 0
              args = ast.array(args_id, "arguments", default: [])
              args.each do |aid|
                path = collect_dsl_module_path(ast, aid)
                next unless path
                # BPF::EventLoop marker — same module then expects
                # `on :kind do ... end` calls.
                if path == BPF_EVENT_LOOP_PATH
                  event_loop = true
                else
                  prefix ||= dsl_prefix_for_include!(path)
                end
              end
            elsif cname == "on"
              # Collect `on :kind do ... end` calls for later
              # processing once we know this module is an EventLoop.
              on_calls << bn
            end
          when "DefNode"
            defs << bn
          end
        end

        if event_loop
          reactor_react_counter = 0
          on_calls.each do |cn|
            args_id = cn.refs.fetch("arguments", -1)
            next if args_id < 0
            arg_ids = ast.array(args_id, "arguments", default: [])
            next if arg_ids.empty?
            sym = ast.node(arg_ids[0])
            next unless sym && sym.type == "SymbolNode"
            kind = sym.attrs.fetch("value", "")
            info = event_loop_kind!(kind)

            # Collect target arguments (StringNode) for arity 1/2
            # forms like `on :kprobe, "sys_open"` or
            # `on :tracepoint, "sched", "sched_switch"`.
            targets = []
            (1..info.arity).each do |i|
              tnode_id = arg_ids[i]
              next unless tnode_id
              tnode = ast.node(tnode_id)
              next unless tnode && tnode.type == "StringNode"
              tval = tnode.attrs.fetch("content", "")
              targets << tval unless tval.empty?
            end
            next if targets.length != info.arity

            # Reactor uprobe / uretprobe / usdt — split target string(s)
            # into binary path + func / provider + probe and synthesize a
            # generic method name (`uprobe__react0` etc.) whose attach metadata
            # is carried via MethodInfo's dsl_uprobe_* fields. glue.c reads
            # those at attach time so the SEC merely says "uprobe" / "usdt"
            # and libbpf doesn't have to parse paths out of program names.
            # Also parse a trailing `pid: N` KeywordHashNode for per-handler
            # PID restriction.
            dsl_uprobe_binary   = nil
            dsl_uprobe_func     = nil
            dsl_uprobe_retprobe = nil
            dsl_usdt_provider   = nil
            dsl_usdt_name       = nil
            dsl_attach_pid      = nil
            reactor_uprobe_kind = (kind == "uprobe" || kind == "uretprobe" || kind == "usdt")
            if reactor_uprobe_kind
              # Look for a trailing KeywordHashNode `pid: N` after the
              # positional target args. Optional; nil means system-wide.
              kw_id = arg_ids[info.arity + 1]
              dsl_attach_pid = parse_attach_pid(ast, kw_id) if kw_id
            end
            if reactor_uprobe_kind
              if kind == "usdt"
                dsl_uprobe_binary = targets[0]
                dsl_usdt_provider = targets[1]
                dsl_usdt_name     = targets[2]
              else
                # `bin/path:func` — split on the LAST `:` so paths with `:`
                # somewhere in the directory still work (rare but possible).
                spec = targets[0]
                idx  = spec.rindex(":")
                if idx.nil? || idx == 0 || idx == spec.length - 1
                  $stderr.puts "spinel-ebpf: warning: `on :#{kind}, #{spec.inspect}` " \
                               "doesn't match 'bin:func' form — skipping handler"
                  next
                end
                dsl_uprobe_binary   = spec[0...idx]
                dsl_uprobe_func     = spec[(idx + 1)..]
                dsl_uprobe_retprobe = (kind == "uretprobe")
              end
            end

            method_name = case info.arity
                          when 0 then info.prefix
                          when 1 then
                            if reactor_uprobe_kind
                              n = reactor_react_counter
                              reactor_react_counter += 1
                              "#{info.prefix}#{n}"
                            else
                              "#{info.prefix}#{targets[0]}"
                            end
                          when 2 then "#{info.prefix}#{targets[0]}#{info.joiner}#{targets[1]}"
                          when 3 then
                            # usdt — synthesize `usdt__react__<N>`, real
                            # provider/probe carried in MethodInfo.
                            n = reactor_react_counter
                            reactor_react_counter += 1
                            "#{info.prefix}#{n}"
                          end

            # For `on :timer`, look for a trailing `every: N.<unit>`
            # KeywordHashNode in the arguments list and resolve it to ns.
            interval_ns = nil
            if kind == "timer"
              kw = arg_ids[info.arity + 1] || arg_ids[1]
              interval_ns = parse_timer_interval_ns(ast, kw) if kw
              # Without a valid interval the timer block has no way to fire,
              # so skip silently and emit a warning to stderr.
              if interval_ns.nil?
                $stderr.puts "spinel-ebpf: warning: `on :timer` without `every: N.<unit>` — skipping handler"
                next
              end
            end

            # For `on :perf_event`, look for a trailing `hz: N`
            # KeywordHashNode. Optional; nil means glue.c falls back to
            # $SPNL_PERF_HZ (default 49).
            perf_hz = nil
            if kind == "perf_event"
              kw = arg_ids[info.arity + 1] || arg_ids[1]
              perf_hz = parse_perf_event_hz(ast, kw) if kw
            end

            block_id = cn.refs.fetch("block", -1)
            next if block_id < 0
            handler_body_id = ast.ref(block_id, "body", default: -1)
            next if handler_body_id < 0
            out << MethodInfo.new(
              scope: :top_level, class_name: nil,
              method_name: method_name,
              body_id: handler_body_id,
              flags: MethodFlags.default, tag: nil,
              # block_id is set as the AST hint so codegen's
              # method_return_type fallback returns "int"; params
              # (block parameters) are not supported in MVP and end up
              # as [] because BlockNode#parameters points to a
              # BlockParametersNode which has no `requireds`.
              dsl_ast_def_id: block_id, dsl_orig_name: "on_#{kind}",
              dsl_timer_interval_ns: interval_ns,
              dsl_uprobe_binary: dsl_uprobe_binary,
              dsl_uprobe_func: dsl_uprobe_func,
              dsl_uprobe_retprobe: dsl_uprobe_retprobe,
              dsl_usdt_provider: dsl_usdt_provider,
              dsl_usdt_name: dsl_usdt_name,
              dsl_attach_pid: dsl_attach_pid,
              dsl_perf_event_hz: perf_hz,
            )
          end
        elsif prefix
          defs.each do |dn|
            name = dn.attrs.fetch("name", "")
            next if name.empty?
            body_node_id = dn.refs.fetch("body", -1)
            next if body_node_id < 0
            out << MethodInfo.new(
              scope: :top_level, class_name: nil,
              method_name: "#{prefix}#{name}",
              body_id: body_node_id,
              flags: MethodFlags.default, tag: nil,
              dsl_ast_def_id: dn.id, dsl_orig_name: name,
            )
          end
        end
      end
      out
    end

    # Parse a `every: N.<unit>` keyword from the `on :timer` args.
    # `kw_id` should point at the KeywordHashNode containing the `every:`
    # assoc. Returns the interval in nanoseconds (Integer) or nil if the
    # shape doesn't match (missing key, non-literal interval, unknown unit).
    def parse_timer_interval_ns(ast, kw_id)
      kw = ast.node(kw_id)
      return nil unless kw && kw.type == "KeywordHashNode"
      elements = ast.array(kw_id, "elements", default: [])
      elements.each do |aid|
        an = ast.node(aid)
        next unless an && an.type == "AssocNode"
        key_id = ast.ref(aid, "key", default: -1)
        next if key_id < 0
        key_node = ast.node(key_id)
        next unless key_node && key_node.type == "SymbolNode"
        next unless key_node.attrs.fetch("value", "") == "every"

        val_id = ast.ref(aid, "value", default: -1)
        next if val_id < 0
        # Expect `N.<unit>` -> CallNode(name=<unit>, receiver=IntegerNode(N)).
        # Bare integers (`every: 5`) are treated as nanoseconds for forward
        # compatibility; CRuby's `5.seconds` style is recommended.
        val_node = ast.node(val_id)
        if val_node && val_node.type == "IntegerNode"
          return Integer(val_node.attrs.fetch("value", 0))
        end
        next unless val_node && val_node.type == "CallNode"
        unit_name = val_node.attrs.fetch("name", "")
        unit_ns = BPF_TIMER_UNIT_NS[unit_name]
        next unless unit_ns
        recv_id = val_node.refs.fetch("receiver", -1)
        next if recv_id < 0
        recv = ast.node(recv_id)
        next unless recv && recv.type == "IntegerNode"
        n = Integer(recv.attrs.fetch("value", 0))
        return n * unit_ns
      end
      nil
    end

    # Parse `hz: N` from a KeywordHashNode (the trailing kwarg of
    # `on :perf_event, hz: 99 do ... end`). Returns the Integer hz, or nil
    # if the shape doesn't match. Values <= 0 are coerced to nil (let
    # glue.c fall back to env / default).
    def parse_perf_event_hz(ast, kw_id)
      kw = ast.node(kw_id)
      return nil unless kw && kw.type == "KeywordHashNode"
      elements = ast.array(kw_id, "elements", default: [])
      elements.each do |aid|
        an = ast.node(aid)
        next unless an && an.type == "AssocNode"
        key_id = ast.ref(aid, "key", default: -1)
        next if key_id < 0
        key_node = ast.node(key_id)
        next unless key_node && key_node.type == "SymbolNode"
        next unless key_node.attrs.fetch("value", "") == "hz"

        val_id = ast.ref(aid, "value", default: -1)
        next if val_id < 0
        val_node = ast.node(val_id)
        next unless val_node && val_node.type == "IntegerNode"
        n = Integer(val_node.attrs.fetch("value", 0))
        return n > 0 ? n : nil
      end
      nil
    end

    # Parse `pid: N` from a KeywordHashNode (the trailing kwarg of a
    # reactor uprobe/USDT `on` call). Returns the Integer pid, or nil if
    # the shape doesn't match. Negative values map to nil (meaning
    # "system-wide" — equivalent to libbpf's pid=-1).
    def parse_attach_pid(ast, kw_id)
      kw = ast.node(kw_id)
      return nil unless kw && kw.type == "KeywordHashNode"
      elements = ast.array(kw_id, "elements", default: [])
      elements.each do |aid|
        an = ast.node(aid)
        next unless an && an.type == "AssocNode"
        key_id = ast.ref(aid, "key", default: -1)
        next if key_id < 0
        key_node = ast.node(key_id)
        next unless key_node && key_node.type == "SymbolNode"
        next unless key_node.attrs.fetch("value", "") == "pid"

        val_id = ast.ref(aid, "value", default: -1)
        next if val_id < 0
        val_node = ast.node(val_id)
        next unless val_node && val_node.type == "IntegerNode"
        n = Integer(val_node.attrs.fetch("value", 0))
        return n >= 0 ? n : nil
      end
      nil
    end

    # Walk a ConstantPathNode (or ConstantReadNode root) bottom-up and
    # return ["BPF", "TcpCC"] etc., or nil if the chain leaves the
    # constant-path shape (e.g. absolute `::Foo`).
    def collect_dsl_module_path(ast, nid)
      path = []
      cur = nid
      8.times do
        return nil if cur < 0
        n = ast.node(cur)
        return nil unless n
        case n.type
        when "ConstantPathNode"
          path.unshift(n.attrs.fetch("name", ""))
          cur = n.refs.fetch("parent", -1)
        when "ConstantReadNode"
          path.unshift(n.attrs.fetch("name", ""))
          return path
        else
          return nil
        end
      end
      nil
    end

    # ---------- Phase 2: per-method AST walk ----------

    # Method names on receivers that we treat as I/O / non-eBPF.
    IO_RECV_CLASSES = %w[File Socket TCPSocket UDPSocket IO STDIN STDOUT STDERR Dir Kernel].freeze
    IO_METHOD_NAMES = %w[
      puts print printf p pp gets readline readlines write
      open read readpartial syscall system exec spawn
    ].freeze
    DYNAMIC_STRING_OPS = %w[+ << concat * %].freeze
    DYNAMIC_ARRAY_OPS  = %w[push << unshift concat insert].freeze

    # Walk the subtree rooted at body_id; fill mi.flags.
    def analyze_method(mi, ast)
      visited = {}
      walk(mi.body_id, ast, mi.flags, visited)
      mi.flags
    end

    def walk(nid, ast, flags, visited)
      return if nid < 0
      return if visited[nid]
      visited[nid] = true

      node = ast.node(nid)
      return unless node

      case node.type
      when "DefNode", "ClassNode", "ModuleNode"
        # Definitions inside a body (e.g., main's body containing `def foo`)
        # have their own bodies that are analyzed as separate methods.
        # Don't recurse into them — would double-count flags.
        return
      when "FloatNode"
        flags.uses_float = true
      when "RegularExpressionNode", "InterpolatedRegularExpressionNode"
        flags.uses_regex = true
      when "MatchPredicateNode", "MatchRequiredNode", "MatchWriteNode", "MatchLastLineNode"
        flags.uses_regex = true
      when "LambdaNode"
        # A naked lambda definition — closure-capable until proven otherwise.
        flags.uses_closure = true
      when "BlockNode"
        # Blocks attached to enumerator-like calls (5.times {}) are bounded
        # iteration; treat as non-closure for now. A block with references
        # to outer locals will still register the call as closure-using
        # at a future refinement step (out of scope for Phase 2).
        # Walk children unconditionally.
      when "WhileNode", "UntilNode"
        # Statically bounded loops would need constant-folding the predicate;
        # for the prototype, treat any while/until as unbounded.
        flags.uses_unbounded_loop = true
      when "InterpolatedStringNode"
        flags.uses_dynamic_string_concat = true
      when "CallNode"
        name = ast.name_of(nid)
        recv = ast.receiver_of(nid)
        recv_type = recv >= 0 ? ast.type_of(recv) : nil
        recv_name = recv >= 0 ? ast.name_of(recv) : nil

        # callee tracking for Phase 3
        flags.calls << name if name && !name.empty?

        # `loop do ... end` is an unbounded Kernel#loop. Codegen has no
        # way to lower it (no static bound), so partition must keep methods
        # using it on the :native side. (`n.times { }` is the bounded form
        # and stays :ebpf via bpf_loop lowering.)
        if name == "loop" && recv < 0
          flags.uses_unbounded_loop = true
        end

        # `<Module>.sp_<...>` style call → likely an ffi_func into libc
        # or libspinel_rt. Those are userspace syscalls that BPF can't replay,
        # so treat as I/O. The naming convention `sp_*` is enforced by all
        # libspinel_rt-resident helpers (sp_net_*, sp_crypto_*, sp_bigint_*).
        if recv_type == "ConstantReadNode" && name && name.start_with?("sp_")
          flags.uses_io = true
        end

        # I/O detection
        if name && IO_METHOD_NAMES.include?(name) && (recv < 0 || recv_type == "SelfNode")
          # bare puts / print / gets at receiver-less site
          flags.uses_io = true
        end
        if recv_type == "ConstantReadNode" && recv_name && IO_RECV_CLASSES.include?(recv_name)
          flags.uses_io = true
        end
        if recv_name == "File" || recv_name == "IO"
          flags.uses_io = true
        end

        # Thread.new / Fiber.new
        if name == "new" && recv_type == "ConstantReadNode"
          flags.uses_thread = true if recv_name == "Thread"
          flags.uses_fiber  = true if recv_name == "Fiber"
        end

        # Dynamic string / array ops on inferred receivers.
        # We don't have type inference at this layer; approximate by
        # method-name + receiver-being-a-call.
        if DYNAMIC_STRING_OPS.include?(name) && string_like_receiver?(ast, recv)
          flags.uses_dynamic_string_concat = true
        end
        if DYNAMIC_ARRAY_OPS.include?(name) && array_like_receiver?(ast, recv)
          flags.uses_dynamic_array_grow = true
        end
      end

      # Walk children: only R (refs) and A (arrays) carry node IDs.
      # I (literal int) values must NOT be followed — e.g. IntegerNode#value=0
      # would otherwise be mistaken for a reference to node id 0 (the root).
      node.refs.each_value do |child|
        walk(child, ast, flags, visited) if child.is_a?(Integer) && child >= 0
      end
      node.arrays.each_value do |arr|
        arr.each { |c| walk(c, ast, flags, visited) if c.is_a?(Integer) && c >= 0 }
      end
    end

    # Heuristic: receiver is "string-like" if it's a string literal, an
    # interpolated string, or another `+` on strings. We are conservative:
    # any unknown receiver is *not* string-like (so we under-detect rather
    # than over-mark eBPF-impossible).
    def string_like_receiver?(ast, recv)
      return false if recv < 0
      t = ast.type_of(recv)
      ["StringNode", "InterpolatedStringNode"].include?(t)
    end

    # Heuristic: receiver is "array-like" if it's an array literal or a
    # `LocalVariableReadNode` we can't resolve. Conservative on the same
    # principle.
    def array_like_receiver?(ast, recv)
      return false if recv < 0
      ast.type_of(recv) == "ArrayNode"
    end

    # ---------- Phase 3: fix-point + tag decision ----------

    # Build a map from method name → MethodInfo for callee resolution.
    # Note: this loses class scope (Foo#bar and Baz#bar collide). For
    # MVP we accept the over-approximation: any callee with matching
    # bare name is considered.
    def build_name_index(methods)
      idx = Hash.new { |h, k| h[k] = [] }
      methods.each { |m| idx[m.method_name] << m }
      idx
    end

    def fixpoint_propagate(methods)
      idx = build_name_index(methods)
      changed = true
      while changed
        changed = false
        methods.each do |m|
          m.flags.calls.each do |callee_name|
            (idx[callee_name] || []).each do |callee_mi|
              # self-recursion (including via name collision)
              if callee_mi.equal?(m)
                if !m.flags.uses_recursion
                  m.flags.uses_recursion = true
                  changed = true
                end
              elsif callee_mi.flags.ebpf_impossible?
                if !m.flags.inherits_unsupported
                  m.flags.inherits_unsupported = true
                  changed = true
                end
              end
            end
          end
        end
      end
    end

    def decide_tag!(mi, force_native = nil)
      # <main> is the program's entry point. spinel produces it as the C
      # main(); spinel-ebpf keeps it native so the host can orchestrate
      # calls into the :ebpf methods (cannot offload main itself).
      return mi.tag = :native if mi.scope == :main
      # Synthesized userspace consumer / driver / named-handler methods
      # (the `on_emit` / `on_emit :name` DSL lowered by SpinelEbpf::Consumer) are
      # always native — they run in userspace draining the emit ringbuf, even
      # though the body may look eBPF-eligible (int + top-level ivar).
      return mi.tag = :native if mi.method_name.start_with?("__spnl_")
      # --instrument --instrument-self combines the workload + the agent in
      # one ebpf-mixed unit. The workload methods (the uprobe *targets*) are
      # eBPF-eligible (pure int) but MUST stay native — they run as the workload
      # and the self-uprobe attaches to their sp_<name> symbols. Force them native.
      return mi.tag = :native if force_native && force_native.include?(mi.method_name)
      mi.tag = mi.flags.ebpf_impossible? ? :native : :ebpf
    end

    # ---------- Top-level entry ----------

    def classify(ir, ast, force_native: nil)
      methods = enumerate_methods(ir, ast)
      methods.each do |mi|
        analyze_method(mi, ast)
        # Even when the body has no FloatNode literal, spinel's signature
        # inference can tell us a param or return is float. Mark uses_float
        # accordingly so partition sees indirect float usage.
        refine_flags_from_signature(mi, ir)
      end
      fixpoint_propagate(methods)
      methods.each { |mi| decide_tag!(mi, force_native) }
      synthesize_kernel_cache_slice!(methods, ast)
      Result.new(methods: methods, program_warnings: program_warnings(ir))
    end

    # `kernel_cache "/path","body"` declarations serve those responses
    # from the kernel (pure-XDP TCP slice) — no hand-written eBPF. Append a
    # body-less :ebpf MethodInfo so codegen emits the slice wrapper + bundle
    # (which read the declarations for the match string / response). Appended
    # after tag decisions so it isn't re-analyzed; absent any declaration this
    # is a no-op (existing programs unaffected).
    def synthesize_kernel_cache_slice!(methods, ast)
      return if ast.nil?
      return if KernelCache.declarations(ast).empty?
      return if methods.any? { |m| m.method_name == "xdp__tcp_slice__kernel_cache" }
      methods << MethodInfo.new(
        scope: :top_level, class_name: nil,
        method_name: "xdp__tcp_slice__kernel_cache",
        body_id: -1, flags: MethodFlags.default, tag: :ebpf,
      )
    end

    # Pull per-method signature (param types + return type) from IR and
    # toggle ebpf-impossible flags for any non-int type. Also flag
    # string / array / hash / poly etc. as unsupported_type — codegen_bpf
    # can't lower these as BPF parameters, so partition must keep such
    # methods :native instead of letting codegen blow up.
    SUPPORTED_EBPF_SIGNATURE_TYPES = %w[int bool void nil].freeze

    def refine_flags_from_signature(mi, ir)
      types = signature_types(mi, ir)
      # signature_types appends the return type as the last element; everything
      # before it is a parameter type.
      last = types.length - 1
      types.each_with_index do |t, i|
        # Nullability (`int?`, `float?`, `string?`, ...) is orthogonal
        # to eBPF type-eligibility — spinel widens a type to nullable for any
        # value that can be nil, and crucially infers `int?` for any method
        # whose body is `if … end` without an explicit `else` (the implicit
        # nil branch). That is the single most common attach-handler shape
        # (`if cond; spnl_emit(x); end`), and the nullable int still lowers to
        # __s64 (nil -> 0). Judge by the base type so `int?` stays eligible,
        # `string?` stays rejected, and `float?` is still attributed to float.
        base = t.end_with?("?") ? t[0..-2] : t
        # The C compiler's analyzer types empty-body / builtin-stub
        # methods' RETURN as `poly` where the legacy Ruby analyzer said `nil`
        # (e.g. `def spnl_emit(x); end`), and callers inherit it. A `poly`
        # RETURN is discarded for attach handlers and lowers to void otherwise,
        # so it must not disqualify (a poly *param* still does — codegen can't
        # lower an object parameter). No-op for the legacy path, which never
        # emits a poly return.
        next if i == last && base == "poly"
        case base
        when "float"  then mi.flags.uses_float = true
        when "bignum" then mi.flags.uses_bignum = true
        when "", *SUPPORTED_EBPF_SIGNATURE_TYPES
          # empty (no info) and known-safe types are fine
        else
          # string, str_array, int_array, hash, poly, lambda, fiber, proc, ...
          mi.flags.uses_unsupported_type = true
        end
      end
    end

    def signature_types(mi, ir)
      case mi.scope
      when :top_level
        # ir.sa() already splits the IR's "|"-separated payload AND pads with
        # empties via split_strs_n. Re-applying flat_map(split("|", -1)) drops
        # empty entries because Ruby's "".split("|", -1) == [] in some versions,
        # which silently misaligns idx → wrong types per method.
        names = ir.sa("@meth_names") || []
        idx = names.index(mi.method_name)
        return [] unless idx
        ptypes = (ir.sa("@meth_param_types")  || [])[idx] || ""
        rtype  = (ir.sa("@meth_return_types") || [])[idx] || ""
        ptypes.split(",", -1) + [rtype]
      when :class
        cls_names = ir.sa("@cls_names") || []
        ci = cls_names.index(mi.class_name)
        return [] unless ci
        m_names = ((ir.sa("@cls_meth_names")   || [])[ci] || "").split(";", -1)
        m_ptypes = ((ir.sa("@cls_meth_ptypes") || [])[ci] || "").split("|", -1)
        m_rtypes = ((ir.sa("@cls_meth_returns")|| [])[ci] || "").split(";", -1)
        m_idx = m_names.index(mi.method_name)
        return [] unless m_idx
        ptypes = m_ptypes[m_idx] || ""
        rtype  = m_rtypes[m_idx] || ""
        ptypes.split(",", -1) + [rtype]
      else
        []
      end
    end

    # Convenience: read .ir + .ast from disk.
    def classify_files(ir_path, ast_path)
      ir = ParseSpinelIR.parse_file(ir_path)
      ast = ParseSpinelAst.parse_file(ast_path)
      classify(ir, ast)
    end
  end
end
