# frozen_string_literal: true
#
# Partition algorithm — Phase 2 (per-method walk + flags) and Phase 3
# (call-graph fix-point + tag decision).
#

# Consumes the parsed IR and AST.

require_relative "parse_spinel_ir"
require_relative "parse_spinel_ast"
require_relative "capabilities"   # the attach-word vocabulary (no cycle: capabilities requires nothing)
require_relative "target_profile"

module SpinelEbpf
  module Partition
    # raised when a construct *names* the BPF plugin namespace
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

    # same lookup but keyed on the constant-path array form
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

    # A description per `on :kind`. `arity` is the number of
    # extra **string** arguments expected after the symbol; the synthesized
    # method name is `<prefix>` for arity 0 (already includes "main") or
    # `<prefix><target>` / `<prefix><target1>__<target2>` for arity 1/2.
    #
    # The four arity-0 kinds came first; the per-target attach
    # kinds (kprobe/kretprobe/fentry/fexit/tracepoint) which need a target
    # function or tracepoint name encoded into the SEC().
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
      # the reactor form of the userspace probes. Target binary path
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
      # Go return-probe. uretprobe is unusable on Go (movable stack
      # corrupts the return-address trampoline), so the handler is a plain
      # SEC("uprobe") (shares the "uprobe" prefix/codegen) that glue.c attaches
      # at every RET instruction offset of the function (found by scanning the
      # target ELF for the arm64 `ret` = 0xd65f03c0). At a RET, PARM1 (=R0) is
      # the function's return value.
      "go_uret"    => EventLoopKind.new(prefix: "uprobe__react",    arity: 1),
      "usdt"       => EventLoopKind.new(prefix: "usdt__react__",    arity: 3),
      # perf_event sampling. `on :perf_event, hz: 99 do … end`. arity 0
      # for the symbol args; frequency is parsed from a trailing
      # KeywordHashNode (hz:) and stashed in MethodInfo.dsl_perf_event_hz.
      "perf_event" => EventLoopKind.new(prefix: "perf_event__main", arity: 0),
    }.freeze

    # parse `every: N.<unit>` keyword in `on :timer, every: 5.seconds do…`.
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

    # Backward-compatible alias: older tests read this map directly. Holds
    # only the arity-0 attach kinds whose prefix is `<attach_prefix>main`
    # AND whose bare prefix is one of the BPF_DSL_PARENT_TO_PREFIX values
    # (so xdp / sock_ops / tc_*). user_cmd has its own unique
    # method name (`user_ringbuf__cmd_handler`) and the timer is also
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

      # Eligibility is target-relative. A profile names which flags are fatal
      # and (for restricted targets like AMP v0) which identifier calls exist
      # at all. The historical ebpf_impossible?/reasons pair delegates to the
      # linux-ebpf profile, so every existing caller and printed string is
      # unchanged.
      def impossible_for?(profile)
        profile.fatal_flags.any? { |f| self[f] } ||
          !unsupported_calls_for(profile).empty?
      end

      # Identifier-shaped calls the target's codegen cannot lower ([] when the
      # profile has a full builtin surface).
      def unsupported_calls_for(profile)
        return [] if profile.call_allowlist.nil?
        calls.select { |c| profile.identifier_call?(c) && !profile.allows_call?(c) }.uniq
      end

      def ebpf_impossible?
        impossible_for?(TargetProfile::LINUX_EBPF)
      end

      def reasons_for(profile)
        r = []
        TargetProfile::FLAG_REASONS.each do |flag, text|
          r << text if profile.fatal_flags.include?(flag) && self[flag]
        end
        bad = unsupported_calls_for(profile)
        unless bad.empty?
          r << "calls #{bad.map { |c| "'#{c}'" }.join(", ")} — not available on the #{profile.name} target" \
               " (supported: #{profile.supported_summary})"
        end
        r
      end

      def reasons
        reasons_for(TargetProfile::LINUX_EBPF)
      end
    end

    # The unit of partition decision.
    MethodInfo = Struct.new(
      :scope,           # :top_level | :class | :main
      :class_name,      # String or nil
      :method_name,     # String (or "<main>" for main)
      :body_id,         # Integer (AST node id)
      # The IR's OWN body node id for the same method. Not the same number as
      # :body_id -- the two numbering spaces have been measured drifting by 1216
      # -- and the difference matters here, because the IR's per-body scope
      # records (SN/ST) are keyed by the IR id. nil when the method has no IR row
      # (a synthesised DSL / reactor handler), in which case there is nothing to
      # look up.
      :ir_body_id,      # Integer (IR node id) or nil
      :flags,           # MethodFlags
      :tag,             # :ebpf | :native | :error  (filled in Phase 3)
      # when a method came from a `class Foo < BPF::Bar` block we
      # synthesize a top-level entry with method_name = "<prefix>__<orig>".
      # These hints let method_params look up the original spinel
      # @cls_meth_params slot (params live in the class table, not the
      # top-level table) without touching the rest of the pipeline.
      :dsl_class_idx,   # Integer index into @cls_names, or nil
      :dsl_orig_name,   # Original (unprefixed) method name, or nil
      # same idea for `module Foo; include BPF::Bar; end`. spinel's
      # IR doesn't track module-defined methods (@cls_* arrays are empty
      # for them), so we point straight at the DefNode in the AST and
      # codegen falls back to AST-driven param extraction.
      :dsl_ast_def_id,  # Integer AST node id of the DefNode, or nil
      # bpf_timer interval in nanoseconds. Set for `on :timer, every:
      # N.seconds do ... end` blocks; the codegen reads it to emit the
      # timer arm prog with the right interval and to bake the re-arm
      # constant into the callback. nil for non-timer methods.
      :dsl_timer_interval_ns,
      # reactor-form uprobe/USDT target info. For uprobe / uretprobe
      # the binary + func come from a single colon-separated string arg
      # (`"/usr/bin/bash:readline"`); for USDT three string args
      # (binary, provider, probe). glue.c reads these from a per-prog
      # target table to call bpf_program__attach_uprobe / _usdt with the
      # right parameters.
      :dsl_uprobe_binary,   # String — binary path for any reactor uprobe/USDT
      :dsl_uprobe_func,     # String — function name for uprobe/uretprobe
      :dsl_uprobe_retprobe, # Boolean — true for uretprobe
      :dsl_uprobe_go_ret,   # Boolean -- true for go_uret (attach at every RET offset)
      :dsl_usdt_provider,   # String — for usdt
      :dsl_usdt_name,       # String — for usdt
      # per-handler PID for reactor uprobe/USDT (`on :uprobe, "...",
      # pid: 12345`). nil = system-wide (libbpf attach with pid=-1). Falls
      # through to env $SPNL_*_PID if also unset there.
      :dsl_attach_pid,
      # sampling frequency (Hz) for `on :perf_event, hz: 99 do ... end`.
      # nil for flat-form (def perf_event__<name>) — glue.c uses $SPNL_PERF_HZ
      # (default 49). Integer for reactor form.
      :dsl_perf_event_hz,
      # Array[String] for the multi-symbol form `on :kprobe, %w[a b c]`; nil for
      # every 1-to-1 form.
      :dsl_multi_syms,
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
    Result = Struct.new(:methods, :program_warnings, :target, keyword_init: true) do
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

      handler_not_realised!(
        "unknown reactor event kind `on :#{kind}`.",
        "inside `include BPF::EventLoop` every `on :sym` IS a handler, so a kind this table does " \
        "not know names an event that will never be hooked. There is no fallback: the 16 kinds " \
        "below are the definition of the reactor surface.",
        "use one of #{BPF_EVENT_LOOP_KINDS.keys.map { |k| ":#{k}" }.join(', ')}, or write the flat " \
        "form `def <prefix>__<target>` if you need an attach kind the reactor does not spell " \
        "(`spinel-ebpf capabilities` lists all of them).",
      )
    end

    # ---------- a declared handler that cannot be realised ----------
    #
    # THE FAILURE THIS REPLACES. When the partition could not turn something the
    # author wrote into a handler it used to do one of three different things,
    # and two of them reported success. Measured over the shapes that reach this
    # code: 13 of them, 12 exited 0, and 10 of those printed no diagnostic at
    # all.
    #
    #   on :no_such_kind do … end   PartitionError, raw Ruby backtrace     exit 1
    #   on :timer do … end          "warning: … — skipping handler"        exit 0
    #   on :xdp                     nothing whatsoever                     exit 0
    #
    # The third is the pure form: the author declares an XDP handler and gets a
    # program with no XDP handler and zero diagnostics. It is the same shape an
    # earlier audit found for `:timer` ("the body never appears in the output")
    # except that this one is not a porting oversight — it is a `next` somebody
    # wrote on purpose, which is why closing it needed a verdict per site rather
    # than a patch.
    #
    # WHY REFUSE RATHER THAN WARN. The in-kernel common filter chose "refuse the
    # whole declaration" over partial application because warnings are not read,
    # and this tree has the receipts: the retired `kernel_cache` directive
    # returned -2 into a value the shipped demo discarded, and the negative
    # fixture `163_timer_no_interval` — whose own header says it "must not
    # compile" — warned and exited 0 for as long as it had existed.
    #
    # WHY HERE AND NOT IN validate.rb. By the time Validate runs, the dropped
    # handler is gone from Result#methods; there is nothing left to check. The
    # partition is the last layer that still knows the author wrote `on :xdp` —
    # the same argument that put the `kernel_cache` refusal in the pass that can
    # still see the word.
    #
    # The message shape is this project's: what / why / how to fix.
    def handler_not_realised!(what, why, fix)
      raise PartitionError, "#{what}\n  Why: #{why}\n  Fix: #{fix}"
    end

    # Does this method name declare a kernel attach point?
    #
    # Derived from the affordance (Capabilities::ATTACH_KINDS) rather than from
    # CodegenBpf::ATTACH_PATTERNS, for two reasons: codegen_bpf.rb requires
    # partition.rb (a `require_relative` back would be a cycle), and the
    # affordance is the authority for what attach kinds exist. Same derivation
    # Validate::ATTACH_WORDS uses.
    #
    # Deliberately NOT the withdrawn kinds: those are refused by name in the C
    # codegen with their own message, which is more specific than anything this
    # could say.
    #
    # DELIBERATELY BROADER than CodegenBpf.detect_attach, in the safe direction.
    # Six of the 25 words name two-segment kinds (`tracepoint__<cat>__<event>`,
    # `tc__ingress__<name>`, …), so `tracepoint__probe` passes here and fails
    # there. That over-approximation only decides whether a BODY-LESS def is
    # refused or dropped, and refusing a malformed attach name is better than
    # losing it: a well-formed one is a real handler, and a malformed one is a
    # mistake either way. It must never go the other way — a word this misses is
    # a handler that can still vanish — which is why the direction is pinned by
    # a test rather than left to the reader.
    ATTACH_DECL_WORDS = Capabilities::ATTACH_KINDS
                        .filter_map { |a| a[:method_prefix][/\A([a-z0-9_]+?)__/, 1] }
                        .uniq
                        .sort_by { |w| -w.length }
                        .freeze

    def attach_decl?(name)
      return false if name.nil? || name.empty?
      ATTACH_DECL_WORDS.any? { |w| name.start_with?("#{w}__") && name.length > w.length + 2 }
    end

    # The `do … end` block of an `on` call, or a refusal.
    # The two conditions are adjacent at every reactor site (the block may be
    # absent, or present and empty), and they are the same mistake to the
    # author: a declared handler with no body.
    def reactor_block_body!(ast, call_node, spelling, where)
      block_id = call_node.refs.fetch("block", -1)
      if block_id < 0
        handler_not_realised!(
          "`#{spelling}` in #{where} declares a handler with no `do … end` block.",
          "the block IS the handler body. Without one there is nothing to compile, so this " \
          "declaration used to be dropped and the build exited 0 having emitted no program for it " \
          "at all — the author asks for a hook and gets a binary that hooks nothing.",
          "give it a body: `#{spelling} do … end`, or delete the line.",
        )
      end
      body_id = ast.ref(block_id, "body", default: -1)
      if body_id < 0
        handler_not_realised!(
          "`#{spelling}` in #{where} declares a handler whose block is empty.",
          "an empty block has no body to lower, so no program is emitted and nothing is attached. " \
          "That is not the same as a handler that does nothing: a program that exists attaches, is " \
          "visible to `bpftool prog show`, and (for XDP) holds the interface; one that was never " \
          "emitted does none of that, silently.",
          "put at least one statement in the block, or delete the declaration until you need it.",
        )
      end
      [block_id, body_id]
    end

    def program_warnings(ir)
      PROGRAM_WARNING_FLAGS.filter_map do |ivar, msg|
        (ir.int(ivar) || 0) != 0 ? msg : nil
      end
    end

    # ---------- AST body resolution ----------
    #
    # The .ir and the .ast come from two DIFFERENT spinel invocations —
    # `spinel --dump-ast` (upstream binary) and the in-process
    # `spinel-ebpf-cc --ir` (bin/spinel-ebpf#run_spinel_to_ir). A plain
    # `require` resolves relative to the RUNNING EXECUTABLE (/proc/self/exe;
    # spinel_parse.c#resolve_plain_requires), so the two parses can be handed
    # different source text and therefore number their nodes differently.
    #
    # Measured on examples/http_server/so-reuseport/server.rb: the word "Set"
    # inside a *comment* trips spinel's implicit `require "set"` splice, which
    # only the upstream binary can resolve (its `packages/set/set.rb` sits beside
    # its own bin/). 1216 nodes exist in the .ast that the .ir never saw, so
    # every user node in the .ast sits 1216 higher than the id the IR reports.
    #
    # An IR body id is therefore an id in the IR's OWN parse, not a node id in
    # the .ast. Each artifact stays authoritative for what it actually
    # describes: the IR for which methods exist and what their types are, the
    # AST for where the body is. So the body is resolved out of the AST, by
    # name within scope, and the IR's id is used only as "this method exists".
    #
    # Rejected alternatives: translating by an offset — the offset is only
    # constant because `set` splices at the very front; a plain require inside a
    # required file splices mid-tree and the offset goes piecewise — and
    # renumbering the .ast — there is no fixed "prelude" to strip, and every
    # other AST consumer (dsl_ast_def_id, consumer.rb, kernel_cache,
    # param/filter_by) is already correct in .ast space.

    # `bodyless` records the defs the other two tables cannot: scope (nil for
    # top level) -> Set of names whose DefNode has no body at all. A missing
    # entry in `top_level`/`scoped` is ambiguous — it means EITHER "the author
    # wrote `def x; end`" OR "the IR names a method this AST never saw" (the
    # require-splice case above, where dropping is correct). Only the first is a
    # declaration that failed to be realised, so the two are told apart here
    # rather than guessed at the drop site.
    AstDefIndex = Struct.new(:top_level, :scoped, :bodyless, keyword_init: true) do
      def bodyless?(scope, name)
        (bodyless[scope] || []).include?(name)
      end
    end

    # name -> [body node id, ...] for top-level defs, and
    # class-or-module name -> name -> [body node id, ...] for the rest.
    # Ids come out in ascending order (spinel's flatten numbers pre-order, so a
    # later sibling gets a higher id), which is what makes `.last` mean "the
    # definition Ruby would keep" for a redefinition.
    def build_ast_def_index(ast)
      top      = Hash.new { |h, k| h[k] = [] }
      scoped   = Hash.new { |h, k| h[k] = Hash.new { |g, m| g[m] = [] } }
      bodyless = Hash.new { |h, k| h[k] = [] }
      idx = AstDefIndex.new(top_level: top, scoped: scoped, bodyless: bodyless)
      return idx unless ast && ast.nodes

      parent = {}
      ast.nodes.each do |id, n|
        n.refs.each_value { |c| parent[c] = id if c.is_a?(Integer) && c >= 0 }
        n.arrays.each_value do |arr|
          arr.each { |c| parent[c] = id if c.is_a?(Integer) && c >= 0 }
        end
      end

      ast.nodes.keys.sort.each do |id|
        n = ast.nodes[id]
        next unless n.type == "DefNode"
        name = n.attrs.fetch("name", "")
        next if name.empty?
        body = n.refs.fetch("body", -1)
        scope = enclosing_scope_name(ast, parent, id)
        if body < 0
          bodyless[scope] << name   # "written, but with no body"
          next
        end
        (scope ? scoped[scope] : top)[name] << body
      end
      idx
    end

    # Nearest enclosing ClassNode/ModuleNode name, or nil for a top-level def.
    # A def nested inside another def is reported as nil-scope too: spinel's
    # method tables cannot name it, so it will simply never be looked up.
    def enclosing_scope_name(ast, parent, id)
      cur = parent[id]
      512.times do
        break unless cur
        n = ast.node(cur)
        break unless n
        case n.type
        when "ClassNode", "ModuleNode"
          cp = n.refs.fetch("constant_path", -1)
          nm = ast.str_attr(cp, "name", default: "")
          return nm.empty? ? nil : nm
        when "DefNode"
          return nil
        end
        cur = parent[cur]
      end
      nil
    end

    # Resolve one method's body. `scope_name` nil = top level. Returns nil when
    # the AST has no such definition — the caller decides what that means.
    def resolve_ast_body_id(idx, scope_name, method_name)
      bucket = scope_name ? idx.scoped[scope_name] : idx.top_level
      cands = bucket[method_name]
      cands.empty? ? nil : cands.last
    end

    # ---------- Method enumeration ----------

    # Yields MethodInfo objects (without filling :flags / :tag yet).
    def enumerate_methods(ir, ast)
      results = []
      ast_defs = build_ast_def_index(ast)

      # Top-level methods
      names_arr   = (ir.sa("@meth_names") || []).flat_map { |s| s.split(";", -1) }.reject(&:empty?)
      bodies_arr  = ir.ia("@meth_body_ids") || []
      names_arr.zip(bodies_arr).each do |name, bid|
        # `def xdp__main; end` — an attach handler with an empty body. Measured
        # exit 0, no diagnostic, no XDP program. spinel reports body_id -1 for a
        # body-less def, so this is the drop, one guard EARLIER than the AST
        # lookup below.
        #
        # Two conditions keep this off the rest of the corpus. `attach_decl?`:
        # only an attach name is a declaration that the program hooks something
        # — a body-less plain `def spnl_emit(x); end` is the builtin-stub shape
        # the corpus relies on and must keep being skipped. `bodyless?`: the
        # author actually wrote a body-less def in THIS file, as opposed to the
        # IR naming a method this AST never saw (the require-splice case above,
        # where dropping is correct).
        if (bid.nil? || bid < 0) && attach_decl?(name) && ast_defs.bodyless?(nil, name)
          handler_not_realised!(
            "`def #{name}` has an empty body.",
            "the name is spelled as a kernel attach point, and an attach handler has no native " \
            "execution path — an empty body means no program is emitted, so nothing is attached " \
            "and the hook never exists. That used to compile and exit 0 with no diagnostic.",
            "put at least one statement in `#{name}` (`spinel-ebpf capabilities` lists what the " \
            "eBPF subset allows), or delete the declaration until you need it.",
          )
        end
        next if bid.nil? || bid < 0
        # The IR says the method exists; the AST says where its body is.
        body = resolve_ast_body_id(ast_defs, nil, name)
        next if body.nil?
        results << MethodInfo.new(
          scope: :top_level, class_name: nil, method_name: name,
          body_id: body, ir_body_id: bid, flags: MethodFlags.default, tag: nil,
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
          # `class C < BPF::XDP; def main; end; end`. A DSL parent binds EVERY
          # method of the class to an attach kind, so an empty body is the same
          # silent loss as the top-level case above — and it lands on the same
          # earlier guard, because spinel reports -1 in @cls_meth_bodies too.
          # Plain classes are untouched: an empty method there is just an empty
          # method, with a native execution path like any other.
          if (bid.nil? || bid < 0) && dsl_prefix && ast_defs.bodyless?(cname, name)
            handler_not_realised!(
              "`def #{name}` in class `#{cname}` (< BPF::…) has an empty body.",
              "the DSL base class binds every method of `#{cname}` to an attach kind — this one " \
              "becomes `#{dsl_prefix}#{name}`. An empty body has nothing to lower, so no program " \
              "is emitted and nothing is attached, with no diagnostic at all.",
              "put at least one statement in `#{name}`, or delete it until you need it.",
            )
          end
          next if bid.nil? || bid < 0
          # Same split of authority as the top-level table above. The scope key
          # is the class-or-module's simple name, which is what @cls_names
          # carries (spinel surfaces module methods here too).
          body = resolve_ast_body_id(ast_defs, cname, name)
          next if body.nil?
          ir_bid = bid   # keep the IR's id before the AST id shadows it
          bid = body
          if dsl_prefix
            results << MethodInfo.new(
              scope: :top_level, class_name: nil,
              method_name: "#{dsl_prefix}#{name}",
              body_id: bid, ir_body_id: ir_bid, flags: MethodFlags.default, tag: nil,
              dsl_class_idx: ci, dsl_orig_name: name,
            )
          else
            results << MethodInfo.new(
              scope: :class, class_name: cname, method_name: name,
              body_id: bid, ir_body_id: ir_bid, flags: MethodFlags.default, tag: nil,
            )
          end
        end
      end

      # top-level `module Foo; include BPF::Bar; def ...; end; end`.
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

    # walk the AST root for top-level `module Foo; include BPF::Bar;
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
        # An empty `module Foo; end` declares nothing, so there is nothing that
        # could fail to be realised — not a drop site.
        next if body_id < 0
        mod_name = ast.str_attr(n.refs.fetch("constant_path", -1), "name", default: "")
        mod_where = mod_name.empty? ? "this module" : "module `#{mod_name}`"
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
              # collect `on :kind do ... end` calls for later
              # processing once we know this module is an EventLoop.
              on_calls << bn
            end
          when "DefNode"
            defs << bn
          end
        end

        if event_loop
          reactor_react_counter = 0
          reactor_multi_counter = 0   # `on :kprobe, %w[...]` sets
          on_calls.each do |cn|
            args_id = cn.refs.fetch("arguments", -1)
            arg_ids = args_id < 0 ? [] : ast.array(args_id, "arguments", default: [])
            sym = arg_ids.empty? ? nil : ast.node(arg_ids[0])
            # `on do … end`, `on()` and `on "xdp" do … end` all arrive here with
            # no leading SymbolNode. All three used to be dropped without a word.
            unless sym && sym.type == "SymbolNode"
              got = sym ? sym.type : "no arguments"
              handler_not_realised!(
                "`on` in #{mod_where} does not name an event kind (got #{got}).",
                "the first argument of a reactor `on` selects the kernel event to hook, and it has " \
                "to be a symbol literal so the partition can resolve it at compile time. Anything " \
                "else names nothing, and the handler used to be dropped silently.",
                "write the kind as a symbol: `on :xdp do … end` " \
                "(valid: #{BPF_EVENT_LOOP_KINDS.keys.map { |k| ":#{k}" }.join(', ')}).",
              )
            end
            kind = sym.attrs.fetch("value", "")

            # `on :kprobe, %w[a b c]` -- one body, many symbols. The list sits
            # where the 1-to-1 form puts a single string, so the shape is decided
            # before the target collection below.
            #
            # WHICH LOWERING (expand into N programs vs one kprobe_multi link) IS
            # NOT DECIDED HERE. It is decided once, in the C codegen, and read back
            # out of the emitted .bpf.c by build_binary -- a threshold that lived in
            # two languages would be a threshold that drifts. Partition only has to
            # know that this handler exists and is eBPF-eligible.
            if (multi_syms = multi_symbol_list(ast, arg_ids))
              n = reactor_multi_counter
              reactor_multi_counter += 1
              # The multi-symbol form drops on the same two conditions as the
              # 1-to-1 form below, so it refuses the same way.
              block_id, handler_body_id =
                reactor_block_body!(ast, cn, "on :#{kind}, %w[#{multi_syms.first(2).join(' ')}#{multi_syms.length > 2 ? ' …' : ''}]", mod_where)
              out << MethodInfo.new(
                scope: :top_level, class_name: nil,
                method_name: "kprobe_multi__set#{n}",
                body_id: handler_body_id,
                flags: MethodFlags.default, tag: nil,
                dsl_ast_def_id: block_id, dsl_orig_name: "on_#{kind}",
                dsl_multi_syms: multi_syms,
              )
              next
            end

            info = event_loop_kind!(kind)

            # collect target arguments (StringNode) for arity 1/2
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
            # `on :kprobe do … end` with no function name. The target is what
            # the SEC() is built from, so without it there is no event to attach
            # to — and this used to be dropped without a word.
            if targets.length != info.arity
              slots = Array.new(info.arity) { '"…"' }.join(", ")
              plural = info.arity == 1 ? "argument" : "arguments"
              handler_not_realised!(
                "`on :#{kind}` in #{mod_where} needs #{info.arity} target #{plural}, got #{targets.length}.",
                "the target names the kernel object to hook and is baked into the SEC() at compile " \
                "time (`#{info.prefix}` + target). With the wrong number of string literals there is " \
                "no event to attach to, and the handler used to be dropped silently.",
                "supply the target(s) as string literals: `on :#{kind}, #{slots} do … end`.",
              )
            end

            # reactor uprobe / uretprobe / usdt — split target string(s)
            # into binary path + func / provider + probe and synthesize a
            # generic method name (`uprobe__react0` etc.) whose attach metadata
            # is carried via MethodInfo's dsl_uprobe_* fields. glue.c reads
            # those at attach time so the SEC merely says "uprobe" / "usdt"
            # and libbpf doesn't have to parse paths out of program names.
            # also parse trailing `pid: N` KeywordHashNode for per-handler
            # PID restriction.
            dsl_uprobe_binary   = nil
            dsl_uprobe_func     = nil
            dsl_uprobe_retprobe = nil
            dsl_uprobe_go_ret   = nil   # attach at every RET offset (Go return-probe)
            dsl_usdt_provider   = nil
            dsl_usdt_name       = nil
            dsl_attach_pid      = nil
            reactor_uprobe_kind = (kind == "uprobe" || kind == "uretprobe" || kind == "usdt" || kind == "go_uret")
            if reactor_uprobe_kind
              # look for a trailing KeywordHashNode `pid: N` after the
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
                # Was a warning + drop. A warning that is followed by a
                # successful build is exactly the shape the common-filter
                # declaration refused.
                if idx.nil? || idx == 0 || idx == spec.length - 1
                  handler_not_realised!(
                    "`on :#{kind}, #{spec.inspect}` in #{mod_where} is not in `binary:function` form.",
                    "a #{kind} attaches to a symbol inside a specific executable, so the target " \
                    "carries both halves; glue.c splits them at the last `:` to call " \
                    "bpf_program__attach_uprobe_opts. With only one half there is nothing to attach " \
                    "to, and this used to warn and then exit 0 anyway.",
                    "write both halves: `on :#{kind}, \"/usr/bin/bash:readline\" do … end`.",
                  )
                end
                dsl_uprobe_binary   = spec[0...idx]
                dsl_uprobe_func     = spec[(idx + 1)..]
                dsl_uprobe_retprobe = (kind == "uretprobe")
                dsl_uprobe_go_ret   = (kind == "go_uret")   # the glue attaches at RET offsets
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

            # for `on :timer`, look for a trailing `every: N.<unit>`
            # KeywordHashNode in the arguments list and resolve it to ns.
            interval_ns = nil
            if kind == "timer"
              kw = arg_ids[info.arity + 1] || arg_ids[1]
              interval_ns = parse_timer_interval_ns(ast, kw) if kw
              # Was a warning + drop. The negative fixture
              # tests/fixtures/163_timer_no_interval's own header says a timer
              # that cannot fire "must not compile", and the C codegen does
              # refuse it — but the CLI never got that far, because this drop
              # left the eBPF method count at zero and the codegen was never
              # called. The refusal has to be here for a user to ever see it.
              if interval_ns.nil?
                units = BPF_TIMER_UNIT_NS.keys.join(", ")
                handler_not_realised!(
                  "`on :timer` in #{mod_where} has no `every: N.<unit>` interval.",
                  "the interval is folded into bpf_timer_start at compile time, so a timer without " \
                  "one has nothing to arm and can never fire. An earlier audit measured what the " \
                  "silence cost: the whole block vanished from the emitted C and the probe still " \
                  "exited 0.",
                  "give it a period: `on :timer, every: 1.seconds do … end` (units: #{units}).",
                )
              end
            end

            # for `on :perf_event`, look for a trailing `hz: N`
            # KeywordHashNode. Optional; nil means glue.c falls back to
            # $SPNL_PERF_HZ (default 49).
            perf_hz = nil
            if kind == "perf_event"
              kw = arg_ids[info.arity + 1] || arg_ids[1]
              perf_hz = parse_perf_event_hz(ast, kw) if kw
            end

            # THE headline case. `on :xdp` with no block was the purest form of
            # the bug — no warning, no error, no XDP program.
            spelling = "on :#{kind}" + targets.map { |t| ", #{t.inspect}" }.join
            _block_id, handler_body_id = reactor_block_body!(ast, cn, spelling, mod_where)
            block_id = _block_id
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
              dsl_uprobe_go_ret:   dsl_uprobe_go_ret,
              dsl_usdt_provider: dsl_usdt_provider,
              dsl_usdt_name: dsl_usdt_name,
              dsl_attach_pid: dsl_attach_pid,
              dsl_perf_event_hz: perf_hz,
            )
          end
        elsif prefix
          defs.each do |dn|
            name = dn.attrs.fetch("name", "")
            # Not reachable from any Ruby source — spinel always writes a
            # DefNode's name. Kept as an invariant rather than a drop: if it
            # ever fires it is a bug in the AST dump, not in the probe, and
            # silently losing an attach handler is the wrong way to find out.
            raise PartitionError,
                  "internal: DefNode #{dn.id} in #{mod_where} (include BPF::…) has no name; " \
                  "every method in a DSL-bound module becomes an attach handler, so it cannot be " \
                  "skipped. Please report this with the .rb and the .ast." if name.empty?
            body_node_id = dn.refs.fetch("body", -1)
            # `module M; include BPF::XDP; def main; end; end`. Every method of
            # a DSL-bound module IS an attach handler, so an empty body meant no
            # program at all — measured exit 0, no output.
            if body_node_id < 0
              handler_not_realised!(
                "`def #{name}` in #{mod_where} (include BPF::…) has an empty body.",
                "including a BPF DSL module binds every method in it to an attach kind — this one " \
                "becomes `#{prefix}#{name}`. An empty body has nothing to lower, so no program is " \
                "emitted and nothing is attached, and that used to happen with no diagnostic at " \
                "all.",
                "put at least one statement in `#{name}`, or delete it until you need it.",
              )
            end
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

    # The multi-symbol form's argument shape. Returns the symbol list, or nil when
    # this `on` is one of the 1-to-1 forms. Only the SHAPE is decided here; every
    # diagnostic about the contents (empty list, non-literal element, duplicate,
    # bad `via:`) is raised by the C codegen, which is the one place that has to be
    # right -- partition and the codegen both walk this AST, and two copies of the
    # same rule is two things to keep in step.
    def multi_symbol_list(ast, arg_ids)
      return nil unless arg_ids.length >= 2
      node = ast.node(arg_ids[1])
      return nil unless node && node.type == "ArrayNode"
      ast.array(arg_ids[1], "elements", default: []).filter_map do |eid|
        el = ast.node(eid)
        el && el.type == "StringNode" ? el.attrs.fetch("content", "") : nil
      end.reject(&:empty?)
    end

    # parse a `every: N.<unit>` keyword from the `on :timer` args.
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

    # parse `hz: N` from a KeywordHashNode (the trailing kwarg of
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

    # parse `pid: N` from a KeywordHashNode (the trailing kwarg of a
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
    # Modules whose body declares FFI (ffi_func / ffi_lib / ...) name extern C
    # functions, which are host-only: BPF cannot replay a foreign call. The sp_*
    # rule below catches the runtime's own helpers by naming convention, but a
    # user FFI module (SQL.sqlite3_open, DUCK.duckdb_query, ...) follows no such
    # convention and used to slip through, only to die later in codegen. Collect
    # the declared FFI modules from the AST and treat any call through them as
    # host I/O.
    FFI_DSL_NAMES = %w[ffi_func ffi_lib ffi_cflags ffi_const ffi_buffer
                       ffi_read_ptr ffi_read_u32 ffi_read_i32].freeze

    def collect_ffi_modules(ast)
      out = {}
      root = ast.root_id
      return out unless root
      stmts_id = ast.attr(root, "statements", default: -1)
      return out if stmts_id < 0
      ast.array(stmts_id, "body", default: []).each do |sid|
        n = ast.node(sid)
        next unless n && n.type == "ModuleNode"
        body_id = n.refs.fetch("body", -1)
        next if body_id < 0
        mod_name = ast.str_attr(n.refs.fetch("constant_path", -1), "name", default: "")
        next if mod_name.empty?
        has_ffi = ast.array(body_id, "body", default: []).any? do |bid|
          bn = ast.node(bid)
          bn && bn.type == "CallNode" && FFI_DSL_NAMES.include?(bn.attrs.fetch("name", ""))
        end
        out[mod_name] = true if has_ffi
      end
      out
    end

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
      when "InstanceVariableWriteNode"
        # `@x = []` / `@x = {}` / `@x = ""` / `@x = nil`: an ivar holding a
        # dynamic structure (or nil) makes the class a host-side object. Only
        # integer ivars map onto BPF (one HASH map per ivar). Without this a
        # no-arg initialize whose body is only such assignments looked
        # eBPF-eligible and died later in codegen. Note uses_dynamic_array_grow
        # alone is informational and does not block, hence the extra flag.
        vid = node.refs.fetch("value", -1)
        vt = vid >= 0 ? ast.type_of(vid) : nil
        if vt == "ArrayNode" || vt == "HashNode"
          flags.uses_dynamic_array_grow = true
          flags.uses_unsupported_type = true
        elsif vt == "NilNode" || vt == "StringNode"
          flags.uses_unsupported_type = true
        end
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
        # and stays :ebpf by lowering to bpf_loop.)
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
        # Declaration-based FFI detection (does not depend on the sp_* naming
        # convention above).
        if recv_type == "ConstantReadNode" && recv_name && @ffi_modules && @ffi_modules[recv_name]
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
              elsif callee_mi.flags.impossible_for?(@target || TargetProfile::LINUX_EBPF)   # propagation follows the target too
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
      # synthesized userspace consumer / driver / named-handler methods
      # (the `on_emit` / `on_emit :name` DSL lowered by SpinelEbpf::Consumer) are
      # always native — they run in userspace draining the emit ringbuf, even
      # though the body may look eBPF-eligible (int + top-level ivar).
      return mi.tag = :native if mi.method_name.start_with?("__spnl_")
      # --instrument --instrument-self combines the workload + the agent in
      # one ebpf-mixed unit. The workload methods (the uprobe *targets*) are
      # eBPF-eligible (pure int) but MUST stay native — they run as the workload
      # and the self-uprobe attaches to their sp_<name> symbols. Force them native.
      return mi.tag = :native if force_native && force_native.include?(mi.method_name)
      mi.tag = mi.flags.impossible_for?(@target || TargetProfile::LINUX_EBPF) ? :native : :ebpf
    end

    # ---------- Top-level entry ----------

    def classify(ir, ast, force_native: nil, target: TargetProfile::LINUX_EBPF)
      @target = target                          # eligibility is target-relative
      @ffi_modules = collect_ffi_modules(ast)
      methods = enumerate_methods(ir, ast)
      methods.each do |mi|
        analyze_method(mi, ast)
        # even when body has no FloatNode literal, spinel's signature
        # inference can tell us a param or return is float. Mark uses_float
        # accordingly so partition sees indirect float usage.
        refine_flags_from_signature(mi, ir)
        # ...and the locals, which no pass looked at. A bignum local is the one
        # type whose value is already destroyed by the time we see it.
        refine_flags_from_locals(mi, ir)
      end
      fixpoint_propagate(methods)
      methods.each { |mi| decide_tag!(mi, force_native) }
      # A synthesized `xdp__tcp_slice__kernel_cache` :ebpf method used to be
      # appended here whenever a `kernel_cache "/path", body` declaration was
      # present, so the retired Ruby generator would emit the kernel-cache
      # slice. It is deleted: the C codegen never carried that branch, the
      # re-port of the TCP slice did not either, and the directive is a compile
      # error now -- so the only thing the synthesis still did was print
      #
      #   ebpf   xdp__tcp_slice__kernel_cache
      #
      # in the tag table of a program that Validate (6) refuses two lines later.
      # Announcing a handler that cannot exist is the same failure as dropping
      # one that can, pointing the other way; a refused program must not be told
      # it got a handler.
      Result.new(methods: methods, program_warnings: program_warnings(ir),
                 target: @target || TargetProfile::LINUX_EBPF)
    end

    # pull per-method signature (param types + return type) from IR and
    # toggle ebpf-impossible flags for any non-int type.
    # widen to flag string / array / hash / poly etc. as unsupported_type
    # — codegen_bpf can't lower these as BPF parameters, so partition must
    # keep such methods :native instead of letting codegen blow up.
    SUPPORTED_EBPF_SIGNATURE_TYPES = %w[int bool void nil].freeze

    def refine_flags_from_signature(mi, ir)
      types = signature_types(mi, ir)
      # signature_types appends the return type as the last element; everything
      # before it is a parameter type.
      last = types.length - 1
      types.each_with_index do |t, i|
        # nullability (`int?`, `float?`, `string?`, ...) is orthogonal
        # to eBPF type-eligibility — spinel widens a type to nullable for any
        # value that can be nil, and crucially infers `int?` for any method
        # whose body is `if … end` without an explicit `else` (the implicit
        # nil branch). That is the single most common attach-handler shape
        # (`if cond; spnl_emit(x); end`), and the nullable int still lowers to
        # __s64 (nil -> 0). Judge by the base type so `int?` stays eligible,
        # `string?` stays rejected, and `float?` is still attributed to float.
        base = t.end_with?("?") ? t[0..-2] : t
        # the C compiler's analyzer types empty-body / builtin-stub
        # methods' RETURN as `poly` where the legacy Ruby analyzer said `nil`
        # (e.g. `def spnl_emit(x); end`), and callers inherit it. A `poly`
        # RETURN is discarded for attach handlers and lowers to void otherwise,
        # so it must not disqualify (a poly *param* still does — codegen can't
        # lower an object parameter). No-op for the legacy path, which never
        # emits a poly return.
        next if i == last && base == "poly"
        case base
        when "float"  then mi.flags.uses_float = true
        # This arm used to read `when "bignum"`, and **spinel has no such type
        # name** -- its own table spells it `bigint`. So the arm was unreachable
        # and `uses_bignum` was a flag nothing ever set, while the affordance
        # advertised it in RUBY_SUBSET[:rejected] as a loud refusal. A bignum in
        # SIGNATURE position still failed loudly (it fell through to the `else`
        # and became uses_unsupported_type), so the mistake was only visible as a
        # wrong REASON -- until you put the bignum in a local, where nothing
        # looked at all: measured exit 0 with `9223372036854775807` baked into the
        # kernel program, because spinel's front end clamps a >64-bit literal to
        # INT64_MAX before either the AST dump or the IR is written. The clamped
        # VALUE is all that survives; the only trace of what the author wrote is
        # the inferred type, which is why the locals pass below exists.
        when "bigint" then mi.flags.uses_bignum = true
        when "", *SUPPORTED_EBPF_SIGNATURE_TYPES
          # empty (no info) and known-safe types are fine
        else
          # string, str_array, int_array, hash, poly, lambda, fiber, proc, ...
          mi.flags.uses_unsupported_type = true
        end
      end
    end

    # The same judgement for LOCALS. `refine_flags_from_signature` only ever sees
    # params and the return type, so a value that never crosses a method boundary
    # was judged by nothing at all -- and for a bignum that is not a missing
    # diagnostic but a WRONG VALUE: spinel clamps the literal to INT64_MAX in its
    # own front end, so the kernel program gets 9223372036854775807 where the
    # author wrote a 30-digit number, with exit 0 (measured).
    #
    # Only `bigint` is judged here, deliberately. The other rejected types
    # (string / array / hash / lambda / ...) appear in locals of perfectly good
    # NATIVE methods all over the corpus; a local's type is not a statement about
    # eBPF eligibility in general. A bignum is different: it cannot be represented
    # at all on the eBPF side, in any position, and the value is already gone.
    #
    # The lookup is keyed by the IR's body id, not the AST one: the SN/ST scope
    # records come from the IR, and the two numbering spaces are not the same. A
    # method with no IR row has nothing to look up and is skipped.
    def refine_flags_from_locals(mi, ir)
      return unless mi.ir_body_id
      return unless ir.respond_to?(:scope_locals)
      (ir.scope_locals[mi.ir_body_id] || []).each do |_name, t|
        base = t.to_s.end_with?("?") ? t[0..-2] : t.to_s
        mi.flags.uses_bignum = true if base == "bigint"
      end
    end

    def signature_types(mi, ir)
      case mi.scope
      when :top_level
        # ir.sa() already splits the IR's "|"-separated payload AND pads with
        # empties via split_strs_n. Re-applying flat_map(split("|", -1)) drops
        # empty entries because Ruby's "".split("|", -1) == [] in some versions,
        # which silently misaligns idx and yields wrong types per method.
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
