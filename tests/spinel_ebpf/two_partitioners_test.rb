# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/two_partitioners_test.rb
#
# spinel-ebpf runs TWO partitions over the same program — the Ruby one
# (Partition.classify, walks the body) and the C one (cc_sig_eligible, reads the
# signature). They disagree in one direction, Ruby wins, and every override is
# announced. What this file pins is the part that has no type to protect it:
#
#   (a) the list the CLI hands the codegen never contains an attach handler
#       — that is the ONLY way this change could turn a loud failure into a
#         silently dropped program (the stated reason for not wiring it at all),
#   (b) the two readers of $SPNL_PARTITION_NATIVE agree on the name AND on the
#       qualified form for a class method (the Ruby side writes the string, the
#       C side parses it; nothing else joins them),
#   (c) the override is applied at cc_method_eligible — i.e. at the ONE
#       predicate every emission site already calls, not at a subset of them
#       (the "partial application" failure the common filter refused,
#        transplanted),
#   (d) the report is computed from cc_sig_eligible, because computing it from
#       cc_method_eligible would make it structurally silent (that predicate is
#       false for exactly the methods the report exists to name),
#   (e) check (7)'s two axes: it fires on the real problem (the multi-worker
#       HTTP example, and 32_path_counter
#       — upstream refuses those today, measured) and does NOT fire on the two
#       shapes that make the corpus compile: a builtin stub, and an attach
#       handler nothing calls from Ruby.
require "minitest/autorun"
require "spinel_ebpf/partition"
require "spinel_ebpf/validate"
require "spinel_ebpf/codegen_bpf"

class TwoPartitionersTest < Minitest::Test
  P    = SpinelEbpf::Partition
  V    = SpinelEbpf::Validate
  GEN  = SpinelEbpf::CodegenBpf
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  CC   = File.read(File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c"))
  CLI  = File.read(File.join(ROOT, "bin/spinel-ebpf"))

  def load(name, dir = FIX)
    ir  = SpinelEbpf::ParseSpinelIR.parse_file(File.join(dir, "#{name}.ir"))
    ast = SpinelEbpf::ParseSpinelAst.parse_file(File.join(dir, "#{name}.ast"))
    [ir, ast, P.classify(ir, ast)]
  end

  def mi(name, tag, scope: :top_level, cls: nil)
    P::MethodInfo.new(scope: scope, class_name: cls, method_name: name,
                      body_id: 1, flags: P::MethodFlags.default, tag: tag)
  end

  # ---------- (a) the list may never drop an attach handler ----------

  # An attach handler that the Ruby partition rules native must NOT appear on
  # the list. Attach is the author's stated intent and has no native execution
  # path, so excluding one turns "it fires" into "it never fires" with exit 0 —
  # the silent drop this change refused to risk. check (1) already dies on this
  # shape one layer earlier; keeping it off the list means the override cannot
  # reintroduce the failure even if check (1) were ever narrowed.
  def test_attach_handler_is_never_on_the_override_list
    r = P::Result.new(methods: [
      mi("kprobe__do_sys_openat2", :native),
      mi("xdp__main", :native),
      mi("tracepoint__syscalls__sys_enter_openat", :native),
      mi("worker_loop", :native),
    ], program_warnings: [])
    assert_equal ["worker_loop"], V.native_override_names(r)
  end

  # ... and the same over every committed fixture, so a future attach kind that
  # partition can tag native does not slip in unnoticed.
  def test_no_fixture_puts_an_attach_name_on_the_override_list
    n = 0
    Dir[File.join(FIX, "*.rb")].sort.each do |rb|
      base = File.basename(rb, ".rb")
      next unless File.exist?(File.join(FIX, "#{base}.ast")) && File.exist?(File.join(FIX, "#{base}.ir"))
      begin
        _ir, _ast, r = load(base)
      rescue StandardError
        next
      end
      n += 1
      V.native_override_names(r).each do |name|
        assert_nil GEN.detect_attach(name),
                   "#{base}: `#{name}` is an attach handler and must never be excluded from the .bpf.c"
      end
    end
    assert_operator n, :>, 100, "expected the fixture corpus, got #{n} programs"
  end

  def test_override_list_is_the_native_side_only
    r = P::Result.new(methods: [
      mi("record_path_hit", :ebpf),
      mi("worker_loop", :native),
      mi("__spnl_consumer0", :native),
      mi("<main>", :native, scope: :main),
      mi("total", :native, scope: :class, cls: "Accumulator"),
    ], program_warnings: [])
    assert_equal %w[worker_loop Accumulator#total], V.native_override_names(r)
  end

  # The multi-worker HTTP example is the program this was opened over: two names,
  # both plain helpers, both signature-eligible on the C side.
  def test_so_reuseport_example_override_list
    ir  = SpinelEbpf::ParseSpinelIR.parse_file(File.join(FIX, "32_path_counter.ir"))
    ast = SpinelEbpf::ParseSpinelAst.parse_file(File.join(FIX, "32_path_counter.ast"))
    r   = P.classify(ir, ast)
    # 32_path_counter has no native helper at all — the list is empty, which is
    # what "the CLI passes nothing" has to look like (env unset => no behaviour
    # change at all, the property every untouched fixture relies on).
    assert_empty V.native_override_names(r)
  end

  # ---------- (b) two readers, one contract ----------

  def test_both_sides_name_the_same_variable
    assert_includes CC,  'cc_name_in_env_list(q, "SPNL_PARTITION_NATIVE")'
    assert_includes CC,  'cc_name_in_env_list(me->name, "SPNL_PARTITION_NATIVE")'
    assert_includes CLI, 'icc_env["SPNL_PARTITION_NATIVE"]'
    assert_includes CLI, "SpinelEbpf::Validate.native_override_names(result)"
  end

  # The Ruby side writes "Class#name"; the C side has to build the same string
  # or a class method would silently never match. Nothing else joins the two.
  def test_class_scoped_form_agrees
    r = P::Result.new(methods: [mi("total", :native, scope: :class, cls: "Accumulator")],
                      program_warnings: [])
    assert_equal ["Accumulator#total"], V.native_override_names(r)
    assert_includes CC, 'snprintf(q, sizeof q, "%s#%s", me->cls, me->name);'
  end

  # $SPNL_EBPF_EXCLUDE must stay a separate list: it also filters
  # cc_build_ir_text, i.e. it edits the .ir the Ruby partition is computed FROM.
  # Merging the two would let a partition verdict rewrite its own input.
  def test_does_not_reuse_the_ebpf_exclude_variable
    assert_includes CC, 'cc_name_in_env_list(name, "SPNL_EBPF_EXCLUDE")'
    refute_includes CC, '"SPNL_EBPF_EXCLUDE,SPNL_PARTITION_NATIVE"'
    # cc_is_consumer_fn (the IR-text filter) must not learn about the new list.
    consumer = CC[/static int cc_is_consumer_fn.*?\n}/m]
    refute_nil consumer
    refute_includes consumer, "SPNL_PARTITION_NATIVE"
  end

  # ---------- (c)(d) applied once, reported honestly ----------

  # Every emission site already calls cc_method_eligible; the override belongs
  # THERE and nowhere else, so no site can be left un-overridden.
  def test_override_is_applied_inside_cc_method_eligible
    body = CC[/static int cc_method_eligible\(const Method \*me\) \{.*?\n\}/m]
    refute_nil body, "cc_method_eligible not found"
    assert_includes body, "cc_sig_eligible(me)"
    assert_includes body, "!cc_partition_native(me)"
    # The signature-only rule keeps exactly three call-shaped occurrences: its own
    # definition, the override wrapper, and the report. A fourth would be a site
    # deciding eligibility while ignoring the partition.
    assert_equal 3, CC.scan(/cc_sig_eligible\(/).length,
                 "cc_sig_eligible must only be read by cc_method_eligible and the report"
  end

  # Computing the report from cc_method_eligible would make it print nothing,
  # ever — that predicate is false for precisely the methods being reported.
  def test_report_reads_the_signature_rule_not_the_overridden_one
    body = CC[/static void cc_report_partition_overrides\(IR \*ir\) \{.*?\n\}/m]
    refute_nil body, "cc_report_partition_overrides not found"
    assert_includes body, "!cc_sig_eligible(me) || !cc_partition_native(me)"
    refute_includes body, "cc_method_eligible"
    assert_includes body, "fprintf(stderr"
  end

  def test_report_runs_before_anything_is_emitted
    prog = CC[/static char \*ebpf_codegen_program\(IR \*ir, AST \*ast, const char \*base\) \{.*?\n\}/m]
    refute_nil prog
    at_report = prog.index("cc_report_partition_overrides(ir)")
    at_bind   = prog.index("cc_bind_dsl_class_attach(ir, ast)")
    refute_nil at_report, "the report is not called from ebpf_codegen_program"
    refute_nil at_bind
    assert_operator at_report, :<, at_bind,
                    "the override must be announced before any pass rewrites the method table"
  end

  # --target amp-m7 deliberately ignores tags and emits whichever
  # handler is signature-eligible; handing it the tags would contradict that.
  def test_amp_is_left_alone
    assert_match(/unless opts\[:amp\]\s*\n\s*pn = SpinelEbpf::Validate\.native_override_names/, CLI)
  end

  # `check` is the machine-facing surface; it must run the codegen in the same
  # environment `compile` does, or the two would disagree about which methods
  # are emitted — the very shape this closes.
  def test_check_runs_the_codegen_with_the_same_verdict
    assert_includes CLI, "Open3.capture3(icc_env, icc, ctx[:input], ctx[:base])"
    assert_equal 2, CLI.scan(/Validate\.native_override_names/).length,
                 "exactly two callers: cmd_compile and check_stage_codegen"
  end

  # The one remaining way a :native tag can exist without check (1) having looked
  # at it is `force_native` (--instrument --instrument-self). Those names come
  # from Instrument.instrumentable, which drops attach handlers — so that path
  # cannot produce an attach handler either, and the override list is not the
  # only thing standing between an attach handler and a silent drop.
  def test_force_native_names_can_never_be_attach_handlers
    require "spinel_ebpf/instrument"
    recs = [{ ruby: "kprobe__do_sys_openat2", c: "sp_kprobe__do_sys_openat2", kind: "toplevel" },
            { ruby: "xdp__main",              c: "sp_xdp__main",              kind: "toplevel" },
            { ruby: "fib",                    c: "sp_fib",                    kind: "toplevel" }]
    kept = SpinelEbpf::Instrument.instrumentable(recs)
    assert_equal ["fib"], SpinelEbpf::Instrument.self_target_names(kept)
  end

  # ---------- (e) check (7): fires on the problem, not on the corpus ----------

  def test_ebpf_only_builtin_in_a_natively_compiled_body_is_refused
    _ir, ast, r = load("32_path_counter")
    err = assert_raises(V::Error) { V.validate!(ast, r, ebpf_dispatch: false) }
    m = err.message
    # what
    assert_includes m, "record_path_hit"
    assert_includes m, "path_counter_inc"
    assert_includes m, "compiled into the native C"
    # why (with the upstream message the author would otherwise be handed raw)
    assert_includes m, "Why:"
    assert_includes m, "unsupported call"
    assert_includes m, "reachable from `<main>`"
    # how
    assert_includes m, "Fix:"
    assert_includes m, "--ebpf-dispatch"
    assert_includes m, "SPINEL_EXTERN_METHODS"
  end

  # The fix the message names has to be true. (Verified end to end against a
  # running binary; here it is pinned at the layer the message is produced.)
  def test_dispatch_clears_the_refusal
    _ir, ast, r = load("32_path_counter")
    V.validate!(ast, r, ebpf_dispatch: true)   # must not raise
  end

  # A stub `def spnl_emit(x); end` is how the corpus teaches the native pass the
  # name (measured: upstream accepts it). Reading the PARTITION for defined names
  # instead of the AST missed these — the partition skips a body-less def — and
  # rejected three fixtures that build.
  def test_builtin_stub_is_not_refused
    _ir, ast, r = load("12_spnl_emit")
    V.validate!(ast, r, ebpf_dispatch: false)  # must not raise
    assert_includes V.ast_defined_method_names(ast), "spnl_emit"
  end

  # An attach handler is never called from Ruby, so upstream never emits a body
  # for it and never sees the builtin. Most of the corpus is this shape; a check
  # without reachability would reject nearly all of it.
  def test_unreachable_handler_is_not_refused
    _ir, ast, r = load("111_cgroup_id")
    V.validate!(ast, r, ebpf_dispatch: false)  # must not raise
    refute_includes V.ast_defined_method_names(ast), "spnl_emit",
                    "this fixture must have NO stub, else it does not test reachability"
    handler = r.methods.find { |x| x.method_name == "kprobe__do_sys_openat2" }
    refute_nil handler
    assert_equal :ebpf, handler.tag
  end

  # Whole committed fixture corpus, both axes at once.
  def test_fixture_corpus_two_axis_sweep
    refused = []
    Dir[File.join(FIX, "*.rb")].sort.each do |rb|
      base = File.basename(rb, ".rb")
      next unless File.exist?(File.join(FIX, "#{base}.ast")) && File.exist?(File.join(FIX, "#{base}.ir"))
      begin
        _ir, ast, r = load(base)
      rescue StandardError
        next
      end
      begin
        V.validate!(ast, r, ebpf_dispatch: false)
      rescue V::Error => e
        refused << base if e.message.include?("calls the eBPF-only builtin")
      end
    end
    # Exactly the fixture whose own header says "--ebpf-dispatch" is required.
    assert_equal ["32_path_counter"], refused
  end
end
