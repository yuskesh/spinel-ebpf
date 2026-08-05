# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/declared_handler_test.rb
#
# A handler the author DECLARED must never disappear quietly.
#
# Partitioning used to answer "I cannot realise this declaration" in three
# different ways, and two of them reported success. A census of every shape that
# reaches these sites found 13 of them, 12 exiting 0, and 10 of those with no
# diagnostic whatsoever:
#
#   on :no_such_kind do … end   PartitionError, as a raw Ruby backtrace   exit 1
#   on :timer do … end          "warning: … — skipping handler"           exit 0
#   on :xdp                     nothing at all                           exit 0
#
# WHAT THESE TESTS PIN. Not "an error happens" — the census's own two axes, for
# every one of the 14 shapes:
#
#   negative   the shape is REFUSED (a PartitionError, not a warning)
#   positive   the same shape with the mistake corrected still classifies
#
# The positive half is not decoration. A refusal that also rejects the correct
# spelling is not a fix, and every one of these sites sits on a path the whole
# corpus goes through. It is the same two-axis rule tools/affordance_gate.rb
# applies to advertised-vs-withdrawn.
#
# WHY SYNTHETIC AST/IR AND NOT COMMITTED FIXTURES. Committing 14 refusing .rb
# files would put them in three corpus sweeps that count what they find
# (tools/partition_id_check.rb, tools/golden.rb, and the census itself), so the
# baselines would move for a reason unrelated to what they defend. Building the
# two text formats here also puts the SHAPE in the test — `on` with no block is
# a CallNode whose `block` ref is -1, and that is the whole bug — where a
# generated fixture would hide it.
require "minitest/autorun"
require "spinel_ebpf/partition"
require "spinel_ebpf/capabilities"

class DeclaredHandlerTest < Minitest::Test
  P = SpinelEbpf::Partition

  # ---------- synthetic SPINEL AST (deps/spinel/docs/AST.md) ----------
  class Ast
    def initialize
      @lines = ["ROOT 0"]
      @next  = 0
    end

    def node(type)
      id = @next
      @next += 1
      @lines << "N #{id} #{type}"
      id
    end

    def s(id, f, v) = tap { @lines << "S #{id} #{f} #{v}" }
    def r(id, f, v) = tap { @lines << "R #{id} #{f} #{v}" }
    def a(id, f, v) = tap { @lines << "A #{id} #{f} #{v.join(',')}" }
    def text = "#{@lines.join("\n")}\n"
    def parse = SpinelEbpf::ParseSpinelAst.parse(text)
  end

  # A `module <name>` whose body is `stmts`, at program top level.
  # Returns [Ast, module_body_statements_id, appender] so a caller can fill in
  # the body after the ids around it are fixed.
  def program_with_module(name)
    ast = Ast.new
    prog  = ast.node("ProgramNode")
    stmts = ast.node("StatementsNode")
    mod   = ast.node("ModuleNode")
    cpath = ast.node("ConstantReadNode")
    body  = ast.node("StatementsNode")
    ast.r(prog, "statements", stmts)
    ast.a(stmts, "body", [mod])
    ast.r(mod, "constant_path", cpath)
    ast.r(mod, "body", body)
    ast.s(cpath, "name", name)
    [ast, body]
  end

  # `include BPF::<tail>` (or BPF::EventLoop) as a CallNode. Returns its id.
  def include_call(ast, tail)
    call = ast.node("CallNode")
    args = ast.node("ArgumentsNode")
    root = ast.node("ConstantReadNode")
    leaf = ast.node("ConstantPathNode")
    ast.s(call, "name", "include")
    ast.r(call, "arguments", args)
    ast.a(args, "arguments", [leaf])
    ast.s(root, "name", "BPF")
    ast.s(leaf, "name", tail)
    ast.r(leaf, "parent", root)
    call
  end

  # `on <args> [do <body> end]`. `args` is a list of [type, field, value]
  # triples built by the helpers below; `block:` false means no `do … end` at
  # all, `block: :empty` means a BlockNode whose body ref is -1.
  def on_call(ast, args, block: :body)
    call = ast.node("CallNode")
    ast.s(call, "name", "on")
    unless args.nil?
      argsn = ast.node("ArgumentsNode")
      ids = args.map do |type, field, value|
        n = ast.node(type)
        ast.s(n, field, value) if field
        n
      end
      ast.r(call, "arguments", argsn)
      ast.a(argsn, "arguments", ids)
    end
    case block
    when false then nil
    when :empty
      b = ast.node("BlockNode")
      ast.r(call, "block", b)
      ast.r(b, "body", -1)
    else
      b  = ast.node("BlockNode")
      bs = ast.node("StatementsNode")
      iv = ast.node("InstanceVariableWriteNode")
      ast.r(call, "block", b)
      ast.r(b, "body", bs)
      ast.a(bs, "body", [iv])
      ast.s(iv, "name", "@hits")
    end
    call
  end

  def sym(v)  = ["SymbolNode", "value", v]
  def str(v)  = ["StringNode", "content", v]

  # An `%w[a b]` ArrayNode has to be built inside the same Ast, so it is a
  # special argument form rather than a triple.
  def on_call_multi(ast, kind, syms, block: :body)
    call  = ast.node("CallNode")
    argsn = ast.node("ArgumentsNode")
    symn  = ast.node("SymbolNode")
    arr   = ast.node("ArrayNode")
    ast.s(call, "name", "on")
    ast.s(symn, "value", kind)
    ast.r(call, "arguments", argsn)
    els = syms.map do |sv|
      n = ast.node("StringNode")
      ast.s(n, "content", sv)
      n
    end
    ast.a(arr, "elements", els)
    ast.a(argsn, "arguments", [symn, arr])
    case block
    when false then nil
    when :empty
      b = ast.node("BlockNode")
      ast.r(call, "block", b)
      ast.r(b, "body", -1)
    else
      b  = ast.node("BlockNode")
      bs = ast.node("StatementsNode")
      iv = ast.node("InstanceVariableWriteNode")
      ast.r(call, "block", b)
      ast.r(b, "body", bs)
      ast.a(bs, "body", [iv])
      ast.s(iv, "name", "@hits")
    end
    call
  end

  # A reactor module: `module R; include BPF::EventLoop; <on…>; end`.
  # `build` receives the Ast and returns the `on` CallNode id.
  def reactor(&build)
    ast, body = program_with_module("R")
    inc = include_call(ast, "EventLoop")
    on  = build.call(ast)
    ast.a(body, "body", [inc, on])
    ast.parse
  end

  # ---------- synthetic SPINEL-IR (deps/spinel/docs/ANALYZE-IR.md) ----
  # The reactor cases need no methods at all: `on` blocks are not `def`s, so
  # spinel's IR omits them entirely and the partition synthesizes from the AST.
  def ir(lines = [])
    SpinelEbpf::ParseSpinelIR.parse(([P::ParseSpinelIR::VERSION_STAMP] + lines).join("\n") + "\n")
  rescue NameError
    SpinelEbpf::ParseSpinelIR.parse((["SPINEL-IR v1"] + lines).join("\n") + "\n")
  end

  def refusal_for(ast, ir_lines = [])
    assert_raises(P::PartitionError) { P.classify(ir(ir_lines), ast) }
  end

  def assert_diagnostic_shape(msg, *must_include)
    assert_match(/\n  Why: /, msg, "message has no `Why:` line (what / why / how to fix):\n#{msg}")
    assert_match(/\n  Fix: /, msg, "message has no `Fix:` line (what / why / how to fix):\n#{msg}")
    must_include.each { |kw| assert_includes msg, kw, "message missing #{kw.inspect}:\n#{msg}" }
  end

  # ---------- A1/A2/A3: `on` that names no event kind ----------

  def test_a1_on_with_no_arguments_is_refused
    ast = reactor { |a| on_call(a, nil) }
    assert_diagnostic_shape refusal_for(ast).message, "does not name an event kind", "no arguments", ":xdp"
  end

  def test_a3_on_with_a_string_kind_is_refused
    ast = reactor { |a| on_call(a, [str("xdp")]) }
    assert_diagnostic_shape refusal_for(ast).message, "does not name an event kind", "StringNode"
  end

  # ---------- A4/A5: the multi-symbol form ----------

  def test_a4_multi_symbol_without_a_block_is_refused
    ast = reactor { |a| on_call_multi(a, "kprobe", %w[vfs_read vfs_write], block: false) }
    assert_diagnostic_shape refusal_for(ast).message, "no `do … end` block", "vfs_read"
  end

  def test_a5_multi_symbol_with_an_empty_block_is_refused
    ast = reactor { |a| on_call_multi(a, "kprobe", %w[vfs_read vfs_write], block: :empty) }
    assert_diagnostic_shape refusal_for(ast).message, "block is empty"
  end

  def test_a4_positive_control_multi_symbol_with_a_body_classifies
    ast = reactor { |a| on_call_multi(a, "kprobe", %w[vfs_read vfs_write]) }
    names = P.classify(ir, ast).methods.map(&:method_name)
    assert_includes names, "kprobe_multi__set0"
  end

  # ---------- A6/A7: a per-target kind with the wrong number of targets ------

  def test_a7_kprobe_without_a_target_is_refused
    ast = reactor { |a| on_call(a, [sym("kprobe")]) }
    assert_diagnostic_shape refusal_for(ast).message, "needs 1 target argument", "got 0"
  end

  def test_a7_tracepoint_says_it_needs_two
    ast = reactor { |a| on_call(a, [sym("tracepoint"), str("sched")]) }
    assert_diagnostic_shape refusal_for(ast).message, "needs 2 target arguments", "got 1"
  end

  def test_a7_positive_control_kprobe_with_a_target_classifies
    ast = reactor { |a| on_call(a, [sym("kprobe"), str("vfs_read")]) }
    assert_includes P.classify(ir, ast).methods.map(&:method_name), "kprobe__vfs_read"
  end

  # ---------- A8: uprobe target that is not `binary:function` ----------
  # This one WARNED and then exited 0. It is in the census because a warning
  # followed by a successful build is the shape the common-filter declaration
  # refused.

  def test_a8_uprobe_target_without_a_colon_is_refused
    ast = reactor { |a| on_call(a, [sym("uprobe"), str("readline")]) }
    assert_diagnostic_shape refusal_for(ast).message, "binary:function", "/usr/bin/bash:readline"
  end

  def test_a8_positive_control_full_uprobe_spec_classifies
    ast = reactor { |a| on_call(a, [sym("uprobe"), str("/usr/bin/bash:readline")]) }
    assert_includes P.classify(ir, ast).methods.map(&:method_name), "uprobe__react0"
  end

  # ---------- A9: `on :timer` with no interval ----------
  # tests/fixtures/163_timer_no_interval's own header says a timer that cannot
  # fire "must not compile".
  # The C codegen agrees and refuses it; the CLI never used to ask, because
  # this drop left the eBPF method count at zero.

  def test_a9_timer_without_an_interval_is_refused
    ast = reactor { |a| on_call(a, [sym("timer")]) }
    assert_diagnostic_shape refusal_for(ast).message, "every: N.<unit>", "can never fire", "seconds"
  end

  # ---------- A10/A11: THE headline case ----------

  def test_a10_on_xdp_with_no_block_is_refused
    ast = reactor { |a| on_call(a, [sym("xdp")], block: false) }
    assert_diagnostic_shape refusal_for(ast).message, "`on :xdp`", "no `do … end` block", "module `R`"
  end

  def test_a11_on_xdp_with_an_empty_block_is_refused
    ast = reactor { |a| on_call(a, [sym("xdp")], block: :empty) }
    assert_diagnostic_shape refusal_for(ast).message, "`on :xdp`", "block is empty"
  end

  def test_a10_positive_control_on_xdp_with_a_body_classifies
    ast = reactor { |a| on_call(a, [sym("xdp")]) }
    assert_includes P.classify(ir, ast).methods.map(&:method_name), "xdp__main"
  end

  # The refusal names the declaration the way the author typed it, targets and
  # all — "somewhere in module R" is not locatable in a file with four handlers.
  def test_the_refusal_echoes_the_spelling_including_targets
    ast = reactor { |a| on_call(a, [sym("kprobe"), str("vfs_read")], block: false) }
    assert_includes refusal_for(ast).message, '`on :kprobe, "vfs_read"`'
  end

  # ---------- Z: unknown reactor kind ----------
  # This was left as an open item by an earlier audit; it was in fact already
  # refused, but as a raw Ruby backtrace. What changed is the SHAPE, so that is
  # what is pinned here.

  def test_unknown_kind_is_refused_in_the_diagnostic_shape
    ast = reactor { |a| on_call(a, [sym("no_such_kind")]) }
    msg = refusal_for(ast).message
    assert_diagnostic_shape msg, "unknown reactor event kind", ":no_such_kind"
    assert_includes msg, ":perf_event", "the refusal should enumerate the valid kinds"
  end

  # ---------- B2: `module M; include BPF::XDP; def main; end; end` ----------

  def test_b2_bodyless_method_in_a_dsl_bound_module_is_refused
    ast, body = program_with_module("R")
    inc = include_call(ast, "XDP")
    dn  = ast.node("DefNode")
    ast.s(dn, "name", "main")
    ast.r(dn, "body", -1)
    ast.a(body, "body", [inc, dn])
    assert_diagnostic_shape refusal_for(ast.parse).message, "`def main`", "empty body", "xdp__main"
  end

  def test_b2_positive_control_module_method_with_a_body_classifies
    ast, body = program_with_module("R")
    inc  = include_call(ast, "XDP")
    dn   = ast.node("DefNode")
    stmt = ast.node("StatementsNode")
    iv   = ast.node("InstanceVariableWriteNode")
    ast.s(dn, "name", "main")
    ast.r(dn, "body", stmt)
    ast.a(stmt, "body", [iv])
    ast.s(iv, "name", "@hits")
    ast.a(body, "body", [inc, dn])
    assert_includes P.classify(ir, ast.parse).methods.map(&:method_name), "xdp__main"
  end

  # ---------- C2: flat `def xdp__main; end` ----------
  # spinel reports body_id -1 for a body-less def, so the drop is one guard
  # EARLIER than the AST lookup.

  def flat_def(name, body: false)
    ast = Ast.new
    prog  = ast.node("ProgramNode")
    stmts = ast.node("StatementsNode")
    dn    = ast.node("DefNode")
    ast.r(prog, "statements", stmts)
    ast.a(stmts, "body", [dn])
    ast.s(dn, "name", name)
    if body
      st = ast.node("StatementsNode")
      iv = ast.node("InstanceVariableWriteNode")
      ast.r(dn, "body", st)
      ast.a(st, "body", [iv])
      ast.s(iv, "name", "@hits")
      [ast.parse, ["SA @meth_names 1 #{name}", "IA @meth_body_ids 1 #{st}"]]
    else
      ast.r(dn, "body", -1)
      [ast.parse, ["SA @meth_names 1 #{name}", "IA @meth_body_ids 1 -1"]]
    end
  end

  def test_c2_bodyless_attach_handler_is_refused
    ast, irl = flat_def("xdp__main")
    assert_diagnostic_shape refusal_for(ast, irl).message, "`def xdp__main`", "empty body", "never exists"
  end

  # Every attach kind the affordance advertises in flat `def` form, not just
  # xdp. A word that stopped being recognised here is a whole attach kind that
  # can go back to vanishing quietly, and nothing else would notice.
  def test_c2_every_advertised_flat_attach_kind_is_refused_when_bodyless
    checked = 0
    P::ATTACH_DECL_WORDS.each do |w|
      name = "#{w}__probe"
      ast, irl = flat_def(name)
      err = assert_raises(P::PartitionError, "`def #{name}; end` was not refused") do
        P.classify(ir(irl), ast)
      end
      assert_includes err.message, "empty body"
      checked += 1
    end
    assert_equal P::ATTACH_DECL_WORDS.size, checked
    assert_operator checked, :>, 20, "the attach vocabulary shrank; re-measure before accepting"
  end

  def test_c2_positive_control_attach_handler_with_a_body_classifies
    ast, irl = flat_def("xdp__main", body: true)
    assert_includes P.classify(ir(irl), ast).methods.map(&:method_name), "xdp__main"
  end

  # THE constraint that keeps this refusal off the corpus. `def spnl_emit(x);
  # end` is the builtin-stub shape most fixtures use (Validate documents why:
  # upstream spinel resolves the call against it), and it is body-less on
  # purpose. Only an ATTACH name declares that the program hooks something.
  def test_c2_a_bodyless_plain_method_is_still_skipped_silently
    ast, irl = flat_def("spnl_emit")
    names = P.classify(ir(irl), ast).methods.map(&:method_name)
    refute_includes names, "spnl_emit"
  end

  # ---------- D2: `class C < BPF::XDP; def main; end; end` ----------

  def class_with_parent(cname, mname, parent, body: false)
    ast = Ast.new
    prog  = ast.node("ProgramNode")
    stmts = ast.node("StatementsNode")
    cn    = ast.node("ClassNode")
    cpath = ast.node("ConstantReadNode")
    cbody = ast.node("StatementsNode")
    dn    = ast.node("DefNode")
    ast.r(prog, "statements", stmts)
    ast.a(stmts, "body", [cn])
    ast.r(cn, "constant_path", cpath)
    ast.r(cn, "body", cbody)
    ast.s(cpath, "name", cname)
    ast.a(cbody, "body", [dn])
    ast.s(dn, "name", mname)
    bid = -1
    if body
      st = ast.node("StatementsNode")
      iv = ast.node("InstanceVariableWriteNode")
      ast.a(st, "body", [iv])
      ast.s(iv, "name", "@hits")
      bid = st
    end
    ast.r(dn, "body", bid)
    [ast.parse, ["SA @cls_names 1 #{cname}",
                 "SA @cls_parents 1 #{parent}",
                 "SA @cls_meth_names 1 #{mname}",
                 "SA @cls_meth_bodies 1 #{bid}"]]
  end

  def test_d2_bodyless_method_in_a_dsl_bound_class_is_refused
    ast, irl = class_with_parent("R", "main", "BPF_XDP")
    assert_diagnostic_shape refusal_for(ast, irl).message, "`def main`", "class `R`", "xdp__main"
  end

  def test_d2_positive_control_class_method_with_a_body_classifies
    ast, irl = class_with_parent("R", "main", "BPF_XDP", body: true)
    assert_includes P.classify(ir(irl), ast).methods.map(&:method_name), "xdp__main"
  end

  # A plain class is untouched: an empty method there is just an empty method,
  # with a native execution path like any other. Narrowing to DSL-bound classes
  # is what keeps this off ordinary Ruby.
  def test_d2_a_bodyless_method_in_a_plain_class_is_still_skipped_silently
    ast, irl = class_with_parent("Counter", "reset", "")
    names = P.classify(ir(irl), ast).methods.map(&:method_name)
    refute_includes names, "reset"
  end

  # ---------- the vocabulary the refusals are derived from ----------

  # `attach_decl?` decides whether a body-less `def` is refused or dropped. It
  # reads the affordance -- the authority for what attach kinds exist -- rather
  # than CodegenBpf::ATTACH_PATTERNS, because codegen_bpf.rb requires
  # partition.rb and the other direction would be a cycle.
  #
  # It must COVER every name the codegen would treat as an attach handler.
  # Missing one is the failure this whole change is about: that handler could
  # still be dropped without a word. The probe names come from the affordance's own
  # `method_prefix` with its placeholders filled, which is how
  # tools/affordance_gate.rb builds probes — inventing `<word>__probe` instead
  # is what made the first version of this test wrong (six of the 25 words name
  # two-segment kinds, so `tracepoint__probe` is not a valid attach name).
  def test_attach_decl_covers_every_name_the_codegen_detects
    require "spinel_ebpf/codegen_bpf"
    checked = 0
    SpinelEbpf::Capabilities::ATTACH_KINDS.each do |a|
      mp = a[:method_prefix]
      next unless mp =~ /\A[a-z0-9_]+__/          # flat `def` forms only (kprobe_multi is `on :…`)
      name = mp.gsub(/<[^>]+>/, "probe")
      next unless SpinelEbpf::CodegenBpf.detect_attach(name)
      assert P.attach_decl?(name),
             "#{name}: the codegen detects this attach handler but attach_decl? does not, so a " \
             "body-less one would be dropped silently again"
      checked += 1
    end
    assert_operator checked, :>, 25, "the attach corpus shrank; re-measure before accepting"
  end

  # The over-approximation is allowed, but only in the safe direction, and it is
  # a fact worth keeping visible: `tracepoint__probe` is not a valid attach name
  # (the kind needs `<cat>__<event>`), yet a body-less one is still refused
  # rather than dropped. Measured extent: 6 of the 25 words.
  def test_attach_decl_over_approximates_only_on_two_segment_kinds
    require "spinel_ebpf/codegen_bpf"
    broader = P::ATTACH_DECL_WORDS.reject { |w| SpinelEbpf::CodegenBpf.detect_attach("#{w}__probe") }
    assert_equal %w[cgroup iter sk_skb tc tracepoint usdt], broader.sort,
                 "the set of attach words whose one-segment form is not a valid attach name " \
                 "changed. Broader is safe (a malformed attach name is refused rather than " \
                 "dropped); narrower is the bug this closed."
  end

  def test_attach_decl_does_not_fire_on_the_builtin_stub_names
    %w[spnl_emit spnl_emit_pair hist_observe pkt_len main route].each do |n|
      refute P.attach_decl?(n), "#{n}: must not be taken for an attach declaration"
    end
    # A bare kind word with nothing after it is not a declaration either.
    refute P.attach_decl?("xdp__"), "`xdp__` names no target"
  end

  # The reactor exists in two languages: BPF_EVENT_LOOP_KINDS here and
  # cc_reactor_kind() in src/codegen_c/spinel_ebpf_cc.c. A kind present here
  # and absent there is synthesized by the partition and then silently dropped
  # by the codegen — which is EXACTLY what was measured for `:timer` (the body
  # never appeared in the emitted C, and the probe still exited 0). Refusal
  # covers the shapes the partition can see; it cannot see that one, so the
  # agreement is pinned instead.
  def test_the_two_reactor_kind_tables_name_the_same_set
    c = File.read(File.expand_path("../../src/codegen_c/spinel_ebpf_cc.c", __dir__))
    table = c[/static const ReactorKind \*cc_reactor_kind.*?\n\}/m]
    refute_nil table, "cc_reactor_kind() not found — has the C reactor table moved?"
    c_kinds = table.scan(/\{"([a-z0-9_]+)",\s*"/).flatten.sort
    assert_equal P::BPF_EVENT_LOOP_KINDS.keys.sort, c_kinds,
                 "the Ruby and C reactor kind tables disagree. A kind only Ruby knows is " \
                 "synthesized and then dropped by the codegen with no diagnostic (as `:timer` was); " \
                 "a kind only C knows is refused by the partition before the codegen sees it."
  end
end
