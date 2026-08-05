# frozen_string_literal: true
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/partition_test.rb

require "minitest/autorun"
require "spinel_ebpf/partition"

class PartitionTest < Minitest::Test
  P = SpinelEbpf::Partition
  FIX = File.expand_path("../fixtures", __dir__)

  def classify(name)
    P.classify_files("#{FIX}/#{name}.ir", "#{FIX}/#{name}.ast")
  end

  def tags(result)
    result.methods.to_h { |m| [m.qualified_name, m.tag] }
  end

  # ---------- per-fixture expected tag tables ----------

  def test_01_hello
    r = classify("01_hello")
    assert_equal({ "<main>" => :native }, tags(r))
    # main is native specifically because puts → uses_io
    main = r.methods.first
    assert main.flags.uses_io, "puts should mark main as uses_io"
  end

  def test_02_integer_arith
    r = classify("02_integer_arith")
    assert_equal({ "add" => :ebpf, "sub" => :ebpf, "<main>" => :native }, tags(r))
  end

  def test_03_fib_recursion_marked_recursive
    r = classify("03_fib_recursion")
    fib = r.by_qualified_name["fib"]
    refute_nil fib
    assert fib.flags.uses_recursion, "fib calls itself; uses_recursion must be true"
    assert_equal :native, fib.tag
    # main inherits unsupported from fib
    main = r.by_qualified_name["<main>"]
    assert main.flags.inherits_unsupported || main.flags.uses_io
    assert_equal :native, main.tag
  end

  def test_04_class_with_ivars_all_methods_ebpf
    r = classify("04_class_with_ivars")
    %w[Counter#initialize Counter#incr Counter#value].each do |q|
      m = r.by_qualified_name[q]
      refute_nil m, "missing #{q}"
      assert_equal :ebpf, m.tag, "#{q} should be eBPF-eligible (int + ivar only)"
    end
    assert_equal :native, r.by_qualified_name["<main>"].tag
  end

  def test_05_closure_block_top_level_method_eligible
    r = classify("05_closure_block")
    # sum_squares uses `n.times { |i| total += i*i }` — block but bounded
    # iteration. Our MVP heuristic does not mark it impossible.
    sq = r.by_qualified_name["sum_squares"]
    refute_nil sq
    assert_equal :ebpf, sq.tag, "sum_squares should be ebpf in MVP (bounded times-block)"
  end

  def test_06_regex_method_marked_unsupported
    r = classify("06_regex")
    m = r.by_qualified_name["looks_like_email?"]
    refute_nil m
    assert m.flags.uses_regex   # per-method, detected from the AST (regex literal)
    assert_equal :native, m.tag
    # NOTE: the program-wide regex warning derived from the @needs_regexp IR flag,
    # which the C compiler does not track (build_ir_text/cc_build_ir_text hardcode
    # @needs_* to 0 — the eBPF subset never uses them). Per-method AST detection
    # (uses_regex above) is the actionable signal and is unaffected.
    assert_includes m.flags.reasons.join(" "), "regex"
  end

  def test_07_float_method_marked_unsupported
    r = classify("07_float")
    m = r.by_qualified_name["circle_area"]
    refute_nil m
    assert m.flags.uses_float
    assert_equal :native, m.tag
  end

  def test_08_file_io_method_marked_io
    r = classify("08_file_io")
    m = r.by_qualified_name["read_first_line"]
    refute_nil m
    assert m.flags.uses_io
    assert_equal :native, m.tag
  end

  def test_09_string_signature_forces_native
    # The signature check rejects string / array / hash etc. — codegen_bpf can't
    # lower these as BPF params, so partition must keep such methods :native.
    # greet(name : string) -> string trips the uses_unsupported_type flag.
    r = classify("09_string_ops")
    m = r.by_qualified_name["greet"]
    refute_nil m
    assert m.flags.uses_unsupported_type
    assert_equal :native, m.tag
  end

  def test_10_polymorphic_methods_all_ebpf
    r = classify("10_polymorphic")
    %w[Shape#area Square#initialize Square#area Triangle#initialize Triangle#area].each do |q|
      m = r.by_qualified_name[q]
      refute_nil m, "missing #{q}"
      assert_equal :ebpf, m.tag, "#{q} should be ebpf-eligible"
    end
    assert_equal :native, r.by_qualified_name["<main>"].tag
  end

  # ---------- signature-based float detection ----------

  def test_indirect_float_detected_via_signature
    r = classify("23_indirect_float")
    indirect = r.by_qualified_name["needs_float_indirect"]
    refute_nil indirect
    assert indirect.flags.uses_float, "needs_float_indirect has float param/return per IR"
    assert_equal :native, indirect.tag
    # pure_int should stay :ebpf (signature is int,int → int)
    pure = r.by_qualified_name["pure_int"]
    refute_nil pure
    refute pure.flags.uses_float
    assert_equal :ebpf, pure.tag
  end

  # ---------- flag-level checks ----------

  def test_no_false_positive_io_in_pure_int_method
    r = classify("02_integer_arith")
    add = r.by_qualified_name["add"]
    refute add.flags.uses_io,    "add() does not perform I/O"
    refute add.flags.uses_float, "add() does not use Float"
  end

  def test_walker_does_not_traverse_integer_literals
    # Regression: integer literal value=0 must not be mistaken for ref to node 0.
    # If the walker were following literals, Counter#initialize (`@count = 0`)
    # would visit the entire ProgramNode tree and pick up `puts c.value`.
    r = classify("04_class_with_ivars")
    init = r.by_qualified_name["Counter#initialize"]
    refute init.flags.uses_io, "Counter#initialize must not see puts via literal 0 leak"
  end

  # ---------- nullable (`int?`) signatures ----------
  #
  # spinel infers a *nullable* return (`int?`) for any method whose body is
  # `if ... end` without an explicit `else` -- the implicit nil branch. That is
  # the single most common attach-handler shape (`if cond; spnl_emit(x); end`).
  # Nullability is orthogonal to eBPF type-eligibility: a nullable int still
  # lowers to __s64 (nil -> 0). Previously `int?` fell through to the
  # "non-int type" rejection and forced the whole handler :native.

  # Minimal IR stand-in: signature_types only ever calls ir.sa(key).
  class StubIR
    def initialize(h) = @h = h
    def sa(k) = @h[k]
  end

  def refine(method_name, ptypes, rtype)
    flags = P::MethodFlags.default
    mi = P::MethodInfo.new(scope: :top_level, method_name: method_name, flags: flags)
    ir = StubIR.new(
      "@meth_names"        => [method_name],
      "@meth_param_types"  => [ptypes],
      "@meth_return_types" => [rtype],
    )
    P.refine_flags_from_signature(mi, ir)
    mi.flags
  end

  def test_nullable_int_return_stays_ebpf_eligible
    f = refine("kprobe__tcp_sendmsg", "int,int,int", "int?")
    refute f.uses_unsupported_type,
           "int? (nullable int from `if…end`) must NOT disqualify a handler"
    refute f.ebpf_impossible?
  end

  def test_nullable_string_return_still_native
    f = refine("greet", "string", "string?")
    assert f.uses_unsupported_type,
           "string? must still be rejected (heap string, not eBPF-legal)"
  end

  def test_nullable_float_return_still_trips_float
    f = refine("f", "int", "float?")
    assert f.uses_float, "float? must still trip uses_float (no FPU in BPF)"
  end

  def test_plain_int_signature_unaffected
    f = refine("add", "int,int", "int")
    refute f.uses_unsupported_type
    refute f.ebpf_impossible?
  end

  def test_fixture_conditional_kprobe_is_ebpf
    # Real spinel-generated fixture: `if size > 256; spnl_emit(size); end`
    # in a kprobe handler -> spinel infers `int?` return. Must stay :ebpf.
    r = classify("97_kprobe_conditional_emit")
    m = r.by_qualified_name["kprobe__tcp_sendmsg"]
    refute_nil m
    refute m.flags.uses_unsupported_type,
           "int? return from `if…end` must not disqualify the kprobe handler"
    assert_equal :ebpf, m.tag
  end

  # ---------- API shape sanity ----------

  def test_classify_returns_result_with_methods_and_warnings
    r = classify("06_regex")
    assert_kind_of Array, r.methods
    assert_kind_of Array, r.program_warnings
    r.methods.each do |m|
      assert_includes [:ebpf, :native], m.tag
      assert [:top_level, :class, :main].include?(m.scope)
    end
  end

  # ---------- BPF namespace fail-fast ----------
  # A construct that names the BPF plugin namespace but an UNKNOWN member must
  # raise PartitionError, not silently fall back to native / drop the handler
  # (no silent fallback). Inputs are built inline so the broken shapes need no
  # committed fixtures.
  PE = SpinelEbpf::Partition::PartitionError

  def parse_ir(lines)  = SpinelEbpf::ParseSpinelIR.parse(lines.join("\n") + "\n")
  def parse_ast(lines) = SpinelEbpf::ParseSpinelAst.parse(lines.join("\n") + "\n")

  EMPTY_AST_LINES = ["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
                     "R 0 statements 1", "A 1 body "].freeze
  EMPTY_IR_LINES  = ["SPINEL-IR v1", "SA @meth_names 0 ", "IA @meth_body_ids 0 ",
                     "SA @cls_names 0 ", "SA @cls_parents 0 ",
                     "SA @cls_meth_names 0 ", "SA @cls_meth_bodies 0 "].freeze

  # `module Foo; include BPF::<inc>; <tail nodes, ids start at 9>; end`
  def module_ast(inc, tail)
    parse_ast(["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
               "R 0 statements 1", "A 1 body 2",
               "N 2 ModuleNode", "N 3 ConstantReadNode", "S 3 name Foo",
               "R 2 constant_path 3", "N 4 StatementsNode", "R 2 body 4",
               "A 4 body 5,9",
               "N 5 CallNode", "S 5 name include", "R 5 receiver -1",
               "N 6 ArgumentsNode", "N 7 ConstantPathNode", "N 8 ConstantReadNode",
               "S 8 name BPF", "R 7 parent 8", "S 7 name #{inc}",
               "A 6 arguments 7", "R 5 arguments 6", "R 5 block -1"] + tail)
  end

  def test_phase2_unknown_class_base_raises
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 0 ", "IA @meth_body_ids 0 ",
                   "SA @cls_names 1 Bogus", "SA @cls_parents 1 BPF_Bogus",
                   "SA @cls_meth_names 1 handle", "SA @cls_meth_bodies 1 1"])
    e = assert_raises(PE) { P.classify(ir, parse_ast(EMPTY_AST_LINES)) }
    assert_match(/unknown BPF DSL base class `BPF::Bogus`/, e.message)
  end

  def test_phase2_unknown_include_raises
    ast = module_ast("Unknown", ["N 9 DefNode", "S 9 name foo", "R 9 body 1"])
    e = assert_raises(PE) { P.classify(parse_ir(EMPTY_IR_LINES), ast) }
    assert_match(/unknown BPF DSL module `BPF::Unknown`/, e.message)
  end

  def test_phase2_unknown_reactor_kind_raises
    ast = module_ast("EventLoop",
                     ["N 9 CallNode", "S 9 name on", "R 9 receiver -1",
                      "N 10 ArgumentsNode", "N 11 SymbolNode", "S 11 value bogus",
                      "A 10 arguments 11", "R 9 arguments 10",
                      "N 12 BlockNode", "R 9 block 12",
                      "N 13 StatementsNode", "R 12 body 13", "A 13 body "])
    e = assert_raises(PE) { P.classify(parse_ir(EMPTY_IR_LINES), ast) }
    assert_match(/unknown reactor event kind `on :bogus`/, e.message)
  end

  # A non-BPF superclass is OUTSIDE the namespace -> stays native, no raise.
  # The AST has to actually contain `class Widget; def handle; end; end` -- the
  # enumeration reads the body out of the AST now, so an IR naming code the AST
  # does not have enumerates nothing (which is the whole point).
  def test_phase2_non_bpf_superclass_stays_native
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 0 ", "IA @meth_body_ids 0 ",
                   "SA @cls_names 1 Widget", "SA @cls_parents 1 PlainBase",
                   "SA @cls_meth_names 1 handle", "SA @cls_meth_bodies 1 1"])
    res = P.classify(ir, parse_ast(class_ast("Widget", "handle"))) # must not raise
    assert(res.methods.any? { |m| m.qualified_name == "Widget#handle" },
           "non-BPF class method should be enumerated, not error")
  end

  # ---------- the IR's body ids are ids in the IR's OWN parse ----------
  #
  # The .ast and the .ir come from two different spinel invocations, and a plain
  # `require` resolves relative to the running executable -- so the two parses can
  # be handed different source text and number their nodes differently (a
  # 1216-node shift was measured on examples/http_server/so-reuseport/server.rb). The IR
  # says WHICH methods exist; the AST says WHERE the body is.

  # `def <name>; <body stmts>; end` at top level, ids from 2.
  def toplevel_def_ast(name, body_lines = ["A 4 body "])
    ["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
     "R 0 statements 1", "A 1 body 2",
     "N 2 DefNode", "S 2 name #{name}", "N 3 ParametersNode",
     "R 2 parameters 3", "N 4 StatementsNode", "R 2 body 4"] + body_lines
  end

  # `class <cls>; def <meth>; end; end`
  def class_ast(cls, meth)
    ["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
     "R 0 statements 1", "A 1 body 2",
     "N 2 ClassNode", "N 3 ConstantReadNode", "S 3 name #{cls}",
     "R 2 constant_path 3", "R 2 superclass -1",
     "N 4 StatementsNode", "R 2 body 4", "A 4 body 5",
     "N 5 DefNode", "S 5 name #{meth}", "N 6 ParametersNode",
     "R 5 parameters 6", "N 7 StatementsNode", "R 5 body 7", "A 7 body "]
  end

  def test_body_comes_from_the_ast_not_the_ir_id
    # The IR claims `probe`'s body is node 999 -- an id from a parse this AST is
    # not. Resolution must land on the DefNode's real body (4), not on 999.
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 1 probe", "IA @meth_body_ids 1 999",
                   "SA @cls_names 0 ", "SA @cls_parents 0 ",
                   "SA @cls_meth_names 0 ", "SA @cls_meth_bodies 0 "])
    res = P.classify(ir, parse_ast(toplevel_def_ast("probe")))
    m = res.by_qualified_name["probe"]
    refute_nil m, "probe must still be enumerated -- the IR is the authority on existence"
    assert_equal 4, m.body_id
  end

  # The failure in miniature: the id the IR reports is a REAL node here, so
  # nothing crashes -- it is simply a different method's body, and the flags come
  # out of the wrong code. Walking node 4 sees `loop`; walking node 8 does not.
  def test_shifted_id_would_read_another_methods_body
    ast_lines = ["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
                 "R 0 statements 1", "A 1 body 2,6",
                 # def spliced_in;  loop do ... end ; end
                 "N 2 DefNode", "S 2 name spliced_in", "N 3 ParametersNode",
                 "R 2 parameters 3", "N 4 StatementsNode", "R 2 body 4", "A 4 body 5",
                 "N 5 CallNode", "S 5 name loop", "R 5 receiver -1",
                 # def probe; end
                 "N 6 DefNode", "S 6 name probe", "N 7 ParametersNode",
                 "R 6 parameters 7", "N 8 StatementsNode", "R 6 body 8", "A 8 body "]
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 1 probe", "IA @meth_body_ids 1 4",
                   "SA @cls_names 0 ", "SA @cls_parents 0 ",
                   "SA @cls_meth_names 0 ", "SA @cls_meth_bodies 0 "])
    m = P.classify(ir, parse_ast(ast_lines)).by_qualified_name["probe"]
    assert_equal 8, m.body_id, "must resolve `probe`, not the body the stale id points at"
    refute m.flags.uses_unbounded_loop,
           "`loop` belongs to spliced_in -- reading it as probe's is exactly the bug"
    assert_equal :ebpf, m.tag
  end

  # Same bare name at two scopes: the class table must not pick up the top-level
  # `def initialize`, which is what a whole-AST name search would do.
  def test_scope_disambiguates_same_name
    ast_lines = ["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
                 "R 0 statements 1", "A 1 body 2,6",
                 "N 2 DefNode", "S 2 name handle", "N 3 ParametersNode",
                 "R 2 parameters 3", "N 4 StatementsNode", "R 2 body 4", "A 4 body 5",
                 "N 5 CallNode", "S 5 name loop", "R 5 receiver -1",
                 "N 6 ClassNode", "N 7 ConstantReadNode", "S 7 name Widget",
                 "R 6 constant_path 7", "R 6 superclass -1",
                 "N 8 StatementsNode", "R 6 body 8", "A 8 body 9",
                 "N 9 DefNode", "S 9 name handle", "N 10 ParametersNode",
                 "R 9 parameters 10", "N 11 StatementsNode", "R 9 body 11", "A 11 body "]
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 1 handle", "IA @meth_body_ids 1 4",
                   "SA @cls_names 1 Widget", "SA @cls_parents 1 ",
                   "SA @cls_meth_names 1 handle", "SA @cls_meth_bodies 1 11"])
    r = P.classify(ir, parse_ast(ast_lines))
    assert_equal 4,  r.by_qualified_name["handle"].body_id
    assert_equal 11, r.by_qualified_name["Widget#handle"].body_id
    assert r.by_qualified_name["handle"].flags.uses_unbounded_loop
    refute r.by_qualified_name["Widget#handle"].flags.uses_unbounded_loop
  end

  # Redefinition: Ruby keeps the last one, and spinel's flatten numbers a later
  # sibling higher -- so `.last` is the definition that actually runs.
  def test_redefinition_resolves_to_the_last_definition
    ast_lines = ["ROOT 0", "N 0 ProgramNode", "N 1 StatementsNode",
                 "R 0 statements 1", "A 1 body 2,6",
                 "N 2 DefNode", "S 2 name probe", "N 3 ParametersNode",
                 "R 2 parameters 3", "N 4 StatementsNode", "R 2 body 4", "A 4 body 5",
                 "N 5 CallNode", "S 5 name loop", "R 5 receiver -1",
                 "N 6 DefNode", "S 6 name probe", "N 7 ParametersNode",
                 "R 6 parameters 7", "N 8 StatementsNode", "R 6 body 8", "A 8 body "]
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 1 probe", "IA @meth_body_ids 1 4",
                   "SA @cls_names 0 ", "SA @cls_parents 0 ",
                   "SA @cls_meth_names 0 ", "SA @cls_meth_bodies 0 "])
    m = P.classify(ir, parse_ast(ast_lines)).by_qualified_name["probe"]
    assert_equal 8, m.body_id
    refute m.flags.uses_unbounded_loop
  end

  # A method the IR names but the AST does not define is dropped rather than
  # given somebody else's body -- the enumeration cannot invent a location.
  def test_unresolvable_name_is_not_enumerated
    ir = parse_ir(["SPINEL-IR v1", "SA @meth_names 1 ghost", "IA @meth_body_ids 1 4",
                   "SA @cls_names 0 ", "SA @cls_parents 0 ",
                   "SA @cls_meth_names 0 ", "SA @cls_meth_bodies 0 "])
    res = P.classify(ir, parse_ast(toplevel_def_ast("probe")))
    assert_nil res.by_qualified_name["ghost"]
  end
end
