# frozen_string_literal: true
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/parse_spinel_ir_test.rb
#
# Tests the SPINEL-IR v1 parser against:
#   1. Synthetic IR strings (unit-level)
#   2. Real spinel-generated IR files under tests/fixtures/*.ir (if present)

require "minitest/autorun"
require "spinel_ebpf/parse_spinel_ir"

class ParseSpinelIRTest < Minitest::Test
  P = SpinelEbpf::ParseSpinelIR

  # ---------- encoding round-trip ----------

  def test_encode_basics
    assert_equal "hello",       P.encode("hello")
    assert_equal "hi%20world",  P.encode("hi world")
    assert_equal "a%7Cb",       P.encode("a|b")
    assert_equal "a%0Ab",       P.encode("a\nb")
    assert_equal "100%25",      P.encode("100%")
    # '%' must encode first so substitutes aren't double-encoded
    assert_equal "a%2520b",     P.encode("a%20b")
  end

  def test_decode_basics
    assert_equal "hello",       P.decode("hello")
    assert_equal "hi world",    P.decode("hi%20world")
    assert_equal "a|b",         P.decode("a%7Cb")
    assert_equal "a\nb",        P.decode("a%0Ab")
    assert_equal "100%",        P.decode("100%25")
    assert_equal "a%20b",       P.decode("a%2520b")
  end

  def test_encode_decode_roundtrip
    [
      "",
      "hello",
      "obj_Foo",
      "x|y|z",
      "line\nwith\nnewlines",
      "tabs\there",
      "percent 100%",
      "all\n\t\r |%",
    ].each do |s|
      assert_equal s, P.decode(P.encode(s)), "roundtrip failed for #{s.inspect}"
    end
  end

  # ---------- parse: empty IR ----------

  def test_parse_version_only
    ir = P.parse("SPINEL-IR v1\n")
    assert_equal "SPINEL-IR v1", ir.version
    assert_equal [], ir.records
  end

  # ---------- parse: scalar tags ----------

  def test_parse_int
    text = "SPINEL-IR v1\nINT @nd_count 42\nINT @needs_gc 1\n"
    ir = P.parse(text)
    assert_equal 2, ir.records.length
    assert_equal 42, ir.int("@nd_count")
    assert_equal 1,  ir.int("@needs_gc")
    assert_nil ir.int("@needs_regexp")
  end

  def test_parse_str_with_encoded_payload
    # STR carries a percent-encoded string in payload
    text = "SPINEL-IR v1\nSTR @cls_meth_live Foo::bar;Baz::qux\n"
    ir = P.parse(text)
    assert_equal "Foo::bar;Baz::qux", ir.str("@cls_meth_live")
  end

  # ---------- parse: SA / IA with count ----------

  def test_parse_sa_basic
    text = "SPINEL-IR v1\nSA @meth_names 3 foo|bar|baz\n"
    ir = P.parse(text)
    assert_equal ["foo", "bar", "baz"], ir.sa("@meth_names")
  end

  def test_parse_sa_empty_vs_single_empty
    # count=0 vs count=1 with empty element — bodies look the same, count distinguishes
    e0 = P.parse("SPINEL-IR v1\nSA @x 0 \n")
    e1 = P.parse("SPINEL-IR v1\nSA @x 1 \n")
    assert_equal [], e0.sa("@x")
    assert_equal [""], e1.sa("@x")
  end

  def test_parse_sa_with_encoded_pipe
    text = "SPINEL-IR v1\nSA @x 2 a%7Cb|c\n"
    ir = P.parse(text)
    assert_equal ["a|b", "c"], ir.sa("@x")
  end

  def test_parse_ia_basic
    text = "SPINEL-IR v1\nIA @meth_body_ids 3 42,99,-1\n"
    ir = P.parse(text)
    assert_equal [42, 99, -1], ir.ia("@meth_body_ids")
  end

  # ---------- parse: per-node tags ----------

  def test_parse_t_record
    text = "SPINEL-IR v1\nT 100 int\nT 101 obj_Foo\n"
    ir = P.parse(text)
    assert_equal 2, ir.t_records.length
    assert_equal 100, ir.t_records[0].name
    assert_equal "int", ir.t_records[0].payload
  end

  def test_parse_sn_st_pair
    text = "SPINEL-IR v1\nSN 42 x|y|z\nST 42 int|string|obj_Foo\n"
    ir = P.parse(text)
    assert_equal 1, ir.sn_records.length
    assert_equal 1, ir.st_records.length
    assert_equal 42, ir.sn_records[0].name
    assert_equal "x|y|z", ir.sn_records[0].payload
  end

  def test_parse_nm_nb_records
    text = "SPINEL-IR v1\nNM 50 __sp_ieval_3\nNB 50 -1\n"
    ir = P.parse(text)
    assert_equal "__sp_ieval_3", ir.nm_records[0].payload
    assert_equal "-1", ir.nb_records[0].payload
  end

  # IR#scope_locals decodes the SN/ST scope records into a per-body
  # { body_nid => [[name, spinel_type], ...] } table that the eBPF codegen
  # uses to type local declarations.
  def test_scope_locals_decode
    text = "SPINEL-IR v1\nSN 42 x|y|z\nST 42 int|string|obj_Foo\nSN 7 acc\nST 7 int\n"
    ir = P.parse(text)
    assert_equal([["x", "int"], ["y", "string"], ["z", "obj_Foo"]], ir.scope_locals[42])
    assert_equal([["acc", "int"]], ir.scope_locals[7])
  end

  def test_scope_locals_handles_escaped_pipe
    # spinel %-escapes the "|"-joined list; an empty payload yields no entries.
    text = "SPINEL-IR v1\nSN 1 a%7Cb\nST 1 int%7Cint\n"
    ir = P.parse(text)
    assert_equal([["a", "int"], ["b", "int"]], ir.scope_locals[1])
  end

  def test_scope_locals_empty_when_no_records
    ir = P.parse("SPINEL-IR v1\nINT @nd_count 0\n")
    assert_empty ir.scope_locals
  end

  # ---------- roundtrip ----------

  def test_roundtrip_synthetic
    input = <<~IR
      SPINEL-IR v1
      INT @nd_count 5
      INT @needs_gc 1
      STR @cls_meth_live Foo::bar
      SA @meth_names 2 foo|bar
      IA @meth_body_ids 2 1,2
      T 0 int
      T 1 string
      NM 2 __sp_ieval_0
      NB 2 -1
      SN 3 x|y
      ST 3 int|string
    IR
    ir = P.parse(input)
    assert_equal input, P.dump(ir), "roundtrip should be byte-identical"
  end

  def test_roundtrip_unknown_tag_raises
    text = "SPINEL-IR v1\nWAT 1 2 3\n"
    assert_raises(ArgumentError) { P.parse(text) }
  end

  # ---------- against real spinel fixtures (if any) ----------

  FIXTURE_DIR = File.expand_path("../fixtures", __dir__)

  def fixture_irs
    Dir.glob(File.join(FIXTURE_DIR, "*.ir"))
  end

  def test_real_fixtures_roundtrip_byte_identical
    fixtures = fixture_irs
    skip "no fixtures under #{FIXTURE_DIR} — run scripts/regen-fixtures.sh first" if fixtures.empty?

    fixtures.each do |path|
      original = File.read(path, encoding: "UTF-8")
      ir = P.parse(original)
      dumped = P.dump(ir)
      assert_equal original, dumped, "roundtrip not byte-identical for #{path}"
    end
  end

  # End-to-end check that scope_locals sources real per-local types from a
  # spinel-generated fixture (13_locals has three methods with int locals).
  # The C compiler's SN/ST records list params + body locals per scope, so the
  # three methods contribute a=b=x=y (scope 1) + n,inc,doubled (scope 2) +
  # n,acc (scope 3) — params included (the legacy Ruby analyzer's SN listed body
  # locals only).
  def test_scope_locals_real_fixture_13_locals
    path = File.join(FIXTURE_DIR, "13_locals.ir")
    skip "13_locals.ir missing" unless File.exist?(path)
    ir = P.parse(File.read(path, encoding: "UTF-8"))
    all = ir.scope_locals.values.flatten(1)
    refute_empty all, "expected scope_locals to resolve some locals"
    names = all.map(&:first).sort
    assert_equal %w[a acc b doubled inc n n x y], names
    assert(all.all? { |_, t| t == "int" }, "all 13_locals locals should infer int, got #{all.inspect}")
  end
end
