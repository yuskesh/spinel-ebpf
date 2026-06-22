# frozen_string_literal: true
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/parse_spinel_ast_test.rb

require "minitest/autorun"
require "spinel_ebpf/parse_spinel_ast"

class ParseSpinelAstTest < Minitest::Test
  P = SpinelEbpf::ParseSpinelAst

  # ---------- escape/unescape ----------

  def test_escape_basics
    assert_equal "hello",            P.escape_str("hello")
    assert_equal "hi\\nworld",       P.escape_str("hi\nworld")
    assert_equal "a\\tb",            P.escape_str("a\tb")
    assert_equal "back\\\\slash",    P.escape_str("back\\slash")
    assert_equal "she said \\\"hi\\\"", P.escape_str('she said "hi"')
    assert_equal "x\\0y",            P.escape_str("x\0y")
  end

  def test_escape_unescape_roundtrip
    [
      "",
      "plain",
      "with\nnewline",
      "tab\there",
      "back\\slash",
      "quote \"in\" middle",
      "null\0byte",
      "all\n\t\\\"\0mix",
      "UTF-8: 日本語",
    ].each do |s|
      assert_equal s, P.unescape_str(P.escape_str(s)), "roundtrip failed for #{s.inspect}"
    end
  end

  # ---------- basic parse ----------

  def test_parse_root_only_is_invalid_without_records
    # Spec implies first line is ROOT; minimal valid AST has at least ROOT.
    ast = P.parse("ROOT 0\nN 0 ProgramNode\n")
    assert_equal 0, ast.root_id
    assert_equal "ProgramNode", ast.type_of(0)
  end

  def test_parse_call_node_example
    # From AST.md §Example, "puts \"hi\"":
    text = <<~AST
      ROOT 0
      N 0 ProgramNode
      N 1 StatementsNode
      N 2 CallNode
      S 2 name puts
      R 2 receiver -1
      N 3 ArgumentsNode
      N 4 StringNode
      S 4 content hi
      A 3 arguments 4
      R 2 arguments 3
      R 2 block -1
      A 1 body 2
      R 0 statements 1
    AST
    ast = P.parse(text)
    assert_equal "ProgramNode", ast.type_of(0)
    assert_equal "CallNode",    ast.type_of(2)
    assert_equal "puts",        ast.name_of(2)
    assert_equal(-1, ast.receiver_of(2))
    assert_equal 3, ast.arguments_of(2)
    assert_equal "hi", ast.attr(4, "content")
    assert_equal [4], ast.attr(3, "arguments")
    assert_equal [2], ast.body_array_of(1)
  end

  def test_parse_handles_integer_value
    text = "ROOT 0\nN 0 IntegerNode\nI 0 value 42\n"
    ast = P.parse(text)
    assert_equal 42, ast.attr(0, "value")
  end

  def test_parse_handles_float_value
    text = "ROOT 0\nN 0 FloatNode\nF 0 value 3.14159\n"
    ast = P.parse(text)
    assert_in_delta 3.14159, ast.attr(0, "value"), 1e-9
  end

  def test_parse_handles_empty_array_body
    # A record with empty body = "[]"
    text = "ROOT 0\nN 0 StatementsNode\nA 0 body \n"
    ast = P.parse(text)
    assert_equal [], ast.body_array_of(0)
  end

  def test_parse_string_with_escapes
    # spinel encodes newline as \\n; unescape should recover "\n"
    text = "ROOT 0\nN 0 StringNode\nS 0 content hi\\nworld\n"
    ast = P.parse(text)
    assert_equal "hi\nworld", ast.attr(0, "content")
  end

  def test_parse_unknown_tag_raises
    text = "ROOT 0\nWAT 1 something\n"
    assert_raises(ArgumentError) { P.parse(text) }
  end

  def test_parse_attribute_before_node_raises
    # S record for an id with no preceding N record
    text = "ROOT 0\nS 99 name foo\n"
    assert_raises(ArgumentError) { P.parse(text) }
  end

  # ---------- round-trip on real spinel-generated fixtures ----------

  FIXTURE_DIR = File.expand_path("../fixtures", __dir__)

  def test_real_fixtures_roundtrip_byte_identical
    asts = Dir.glob(File.join(FIXTURE_DIR, "*.ast"))
    skip "no .ast fixtures — run scripts/regen-fixtures.sh first" if asts.empty?

    asts.each do |path|
      original = File.read(path, encoding: "UTF-8")
      ast = P.parse(original)
      assert_equal original, P.dump(ast), "round-trip not byte-identical for #{path}"
    end
  end
end
