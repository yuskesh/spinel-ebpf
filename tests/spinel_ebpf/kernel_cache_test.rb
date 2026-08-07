# frozen_string_literal: true

require "minitest/autorun"
require "spinel_ebpf/parse_spinel_ast"
require "spinel_ebpf/kernel_cache"

# What this file is, and what it is NOT.
#
# `kernel_cache` is a REFUSED surface: it was built in the retired Ruby
# generator, the C port never carried it, and it is a compile-time error now
# (Validate check (6)). So there is no live behaviour to fix here.
#
# This file used to have ten tests, and six of them pinned the behaviour of the
# refused path -- partitioning synthesizing an eBPF method the tool then refuses,
# and the retired generator's map-backed multi-route bundle. Green, and green
# about nothing anyone can reach. Worse, nothing said whether they were a RECORD
# of a retired implementation or a CONTRACT the tool still owes. Those six are
# gone; the generator's text itself is kept, in the generator, labelled (it still
# compiles and loads on a current kernel, so it is a usable reference for a port).
#
# What survives is the one thing that is still live and still consequential:
# the refusal's BLAST RADIUS. `KernelCache.declared_paths` decides which programs
# get refused. Too narrow and a `kernel_cache` form slips through to the silent
# no-op the refusal closed; too wide and a program that merely has a method named
# `kernel_cache` is refused for no reason. Both directions are tested below.
#
# The refusal's message quality is error_quality_test.rb's business
# (test_kernel_cache_directive_is_loud); that it fires at every entry point which
# runs the eBPF validator is recorded at the `mode == :native_only` return in
# bin/spinel-ebpf, the one place it deliberately does not.
class KernelCacheTest < Minitest::Test
  # Verbatim `spinel --dump-ast --no-line-map` output for:
  #   kernel_cache "/health", "OK\n"
  #   kernel_cache "/version", "spinel 1.0\n"
  TWO_DECLS = <<~AST
    ROOT 0
    SOURCE_FILE kc.rb
    N 0 ProgramNode
    N 1 StatementsNode
    N 2 CallNode
    S 2 name kernel_cache
    R 2 receiver -1
    N 3 ArgumentsNode
    N 4 StringNode
    S 4 content /health
    N 5 StringNode
    S 5 content OK%0A
    A 3 arguments 4,5
    R 2 arguments 3
    R 2 block -1
    S 2 call_operator .
    N 6 CallNode
    S 6 name kernel_cache
    R 6 receiver -1
    N 7 ArgumentsNode
    N 8 StringNode
    S 8 content /version
    N 9 StringNode
    S 9 content spinel%201.0%0A
    A 7 arguments 8,9
    R 6 arguments 7
    R 6 block -1
    S 6 call_operator .
    A 1 body 2,6
    R 0 statements 1
  AST

  # `kernel_cache "/ping", body` -- the runtime-body form. The body is not a
  # literal, and the glue that used to populate it (sp_kc_set) has been deleted,
  # so this form reaches nothing either and must still be refused.
  RUNTIME_BODY = <<~AST
    ROOT 0
    N 0 ProgramNode
    N 1 StatementsNode
    N 2 CallNode
    S 2 name kernel_cache
    R 2 receiver -1
    N 3 ArgumentsNode
    N 4 StringNode
    S 4 content /ping
    N 5 LocalVariableReadNode
    S 5 name body
    A 3 arguments 4,5
    R 2 arguments 3
    R 2 block -1
    A 1 body 2
    R 0 statements 1
  AST

  def parse(text)
    SpinelEbpf::ParseSpinelAst.parse(text)
  end

  # ---------- caught: the forms that must not slip past the refusal ----------

  # Every declaration is reported, in source order, so the message can name all
  # of them ("1 declaration(s): \"/ping\"" is the part that tells the author WHERE).
  def test_reports_every_declared_path_in_source_order
    assert_equal ["/health", "/version"],
                 SpinelEbpf::KernelCache.declared_paths(parse(TWO_DECLS))
  end

  # The second argument's type is deliberately not inspected: a runtime body is
  # still a declaration. This is the form that shipped, so it is the one most
  # likely to be written, and it reaches exactly as little as the literal one.
  def test_runtime_body_is_still_a_declaration
    assert_equal ["/ping"], SpinelEbpf::KernelCache.declared_paths(parse(RUNTIME_BODY))
  end

  # ---------- not caught: the refusal must not spread ----------

  def test_no_declarations_when_none_present
    plain = <<~AST
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
    assert_empty SpinelEbpf::KernelCache.declared_paths(parse(plain))
  end

  # `kernel_cache "/x"` (wrong arity) and `obj.kernel_cache "/y","z"` (has a
  # receiver) are somebody else's method that happens to share the name. Refusing
  # them would fail a program for a word, not for a surface.
  def test_ignores_wrong_arity_and_method_receiver
    ast = <<~AST
      ROOT 0
      N 0 ProgramNode
      N 1 StatementsNode
      N 2 CallNode
      S 2 name kernel_cache
      R 2 receiver -1
      N 3 ArgumentsNode
      N 4 StringNode
      S 4 content /x
      A 3 arguments 4
      R 2 arguments 3
      R 2 block -1
      N 5 CallNode
      S 5 name kernel_cache
      R 5 receiver 6
      N 6 CallNode
      S 6 name obj
      R 6 receiver -1
      R 6 arguments -1
      R 6 block -1
      N 7 ArgumentsNode
      N 8 StringNode
      S 8 content /y
      N 9 StringNode
      S 9 content z
      A 7 arguments 8,9
      R 5 arguments 7
      R 5 block -1
      A 1 body 2,5
      R 0 statements 1
    AST
    assert_empty SpinelEbpf::KernelCache.declared_paths(parse(ast))
  end

  # ---------- the surface has no other live consumer ----------
  #
  # The finding in one assertion: if a third caller appears in src/, either
  # someone is porting the surface back (then this file is the wrong shape) or a
  # refused surface has grown an implementation again.
  def test_the_detector_has_exactly_one_live_consumer
    src = File.expand_path("../../src/spinel_ebpf", __dir__)
    callers = Dir[File.join(src, "*.rb")].select do |f|
      File.read(f).scan(/^[^#]*KernelCache\.declared_paths/).any?
    end.map { |f| File.basename(f) }.sort
    assert_equal ["codegen_bpf.rb", "validate.rb"], callers,
                 "kernel_cache is a refused surface: validate.rb refuses it and the " \
                 "retired generator (codegen_bpf.rb, unreachable from any CLI " \
                 "invocation) keeps the record. A third caller means it is live again."
  end
end
