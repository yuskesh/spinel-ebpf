# frozen_string_literal: true
#
# Runtime parameters -- `param :name, default: N`.
#
# The thing being defended is narrow and specific: ONE binary must be able to
# behave two ways, and the compiler must refuse every shape where an operator
# could turn a knob and be lied to. So the tests split into three groups:
#
#   1. the declaration is read the same way by the two readers of it (the C
#      codegen, which owns the contract, and the Ruby side, which generates the
#      loader and `describe`) -- drift between them is the failure this feature is
#      most exposed to, since each reads the source independently;
#   2. `volatile` survives into the emitted C. Dropping it is silent: -O2 folds
#      the value at compile time, the skeleton has nothing to patch, and every
#      run behaves like the default. Nothing else in the pipeline would notice;
#   3. the refusals, and their wording -- a message that does not say what to do
#      instead is not a refusal, it is a complaint.
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/param_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/parse_spinel_ast"
require "spinel_ebpf/param"
require "spinel_ebpf/introspect"
require "spinel_ebpf/capabilities"

class ParamTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  P    = SpinelEbpf::Param

  # Same preflight golden.rb uses: build/ is bind-mounted into the container, so
  # +x does not mean runnable here.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def skip_unless_cc
    skip "C codegen binary not runnable on this host" unless self.class.runnable?
  end

  def run_cc(base)
    Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
  end

  def ast(base) = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{base}.ast")
  def src(base) = File.read("#{FIX}/#{base}.rb", encoding: "UTF-8")

  # ---- 1. the declaration, and the two readers of it ------------------------

  def test_declarations_from_ast
    ds = P.declarations(ast("126_runtime_param"))
    assert_equal %w[target_pid min_dfd], ds.map(&:name), "declaration order is the emission order"
    assert_equal [0, 0], ds.map(&:default)
  end

  def test_default_is_optional_and_means_zero
    # `param :min_dfd` carries no keyword. 0 is not a fallback chosen for
    # convenience: it is the value that makes a guard on the parameter vanish
    # from the verified program, so "not set" and "off" are the same state.
    ds = P.declarations(ast("126_runtime_param"))
    assert_equal 0, ds.find { |d| d.name == "min_dfd" }.default
    assert_equal 0, P::IMPLICIT_DEFAULT
  end

  def test_c_symbol_and_env_name
    d = P.declarations(ast("126_runtime_param")).first
    assert_equal "spnl_param_target_pid", d.c_symbol
    assert_equal "SPNL_PARAM_TARGET_PID", d.env_name
  end

  # The source scan (used by `describe`, which must work on a file that does not
  # compile) has to agree with the AST scan (used by the loader generator).
  def test_source_scan_agrees_with_ast_scan
    %w[126_runtime_param 127_param_unused].each do |base|
      from_ast = P.declarations(ast(base)).map { |d| [d.name, d.default] }
      from_src = P.scan_source(src(base)).map { |h| [h[:name], h[:default]] }
      assert_equal from_ast, from_src, "#{base}: the two readers disagree"
    end
  end

  def test_negative_default_is_carried_through
    a = SpinelEbpf::ParseSpinelAst.parse(<<~AST)
      ROOT 0
      N 0 ProgramNode
      N 1 StatementsNode
      N 2 CallNode
      S 2 name param
      R 2 receiver -1
      N 3 ArgumentsNode
      N 4 SymbolNode
      S 4 value skew
      N 5 KeywordHashNode
      N 6 AssocNode
      N 7 SymbolNode
      S 7 value default
      N 8 IntegerNode
      I 8 value -5
      R 6 key 7
      R 6 value 8
      A 5 elements 6
      A 3 arguments 4,5
      R 2 arguments 3
      A 1 body 2
      R 0 statements 1
    AST
    assert_equal [["skew", -5]], P.declarations(a).map { |d| [d.name, d.default] }
  end

  def test_a_method_call_named_param_on_a_receiver_is_not_a_declaration
    # `cfg.param :x` is somebody else's method. Only the bare top-level form is a
    # declaration, the same rule kernel_cache uses.
    a = SpinelEbpf::ParseSpinelAst.parse(<<~AST)
      ROOT 0
      N 0 ProgramNode
      N 1 StatementsNode
      N 2 CallNode
      S 2 name param
      R 2 receiver 9
      N 9 CallNode
      S 9 name cfg
      R 9 receiver -1
      N 3 ArgumentsNode
      N 4 SymbolNode
      S 4 value x
      A 3 arguments 4
      R 2 arguments 3
      A 1 body 2
      R 0 statements 1
    AST
    assert_empty P.declarations(a)
  end

  def test_referenced_ignores_the_declaration_line_itself
    assert P.referenced?(src("126_runtime_param"), "target_pid")
    refute P.referenced?(src("127_param_unused"), "verbosity"),
           "the declaration line must not count as a use of the parameter"
  end

  # The native pass gets the declarations neutralised (spinel's own codegen
  # refuses the call). Line-for-line, because #line directives in the emitted C
  # point at the file we hand spinel.
  def test_strip_preserves_line_count_and_removes_the_declaration
    s = src("126_runtime_param")
    stripped = P.strip_declarations(s)
    assert_equal s.lines.length, stripped.lines.length
    refute P.present?(stripped)
    assert P.present?(s)
    assert_includes stripped, "def tracepoint__syscalls__sys_enter_openat(dfd)"
  end

  # ---- 2. what the codegen emits -------------------------------------------

  def test_emits_volatile_const_in_declaration_order
    skip_unless_cc
    out, err, st = run_cc("126_runtime_param")
    assert st.success?, err
    assert_includes out, "volatile const __s64 spnl_param_target_pid = 0;"
    assert_includes out, "volatile const __s64 spnl_param_min_dfd = 0;"
    assert_operator out.index("spnl_param_target_pid ="), :<, out.index("spnl_param_min_dfd ="),
                    "emission order must follow declaration order (it is the .rodata layout)"
  end

  # The one that cannot be caught downstream. Without `volatile`, -O2 folds the
  # read at compile time: the C still compiles, the program still loads, the
  # golden still looks plausible, and every run silently behaves like the
  # default. Nothing else in the pipeline distinguishes the two.
  def test_volatile_is_not_optional
    skip_unless_cc
    out, = run_cc("126_runtime_param")
    out.each_line do |l|
      next unless l.include?("spnl_param_") && l.include?("__s64") && l.strip.end_with?(";")
      assert l.start_with?("volatile const "),
             "a parameter must be `volatile const`, got: #{l.strip}"
    end
  end

  def test_reference_lowers_to_the_rodata_symbol_not_a_local
    skip_unless_cc
    out, = run_cc("126_runtime_param")
    body = out[/_inner\(__s64 dfd\).*/m].to_s
    assert_includes body, "spnl_param_target_pid == 0"
    assert_includes body, "dfd >= spnl_param_min_dfd"
    refute_match(/__s64 target_pid = 0;/, body, "must not become a zeroed local")
  end

  def test_a_program_without_params_emits_no_rodata_section
    skip_unless_cc
    out, = run_cc("17_kprobe")
    refute_includes out, "volatile const"
    refute_includes out, "runtime parameters"
  end

  # ---- 3. the refusals, and how they read ----------------------------------

  def test_unused_parameter_is_refused_with_the_env_var_and_a_fix
    skip_unless_cc
    _out, err, st = run_cc("127_param_unused")
    refute st.success?, "a parameter nothing reads must not compile"
    assert_includes err, "verbosity",              "name the parameter"
    assert_includes err, "SPNL_PARAM_VERBOSITY",   "name the switch that would do nothing"
    assert_includes err, "would change nothing",   "say what the consequence is"
    assert_includes err, "delete the declaration", "offer a way out"
    assert_includes err, "builtin wins",           "name the non-obvious cause (a shadowed name)"
  end

  def test_non_literal_default_is_refused_with_the_reason
    skip_unless_cc
    _out, err, st = run_cc("128_param_bad_default")
    refute st.success?
    assert_includes err, "min_size"
    assert_includes err, "integer literal"
    assert_includes err, ".rodata",  "say WHY a literal (it is baked in at compile time)"
  end

  def test_refused_fixtures_have_no_golden
    %w[127_param_unused 128_param_bad_default].each do |b|
      refute File.exist?(File.join(GOLD, "#{b}.bpf.c")),
             "#{b} is refused, so a golden for it is output that can no longer be produced"
    end
  end

  # ---- introspection --------------------------------------------------------

  def test_describe_lists_the_parameters_and_their_env_vars
    r = SpinelEbpf::Introspect.report(src("126_runtime_param"), "126_runtime_param.rb")
    assert_includes r, "runtime parameters"
    assert_includes r, "target_pid"
    assert_includes r, "SPNL_PARAM_TARGET_PID"
    assert_includes r, "SPNL_PARAM_MIN_DFD"
  end

  def test_describe_warns_when_nothing_reads_a_parameter
    r = SpinelEbpf::Introspect.report(src("127_param_unused"), "127_param_unused.rb")
    assert_match(/param :verbosity .*SPNL_PARAM_VERBOSITY/m, r)
    assert_includes r, "changes nothing"
  end

  def test_describe_is_silent_for_a_program_without_parameters
    r = SpinelEbpf::Introspect.report(src("17_kprobe"), "17_kprobe.rb")
    refute_includes r, "runtime parameters"
  end

  def test_capabilities_publishes_the_param_surface
    a = SpinelEbpf::Capabilities.affordance
    rp = a[:runtime_params]
    refute_nil rp, "an AI that does not know `param` exists rewrites the whole probe to change a pid"
    assert_includes rp[:form], "param :<name>"
    assert_includes rp[:set_by], "SPNL_PARAM_"
    assert_includes rp[:kernel_floor], "5.2"
    # The tempting misuse has to be named, not merely absent.
    assert_includes rp[:not_for], "frozen"
    assert_operator rp[:refused].length, :>=, 5
  end

  # capabilities.rb deliberately requires nothing (see its header), so the
  # implicit default is written there as a literal. This is the drift check that
  # buys the right to do that.
  def test_capabilities_default_matches_the_implementation
    assert_equal P::IMPLICIT_DEFAULT,
                 SpinelEbpf::Capabilities::RUNTIME_PARAMS[:default_when_omitted]
  end

  # ---- the portability claim ------------------------------------------------
  #
  # The whole design rests on the floor being one eBPF already needs. If a future
  # change makes .rodata patching cost more than the base, that is a contract
  # change and must be argued, not discovered.
  def test_parameters_do_not_raise_the_kernel_floor
    require "spinel_ebpf/portability"
    assert_equal "5.2", SpinelEbpf::Portability::BASE_EBPF_KERNEL
    refute SpinelEbpf::Portability::MIN_KERNEL.key?("param"),
           "a parameter needs no feature beyond the base (read-only map + BPF_MAP_FREEZE, 5.2)"
  end
end
