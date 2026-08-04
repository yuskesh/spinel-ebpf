# frozen_string_literal: true
#
# The in-kernel common filter -- `filter_by :pid, :comm`.
#
# What is being defended is a claim about COVERAGE, not about narrowing: one
# declaration narrows every attach handler in the unit, or the build fails.
# A probe narrowed in three handlers out of four still reports everything, and
# that failure is invisible to every gate this project has (measured: the channel
# balance report can say "nothing came out", never "the wrong things came out").
# So the tests split into four groups:
#
#   1. the declaration is read the same way by its two readers -- the C codegen,
#      which owns the contract, and the Ruby side, which generates the loader and
#      `describe`. Each reads the source independently, so drift between the two
#      key tables is the failure this feature is most exposed to;
#   2. every eligible handler gets the guard, and the guard sits in the WRAPPER
#      (not the inner), so a BPF-to-BPF call is not filtered twice;
#   3. the dead-code shape: each key's test is nested inside "is this key set",
#      which is what lets the verifier drop the helper call and not just the
#      comparison. A flattened emission would still be correct and would silently
#      cost a helper call per event;
#   4. the refusals and their wording -- a message that does not say what to do
#      instead is a complaint, not a refusal.
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/common_filter_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/parse_spinel_ast"
require "spinel_ebpf/common_filter"
require "spinel_ebpf/param"
require "spinel_ebpf/introspect"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/codegen_bpf"
require "spinel_ebpf/portability"

class CommonFilterTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CF   = SpinelEbpf::CommonFilter

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
  def gold(base) = File.read(File.join(GOLD, "#{base}.bpf.c"), encoding: "UTF-8")

  # ---- 1. the declaration, and the two readers of it ------------------------

  def test_declarations_from_ast
    ks = CF.declarations(ast("129_common_filter")).map(&:name)
    assert_equal %w[pid comm], ks
    assert_equal %w[pid tid uid gid cgroup_id comm],
                 CF.declarations(ast("130_common_filter_all")).map(&:name)
  end

  def test_no_declaration_is_not_an_error
    assert_empty CF.declarations(ast("126_runtime_param"))
    refute CF.present?(src("126_runtime_param"))
  end

  def test_source_scan_agrees_with_the_ast_scan
    # `describe` reads raw source because it must work on a file that does not
    # compile. Two scanners of one declaration is a drift risk; this pins them
    # together on the fixtures that have the declaration.
    %w[129_common_filter 130_common_filter_all].each do |b|
      from_ast = CF.declarations(ast(b)).map(&:name)
      from_src = CF.scan_source(src(b)).flat_map { |d| d[:keys] }
      assert_equal from_ast, from_src, "#{b}: source scan != AST scan"
    end
  end

  def test_env_names_and_symbols_are_mechanical
    k = CF::KEYS_BY_NAME.fetch("cgroup_id")
    assert_equal "SPNL_FILTER_CGROUP_ID", k.env_name
    assert_equal "spnl_filter_cgroup_id", k.c_symbol
    refute k.string?
    assert CF::KEYS_BY_NAME.fetch("comm").string?
  end

  # The two key tables (Ruby here, CC_FILTER_KEYS in the C codegen) are written
  # out separately because each side needs different columns. Same names, same
  # ORDER, same unset sentinel -- anything else and the loader would patch a
  # symbol the kernel is not testing, or `describe` would print the wrong "unset".
  def test_key_table_matches_the_c_codegen
    c = File.read(File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c"), encoding: "UTF-8")
    tbl = c[/static const CcFilterKey CC_FILTER_KEYS\[\] = \{(.+?)\n\};/m, 1]
    refute_nil tbl, "CC_FILTER_KEYS table not found in the C codegen"
    rows = tbl.scan(/\{\s*"([a-z_]+)",\s*"([a-z_]+)",\s*"([A-Z_]+)",\s*"([^"]*)"/)
    assert_equal CF::KEYS.map(&:name), rows.map { |r| r[0] }, "key names/order drifted"
    rows.each do |name, sym, env, init|
      k = CF::KEYS_BY_NAME.fetch(name)
      assert_equal k.c_symbol, sym, "#{name}: C symbol drifted"
      assert_equal k.env_name, env, "#{name}: env var drifted"
      next if k.string?   # "{}" in C, "" in Ruby: same emptiness, different syntax
      assert_equal k.unset.to_s, init, "#{name}: unset sentinel drifted"
    end
  end

  # uid/gid alone among the keys use -1, and the reason is not stylistic: uid 0
  # is root, so 0 cannot mean "unset" without making root unselectable.
  def test_uid_and_gid_are_unset_at_minus_one
    assert_equal(-1, CF::KEYS_BY_NAME.fetch("uid").unset)
    assert_equal(-1, CF::KEYS_BY_NAME.fetch("gid").unset)
    assert_equal 0,  CF::KEYS_BY_NAME.fetch("pid").unset
  end

  # ---- 2. coverage: every eligible handler, in the wrapper ------------------

  def test_every_attach_handler_gets_the_guard
    g = gold("129_common_filter")
    wrappers = g.scan(/^int (\w+)\((?:struct pt_regs|void) \*ctx\)$/).flatten
    assert_equal 2, wrappers.length, "fixture should have two attach handlers"
    assert_equal 2, g.scan(/if \(spnl_filter_discard\(\)\) return 0;/).length,
                 "the declaration must reach EVERY handler -- that is the whole feature"
  end

  # The guard belongs to the wrapper, not the _inner: an _inner can also be
  # called BPF-to-BPF, where filtering again would be both wrong and
  # invisible. It also runs before the argument extractors, so a discarded event
  # skips their probe_reads.
  def test_the_guard_is_in_the_wrapper_not_the_inner
    gold("129_common_filter").split(/^\/\* (?:impl|entry wrapper)/).each do |chunk|
      next unless chunk.include?("spnl_filter_discard()) return 0;")
      assert_includes chunk, "SEC(", "the guard landed outside an entry wrapper"
    end
    # and it precedes the call that runs the argument extractors
    assert_match(/if \(spnl_filter_discard\(\)\) return 0;.*?_inner\(/m, gold("129_common_filter"))
  end

  def test_a_probe_without_the_declaration_is_untouched
    refute_includes gold("126_runtime_param"), "spnl_filter_discard"
    refute_includes gold("97_kprobe_conditional_emit"), "spnl_filter_discard"
  end

  # ---- 3. the dead-code shape ----------------------------------------------

  # The property this feature rests on is that an unset key is free. That needs
  # the helper call to be INSIDE the "is it set" guard: a flattened
  # `if (k != 0 && k != f())` would be just as correct and would cost a helper
  # call on every event forever.
  def test_helper_calls_are_nested_inside_the_is_set_guard
    g = gold("130_common_filter_all")
    body = g[/static __always_inline int spnl_filter_discard\(void\)\n\{(.+?)\n\}/m, 1]
    refute_nil body
    body.each_line do |line|
      next unless line.include?("bpf_get_current_")
      assert_match(/^        /, line,
                   "helper call is not nested under an is-set guard: #{line.strip}")
    end
    assert_match(/if \(spnl_filter_pid != 0 \|\| spnl_filter_tid != 0\) \{\n\s+__u64 _pt = bpf_get_current_pid_tgid\(\);/, body)
    assert_match(/if \(spnl_filter_uid >= 0 \|\| spnl_filter_gid >= 0\) \{\n\s+__u64 _ug = bpf_get_current_uid_gid\(\);/, body)
    assert_match(/if \(spnl_filter_comm\[0\] != '\\0'\) \{/, body)
  end

  # `volatile` is the mechanism, not decoration: without it -O2 proves the object
  # is never written and folds it at COMPILE time, the skeleton has nothing to
  # patch, and every run silently behaves like the default.
  def test_the_rodata_is_volatile_const
    g = gold("130_common_filter_all")
    CF::KEYS.each do |k|
      pat = k.string? ? "volatile const char #{k.c_symbol}[16]" : "volatile const __s64 #{k.c_symbol} ="
      assert_includes g, pat, "#{k.name}: not emitted as volatile const"
    end
  end

  # Only what was declared is exposed (the same rule `param` follows): a
  # key the author did not ask for would appear in the skeleton and in nothing
  # `describe` prints.
  def test_only_declared_keys_are_emitted
    g = gold("129_common_filter")
    assert_includes g, "spnl_filter_pid"
    assert_includes g, "spnl_filter_comm"
    %w[tid uid gid cgroup_id].each { |k| refute_includes g, "spnl_filter_#{k}" }
  end

  # ---- 4. refusals ----------------------------------------------------------

  def test_refuses_a_unit_with_a_hook_it_cannot_cover
    skip_unless_cc
    _out, err, st = run_cc("131_filter_verdict_hook")
    refute st.success?
    assert_includes err, "xdp__main"                       # which handler
    assert_includes err, "skip this event"                 # what the filter means
    assert_includes err, "looks narrowed and is not"       # why refusing beats partial
    assert_includes err, "kprobe kretprobe tracepoint"     # what IS covered
    assert_includes err, "its own probe"                   # what to do instead
  end

  def test_refuses_a_declaration_wired_to_nothing
    skip_unless_cc
    _out, err, st = run_cc("132_filter_no_handler")
    refute st.success?
    assert_includes err, "no attach handler it can cover"
    assert_includes err, "SPNL_FILTER_* would change nothing"
    assert_includes err, "delete the declaration"
  end

  def test_the_negative_fixtures_have_no_golden
    # A fixture the codegen refuses must not also ship a golden -- that pair is a
    # contradiction: a golden for output that can no longer be produced.
    %w[131_filter_verdict_hook 132_filter_no_handler].each do |b|
      refute File.exist?(File.join(GOLD, "#{b}.bpf.c")), "#{b} is refused AND has a golden"
      assert_includes File.read(File.join(GOLD, "codegen_reject.tsv")), b
    end
  end

  # ---- 5. what a reader / an AI is told ------------------------------------

  # `describe` is where the tension in this design is paid off: the injection is
  # invisible in the handler bodies, so it has to be visible somewhere a reader
  # looks. The NO-declaration case matters more than the declared one -- "this
  # probe is not narrowed" is the fact an author is least likely to notice.
  def test_describe_names_the_keys_and_the_handlers_they_reach
    out = SpinelEbpf::Introspect.report(src("129_common_filter"), "129_common_filter.rb")
    assert_includes out, "in-kernel common filter"
    assert_includes out, "SPNL_FILTER_PID"
    assert_includes out, "SPNL_FILTER_COMM"
    assert_includes out, "kprobe__do_sys_openat2"
    assert_includes out, "tracepoint__syscalls__sys_enter_execve"
  end

  def test_describe_says_so_when_a_probe_is_not_narrowed
    out = SpinelEbpf::Introspect.report(src("97_kprobe_conditional_emit"), "97_kprobe_conditional_emit.rb")
    assert_includes out, "in-kernel common filter"
    assert_includes out, "not narrowed"
    assert_includes out, "filter_by"
  end

  def test_describe_warns_about_an_unknown_key
    out = SpinelEbpf::Introspect.report("filter_by :pid, :ppid\n\ndef kprobe__x(a)\n  0\nend\n", "x.rb")
    assert_includes out, ":ppid"
    assert_includes out, "at compile time"
  end

  # capabilities --json answers the question BEFORE "what can I narrow": should
  # this probe narrow at all, and where does the narrowing go.
  def test_capabilities_exposes_the_surface
    cf = SpinelEbpf::Capabilities.affordance[:common_filter]
    refute_nil cf
    assert_equal CF::KEYS.map(&:name).sort, cf[:keys].keys.sort
    CF::KEYS.each do |k|
      assert_equal k.env_name, cf[:keys][k.name][:env]
      assert_equal k.unset, cf[:keys][k.name][:unset], "#{k.name}: unset sentinel drifted"
    end
    assert_match(/AND/, cf[:combining])
    assert_includes cf[:covers], "kprobe"
    refute_includes cf[:covers], "xdp"
    refute_includes cf[:covers], "lsm"
    assert cf[:refuses].any? { |r| r.include?("verdict hook") }
    # the hand-written equivalent is stated, because that is what makes the
    # declaration a shorthand rather than a black box
    assert_match(/param :target_pid/, cf[:hand_written_equivalent])
  end

  # The `uid` / `gid` builtins exist for that same reason: `filter_by :uid` must
  # not be able to filter on something the language cannot read.
  def test_uid_and_gid_are_readable_builtins
    %w[uid gid].each do |b|
      sig = SpinelEbpf::Capabilities.signature_for(b)
      refute_nil sig, "#{b} has no signature entry"
      assert_equal 0, sig[:arity]
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  # ---- 6. the native pass --------------------------------------------------

  # Upstream spinel's native codegen has no notion of `filter_by` and refuses the
  # unknown top-level call, so the native pass gets a copy with the declaration
  # commented out. Line-for-line, because every later line number has to stay
  # honest in a backtrace.
  def test_strip_for_the_native_pass_preserves_line_numbers
    s = src("129_common_filter")
    out = CF.strip_declarations(s)
    assert_equal s.lines.length, out.lines.length
    refute_includes out, "\nfilter_by :pid, :comm"
    assert_includes out, "# (filter_by stripped for native codegen)"
  end

  def test_strip_composes_with_the_param_strip
    s = "param :a, default: 1\nfilter_by :pid\n\ndef kprobe__x(v)\n  0\nend\n"
    out = SpinelEbpf::CommonFilter.strip_declarations(SpinelEbpf::Param.strip_declarations(s))
    assert_equal s.lines.length, out.lines.length
    refute_match(/^param /, out)
    refute_match(/^filter_by /, out)
  end

  # ---- 7. the portability contract is not narrowed -------------------------

  # Same .rodata mechanism as `param`: read-only map + BPF_MAP_FREEZE,
  # kernel 5.2, which is already the base eBPF floor. Declaring a filter must not
  # cost a probe the machines it can run on.
  def test_filter_does_not_raise_the_kernel_floor
    mk = SpinelEbpf::Portability::MIN_KERNEL
    refute mk.key?("filter_by"), "filter_by must not appear in MIN_KERNEL"
    CF::KEYS.each { |k| refute mk.key?(k.c_symbol), "#{k.name} must not raise the floor" }
  end
end
