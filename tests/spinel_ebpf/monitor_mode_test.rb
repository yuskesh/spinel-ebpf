# frozen_string_literal: true
#
# Dry-run / monitor mode (--enforcement=monitor).
#
# Monitor mode is a property of the *production* C codegen (src/codegen_c/
# spinel_ebpf_cc.c), not the retired Ruby oracle, so this test drives the built
# C binary directly (same binary tools/golden.rb pins) with and without the
# SPNL_ENFORCEMENT=monitor env -- the exact wiring bin/spinel-ebpf uses.
#
# The semantics under test: deny is not a dedicated codegen path -- the wrapper
# propagates the handler's verdict. So monitor mode must keep
# every side effect (the inner is still called: map updates / emit / counters) and
# only neutralize the verdict to the "allow" constant for the enforcement-carrying
# attach kinds: lsm (0), fmod_ret (0), cgroup/connect4|bind4 (1). Every other
# verdict kind (xdp/tc/sk_*) is left untouched.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/monitor_mode_test.rb

require "minitest/autorun"
require "open3"

class MonitorModeTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")

  # Mirror golden.rb's preflight: +x is not enough (build/ is bind-mounted, so the
  # binary here may be built for the other platform). A working binary prints its
  # usage line with no args; if it can't run here, skip rather than false-fail.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def gen(base, monitor:)
    env = monitor ? { "SPNL_ENFORCEMENT" => "monitor" } : {}
    out, err, st = Open3.capture3(env, CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
    assert st.success?, "codegen failed for #{base}: #{err}"
    out
  end

  def skip_unless_cc
    skip "C codegen binary not runnable on this host (build: cc -O2 -o #{CC} " \
         "src/codegen_c/spinel_ebpf_cc.c)" unless self.class.runnable?
  end

  # ---- enforce (default) is byte-identical to the committed golden ----

  def test_enforce_default_is_byte_identical_to_golden
    skip_unless_cc
    %w[58_lsm_fmod 61_cgroup_connect4 24_xdp_counter].each do |b|
      gold = File.join(GOLD, "#{b}.bpf.c")
      next unless File.exist?(gold)
      assert_equal File.read(gold), gen(b, monitor: false),
                   "enforce default must be byte-identical to golden for #{b}"
    end
  end

  # ---- lsm / fmod_ret: verdict neutralized to allow (0), inner still called ----

  def test_lsm_verdict_neutralized_to_allow_zero
    skip_unless_cc
    m = gen("58_lsm_fmod", monitor: true)
    # inner still invoked (side effects preserved), but discarded + allow returned.
    assert_match(/\(void\)lsm__file_open_inner\([^;]*\);\s*\/\* monitor: verdict neutralized to allow \*\//, m)
    # the wrapper's return is the allow constant (0), not the propagated verdict.
    assert_match(/verdict neutralized to allow \*\/\n\s*return 0;/, m)
    refute_includes m, "return (int)lsm__file_open_inner",
                     "monitor must not propagate the lsm verdict"
  end

  def test_fmod_ret_verdict_neutralized_to_zero
    skip_unless_cc
    m = gen("58_lsm_fmod", monitor: true)
    assert_match(/\(void\)fmod_ret__security_file_open_inner\([^;]*\);\s*\/\* monitor: verdict neutralized to allow \*\//, m)
    refute_includes m, "return (int)fmod_ret__security_file_open_inner",
                     "monitor must not propagate the fmod_ret verdict"
  end

  # ---- cgroup/connect4: allow constant is 1 (not 0) ----

  def test_cgroup_connect4_verdict_neutralized_to_one
    skip_unless_cc
    m = gen("61_cgroup_connect4", monitor: true)
    assert_match(/\(void\)cgroup__connect4__guard_inner\(ctx\);\s*\/\* monitor: verdict neutralized to allow \*\//, m)
    assert_match(/verdict neutralized to allow \*\/\n\s*return 1;/, m,
                 "cgroup/connect4 allow constant must be 1, not 0")
    refute_includes m, "return (int)cgroup__connect4__guard_inner"
  end

  # ---- side effects are preserved: the inner body (map update) is unchanged ----

  def test_side_effects_preserved_in_monitor
    skip_unless_cc
    e = gen("58_lsm_fmod", monitor: false)
    m = gen("58_lsm_fmod", monitor: true)
    # The `_inner` function bodies (which do the map updates) are byte-identical;
    # only the wrapper's return differs. Extract each inner body and compare.
    %w[lsm__file_open_inner fmod_ret__security_file_open_inner].each do |fn|
      re = /static __noinline [^\n]*#{Regexp.escape(fn)}\(.*?\n\}\n/m
      assert_equal e[re], m[re], "#{fn} body (side effects) must be unchanged in monitor"
      assert e[re], "expected to find #{fn} body"
    end
  end

  # ---- non-enforcement verdict kinds (xdp) are NOT rewritten ----

  def test_xdp_verdict_untouched_by_monitor
    skip_unless_cc
    e = gen("24_xdp_counter", monitor: false)
    m = gen("24_xdp_counter", monitor: true)
    # Strip the monitor header marker (the only allowed difference) and compare.
    stripped = m.lines.reject { |l| l.include?("ENFORCEMENT=monitor") ||
                                     l.include?("are neutralized to allow") }.join
    assert_equal e, stripped, "xdp verdict/code must be untouched by monitor (only the header marker differs)"
    refute_includes m, "verdict neutralized to allow",
                     "monitor must not neutralize non-enforcement (xdp) verdicts"
  end

  # ---- the build carries a monitor marker; enforce does not ----

  def test_monitor_marker_present_only_in_monitor
    skip_unless_cc
    assert_includes gen("58_lsm_fmod", monitor: true), "ENFORCEMENT=monitor"
    refute_includes gen("58_lsm_fmod", monitor: false), "ENFORCEMENT=monitor"
  end
end
