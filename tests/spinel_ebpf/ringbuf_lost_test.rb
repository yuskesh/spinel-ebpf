# frozen_string_literal: true
#
# Ringbuf lost-sample accounting.
#
# Asserts the production C codegen (build/codegen_c/spinel_ebpf_cc) emits, for
# any unit with a ringbuf emit, a per-unit lost-sample counter map + helper and
# an else-branch on every bpf_ringbuf_reserve() that bumps it -- so a reserve
# failure (ring full) is counted instead of dropped silently. A unit with no
# emit gets neither (proves the gate, not a coincidence).
#
# Golden snapshots (tests/golden/*.bpf.c) lock the exact text; this test states
# the invariant in prose so a future refactor that keeps golden passing but
# breaks the intent is still caught by name.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/ringbuf_lost_test.rb

require "minitest/autorun"
require "open3"

class RingbufLostTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  FIX  = File.join(ROOT, "tests/fixtures")

  def gen(base)
    # C codegen usage: spinel_ebpf_cc <ir> <ast> <base_name>
    out, err, st = Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
    assert st.success?, "codegen failed for #{base}: #{err}"
    out
  end

  def setup
    skip "C codegen not built (#{CC}) -- run `make -C src/codegen_c`" unless File.executable?(CC)
  end

  def test_emit_unit_gets_lost_map_and_helper
    c = gen("12_spnl_emit")
    assert_includes c, "u_12_spnl_emit_lost SEC(\".maps\")",
                    "an emit unit must declare its per-unit lost counter map"
    assert_includes c, "BPF_MAP_TYPE_PERCPU_ARRAY",
                    "the lost counter must be a per-CPU array (no atomic on the bump)"
    assert_includes c, "static __always_inline void spnl_lost_inc(void)",
                    "the lost-counter increment helper must be defined"
  end

  def test_every_reserve_has_a_lost_accounting_else
    c = gen("12_spnl_emit")
    reserves = c.scan("= bpf_ringbuf_reserve(").length
    elses    = c.scan("else spnl_lost_inc();").length
    assert_operator reserves, :>=, 1, "fixture must exercise at least one reserve"
    assert_equal reserves, elses,
                 "every bpf_ringbuf_reserve() must have a lost-accounting else-branch"
  end

  def test_packed_channel_reserve_also_accounts
    # A packed-record channel (conn) routes through the templates, not the
    # hardcoded emit path -- confirm the else lands there too.
    c = gen("104_emit_connect")
    reserves = c.scan("= bpf_ringbuf_reserve(").length
    elses    = c.scan("else spnl_lost_inc();").length
    assert_operator reserves, :>=, 1
    assert_equal reserves, elses,
                 "packed-channel reserves must also account lost samples"
  end

  def test_non_emit_unit_has_no_lost_map
    c = gen("02_integer_arith")
    refute_includes c, "_lost SEC(\".maps\")",
                    "a unit with no ringbuf emit must not declare a lost counter"
    refute_includes c, "spnl_lost_inc",
                    "a unit with no ringbuf emit must not reference the lost helper"
  end
end
