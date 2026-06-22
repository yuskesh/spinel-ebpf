# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/instrument_test.rb
#
# --instrument: symbol-map parsing / filtering / noinline / agent gen.

require "minitest/autorun"
require "spinel_ebpf/instrument"

class InstrumentTest < Minitest::Test
  I = SpinelEbpf::Instrument

  SYMMAP = <<~JSON
    {"symbols":[
      {"c":"sp_fib","ruby":"fib","kind":"toplevel","file":"/t/w.rb","line":1},
      {"c":"sp_Counter_incr","ruby":"Counter#incr","kind":"imeth","file":"/t/w.rb","line":9},
      {"c":"sp_spnl_emit","ruby":"spnl_emit","kind":"toplevel","file":null,"line":null}
    ]}
  JSON

  def rec(ruby, c, idx, kind: "toplevel", file: "w.rb", line: 1)
    { ruby: ruby, c: c, kind: kind, file: file, line: line, idx: idx }
  end

  def test_parse_symbol_map
    recs = I.parse_symbol_map(SYMMAP)
    assert_equal %w[sp_fib sp_Counter_incr sp_spnl_emit], recs.map { |r| r[:c] }
    assert_equal "w.rb", recs[0][:file]   # basenamed
    assert_equal 1, recs[0][:line]
    assert_equal "imeth", recs[1][:kind]
    assert_equal "", recs[2][:file]       # null -> ""
  end

  def test_instrumentable_filters_builtins_and_assigns_idx
    recs = I.instrumentable(I.parse_symbol_map(SYMMAP))
    assert_equal %w[fib Counter#incr], recs.map { |r| r[:ruby] }   # spnl_emit (builtin) dropped
    assert_equal [0, 1], recs.map { |r| r[:idx] }
  end

  def test_instrumentable_only_skip_match_short_or_full
    base = I.parse_symbol_map(SYMMAP)
    assert_equal %w[fib],          I.instrumentable(base, only: %w[fib]).map { |r| r[:ruby] }
    assert_equal %w[Counter#incr], I.instrumentable(base, only: %w[incr]).map { |r| r[:ruby] }          # short
    assert_equal %w[Counter#incr], I.instrumentable(base, only: ["Counter#incr"]).map { |r| r[:ruby] }  # full
    assert_equal %w[Counter#incr], I.instrumentable(base, skip: %w[fib]).map { |r| r[:ruby] }
  end

  def test_self_target_names_toplevel_only
    recs = I.instrumentable(I.parse_symbol_map(SYMMAP))
    assert_equal %w[fib], I.self_target_names(recs)  # Counter#incr is imeth -> native already
  end

  def test_inject_noinline_on_real_symbols_not_calls
    src = <<~C
      static mrb_int sp_Counter_incr(mrb_int self, mrb_int lv_x);
      static mrb_int sp_Counter_incr(mrb_int self, mrb_int lv_x) {
        return sp_Counter_incr(self, lv_x);
      }
    C
    out = I.inject_noinline(src, %w[sp_Counter_incr])
    assert_equal 2, out.scan("__attribute__((noinline))").length  # decl + def
    assert_includes out, "  return sp_Counter_incr(self, lv_x);"  # call site untouched
  end

  def test_probe_defs_uses_real_symbols
    p = I.probe_defs([rec("fib", "sp_fib", 0), rec("Counter#incr", "sp_Counter_incr", 1)])
    assert_includes p, "def uprobe__sp_fib"
    assert_includes p, "def uprobe__sp_Counter_incr"
    assert_includes p, "lat_start((tid << 8) | 1)"
    assert_includes p, "hist_observe_by(1, d)"
  end

  def test_probe_defs_depth_collapse
    p = I.probe_defs([rec("fib", "sp_fib", 0)], depth_collapse: true)
    assert_includes p, "if depth_inc(k) == 1"
    assert_includes p, "if depth_dec(k) == 0"
    refute_includes I.probe_defs([rec("fib", "sp_fib", 0)]), "depth_inc"
  end

  def test_metrics_agent_uses_symbols_and_labels
    recs = [rec("fib", "sp_fib", 0), rec("Counter#incr", "sp_Counter_incr", 1, kind: "imeth", line: 9)]
    a = I.generate_agent(recs, target_bin: "/t/x", port: 9123)
    assert_includes a, "use_plugin :ebpf"
    assert_includes a, "def uprobe__sp_Counter_incr"     # class method by real symbol
    assert_includes a, "def __spnl_run_agent"
    # labels carry ruby name + file + line
    assert_includes a, %(__spnl_mcalls("fib", "w.rb", 1, 0))
    assert_includes a, %(__spnl_mcalls("Counter#incr", "w.rb", 9, 1))
    assert_includes a, 'file="'
    assert_includes a, %(ENV["SPINEL_HTTP_PORT"] || "9123")
  end

  def test_dump_agent_shape
    a = I.generate_agent([rec("fib", "sp_fib", 0)], target_bin: "/t/x", mode: :dump, wait_seconds: 7)
    assert_includes a, "sleep 7"
    assert_includes a, %(puts "fib calls")
    assert_includes a, %(SpnlHistFFI.spnl_dump_log2_hist_keyed("bpf_hist_keyed", 0, "fib ns"))
    refute_includes a, "/metrics"
  end

  def test_self_agent_embeds_workload_then_runs_agent
    a = I.generate_self_agent([rec("fib", "sp_fib", 0)], "def fib(n)\n  n\nend\nputs fib(5)\n")
    assert_includes a, "def uprobe__sp_fib"
    assert_includes a, "def fib(n)"        # workload embedded verbatim
    assert_includes a, "puts fib(5)"
    assert a.index("puts fib(5)") < a.rindex("\n__spnl_run_agent")
  end
end
