# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/introspect_test.rb
#
# `describe` emit/consumer introspection.

require "minitest/autorun"
require "spinel_ebpf/introspect"

class IntrospectTest < Minitest::Test
  I = SpinelEbpf::Introspect

  def test_emits_detects_kinds_and_ignores_comments
    src = <<~RUBY
      # spnl_emit_pair(a, b) in a comment must NOT count
      def k(ret)
        spnl_emit_pair(0, latency_end)
      end
      def j; spnl_emit(7); end
    RUBY
    es = I.emits(src)
    assert_equal %w[spnl_emit_pair spnl_emit], es.map { |e| e[:name] }
    assert_equal [2, 1], es.map { |e| e[:arity] }
  end

  def test_consumers_capture_params
    src = "on_emit_pair do |svc, dur|\nend\non_emit do |v|\nend\n"
    cs = I.consumers(src)
    assert_equal %w[on_emit_pair on_emit], cs.map { |c| c[:consumer] }
    assert_equal [2, 1], cs.map { |c| c[:nparams] }
  end

  def test_report_binding_ok
    src = "spnl_emit_pair(0, x)\non_emit_pair do |a, b|\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/:pair\s+producers\[spnl_emit_pair@L1\] -> consumers\[on_emit_pair@L2\]\s+OK/, r)
    assert_match(/warnings:\n\s+\(none\)/, r)
  end

  def test_report_warns_arity_mismatch
    src = "spnl_emit_pair(0, x)\non_emit_pair do |a|\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/block params 1 != emit arity 2/, r)
  end

  def test_report_warns_missing_consumer_and_producer
    miss_cons = I.report("spnl_emit(1)\n", "t.rb")
    assert_match(/has no matching on_emit/, miss_cons)
    miss_prod = I.report("on_emit do |v|\nend\n", "t.rb")
    assert_match(/on_emit has no matching emit/, miss_prod)
  end

  def test_report_warns_multisite_indistinguishable
    src = "spnl_emit_pair(0, a)\nspnl_emit_pair(1, b)\non_emit_pair do |x, y|\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/2 emit sites of the same kind/, r)
  end

  # ---------- named events in describe ----------

  def test_named_emits_and_consumers_scanned
    src = "  emit :http, dur\non_emit :http do |v|\nend\n"
    assert_equal [{ line: 1, name: "http", text: "emit :http, dur" }], I.named_emits(src)
    assert_equal "http", I.named_consumers(src).first[:name]
  end

  def test_report_named_binding_and_tag
    src = "emit :http, dur\non_emit :http do |v|\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/named events/, r)
    assert_match(/:http\s+tag=0x\h+\s+producers\[emit@L1\] -> consumers\[on_emit@L2\]\s+OK/, r)
  end

  def test_report_named_warns_missing
    miss = I.report("on_emit :http do |v|\nend\n", "t.rb")
    assert_match(/on_emit :http has no matching emit/, miss)
  end
end
