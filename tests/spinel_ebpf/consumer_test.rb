# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/consumer_test.rb
#
# userspace consumer DSL (on_emit / on_emit_pair) source transform.

require "minitest/autorun"
require "spinel_ebpf/consumer"

class ConsumerTest < Minitest::Test
  C = SpinelEbpf::Consumer

  DSL_INT = <<~RUBY
    @sum = 0
    def produce(n)
      n.times { |i| spnl_emit(i) }
    end
    on_emit do |v|
      @sum = @sum + v
    end
    produce(5)
    consume_events(200)
    puts @sum
  RUBY

  DSL_PAIR = <<~RUBY
    @reqs = 0
    on_emit_pair do |svc, dur|
      @reqs = @reqs + 1
    end
    consume_events(100)
  RUBY

  def test_present_kinds
    assert_equal({ "" => 1 }, C.present(DSL_INT))            # suffix => nparams
    assert_equal({ "_pair" => 2 }, C.present(DSL_PAIR))
    refute C.present?("def f(x)\n  x + 1\nend\n")
  end

  def test_int_block_lowered_to_method
    out = C.transform(DSL_INT)
    assert_includes out, "def __spnl_consume_int(v)"
    refute_match(/^\s*on_emit\s+do/, out)
    assert_includes out, "  @sum = @sum + v"        # body preserved
    assert_includes out, "__spnl_consume_events(200)" # call rewritten
    refute_match(/^\s*consume_events\(/, out)
  end

  def test_pair_block_lowered_to_method
    out = C.transform(DSL_PAIR)
    assert_includes out, "def __spnl_consume_pair(svc, dur)"
    assert_includes out, "__spnl_consume_events(100)"
  end

  def test_int_driver_ffi_and_loop
    out = C.transform(DSL_INT)
    assert_includes out, "ffi_func :spnl_consume_poll, [:int], :int"
    assert_includes out, "ffi_func :spnl_consume_count_int, [], :int"
    assert_includes out, "ffi_func :spnl_cget, [:int], :int"
    assert_includes out, "SpnlConsumeFFI.spnl_consume_poll(t)"   # single persistent poll
    assert_match(/n0 = SpnlConsumeFFI\.spnl_consume_count_int/, out)
    assert_match(/__spnl_consume_int\(SpnlConsumeFFI\.spnl_cget\(i0\)\)/, out)
  end

  def test_pair_driver_ffi_and_loop
    out = C.transform(DSL_PAIR)
    assert_includes out, "ffi_func :spnl_consume_count_pair, [], :int"
    assert_includes out, "ffi_func :spnl_cget_pair_a, [:int], :int"
    assert_includes out, "ffi_func :spnl_cget_pair_b, [:int], :int"
    assert_match(/__spnl_consume_pair\(SpnlConsumeFFI\.spnl_cget_pair_a\(i0\), SpnlConsumeFFI\.spnl_cget_pair_b\(i0\)\)/, out)
  end

  def test_pair_with_timestamp_param
    # an extra trailing param beyond the value arity binds the ts.
    src = "on_emit_pair do |svc, dur, ts|\n  @x = ts\nend\nconsume_events(0)\n"
    out = C.transform(src)
    assert_includes out, "def __spnl_consume_pair(svc, dur, ts)"
    assert_includes out, "ffi_func :spnl_cget_pair_ts, [:int], :long"
    assert_match(/__spnl_consume_pair\(SpnlConsumeFFI\.spnl_cget_pair_a\(i0\), SpnlConsumeFFI\.spnl_cget_pair_b\(i0\), SpnlConsumeFFI\.spnl_cget_pair_ts\(i0\)\)/, out)
  end

  def test_int_no_ts_unchanged
    out = C.transform(DSL_INT)   # |v| only -> no ts getter
    refute_includes out, "spnl_cget_ts"
  end

  def test_on_emit_with_trailing_comment
    src = "on_emit do |v|   # handle each event\n  @s = @s + v\nend\nconsume_events(50)\n"
    out = C.transform(src)
    assert_includes out, "def __spnl_consume_int(v)"
    assert_includes out, "__spnl_consume_events(50)"
  end

  def test_transform_noop_without_dsl
    plain = "def f(x)\n  x + 1\nend\nputs f(2)\n"
    assert_equal plain, C.transform(plain)
  end

  def test_native_method_name_predicate
    assert C.native_method_name?("__spnl_consume_int")
    assert C.native_method_name?("__spnl_consume_pair")
    assert C.native_method_name?("__spnl_consume_events")
    assert C.native_method_name?("__spnl_named_http_open")
    refute C.native_method_name?("produce")
  end

  # ---------- named emits ----------

  NAMED = <<~RUBY
    def kretprobe__x(r)
      emit :http_open, latency_end
      emit :tcp_send,  42
    end
    on_emit :http_open do |v|
      @h = @h + v
    end
    on_emit :tcp_send do |v|
      @t = @t + v
    end
    consume_events(0)
  RUBY

  def test_name_tag_stable_positive_distinct
    assert_equal C.name_tag("svc_a"), C.name_tag("svc_a")
    assert C.name_tag("svc_a").positive?
    assert C.name_tag("svc_a") < (1 << 31)
    refute_equal C.name_tag("svc_a"), C.name_tag("svc_b")
  end

  def test_named_detect
    assert_equal({ "http_open" => "v", "tcp_send" => "v" }, C.named(NAMED))
  end

  def test_named_transform_producer_and_consumer
    out = C.transform(NAMED)
    th = C.name_tag("http_open")
    tt = C.name_tag("tcp_send")
    # producer: emit :name, expr -> spnl_emit_pair(tag, (expr))
    assert_includes out, "spnl_emit_pair(#{th}, (latency_end))"
    assert_includes out, "spnl_emit_pair(#{tt}, (42))"
    # consumer: on_emit :name do |v| -> def + tagged dispatch
    assert_includes out, "def __spnl_named_http_open(v)"
    assert_includes out, "def __spnl_named_tcp_send(v)"
    assert_match(/__spnl_named_http_open\(v\) if tag == #{th}/, out)
    assert_match(/__spnl_named_tcp_send\(v\) if tag == #{tt}/, out)
    assert_includes out, "ffi_func :spnl_consume_count_pair, [], :int"
  end
end
