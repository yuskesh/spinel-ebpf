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
  # ---- typed record consumer ------------------------------------------------

  TYPED = <<~RUBY
    def kprobe__udp_sendmsg(sk, msg, len)
      emit_dns(msg)
      0
    end
    @ep = "http://127.0.0.1:4318"
    @sent = 0
    def interesting?(name)
      name.end_with?(".invalid")
    end
    on_emit :dns do |ev|
      next unless interesting?(ev.qname)   # ev.qname inside a comment is left alone
      send_otlp(to_span(ev), @ep)
      @sent = @sent + 1
      puts ev.comm
    end
    loop do
      sleep 1
      st = consume_records(200)
    end
  RUBY

  # `on_emit :dns` names a record channel id, so it takes the typed record path
  # rather than the named-event one.
  def test_record_consumer_detected_by_channel_id
    assert_equal({ "dns" => "ev" }, C.record_consumers(TYPED))
    assert_empty C.record_consumers("on_emit :http_open do |v|\n  x\nend\n")   # an unknown id stays a named event
    assert C.present?(TYPED)
  end

  def test_record_block_becomes_a_method_and_next_becomes_return
    out = C.transform(TYPED)
    assert_includes out, "def __spnl_consume_rec_dns(ev)"
    # the block became a method, so the block-local `next` becomes a method-local `return`
    assert_includes out, "return 0 unless interesting?(SpnlRecDns.spnl_rec_dns_qname(ev))"
    refute_match(/^\s*next\b/, out)
  end

  def test_record_properties_lower_to_generated_accessors
    out = C.transform(TYPED)
    assert_includes out, "SpnlRecDns.spnl_rec_dns_qname(ev)"
    assert_includes out, "puts SpnlRecDns.spnl_rec_dns_comm(ev)"
    # to_span / send_otlp are callee renames (the arguments are untouched, so nesting survives)
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecDns.spnl_rec_dns_to_span(ev), @ep)"
  end

  # What "typed" buys: a property that is not in the declaration fails at compile
  # time -- not as a link error, not as a silent 0.
  def test_unknown_property_is_a_loud_error_listing_the_real_set
    bad = "on_emit :dns do |ev|\n  puts ev.qnam\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(bad) }
    assert_match(/has no property `qnam`/, e.message)
    assert_match(/ev\.qname/, e.message)      # it names the correct spelling
  end

  # Only a receiver named like the handle is rewritten (`req.pid` must not become
  # a record accessor).
  def test_only_the_handle_receiver_is_rewritten
    src = "on_emit :dns do |ev|\n  puts ev.pid\nend\nputs req.pid\n"
    out = C.transform(src)
    assert_includes out, "puts SpnlRecDns.spnl_rec_dns_pid(ev)"
    assert_includes out, "puts req.pid"
  end

  def test_record_driver_declares_ffi_from_the_declaration_and_flushes
    out = C.transform(TYPED)
    assert_includes out, "ffi_func :spnl_rec_dns_drain, [:int], :int"
    assert_includes out, "ffi_func :spnl_rec_dns_qname, [:int], :str"     # derived, :str
    assert_includes out, "ffi_func :spnl_rec_dns_cgid, [:int], :long"     # scalar, :long
    assert_includes out, "ffi_func :spnl_otlp_span_send, [:int, :str], :int"
    assert_includes out, "def __spnl_consume_records(t)"
    assert_includes out, "__spnl_consume_rec_dns(i0)"
    assert_includes out, "SpnlRecSink.spnl_otlp_span_flush"
    assert_includes out, "st = __spnl_consume_records(200)"
    # the generated methods live in the __spnl_ namespace that partition/codegen forces native
    assert C.native_method_name?("__spnl_consume_rec_dns")
    assert C.native_method_name?("__spnl_consume_records")
  end

  # A named event and a typed consumer of the same name cannot both be meant --
  # reject instead of guessing which one it is.
  def test_ambiguous_named_event_and_record_channel_is_rejected
    src = "emit :dns, 1\non_emit :dns do |ev|\n  puts ev.pid\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(src) }
    assert_match(/named event of the same name/, e.message)
  end

  # The short form (an existing probe) never enters the typed path -- not one
  # character of it changes.
  def test_concise_probe_is_untouched
    src = File.read(File.expand_path("../../examples/observability/otlp/audit_dns.rb", __dir__))
    assert_equal src, C.transform(src)
  end

  # ---- resolving `to_span` when a program consumes several channels ----------
  #
  # `to_span` stays the one **generic entry point** the probe writes (no extra name
  # per channel). Which channel it means is resolved from the scope of the
  # enclosing **`on_emit :<ch>` block**. Two blocks may use the same parameter name
  # (`ev`) -- inside a block that name is not ambiguous.

  MULTI = <<~RUBY
    def kprobe__udp_sendmsg(sk, msg, len)
      emit_dns(msg)
      0
    end
    def kprobe__tcp_sendmsg(sk, msg, size)
      http_req_start(sk, msg)
      0
    end
    @ep = "http://127.0.0.1:4318"
    on_emit :dns do |ev|
      next unless ev.qname.end_with?(".invalid")
      send_otlp(to_span(ev), @ep)
    end
    on_emit :http do |ev|
      next unless ev.status >= 500
      send_otlp(to_span(ev), @ep)
      puts ev.method + " " + ev.path
    end
    st = consume_records(200)
  RUBY

  def test_multi_channel_to_span_resolves_from_the_enclosing_block
    out = C.transform(MULTI)
    assert_equal({ "dns" => "ev", "http" => "ev" }, C.record_consumers(MULTI))
    # the same spelling `to_span(ev)` lowers to a different channel's builder per block
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecDns.spnl_rec_dns_to_span(ev), @ep)"
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecHttp.spnl_rec_http_to_span(ev), @ep)"
    # properties resolve in block scope too (a shared parameter name does not collide)
    assert_includes out, "SpnlRecDns.spnl_rec_dns_qname(ev)"
    assert_includes out, "SpnlRecHttp.spnl_rec_http_status(ev)"
    assert_includes out, "SpnlRecHttp.spnl_rec_http_method(ev)"
    assert_includes out, "SpnlRecHttp.spnl_rec_http_path(ev)"
    refute_includes out, "spnl_rec_dns_status", "the http block lowered to a dns accessor"
  end

  def test_multi_channel_driver_drains_every_channel_and_flushes_once
    out = C.transform(MULTI)
    assert_includes out, "ffi_func :spnl_rec_dns_drain, [:int], :int"
    assert_includes out, "ffi_func :spnl_rec_http_drain, [:int], :int"
    assert_includes out, "ffi_func :spnl_rec_http_status, [:int], :long"   # derived, int
    assert_includes out, "ffi_func :spnl_rec_http_method, [:int], :str"    # derived, str
    assert_includes out, "__spnl_consume_rec_dns(i0)"
    assert_includes out, "__spnl_consume_rec_http(i1)"
    assert_equal 1, out.scan("SpnlRecSink.spnl_otlp_span_flush").length, "flush must run once per drain cycle"
  end

  # The property set is per block too: `ev.path` in the dns block fails, naming the
  # dns set.
  def test_property_set_is_per_block
    bad = "on_emit :dns do |ev|\n  puts ev.path\nend\non_emit :http do |ev|\n  puts ev.path\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(bad) }
    assert_match(/the `dns` record has no property `path`/, e.message)
    assert_match(/ev\.qname/, e.message)
  end

  # When it cannot be resolved, **do not guess**: report the line, the reason and
  # the escape hatch, all three.
  def test_to_span_outside_any_block_is_a_loud_error
    src = "on_emit :dns do |ev|\n  puts ev.pid\nend\n" \
          "on_emit :http do |ev|\n  puts ev.pid\nend\n" \
          "def emit_it(x)\n  send_otlp(to_span(x), @ep)\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(src) }
    assert_match(/`to_span\(\.\.\.\)` \(line 8\)/, e.message)          # where
    assert_match(/outside every `on_emit :<channel>` block/, e.message) # why
    assert_match(/dns_span\(ev\) \/ http_span\(ev\)/, e.message)        # how to spell it instead
    assert_match(/consumes 2 typed record channels \(dns, http\)/, e.message)
  end

  def test_to_span_on_a_copied_handle_inside_a_block_is_a_loud_error
    src = "on_emit :dns do |ev|\n  puts ev.pid\nend\n" \
          "on_emit :http do |ev|\n  keep = ev\n  send_otlp(to_span(keep), @ep)\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(src) }
    assert_match(/`to_span\(\.\.\.\)` \(line 6\)/, e.message)
    assert_match(/inside `on_emit :http`/, e.message)
    assert_match(/applied to something other than that block's own parameter `ev`/, e.message)
    assert_match(/http_span\(ev\)/, e.message)
  end

  # The escape hatch: the explicit form that names the channel. **An escape hatch,
  # not the way to write it normally.**
  def test_channel_span_escape_hatch_is_unambiguous_anywhere
    src = "on_emit :dns do |ev|\n  puts ev.pid\nend\n" \
          "on_emit :http do |ev|\n  keep = ev\n  send_otlp(http_span(keep), @ep)\nend\n" \
          "def send_dns(h)\n  send_otlp(dns_span(h), @ep)\nend\n"
    out = C.transform(src)
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecHttp.spnl_rec_http_to_span(keep), @ep)"
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecDns.spnl_rec_dns_to_span(h), @ep)"
  end

  # The explicit form for a channel the program does not consume is a compile
  # error, not a link error.
  def test_channel_span_for_an_unconsumed_channel_is_a_loud_error
    src = "on_emit :dns do |ev|\n  send_otlp(http_span(ev), @ep)\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(src) }
    assert_match(/`http_span\(\.\.\.\)` \(line 2\)/, e.message)
    assert_match(/no `on_emit :http do \|ev\| \.\.\. end` block/, e.message)
    assert_match(/`dns_span\(ev\)`/, e.message)
  end

  # A single-channel program still resolves anywhere, so the earlier way of
  # writing it keeps working.
  def test_single_channel_still_resolves_outside_the_block
    src = "on_emit :dns do |ev|\n  emit_it(ev)\nend\n" \
          "def emit_it(x)\n  send_otlp(to_span(x), @ep)\nend\n"
    out = C.transform(src)
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecDns.spnl_rec_dns_to_span(x), @ep)"
  end

  # Passing the handle to a helper method also resolves outside the block, as long
  # as the program consumes a single channel.
  def test_single_channel_handle_property_outside_the_block
    src = "on_emit :dns do |ev|\n  hot?(ev)\nend\ndef hot?(ev)\n  ev.duration_ns > 1000\nend\n"
    out = C.transform(src)
    assert_includes out, "SpnlRecDns.spnl_rec_dns_duration_ns(ev) > 1000"
  end

  # ---- the offcpu channel (filtering on "why was it slow") ------------------
  #
  # The offcpu `ev` carries three values that are **not fields read as-is** (a
  # clamp, a difference, and a kallsyms classification). From Ruby they look like
  # ordinary properties, and their values equal the span attributes (a parity test
  # pins that).
  OFFCPU_TYPED = <<~RUBY
    def kprobe__tcp_sendmsg(sk, msg)
      offcpu_emit(sk, msg)
      0
    end
    @ep = "http://127.0.0.1:4318"
    on_emit :offcpu do |ev|
      next unless ev.offcpu_ns > 100000000
      send_otlp(to_span(ev), @ep)
      puts ev.method + " " + ev.path + " " + ev.wait_kind + " on=" + ev.oncpu_ns.to_s
    end
    st = consume_records(200)
  RUBY

  def test_offcpu_channel_is_a_typed_consumer
    assert_includes C.record_channel_ids, "offcpu"
    assert_equal({ "offcpu" => "ev" }, C.record_consumers(OFFCPU_TYPED))
    out = C.transform(OFFCPU_TYPED)
    assert_includes out, "def __spnl_consume_rec_offcpu(ev)"
    # clamped off-CPU / computed on-CPU / kallsyms classification -- all lower to generated accessors
    assert_includes out, "SpnlRecOffcpu.spnl_rec_offcpu_offcpu_ns(ev) > 100000000"
    assert_includes out, "SpnlRecOffcpu.spnl_rec_offcpu_oncpu_ns(ev)"
    assert_includes out, "SpnlRecOffcpu.spnl_rec_offcpu_wait_kind(ev)"
    assert_includes out, "SpnlRecSink.spnl_otlp_span_send(SpnlRecOffcpu.spnl_rec_offcpu_to_span(ev), @ep)"
    assert_includes out, "ffi_func :spnl_rec_offcpu_drain, [:int], :int"
    assert_includes out, "ffi_func :spnl_rec_offcpu_wait_kind, [:int], :str"    # derived, str
    assert_includes out, "ffi_func :spnl_rec_offcpu_offcpu_ns, [:int], :long"   # derived, int
    assert_includes out, "__spnl_consume_rec_offcpu(i0)"
  end

  # The raw fields that are not exposed (stack id, window anchor, raw header) fail
  # by name.
  def test_offcpu_raw_fields_are_not_properties
    %w[wait_stack start_ktime hdr_ext].each do |f|
      e = assert_raises(SpinelEbpf::Consumer::Error) {
        C.transform("on_emit :offcpu do |ev|\n  puts ev.#{f}\nend\n")
      }
      assert_match(/the `offcpu` record has no property `#{f}`/, e.message)
      assert_match(/ev\.wait_kind/, e.message)   # it names what to read instead
    end
  end

  # The short form (an unmodified off-CPU probe) never enters the typed path --
  # not one character of it changes.
  def test_concise_offcpu_probe_is_untouched
    src = File.read(File.expand_path("../../examples/observability/otlp/audit_offcpu.rb", __dir__))
    assert_equal src, C.transform(src)
  end

  # Two blocks use the same parameter name and that name is also read outside both
  # of them: ambiguous -> loud error.
  def test_same_param_name_read_outside_both_blocks_is_a_loud_error
    src = "on_emit :dns do |ev|\n  puts ev.pid\nend\n" \
          "on_emit :http do |ev|\n  puts ev.pid\nend\n" \
          "def dump(ev)\n  puts ev.pid\nend\n"
    e = assert_raises(SpinelEbpf::Consumer::Error) { C.transform(src) }
    assert_match(/`ev\.pid` \(line 8\)/, e.message)
    assert_match(/block parameter of 2 typed consumers \(on_emit :dns, on_emit :http\)/, e.message)
    assert_match(/distinct parameter names/, e.message)
  end
end
