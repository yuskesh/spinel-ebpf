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
    assert_match(/1 block params, but emit has arity 2/, r)
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

  # These fixtures used to name the event `:http`, but `http` is now opted in as a
  # typed record channel, so `on_emit :http` means a **typed record consumer**.
  # These tests are about named events, so they use a name that is not a channel id
  # (test_channel_id_name_is_a_typed_consumer_not_a_named_event below pins that boundary).
  def test_named_emits_and_consumers_scanned
    src = "  emit :http_open, dur\non_emit :http_open do |v|\nend\n"
    assert_equal [{ line: 1, name: "http_open", text: "emit :http_open, dur" }], I.named_emits(src)
    assert_equal "http_open", I.named_consumers(src).first[:name]
  end

  def test_report_named_binding_and_tag
    src = "emit :http_open, dur\non_emit :http_open do |v|\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/named events/, r)
    assert_match(/:http_open\s+tag=0x\h+\s+producers\[emit@L1\] -> consumers\[on_emit@L2\]\s+OK/, r)
  end

  def test_report_named_warns_missing
    miss = I.report("on_emit :http_open do |v|\nend\n", "t.rb")
    assert_match(/on_emit :http_open has no matching emit/, miss)
  end

  # The one backward-incompatible surface of opting a channel in: the moment a
  # channel is opted in, a named event that happens to share its id means a
  # **typed record consumer** instead. describe reports it under record channels
  # rather than named events -- it does not quietly become something else, so pin
  # that both the display and the contract switch to the typed side.
  # For a probe that consumes two channels, "which parts of the record did this
  # consumer read" is scanned **inside the block** only. Scanning the whole file
  # would credit one channel with a read belonging to the other block that shares
  # the parameter name (`ev`), making the granularity of a privacy review a lie.
  def test_reads_are_scoped_to_each_block
    src = "on_emit :dns do |ev|\n  puts ev.qname\nend\n" \
          "on_emit :http do |ev|\n  puts ev.status\nend\n"
    cs = I.record_consumers(src)
    assert_equal [%w[qname], %w[status]], cs.map { |c| c[:props] }
    assert_equal %w[dns http], cs.map { |c| c[:channel] }
    r = I.report(src, "t.rb")
    assert_match(/consumer: on_emit :dns do \|ev\|@L1  \(ev\.pid.*\)\n\s+reads: ev\.qname\n/, r)
    assert_match(/consumer: on_emit :http do \|ev\|@L4  \(ev\.pid.*\)\n\s+reads: ev\.status\n/, r)
  end

  def test_channel_id_name_is_a_typed_consumer_not_a_named_event
    r = I.report("on_emit :http do |ev|\n  puts ev.path\nend\n", "t.rb")
    assert_match(/consumer: on_emit :http do \|ev\|/, r)
    assert_match(/reads: ev\.path/, r)
    assert_empty I.named_consumers("on_emit :http do |ev|\nend\n"),
                 "a channel id must not be counted as a named event (it would be reported twice)"
  end

  # ---------- the egress summary of a packed-record channel ----------

  # A complete probe (emit + drain) reports everything it writes and the span those
  # bytes become, with no warnings.
  FULL_DNS_PROBE = <<~RUBY
    module Otlp
      ffi_func :spnl_otlp_dns_span_push, [:str], :int
    end
    def kprobe__udp_sendmsg(sk, msg, len)
      emit_dns(msg)
      0
    end
    loop { sleep 2; Otlp.spnl_otlp_dns_span_push("http://127.0.0.1:4318") }
  RUBY

  def test_record_emits_scanned_with_channel
    res = I.record_emits(FULL_DNS_PROBE)
    assert_equal [{ line: 5, name: "emit_dns", channel: "dns" }], res
    assert_empty I.record_emits("hist_observe(1)\n"), "a scalar emit is not a record channel"
    assert_empty I.record_emits("# emit_dns(msg) in a comment\n"), "comments must not be picked up"
  end

  def test_report_shows_record_layout_and_egress_attributes
    r = I.report(FULL_DNS_PROBE, "t.rb")
    assert_match(/record channels/, r)
    assert_match(/dns\s+<unit>_dns_event \(120 B, map <unit>_dns_events\) <- emit_dns@L5/, r)
    assert_match(/@36\s+raw\s+unsigned char\[64\]/, r)   # the byte layout (offsets come from the generator)
    assert_match(/egress: spnl_otlp_dns_span_push -> span "resolve \{dns\.question\.name\}" \(SpanKind INTERNAL\)/, r)
    assert_match(/dns\.question\.name\s+semconv/, r)
    assert_match(/spnl\.dns\.latency_ns\s+spinel/, r)    # spinel-specific attributes print apart from semconv ones
    assert_match(/enrichers.*k8s, cri/, r)
    assert_match(/warnings:\n\s+\(none\)/, r)
  end

  # A whole class of bug: the kernel keeps accumulating records, and without a drain
  # in userspace not one span comes out. describe does not stop the compile (it is a
  # review surface), but it names that hole. There are two ways to drain, so the
  # warning only fires when **neither** is present.
  def test_report_warns_when_record_drain_is_missing
    r = I.report("def kprobe__udp_sendmsg(sk, msg, len)\n  emit_dns(msg)\n  0\nend\n", "t.rb")
    assert_match(/spnl_otlp_dns_span_push/, r)
    assert_match(/on_emit :dns do \|ev\|/, r)          # the explicit form is suggested too
    assert_match(/no span is produced/, r)
  end

  # --- typed record consumer ---------------------------------

  TYPED_DNS_PROBE = <<~RB
    def kprobe__udp_sendmsg(sk, msg, len)
      emit_dns(msg)
      0
    end
    @ep = "http://127.0.0.1:4318"
    on_emit :dns do |ev|
      next unless ev.qname.end_with?(".invalid")
      send_otlp(to_span(ev), @ep)
    end
    loop { sleep 1; consume_records(200) }
  RB

  # The explicit form never calls the push FFI. If the missing-drain warning still
  # fired for it, a correct probe would carry a bogus warning -- check it is gone.
  def test_typed_consumer_satisfies_the_drain_requirement
    r = I.report(TYPED_DNS_PROBE, "t.rb")
    refute_match(/no span is produced/, r)
    assert_match(/warnings:\n\s+\(none\)/, r)
  end

  # `on_emit :dns` names a record channel id, so it is not a named event.
  # Misclassifying it produces the bogus warning "there is no emit :dns".
  def test_typed_consumer_is_not_reported_as_a_named_event
    r = I.report(TYPED_DNS_PROBE, "t.rb")
    refute_match(/named events/, r)
    refute_match(/on_emit :dns has no matching emit/, r)
    assert_empty I.named_consumers(TYPED_DNS_PROBE)
  end

  # The consumer binding and the properties it actually reads show up on the review surface.
  def test_report_shows_typed_consumer_binding_and_properties_read
    r = I.report(TYPED_DNS_PROBE, "t.rb")
    assert_match(/consumer: on_emit :dns do \|ev\|@L6\s+\(ev\.pid ev\.comm ev\.cgid ev\.duration_ns ev\.qname\)/, r)
    assert_match(/reads: ev\.qname/, r)
    sites = I.record_consumers(TYPED_DNS_PROBE)
    assert_equal 1, sites.length
    assert_equal({ channel: "dns", param: "ev" }, sites[0].slice(:channel, :param))
    assert_equal ["qname"], sites[0][:props]
  end

  # The same hole in the explicit form: the block is there, but the drain loop
  # (consume_records) is never called.
  def test_report_warns_when_typed_consumer_is_never_driven
    src = TYPED_DNS_PROBE.sub(/loop.*\n/, "")
    r = I.report(src, "t.rb")
    assert_match(/consume_records\(timeout_ms\) is never called/, r)
  end

  # The hole in reverse: a consumer with no producer (emit_dns) drains 0 records forever.
  def test_report_warns_when_typed_consumer_has_no_producer
    src = "@ep = \"x\"\non_emit :dns do |ev|\n  send_otlp(to_span(ev), @ep)\nend\nconsume_records(1)\n"
    r = I.report(src, "t.rb")
    assert_match(/calls none of the builtins that write the record \(emit_dns \/ dns_emit\)/, r)
  end

  # ---- `# @intent` / `# @expect`: shown, never checked ----------------------

  ANNOTATED = <<~RB
    # @intent  record which process resolved which name
    # @expect  one span per query
    #          A and AAAA are separate queries, so one resolution emits two
    # an ordinary comment (not indented enough to be a continuation)
    def kprobe__udp_sendmsg(sk, msg, len)
      emit_dns(msg)
    end
  RB

  def test_annotations_are_parsed_with_line_and_tag
    a = I.annotations(ANNOTATED)
    assert_equal 2, a.length
    assert_equal ["intent", "expect"], a.map { |x| x[:tag] }
    assert_equal [1, 2], a.map { |x| x[:line] }
    assert_match(/which process resolved which name/, a[0][:text])
  end

  # Continuations are folded in: silently dropping what the author wrote is as
  # bad as showing something they did not write.
  def test_indented_continuation_is_folded_into_the_previous_annotation
    a = I.annotations(ANNOTATED)
    assert_match(/A and AAAA are separate queries/, a[1][:text])
  end

  # And the converse: a following comment that is not indented is not absorbed.
  def test_ordinary_comment_after_an_annotation_is_not_swallowed
    a = I.annotations(ANNOTATED)
    refute(a.any? { |x| x[:text].include?("an ordinary comment") },
           "an under-indented comment was taken as stated intent")
  end

  # A continuation must be adjacent, so a comment elsewhere in the file cannot
  # be pulled into an annotation written earlier.
  def test_continuation_must_be_adjacent
    src = "# @intent  foo\n\n#     detached, so not a continuation\n"
    a = I.annotations(src)
    assert_equal 1, a.length
    assert_equal "foo", a[0][:text]
  end

  def test_report_shows_stated_intent_and_says_it_is_not_checked
    r = I.report(ANNOTATED, "t.rb")
    assert_match(/stated intent/, r)
    assert_match(/not checked/, r)
    assert_match(/@intent/, r)
  end

  # With none written the section still appears, so the annotations are
  # discoverable -- but it is **not** a warning. Making it one would be read as
  # "writing @intent makes the probe safe".
  def test_missing_intent_is_a_hint_not_a_warning
    src = "def kprobe__x(a)\n  spnl_emit(a)\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/stated intent .*:\n  \(none\)/, r)
    warn_section = r[/\nwarnings:\n.*/m]
    refute_match(/@intent/, warn_section)
  end
end
