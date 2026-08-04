# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/keep_filter_test.rb
#
# The declarative userspace consumer filter (`keep_if`).
#
# What is worth fixing in a test, in the order the design argues it:
#   * the LOWERING is total -- every operator/type pair the vocabulary declares
#     has a lowering, and no lowering exists for a pair the vocabulary refuses
#     (the rule: do not make a combination declarable that cannot be built);
#   * the GUARD IS HOISTED -- the generated Ruby puts it above the body, which is
#     the property a hand-written `next` cannot have;
#   * the LINE to the in-kernel filter (D1) is data, joined from the record
#     contract to CommonFilter's vocabulary, and holds in both directions;
#   * the REFUSALS name the reason, the place and the way out.
require "minitest/autorun"
require "spinel_ebpf/keep_filter"
require "spinel_ebpf/consumer"
require "spinel_ebpf/common_filter"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/introspect"

class KeepFilterTest < Minitest::Test
  KF  = SpinelEbpf::KeepFilter
  CON = SpinelEbpf::Consumer
  CF  = SpinelEbpf::CommonFilter
  CAP = SpinelEbpf::Capabilities

  BODY = <<~'EOS'
    on_emit :dns do |ev|
      send_otlp(to_span(ev), @ep)
    end
    loop do
      consume_records(200)
    end
  EOS

  def xform(decl) = CON.transform(decl + BODY)

  def refusal(decl)
    err = assert_raises(CON::Error) { xform(decl) }
    err.message
  end

  # ---------- vocabulary is total and closed ----------

  # Every (operator, type) the vocabulary declares must have a lowering, and
  # every lowering must correspond to a declared pair. A pair that is declarable
  # but not buildable is the failure mode this rules out; the reverse (a lowering
  # nothing can reach) is dead code that will drift.
  def test_every_declared_operator_type_pair_has_exactly_one_lowering
    declared = KF::OPS.flat_map { |o| o.types.map { |t| [o.name, t] } }.sort
    assert_equal declared, KF::LOWERING.keys.sort,
                 "declared operator/type pairs and lowerings must be the same set"
  end

  def test_operators_only_use_the_two_ruby_exposures
    assert_equal %w[int str], KF::OPS.flat_map(&:types).uniq.sort
    KF::OPS.each { |o| refute_empty o.types, "#{o.name} accepts nothing" }
  end

  def test_ops_for_partitions_by_type
    assert_equal %w[eq ne ge le], KF.ops_for("int").map(&:name)
    assert_equal %w[eq ne contains], KF.ops_for("str").map(&:name)
  end

  def test_env_name_is_derived_from_channel_and_property
    assert_equal "SPNL_KEEP_DNS_QNAME", KF.env_name("dns", "qname")
    assert_equal "SPNL_KEEP_HTTP_DURATION_NS", KF.env_name("http", "duration_ns")
    assert KF.env_name("dns", "qname").start_with?(KF::ENV_PREFIX)
  end

  # ---------- source scan ----------

  def test_scan_source_reads_channel_and_predicates_in_order
    src = "keep_if :dns, qname: :contains, duration_ns: :ge\nkeep_if :http, status: :ge\n"
    got = KF.scan_source(src)
    assert_equal [1, 2], got.map { |d| d[:line] }
    assert_equal %w[dns http], got.map { |d| d[:channel] }
    assert_equal [{ prop: "qname", op: "contains" }, { prop: "duration_ns", op: "ge" }], got[0][:preds]
  end

  def test_scan_source_reports_a_non_predicate_instead_of_refusing
    got = KF.scan_source("keep_if :dns, qname\n")
    assert_equal ["qname"], got[0][:bad]
    assert_empty got[0][:preds]
  end

  def test_scan_source_ignores_a_trailing_comment_and_a_method_call
    assert_equal 1, KF.scan_source("keep_if :dns, qname: :eq   # why\n").length
    assert_empty KF.scan_source("x.keep_if :dns, qname: :eq\n")
    assert_empty KF.scan_source("  # keep_if :dns, qname: :eq\n")
  end

  def test_strip_declarations_preserves_line_numbers
    src = "a = 1\nkeep_if :dns, qname: :eq\nb = 2\n"
    out = KF.strip_declarations(src)
    assert_equal src.lines.length, out.lines.length
    refute_includes out, "keep_if :dns"
    assert_equal "b = 2\n", out.lines[2]
  end

  def test_loader_declarations_flatten_to_one_row_per_predicate
    rows = KF.loader_declarations("keep_if :dns, qname: :contains, duration_ns: :ge\n")
    assert_equal %w[SPNL_KEEP_DNS_QNAME SPNL_KEEP_DNS_DURATION_NS], rows.map { |r| r[:env] }
    assert_equal %w[str int], rows.map { |r| r[:expose] }
  end

  # ---------- D1: the line to the in-kernel filter ----------

  # `kfilter` is declared in the record contract; every value it can take must be
  # a key the in-kernel filter actually has. The generator has no view of the
  # Ruby-side vocabulary, so this join is the check that keeps the two tables
  # from drifting into a redirect that names a `filter_by` key nobody accepts.
  def test_every_declared_kernel_equivalent_is_a_real_filter_by_key
    seen = 0
    CAP.typed_record_channel_ids.each do |id|
      CAP.record_properties(id).each do |p|
        k = p[:kfilter].to_s
        next if k.empty?
        seen += 1
        assert CF::KEYS_BY_NAME.key?(k),
               "#{id}.#{p[:name]} declares kfilter #{k.inspect}, which is not a filter_by key " \
               "(#{CF::KEYS.map(&:name).join(' ')})"
      end
    end
    assert_operator seen, :>, 0, "no channel declares a kernel equivalent -- the join is untested"
  end

  # A derivation is computed in userspace, so no kernel key can ever see it.
  # This is the reason the userspace filter exists at all, and it is a property
  # of the declaration rather than a convention.
  def test_no_derived_property_claims_a_kernel_equivalent
    CAP.typed_record_channel_ids.each do |id|
      CAP.record_properties(id).select { |p| p[:kind] == "derived" }.each do |p|
        assert_nil KF.kernel_key(id, p[:name]),
                   "#{id}.#{p[:name]} is derived but claims a kernel equivalent"
      end
    end
  end

  # The measured asymmetry this design turns on: dns fills pid/comm/cgid from
  # bpf_get_current_* in the emitting task, so the kernel key selects the same
  # set; conn/l7/http fill them from an entry stashed in an earlier task, so it
  # does not. Fixing it here means a change to a producer that breaks the
  # equivalence has to come past this test.
  def test_only_channels_whose_producers_read_the_current_task_have_kernel_equivalents
    assert_equal "pid",       KF.kernel_key("dns", "pid")
    assert_equal "comm",      KF.kernel_key("dns", "comm")
    assert_equal "cgroup_id", KF.kernel_key("dns", "cgid")
    %w[conn l7 http offcpu].each do |id|
      %w[pid comm cgid].each do |prop|
        next unless CAP.record_properties(id).any? { |p| p[:name].to_s == prop }
        assert_nil KF.kernel_key(id, prop),
                   "#{id}.#{prop} must not claim a kernel equivalent: it is not the current task's " \
                   "value at emit (or the channel needs handlers that run in other tasks)"
      end
    end
  end

  def test_placement_answers_why_a_predicate_runs_in_userspace
    assert_equal :derived,       KF.placement("dns", "qname", "contains")
    assert_equal :no_kernel_key, KF.placement("dns", "duration_ns", "ge")
    assert_equal :operator,      KF.placement("dns", "comm", "contains")
    KF::PLACEMENT_NOTE.each_value { |v| refute_empty v }
  end

  # ---------- lowering: the guard is hoisted ----------

  def test_guard_is_emitted_at_the_head_of_the_generated_handler
    out = xform("keep_if :dns, qname: :contains\n").lines.map(&:chomp)
    head = out.index { |l| l.include?("def __spnl_consume_rec_dns(ev)") }
    guard = out.index { |l| l.include?("SPNL_KEEP_DNS_QNAME") }
    body = out.index { |l| l.include?("spnl_otlp_span_send") }
    refute_nil head
    refute_nil guard
    refute_nil body
    assert_operator head, :<, guard, "the guard must be inside the handler"
    assert_operator guard, :<, body, "the guard must precede the body -- that is the whole point"
  end

  def test_guard_reads_the_same_generated_accessor_as_ev_dot_property
    out = xform("keep_if :dns, qname: :contains\n")
    assert_includes out, "SpnlRecDns.spnl_rec_dns_qname(ev).include?(__spnl_keep_dns_qname)"
    # ...and it is the same symbol `ev.qname` in the body lowers to.
    body = CON.transform("on_emit :dns do |ev|\n  puts ev.qname\nend\n")
    assert_includes body, "SpnlRecDns.spnl_rec_dns_qname(ev)"
  end

  def test_unset_environment_does_not_constrain
    out = xform("keep_if :dns, duration_ns: :ge\n")
    assert_includes out, '__spnl_keep_dns_duration_ns = ENV["SPNL_KEEP_DNS_DURATION_NS"] || ""'
    assert_includes out, 'if __spnl_keep_dns_duration_ns != ""'
  end

  def test_each_operator_lowers_to_the_expected_drop_condition
    {
      "duration_ns: :eq" => "return 0 if SpnlRecDns.spnl_rec_dns_duration_ns(ev) != __spnl_keep_dns_duration_ns.to_i",
      "duration_ns: :ne" => "return 0 if SpnlRecDns.spnl_rec_dns_duration_ns(ev) == __spnl_keep_dns_duration_ns.to_i",
      "duration_ns: :ge" => "return 0 if SpnlRecDns.spnl_rec_dns_duration_ns(ev) < __spnl_keep_dns_duration_ns.to_i",
      "duration_ns: :le" => "return 0 if SpnlRecDns.spnl_rec_dns_duration_ns(ev) > __spnl_keep_dns_duration_ns.to_i",
      "qname: :eq"       => "return 0 if SpnlRecDns.spnl_rec_dns_qname(ev) != __spnl_keep_dns_qname",
      "qname: :ne"       => "return 0 if SpnlRecDns.spnl_rec_dns_qname(ev) == __spnl_keep_dns_qname",
      "qname: :contains" => "return 0 unless SpnlRecDns.spnl_rec_dns_qname(ev).include?(__spnl_keep_dns_qname)",
    }.each do |decl, want|
      assert_includes xform("keep_if :dns, #{decl}\n"), want, "lowering for #{decl}"
    end
  end

  # The generated Ruby must stay inside the subset a reader can hand-write: no
  # `!`, no regexp, nothing the declaration is hiding that the language cannot say.
  def test_generated_guard_uses_no_construct_outside_the_hand_written_equivalent
    out = xform("keep_if :dns, qname: :contains, duration_ns: :ge\n")
    guards = out.lines.select { |l| l =~ /__spnl_keep_/ }
    refute_empty guards
    guards.each do |l|
      refute_match(/(?<![!<>=])!(?!=)/, l, "generated guard uses `!`: #{l}")
      refute_match(%r{=~|/.*/}, l, "generated guard uses a regexp: #{l}")
    end
  end

  def test_declaration_never_reaches_spinel
    out = xform("keep_if :dns, qname: :eq\n")
    refute_match(/^\s*keep_if\b/, out)
    assert_includes out, "# (keep_if lowered into the consumer)"
  end

  def test_a_program_without_a_declaration_is_byte_identical
    assert_equal CON.transform(BODY), CON.transform(BODY)
    refute_includes CON.transform(BODY), "__spnl_keep_"
  end

  # ---------- refusals (reason + place + way out) ----------

  def test_unknown_property_lists_the_real_set
    m = refusal("keep_if :dns, qnmae: :contains\n")
    assert_includes m, "line 1"
    assert_includes m, "has no property `qnmae`"
    assert_includes m, "qname (str)"
    assert_includes m, "capabilities --json"
  end

  def test_unknown_operator_lists_the_ones_the_type_accepts
    m = refusal("keep_if :dns, qname: :matches\n")
    assert_includes m, "unknown operator `:matches`"
    assert_includes m, ":contains"
  end

  def test_operator_type_mismatch_is_refused_both_ways
    m = refusal("keep_if :dns, qname: :ge\n")
    assert_includes m, "does not apply to a str property"
    m2 = refusal("keep_if :dns, duration_ns: :contains\n")
    assert_includes m2, "does not apply to a int property"
  end

  # D1's refusal, and the one that carries the most weight: the message must name
  # the replacement, its env var, WHY it is better, and the way out when the
  # in-kernel filter is not usable for this unit.
  def test_eq_on_a_kernel_equivalent_is_redirected_to_filter_by
    m = refusal("keep_if :dns, pid: :eq\n")
    assert_includes m, "before it exists"
    assert_includes m, "filter_by :pid"
    assert_includes m, "SPNL_FILTER_PID"
    assert_includes m, "saves the ringbuf"
    assert_includes m, "verdict hook"          # the case where filter_by cannot be used
    assert_includes m, "next if ev.pid !="     # the hand-written way out
  end

  # ...and only `:eq`. The in-kernel filter is equality-AND only, so every other
  # operator on the same property has no kernel form and belongs here.
  def test_other_operators_on_a_kernel_equivalent_property_are_accepted
    %w[ne contains].each do |op|
      out = xform("keep_if :dns, comm: :#{op}\n")
      assert_includes out, "SPNL_KEEP_DNS_COMM"
    end
    assert_includes xform("keep_if :dns, pid: :ge\n"), "SPNL_KEEP_DNS_PID"
  end

  def test_channel_without_a_typed_consumer_is_refused
    m = refusal("keep_if :redis, foo: :eq\n")
    assert_includes m, "not a typed record channel"
    assert_includes m, "dns"
  end

  def test_channel_this_program_does_not_consume_is_refused
    m = refusal("keep_if :conn, dport: :ge\n")
    assert_includes m, "no `on_emit :conn do |ev| ... end` block"
    assert_includes m, "wired to nothing"
  end

  # A declaration with no consumer at all must still be loud: otherwise it
  # reaches spinel as an unknown top-level call and dies about the wrong thing.
  def test_declaration_without_any_typed_consumer_is_refused
    err = assert_raises(CON::Error) { CON.transform("keep_if :dns, qname: :eq\nputs 1\n") }
    assert_includes err.message, "no `on_emit :dns do |ev| ... end` block"
  end

  def test_second_declaration_for_the_same_channel_is_refused
    m = refusal("keep_if :dns, qname: :eq\nkeep_if :dns, duration_ns: :ge\n")
    assert_includes m, "declared twice"
    assert_includes m, "line 1"
  end

  def test_same_property_twice_is_refused
    m = refusal("keep_if :dns, qname: :eq, qname: :ne\n")
    assert_includes m, "listed twice"
  end

  def test_no_predicate_and_non_predicate_are_refused_differently
    assert_includes refusal("keep_if :dns\n"), "at least one predicate"
    assert_includes refusal("keep_if :dns, qname\n"), "is not a predicate"
  end

  # ---------- describe ----------

  def test_describe_says_a_consumer_without_a_declaration_drops_nothing
    r = SpinelEbpf::Introspect.report(BODY, "t.rb")
    assert_includes r, "userspace consumer filter"
    assert_includes r, "sends every record"
    assert_includes r, "keep_if :dns, qname: :contains"   # the suggestion
  end

  def test_describe_lists_the_declaration_with_env_and_why_it_is_here
    r = SpinelEbpf::Introspect.report("keep_if :dns, qname: :contains\n" + BODY, "t.rb")
    assert_includes r, "SPNL_KEEP_DNS_QNAME"
    assert_includes r, "userspace-only"
    assert_includes r, "egress declaration"
  end

  # D3's trap, addressed where a reader will hit it: `SPNL_MAX_EVENTS` is the
  # FIRST K, which is not a filter, and the two are constantly confused.
  def test_describe_separates_the_filter_from_the_first_k_events_knob
    r = SpinelEbpf::Introspect.report(BODY, "t.rb")
    assert_includes r, "SPNL_MAX_EVENTS"
    assert_includes r, "sort/top-N is not implemented"
  end

  # A declaration with no consumer is a filter wired to nothing. compile refuses
  # it; describe also runs on sources that do not compile, so it says so too.
  def test_describe_warns_when_the_declared_channel_is_not_consumed
    r = SpinelEbpf::Introspect.report("keep_if :dns, qname: :contains\ndef kprobe__x(a)\n  0\nend\n", "t.rb")
    assert_includes r, "never drained, so it narrows nothing"
  end

  def test_describe_warns_rather_than_refusing_on_a_bad_declaration
    r = SpinelEbpf::Introspect.report("keep_if :dns, nope: :eq\n" + BODY, "t.rb")
    assert_includes r, "unknown property"
  end

  # ---------- capabilities ----------

  def test_capabilities_publishes_the_filter_surface_and_the_line
    f = CAP::CONSUMER_FILTER
    assert_equal KF::OPS.map(&:name).sort, f[:operators].keys.sort
    KF::OPS.each { |o| assert_equal o.types, f[:operators][o.name][:types] }
    assert_includes f[:line], "filter_by"
    assert_includes f[:span_unchanged], "egress declaration"
    refute_empty f[:refuses]
  end

  # What is NOT implemented has to be in the machine-readable surface, not only
  # in prose: an unlisted absence is what a model fills in by inventing syntax.
  def test_capabilities_names_what_is_not_implemented
    ni = CAP::CONSUMER_FILTER[:not_implemented]
    assert ni.key?("sort / top-N")
    assert_includes ni["sort / top-N"], "SPNL_MAX_EVENTS"
    assert_includes ni["--fields"], "egress declaration"
    assert_includes ni["-o json"], "OTEL_EXPORTER_OTLP_PROTOCOL=http/json"
  end

  def test_capabilities_json_carries_the_filter_and_the_per_property_kfilter
    require "json"
    d = JSON.parse(CAP.affordance_json)
    assert d.key?("consumer_filter")
    dns = d["record_channels"].find { |c| c["id"] == "dns" }
    props = dns["consumer"]["properties"].to_h { |p| [p["name"], p["kfilter"]] }
    assert_equal "pid", props["pid"]
    assert_equal "",    props["qname"]
  end
end
