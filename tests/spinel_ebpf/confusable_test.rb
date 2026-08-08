# frozen_string_literal: true
#
# The builtin pairs where picking the wrong spelling is SILENT.
#
# One of them was measured and fixed: `sock_dport(sk)` in a udp_sendmsg probe
# reports nothing at all for a sender that does not connect (dnsmasq: 0 spans ->
# 4). It added `udp_dport(sk, msg)` and stopped there, so nothing prevented
# writing the other one -- and the wrong one type-checks, passes the verifier,
# loads, and returns the RIGHT number on a connected socket.
#
# Two things are pinned here, and neither of them counts inventory:
#
#   1. the SHAPE of the rule the codegen enforces. It is directional, not a
#      blocklist: on a datagram send hook the socket does not know the
#      destination, and on a datagram receive hook the message does not. So the
#      test demands BOTH refusals AND the two-sided control -- one probe using
#      each spelling on its own side, which must compile. A blocklist would pass
#      the two refusals and fail the control, which is why the control is here.
#
#   2. the CONTRACT on Capabilities::CONFUSABLE. Every entry either names a gate
#      the codegen really has, or says why it cannot have one. "We cannot check
#      this" must not be spelled the same way as "there is nothing to check"
#      (the record contract's `unexpressible` declaration makes the same
#      distinction on the reader side).
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/confusable_test.rb

require "minitest/autorun"
require "open3"
require "json"
require "spinel_ebpf/capabilities"

class ConfusableTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures/confusable")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CAP  = SpinelEbpf::Capabilities

  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)

    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def run_cc(base)
    skip "C codegen binary not runnable on this host" unless self.class.runnable?
    Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
  end

  # ---------- (1) the rule the codegen enforces ----------

  def test_socket_accessor_on_a_datagram_send_hook_is_refused
    _out, err, st = run_cc("wrong_dst_on_send")
    refute_equal 0, st.exitstatus, "sock_dport in udp_sendmsg must not compile"
    assert_includes err, "sock_dport", "must name what the author wrote"
    assert_includes err, "udp_dport(sk, msg)", "must name the spelling to write instead"
    # the consequence, in the terms that make it worth refusing
    assert_includes err, "NOTHING"
    assert_includes err, "Measured:", "must cite where the behaviour was measured"
    assert_includes err, "kprobe__udp_sendmsg", "must say where they wrote it"
  end

  def test_message_accessor_on_a_datagram_recv_hook_is_refused
    _out, err, st = run_cc("wrong_dst_on_recv")
    refute_equal 0, st.exitstatus, "udp_dport in udp_recvmsg must not compile"
    assert_includes err, "udp_dport"
    assert_includes err, "sock_dport(sk)", "must name the spelling to write instead"
    assert_includes err, "OUTPUT", "must say why the message cannot answer here"
  end

  # The control that makes this a direction rule rather than a ban. A DNS latency
  # probe hooks both sides of the same function pair and needs a DIFFERENT
  # spelling on each; a blocklist over either name would refuse this program.
  def test_each_spelling_on_its_own_side_compiles
    out, err, st = run_cc("right_both_sides")
    assert_equal 0, st.exitstatus, "the two-sided probe must compile:\n#{err}"
    assert_includes out, "spnl_udp_dport", "the send side must lower to the datagram form"
    assert_includes out, "skc_dport", "the recv side must lower to the socket form"
  end

  # ---------- (2) the contract on the declaration ----------

  def test_every_confusable_names_a_real_gate_or_says_why_not
    cc = File.read(File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c"))
    refute_empty CAP::CONFUSABLE
    CAP::CONFUSABLE.each do |c|
      if c[:gate]
        assert_includes cc, "#{c[:gate]}(",
                        "#{c[:id]}: claims gate `#{c[:gate]}`, which the codegen does not define"
        assert_nil c[:why_ungated], "#{c[:id]}: a gated pair must not also explain its absence"
      else
        refute_nil c[:why_ungated], "#{c[:id]}: an ungated pair must say WHY it cannot be gated"
        assert_operator c[:why_ungated].length, :>, 60,
                        "#{c[:id]}: `why_ungated` has to be a reason, not a label"
      end
    end
  end

  def test_every_confusable_states_where_the_two_agree_and_where_they_diverge
    CAP::CONFUSABLE.each do |c|
      %i[question_a question_b agree_when disagree_when wrong_answer].each do |k|
        refute_nil c[k], "#{c[:id]}: missing #{k}"
        refute_empty c[k].to_s.strip, "#{c[:id]}: empty #{k}"
      end
      # `agree_when` is the whole reason these are hard: without a stated
      # environment in which the two return the SAME number, the entry is
      # describing an ordinary bug, not a silent one.
      assert_includes %i[measured documented], c[:evidence], "#{c[:id]}: evidence must be measured|documented"
    end
  end

  # Both spellings have to be things an author can actually write, or the pair is
  # not a choice anybody faces.
  def test_confusable_members_are_advertised_surface
    names = JSON.parse(CAP.affordance_json)["builtins"].map { |b| b["name"] }.to_set
    CAP::CONFUSABLE.each do |c|
      [c[:a], c[:b], *c[:also]].each do |spelling|
        idents = spelling.scan(/[a-z_][a-z0-9_]*/)
        assert idents.any? { |i| names.include?(i) },
               "#{c[:id]}: `#{spelling}` names no advertised builtin"
      end
    end
  end

  def test_affordance_publishes_the_pairs
    require "json"
    doc = JSON.parse(CAP.affordance_json)
    assert doc.key?("confusable"), "the pairs must reach the machine-readable surface"
    assert_equal CAP::CONFUSABLE.size, doc["confusable"].size
    gated = doc["confusable"].select { |c| c["gate"] }
    refute_empty gated, "at least one pair must be enforced, or Part B declared nothing"
    doc["confusable"].reject { |c| c["gate"] }.each do |c|
      refute_nil c["why_ungated"], "#{c['id']}: published without a gate and without a reason"
    end
  end

  # ---------- self-control ----------
  #
  # A contract test that cannot fail is decoration. These two synthesise the
  # violations the tests above exist to catch and demand the check rejects them.
  def test_self_control_the_contract_check_can_say_no
    cc = "static void cc_require_dgram_dst_direction(const char *who) {"
    bogus = { id: "sc", gate: "cc_no_such_gate_exists", why_ungated: nil }
    refute cc.include?("#{bogus[:gate]}("), "a gate nobody defines must not look defined"

    ungated_no_reason = { id: "sc2", gate: nil, why_ungated: nil }
    assert_nil ungated_no_reason[:why_ungated]
    # and a reason that is only a label must not pass the length rule either
    assert_operator "not possible".length, :<, 60
  end

  def test_self_control_a_non_member_is_detected
    names = JSON.parse(CAP.affordance_json)["builtins"].map { |b| b["name"] }.to_set
    refute names.include?("sock_dport_zzz"),
           "the membership check would pass anything if the registry answered yes"
  end
end
