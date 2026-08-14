# frozen_string_literal: true
#
# TargetProfile: the contract for the first step of making eligibility
# target-relative.
#
# Pinned here:
#   (1) the linux-ebpf profile is exactly equivalent to the historical
#       ebpf_impossible?/reasons pair (every existing caller, through the
#       delegators, is unchanged to the character)
#   (2) the AMP profile's call_allowlist is in lockstep with the declaration
#       both it and the C-side backstop (amp_scan_supported in
#       src/codegen_c/spinel_ebpf_cc.c) derive from -- change one side alone and
#       this test names the drift (the same shape as the two-partitioner
#       discipline)
#   (3) the allowlist governs identifier-shaped calls only (operator
#       CallNodes are structural)

require "minitest/autorun"
require "spinel_ebpf/partition"

class TargetProfileTest < Minitest::Test
  P = SpinelEbpf::TargetProfile
  Flags = SpinelEbpf::Partition::MethodFlags

  # ---- (1) linux profile == historical behavior ----

  def test_linux_profile_covers_every_flag
    assert_equal P::FLAG_REASONS.map(&:first), P::LINUX_EBPF.fatal_flags
  end

  def test_each_flag_is_fatal_on_linux_and_delegator_agrees
    P::ALL_FLAGS.each do |flag|
      f = Flags.default
      f[flag] = true
      assert f.impossible_for?(P::LINUX_EBPF), "#{flag} should be fatal on linux-ebpf"
      assert f.ebpf_impossible?, "delegator should agree for #{flag}"
      assert_equal f.reasons_for(P::LINUX_EBPF), f.reasons, "reasons delegator for #{flag}"
      assert_equal 1, f.reasons.length
    end
  end

  def test_clean_flags_are_eligible_on_linux
    f = Flags.default
    refute f.ebpf_impossible?
    assert_empty f.reasons
  end

  def test_linux_has_no_call_allowlist
    f = Flags.default
    f.calls.concat(%w[hist_observe pkt_len anything_at_all])
    refute f.impossible_for?(P::LINUX_EBPF)
    assert_empty f.unsupported_calls_for(P::LINUX_EBPF)
  end

  # ---- (2) AMP allowlist is in lockstep with the C backstop ----
  #
  # The allowlist's authority is now cc_builtin_targets in
  # src/codegen_c/builtin_schema.h: the Ruby profile reads the generated JSON and
  # the C backstop walks the same table through cc_builtin_on_target(). So this
  # test pins two things:
  #   (a) the profile's allowlist == the table's rows for this target (catching a
  #       re-literalization of what is supplied from the JSON)
  #   (b) the backstop really does consult the table (the mechanism's witness --
  #       a regression to an inline strcmp chain would keep dying on the old set
  #       however far the table is widened)

  C_SOURCE = File.expand_path("../../src/codegen_c/spinel_ebpf_cc.c", __dir__)
  SCHEMA_H = File.expand_path("../../src/codegen_c/builtin_schema.h", __dir__)

  def schema_side_allowlist(tgt_macro)
    src = File.read(SCHEMA_H)
    table = src[/static const CcBuiltinTargets cc_builtin_targets\[\] = \{(.*?)\n\};/m, 1]
    refute_nil table, "cc_builtin_targets is not in builtin_schema.h (did its shape change?)"
    table.scan(/\{\s*"(\w+)",\s*([^}]+)\}/)
         .select { |_, bits| bits.include?(tgt_macro) }
         .map(&:first).sort
  end

  def assert_backstop_walks_the_table(scan_fn, tgt_macro)
    src = File.read(C_SOURCE)
    fn = src[/static void #{scan_fn}.*?\n\}/m]
    refute_nil fn, "#{scan_fn} not found in spinel_ebpf_cc.c — the C backstop moved; update this test AND the profile together"
    assert_includes fn, "cc_builtin_on_target(nm, #{tgt_macro})",
                    "#{scan_fn} does not consult cc_builtin_on_target(#{tgt_macro}) — " \
                    "a backstop that regresses to another spelling keeps dying however " \
                    "far the table is widened"
  end

  def test_amp_allowlist_lockstep_with_c_backstop
    assert_equal schema_side_allowlist("CC_TGT_AMP"), P::AMP.call_allowlist.sort,
                 "AMP profile and the builtin_schema.h allowlist have drifted — only one side was changed"
    assert_backstop_walks_the_table("amp_scan_supported", "CC_TGT_AMP")
  end

  def test_amp_supported_summary_matches_c_message
    src = File.read(C_SOURCE)
    # The supported set the C die message enumerates and the profile summary
    # must describe the same surface.
    assert_includes src, "Supported: #{P::AMP.supported_summary}",
                    "amp_scan_supported's die message and profile.supported_summary have drifted"
  end

  # ---- (3) allowlist semantics ----

  def test_amp_rejects_identifier_calls_outside_allowlist
    f = Flags.default
    f.calls.concat(%w[hist_observe spnl_emit])
    assert f.impossible_for?(P::AMP)
    assert_equal %w[hist_observe], f.unsupported_calls_for(P::AMP)
    reason = f.reasons_for(P::AMP).join("; ")
    assert_includes reason, "hist_observe"
    assert_includes reason, "amp"
  end

  def test_amp_accepts_allowlisted_and_operator_calls
    f = Flags.default
    f.calls.concat(["spnl_emit", "ktime_ns", "+", "<<", ">=", "=="])
    refute f.impossible_for?(P::AMP)
  end

  def test_amp_still_applies_structural_flags
    f = Flags.default
    f.uses_float = true
    f.calls << "spnl_emit"
    assert f.impossible_for?(P::AMP)
  end

  # ---- classify carries the target (via Result) ----

  def test_result_carries_target_default_linux
    assert SpinelEbpf::Partition::Result.members.include?(:target)
  end
end
