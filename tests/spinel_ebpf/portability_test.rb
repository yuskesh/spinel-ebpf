# frozen_string_literal: true

require "minitest/autorun"
require "spinel_ebpf/portability"

# The portability contract, stated per partition.
class PortabilityTest < Minitest::Test
  P = SpinelEbpf::Portability

  def test_no_ebpf_partition_keeps_only_the_upstream_contract
    c = P.contract(nil)
    assert_nil c.ebpf
    assert_match(/POSIX/, c.native["platform"])
    assert_match(/gcc/, c.native["toolchain"])
    assert_match(/native/, P.human(c))
  end

  def test_empty_source_is_treated_as_no_ebpf
    assert_nil P.contract("").ebpf
  end

  def test_floor_is_core_btf_when_no_known_feature_is_used
    c = P.contract('SEC("kprobe/do_sys_openat2") int probe(void) { return 0; }')
    assert_equal P::BASE_EBPF_KERNEL, c.ebpf["min_kernel"]
    assert_empty c.ebpf["reasons"]
  end

  def test_floor_is_the_max_over_the_features_actually_used
    # ringbuf (5.8) + d_path (5.10) + lsm (5.7) -> 5.10 dominates.
    c = P.contract('SEC("lsm/file_open") bpf_ringbuf_reserve bpf_d_path')
    assert_equal "5.10", c.ebpf["min_kernel"]
    keys = c.ebpf["reasons"].map { |r| r["feature"] }
    assert_includes keys, "ringbuf"
    assert_includes keys, "lsm"
    assert_includes keys, "d_path"
  end

  def test_version_compare_is_numeric_not_lexical
    # 5.9 < 5.17: a string compare would wrongly pick "5.9".
    c = P.contract("bpf_loop bpf_ringbuf_reserve")
    assert_equal "5.17", c.ebpf["min_kernel"]
  end

  def test_reasons_are_ordered_newest_first
    c = P.contract("bpf_loop bpf_ringbuf_reserve bpf_d_path")
    kernels = c.ebpf["reasons"].map { |r| P.version_key(r["kernel"]) }
    assert_equal kernels.sort.reverse, kernels
  end

  def test_xdp_floor_reflects_the_link_based_attach_choice
    # We attach XDP via bpf_link (5.9+) so a foreign program is never replaced
    # and a SIGKILL leaves no trace. That choice IS a version floor.
    c = P.contract('SEC("xdp") int xdp__main(void) { return 2; }')
    assert_equal "5.9", c.ebpf["min_kernel"]
    assert_equal "xdp", c.ebpf["reasons"].first["feature"]
  end

  def test_lsm_carries_the_silent_failure_caveat
    c = P.contract('SEC("lsm/file_open")')
    assert(c.ebpf["caveats"].any? { |x| x.include?("silent") },
           "BPF LSM must warn that it attaches but never fires without lsm=...,bpf")
  end

  def test_undeclared_features_are_named_not_guessed
    # Fail loud: an unknown floor is reported as unknown, never invented.
    c = P.contract("struct tcp_congestion_ops x;")
    refute_empty c.ebpf["undeclared"]
    assert_match(/floor not established/, P.human(c))
  end

  def test_requires_btf_and_privilege
    c = P.contract("bpf_ringbuf_reserve")
    assert(c.ebpf["requires"].any? { |r| r.include?("BTF") })
    assert(c.ebpf["requires"].any? { |r| r.include?("CAP_BPF") })
  end

  # Correction (2026-08-03, from a survey of upstream ebpf-go): the note used to
  # claim architecture-neutrality with no qualifier. clang has three BPF targets
  # (bpf / bpfel / bpfeb) and bpf2go's default is "bpfel,bpfeb" -- upstream
  # builds one object per endianness, so neutrality holds *within* one.
  def test_arch_note_bounds_neutrality_to_one_endianness
    c = P.contract("bpf_ringbuf_reserve")
    note = c.ebpf["arch_note"]
    assert_match(/architecture-independent/, note)
    assert_match(/within one endianness/, note,
                 "the neutrality claim must carry its endianness bound, not stand alone")
  end

  def test_endian_note_names_the_endianness_the_skeleton_was_built_for
    e = P.contract("bpf_ringbuf_reserve").ebpf["endian_note"]
    assert_match(/-target bpf/, e, "say how the bytecode was produced, not just that it travels")
    assert_match(/build host/, e)
  end

  # Same discipline as `undeclared`: what we have not checked is reported as
  # unchecked. A big-endian target is neither promised nor declared broken.
  def test_crossing_endianness_is_reported_as_untested_not_as_supported
    e = P.contract("bpf_ringbuf_reserve").ebpf["endian_note"]
    assert_match(/untested/, e)
    refute_match(/\bis verified\b|\bknown to work\b/, e,
                 "spinel-ebpf has only ever built and run on little-endian hosts")
  end

  # The contract is only worth something if the reader sees it: `human` is what
  # compile prints after the partition table and what MANIFEST.md embeds.
  def test_human_states_the_endianness_bound_for_an_ebpf_unit
    h = P.human(P.contract("bpf_ringbuf_reserve"))
    assert_match(/within one endianness/, h)
    assert_match(/untested/, h)
  end

  def test_human_says_nothing_about_endianness_when_there_is_no_ebpf_partition
    # A native-only unit ships no bytecode, so it carries no such limit.
    refute_match(/endian/i, P.human(P.contract(nil)))
  end

  def test_to_h_round_trips_both_sides
    h = P.to_h(P.contract("bpf_ringbuf_reserve"))
    assert h["native"]
    assert_equal "5.8", h["ebpf"]["min_kernel"]
  end

  # --- arch binding ---------------------------------------------------------
  #
  # Measured on an arm64 host (kernel 7.1.5-ebpf, clang 19.1.7) across all 118
  # goldens: the 37 units that read arguments out of registers compile for zero
  # foreign arches, and the 80 that do not are instruction-identical under both
  # -D__TARGET_ARCH_arm64 and -D__TARGET_ARCH_x86.

  def test_register_argument_access_binds_the_unit_to_one_arch
    c = P.contract("v = (__s64)PT_REGS_PARM1(ctx);", build_arch: "arm64")
    assert c.ebpf["arch_bound"]
    assert_equal "arm64", c.ebpf["build_arch"]
    refute_empty c.ebpf["arch_bound_by"]
  end

  # The binding is not "kprobe", it is "reads arguments from registers". A
  # handler on the same attach point with no parameters emits no PT_REGS_PARM
  # and built byte-identically under both macros (measured with a matched pair
  # through the real pipeline), so it must NOT be reported as bound.
  def test_an_attach_point_alone_does_not_bind_the_arch
    c = P.contract('SEC("kprobe/do_sys_openat2") int probe(void *ctx) { return 0; }')
    refute c.ebpf["arch_bound"]
    assert_empty c.ebpf["arch_bound_by"]
  end

  # Two USDT goldens contain zero PT_REGS_PARM and still failed under the
  # foreign macro: <bpf/usdt.bpf.h> reads pt_regs.ip itself. Keying only on our
  # own emitted macro would have called them portable.
  def test_usdt_binds_the_arch_even_with_no_pt_regs_parm_of_our_own
    src = '#include <bpf/usdt.bpf.h>' + "\n" + 'bpf_usdt_arg(ctx, 0, &v);'
    refute_match(/PT_REGS_PARM/, src, "this fixture must not smuggle in the other marker")
    assert P.contract(src).ebpf["arch_bound"]
  end

  def test_usdt_reports_its_binding_once_not_once_per_marker
    # Both markers are present; they describe one binding, so say it once.
    src = '#include <bpf/usdt.bpf.h>' + "\n" + 'bpf_usdt_arg(ctx, 0, &v);'
    assert_equal 1, P.contract(src).ebpf["arch_bound_by"].length
  end

  def test_human_puts_the_unit_verdict_on_the_arch_line_for_a_bound_unit
    # A reader who stops at the `arch` line must not come away with the
    # unqualified neutrality claim, so the verdict outranks the general note.
    line = P.human(P.contract("PT_REGS_PARM1(ctx)", build_arch: "arm64"))
              .lines.find { |l| l.include?("arch    :") }
    assert_match(/architecture-bound/, line)
    assert_match(/arm64/, line)
  end

  def test_human_says_a_free_unit_is_free_rather_than_staying_silent
    # "not bound" and "nobody checked" must not look the same to the reader.
    line = P.human(P.contract('SEC("xdp") int x(void *c){return 2;}'))
              .lines.find { |l| l.include?("arch    :") }
    refute_match(/architecture-bound/, line)
    assert_match(/not bound to an architecture/, line)
  end

  # Same discipline as `undeclared` and the endianness note: what was measured
  # is "this host cannot build it for that arch". Whether a correctly built
  # object runs there was never measured -- and a probe has been shipped to a
  # foreign machine by supplying that machine's BTF -- so the contract must not
  # close that door.
  def test_arch_bound_note_does_not_claim_the_probe_would_not_work_elsewhere
    note = P.contract("PT_REGS_PARM1(ctx)", build_arch: "arm64").ebpf["arch_unit_note"]
    assert_match(/does not compile/, note, "state the thing that WAS measured")
    assert_match(/was not measured|not a finding/, note)
    refute_match(/will not work on another arch|does not work on other architectures/, note)
  end

  def test_arch_bound_note_names_what_binds_it_and_how_to_target_another_arch
    note = P.contract("PT_REGS_PARM1(ctx)", build_arch: "arm64").ebpf["arch_unit_note"]
    assert_match(/pt_regs/, note, "name the mechanism, not just the verdict")
    assert_match(/rebuild/, note, "an unusable contract states a cost with no remedy")
  end

  # The arch verdict appended keys; the pre-existing ones keep their meaning
  # (the same append-only rule the record contract is held to,
  # tools/record_gate.rb).
  def test_arch_keys_are_appended_without_disturbing_the_existing_ones
    e = P.to_h(P.contract("PT_REGS_PARM1(ctx) bpf_ringbuf_reserve"))["ebpf"]
    %w[platform min_kernel requires reasons caveats undeclared arch_note endian_note].each do |k|
      assert e.key?(k), "existing contract key #{k} disappeared"
    end
    assert_match(/within one endianness/, e["arch_note"], "arch_note must keep its old meaning")
    %w[build_arch arch_bound arch_bound_by arch_unit_note].each { |k| assert e.key?(k) }
  end

  def test_build_arch_follows_the_host_the_same_way_the_clang_argv_does
    # bin/spinel-ebpf picks -D__TARGET_ARCH_* off RbConfig host_cpu; the
    # contract must name the arch the compiler was actually told about.
    assert_includes %w[arm64 x86_64], P.build_arch
  end
  # Literal `n.times` lowers to the open-coded iterator, which raises
  # the floor from bpf_loop's 5.17 to 6.4. The declaration for that has been in
  # FEATURES all along -- but a declared marker is not a detected one (we once found
  # `SEC("kprobe.multi` declared nowhere and the multi lowering under-reporting
  # 5.8 as a result). So this reads the marker off the REAL codegen output rather
  # than a hand-written string: if the emitted spelling ever drifts from
  # "bpf_iter_num_new", the floor silently drops back to 5.17 and a probe gets
  # shipped claiming it runs on kernels that have no such kfunc.
  def test_open_coded_iterator_floor_is_read_off_the_real_codegen_output
    src = File.read(File.expand_path("../golden/183_open_coded_loop.bpf.c", __dir__))
    c = P.contract(src)
    assert_equal "6.4", c.ebpf["min_kernel"]
    keys = c.ebpf["reasons"].map { |r| r["feature"] }
    assert_includes keys, "open_coded_iter"
    # That fixture carries a dynamic-N loop too: both lowerings are named, and
    # the newer one wins the floor rather than either one being dropped.
    assert_includes keys, "bpf_loop"
    # The prose must say WHICH n.times this is about -- "open-coded iterator"
    # alone does not tell a reader why their dynamic-N loop did not raise the floor.
    assert_match(/literal/i, c.ebpf["reasons"].find { |r| r["feature"] == "open_coded_iter" }["why"])
  end

end
