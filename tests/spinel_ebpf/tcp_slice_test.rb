# frozen_string_literal: true

# The pure-XDP TCP slice -- the `xdp__tcp_slice__` attach kind and the seven
# builtins that an audit withdrew along with it.
#
# What these tests are for, and what they deliberately are NOT for:
#
#   * the generated C is pinned by tests/golden/{144_tcp_slice,
#     174_tcp_slice_builtins}.bpf.c, and whether it BUILDS AND LOADS is pinned by
#     tests/golden/compile_status.tsv. Neither is re-done here.
#   * what is here is the set of facts that live in TWO places and that no gate
#     compiles together -- the kind of fact successive audits each found a drift
#     in.
#
# The load-bearing one is the syncookie asymmetry: `gen` must resize the frame
# and `check` must not. It is invisible in the golden (both are just C), it is
# invisible to the affordance gate (both compile), and getting it backwards
# produces a program that either does not load at all or silently damages the
# handshake ACK. All three variants were measured; this test pins the outcome.
require "minitest/autorun"
require "spinel_ebpf/capabilities"

class TcpSliceTest < Minitest::Test
  CAP = SpinelEbpf::Capabilities
  ROOT = File.expand_path("../..", __dir__)
  TPL  = File.join(ROOT, "src/codegen_c/templates")
  CC   = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")

  def tpl(name) = File.read(File.join(TPL, "#{name}.template.c"))
  def cc_src    = (@cc ||= File.read(CC))

  BUILTINS = %w[tcp_syncookie_gen tcp_syncookie_check tcp_reply_header
                tcp_reply_synack tcp_synack_cookie tcp_reply_data payload_starts].freeze

  # ---------------------------------------------------------------- the seven

  def test_all_seven_are_advertised_and_none_is_withdrawn
    BUILTINS.each do |b|
      assert_includes CAP.all_builtins, b, "#{b} is not in the affordance"
      refute_includes CAP::WITHDRAWN.keys, b, "#{b} is both advertised and withdrawn"
      assert CAP.signature_for(b), "#{b} has no signature"
    end
  end

  # The seven were withdrawn AS A SET, on the stated ground that they only made
  # sense with the bundle. Coming back as a set is therefore part of the claim --
  # six-of-seven would leave the affordance describing a machine that cannot be
  # written. (A partial port is exactly what the audits kept finding.)
  def test_the_set_is_whole_in_the_codegen
    BUILTINS.each do |b|
      assert_includes cc_src, "\"#{b}\"", "#{b} is not in the C codegen"
    end
  end

  # All seven touch or resize the frame through `struct xdp_md`. The gate is not
  # decoration: in TC the same names would reach clang and die naming a C
  # identifier instead of the hook the author chose (a refusal has to be spelled
  # in the author's vocabulary; there is no silent fallback).
  def test_all_seven_are_gated_to_xdp
    BUILTINS.each do |b|
      req = CAP::CONTEXT_REQUIREMENTS[b]
      refute_nil req, "#{b} has no context requirement"
      assert_equal %i[xdp], req[:kinds], "#{b}'s gate admits something other than xdp"
    end
  end

  # The slice attach kind discards the body, so a builtin written INSIDE it would
  # be dropped without a diagnostic. "Allowed there" would be the one context
  # where the affordance's answer is a lie, which is why xdp_tcp_slice is absent
  # from every mask above.
  def test_the_gate_does_not_admit_the_bundle_kind
    BUILTINS.each do |b|
      refute_includes CAP::CONTEXT_REQUIREMENTS[b][:kinds], :xdp_tcp_slice,
                      "#{b} is permitted inside the kind that discards the body"
    end
  end

  # The two literal-taking builtins cannot be called with a placeholder, so the
  # affordance has to publish a real literal -- the gate compiles `example_for`
  # verbatim, and a positional stand-in would make the gate test the refusal
  # instead of the feature.
  def test_literal_taking_builtins_publish_a_compilable_example
    { "payload_starts" => /payload_starts\(".+"\)/,
      "tcp_reply_data" => /tcp_reply_data\(.+, ".+"\)/ }.each do |b, re|
      ex = CAP.example_for(b)
      refute_nil ex, "#{b} has no example (the gate cannot call it)"
      assert_match re, ex, "#{b}'s example does not pass a string literal"
    end
  end

  # ------------------------------------------------- the syncookie asymmetry

  # The central measurement, in the form that can rot silently.
  #
  # bpf_tcp_raw_gen_syncookie_ipv4 demands TCP_MAXLEN (60) bytes readable
  # whatever the actual header length is, so `gen` must grow the frame first.
  # bpf_tcp_raw_check_syncookie_ipv4 does not, so `check` must NOT -- it runs on
  # the handshake ACK, a frame that has to be passed on undisturbed.
  #
  # Measured on 7.1.5: the un-grown form -- which is what the retired Ruby oracle
  # emitted -- does not load at all.
  def test_syncookie_gen_grows_the_frame_and_check_does_not
    gen   = tpl("bi_syncookie_gen")
    check = tpl("bi_syncookie_check")
    assert_includes gen, "bpf_xdp_adjust_tail",
                    "gen does not grow the frame -- the kfunc requires 60 readable bytes " \
                    "whatever the real header length is"
    refute_includes check, "bpf_xdp_adjust_tail",
                    "check touches the frame -- that damages the handshake ACK it runs on"
    assert_includes gen, "bpf_tcp_raw_gen_syncookie_ipv4"
    assert_includes check, "bpf_tcp_raw_check_syncookie_ipv4"
  end

  # The grow ALONE is not enough: variant B (grow + re-read, no explicit bound)
  # also fails to load. Two more things are load-bearing and both are one line,
  # i.e. both are the kind of thing a later tidy-up removes.
  def test_gen_keeps_the_barrier_and_the_explicit_sixty_byte_bound
    gen = tpl("bi_syncookie_gen")
    assert_includes gen, 'asm volatile("" ::: "memory")',
                    "the compiler barrier is gone -- clang re-reads data_end from ctx+4 " \
                    "instead of after the resize, and the verifier rejects the program"
    assert_match(/\(char \*\)tcp \+ 60 > \(char \*\)data_end/, gen,
                 "the explicit 60-byte bound after the grow is gone -- bpf_xdp_adjust_tail " \
                 "alone does not teach the verifier the bytes are there (variant B above)")
  end

  # The reason the two are separate templates at all. If they ever merge back
  # into one parameterised template, one of the two behaviours is wrong.
  def test_gen_and_check_are_separate_templates
    assert File.exist?(File.join(TPL, "bi_syncookie_gen.template.c"))
    assert File.exist?(File.join(TPL, "bi_syncookie_check.template.c"))
    refute File.exist?(File.join(TPL, "bi_syncookie.template.c")),
           "gen and check have merged back into one template -- one of the two must grow " \
           "the frame and the other must not"
  end

  # The caller-visible consequence of the grow, which is why it is documented
  # rather than hidden: gen leaves a 60-byte TCP header behind and reply_synack
  # is what shrinks it. Both halves have to say so.
  def test_the_resize_is_stated_where_a_caller_would_look
    assert_match(/tcp_synack_cookie/, CAP.signature_for("tcp_syncookie_gen")[:summary],
                 "gen's summary does not point at the alternative that does both steps " \
                 "in one call")
    assert_match(/60|grow/, CAP.signature_for("tcp_syncookie_gen")[:summary],
                 "gen's summary does not mention that it resizes the frame")
  end

  # ------------------------------------------------------- the attach kind

  def test_attach_kind_is_advertised_and_not_withdrawn
    e = CAP::ATTACH_KINDS.find { |a| a[:kind] == :xdp_tcp_slice }
    refute_nil e, "xdp_tcp_slice is not in ATTACH_KINDS"
    assert_equal "xdp", e[:sec]
    refute_includes CAP::WITHDRAWN_ATTACH.keys, :xdp_tcp_slice
  end

  # The one attach kind whose body is thrown away. It has to be MACHINE-READABLE
  # (the affordance gate's stage 2 asks "did the body reach the C?", which is
  # false here by design) and it has to be readable by a person, because nothing
  # downstream will ever tell them: the compile succeeds and the slice works.
  def test_the_discarded_body_is_declared_not_just_documented
    e = CAP::ATTACH_KINDS.find { |a| a[:kind] == :xdp_tcp_slice }
    assert_equal :discarded, e[:body]
    assert_equal "spnl_tcp_slice_main", e[:emits],
                 "since the body is discarded, the entry has to name the symbol the gate " \
                 "should look for instead"
    assert_includes tpl("tcp_slice"), "spnl_tcp_slice_main",
                    "the template does not emit the symbol the affordance names"
  end

  # The codegen and the affordance must agree that this prefix is checked BEFORE
  # the plain `xdp__` one -- "xdp__tcp_slice__health" starts with "xdp__", and
  # answering from the shorter prefix is exactly the false negative that let an
  # unported attach kind look present (a prefix scan answers "present").
  def test_the_bundle_prefix_is_matched_before_plain_xdp
    i_slice = cc_src.index('cc_starts(name, "xdp__tcp_slice__"')
    i_plain = cc_src.index('cc_starts(name, "xdp__", &rest)')
    refute_nil i_slice, "there is no xdp__tcp_slice__ branch"
    refute_nil i_plain
    assert i_slice < i_plain,
           "the xdp__ branch comes first -- a tcp_slice would be lowered as an " \
           "ordinary XDP program"
  end

  # ------------------------------------------------------------- the maps

  def test_both_maps_are_claimed_with_what_happens_when_they_fill
    %w[bpf_conntab bpf_ts_counters].each do |m|
      claim = CAP::MAPS.find { |x| x[:map] == m }
      refute_nil claim, "#{m} has no claim"
      assert_equal %w[xdp_tcp_slice], claim[:created_by]
      refute_empty claim[:when_full].to_s, "#{m} has no when_full"
    end
    conntab = CAP::MAPS.find { |x| x[:map] == "bpf_conntab" }
    # The one that matters operationally: an LRU does not fail, it forgets, and
    # the forgetting shows up as requests that are never answered.
    assert_match(/LRU|evict/, conntab[:when_full])
  end

  # ------------------------------------------------------- the kernel floor

  # The slice raises the floor to 6.8 -- higher than SEC("xdp") (5.9), higher
  # than the bpf_timer it embeds (5.15), higher than USER_RINGBUF (6.1, which was
  # the previous maximum). Under-reporting a floor is the one direction the
  # portability contract may never take, so both kfunc markers are listed.
  def test_both_syncookie_kfuncs_raise_the_floor_to_6_8
    require "spinel_ebpf/portability"
    mk = SpinelEbpf::Portability::MIN_KERNEL
    %w[bpf_tcp_raw_gen_syncookie_ipv4 bpf_tcp_raw_check_syncookie_ipv4].each do |sym|
      f = mk[sym]
      refute_nil f, "#{sym} is not in MIN_KERNEL (the floor would be under-reported)"
      assert_equal "6.8", f.kernel
    end
    # The bundle uses both; a hand-written slice may use only one. Either alone
    # has to produce the same floor, which is why they are two entries and not
    # one: a missing marker is how a floor gets under-reported.
    assert_equal mk["bpf_tcp_raw_gen_syncookie_ipv4"].kernel,
                 mk["bpf_tcp_raw_check_syncookie_ipv4"].kernel
  end
end
