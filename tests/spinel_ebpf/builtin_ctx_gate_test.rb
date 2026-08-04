# frozen_string_literal: true
#
# The packet-context gate for the datapath builtins, and the quality of the
# message it fails with.
#
# Background -- why this test exists at all. Four fixtures say in their own opening
# comment that codegen must reject them (78 fib_lookup from a kprobe, 80/82 skb_*
# from XDP, 96 sk_assign_tcp from tc egress). The Ruby codegen -- the reference
# the in-process C codegen replaced -- raises UnsupportedNode on all four. The C
# port dropped the checks, and because tools/golden.rb only compared TEXT, each
# of them acquired a committed golden instead. Measured on 7.1.5-ebpf /
# clang 19.1.7, the four then failed in four different places and one did not
# fail at all:
#
#   78  clang        "use of undeclared identifier 'ctx'"
#   80  verifier     "program of this type cannot use helper bpf_skb_store_bytes"
#   82  verifier     "program of this type cannot use helper bpf_skb_load_bytes"
#   96  nothing      compiled and loaded; bpf_sk_assign simply cannot work there
#
# So "it fails eventually" is not a substitute for the gate: for 96 there is no
# eventually, and for 78/80/82 the message names a C identifier or a helper
# number rather than the thing the author got wrong. The fail-loud rule wants the
# refusal at the layer that still knows the author wrote `def kprobe__tcp_sendmsg`.
#
# This drives the PRODUCTION C codegen (src/codegen_c/spinel_ebpf_cc.c) directly,
# the same binary tools/golden.rb pins -- the Ruby oracle is retired, so testing
# it would prove nothing about what a user compiles.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/builtin_ctx_gate_test.rb

require "minitest/autorun"
require "open3"

class BuiltinCtxGateTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")

  # Mirror golden.rb's preflight: +x is not enough (build/ is bind-mounted into
  # the container, so the binary here may be built for the other platform). A
  # working binary prints its usage line with no args.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def skip_unless_cc
    skip "C codegen binary not runnable on this host (build: cc -O2 -o #{CC} " \
         "src/codegen_c/spinel_ebpf_cc.c)" unless self.class.runnable?
  end

  def run_cc(base)
    Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
  end

  # The fixture must be refused, and the message must carry the four things an
  # author (or an AI rewriting the probe) needs to act without reading codegen:
  # what was refused, why, which contexts do work, and where they wrote it.
  def assert_ctx_gate(base, builtin:, why:, contexts:, wrote_in:)
    skip_unless_cc
    _out, err, st = run_cc(base)
    refute st.success?, "#{base}: expected the codegen to refuse this fixture (its own " \
                        "comment says so), got exit 0"
    assert_includes err, builtin, "#{base}: message must name the builtin"
    why.each { |w| assert_includes err, w, "#{base}: message must say why" }
    contexts.each do |c|
      assert_includes err, c, "#{base}: message must name a context that works"
    end
    assert_includes err, wrote_in, "#{base}: message must say where the author wrote it"
    # It must NOT be one of the downstream messages this gate exists to replace.
    refute_includes err, "undeclared identifier"
    err
  end

  # ---- the four fixtures whose comments demand a refusal ---------------------

  def test_fib_lookup_from_kprobe_is_refused_at_codegen
    assert_ctx_gate("78_fib_lookup_kprobe",
                    builtin: "fib_lookup",
                    why: ["packet ctx", "routing table"],
                    contexts: ["def xdp__", "def tc__ingress__", "def tc__egress__"],
                    wrote_in: "kprobe__tcp_sendmsg")
  end

  def test_skb_store_from_xdp_is_refused_at_codegen
    msg = assert_ctx_gate("80_skb_rewrite_xdp",
                          builtin: "skb_store_byte",
                          why: ["__sk_buff", "xdp_md"],
                          contexts: ["def tc__ingress__", "def tc__egress__"],
                          wrote_in: "xdp__main")
    # XDP is the context the author is IN, so offering it back would be nonsense.
    refute_includes msg, "def xdp__"
  end

  def test_skb_load_from_xdp_is_refused_at_codegen
    assert_ctx_gate("82_nat_xdp",
                    builtin: "skb_load_u32",
                    why: ["__sk_buff", "xdp_md"],
                    contexts: ["def tc__ingress__", "def tc__egress__"],
                    wrote_in: "xdp__main")
  end

  # The one a compile/load gate cannot catch: it built and loaded fine.
  def test_sk_assign_from_tc_egress_is_refused_at_codegen
    msg = assert_ctx_gate("96_sk_assign_egress",
                          builtin: "sk_assign_tcp",
                          why: ["RECEIVED"],
                          contexts: ["def tc__ingress__"],
                          wrote_in: "tc__egress__steer")
    refute_includes msg, "def tc__egress__"
  end

  # ---- the gate must not fire where the builtin is legal --------------------
  #
  # A gate that refuses everything is not a gate. These are the positive fixtures
  # for the same builtins; each still produces its committed golden byte for byte
  # (so the gate added no output), which tools/golden.rb also checks -- asserted
  # here too so a single test file tells the whole story.
  def test_legal_uses_still_compile_and_are_byte_identical
    skip_unless_cc
    {
      "77_fib_lookup"  => "xdp__fib",           # fib_lookup from XDP
      "92_fib6"        => "tc__ingress__r6",    # fib_lookup6 from TC ingress
      "79_skb_rewrite" => "tc__egress__ttl",    # skb_* + csum from TC egress
      "81_nat_rewrite" => "tc__ingress__dnat",  # skb_* + csum from TC ingress
      "91_ip_options"  => "tc__ingress__demo",  # l4_offset from TC ingress
      "93_sk_lookup"   => "tc__ingress__sklook",# sk_lookup_tcp from TC ingress
      "94_router"      => "tc__ingress__router",# fib_lookup + redirect
      "95_sk_assign"   => "tc__ingress__steer", # sk_assign_tcp from TC INGRESS
    }.each do |base, meth|
      out, err, st = run_cc(base)
      assert st.success?, "#{base} (#{meth}) must still compile, got: #{err}"
      gold = File.join(GOLD, "#{base}.bpf.c")
      assert File.exist?(gold), "#{base}: expected a committed golden"
      assert_equal File.read(gold), out, "#{base}: the ctx gate changed the output"
    end
  end

  # ---- the two halves must agree -------------------------------------------
  #
  # A refused fixture may not also have a golden: that pair is the contradiction
  # this gate closed. tools/golden.rb enforces it over the whole corpus; this pins
  # it for the four that were actually wrong, so the property survives even if the
  # baseline file is regenerated carelessly.
  def test_refused_fixtures_have_no_golden
    skip_unless_cc
    %w[78_fib_lookup_kprobe 80_skb_rewrite_xdp 82_nat_xdp 96_sk_assign_egress].each do |b|
      refute File.exist?(File.join(GOLD, "#{b}.bpf.c")),
             "#{b}: the codegen refuses this fixture, so a golden for it is output " \
             "that can no longer be produced (delete tests/golden/#{b}.bpf.c)"
      assert File.exist?(File.join(FIX, "#{b}.rb")), "#{b}: the fixture itself must stay"
    end
  end
end
