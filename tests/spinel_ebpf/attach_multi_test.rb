# frozen_string_literal: true
#
# One definition, many attach points.
#
# The claim this file exists to keep true is D1: **the body is written one way**.
# A multi-symbol handler can be lowered two ways -- N expanded programs whose
# symbol index is a literal, or one SEC("kprobe.multi") program that reads a
# per-symbol cookie -- and which one runs depends on the LIST SIZE. If that
# difference could reach the author, then code written against a short list would
# break the day the list grew. So the strongest assertion here is not that either
# lowering works; it is that the `_inner` emitted for the SAME source is
# BYTE-IDENTICAL under both, and that only the wrapper differs.
#
# Driven against the production C codegen (src/codegen_c/spinel_ebpf_cc.c), the
# same binary tools/golden.rb pins.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/attach_multi_test.rb

require "minitest/autorun"
require "open3"
require "tmpdir"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/introspect"

class AttachMultiTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CC_H = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")

  # Mirror golden.rb's preflight: +x is not enough (build/ is bind-mounted, so
  # the binary here may be the other platform's). Skip rather than false-fail.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def emit(base, mode: nil)
    skip "codegen binary not runnable here" unless self.class.runnable?
    env = { "SPNL_ATTACH_MULTI" => mode }
    out, err, st = Open3.capture3(env, CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
    [out.dup.force_encoding("UTF-8").scrub, err.dup.force_encoding("UTF-8").scrub, st]
  end

  def inner_of(src)
    src[/^static __noinline .*?_inner\(.*?^\}$/m] or flunk("no _inner in emitted C")
  end

  # --- D1: the body is compiled once ---------------------------------------

  def test_the_inner_is_byte_identical_under_both_lowerings
    ex, _, ste = emit("155_attach_multi_auto", mode: "expand")
    mu, _, stm = emit("155_attach_multi_auto", mode: "multi")
    assert ste.success? && stm.success?
    refute_equal ex, mu, "the two lowerings must not produce the same FILE -- " \
                         "if they do, the env knob did nothing and this test proves nothing"
    assert_equal inner_of(ex), inner_of(mu),
                 "the handler body must be compiled once: only the wrapper may differ"
  end

  def test_only_the_wrapper_differs
    ex, = emit("155_attach_multi_auto", mode: "expand")
    mu, = emit("155_attach_multi_auto", mode: "multi")
    # Every line that differs belongs to a wrapper / manifest, never to the body.
    only_ex = ex.lines - mu.lines
    only_mu = mu.lines - ex.lines
    (only_ex + only_mu).each do |l|
      assert_match(/SEC\("kprobe|attach-multi|entry wrapper|int kprobe_multi__|_inner\(|\A[{}\s]*\z|\(void\)ctx/,
                   l, "a line outside the wrapper changed with the lowering: #{l.inspect}")
    end
  end

  # --- the single spelling lowers to one thing ------------------------------

  def test_attached_index_lowers_to_a_literal_when_expanded
    src, = emit("153_attach_multi_expand")
    assert_includes src, 'SEC("kprobe/vfs_read")'
    assert_includes src, 'SEC("kprobe/vfs_write")'
    assert_match(/_inner\(0\)/, src)
    assert_match(/_inner\(1\)/, src)
    refute_includes src, "bpf_get_attach_cookie"
  end

  def test_attached_index_lowers_to_the_cookie_when_multi
    src, = emit("154_attach_multi_multi")
    assert_includes src, 'SEC("kprobe.multi")'
    assert_includes src, "_inner((__s64)bpf_get_attach_cookie(ctx))"
    refute_includes src, 'SEC("kprobe/'
  end

  def test_attached_symbol_eq_is_resolved_at_compile_time
    # Both lowerings compare against the same index; neither emits a string.
    %w[153_attach_multi_expand 154_attach_multi_multi].each do |b|
      src, = emit(b)
      assert_includes src, "(__spnl_sym == 0)", "#{b}: vfs_read is index 0"
      refute_includes src, '"vfs_read"'
    end
  end

  # The affordance claims the multi kind takes its args "PT_REGS_PARM<N>(ctx) --
  # same as kprobe". kprobe_multi is fprobe-backed, so that is a claim about the
  # KERNEL, not about this codegen; it was measured on 7.1.5/arm64
  # (calls=50 / buf_nonzero=50 under BOTH lowerings). What is pinned here is the
  # part that broke first: the extractor needs <bpf/bpf_tracing.h>, and the
  # include list was keyed on an attach-kind allowlist that the new kind was not
  # in -- clang, not the codegen, was what said no.
  def test_params_reach_the_inner_and_pull_in_the_macro_header
    src, = emit("161_attach_multi_params")
    assert_includes src, "#include <bpf/bpf_tracing.h>"
    assert_includes src, "_inner((__s64)bpf_get_attach_cookie(ctx), " \
                         "(__s64)PT_REGS_PARM1(ctx), (__s64)PT_REGS_PARM2(ctx))"
  end

  # --- auto, and the escape hatch -------------------------------------------

  def test_auto_expands_below_the_threshold
    src, = emit("155_attach_multi_auto")
    assert_includes src, "mode=expand"
  end

  def test_via_beats_the_env_knob
    # `via:` is a deployment statement (the multi lowering raises the kernel
    # floor), so a measurement knob must not silently override it.
    src, = emit("154_attach_multi_multi", mode: "expand")
    assert_includes src, "mode=multi"
    src2, = emit("153_attach_multi_expand", mode: "multi")
    assert_includes src2, "mode=expand"
  end

  # --- the threshold lives in two languages, so it is gated -----------------

  def test_the_threshold_is_the_same_number_in_c_and_ruby
    c = File.read(CC_H)[/^#define CC_MULTI_AUTO_THRESHOLD (\d+)/, 1]
    refute_nil c, "CC_MULTI_AUTO_THRESHOLD not found in #{CC_H}"
    assert_equal SpinelEbpf::Capabilities::ATTACH_MULTI_THRESHOLD, c.to_i,
                 "the auto threshold drifted between the codegen and the affordance"
  end

  # --- the manifest is a contract between two files -------------------------

  def test_the_manifest_line_is_what_the_glue_parses
    src, = emit("154_attach_multi_multi")
    line = src[/^\/\* spnl:attach-multi .*\*\/$/] or flunk("no manifest line")
    # The exact regex bin/spinel-ebpf uses to find kprobe_multi programs.
    m = line.match(%r{/\* spnl:attach-multi kind=kprobe mode=multi n=\d+ prog=(\S+) syms=(\S+) \*/})
    refute_nil m, "the glue's reader would not match: #{line.inspect}"
    assert_equal "kprobe_multi__set0", m[1]
    assert_equal %w[vfs_read vfs_write], m[2].split(",")
    # And the named program must actually be in the emitted C.
    assert_includes src, "int #{m[1]}(struct pt_regs *ctx)"
  end

  def test_the_expanded_form_declares_itself_but_needs_no_glue
    src, = emit("153_attach_multi_expand")
    assert_includes src, "mode=expand"
    refute_match(%r{spnl:attach-multi kind=kprobe mode=multi}, src,
                 "an expanded set must not ask the glue for a kprobe_multi link")
  end

  # --- negative controls: the refusals ---------------------------------------

  def test_a_symbol_outside_the_list_is_refused
    _, err, st = emit("156_attach_multi_unknown_symbol")
    refute st.success?, "an unattached name can never match; it must not compile"
    assert_match(/not in this handler's list/, err)
    assert_match(/declared: vfs_read vfs_write/, err, "the message must name the alternatives")
  end

  def test_asking_which_symbol_outside_a_multi_handler_is_refused
    _, err, st = emit("157_attached_index_outside_multi")
    refute st.success?
    assert_match(/only available inside a multi-symbol handler/, err)
  end

  # Each malformed declaration is refused, and the message says WHY rather than
  # naming a rule. Run through the real codegen, not by grepping its source: what
  # matters is that the compile stops, not that the string exists.
  def test_malformed_declarations_are_refused_with_a_reason
    {
      "158_attach_multi_empty_list" => /symbol list is empty.*never fires/m,
      "159_attach_multi_duplicate"  => /duplicate symbol: vfs_read/,
      "160_attach_multi_bad_via"    => /`via:` must be :expand or :multi/,
    }.each do |base, want|
      _, err, st = emit(base)
      refute st.success?, "#{base} must not compile"
      assert_match want, err, "#{base}: the diagnostic does not explain itself"
    end
  end

  # The one trap that cannot be caught at run time: partition walks the AST, so a
  # list built by metaprogramming is invisible. The refusal has to say so, because
  # the author's next move after "element must be a literal" would otherwise be to
  # reach for `define_method`.
  def test_the_metaprogramming_dead_end_is_named_in_the_diagnostic
    assert_includes File.read(CC_H), "define_method"
  end

  # --- the affordance says all of this --------------------------------------

  def test_capabilities_publishes_the_attach_kind_and_its_two_mechanisms
    e = SpinelEbpf::Capabilities::ATTACH_KINDS.find { |a| a[:kind] == :kprobe_multi }
    refute_nil e, "kprobe_multi missing from ATTACH_KINDS"
    assert_equal "kprobe.multi", e[:sec]
    assert_match(/%w\[/, e[:method_prefix], "the surface is the reactor list form")
    assert_match(/5\.18/, e[:context_note], "the raised kernel floor must be stated")
    assert_match(/via: :expand/, e[:context_note])
  end

  def test_the_two_spellings_are_gated_to_multi_handlers
    %w[attached_index attached_symbol_eq].each do |b|
      req = SpinelEbpf::Capabilities::CONTEXT_REQUIREMENTS[b]
      refute_nil req, "#{b} has no context requirement"
      assert_equal %i[kprobe_multi], req[:kinds]
    end
  end

  def test_describe_names_the_chosen_mechanism_and_the_index_table
    src = File.read(File.join(ROOT, "examples/observability/attach_multi_demo.rb"))
    rep = SpinelEbpf::Introspect.report(src, path: "attach_multi_demo.rb")
    assert_match(/multi-symbol attach/, rep)
    assert_match(/3 symbols.*expand/, rep, "describe must say WHICH mechanism was picked")
    assert_match(/0\s+vfs_read/, rep, "attached_index is unreadable without the table")
    assert_match(/2\s+vfs_open/, rep)
  end

  # --- the branch is invisible to the BODY, not to DEPLOYMENT ---------------
  #
  # RECORDED GAP. The multi lowering needs kernel 5.18 (kprobe_multi +
  # bpf_get_attach_cookie); the expanded one needs nothing past the 5.2 baseline.
  # Measured: a `via: :multi` probe reported 5.8 (the ringbuf floor) while
  # kprobe_multi needs 5.18 -- an UNDERSTATEMENT, the one direction the portability
  # contract must never fail in: it would promise a 5.9 host that the probe
  # runs there, and the attach would fail at the customer. The portability row for
  # this attach kind was added later; this assertion is the one that pins it, and
  # it fails the moment the row goes missing again.
  #
  # The pair below is the point: the SAME source, compiled two ways, states two
  # different floors -- which is why `via:` has to stay reachable.
  def test_multi_raises_the_kernel_floor_and_expand_does_not
    require "spinel_ebpf/portability"
    multi  = File.read(File.join(ROOT, "tests/golden/154_attach_multi_multi.bpf.c"))
    expand = File.read(File.join(ROOT, "tests/golden/153_attach_multi_expand.bpf.c"))
    assert_equal "5.18", SpinelEbpf::Portability.contract(multi).ebpf["min_kernel"],
                 "the 5.18 floor kprobe_multi needs is missing from the contract " \
                 "(understating it is the one direction the contract must never get wrong)"
    assert_equal "5.8", SpinelEbpf::Portability.contract(expand).ebpf["min_kernel"],
                 "expand is a plain kprobe, so it must not raise the floor"
    # the affordance says the same number where a reader looks first
    e = SpinelEbpf::Capabilities::ATTACH_KINDS.find { |a| a[:kind] == :kprobe_multi }
    assert_match(/5\.18/, e[:context_note])
  end

  def test_describe_reports_the_multi_mechanism_and_its_kernel_floor
    src = File.read(File.join(FIX, "154_attach_multi_multi.rb"))
    rep = SpinelEbpf::Introspect.report(src, path: "154.rb")
    assert_match(/multi\s+\(stated with `via: :multi`/, rep)
    assert_match(/5\.18/, rep, "the mechanism is invisible to the body but not to deployment")
  end
end
