# frozen_string_literal: true
#
# `on :timer, every: N.<unit>` -- the bpf_timer reactor handler, re-ported from
# the retired Ruby codegen.
#
# WHAT IS ACTUALLY AT RISK HERE, and why this file is not just "does it compile".
#
# The audit that withdrew this surface measured it as the worst of the five it
# withdrew: the C reactor table had no :timer entry, unknown kinds are SKIPPED,
# so the handler body never reached the emitted C -- and the advertised SEC
# ("syscall") is the same string a silently degraded program carries, so a
# SEC-comparison audit called it fine. The only tell was "did the body come
# out". That question is asserted here by hand
# (test_the_handler_body_reaches_the_emitted_c) as well as by the affordance
# gate, because it is the one this feature dies of.
#
# The re-port also created three JOINS that live in different languages, and a
# join nothing checks is a join that drifts:
#
#   1. the time-unit table   Ruby Partition::BPF_TIMER_UNIT_NS  <->  C CC_TIMER_UNITS
#   2. the synthesized name  Ruby BPF_EVENT_LOOP_KINDS["timer"] <->  C cc_reactor_kind
#   3. the arm program name  C codegen emits spnl_timer_arm_*   <->  glue.c looks
#                            for it with strncmp(..., 15) in bin/spinel-ebpf
#
# (3) is the interesting one: the glue side SURVIVED the port from the Ruby
# code generator to the C one and was left searching for a program no codegen
# emitted. It is load-bearing again, and its two halves live in two files.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/timer_test.rb

require "minitest/autorun"
require "spinel_ebpf/loader_contract_gen"   # the codegen <-> loader seam
require "open3"
require "spinel_ebpf/partition"
require "spinel_ebpf/capabilities"

class TimerTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CC_H = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
  GLUE = File.join(ROOT, "bin/spinel-ebpf")
  TPL  = File.join(ROOT, "src/codegen_c/templates")

  P   = SpinelEbpf::Partition
  CAP = SpinelEbpf::Capabilities

  # Same preflight golden.rb uses: +x is not enough, because build/ is
  # bind-mounted into the container and may hold the other platform's binary.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def emit(base)
    skip "C codegen binary not runnable on this host" unless self.class.runnable?
    out, err, st = Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
    [out.dup.force_encoding("UTF-8").scrub, err.dup.force_encoding("UTF-8").scrub, st]
  end

  def cc_source = @cc_source ||= File.read(CC_H)

  # --- join 1: the time-unit table exists twice ----------------------------

  # The C codegen builds the reactor itself and never sees a MethodInfo, so the
  # unit table was mirrored rather than threaded across the boundary. Mirrored
  # tables drift; the multi-attach threshold is pinned across the two languages
  # the same way, for the same reason.
  def c_timer_units
    body = cc_source[/CC_TIMER_UNITS\[\][^{]*\{(.*?)\n\};/m]
    refute_nil body, "CC_TIMER_UNITS not found in #{CC_H} -- if it was renamed, this " \
                     "test stopped checking the Ruby/C unit tables agree"
    body.scan(/\{\s*"([a-z]+)"\s*,\s*(\d+)LL\s*\}/).to_h { |u, n| [u, n.to_i] }
  end

  def test_the_time_unit_tables_agree_between_ruby_and_c
    assert_equal P::BPF_TIMER_UNIT_NS, c_timer_units,
                 "the Ruby partition and the C codegen disagree about what a time unit is " \
                 "worth. The C table is what gets folded into bpf_timer_start; the Ruby one " \
                 "is what `describe` and the partition report. A probe would then be " \
                 "documented as firing at one rate and compiled to another."
  end

  def test_every_unit_is_a_positive_number_of_nanoseconds
    c_timer_units.each do |unit, ns|
      assert_operator ns, :>, 0, "#{unit} maps to #{ns} ns"
    end
    assert_equal 1_000_000_000, c_timer_units.fetch("seconds")
    assert_equal 1_000_000,     c_timer_units.fetch("ms")
    assert_equal 1,             c_timer_units.fetch("ns")
  end

  # --- join 2: the synthesized method name ---------------------------------

  def test_the_reactor_synthesizes_the_same_method_name_in_both_languages
    ruby_prefix = P::BPF_EVENT_LOOP_KINDS.fetch("timer").prefix
    c_table = cc_source[/static const ReactorKind K\[\] = \{(.*?)\n  \};/m]
    refute_nil c_table, "the C reactor table was not found"
    c_prefix = c_table[/\{"timer",\s*"([^"]+)"/, 1]
    refute_nil c_prefix, "the C reactor table has no :timer entry. That absence IS the " \
                         "failure this surface was withdrawn for: an unknown reactor kind " \
                         "is skipped, so the handler body never reaches the emitted C and " \
                         "the probe still exits 0."
    assert_equal ruby_prefix, c_prefix
  end

  # --- join 3: the glue has been waiting for this name ---------------------

  def test_the_glue_searches_for_the_program_name_the_codegen_emits
    glue = File.read(GLUE)
    # The prefix and its strncmp length both come from
    # src/codegen_c/loader_contract.h -- the generator computes the length from
    # the token, so "the length matches the literal" is no longer a thing that
    # CAN be false and is no longer asserted here. What is still checked is that
    # the loader searches at all, and that the template emits a name that starts
    # with the declared prefix.
    assert_includes glue,
                    %(strncmp(name, "\#{lc::PREFIX_TIMER_ARM}", \#{lc::PREFIX_TIMER_ARM_LEN})),
                    "bin/spinel-ebpf no longer greps for the timer arm program. That glue " \
                    "(_spnl_timer_arm_all) is what fires it once at load time; " \
                    "without it the timer is compiled and never armed."
    prefix = SpinelEbpf::LoaderContract::PREFIX_TIMER_ARM
    assert_equal prefix.length, SpinelEbpf::LoaderContract::PREFIX_TIMER_ARM_LEN
    tpl = File.read(File.join(TPL, "timer_prog.template.c"))
    emitted = tpl[/^int (spnl_timer_arm_\S+?)\(/, 1]
    refute_nil emitted, "the timer template no longer emits an arm program"
    assert emitted.start_with?(prefix),
           "codegen emits `#{emitted}`, glue looks for `#{prefix}...` -- the arm program " \
           "would never be fired and the timer would never tick"
  end

  # --- the verifier rules, as they exist in the template -------------------

  # Re-measured on 7.1.5: returning an
  # unknown scalar from the callback still fails with "At async callback return
  # the register R0 has unknown scalar value should have been in [0, 0]". The
  # codegen achieves the literal by lowering the body with ret=VOID, so nothing
  # appends `return <expr>;`; the template supplies the only exit.
  def test_the_callback_returns_a_literal_zero_after_the_re_arm
    tpl = File.read(File.join(TPL, "timer_prog.template.c"))
    cb = tpl[/static int spnl_timer_cb_\S+?\(.*?\n\}/m]
    refute_nil cb, "the callback is no longer in the template"
    # `@BODY@` carries its own trailing newline (each lowered line does), so the
    # slot sits at the head of the re-arm's line in the template text.
    tail = cb.lines.map { |l| l.sub(/\A@BODY@/, "").strip }.reject(&:empty?).last(3)
    assert_equal "bpf_timer_start(&v->t, @NS@ULL, 0);", tail[0],
                 "the callback must re-arm itself or the timer fires once, not periodically"
    assert_equal "return 0;", tail[1]
    assert_equal "}", tail[2]
    assert_operator cb.index("@BODY@"), :<, cb.index("return 0;"),
                    "the handler body must be emitted before the return"
  end

  def test_the_body_slot_precedes_the_re_arm
    tpl = File.read(File.join(TPL, "timer_prog.template.c"))
    assert_operator tpl.index("@BODY@"), :<, tpl.index("bpf_timer_start(&v->t"),
                    "re-arming before the body would still work, but the codegen emits the " \
                    "body first and the golden pins that order"
  end

  # CLOCK_MONOTONIC is still absent from vmlinux.h on 7.1.5 (measured), so the
  # literal 1 is not a shortcut -- it is the only spelling that compiles.
  def test_the_clock_is_the_literal_one_with_its_reason_written_down
    tpl = File.read(File.join(TPL, "timer_prog.template.c"))
    assert_match(/bpf_timer_init\(&_v->t, &spnl_timer_map, 1 \/\* CLOCK_MONOTONIC \*\/\)/, tpl)
  end

  # --- affordance ----------------------------------------------------------

  def test_timer_is_advertised_and_not_withdrawn
    kinds = CAP::ATTACH_KINDS.map { |a| a[:kind] }
    assert_includes kinds, :timer
    refute_includes CAP::WITHDRAWN_ATTACH.keys, :timer
    # Read the PREFIXES, not the table text: the comment that records the entry's
    # removal names spnl_timer__ too, and a test that cannot tell a refusal from
    # its obituary is not checking anything.
    body = cc_source[/CC_WITHDRAWN_ATTACH\[\][^{]*\{(.*?)\n\};/m].to_s
    prefixes = body.scan(/\{\s*"([^"]+)"/).flatten
    refute_includes prefixes, "spnl_timer__",
                    "the codegen still refuses spnl_timer__ while the affordance advertises it"
  end

  # The gate computes its expectation from :sec, so a wrong value here would make
  # the gate demand the wrong thing rather than fail.
  def test_the_advertised_sec_is_the_one_the_arm_program_carries
    entry = CAP::ATTACH_KINDS.find { |a| a[:kind] == :timer }
    assert_equal "syscall", entry[:sec]
    tpl = File.read(File.join(TPL, "timer_prog.template.c"))
    assert_includes tpl, %(SEC("syscall"))
  end

  # A surface that creates storage nobody told the author about is the silent
  # failure the map section of the affordance exists for. The timer creates one.
  def test_the_timer_map_is_advertised_against_the_timer_surface
    m = CAP::MAPS.find { |e| e[:map] == "spnl_timer_map" }
    refute_nil m, "spnl_timer_map is not in Capabilities::MAPS -- an `on :timer` probe " \
                  "would create a map the affordance never mentions, which is the coverage " \
                  "direction: every map the codegen makes has to be claimed somewhere"
    assert_equal "ARRAY", m[:type]
    assert_equal "1", m[:max_entries]
    assert_includes m[:created_by], "timer"
    assert_equal :attach, m[:probe_kind]
    assert m[:when_full], "every map claim must say what happens when it fills"
  end

  # `describe`'s standing advice when nothing is declared is "narrow it with
  # filter_by". On a unit with a timer that advice does not compile (the common
  # filter's gate, exercised by fixture 165), and an affordance that recommends
  # a spelling the compiler refuses is the same class of defect as one that
  # advertises a dead builtin -- it just fails on the reader's side instead of
  # silently.
  def test_describe_does_not_recommend_filter_by_on_a_probe_with_a_timer
    require "spinel_ebpf/introspect"
    src = File.read(File.join(FIX, "145_timer_event_loop.rb"))
    out = SpinelEbpf::Introspect.report(src, "145_timer_event_loop.rb")
    assert_includes out, "`filter_by` cannot be used"
    plain = SpinelEbpf::Introspect.report(
      File.read(File.join(FIX, "97_kprobe_conditional_emit.rb")), "97.rb")
    refute_includes plain, "`filter_by` cannot be used",
                    "the caveat must be about the timer, not printed for every probe"
  end

  # --- what the codegen actually emits -------------------------------------

  # The audit's stage 2, asserted directly: the advertised SEC ("syscall") is the
  # same string a silently degraded program carries, so the presence of the SEC
  # proves nothing. The body is the tell.
  def test_the_handler_body_reaches_the_emitted_c
    out, _err, st = emit("145_timer_event_loop")
    assert st.success?
    assert_includes out, "u_145_timer_event_loop_top_ticks",
                    "the `@ticks = @ticks + 1` the author wrote is not in the output -- " \
                    "this is exactly the failure the surface was withdrawn for, where the " \
                    "whole block was skipped"
    assert_includes out, "static int spnl_timer_cb_main("
    assert_includes out, %(SEC("syscall")\nint spnl_timer_arm_main(__u64 *ctx))
    assert_includes out, "} spnl_timer_map SEC(\".maps\");"
  end

  def test_the_interval_is_folded_in_twice_at_the_declared_value
    out, _err, st = emit("145_timer_event_loop")
    assert st.success?
    starts = out.scan(/bpf_timer_start\([^;]*?, (\d+)ULL, 0\)/).flatten
    assert_equal %w[1000000000 1000000000], starts,
                 "the interval is spent twice -- the arm program's first start and the " \
                 "callback's re-arm. A probe with only one is a timer that fires once."
  end

  def test_a_sub_second_unit_is_converted_not_truncated
    out, _err, st = emit("162_timer_with_handlers")
    assert st.success?
    assert_equal %w[500000000 500000000],
                 out.scan(/bpf_timer_start\([^;]*?, (\d+)ULL, 0\)/).flatten
  end

  # A timer is a callback plus an arm program: there is no inner/wrapper pair.
  # (That absence is why tools/golden.rb's old `_inner` test skipped a timer-only
  # probe entirely -- it was replaced with "did a program SEC come out".)
  def test_a_timer_emits_no_inner_and_does_not_disturb_its_neighbours
    out, _err, st = emit("162_timer_with_handlers")
    assert st.success?
    refute_includes out, "spnl_timer__main_inner", "a timer must not get the ordinary wrapper form"
    assert_includes out, "static __noinline __s64 kprobe__do_sys_openat2_inner(void)"
    assert_includes out, %(SEC("kprobe/do_sys_openat2"))
    # The map the callback references must be declared before the callback.
    assert_operator out.index("} spnl_timer_map"), :<, out.index("static int spnl_timer_cb_main(void *map")
  end

  # --- refusals: what / why / how to fix, never a silent fallback -----------

  def refusal(base)
    _out, err, st = emit(base)
    refute st.success?, "#{base}: expected the codegen to refuse this fixture, got exit 0"
    err
  end

  def test_a_timer_without_an_interval_is_refused_with_the_shape_spelled_out
    err = refusal("163_timer_no_interval")
    assert_includes err, "every:"
    assert_includes err, "1.seconds"
    assert_includes err, "bpf_timer_start"
    assert_includes err, "seconds"   # the accepted units are listed
    assert_includes err, "ns"
  end

  def test_a_second_timer_is_refused_by_name_rather_than_by_clang
    err = refusal("164_timer_twice")
    assert_includes err, "one timer per unit"
    assert_includes err, "spnl_timer_cb_main"   # names the collision
    assert_includes err, "counter"              # says what to do instead
    refute_includes err, "redefinition",
                    "that is clang's word for it, at a layer that no longer knows the " \
                    "author wrote two `on :timer` blocks"
  end

  def test_filter_by_and_a_timer_cannot_coexist_and_the_message_names_the_timer_case
    err = refusal("165_timer_filter_by")
    assert_includes err, "filter_by cannot cover"
    assert_includes err, "spnl_timer__main"
    assert_includes err, "bpf_timer callback",
                    "the stock filter_by message names a verdict hook and a packet hook. " \
                    "A timer is neither, and a diagnostic that describes someone else's " \
                    "mistake reads as a confused tool."
    assert_includes err, "looks narrowed and is not"
  end

  # The synthesized name is not a surface: writing it by hand skips the `every:`
  # keyword, so there is no interval to arm with.
  def test_the_synthesized_name_written_by_hand_is_refused_with_the_real_surface
    skip "C codegen binary not runnable on this host" unless self.class.runnable?
    guard = cc_source[/if \(!g_uses_timer\)\n\s*die\("`spnl_timer__<name>`(.*?)\);/m]
    refute_nil guard, "the flat-spelling guard is gone: `def spnl_timer__x` would emit an " \
                      "arm program with interval 0, i.e. a timer that never fires"
    assert_includes guard, "on :timer, every:"
    assert_includes guard, "BPF::EventLoop"
  end
end
