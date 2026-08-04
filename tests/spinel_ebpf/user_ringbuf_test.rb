# frozen_string_literal: true
#
# The host -> kernel command channel -- `def user_ringbuf__<name>(value)` +
# `user_ringbuf_drain` + USER_RINGBUF + the reactor spelling
# `on :user_cmd do |cmd|`, re-ported from the retired Ruby codegen (an audit had
# withdrawn the builtin, the attach kind and the map).
#
# WHAT IS ACTUALLY AT RISK HERE.
#
# This is the only one of these re-ports where the loader half did not exist at
# all: the original work pushed records with a standalone throwaway program and
# left extending the glue for whenever something demanded it. So the seam here
# was WRITTEN rather than matched, and a seam this work authored is a seam this
# work has to pin. It shares exactly two literals with the generated C, and the
# two fail differently:
#
#   1. the map name `bpf_user_cmds` -- a drift makes every push return -2.
#      LOUD, if the caller looks at the return value.
#   2. the RECORD SIZE (8 bytes) -- the callback reads sizeof(__s64) with
#      bpf_dynptr_read, the pusher reserves sizeof(long long). A drift here is
#      SILENT in one direction: measured -- a short record still fires the
#      callback and still counts, and only the VALUE comes out wrong (0).
#      "How many commands arrived" cannot see it.
#
# Both halves are C source in two files, one of which (the glue) is a heredoc
# inside a Ruby script that no gate in this tree ever compiles -- measured
# independently on two other surfaces. So these are string comparisons,
# deliberately.
#
# The second group is the three compile-time refusals, which exist because the
# ways to get this wrong ARE decidable here: a callback nobody drains, a drain
# with no callback, and two callbacks (the drain names one by symbol).
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/user_ringbuf_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/loader_contract_gen"   # the codegen <-> loader seam
require "spinel_ebpf/introspect"

class UserRingbufTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CC_H = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
  GLUE = File.join(ROOT, "bin/spinel-ebpf")
  TPL_MAP = File.join(ROOT, "src/codegen_c/templates/user_ringbuf.template.c")
  TPL_CB  = File.join(ROOT, "src/codegen_c/templates/user_ringbuf_cb.template.c")

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
    [out, err, st]
  end

  def refuse(base)
    _out, err, st = emit(base)
    refute st.success?, "#{base}: expected the codegen to refuse this"
    err
  end

  # ---- the seam: two literals, two files, no compiler in between -----------

  def test_map_name_is_the_same_string_in_the_template_and_in_the_loader
    tpl  = File.read(TPL_MAP)
    glue = File.read(GLUE)
    assert_match(/\}\s*bpf_user_cmds\s+SEC\(".maps"\);/, tpl,
                 "template no longer declares a map named bpf_user_cmds")
    # The literal moved into src/codegen_c/loader_contract.h and the glue
    # interpolates it, so what is asserted here is that the DECLARATION agrees with
    # the codegen; "the glue holds no raw literal" belongs to loader_gate.rb.
    assert_equal "bpf_user_cmds", SpinelEbpf::LoaderContract::MAP_USER_CMDS
    assert_match(/bpf_object__find_map_by_name\(_spnl_skel->obj,\s*"\#\{lc::MAP_USER_CMDS\}"\)/, glue,
                 "the loader looks up a different map name than the codegen emits -- " \
                 "every sp_bpf_user_cmd_push would return -2 and the ring would stay empty")
  end

  # The silent one. Stated as: the callback's read width and the pusher's
  # reserve width are both the width of a 64-bit integer, spelled with sizeof on
  # both sides so neither can drift to a magic number unnoticed.
  def test_record_width_agrees_between_the_callback_and_the_pusher
    cb   = File.read(TPL_CB)
    glue = File.read(GLUE)
    assert_match(/bpf_dynptr_read\(&@PARAM@, sizeof\(@PARAM@\), dynptr, 0, 0\);/, cb,
                 "the callback no longer reads exactly one whole record field")
    assert_match(/@CTYPE@ @PARAM@ = 0;/, cb,
                 "the callback's local is no longer the declared parameter type")
    # The reserve size is no longer a `sizeof` that happens to agree -- it is THE
    # declared width (loader_contract.h), and the emitted C carries a
    # _Static_assert tying this local's type to the same number, so a real --build
    # fails if they part. Two claims are left here: the declaration is 8, and the
    # loader takes its size from the declaration instead of writing a number.
    # "no raw number at that site" is tools/loader_gate.rb's coverage section,
    # which was measured catching exactly the short-record mutation below.
    assert_equal 8, SpinelEbpf::LoaderContract::MAP_USER_CMDS_BYTES,
                 "the declared bpf_user_cmds record width changed"
    assert_match(/long long \*slot = user_ring_buffer__reserve\(_spnl_user_cmds_rb, \#\{lc::MAP_USER_CMDS_BYTES\}\);/,
                 glue,
                 "the pusher no longer reserves the DECLARED width -- a SHORT record still " \
                 "fires the callback and still counts, and only the value comes out 0 " \
                 "(measured: bpf_dynptr_read returns -E2BIG and is discarded)")
    assert_match(/_Static_assert\(sizeof\(\*slot\) == \#\{lc::MAP_USER_CMDS_BYTES\},/, glue,
                 "the compile-time tie between the loader's local and the declared width is gone")
    # And the callback's type really is 64-bit: `value` is lowered as __s64.
    out, = emit("143_user_ringbuf_channel")
    assert_match(/__s64 value = 0;\s*\n\s*bpf_dynptr_read\(&value, sizeof\(value\)/, out)
  end

  # The pusher must not offer a size knob. If it did, the silent-truncation path
  # would be reachable from Ruby -- which is the whole reason the affordance says
  # "the shipped pusher is the only advertised way in".
  def test_the_pusher_does_not_let_the_caller_choose_a_size
    glue = File.read(GLUE)
    push = glue[/int sp_bpf_user_cmd_push\([^)]*\)/]
    refute_nil push, "sp_bpf_user_cmd_push is gone"
    assert_equal "int sp_bpf_user_cmd_push(long long value)", push,
                 "the pusher grew a parameter: a caller-chosen size reopens the silent path"
  end

  # ---- the shape the oracle shipped ---------------------------------------

  def test_callback_is_a_sec_less_static_long_taking_a_dynptr
    out, = emit("143_user_ringbuf_channel")
    assert_includes out,
                    "static long spnl_user_ringbuf_cb_cmd_handler(struct bpf_dynptr *dynptr, void *_uctx)"
    # forward declaration, because the drain may be lowered before the callback
    assert_includes out,
                    "static long spnl_user_ringbuf_cb_cmd_handler(struct bpf_dynptr *dynptr, void *_uctx);"
    # no SEC of its own, and specifically not the one the silent degradation made
    refute_match(/SEC\("syscall"\)\s*\nint user_ringbuf__/, out,
                 "the callback became a program -- that is the silent degradation " \
                 "this surface was found in and withdrawn for")
  end

  def test_drain_names_the_callback_by_symbol
    out, = emit("143_user_ringbuf_channel")
    assert_includes out,
                    "(void)bpf_user_ringbuf_drain(&bpf_user_cmds, spnl_user_ringbuf_cb_cmd_handler, NULL, 0);"
  end

  # A `long` callback must end in a LITERAL 0, so the body must not be allowed to
  # append `return <expr>;`. Both spellings reach that the same way (ret forced to
  # VOID in one place) -- the flat one inherits `int` from spinel's inference
  # whenever the last statement is an assignment, which is what both committed
  # examples write.
  def test_callback_ends_in_a_literal_return_zero_in_both_spellings
    %w[143_user_ringbuf_channel 173_user_cmd_reactor].each do |base|
      out, = emit(base)
      cb = out[/static long spnl_user_ringbuf_cb_\w+\(struct bpf_dynptr \*dynptr, void \*_uctx\)\n\{.*?\n\}/m]
      refute_nil cb, "#{base}: no callback in the output"
      assert_match(/\n    return 0;\n\}\z/, cb, "#{base}: callback does not end in a literal 0")
      refute_match(/return [^0].*;\n\}\z/, cb, "#{base}: callback returns an expression")
    end
  end

  # The original reactor demo still carries a comment telling the author to
  # declare `on :user_cmd` ABOVE `on :xdp`, because the retired oracle learned the
  # callback's name while EMITTING the callback. Fixture 173 is written in the
  # other order on purpose.
  def test_declaration_order_does_not_matter
    # comments stripped first: the fixture's own header explains the ordering and
    # therefore mentions both spellings before either one is written as code
    src = File.read("#{FIX}/173_user_cmd_reactor.rb")
             .each_line.reject { |l| l.strip.start_with?("#") }.join
    assert src.index("user_ringbuf_drain") < src.index("on :user_cmd"),
           "fixture 173 must keep the drain ABOVE the callback -- that is what it measures"
    out, = emit("173_user_cmd_reactor")
    assert_includes out, "bpf_user_ringbuf_drain(&bpf_user_cmds, spnl_user_ringbuf_cb_cmd_handler"
  end

  def test_map_is_emitted_with_the_oracles_size
    out, = emit("143_user_ringbuf_channel")
    assert_includes out, "__uint(type, BPF_MAP_TYPE_USER_RINGBUF);"
    assert_includes out, "__uint(max_entries, 262144);"
  end

  # ---- the three refusals --------------------------------------------------

  def test_callback_with_no_drain_is_refused
    err = refuse("170_user_ringbuf_no_drain")
    assert_match(/nothing in this unit calls `user_ringbuf_drain`/, err)
    assert_match(/static.*with no caller|no caller/, err, "the reason (dead code) is not stated")
    assert_match(/def xdp__<name>|def kprobe__<func>/, err, "no direction on where to drain")
  end

  def test_drain_with_no_callback_is_refused
    err = refuse("172_user_ringbuf_drain_no_cb")
    assert_match(/no `def user_ringbuf__<name>\(value\)` callback/, err)
    assert_match(/on :user_cmd/, err, "the reactor spelling is not offered")
    assert_match(/sp_bpf_user_cmd_push/, err, "the push side is not named")
  end

  def test_two_callbacks_are_refused
    err = refuse("171_user_ringbuf_twice")
    assert_match(/already declares a USER_RINGBUF callback/, err)
    assert_match(/user_ringbuf__first/, err, "the FIRST one is not named")
    assert_match(/user_ringbuf__second/, err, "the second one is not named")
  end

  # ---- affordance <-> codegen ---------------------------------------------

  def test_affordance_publishes_a_symbol_not_a_sec
    e = CAP::ATTACH_KINDS.find { |a| a[:kind] == :user_ringbuf }
    refute_nil e, "user_ringbuf is not advertised"
    assert_nil e[:sec], "a callback has no SEC; claiming one would be checkable and false"
    assert_match(/\Astatic long spnl_user_ringbuf_cb_<name>\(/, e[:emits])
    # the promise has to be the shape the template actually emits
    tpl = File.read(TPL_CB)
    assert_includes tpl, "static long spnl_user_ringbuf_cb_@CB@(struct bpf_dynptr *dynptr, void *_uctx)"
  end

  def test_builtin_and_map_are_advertised
    assert_includes CAP.all_builtins, "user_ringbuf_drain"
    assert_equal 0, CAP.signature_for("user_ringbuf_drain")[:arity]
    refute CAP::WITHDRAWN.key?("user_ringbuf_drain"), "still recorded as withdrawn"
    refute CAP::WITHDRAWN_ATTACH.key?(:user_ringbuf), "still recorded as withdrawn"
    refute CAP::WITHDRAWN_MAPS.key?("USER_RINGBUF"), "still recorded as withdrawn"
    m = CAP::MAPS.find { |x| x[:id] == :user_ringbuf }
    refute_nil m, "the map claim is missing"
    assert_equal "USER_RINGBUF", m[:type]
    assert_equal "262144", m[:max_entries]
    assert_match(/-5/, m[:when_full], "the push-side error code is not stated")
  end

  # The C refusal table and the affordance's record move together. If the
  # C still refused the name, `capabilities` would advertise something the
  # codegen rejects; if the affordance still recorded it, the gate would demand a
  # refusal that no longer happens. Both directions show up as `orphan` in
  # tools/affordance_gate.rb; this pins the local half.
  def test_the_c_refusal_table_no_longer_names_this_prefix
    src = File.read(CC_H)
    tbl = src[/static const CcWithdrawnAttach CC_WITHDRAWN_ATTACH\[\] = \{.*?\n\};/m]
    refute_nil tbl, "CC_WITHDRAWN_ATTACH is unreadable -- the gate would abort"
    refute_match(/"user_ringbuf__"/, tbl,
                 "the codegen still refuses a name the affordance advertises")
  end

  # The reactor kind survived the port to the C codegen (it was in cc_reactor_kind
  # all along -- unlike :timer, which was measured VANISHING because an unknown
  # kind is skipped). Pinned because that is what makes `on :user_cmd` reach the
  # synthesized flat name at all.
  def test_reactor_kind_maps_to_the_flat_callback_name
    src = File.read(CC_H)
    assert_match(/\{"user_cmd",\s*"user_ringbuf__cmd_handler",/, src)
    sugar = CAP.surface_sugar.find { |s| s[:id] == :reactor_user_cmd }
    refute_nil sugar, "the sugar claim is missing"
    assert_includes sugar[:flat], "def user_ringbuf__cmd_handler(cmd)"
    assert_equal :identical, sugar[:equiv]
    # both spellings must carry the drain site: neither half is legal alone, so a
    # pair without it would be a claim the gate could never satisfy
    assert_includes sugar[:sugar], "user_ringbuf_drain"
    assert_includes sugar[:flat],  "user_ringbuf_drain"
  end

  # ---- describe ------------------------------------------------------------

  def test_describe_states_the_two_facts_the_codegen_cannot_settle
    src = File.read("#{FIX}/143_user_ringbuf_channel.rb")
    facts = SpinelEbpf::Introspect.user_ringbuf_facts(src)
    assert_equal "cmd_handler", facts[:cb]
    assert_equal ["xdp__drain_user_ringbuf"], facts[:drains]
    refute facts[:push], "the fixture does not push; describe must be able to say so"
  end

  # Comments must not be read as code -- describe was measured reporting a
  # fixture's own HEADER SENTENCE as a call site, and both committed examples
  # mention `user_ringbuf_drain` in their headers.
  def test_describe_does_not_read_comments
    src = <<~RB
      # this header mentions user_ringbuf_drain and def user_ringbuf__ghost(value)
      def user_ringbuf__real(value)
        @x = value
      end

      def xdp__pump
        user_ringbuf_drain
        XDP_PASS
      end
    RB
    facts = SpinelEbpf::Introspect.user_ringbuf_facts(src)
    assert_equal "real", facts[:cb]
    assert_equal ["xdp__pump"], facts[:drains]
  end

  # ---- portability ---------------------------------------------------------

  # 6.1 is above BASE_EBPF_KERNEL (5.2), so unlike PROG_ARRAY/REUSEPORT_SOCKARRAY
  # this one can actually BE the floor of a probe. Under-reporting is the one
  # direction the contract may never take.
  def test_the_kernel_floor_is_declared_and_actually_binds
    require "spinel_ebpf/portability"
    f = SpinelEbpf::Portability::MIN_KERNEL.fetch("bpf_user_ringbuf_drain")
    assert_equal "6.1", f.kernel
    assert_operator Gem::Version.new(f.kernel), :>,
                    Gem::Version.new(SpinelEbpf::Portability::BASE_EBPF_KERNEL),
                    "if this ever drops to the base it stops being worth declaring"
    out, = emit("143_user_ringbuf_channel")
    assert_includes out, "bpf_user_ringbuf_drain", "the marker portability keys on is gone"
  end

  def test_the_silent_runtime_condition_is_stated
    require "spinel_ebpf/portability"
    c = SpinelEbpf::Portability::RUNTIME_CAVEATS.fetch("bpf_user_ringbuf_drain")
    assert_match(/8 bytes/, c, "the record width is not stated")
    assert_match(/E2BIG/, c, "the measured failure is not named")
  end

  # ---- golden --------------------------------------------------------------

  def test_goldens_exist_for_both_spellings
    %w[143_user_ringbuf_channel 173_user_cmd_reactor].each do |base|
      assert File.exist?(File.join(GOLD, "#{base}.bpf.c")), "#{base} has no golden"
    end
    %w[170_user_ringbuf_no_drain 171_user_ringbuf_twice 172_user_ringbuf_drain_no_cb].each do |base|
      refute File.exist?(File.join(GOLD, "#{base}.bpf.c")),
             "#{base} is refused; shipping a golden for it is a contradiction"
    end
  end
end
