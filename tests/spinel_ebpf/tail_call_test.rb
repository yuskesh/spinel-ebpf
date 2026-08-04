# frozen_string_literal: true
#
# `xdp_tail__<name>` + `tail_call_to(slot)` + PROG_ARRAY -- the three-vocabulary
# surface, re-ported from the retired Ruby codegen.
#
# WHAT IS ACTUALLY AT RISK HERE, and why this file is not just "does it compile".
#
# Every other re-port in this batch had one failure mode: the surface did not
# work. This one has a second, and it is worse, because the working and the
# broken version are the same program with a different number in it:
#
#   THE CODEGEN AND THE LOADER AGREE ON THREE THINGS THAT ARE WRITTEN DOWN
#   NOWHERE TOGETHER -- the map name (`spnl_prog_array`), the program-name prefix
#   (`xdp_tail__`) and the slot ORDER (declaration order). The codegen emits two
#   of them as text; the loader (bin/spinel-ebpf, _spnl_prog_array_populate)
#   re-derives all three with strncmp and a counter. Change either side and
#   nothing fails: bpf_tail_call into an unpopulated slot does not return an
#   error, it does not abort -- it FALLS THROUGH and the caller keeps running.
#   The symptom is "the packet took the other branch".
#
# So the assertions below are mostly about that seam, and they are string
# comparisons on purpose: the two halves are C source in two files, one of which
# (the glue) is a heredoc inside a Ruby script and can never be linked against.
#
# The second group is the compile-time refusals, which exist because ONE of the
# ways to get the seam wrong is decidable here: a literal slot outside the range
# the loader will populate.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/tail_call_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/loader_contract_gen"   # the codegen <-> loader seam
require "spinel_ebpf/introspect"

class TailCallTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CC_H = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
  GLUE = File.join(ROOT, "bin/spinel-ebpf")

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

  def cc_source   = @cc_source   ||= File.read(CC_H)
  def glue_source = @glue_source ||= File.read(GLUE)
  def golden      = @golden      ||= File.read(File.join(GOLD, "142_tail_call_dispatch.bpf.c"))

  # --- the seam: three agreements between codegen and loader -----------------

  # (1) THE MAP NAME. The loader calls bpf_object__find_map_by_name with a string
  # literal; if the codegen emits any other name the lookup returns NULL and
  # _spnl_prog_array_populate RETURNS SILENTLY (`if (!map) return;`) -- which is
  # correct for a unit with no tail calls and indistinguishable from one that has
  # them under a different name.
  def test_the_map_name_is_the_one_the_loader_looks_up
    # The loader no longer holds this literal -- it interpolates the token
    # declared in src/codegen_c/loader_contract.h, and tools/loader_gate.rb refuses
    # a raw literal at a name-carrying site. What this test still owes is the OTHER
    # half: that the DECLARATION names what the codegen emits.
    assert_equal "spnl_prog_array", SpinelEbpf::LoaderContract::MAP_PROG_ARRAY,
                 "the declared PROG_ARRAY map name changed"
    assert_includes glue_source,
                    'bpf_object__find_map_by_name(_spnl_skel->obj, "#{lc::MAP_PROG_ARRAY}")',
                    "the loader stopped taking the map name from the declaration"
    assert_includes golden, "} spnl_prog_array SEC(\".maps\");",
                    "the emitted map is not named what the loader looks up -- the loader " \
                    "would find nothing and return without a word"
  end

  # (2) THE PROGRAM-NAME PREFIX. Used TWICE in the glue, for opposite decisions:
  # _spnl_prog_array_populate uses it to select what to REGISTER, and
  # _spnl_xdp_attach_all uses it to select what NOT to attach. A prefix mismatch
  # therefore does not merely skip registration -- it also attaches every target
  # to the interface, so the packets reach them directly and the dispatcher's
  # ordering stops mattering. Both would still be exit 0.
  def test_the_program_prefix_is_the_one_the_loader_keys_on
    # The prefix AND its strncmp length come from one declaration, so
    # `strncmp(name, "xdp_tail__", 9)` is no longer writable -- the generator
    # computes the length from the token.
    assert_equal "xdp_tail__", SpinelEbpf::LoaderContract::PREFIX_XDP_TAIL
    assert_equal 10, SpinelEbpf::LoaderContract::PREFIX_XDP_TAIL_LEN
    n = glue_source.scan(/strncmp\(name, "\#\{lc::PREFIX_XDP_TAIL\}", \#\{lc::PREFIX_XDP_TAIL_LEN\}\)/).size
    assert_operator n, :>=, 1, "the glue no longer keys on the xdp_tail__ prefix"
    assert_includes glue_source, "_spnl_is_xdp_tail_prog(prog)) continue;",
                    "the glue no longer skips auto-attach for tail-call targets"
    # And the codegen must emit that literal prefix as the PROGRAM name (not just
    # somewhere in a comment): the wrapper is what carries it into the ELF.
    assert_match(/SEC\("xdp"\)\nint xdp_tail__tcp_handler\(struct xdp_md \*ctx\)/, golden)
  end

  # (3) THE SLOT ORDER. The loader assigns slots by iterating programs and
  # incrementing a counter -- there is no slot number anywhere in the emitted C to
  # compare against, which is exactly why this is the fragile one. What the
  # codegen owes is that the ELF order equals the source order, so the fixture
  # pins it: tcp_handler is declared first and must appear first.
  def test_the_declaration_order_survives_into_the_emitted_c
    i = golden.index("int xdp_tail__tcp_handler(")
    j = golden.index("int xdp_tail__other_handler(")
    refute_nil i
    refute_nil j
    assert_operator i, :<, j,
                    "the emitted order is not the declaration order, so the loader's " \
                    "slot 0 is not the author's first `def xdp_tail__<name>`"
    # The loader counts ONLY xdp_tail__ programs, so a plain xdp__ between them
    # must not consume a slot. The fixture has one (the dispatcher) after both.
    assert_includes golden, "int xdp__dispatcher("
    # ...and it starts counting at 0. Changing this one digit was measured to
    # leave every gate green while ICMP increments the TCP counter, and at the
    # time a string comparison was all that was available (the glue is a heredoc
    # nothing compiles). The base has since moved into the declaration, and
    # tools/loader_gate.rb now checks it two ways this test cannot:
    #   coverage -- the glue must interpolate it, never write a digit
    #   rule     -- the declared base is compared with the range of literal slots
    #               the CODEGEN accepts, by running it
    # What is left here is the declared value and the loader's use of it.
    assert_equal 0, SpinelEbpf::LoaderContract::PROG_ARRAY_SLOT_BASE,
                 "the declared PROG_ARRAY slot base changed; `tail_call_to(0)` is " \
                 "documented everywhere as the author's first `def xdp_tail__<name>`"
    assert_match(/__u32 slot = \#\{lc::PROG_ARRAY_SLOT_BASE\};\s*\n\s*struct bpf_program \*prog;/,
                 glue_source,
                 "the loader's slot counter no longer comes from loader_contract.h")
  end

  # --- what the surface emits ----------------------------------------------

  def test_a_tail_target_is_an_xdp_program_not_a_syscall_wrapper
    out, _err, st = emit("142_tail_call_dispatch")
    assert st.success?
    # The failure shape this surface was withdrawn for, named explicitly: this is
    # what it looked like before the re-port.
    refute_includes out, 'SEC("syscall")',
                    "a tail-call target degraded to the plain-method wrapper -- the " \
                    "silent shape an audit found this surface in"
    assert_equal 3, out.scan(/SEC\("xdp"\)/).size
  end

  # The wrapper comment is the only place the emitted C says which SURFACE the
  # author wrote (both spellings produce SEC("xdp")). It is what a reader diffing
  # against a previously generated tail-call program matches on.
  def test_the_wrapper_comment_names_the_surface_not_just_the_sec
    assert_includes golden, "/* entry wrapper: xdp_tail__tcp_handler [xdp_tail -> xdp] */"
    assert_includes golden, "/* entry wrapper: xdp__dispatcher [xdp -> xdp] */"
  end

  # bpf_tail_call does not return on success, so it is a STATEMENT: in a branch
  # the value is the constant 0, and the fallback after the `if` is what runs
  # when the jump did not happen. If this ever lowered as an expression the
  # generated C would compile and the semantics would be silently different.
  def test_the_tail_call_lowers_as_a_statement_with_a_constant_branch_value
    assert_includes golden, "bpf_tail_call(ctx, &spnl_prog_array, (__u32)(0));"
    assert_includes golden, "bpf_tail_call(ctx, &spnl_prog_array, (__u32)(1));"
    assert_match(/bpf_tail_call\(ctx, &spnl_prog_array, \(__u32\)\(0\)\);\n\s+_if1 = 0;/, golden)
  end

  # Either half alone must emit the map: a lone target is unreachable without it
  # (the loader has nothing to populate), and a lone jump cannot compile without
  # it. The affordance says so in the entry's `note`; this is the measurement.
  def test_a_lone_target_emits_the_map
    src = "XDP_PASS = 2\n\n@hits = 0\n\ndef xdp_tail__only\n  @hits = @hits + 1\n  XDP_PASS\nend\n"
    out = compile_source(src, "lone")
    assert_includes out, "BPF_MAP_TYPE_PROG_ARRAY"
    assert_includes out, "} spnl_prog_array SEC(\".maps\");"
  end

  # --- the refusals ---------------------------------------------------------

  # A literal slot the loader will never populate. The message has to carry the
  # thing that makes this worth refusing: that the failure is silent.
  def test_an_out_of_range_literal_slot_is_refused_and_says_why
    _out, err, st = emit("167_tail_call_slot_out_of_range")
    refute st.success?, "expected a refusal (the fixture's own comment says so)"
    assert_includes err, "tail_call_to(3)"
    assert_includes err, "declares 1 tail-call target"
    assert_includes err, "slot 0"                     # the range that DOES exist
    assert_includes err, "falls through"              # WHY it must be caught here
    assert_includes err, "DECLARATION ORDER"          # how slots are assigned
    assert_includes err, "xdp__dispatcher"            # where the author wrote it
  end

  # The context gate. Refused at the layer that still knows the author wrote a
  # kprobe -- without it the message is about an undeclared C identifier, because
  # a kprobe inner has no ctx parameter for bpf_tail_call to take.
  def test_a_tail_call_outside_xdp_is_refused_and_says_where_it_works
    _out, err, st = emit("166_tail_call_wrong_ctx")
    refute st.success?
    assert_includes err, "tail_call_to"
    assert_includes err, "def xdp__<name>"
    assert_includes err, "kprobe__do_sys_openat2"
    refute_includes err, "undeclared identifier"
  end

  # This sentence was narrowed too: `allow == CC_CTX_XDP` used to print "an XDP
  # or TC program", which invites the author to try the one context the list two
  # lines down already excludes.
  def test_the_xdp_only_gate_does_not_offer_tc
    _out, err, = emit("166_tail_call_wrong_ctx")
    assert_includes err, "only available inside an XDP program"
    refute_includes err, "def tc__ingress__"
  end

  # A computed slot is deliberately NOT refused -- it cannot be checked, and
  # refusing it would remove the only way to write a dispatcher whose target
  # depends on the packet. The affordance says this in as many words; if the
  # codegen ever started refusing it, that sentence would become a lie.
  def test_a_computed_slot_is_allowed
    src = "XDP_PASS = 2\n\ndef xdp_tail__only\n  XDP_PASS\nend\n\n" \
          "def xdp__d\n  n = pkt_l4_proto\n  tail_call_to(n)\n  XDP_PASS\nend\n"
    out = compile_source(src, "computed")
    assert_includes out, "bpf_tail_call(ctx, &spnl_prog_array, (__u32)(n));"
  end

  # --- the affordance says the same things ---------------------------------

  def test_the_three_vocabularies_are_advertised_together
    assert_includes CAP.all_builtins, "tail_call_to"
    assert_includes CAP::ATTACH_KINDS.map { |a| a[:kind] }, :xdp_tail
    assert_includes CAP::MAPS.map { |m| m[:id] }, :prog_array
    # ...and none of them is still recorded as withdrawn (un-withdrawing means
    # moving all three records, and a half-move shows up as `orphan`).
    refute_includes CAP::WITHDRAWN.keys, "tail_call_to"
    refute_includes CAP::WITHDRAWN_ATTACH.keys, :xdp_tail
    refute_includes CAP::WITHDRAWN_MAPS.keys, "PROG_ARRAY"
  end

  # The map claim is what an AI reads to decide whether it may write this. The
  # dangerous property is not capacity (it cannot overflow) but the silence on
  # failure, so the entry must say that where capacity is normally discussed.
  def test_the_map_claim_carries_the_silent_failure
    e = CAP::MAPS.find { |m| m[:id] == :prog_array }
    assert_equal "PROG_ARRAY", e[:type]
    assert_equal :maps, e[:declared_as]
    assert_equal %w[xdp_tail tail_call_to], e[:created_by]
    assert_match(/falls? through/, e[:when_full])
    assert_match(/declaration order/, e[:role])
  end

  # The portability contract must NOT report 4.2 as the floor of this shape. The
  # codegen puts the tail call inside a BPF-to-BPF subprogram (measured in the
  # kernel's own xlated dump), which is a later and per-arch-JIT capability than
  # PROG_ARRAY itself. What an under-report costs has been measured elsewhere in
  # this tree; the rule is to say "not established" rather than pick a number
  # that sounds decisive.
  def test_the_portability_contract_does_not_under_report_the_tail_call_floor
    require "spinel_ebpf/portability"
    h = SpinelEbpf::Portability.to_h(SpinelEbpf::Portability.contract(golden))
    e = h["ebpf"]
    assert_includes e["reasons"].map { |f| f["feature"] }, "prog_array"
    assert e["undeclared"].any? { |u| u.include?("bpf_tail_call") },
           "the subprogram tail call must be reported as an unestablished floor"
    # And the floor that IS declared comes from XDP, which dominates 4.2.
    assert_equal "5.9", e["min_kernel"]
  end

  # The slot<->method correspondence is not derivable from anything the author
  # reads, so `describe` prints it. A probe that jumps to a slot
  # nobody declared is refused by the codegen; a probe that jumps to the WRONG
  # declared slot is not, and this table is the only place it is visible.
  def test_describe_prints_the_slot_table
    src = File.read(File.join(FIX, "142_tail_call_dispatch.rb"))
    out = SpinelEbpf::Introspect.report(src, "142_tail_call_dispatch.rb")
    assert_includes out, "tail-call dispatch"
    assert_match(/slot 0\s+xdp_tail__tcp_handler.*tail_call_to\(0\)/, out)
    assert_match(/slot 1\s+xdp_tail__other_handler.*tail_call_to\(1\)/, out)
  end

  # Comments are stripped before the scan. Measured while writing this: the
  # fixture's own header sentence contains `tail_call_to(slot)` and was reported
  # as a computed slot. A commented-out `def xdp_tail__x` matters more -- it
  # would shift every slot number in the table away from what the codegen does.
  def test_describe_ignores_commented_out_targets
    src = "# def xdp_tail__ghost\ndef xdp_tail__real\n  0\nend\n"
    out = SpinelEbpf::Introspect.report(src, "x.rb")
    assert_includes out, "slot 0   xdp_tail__real"
    refute_includes out, "ghost"
  end

  def test_describe_flags_a_computed_slot_as_uncheckable
    src = "def xdp_tail__t\n  0\nend\n\ndef xdp__d\n  tail_call_to(n)\n  0\nend\n"
    out = SpinelEbpf::Introspect.report(src, "x.rb")
    assert_match(/slot\(s\) are computed/, out)
  end

  # The section has to OPEN for a computed slot with no targets, which is the one
  # shape the codegen cannot refuse (the slot is not a literal, so the range check
  # has nothing to check) -- i.e. the shape most in need of being said out loud.
  # Measured: gating the section on `targets + literal jumps` printed nothing here.
  def test_describe_warns_when_something_jumps_and_nothing_is_a_target
    src = "def xdp__d\n  tail_call_to(n)\n  0\nend\n"
    out = SpinelEbpf::Introspect.report(src, "x.rb")
    assert_includes out, "tail-call dispatch"
    assert_match(/not one `def xdp_tail__<name>`/, out)
    assert_match(/slot\(s\) are computed/, out)
  end

  private

  # These two tests need to compile a source that is not a committed fixture, so
  # they need the IN-PROCESS binary (it parses .rb; the golden binary takes a
  # pre-produced .ast/.ir pair). Same preflight as `runnable?` and for the same
  # reason: build/ is bind-mounted into the container, so on the host this path
  # usually holds a Linux ELF that File.executable? happily says yes to.
  INPROC = File.join(ROOT, "build/codegen_c/spinel-ebpf-cc")

  def self.inproc_runnable?
    return @inproc if defined?(@inproc)
    return @inproc = false unless File.executable?(INPROC)
    out, err, = Open3.capture3(INPROC)
    @inproc = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @inproc = false
  end

  def compile_source(src, tag)
    skip "in-process codegen not runnable on this host (see scripts/regen-fixtures.sh)" \
      unless self.class.inproc_runnable?
    require "tmpdir"
    Dir.mktmpdir do |d|
      path = File.join(d, "#{tag}.rb")
      File.write(path, src)
      out, err, st = Open3.capture3(INPROC, path, "u")
      assert st.success?, "codegen refused: #{err}"
      out.dup.force_encoding("UTF-8").scrub
    end
  end
end
