# frozen_string_literal: true
#
# `reuseport_hash` + `worker_select(idx)` + REUSEPORT_SOCKARRAY -- re-ported
# from the retired Ruby codegen.
#
# WHAT IS ACTUALLY AT RISK HERE.
#
# The tail-call surface has a seam with THREE agreements between the codegen and
# the loader (map name, program-name prefix, slot ORDER), and a one-character
# change to the slot ordering inside the glue heredoc was measured to pass every
# gate and silently route packets to the wrong program.
#
# This surface has the SAME kind of glue and only ONE of those agreements: the
# map name. There is no ordering convention on top of it, because the index is
# not derived by the loader from anything -- it is passed in by the author's own
# Ruby (`sp_bpf_reuseport_register(listen_fd, my_idx)`) and read back by the
# author's own Ruby (`worker_select(idx)`). Both spellings are in the same file,
# in the language the author is writing. So that class of failure does not exist
# here, and the first group below pins the reason rather than the symptom: if
# anyone ever moves the index bookkeeping INTO the glue, these assertions are
# what should start failing.
#
# What IS invisible here is different and worse in its own way: selecting an
# EMPTY slot is not an error. bpf_sk_select_reuseport returns -ENOENT, the
# codegen discards it (byte-for-byte the oracle's `(void)`), and the kernel
# quietly uses its own 5-tuple choice. "The program picked this worker" and "the
# program picked nothing" are the same observation. Nothing in the compiler can
# settle it (how many workers register is a runtime fact), so the second group
# asserts that the affordance and `describe` SAY so -- that is the whole defence.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/reuseport_select_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/loader_contract_gen"   # the codegen <-> loader seam
require "spinel_ebpf/introspect"
require "spinel_ebpf/portability"

class ReuseportSelectTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CC_H = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
  TPL  = File.join(ROOT, "src/codegen_c/templates/reuseport_sockarray.template.c")
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
  def tpl_source  = @tpl_source  ||= File.read(TPL)
  def glue_source = @glue_source ||= File.read(GLUE)
  def golden      = @golden      ||= File.read(File.join(GOLD, "168_reuseport_select.bpf.c"))

  # --- the seam: what the codegen and the loader must agree on ---------------

  # (1) THE MAP NAME, and it is the only one. It used to be a literal in two
  # files -- a template and a heredoc nothing compiles -- with nothing comparing
  # them (changing one token was measured to leave every gate green). The
  # loader's copy has moved into src/codegen_c/loader_contract.h; the template
  # keeps its identifier, and tools/loader_gate.rb compares the declaration
  # against the codegen's own committed output.
  def test_map_name_is_the_same_literal_in_template_and_glue
    assert_includes tpl_source, "} bpf_worker_socks SEC(\".maps\");",
                    "the template must declare the map the glue looks up"
    # The glue no longer holds the literal -- it interpolates the token
    # declared in src/codegen_c/loader_contract.h, so THREE parties now name this
    # map (template, affordance, declaration) and tools/loader_gate.rb compares the
    # declaration against the committed golden. What is left here is that the loader
    # takes its name from the declaration, and that the declaration is this string.
    assert_equal "bpf_worker_socks", SpinelEbpf::LoaderContract::MAP_WORKER_SOCKS,
                 "the declared REUSEPORT_SOCKARRAY map name changed"
    assert_includes glue_source,
                    'bpf_object__find_map_by_name(_spnl_skel->obj, "#{lc::MAP_WORKER_SOCKS}")',
                    "the glue must look up the map the declaration names"
    # and the affordance must claim the same string, which is what gives the
    # affordance gate its independent shot at a codegen-side change.
    claim = CAP::MAPS.find { |m| m[:id] == :reuseport_sockarray }
    refute_nil claim, "the map must be advertised"
    assert_equal "bpf_worker_socks", claim[:map]
  end

  # (2) THERE IS NO SLOT-ORDERING CONVENTION -- the thing measured as
  # undetectable on the tail-call surface. The glue must pass the caller's index
  # through untouched: no counter, no base, no reordering. If this assertion ever
  # has to be weakened, that failure mode (every gate green, traffic routed
  # elsewhere) has been imported into this surface too.
  def test_glue_passes_the_authors_index_through_unchanged
    body = glue_source[/int sp_bpf_reuseport_register\(int listen_fd, int idx\).*?\n    \}/m]
    refute_nil body, "sp_bpf_reuseport_register must exist in the glue"
    assert_includes body, "__u32 k = (__u32)idx;",
                    "the slot must be the caller's index verbatim -- no counter, no offset"
    assert_includes body, "__u64 v = (__u64)listen_fd;"
    refute_match(/\bidx\s*[+-]\s*1\b/, body, "no off-by-one may hide in the glue")
    # No hidden iteration either: the loader must not be walking programs and
    # assigning slots the way _spnl_prog_array_populate does for tail calls.
    refute_includes body, "for ("
  end

  # (3) THE PROGRAM NAME is NOT a convention here -- the author passes it as a
  # string to sp_bpf_reuseport_attach. A typo is therefore loud, and that is a
  # property worth pinning: it is the one part of the tail-call seam that this
  # glue replaced with a diagnostic.
  def test_attach_reports_an_unknown_program_name
    body = glue_source[/int sp_bpf_reuseport_attach\(int listen_fd, const char \*prog_name\).*?\n    \}/m]
    refute_nil body
    assert_includes body, "bpf_object__find_program_by_name(_spnl_skel->obj, prog_name)"
    assert_match(/prog '%s' not found/, body, "an unknown program name must say so")
    assert_includes body, "SO_ATTACH_REUSEPORT_EBPF"
  end

  # --- what the codegen emits ------------------------------------------------

  def test_golden_has_the_map_and_both_lowerings
    assert_includes golden, "__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);"
    assert_includes golden, "} bpf_worker_socks SEC(\".maps\");"
    assert_includes golden, "((__s64)ctx->hash)"
    assert_match(/\(void\)bpf_sk_select_reuseport\(ctx, &bpf_worker_socks, &_ws_idx\d+, 0\);/, golden)
    # the temp is a __u32 by value, because the helper takes a POINTER to the key
    assert_match(/__u32 _ws_idx\d+ = \(__u32\)\(idx\);/, golden)
  end

  # The helper's return code is discarded. That is the oracle's shape and it is
  # deliberate, but it is also the reason the empty-slot fallback is invisible --
  # so if it ever stops being discarded, the affordance text about the silent
  # fallback has to be revisited at the same time.
  def test_the_helpers_return_code_is_discarded_on_purpose
    assert_includes golden, "(void)bpf_sk_select_reuseport("
    assert_includes cc_source, "worker_select",
                    "the builtin must be implemented in the production codegen"
  end

  def test_signed_modulo_of_the_hash_survives_because_the_field_is_u32
    # `reuseport_hash % 4` is a SIGNED modulo in the emitted C. It compiles only
    # because ctx->hash is __u32, so clang can prove the value non-negative and
    # lower it as unsigned. Pinning the cast keeps that argument true: widen from
    # something signed and clang's `unsupported signed division` comes back.
    assert_includes golden, "idx = ((__s64)ctx->hash) % 4;"
    assert_includes cc_source, '"((__s64)ctx->hash)"'
  end

  # --- the map is emitted for the selecting half only ------------------------

  def test_worker_select_emits_the_map_and_reuseport_hash_alone_does_not
    with = compile_source(<<~RB, "sel")
      def sk_reuseport__pick
        worker_select(1)
        SK_PASS
      end
    RB
    assert_includes with, "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"

    without = compile_source(<<~RB, "hashonly")
      @h = 0
      def sk_reuseport__observe
        @h = reuseport_hash
        SK_PASS
      end
    RB
    assert_includes without, "((__s64)ctx->hash)", "the hash reader must still work on its own"
    refute_includes without, "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
                    "a program that only reads the hash indexes no table"
  end

  # --- the context gate ------------------------------------------------------

  def test_wrong_context_is_refused_with_the_four_things_an_author_needs
    _out, err, st = emit("169_worker_select_wrong_ctx")
    refute st.success?, "reuseport builtins outside sk_reuseport must be refused"
    assert_includes err, "reuseport_hash", "what"
    assert_includes err, "sk_reuseport_md", "why (the ctx struct that does not exist here)"
    assert_includes err, "def sk_reuseport__<name>", "which contexts work"
    assert_includes err, "xdp__steer", "where they wrote it"
    assert_equal err, err.scrub("?"), "ASCII only (`check --json` reads this back)"
    assert err.each_char.all? { |c| c.ord < 128 }, "ASCII only"
  end

  def test_the_gate_is_on_the_hook_name_not_the_attach_kind
    # sk_reuseport shares AK_SK_VERDICT with six other hooks, each with its own
    # ctx struct. A kind-based gate would let all seven through.
    assert_includes cc_source, "cc_require_sk_reuseport",
                    "there must be a dedicated gate"
    fn = cc_source[/static void cc_require_sk_reuseport.*?\n\}/m]
    refute_nil fn
    assert_includes fn, 'strcmp(a.kname, "sk_reuseport")',
                    "the gate must compare the hook NAME"
    refute_includes fn, "AK_SK_VERDICT",
                    "comparing the AttachKind would admit sk_msg / sk_skb / sk_lookup / ..."
  end

  def test_refusals_are_recorded_in_the_reject_baseline
    tsv = File.read(File.join(GOLD, "codegen_reject.tsv"))
    assert_match(/^169_worker_select_wrong_ctx\t/, tsv)
    refute File.exist?(File.join(GOLD, "169_worker_select_wrong_ctx.bpf.c")),
           "a refused fixture must not also ship a golden"
  end

  def test_arity_is_checked
    _o, err, st = emit_source_expect_failure(<<~RB)
      def sk_reuseport__pick
        worker_select
        SK_PASS
      end
    RB
    assert_includes err, "worker_select(idx) expects 1 arg"
    assert_includes err, "sp_bpf_reuseport_register",
                    "the arity message must name where the index comes from"
  end

  # --- the affordance --------------------------------------------------------

  def test_all_three_vocabularies_moved_out_of_the_withdrawn_inventories
    # Un-withdrawing has to happen in every place at once. Two of the three here
    # are affordance-side; the third is the map inventory.
    refute_includes CAP::WITHDRAWN.keys, "reuseport_hash"
    refute_includes CAP::WITHDRAWN.keys, "worker_select"
    refute_includes CAP::WITHDRAWN_MAPS.keys, "REUSEPORT_SOCKARRAY"
    assert_includes CAP.all_builtins, "reuseport_hash"
    assert_includes CAP.all_builtins, "worker_select"
    # and the attach kind was never withdrawn (the audit left it alive) -- so
    # there is nothing to move in CC_WITHDRAWN_ATTACH, and nothing that should
    # appear.
    refute_includes cc_source, '{ "sk_reuseport__",'
  end

  def test_the_affordance_says_the_fallback_is_silent
    ws = CAP.builtin_entry("worker_select")
    assert_match(/-ENOENT|does not fail/, ws[:summary],
                 "the empty-slot fallback is the whole hazard; it must be stated")
    claim = CAP::MAPS.find { |m| m[:id] == :reuseport_sockarray }
    assert_match(/does not fail|5-tuple/, claim[:when_full],
                 "when_full must describe what actually goes wrong, not just overflow")
    # The rule for every map claim: state what happens when it is full/missing.
    refute_nil claim[:when_full]
  end

  def test_the_affordance_states_the_runtime_divisor_limit
    rh = CAP.builtin_entry("reuseport_hash")
    assert_match(/signed division|clang/, rh[:summary],
                 "`reuseport_hash % <runtime value>` does not compile (measured)")
  end

  def test_both_builtins_are_gated_in_the_affordance_too
    %w[reuseport_hash worker_select].each do |n|
      req = CAP::CONTEXT_REQUIREMENTS[n]
      refute_nil req, "#{n} must declare its context requirement"
      assert_equal %i[sk_reuseport], req[:kinds]
      assert CAP.builtin_entry(n)[:gated], "#{n} must report itself as gated"
    end
  end

  def test_the_attach_kind_note_no_longer_says_the_builtins_are_missing
    k = CAP::ATTACH_KINDS.find { |a| a[:kind] == :sk_reuseport }
    refute_nil k
    refute_match(/withdrawn|unported/, k[:context_note],
                 "the old caveat must be gone now that the builtins are back")
    assert_match(/worker_select/, k[:context_note],
                 "the kind must say a program can now name the worker itself")
    assert_match(/sp_bpf_reuseport_attach/, k[:context_note],
                 "the kind must say the loader does NOT attach it")
  end

  # --- portability -----------------------------------------------------------

  def test_reuseport_does_not_raise_the_kernel_floor
    c = SpinelEbpf::Portability.contract(golden)
    assert_equal SpinelEbpf::Portability::BASE_EBPF_KERNEL, c.ebpf["min_kernel"],
                 "4.19 is below the 5.2 base; declaring it must not move the floor"
    keys = c.ebpf["reasons"].map { |f| f["feature"] }
    assert_includes keys, "sk_reuseport"
    assert_includes keys, "reuseport_sockarray"
  end

  def test_portability_states_the_two_runtime_conditions
    c = SpinelEbpf::Portability.contract(golden)
    joined = c.ebpf["caveats"].join("\n")
    assert_match(/sp_bpf_reuseport_attach/, joined,
                 "nothing auto-attaches this program; a probe that forgets is silent")
    assert_match(/5-tuple/, joined, "the empty-slot fallback must be a stated caveat")
  end

  # --- describe --------------------------------------------------------------

  def test_describe_reports_the_reachable_slots_through_one_hop
    src = File.read(File.join(FIX, "168_reuseport_select.rb"))
    out = SpinelEbpf::Introspect.report(src, "t.rb")
    assert_match(/reaches the 4 slots 0\.\.3/, out)
    assert_match(/from the single assignment/, out, "one-hop resolution must be disclosed, not hidden")
    assert_match(/sp_bpf_reuseport_register/, out, "it must say who fills the slots")
  end

  def test_describe_refuses_to_resolve_a_reassigned_local
    # Two assignments means the answer is genuinely open. Saying "0..3" because
    # one of them says so would be worse than saying nothing.
    out = SpinelEbpf::Introspect.report(<<~RB, "t.rb")
      def sk_reuseport__pick
        idx = reuseport_hash % 4
        idx = reuseport_hash % 2
        worker_select(idx)
        SK_PASS
      end
    RB
    assert_match(/not decidable at compile time/, out)
    refute_match(/slot 0\.\.3/, out)
  end

  def test_describe_warns_when_the_userspace_half_is_absent
    out = SpinelEbpf::Introspect.report(<<~RB, "t.rb")
      def sk_reuseport__pick
        worker_select(reuseport_hash % 2)
        SK_PASS
      end
    RB
    assert_match(/nothing in this source calls `sp_bpf_reuseport_attach`/, out, "no attach = the program never fires")
    assert_match(/nothing in this source calls `sp_bpf_reuseport_register`/, out, "no register = every pick falls back")
  end

  def test_describe_is_quiet_when_both_halves_are_present
    src = File.read(File.join(ROOT, "examples/http_server/so-reuseport/server.rb"))
    out = SpinelEbpf::Introspect.report(src, "t.rb")
    assert_match(/reaches the 4 slots 0\.\.3/, out)
    refute_match(/nothing in this source calls/, out, "the public example does call both; no warning is due")
  end

  def test_describe_does_not_read_the_call_out_of_a_comment
    # This exact failure was measured: a fixture's own header sentence was parsed
    # as code. A commented-out worker_select is not compiled.
    out = SpinelEbpf::Introspect.report(<<~RB, "t.rb")
      # this probe used to call worker_select(reuseport_hash % 8)
      def kprobe__do_sys_openat2
        0
      end
    RB
    refute_match(/SO_REUSEPORT worker selection/, out)
  end

  # --- helpers ---------------------------------------------------------------

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

  def emit_source_expect_failure(src)
    skip "in-process codegen not runnable on this host" unless self.class.inproc_runnable?
    require "tmpdir"
    Dir.mktmpdir do |d|
      path = File.join(d, "bad.rb")
      File.write(path, src)
      out, err, st = Open3.capture3(INPROC, path, "u")
      refute st.success?, "expected a refusal, got:\n#{out}"
      [out, err.dup.force_encoding("UTF-8").scrub, st]
    end
  end
end
