# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/error_quality_test.rb
#
# Machine-enforce the quality of the errors, since that is what lets an author --
# often a machine -- correct itself. Five kinds of deliberately broken probe must
# fail with an actionable message (what is wrong, why, where, and how to fix it),
# not a cryptic or silent one. What this catches is the worst regression of all: a
# broken probe that passes quietly.
#
# The fixtures are isolated in tests/fixtures/error_quality/ so they do not land in
# the `tests/fixtures/*.ir` glob used by golden.rb, cgen_oracle and the second-stage
# check. Each probe is valid Ruby, so the compiler can still produce its .ast/.ir --
# what is broken about them is eBPF eligibility, not syntax.

require "minitest/autorun"
require "spinel_ebpf/partition"
require "spinel_ebpf/validate"
require "spinel_ebpf/codegen_bpf"
require "spinel_ebpf/capabilities"

class ErrorQualityTest < Minitest::Test
  P   = SpinelEbpf::Partition
  V   = SpinelEbpf::Validate
  GEN = SpinelEbpf::CodegenBpf
  CAP = SpinelEbpf::Capabilities
  FIX = File.expand_path("../fixtures/error_quality", __dir__)

  def load(name)
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{name}.ast")
    [ir, ast, P.classify(ir, ast)]
  end

  # Pin that validate! raises Validate::Error and that its message contains every keyword.
  def assert_validate_error(name, *keywords)
    _ir, ast, r = load(name)
    err = assert_raises(V::Error, "#{name}: expected a loud Validate::Error") do
      V.validate!(ast, r)
    end
    keywords.each do |kw|
      assert_includes err.message, kw, "#{name}: message missing #{kw.inspect}\n  got: #{err.message}"
    end
    err.message
  end

  # Pin that the generator raises UnsupportedNode and that its message contains every keyword.
  def assert_codegen_error(name, *keywords)
    ir, ast, r = load(name)
    err = assert_raises(GEN::UnsupportedNode, "#{name}: expected a codegen UnsupportedNode") do
      GEN.emit(ir, ast, r, base_name: name)
    end
    keywords.each do |kw|
      assert_includes err.message, kw, "#{name}: message missing #{kw.inspect}\n  got: #{err.message}"
    end
    err.message
  end

  # ---------- #1: eBPF-illegal Ruby is rejected loudly, not made a silent native no-op ----------

  # An attach handler that uses a float must not quietly become native (a no-op that
  # never fires); it must be a hard error naming the construct (Float), the reason,
  # the method, and the fix.
  def test_p1_float_attach_handler_is_loud_not_silent_native
    msg = assert_validate_error("p1_float",
                                "kprobe__do_sys_openat2",     # where (the method)
                                "Float",                       # what (the construct)
                                "never fire",                  # why staying silent is wrong
                                "eBPF subset")                 # how to fix it
    # Not "silently made native and reported as success": it names the attach.
    assert_includes msg, "attach handler"
  end

  def test_p1_regex_attach_handler_is_loud
    assert_validate_error("p1_regex", "kprobe__do_sys_openat2", "regex", "never fire")
  end

  # Heap iteration (`[1,2,3].map`) gets a named diagnostic and a fix, rather than a
  # cryptic "not yet ported".
  def test_p1_heap_iteration_is_named_not_cryptic
    assert_validate_error("p1_heap", ".map", "heap", "eBPF-illegal", "n.times")
  end

  # ---------- #2: a builtin in the wrong context (a gate) -- name the allowed contexts ----------

  def test_p2_gate_names_allowed_hooks
    msg = assert_codegen_error("p2_gate", "emit_path", "kernel-gated")
    # Name every allowed context -- the hooks measured to permit bpf_d_path -- in
    # `def <hook>` form, with the `/` of the SEC written as `__`.
    CAP::DPATH_OK_SECS.each do |sec|
      hook = sec.sub("/", "__")   # lsm/file_open -> lsm__file_open
      assert_includes msg, hook, "gate error should name #{sec} (#{hook})"
    end
  end

  # ---------- #3: wrong arity -- name the builtin and the arity it expects ----------

  def test_p3_arity_names_builtin_and_expected
    assert_codegen_error("p3_arity", "hist_observe", "expects 1 arg")
  end

  # ---------- #4: an unknown builtin (a typo) -- name it and suggest the nearest match ----------

  def test_p4_typo_offers_did_you_mean
    msg = assert_validate_error("p4_typo",
                                "hist_observ",       # names the typo
                                "did you mean",       # a suggestion is offered
                                "hist_observe")       # the right candidate
    # The suggestion also shows the signature (arity/params, from the affordance data).
    assert_includes msg, "value"
  end

  # ---------- #5 (the most important): an incomplete required set -- loud, not silent ----------

  # Writing `http_req_start` without its companions (http_resp_stash / http_emit)
  # used to yield no span at all and still exit 0. It is now loud.
  def test_p5_http_incomplete_set_is_loud
    msg = assert_validate_error("p5_http",
                                "http_span",          # the contract name
                                "http_req_start",     # what you are using
                                "http_emit")          # the missing companion
    assert_includes msg, "incomplete builtin set"
  end

  def test_p5_l7_incomplete_pair_is_loud
    assert_validate_error("p5_l7", "req_start", "emit_l7", "incomplete builtin set")
  end

  # ---------- The worst gap of all: a typo in an attach name is loud, not silent ----------

  # `def kprobe_do_sys_openat2` (a single `_`) becomes an orphan SEC("syscall")
  # program that never fires -- and all four stages were measured green on it. It is
  # now a hard error with a did-you-mean suggestion.
  def test_attach_name_typo_is_loud_with_did_you_mean
    msg = assert_validate_error("p6_attach_typo",
                                "kprobe_do_sys_openat2",     # names the typo (single _)
                                "did you mean",               # a suggestion is offered
                                "kprobe__do_sys_openat2",     # the right double-__ form
                                "single underscore",          # why it is dangerous
                                'SEC("syscall")',             # what it turns into
                                "never fires")                # the consequence of staying silent
    # Says it is an attach handler, and offers renaming to a helper as a way out
    # (so this is not over-strict).
    assert_includes msg, "attach"
  end

  # One example from each of the other attach kinds: detection derives its words from
  # the attach kinds in the capability data, so it generalizes.
  def test_typo_suggestion_generalizes_across_attach_kinds
    { "xdp_main"                    => "xdp__main",
      "lsm_file_open"               => "lsm__file_open",
      "sock_ops_observer"           => "sock_ops__observer",
      "fmod_ret_security_file_open" => "fmod_ret__security_file_open" }.each do |typo, want|
      hit = V.attach_name_typo_suggestion(typo)
      refute_nil hit, "#{typo}: expected a typo suggestion"
      assert_equal want, hit[1], "#{typo}: wrong suggestion"
    end
  end

  # Not over-strict: a valid `__` form is picked up by detect_attach and is no typo.
  def test_valid_double_underscore_is_not_a_typo
    # attach_name_typo_suggestion only returns names that doubling a single `_` makes
    # valid. The correct `__` form leaves a remainder starting with `_`, so it is
    # excluded and never flagged falsely.
    assert_nil SpinelEbpf::Validate.attach_name_typo_suggestion("kprobe__do_sys_openat2")
    # A plain helper-looking name -- one that does not start with an attach word --
    # is out of scope too.
    assert_nil SpinelEbpf::Validate.attach_name_typo_suggestion("path_key")
    assert_nil SpinelEbpf::Validate.attach_name_typo_suggestion("record_path_hit")
  end

  # ---------- An extra argument to latency_start/end is loud ----------

  # `latency_start` takes no arguments, yet the C generator silently discarded any
  # that were passed, while its sibling `lat_start` did check arity. That asymmetry
  # is now an "expects no arguments" error.
  def test_latency_start_extra_arg_is_loud
    assert_validate_error("p7_latency_arg",
                          "latency_start",           # which builtin
                          "expects no arguments",     # the expected arity
                          "kprobe__do_sys_openat2")   # where (the method)
  end

  # ---------- The other axis: a legitimate probe must still pass (not over-strict) ----------

  # A complete three-hook http probe passes both validation and code generation.
  def test_ok_http_complete_set_passes
    ir, ast, r = load("ok_http")
    V.validate!(ast, r)   # must not raise
    assert GEN.emit(ir, ast, r, base_name: "ok_http").length > 0
  end

  # emit_connect is valid on its own, so it is deliberately in no required set --
  # the other axis again: do not reject a legitimate form.
  def test_emit_connect_is_standalone_valid
    # The contract data must not demand companions for emit_connect.
    refute CAP.missing_companions(%w[emit_connect]).any? { |g| g[:present].include?("emit_connect") },
           "emit_connect must be standalone-valid; do not require companions"
  end

  # ---------- sanity of the contract data ----------

  def test_required_sets_members_are_real_builtins
    all = (GEN::BUILTIN_NAMES + GEN::DYNPTR_BUILTINS).to_set
    CAP::REQUIRED_SETS.each do |rule|
      names = rule[:mode] == :all ? rule[:members] : ([rule[:trigger]] + rule[:requires])
      names.each { |n| assert_includes all, n, "REQUIRED_SETS references unknown builtin #{n}" }
    end
  end

  # A kernel builtin only piles span records into a map. Without the userspace half
  # of the export (the ffi_func plus the drain loop), compilation and verification
  # are both green and yet not a single span comes out. Pin that every span set
  # carries a userspace_export companion and that its push function really exists in
  # bin/spinel-ebpf, so that dropping the companion FFI is caught.
  def test_span_sets_carry_userspace_export_to_real_push_fn
    bin_src = File.read(File.expand_path("../../bin/spinel-ebpf", __dir__))
    span_sets = CAP::REQUIRED_SETS.select { |r| r[:userspace_export] }
    # Completeness: every :all set (the ones that produce a span) must have a
    # userspace_export.
    CAP::REQUIRED_SETS.select { |r| r[:mode] == :all }.each do |rule|
      refute_nil rule[:userspace_export],
                 "span-producing :all set #{rule[:name]} must carry a userspace_export"
    end
    refute_empty span_sets, "expected span-producing REQUIRED_SETS with userspace_export"
    span_sets.each do |rule|
      ue = rule[:userspace_export]
      fn = ue[:fn]
      assert_kind_of String, fn, "#{rule[:name]}: userspace_export.fn must be a String"
      refute fn.strip.empty?, "#{rule[:name]}: userspace_export.fn must be non-empty"
      # It appears in bin/spinel-ebpf as a real C function definition.
      assert_includes bin_src, "int #{fn}(",
                      "#{rule[:name]}: userspace_export.fn `#{fn}` not defined in bin/spinel-ebpf"
      # ffi_decl and pattern name the same function, so the lines an author copies agree.
      assert_includes ue[:ffi_decl], fn, "#{rule[:name]}: ffi_decl must name #{fn}"
      assert_includes ue[:pattern], fn,  "#{rule[:name]}: pattern must call #{fn}"
    end
  end

  # The required sets show up in the affordance JSON an author reads before writing.
  def test_affordance_exposes_required_sets
    require "json"
    doc = JSON.parse(CAP.affordance_json)
    assert doc.key?("required_sets"), "affordance must expose required_sets"
    names = doc["required_sets"].map { |s| s["name"] }
    assert_includes names, "http_span"
    assert_includes names, "l7_latency"
  end

  # The did-you-mean edit distance picks the near match (sanity of the
  # dependency-free implementation).
  def test_nearest_builtin_picks_close_match
    best, dist = V.nearest_builtin("hist_observ")
    assert_equal "hist_observe", best
    assert_equal 1, dist
  end
end
