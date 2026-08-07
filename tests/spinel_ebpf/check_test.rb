# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/check_test.rb
#
# Machine-enforce, on the host, the per-stage pass/fail/skip semantics of
# `spinel-ebpf check` -- the fast loop an author, often a machine, uses to verify
# the Ruby it just wrote. The stages that need the frontend (the compiler is a
# Linux ELF) or a kernel (BTF) are exercised for real in the container, so what is
# pinned here is the pure-Ruby parts:
#   - pass/fail of the partition/validate stage, over committed .ast/.ir fixtures
#   - the skip verdict for the verifier stage (no kernel/BTF present)
#   - the verifier log summary (extracting the reason for the rejection)
#   - result assembly (ok / failed_stage) and the JSON shape

require "minitest/autorun"
require "json"
require "spinel_ebpf/partition"
require "spinel_ebpf/check"

class CheckTest < Minitest::Test
  P   = SpinelEbpf::Partition
  C   = SpinelEbpf::Check
  FIX  = File.expand_path("../fixtures", __dir__)
  # Deliberately broken probes, kept in their own directory.
  ERRQ = File.expand_path("../fixtures/error_quality", __dir__)

  def classify(dir, name)
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{dir}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{dir}/#{name}.ast")
    [ast, P.classify(ir, ast)]
  end

  # ---------- partition/validate stage verdict ----------

  def test_partition_stage_passes_for_valid_probe
    ast, result = classify(FIX, "17_kprobe")
    st = C.partition_verdict(ast, result)
    assert_equal true, st[:ok], "valid probe should pass partition: #{st[:error]}"
    assert_equal "partition", st[:stage]
    assert_nil st[:error]
  end

  def test_partition_stage_fails_loud_on_float_attach_handler
    ast, result = classify(ERRQ, "p1_float")
    st = C.partition_verdict(ast, result)
    assert_equal false, st[:ok]
    # The loud validation message must survive verbatim as the stage error.
    assert_includes st[:error], "Float"
    assert_includes st[:error], "kprobe__do_sys_openat2"
    assert_includes st[:error], "silently never fire"
  end

  def test_partition_stage_fails_on_incomplete_required_set
    ast, result = classify(ERRQ, "p5_http")
    st = C.partition_verdict(ast, result)
    assert_equal false, st[:ok]
    assert_includes st[:error], "http_span"
    assert_includes st[:error], "http_resp_stash"
  end

  # ---------- verifier availability (stage-4 skip) ----------

  def test_verifier_unavailable_without_btf
    # Deterministic across platforms: a nonexistent BTF path is never available.
    refute C.verifier_available?(btf_path: "/definitely/not/a/real/btf/path"),
           "stage 4 must skip when no kernel/BTF is present"
  end

  def test_linux_predicate_is_boolean
    assert_includes [true, false], C.linux?
  end

  def test_default_btf_path_honors_env
    old = ENV["SPNL_BTF_PATH"]
    ENV["SPNL_BTF_PATH"] = "/custom/btf"
    assert_equal "/custom/btf", C.default_btf_path
  ensure
    ENV["SPNL_BTF_PATH"] = old
  end

  # ---------- verifier log summary ----------

  def test_summarize_packet_bounds_rejection
    log = <<~LOG
      libbpf: prog 'badprog': BPF program load failed: Permission denied
      0: R1=ctx() R10=fp0
      ; return data[100]; @ bad.bpf.c:7
      1: (71) r0 = *(u8 *)(r1 +100)
      invalid access to packet, off=100 size=1, R1(id=0,off=100,r=0)
      R1 offset is outside of the packet
      processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0
      -- END PROG LOAD LOG --
      libbpf: prog 'badprog': failed to load: -13
      libbpf: failed to load object 'bad.bpf.o'
      LOAD_FAIL err=-13
    LOG
    short, detail = C.summarize_verifier_log(log)
    # short verdict names the packet-access problem and the failing prog.
    assert_match(/packet/i, short)
    assert_includes short, "badprog"
    # detail keeps the log tail (the numbered instruction trace lives here).
    assert_includes detail, "processed 2 insns"
  end

  def test_summarize_map_create_failure
    log = <<~LOG
      libbpf: map 'bpf_xskmap': failed to create: Invalid argument(-22)
      libbpf: failed to load object 'demo.bpf.o'
      LOAD_FAIL err=-22
    LOG
    short, _detail = C.summarize_verifier_log(log)
    assert_includes short, "bpf_xskmap"
    assert_match(/invalid argument/i, short)
  end

  def test_summarize_empty_log_has_fallback
    short, _ = C.summarize_verifier_log("")
    assert_equal "verifier rejected the program", short
  end

  # ---------- result assembly + formatting ----------

  def test_assemble_ok_when_no_failure
    stages = [C.ok_stage("partition"), C.ok_stage("codegen"),
              C.ok_stage("clang"), C.ok_stage("verifier")]
    r = C.assemble("x.rb", stages)
    assert_equal true, r[:ok]
    assert_nil r[:failed_stage]
  end

  def test_assemble_reports_first_failed_stage
    stages = [C.ok_stage("partition"),
              C.fail_stage("codegen", "boom"),
              C.skip_stage("clang", "upstream stage failed"),
              C.skip_stage("verifier", "upstream stage failed")]
    r = C.assemble("x.rb", stages)
    assert_equal false, r[:ok]
    assert_equal "codegen", r[:failed_stage]
  end

  # A gate that could not run must not report a pass. On a macOS host every stage
  # skips (frontend is a Linux ELF, no kernel/BTF) -- "nothing ran" and "nothing
  # is wrong" are different answers with opposite remedies (run it in the build
  # container / fix the probe), so they get different verdicts and different exit
  # codes. `ok` is tri-state exactly like a stage's: true / false / nil.
  def test_assemble_is_inconclusive_when_nothing_ran
    stages = C::STAGES.map { |s| C.skip_stage(s, "no toolchain here") }
    r = C.assemble("x.rb", stages)
    assert_nil r[:ok], "no stage ran, so check cannot say the probe is ok"
    assert_nil r[:failed_stage], "nothing failed either -- this is not a probe failure"
    assert_includes r[:unverifiable].to_s, "no toolchain here",
                    "must carry why it could not check, not just that it could not"
  end

  # A partial run is still a real verdict: something executed and passed. Only
  # the empty case is inconclusive, so adding a filter/skip does not silently
  # turn a passing check into an unverifiable one.
  def test_assemble_ok_when_at_least_one_stage_ran
    stages = [C.ok_stage("partition"),
              C.skip_stage("codegen", "no toolchain here"),
              C.skip_stage("clang", "no toolchain here"),
              C.skip_stage("verifier", "no kernel/BTF")]
    r = C.assemble("x.rb", stages)
    assert_equal true, r[:ok]
    assert_nil r[:unverifiable]
  end

  def test_human_output_does_not_claim_ok_when_nothing_ran
    r = C.assemble("x.rb", C::STAGES.map { |s| C.skip_stage(s, "run this in the build container") })
    text = C.human(r)   # must not raise: there is no failed stage to report either
    refute_match(/=> OK/, text, "'no stage ran' must never render as OK")
    assert_includes text, "run this in the build container"
  end

  def test_json_reports_inconclusive_as_null_not_true
    r = C.assemble("p.rb", C::STAGES.map { |s| C.skip_stage(s, "no kernel here") })
    parsed = JSON.parse(C.to_json(r))
    assert_nil parsed["ok"], "an AI reading only `ok` must not see a green light"
    refute_nil parsed["unverifiable"]
  end

  def test_json_shape_is_machine_readable
    r = C.assemble("p.rb", [C.ok_stage("partition"), C.fail_stage("codegen", "bad")])
    parsed = JSON.parse(C.to_json(r))
    assert_equal "p.rb", parsed["file"]
    assert_equal false, parsed["ok"]
    assert_equal "codegen", parsed["failed_stage"]
    assert_equal 2, parsed["stages"].length
    assert_equal %w[stage ok error detail skipped].sort, parsed["stages"][0].keys.sort
  end

  # The loud compile-time message (reason + where it IS legal + how to fix) arrives
  # as the failed stage's `detail`. Printing only `error` throws away the half that
  # says what to do next -- which is the half the author, human or model, acts on.
  def test_human_output_keeps_the_actionable_detail_of_a_failure
    r = C.assemble("p.rb", [C.ok_stage("partition"),
                            C.fail_stage("codegen", "in-process eBPF codegen failed",
                                         detail: "path_eq: bpf_d_path is kernel-gated ...\n" \
                                                 "    file arg : def lsm__file_open / ...")])
    text = C.human(r)
    assert_includes text, "kernel-gated", "the reason must survive into the human output"
    assert_includes text, "def lsm__file_open", "so must the fix"
  end

  def test_human_output_marks_failed_stage
    r = C.assemble("p.rb", [C.ok_stage("partition", detail: "2 methods"),
                            C.fail_stage("codegen", "kaboom"),
                            C.skip_stage("clang", "upstream stage failed")])
    text = C.human(r)
    assert_match(/\[ok\s*\] partition/, text)
    assert_match(/\[FAIL\] codegen/, text)
    assert_match(/\[skip\] clang/, text)
    assert_includes text, "FAILED at codegen: kaboom"
  end
end
