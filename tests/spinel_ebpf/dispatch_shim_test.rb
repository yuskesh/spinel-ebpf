# frozen_string_literal: true
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/dispatch_shim_test.rb

require "minitest/autorun"
require "spinel_ebpf/dispatch_shim"
require "spinel_ebpf/partition"

class DispatchShimTest < Minitest::Test
  P   = SpinelEbpf::Partition
  D   = SpinelEbpf::DispatchShim
  FIX = File.expand_path("../fixtures", __dir__)

  def load(name)
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{name}.ast")
    [ir, ast, P.classify(ir, ast)]
  end

  # ---------- eligibility ----------

  def test_int_top_level_methods_are_eligible
    _, _, res = load("14_calls")
    assert_equal %w[twice quad six_times].sort,
                 D.eligible_method_names(res).sort
  end

  def test_attach_methods_are_not_eligible
    # 17_kprobe defines tracepoint__syscalls__sys_enter_openat — eligible? = false
    _, _, res = load("17_kprobe")
    assert_empty D.eligible_method_names(res)
  end

  def test_builtin_definitions_are_not_eligible
    # 19_emit_str declares `def spnl_emit_str(...); end` as a placeholder.
    # The codegen treats spnl_emit_str as a built-in intrinsic, not a method
    # to dispatch to.
    _, _, res = load("19_emit_str")
    refute_includes D.eligible_method_names(res), "spnl_emit_str"
    refute_includes D.eligible_method_names(res), "spnl_emit"
  end

  # ---------- shim shape ----------

  def test_shim_signature_matches_spinel_convention
    ir, ast, res = load("14_calls")
    out = D.emit(ir, ast, res, base_name: "14_calls")
    # mrb_int + sp_<name> + lv_<param>  — must match spinel_codegen's emission
    assert_match(/mrb_int sp_twice\(mrb_int lv_x\)/, out)
    assert_match(/mrb_int sp_quad\(mrb_int lv_x\)/, out)
    assert_match(/mrb_int sp_six_times\(mrb_int lv_x\)/, out)
  end

  def test_shim_fills_ctx_struct_matching_bpf_side
    ir, ast, res = load("14_calls")
    out = D.emit(ir, ast, res, base_name: "14_calls")
    # codegen_bpf emits `struct twice_ctx { __s64 x; };` (no lv_ prefix);
    # the shim must fill .x (not .lv_x).
    assert_match(/struct twice_ctx ctx = \{[\s\S]*?\.x = \(int64_t\)lv_x/, out)
  end

  def test_shim_uses_bpf_prog_test_run
    ir, ast, res = load("14_calls")
    out = D.emit(ir, ast, res, base_name: "14_calls")
    assert_includes out, "bpf_program__fd(_spnl_skel->progs.twice)"
    assert_includes out, "bpf_prog_test_run_opts"
  end

  def test_shim_extern_skel_pointer_name
    # The skeleton struct name is derived from the unit_name (sanitized).
    ir, ast, res = load("14_calls")
    out = D.emit(ir, ast, res, base_name: "14_calls")
    # base "14_calls" -> sanitize -> "u_14_calls"
    assert_match(/extern struct u_14_calls \*_spnl_skel;/, out)
  end

  def test_returns_nil_when_no_eligible_methods
    ir, ast, res = load("17_kprobe")
    assert_nil D.emit(ir, ast, res, base_name: "17_kprobe")
  end

  def test_sign_extends_retval_to_mrb_int
    # bpf_prog_test_run's retval is __u32; we sign-extend through int32_t
    # so negative ints from BPF are preserved when widened to mrb_int.
    ir, ast, res = load("14_calls")
    out = D.emit(ir, ast, res, base_name: "14_calls")
    assert_match(/return \(mrb_int\)\(int32_t\)opts\.retval;/, out)
  end

  # ---------- boundary ABI contract ----------

  def test_multi_arg_int_dispatch
    # add(a, b): multi-param int dispatch — one ctx field per param.
    ir, ast, res = load("02_integer_arith")
    out = D.emit(ir, ast, res, base_name: "02_integer_arith")
    assert_match(/struct add_ctx \{\s*__s64 a;\s*__s64 b;\s*\}/, out)
    assert_match(/mrb_int sp_add\(mrb_int lv_a, mrb_int lv_b\)/, out)
  end

  def test_bool_params_and_returns_cross
    # is_big(size:int)->bool, both(flag:bool)->bool. Bool crosses as an __s32
    # ctx field (mirroring the BPF side); a bool RETURN is void at the boundary
    # (matching spinel's ir_extern_ret_ctype, which widens only int).
    ir, ast, res = load("98_bool_sig")
    assert_includes D.eligible_method_names(res), "is_big"
    assert_includes D.eligible_method_names(res), "both"
    out = D.emit(ir, ast, res, base_name: "98_bool_sig")
    assert_match(/struct is_big_ctx \{\s*__s64 size;\s*\}/, out)  # int param -> __s64
    assert_match(/struct both_ctx \{\s*__s32 flag;\s*\}/, out)    # bool param -> __s32
    assert_match(/void sp_is_big\(mrb_int lv_size\)/, out)        # bool return -> void
    assert_match(/void sp_both\(mrb_int lv_flag\)/, out)
  end

  def test_ctx_ctype_mirrors_bpf_side
    # The shim's ctx field types MUST equal the BPF side's emit_ctx_struct map.
    assert_equal SpinelEbpf::CodegenBpf::SPINEL_TYPE_TO_C["int"],  D.boundary_ctx_ctype!("m", "p", "int")
    assert_equal SpinelEbpf::CodegenBpf::SPINEL_TYPE_TO_C["bool"], D.boundary_ctx_ctype!("m", "p", "bool")
  end

  def test_boundary_error_on_unsupported_param
    e = assert_raises(D::BoundaryError) { D.boundary_ctx_ctype!("foo", "name", "string") }
    assert_match(/cannot dispatch `sp_foo`/, e.message)
    assert_match(/parameter `name` has type "string"/, e.message)
  end

  def test_boundary_error_on_unsupported_return
    e = assert_raises(D::BoundaryError) { D.boundary_check_return!("foo", "str_array") }
    assert_match(/return type "str_array" does not cross/, e.message)
  end

  def test_supported_return_types_pass
    %w[int bool void nil].each { |t| assert_nil D.boundary_check_return!("m", t) }
  end
end
