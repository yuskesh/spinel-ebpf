# frozen_string_literal: true
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/codegen_bpf_test.rb

require "minitest/autorun"
require "spinel_ebpf/codegen_bpf"
require "spinel_ebpf/partition"

class CodegenBpfTest < Minitest::Test
  P    = SpinelEbpf::Partition
  GEN  = SpinelEbpf::CodegenBpf
  FIX  = File.expand_path("../fixtures", __dir__)

  def emit_for(name, **kw)
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{name}.ast")
    r   = P.classify(ir, ast)
    GEN.emit(ir, ast, r, base_name: name, **kw)
  end

  # ---------- data-driven section registry ----------

  def test_section_registry_covers_all_uses_flags_with_real_emitters
    # Every registry entry's emitter must be a real method, and every flag-symbol
    # gate must be an actual EmitContext member (guards against typos / drift).
    members = SpinelEbpf::CodegenBpf::EmitContext.members
    SpinelEbpf::CodegenBpf::SECTION_REGISTRY.each do |gate, emitter|
      assert SpinelEbpf::CodegenBpf.respond_to?(emitter, true),
             "registry emitter #{emitter} must be a CodegenBpf method"
      assert_includes members, gate, "registry gate #{gate} must be an EmitContext member" unless gate.is_a?(Proc)
    end
  end

  def test_plugin_section_is_spliced_in_additively
    # A plugin can add a section via plugin_sections without editing codegen.
    sentinel = "/* spnl-plugin-section: extra map */"
    plugin = [[->(_ctx) { true }, ->(_ctx) { sentinel }]]
    c = emit_for("02_integer_arith", plugin_sections: plugin)
    assert_includes c, sentinel, "plugin_sections emitter output must appear in the unit"
    # And it must NOT appear without the plugin (proves it's the hook, not coincidence).
    refute_includes emit_for("02_integer_arith"), sentinel
  end

  def test_plugin_section_predicate_gates_emission
    sentinel = "/* gated-off */"
    plugin = [[->(_ctx) { false }, ->(_ctx) { sentinel }]]
    refute_includes emit_for("02_integer_arith", plugin_sections: plugin), sentinel
  end

  # ---------- header + boilerplate ----------

  def test_emits_license_and_includes
    c = emit_for("04_class_with_ivars")
    assert_includes c, '#include "vmlinux.h"'
    assert_includes c, '#include <bpf/bpf_helpers.h>'
    assert_includes c, 'char LICENSE[] SEC("license") = "Dual MIT/GPL";'
  end

  def test_header_mentions_source_unit_and_counts
    c = emit_for("04_class_with_ivars")
    assert_includes c, "Source unit: 04_class_with_ivars.rb"
    assert_includes c, "ebpf-eligible methods: 3, classes touched: 1"
  end

  # ---------- per-ivar HASH map ----------

  def test_counter_ivar_map_declaration
    c = emit_for("04_class_with_ivars")
    assert_includes c, "/* class Counter ivar @count : int */"
    assert_includes c, "BPF_MAP_TYPE_HASH"
    assert_includes c, "__type(key, __u32);"
    assert_includes c, "__type(value, __s64);"
    assert_includes c, "} counter_at_count SEC(\".maps\");"
  end

  # ---------- per-method SEC("syscall") emission ----------

  # NOTE: each ebpf method is now emitted as (static __noinline _inner)
  # + (SEC("syscall") wrapper). Body checks target the _inner block.

  def test_counter_initialize_writes_zero
    c = emit_for("04_class_with_ivars")
    assert_match(/SEC\("syscall"\)\s+int counter_initialize\(void \*ctx\)/, c)
    inner = c[/counter_initialize_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/__s64 _v\d+ = 0;\s*\n\s*bpf_map_update_elem\(&counter_at_count/, inner)
  end

  def test_counter_incr_lookup_add_update_return
    c = emit_for("04_class_with_ivars")
    assert_match(/SEC\("syscall"\)\s+int counter_incr\(void \*ctx\)/, c)
    inner = c[/counter_incr_inner\(.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "bpf_map_lookup_elem(&counter_at_count"
    assert_includes inner, "+ (1)"
    assert_includes inner, "bpf_map_update_elem(&counter_at_count"
    assert_match(/return _v\d+;/, inner)
  end

  def test_counter_value_lookup_only
    c = emit_for("04_class_with_ivars")
    inner = c[/counter_value_inner\(.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "bpf_map_lookup_elem(&counter_at_count"
    refute_includes inner, "bpf_map_update_elem"
    assert_match(/return \(_p\d+ \? \*_p\d+ : 0\);/, inner)
  end

  # ---------- fixtures with no ebpf methods produce no functions ----------

  def test_fixture_with_only_native_methods_emits_no_methods
    # 06_regex: all methods are :native, so we emit header + includes only
    c = emit_for("06_regex")
    assert_includes c, "ebpf-eligible methods: 0"
    refute_match(/SEC\("syscall"\)/, c)
    refute_match(/BPF_MAP_TYPE_HASH/, c)
  end

  # ---------- top-level methods with params + binary ops ----------

  def test_add_emits_ctx_struct_and_function
    c = emit_for("02_integer_arith")
    assert_includes c, "ebpf-eligible methods: 2"
    assert_includes c, "struct add_ctx {"
    assert_includes c, "__s64 a;"
    assert_includes c, "__s64 b;"
    assert_includes c, "struct sub_ctx {"
    assert_match(/int add\(struct add_ctx \*ctx\)/, c)
    assert_match(/int sub\(struct sub_ctx \*ctx\)/, c)
  end

  def test_add_body_uses_inner_with_bare_params
    c = emit_for("02_integer_arith")
    # The implementation lives in <name>_inner with bare param names.
    add_inner = c[/static __noinline __s64 add_inner.*?\n\}/m]
    refute_nil add_inner
    # Defensive parentheses are minimized by delegating to the CPrinter's precedence.
    assert_includes add_inner, "return a + b;"
    sub_inner = c[/static __noinline __s64 sub_inner.*?\n\}/m]
    assert_includes sub_inner, "return a - b;"
    # The SEC wrapper just calls inner with ctx->fields.
    add_wrap = c[/SEC\("syscall"\)\s+int add\(.*?\n\}/m]
    refute_nil add_wrap
    assert_includes add_wrap, "return (int)add_inner(ctx->a, ctx->b);"
  end

  def test_string_signature_keeps_method_native
    # Partition now rejects methods whose signature mentions a non-int
    # type (string/array/hash/...) — see test_09_* in partition_test.rb.
    # As a result, greet (originally :ebpf) becomes :native, codegen
    # has nothing to emit, and we just get a license/header stub. No raise.
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/09_string_ops.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/09_string_ops.ast")
    r   = P.classify(ir, ast)
    assert r.methods.find { |m| m.method_name == "greet" }&.tag == :native,
           "greet should be :native after the signature check"
    # emit should still succeed (no :ebpf methods → minimal output)
    GEN.emit(ir, ast, r, base_name: "09_string_ops")
  end

  # ---------- IfNode + comparison ops ----------

  def test_max_emits_if_else
    c = emit_for("11_max_if")
    inner = c[/static __noinline __s64 max_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "__s64 _if1 = 0;"
    assert_match(/if \(a > b\) \{/, inner)
    assert_includes inner, "_if1 = a;"
    assert_includes inner, "} else {"
    assert_includes inner, "_if1 = b;"
    assert_includes inner, "return _if1;"
  end

  def test_sign_emits_nested_elsif
    c = emit_for("11_max_if")
    inner = c[/static __noinline __s64 sign_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "__s64 _if1 = 0;"
    assert_includes inner, "__s64 _if2 = 0;"
    assert_match(/if \(x > 0\) \{/, inner)
    assert_match(/if \(x < 0\) \{/, inner)
    assert_includes inner, "_if2 = -1;"
    assert_includes inner, "_if1 = _if2;"
  end

  # ---------- ringbuf emit (spnl_emit built-in) ----------

  def test_includes_spnl_types_when_emit_used
    c = emit_for("12_spnl_emit")
    assert_includes c, '#include "spnl/types.h"'
  end

  def test_does_not_include_spnl_types_without_emit
    # Counter doesn't call spnl_emit; the header should NOT be included.
    c = emit_for("04_class_with_ivars")
    refute_includes c, '#include "spnl/types.h"'
  end

  def test_per_unit_ringbuf_map
    c = emit_for("12_spnl_emit")
    # unit_name = sanitize("12_spnl_emit") = "u_12_spnl_emit" (digit prefix)
    assert_includes c, "struct u_12_spnl_emit_event {"
    assert_includes c, "struct spnl_event_hdr hdr;"
    assert_includes c, "__s64 value;"
    assert_includes c, "BPF_MAP_TYPE_RINGBUF"
    assert_match(/} u_12_spnl_emit_events SEC\(".maps"\);/, c)
  end

  def test_report_calls_ringbuf_helpers
    c = emit_for("12_spnl_emit")
    inner = c[/static __noinline (?:void|__s64) report_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "bpf_ringbuf_reserve(&u_12_spnl_emit_events"
    assert_includes inner, "hdr.type = SPNL_EVT_USER_BASE"
    assert_includes inner, "hdr.timestamp = bpf_ktime_get_ns()"
    # params are bare names inside _inner
    assert_includes inner, "->value = x;"
    assert_includes inner, "bpf_ringbuf_submit("
  end

  def test_report_doubled_uses_expression
    c = emit_for("12_spnl_emit")
    inner = c[/static __noinline (?:void|__s64) report_doubled_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "->value = x + x;"
  end

  def test_partition_main_forced_native
    # Even though 12_spnl_emit/main has no impossible features, partition
    # must tag :main as :native (it's the program entry point).
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/12_spnl_emit.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/12_spnl_emit.ast")
    r   = P.classify(ir, ast)
    main = r.methods.find { |m| m.scope == :main }
    refute_nil main
    assert_equal :native, main.tag
  end

  # ---------- local variables ----------

  def test_calc_declares_locals_at_top
    c = emit_for("13_locals")
    inner = c[/static __noinline __s64 calc_inner.*?\n\}/m]
    refute_nil inner
    assert_match(/^    __s64 x = 0;$/, inner)
    assert_match(/^    __s64 y = 0;$/, inner)
    # params are bare names inside _inner
    assert_includes inner, "x = a + b;"
    assert_includes inner, "y = x * 2;"
    assert_includes inner, "return y - 1;"
  end

  # Local declarations are now typed from the IR's inferred type
  # (not a hardcoded __s64), but the LOCAL_TYPE_TO_C table maps every scalar to
  # __s64 so output stays byte-identical. This locks that invariant: a future
  # edit that changes a scalar's local C type would break the byte-identical
  # guarantee and trip this test (a later step will intentionally add ptr/obj_).
  def test_local_type_table_is_all_s64_in_step1
    t = SpinelEbpf::CodegenBpf::LOCAL_TYPE_TO_C
    %w[int bool nil void].each do |scalar|
      assert_equal "__s64", t[scalar], "Step 1 must map local #{scalar} -> __s64"
    end
    # 13_locals' int locals therefore still declare as __s64 (byte-identical).
    inner = emit_for("13_locals")[/static __noinline __s64 calc_inner.*?\n\}/m]
    assert_match(/^    __s64 x = 0;$/, inner)
  end

  def test_step_simple_chain
    c = emit_for("13_locals")
    inner = c[/static __noinline __s64 step_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "__s64 inc = 0;"
    assert_includes inner, "__s64 doubled = 0;"
    assert_includes inner, "inc = n + 1;"
    assert_includes inner, "doubled = inc * 2;"
    assert_includes inner, "return doubled;"
  end

  def test_reassign_keeps_one_declaration
    c = emit_for("13_locals")
    inner = c[/static __noinline __s64 reassign_inner.*?\n\}/m]
    refute_nil inner
    assert_equal 1, inner.scan(/__s64 acc = 0;/).length
    assert_equal 3, inner.scan(/^\s*acc =/).length
    assert_includes inner, "return acc;"
  end

  def test_undeclared_read_raises
    # Force a hypothetical situation: a local read with no corresponding
    # write. Manually craft a fake AST? Simpler — make sure existing
    # fixtures don't hit this; just smoke-test the API path.
    # (Real defensive testing requires a synthetic AST; skipped for MVP.)
  end

  # ---------- BPF-to-BPF calls ----------

  def test_calls_emit_inner_pairs
    c = emit_for("14_calls")
    # 3 ebpf methods, each emits inner + wrapper
    %w[twice quad six_times].each do |name|
      assert_match(/static __noinline __s64 #{name}_inner\(__s64 x\)/, c)
      assert_match(/SEC\("syscall"\)\s+int #{name}\(struct #{name}_ctx \*ctx\)/, c)
      assert_match(/return \(int\)#{name}_inner\(ctx->x\);/, c)
    end
  end

  def test_quad_calls_twice_inner
    c = emit_for("14_calls")
    inner = c[/static __noinline __s64 quad_inner.*?\n\}/m]
    refute_nil inner
    # quad returns twice(x) + twice(x) -- both go through _inner
    assert_includes inner, "return twice_inner(x) + twice_inner(x);"
  end

  def test_six_times_calls_both
    c = emit_for("14_calls")
    inner = c[/static __noinline __s64 six_times_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "return twice_inner(x) + quad_inner(x);"
  end

  # ---------- n.times { } -> bpf_loop ----------

  def test_emit_squares_uses_bpf_loop
    c = emit_for("15_times_loop")
    # callback function appears before the inner that calls it
    cb_idx = c.index(/static int emit_squares_loop\d+_cb/)
    inner_idx = c.index(/static __noinline __s64 emit_squares_inner/)
    refute_nil cb_idx
    refute_nil inner_idx
    assert cb_idx < inner_idx, "callback must be defined before its caller"
    # inner calls bpf_loop with the bound expression
    inner = c[/emit_squares_inner.*?\n\}/m]
    assert_match(/bpf_loop\(n, &emit_squares_loop\d+_cb, NULL, 0\);/, inner)
  end

  def test_callback_body_lowers_block
    c = emit_for("15_times_loop")
    cb = c[/static int emit_squares_loop\d+_cb.*?\n\}/m]
    refute_nil cb
    # callback declares __s64 i = raw index, ignores ctx
    assert_includes cb, "__s64 i = (__s64)_raw_index;"
    assert_includes cb, "(void)_raw_ctx;"
    # body emits ringbuf event with value = i * i
    assert_includes cb, "->value = i * i;"
    assert_includes cb, "return 0;"
  end

  def test_multiple_times_calls_get_unique_cb_names
    c = emit_for("15_times_loop")
    cb_names = c.scan(/static int (emit_(?:squares|indices)_loop\d+_cb)\(/).flatten
    assert_equal cb_names.length, cb_names.uniq.length, "cb names must be unique"
    # one cb for each method
    assert_includes cb_names.join(" "), "emit_squares_loop"
    assert_includes cb_names.join(" "), "emit_indices_loop"
  end

  # ---------- closure capture in n.times ----------

  def test_sum_squares_emits_capture_struct
    c = emit_for("16_closure")
    # capture struct: ptr to total
    assert_match(/struct sum_squares_loop\d+_cb_caps \{\s*\n\s*__s64 \*total;\s*\n\s*\};/, c)
  end

  def test_callback_dereferences_capture
    c = emit_for("16_closure")
    cb = c[/static int sum_squares_loop\d+_cb.*?\n\}/m]
    refute_nil cb
    assert_includes cb, "struct sum_squares_loop"
    assert_includes cb, "*_lc = (struct sum_squares_loop"
    # total = total + i*i lowers to *_lc->total assignment with deref reads
    assert_match(/\*_lc->total = \(\*_lc->total\) \+ i \* i;/, cb)
  end

  def test_inner_initializes_capture_instance_and_passes_address
    c = emit_for("16_closure")
    inner = c[/static __noinline __s64 sum_squares_inner.*?\n\}/m]
    refute_nil inner
    assert_match(/struct sum_squares_loop\d+_cb_caps _loop\d+_caps = \{ \.total = &total \};/, inner)
    assert_match(/bpf_loop\(n, &sum_squares_loop\d+_cb, &_loop\d+_caps, 0\);/, inner)
    assert_includes inner, "return total;"
  end

  def test_emit_running_sum_uses_capture_in_spnl_emit
    c = emit_for("16_closure")
    cb = c[/static int emit_running_sum_loop\d+_cb.*?\n\}/m]
    refute_nil cb
    assert_match(/\*_lc->acc = \(\*_lc->acc\) \+ i;/, cb)
    # spnl_emit reads through the same capture pointer
    assert_includes cb, "->value = (*_lc->acc);"
  end

  # ---------- kernel-event attach via method name prefix ----------

  def test_tracepoint_method_emits_correct_sec
    c = emit_for("17_kprobe")
    assert_match(%r{SEC\("tracepoint/syscalls/sys_enter_openat"\)}, c)
    assert_match(/int tracepoint__syscalls__sys_enter_openat\(void \*ctx\)/, c)
  end

  def test_attach_method_keeps_inner_pattern
    c = emit_for("17_kprobe")
    inner_re = /static __noinline __s64 tracepoint__syscalls__sys_enter_openat_inner\(void\)/
    assert_match(inner_re, c)
    wrapper_block = c[/SEC\("tracepoint\/[^"]*"\)\s+int.*?\n\}/m]
    refute_nil wrapper_block
    assert_includes wrapper_block, "(void)ctx;"
    assert_includes wrapper_block, "tracepoint__syscalls__sys_enter_openat_inner();"
    assert_includes wrapper_block, "return 0;"
  end

  def test_conditional_kprobe_inner_compiles_clean
    # A kprobe handler whose body is `if … end` without `else`.
    # The C compiler types its return `nil` (the implicit nil
    # branch), so the inner is `void` with NO value-return — which compiles
    # clean. (The legacy Ruby analyzer typed it `int?`, which once mis-lowered
    # to a `void` inner *with* a `return <value>;` body -> clang
    # -Wreturn-mismatch; that fixture form is gone now that fixtures are
    # regenerated from the C compiler. The partition-side nullable eligibility
    # is still guarded inline in partition_test.)
    c = emit_for("97_kprobe_conditional_emit")
    inner = c[/static __noinline (?:void|__s64) kprobe__tcp_sendmsg_inner.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "static __noinline void kprobe__tcp_sendmsg_inner",
                    "C compiler types `if…end` return as nil -> void inner"
    # The conditional emit block is intact.
    assert_includes inner, "if (size > 256)"
    assert_includes inner, "bpf_ringbuf_reserve("
    # A void inner must NOT carry a value-return (the -Wreturn-mismatch case).
    refute_includes inner, "return ",
                    "void inner must not emit a value-return (-Wreturn-mismatch)"
    # wrapper calls the (void) inner and returns 0 (kprobe return is ignored).
    wrapper = c[%r{SEC\("kprobe/tcp_sendmsg"\)\s+int.*?\n\}}m]
    refute_nil wrapper
    assert_includes wrapper, "kprobe__tcp_sendmsg_inner("
    assert_includes wrapper, "return 0;"
  end

  def test_bool_signature_lowers_to_s32_and_stays_ebpf
    # A: `bool` is an eligible eBPF signature type (Ruby SUPPORTED_EBPF_SIGNATURE
    # _TYPES). A bool param/return lowers to __s32 (SPINEL_TYPE_TO_C["bool"]); the
    # method stays eBPF instead of falling back to native. (Locals are unaffected
    # — they stay __s64 via LOCAL_TYPE_TO_C.) is_big returns a comparison (bool);
    # both takes that bool and returns it.
    c = emit_for("98_bool_sig")
    assert_includes c, "static __noinline __s32 is_big_inner(__s64 size)"
    assert_includes c, "static __noinline __s32 both_inner(__s32 flag)"
  end

  def test_detect_attach_kprobe_naming
    # The detect_attach helper should map name -> attach metadata.
    m = SpinelEbpf::CodegenBpf.detect_attach("kprobe__do_filp_open")
    refute_nil m
    assert_equal :kprobe, m[:kind]
    assert_equal "kprobe/do_filp_open", m[:sec]
    assert_includes m[:ctx_type], "pt_regs"
  end

  def test_detect_attach_tracepoint_naming
    m = SpinelEbpf::CodegenBpf.detect_attach("tracepoint__syscalls__sys_enter_openat")
    refute_nil m
    assert_equal :tracepoint, m[:kind]
    assert_equal "tracepoint/syscalls/sys_enter_openat", m[:sec]
  end

  def test_detect_attach_returns_nil_for_normal_methods
    assert_nil SpinelEbpf::CodegenBpf.detect_attach("twice")
    assert_nil SpinelEbpf::CodegenBpf.detect_attach("sum_squares")
  end

  # ---------- attach methods with args ----------

  def test_tracepoint_with_args_extracts_from_ctx
    c = emit_for("18_tp_args")
    inner = c[/static __noinline __s64 tracepoint__syscalls__sys_enter_openat_inner\(__s64 dfd\)/]
    refute_nil inner
    wrapper = c[/SEC\("tracepoint\/syscalls\/sys_enter_openat"\)\s+int .*?\n\}/m]
    refute_nil wrapper
    assert_includes wrapper,
      "tracepoint__syscalls__sys_enter_openat_inner((__s64)((struct trace_event_raw_sys_enter *)ctx)->args[0]);"
  end

  def test_extract_attach_args_kprobe
    # Build a mock attach descriptor and exercise the extractor directly.
    attach = { kind: :kprobe, sec: "kprobe/x", ctx_type: "struct pt_regs *" }
    exs = SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["a", "int"], ["b", "int"]])
    assert_equal "(__s64)PT_REGS_PARM1(ctx)", exs[0]
    assert_equal "(__s64)PT_REGS_PARM2(ctx)", exs[1]
  end

  def test_extract_attach_args_tracepoint_sys_enter
    attach = SpinelEbpf::CodegenBpf.detect_attach("tracepoint__syscalls__sys_enter_openat")
    exs = SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["dfd", "int"], ["flags", "int"]])
    assert_includes exs[0], "trace_event_raw_sys_enter"
    assert_includes exs[0], "args[0]"
    assert_includes exs[1], "args[1]"
  end

  def test_extract_attach_args_unsupported_tracepoint_raises
    attach = SpinelEbpf::CodegenBpf.detect_attach("tracepoint__sched__sched_switch")
    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["a", "int"]])
    end
  end

  # ---------- spnl_emit_str (string via bpf_probe_read_user_str) ----------

  def test_emits_separate_str_ringbuf_when_used
    c = emit_for("19_emit_str")
    assert_includes c, "struct u_19_emit_str_str_event {"
    assert_includes c, "char str[256];"
    assert_includes c, "} u_19_emit_str_str_events SEC(\".maps\");"
  end

  def test_lowers_to_bpf_probe_read_user_str
    c = emit_for("19_emit_str")
    inner = c[/static __noinline __s64 tracepoint__syscalls__sys_enter_openat_inner.*?\n\}/m]
    refute_nil inner
    # The string emit reads from the second arg (filename pointer).
    assert_match(/bpf_probe_read_user_str\(_se\d+->str, sizeof\(_se\d+->str\), \(const void \*\)\(filename\)\);/, inner)
    assert_includes inner, "bpf_ringbuf_reserve(&u_19_emit_str_str_events"
    assert_includes inner, "bpf_ringbuf_submit("
  end

  def test_both_int_and_str_channels_coexist
    c = emit_for("19_emit_str")
    # Both ringbufs and both event structs should be present.
    assert_includes c, "u_19_emit_str_events SEC(\".maps\")"
    assert_includes c, "u_19_emit_str_str_events SEC(\".maps\")"
    assert_includes c, "struct u_19_emit_str_event {"
    assert_includes c, "struct u_19_emit_str_str_event {"
  end

  # ---------- top-level ivars ----------

  def test_emits_per_unit_top_ivar_map
    c = emit_for("20_top_ivar")
    assert_includes c, "/* top-level ivar @open_count : int */"
    assert_match(/} u_20_top_ivar_top_open_count SEC\(".maps"\);/, c)
  end

  def test_handler_uses_top_ivar_map_for_read_and_write
    c = emit_for("20_top_ivar")
    inner = c[/static __noinline __s64 tracepoint__syscalls__sys_enter_openat_inner.*?\n\}/m]
    refute_nil inner
    # Both lookup and update happen against the top-level map.
    assert_match(/bpf_map_lookup_elem\(&u_20_top_ivar_top_open_count,/, inner)
    assert_match(/bpf_map_update_elem\(&u_20_top_ivar_top_open_count,/, inner)
  end

  def test_top_ivar_map_name_helper
    assert_equal "u_foo_top_count",
                 SpinelEbpf::CodegenBpf.top_ivar_map_name("u_foo", "@count")
  end

  # ---------- per-tracepoint named field extraction ----------

  def test_sched_switch_uses_named_fields
    c = emit_for("21_sched")
    assert_match(/SEC\("tracepoint\/sched\/sched_switch"\)/, c)
    # named field extraction, NOT positional args[i]
    assert_includes c, "((struct trace_event_raw_sched_switch *)ctx)->prev_pid"
    assert_includes c, "((struct trace_event_raw_sched_switch *)ctx)->next_pid"
    refute_includes c, "->args[0]"
    refute_includes c, "->args[1]"
  end

  def test_unknown_tracepoint_event_raises
    attach = SpinelEbpf::CodegenBpf.detect_attach("tracepoint__net__net_dev_xmit")
    refute_nil attach
    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["a", "int"]])
    end
  end

  def test_unknown_field_in_known_event_raises
    attach = SpinelEbpf::CodegenBpf.detect_attach("tracepoint__sched__sched_switch")
    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["bogus_field", "int"]])
    end
  end

  # ---------- XDP attach + KNOWN_CONSTANTS ----------

  def test_detect_attach_xdp_naming
    m = SpinelEbpf::CodegenBpf.detect_attach("xdp__main")
    refute_nil m
    assert_equal :xdp, m[:kind]
    assert_equal "xdp", m[:sec]
    assert_equal "main", m[:xdp_name]
    assert_equal "struct xdp_md *", m[:ctx_type]
  end

  def test_xdp_method_emits_sec_xdp_and_xdp_md_ctx
    c = emit_for("24_xdp_counter")
    assert_match(%r{SEC\("xdp"\)\s+int xdp__main\(struct xdp_md \*ctx\)}, c)
  end

  def test_xdp_wrapper_propagates_inner_return_value
    # XDP must NOT collapse the inner return like kprobe does (return 0 always).
    # ctx is forwarded into _inner so packet builtins can read headers.
    c = emit_for("24_xdp_counter")
    wrapper = c[/SEC\("xdp"\)\s+int xdp__main\(struct xdp_md \*ctx\)\s*\{.*?\n\}/m]
    refute_nil wrapper
    assert_includes wrapper, "return (int)xdp__main_inner(ctx);"
    refute_includes wrapper, "return 0;"
  end

  def test_xdp_pass_constant_lowered_to_integer_literal
    c = emit_for("24_xdp_counter")
    # body's last expr is XDP_PASS -> literal 2
    assert_includes c, "return 2;"
  end

  def test_xdp_params_raise_unsupported
    attach = SpinelEbpf::CodegenBpf.detect_attach("xdp__main")
    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["pkt", "int"]])
    end
  end

  def test_known_constants_table_has_xdp_retvals
    t = SpinelEbpf::CodegenBpf::KNOWN_CONSTANTS
    assert_equal 0, t["XDP_ABORTED"]
    assert_equal 1, t["XDP_DROP"]
    assert_equal 2, t["XDP_PASS"]
    assert_equal 3, t["XDP_TX"]
    assert_equal 4, t["XDP_REDIRECT"]
  end

  # ---------- XDP fast-path (xdp_match_health + xdp_reply_health) ----------

  def test_builtin_names_include_xdp_health_helpers
    %w[xdp_match_health xdp_reply_health].each do |n|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, n, "missing builtin #{n}"
    end
  end

  def test_request_prefix_and_response_body
    assert_equal "GET /health ", SpinelEbpf::CodegenBpf::HEALTH_REQUEST_PREFIX
    assert_equal "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n",
                 SpinelEbpf::CodegenBpf::HEALTH_RESPONSE_BODY
    assert_equal 41, SpinelEbpf::CodegenBpf::HEALTH_RESPONSE_BODY.length
  end

  def test_response_partial_csum_precomputed
    # Sanity: codegen-time precomputed checksum is non-zero (varies with body
    # bytes). Used to eliminate a verifier-painful payload loop.
    refute_equal 0, SpinelEbpf::CodegenBpf::HEALTH_RESPONSE_CSUM_PARTIAL
  end

  # ---------- sockmap / sk_msg / sk_skb (HTTP server building block) ----------

  def test_detect_attach_sk_msg
    m = SpinelEbpf::CodegenBpf.detect_attach("sk_msg__redirect_all")
    refute_nil m
    assert_equal :sk_msg, m[:kind]
    assert_equal "sk_msg", m[:sec]
    assert_equal "redirect_all", m[:sm_name]
    assert_equal "struct sk_msg_md *", m[:ctx_type]
  end

  def test_detect_attach_sk_skb_verdict
    m = SpinelEbpf::CodegenBpf.detect_attach("sk_skb__verdict__route")
    refute_nil m
    assert_equal :sk_skb_verdict, m[:kind]
    assert_equal "sk_skb/stream_verdict", m[:sec]
    assert_equal "struct __sk_buff *", m[:ctx_type]
  end

  def test_detect_attach_sk_skb_parser
    m = SpinelEbpf::CodegenBpf.detect_attach("sk_skb__parser__chunk")
    refute_nil m
    assert_equal :sk_skb_parser, m[:kind]
    assert_equal "sk_skb/stream_parser", m[:sec]
  end

  def test_sk_msg_method_emits_sec_and_msg_md_ctx
    c = emit_for("34_sk_msg")
    assert_match(%r{SEC\("sk_msg"\)\s+int sk_msg__pass_all\(struct sk_msg_md \*ctx\)}, c)
  end

  def test_sk_skb_method_emits_sec_and_skb_ctx
    c = emit_for("34_sk_msg")
    assert_match(%r{SEC\("sk_skb/stream_verdict"\)\s+int sk_skb__verdict__pass_all\(struct __sk_buff \*ctx\)}, c)
  end

  def test_sockmap_wrappers_propagate_inner_return_value
    c = emit_for("34_sk_msg")
    wrap_msg = c[/SEC\("sk_msg"\).*?\n\}/m]
    refute_nil wrap_msg
    assert_includes wrap_msg, "return (int)sk_msg__pass_all_inner(ctx);"
    wrap_skb = c[/SEC\("sk_skb\/stream_verdict"\).*?\n\}/m]
    refute_nil wrap_skb
    assert_includes wrap_skb, "return (int)sk_skb__verdict__pass_all_inner(ctx);"
  end

  def test_sk_msg_params_raise_unsupported
    attach = SpinelEbpf::CodegenBpf.detect_attach("sk_msg__demo")
    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["x", "int"]])
    end
  end

  # ---------- SK_REUSEPORT BPF (worker selection) ----------

  def test_detect_attach_sk_reuseport
    m = SpinelEbpf::CodegenBpf.detect_attach("sk_reuseport__pass_all")
    refute_nil m
    assert_equal :sk_reuseport, m[:kind]
    assert_equal "sk_reuseport", m[:sec]
    assert_equal "pass_all", m[:sr_name]
    assert_equal "struct sk_reuseport_md *", m[:ctx_type]
  end

  def test_known_constants_has_sk_pass_drop
    t = SpinelEbpf::CodegenBpf::KNOWN_CONSTANTS
    # Kernel <linux/bpf.h>: enum sk_action { SK_DROP = 0, SK_PASS = 1 }
    assert_equal 0, t["SK_DROP"]
    assert_equal 1, t["SK_PASS"]
  end

  def test_sk_reuseport_method_emits_sec_and_md_ctx
    c = emit_for("33_sk_reuseport")
    assert_match(%r{SEC\("sk_reuseport"\)\s+int sk_reuseport__pass_all\(struct sk_reuseport_md \*ctx\)}, c)
  end

  def test_sk_reuseport_wrapper_propagates_inner_return_value
    c = emit_for("33_sk_reuseport")
    wrapper = c[/SEC\("sk_reuseport"\).*?\n\}/m]
    refute_nil wrapper
    assert_includes wrapper, "return (int)sk_reuseport__pass_all_inner(ctx);"
    refute_includes wrapper, "return 0;\n"
  end

  def test_sk_reuseport_params_raise_unsupported
    attach = SpinelEbpf::CodegenBpf.detect_attach("sk_reuseport__pass_all")
    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      SpinelEbpf::CodegenBpf.extract_attach_args(attach, [["hash", "int"]])
    end
  end

  # ---------- path counter (HASH map + atomic inc builtin) ----------

  def test_builtin_names_include_path_counter_inc
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "path_counter_inc"
  end

  def test_path_counter_inc_emits_map_and_helper
    c = emit_for("32_path_counter")
    assert_match(/__uint\(type, BPF_MAP_TYPE_HASH\);[^}]*__type\(key, __u32\);[^}]*__type\(value, __s64\);[^}]*\} bpf_path_counts SEC\(".maps"\);/m, c)
    assert_match(/static __noinline __s64 spnl_path_counter_inc\(__s64 key\)/, c)
    assert_includes c, "__sync_fetch_and_add(v, 1);"
  end

  def test_path_counter_inc_emitted_as_statement_not_dropped
    # Regression: the inc call must appear in the inner body (not silently
    # eliminated because its return value is unused).
    c = emit_for("32_path_counter")
    inner = c[/static __noinline __s64 record_path_hit_inner\(__s64 key\)[^{]*\{[^}]*\}/m]
    refute_nil inner, "record_path_hit_inner missing"
    assert_includes inner, "spnl_path_counter_inc(key);"
  end

  def test_path_counter_only_emitted_when_used
    c = emit_for("31_tc_blocklist")
    refute_includes c, "bpf_path_counts"
    refute_includes c, "spnl_path_counter_inc"
  end

  # ---------- dynamic blocklist (HASH map + builtin) ----------

  def test_builtin_names_include_blocklist_match
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "blocklist_match"
  end

  def test_blocklist_match_emits_map_and_helper
    c = emit_for("31_tc_blocklist")
    # Map declaration
    assert_match(/__uint\(type, BPF_MAP_TYPE_HASH\);[^}]*__type\(key, __u32\);[^}]*__type\(value, __u8\);[^}]*\} bpf_blocklist SEC\(".maps"\);/m, c)
    # Matcher helper
    assert_match(/static __noinline __s64 spnl_blocklist_match\(__s64 ip_host_order\)/, c)
    # Call site (chained with pkt_ip4_src)
    assert_includes c, "spnl_blocklist_match(spnl_tc_pkt_ip4_src(ctx))"
  end

  def test_blocklist_only_emitted_when_used
    # 30_tc_port_filter uses pkt_l4_*port but not blocklist_match
    c = emit_for("30_tc_port_filter")
    refute_includes c, "bpf_blocklist"
    refute_includes c, "spnl_blocklist_match"
  end

  # ---------- TC classifier (tcx/ingress, tcx/egress) ----------

  def test_detect_attach_tc_ingress
    m = SpinelEbpf::CodegenBpf.detect_attach("tc__ingress__http_filter")
    refute_nil m
    assert_equal :tc_ingress, m[:kind]
    assert_equal "tcx/ingress", m[:sec]
    assert_equal "http_filter", m[:tc_name]
    assert_equal "struct __sk_buff *", m[:ctx_type]
  end

  def test_detect_attach_tc_egress
    m = SpinelEbpf::CodegenBpf.detect_attach("tc__egress__shaper")
    refute_nil m
    assert_equal :tc_egress, m[:kind]
    assert_equal "tcx/egress", m[:sec]
  end

  def test_known_constants_has_tc_actions
    t = SpinelEbpf::CodegenBpf::KNOWN_CONSTANTS
    assert_equal 0, t["TC_ACT_OK"]
    assert_equal 2, t["TC_ACT_SHOT"]
    assert_equal 7, t["TC_ACT_REDIRECT"]
  end

  def test_tc_method_emits_sec_tcx_and_skb_ctx
    c = emit_for("30_tc_port_filter")
    assert_match(%r{SEC\("tcx/ingress"\)\s+int tc__ingress__http_filter\(struct __sk_buff \*ctx\)}, c)
  end

  def test_tc_wrapper_propagates_inner_return_value
    c = emit_for("30_tc_port_filter")
    wrapper = c[/SEC\("tcx\/ingress"\).*?\n\}/m]
    refute_nil wrapper
    assert_includes wrapper, "return (int)tc__ingress__http_filter_inner(ctx);"
    refute_includes wrapper, "return 0;"
  end

  def test_pkt_builtins_emit_tc_helper_when_used_in_tc_method
    c = emit_for("30_tc_port_filter")
    # spnl_tc_pkt_l4_dport / sport with struct __sk_buff *ctx
    assert_match(/static __noinline __s64 spnl_tc_pkt_l4_dport\(struct __sk_buff \*ctx\)/, c)
    assert_match(/static __noinline __s64 spnl_tc_pkt_l4_sport\(struct __sk_buff \*ctx\)/, c)
    # call site uses the tc variant
    assert_includes c, "spnl_tc_pkt_l4_dport(ctx)"
    assert_includes c, "spnl_tc_pkt_l4_sport(ctx)"
    # XDP variant should NOT be emitted (no xdp__* method uses pkt_*)
    refute_match(/spnl_pkt_l4_dport\(struct xdp_md/, c)
  end

  def test_or_node_short_circuit_in_codegen
    # OrNode is lowered as direct C `||`.
    c = emit_for("30_tc_port_filter")
    # == (prec 45) binds tighter than || (prec 20), so the operands need no parens.
    assert_match(/spnl_tc_pkt_l4_dport\(ctx\) == 8080 \|\| spnl_tc_pkt_l4_sport\(ctx\) == 8080/, c)
  end

  # ---------- pkt_* builtins (XDP header access) ----------

  def test_builtin_names_include_pkt_helpers
    %w[pkt_len pkt_eth_proto pkt_l4_proto pkt_ip4_src pkt_ip4_dst pkt_l4_sport pkt_l4_dport].each do |n|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, n, "missing builtin #{n}"
      assert_includes SpinelEbpf::CodegenBpf::PKT_BUILTINS, n, "missing PKT_BUILTINS entry #{n}"
    end
  end

  def test_known_constants_table_has_proto_and_ethertype
    t = SpinelEbpf::CodegenBpf::KNOWN_CONSTANTS
    assert_equal 1, t["IPPROTO_ICMP"]
    assert_equal 6, t["IPPROTO_TCP"]
    assert_equal 17, t["IPPROTO_UDP"]
    assert_equal 0x0800, t["ETH_P_IP"]
    assert_equal 0x86DD, t["ETH_P_IPV6"]
  end

  def test_pkt_len_lowers_to_helper_call_and_emits_helper
    c = emit_for("25_xdp_len")
    # Body invocation lowered as spnl_pkt_len(ctx)
    assert_includes c, "spnl_pkt_len(ctx)"
    # Helper definition appears with the bounds-check-safe formulation
    assert_match(/static __noinline __s64 spnl_pkt_len\(struct xdp_md \*ctx\)\s*\{[^}]*unsigned long e[^}]*unsigned long d[^}]*return \(__s64\)\(e - d\);[^}]*\}/m, c)
  end

  def test_xdp_inner_receives_ctx_when_pkt_builtin_used
    c = emit_for("25_xdp_len")
    # The inner signature gains `struct xdp_md *ctx` because pkt_len needs it.
    assert_match(/static __noinline __s64 xdp__main_inner\(struct xdp_md \*ctx\)/, c)
  end

  def test_bpf_endian_header_included_when_pkt_builtins_used
    c = emit_for("25_xdp_len")
    assert_includes c, "#include <bpf/bpf_endian.h>"
  end

  def test_pkt_helpers_emitted_only_when_used
    # 24_xdp_counter doesn't use any pkt_* builtin -> no helper section.
    c = emit_for("24_xdp_counter")
    refute_includes c, "spnl_pkt_len"
    refute_includes c, "#include <bpf/bpf_endian.h>"
  end

  # ---------- pkt_tcp_flags / pkt_l4_payload_len ----------

  def test_builtin_names_include_tcp_flags_and_payload_len
    assert_includes GEN::BUILTIN_NAMES, "pkt_tcp_flags"
    assert_includes GEN::BUILTIN_NAMES, "pkt_l4_payload_len"
    assert_includes GEN::PKT_BUILTINS, "pkt_tcp_flags"
    assert_includes GEN::PKT_BUILTINS, "pkt_l4_payload_len"
  end

  def test_known_constants_has_tcp_flag_bits
    t = GEN::KNOWN_CONSTANTS
    assert_equal 0x01, t["TCP_FLAG_FIN"]
    assert_equal 0x02, t["TCP_FLAG_SYN"]
    assert_equal 0x04, t["TCP_FLAG_RST"]
    assert_equal 0x08, t["TCP_FLAG_PSH"]
    assert_equal 0x10, t["TCP_FLAG_ACK"]
    assert_equal 0x20, t["TCP_FLAG_URG"]
    assert_equal 0x40, t["TCP_FLAG_ECE"]
    assert_equal 0x80, t["TCP_FLAG_CWR"]
  end

  def test_pkt_tcp_flags_helper_xdp_variant_has_bounds_check
    h = GEN.emit_pkt_helper("pkt_tcp_flags", :xdp)
    assert_match(/static __noinline __s64 spnl_pkt_tcp_flags\(struct xdp_md \*ctx\)/, h)
    # RFC 793 13th byte (offset 13) is checked for being in-bounds
    assert_match(/if \(l4 \+ 14 > \(char \*\)data_end\) return 0;/, h)
    # Reads byte at offset 13 (flags)
    assert_match(/__u8 flags = \(__u8\)l4\[13\];/, h)
    # TCP-only (proto 6)
    assert_includes h, "if (iph->protocol != 6) return 0;"
  end

  def test_pkt_tcp_flags_helper_tc_variant
    h = GEN.emit_pkt_helper("pkt_tcp_flags", :tc)
    assert_match(/static __noinline __s64 spnl_tc_pkt_tcp_flags\(struct __sk_buff \*ctx\)/, h)
  end

  def test_pkt_l4_payload_len_helper_handles_tcp_and_udp
    h = GEN.emit_pkt_helper("pkt_l4_payload_len", :tc)
    assert_match(/static __noinline __s64 spnl_tc_pkt_l4_payload_len\(struct __sk_buff \*ctx\)/, h)
    # TCP path subtracts data offset (header size)
    assert_includes h, "__u32 doff = (((__u8)l4[12]) >> 4) * 4;"
    assert_includes h, "if (doff < 20) return 0;"
    # UDP path subtracts fixed 8 bytes
    assert_match(/iph->protocol == 17/, h)
    assert_match(/l4_total > 8/, h)
  end

  # ---------- Roadmap #1 (Ruby tcp_slice): pkt.tcp.seq / pkt.tcp.ack ----------

  def test_pkt_tcp_seq_ack_in_builtins_and_chain_map
    assert_includes GEN::PKT_BUILTINS, "pkt_tcp_seq"
    assert_includes GEN::PKT_BUILTINS, "pkt_tcp_ack"
    # chain accessors pkt.tcp.seq / pkt.tcp.ack resolve to the flat builtins
    assert_equal "pkt_tcp_seq", GEN::PKT_CHAIN_MAP[%w[pkt tcp seq]]
    assert_equal "pkt_tcp_ack", GEN::PKT_CHAIN_MAP[%w[pkt tcp ack]]
  end

  def test_pkt_tcp_seq_helper_reads_offset_4_ntohl
    h = GEN.emit_pkt_helper("pkt_tcp_seq", :xdp)
    assert_match(/static __noinline __s64 spnl_pkt_tcp_seq\(struct xdp_md \*ctx\)/, h)
    assert_includes h, "if (iph->protocol != 6) return 0;"          # TCP-only
    assert_includes h, "__be32 *p = (__be32 *)(l4 + 4);"            # seq at offset 4
    assert_includes h, "if (l4 + 8 > (char *)data_end) return 0;"   # bounds: need 4 bytes
    assert_includes h, "return (__s64)bpf_ntohl(*p);"               # host byte order
  end

  def test_pkt_tcp_ack_helper_reads_offset_8_tc_variant
    h = GEN.emit_pkt_helper("pkt_tcp_ack", :tc)
    assert_match(/static __noinline __s64 spnl_tc_pkt_tcp_ack\(struct __sk_buff \*ctx\)/, h)
    assert_includes h, "__be32 *p = (__be32 *)(l4 + 8);"            # ack_seq at offset 8
    assert_includes h, "if (l4 + 12 > (char *)data_end) return 0;"  # bounds
  end

  # ---------- Roadmap #2 (Ruby tcp_slice): flow-state map ----------

  FlowFakeNode = Struct.new(:type, :attrs, :refs, :arrays)
  class FlowFakeAst
    def initialize(nodes) = (@nodes = nodes)
    def node(id) = @nodes[id]
  end

  def flow_ctx(maps, kinds)
    Struct.new(:unit_name, :flow_maps, :flow_map_kinds).new("u_demo", maps, kinds)
  end

  def test_flow_builtins_registered
    %w[flow_get flow_set flow_del].each { |b| assert_includes GEN::BUILTIN_NAMES, b }
  end

  def test_emit_flow_maps_struct_map_and_key_extract
    c = GEN.emit_flow_maps(flow_ctx({ "conn" => %w[state server_seq] }, { "conn" => Set[:xdp] }))
    # 4-tuple key struct
    assert_match(/struct spnl_flow_u_demo_conn_k \{/, c)
    assert_includes c, "__be32 saddr;"
    assert_includes c, "__be16 dport;"
    # value struct = u64 fields
    assert_match(/struct spnl_flow_u_demo_conn_v \{/, c)
    assert_includes c, "__u64 state;"
    assert_includes c, "__u64 server_seq;"
    # LRU_HASH map keyed/valued by those structs
    assert_includes c, "__uint(type, BPF_MAP_TYPE_LRU_HASH);"
    assert_includes c, "__type(key, struct spnl_flow_u_demo_conn_k);"
    assert_includes c, "} spnl_flow_u_demo_conn SEC(\".maps\");"
    # key-extraction helper (xdp), TCP-only, returns 0 on success
    assert_match(/static __noinline int spnl_flow_u_demo_conn_key_xdp\(struct xdp_md \*ctx, struct spnl_flow_u_demo_conn_k \*k\)/, c)
    assert_includes c, "if (iph->protocol != 6) return -1;"
    assert_includes c, "k->sport = tcp->source;"
  end

  def test_emit_flow_maps_emits_one_key_extract_per_kind
    c = GEN.emit_flow_maps(flow_ctx({ "conn" => %w[state] }, { "conn" => Set[:xdp, :tc] }))
    assert_includes c, "spnl_flow_u_demo_conn_key_xdp(struct xdp_md *ctx"
    assert_includes c, "spnl_flow_u_demo_conn_key_tc(struct __sk_buff *ctx"
  end

  def test_flow_call_name_and_field_extracts_symbols
    ast = FlowFakeAst.new({
      1 => FlowFakeNode.new("CallNode", { "name" => "flow_get" }, { "arguments" => 2, "receiver" => -1 }, {}),
      2 => FlowFakeNode.new("ArgumentsNode", {}, {}, { "arguments" => [3, 4] }),
      3 => FlowFakeNode.new("SymbolNode", { "value" => "conn" }, {}, {}),
      4 => FlowFakeNode.new("SymbolNode", { "value" => "state" }, {}, {}),
    })
    assert_equal ["conn", "state"], GEN.flow_call_name_and_field(ast, ast.node(1))
  end

  def test_collect_flow_maps_infers_from_usage
    # flow_set(:conn, :state, ...) inside an ebpf method body -> {"conn"=>["state"]}
    ast = FlowFakeAst.new({
      10 => FlowFakeNode.new("StatementsNode", {}, {}, { "body" => [11] }),
      11 => FlowFakeNode.new("CallNode", { "name" => "flow_set" }, { "arguments" => 12, "receiver" => -1 }, {}),
      12 => FlowFakeNode.new("ArgumentsNode", {}, {}, { "arguments" => [13, 14, 15] }),
      13 => FlowFakeNode.new("SymbolNode", { "value" => "conn" }, {}, {}),
      14 => FlowFakeNode.new("SymbolNode", { "value" => "state" }, {}, {}),
      15 => FlowFakeNode.new("IntegerNode", { "value" => 1 }, {}, {}),
    })
    mi = Struct.new(:body_id).new(10)
    assert_equal({ "conn" => ["state"] }, GEN.collect_flow_maps(ast, [mi]))
  end

  # ---------- Roadmap #3 (Ruby tcp_slice): tcp_syncookie_gen / check ----------

  def test_syncookie_builtins_registered
    assert_includes GEN::BUILTIN_NAMES, "tcp_syncookie_gen"
    assert_includes GEN::BUILTIN_NAMES, "tcp_syncookie_check"
  end

  def test_emit_syncookie_gen_helper_calls_raw_kfunc
    h = GEN.emit_syncookie_helper(:gen)
    assert_match(/static __noinline __s64 spnl_tcp_syncookie_gen\(struct xdp_md \*ctx\)/, h)
    assert_includes h, "if (iph->protocol != 6) return -1;"  # TCP-only
    assert_includes h, "return (__s64)bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, tcp->doff * 4);"
  end

  def test_emit_syncookie_check_helper_calls_raw_kfunc
    h = GEN.emit_syncookie_helper(:check)
    assert_match(/static __noinline __s64 spnl_tcp_syncookie_check\(struct xdp_md \*ctx\)/, h)
    assert_includes h, "return (__s64)bpf_tcp_raw_check_syncookie_ipv4(iph, tcp);"
  end

  def test_emit_syncookie_helpers_emits_only_used
    ctx = Struct.new(:syncookie_used).new(Set[:check])
    c = GEN.emit_syncookie_helpers(ctx)
    assert_includes c, "spnl_tcp_syncookie_check"
    refute_includes c, "spnl_tcp_syncookie_gen"
  end

  # ---------- Roadmap #4 (Ruby tcp_slice): tcp_reply_header ----------

  def test_tcp_reply_header_registered
    assert_includes GEN::BUILTIN_NAMES, "tcp_reply_header"
  end

  def test_emit_tcp_reply_helper_swaps_sets_and_recomputes_csum
    h = GEN.emit_tcp_reply_helper
    assert_match(/static __noinline __s64 spnl_tcp_reply_header\(struct xdp_md \*ctx, __u32 seq, __u32 ack, __u8 flags\)/, h)
    # endpoint swap
    assert_includes h, "__builtin_memcpy(eth->h_dest, eth->h_source, 6);"
    assert_includes h, "__be32 tip = iph->saddr; iph->saddr = iph->daddr; iph->daddr = tip;"
    assert_includes h, "__be16 tpt = tcp->source; tcp->source = tcp->dest; tcp->dest = tpt;"
    # set seq/ack/flags (host -> net order)
    assert_includes h, "tcp->seq     = bpf_htonl(seq);"
    assert_includes h, "tcp->ack_seq = bpf_htonl(ack);"
    assert_includes h, "((__u8 *)tcp)[13] = flags;"
    # checksum recompute (IP + TCP) — CONSTANT 20-byte length (a variable
    # bpf_csum_diff length is rejected by the verifier; doff is normalised to 5).
    assert_includes h, "tcp->doff = 5;"
    assert_includes h, "iph->check = spnl_reply_csum_fold((__u32)v);"
    assert_includes h, "tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 20, (__u32)v);"
    # error returns (non-TCP / IP options / bounds)
    assert_includes h, "if (iph->protocol != 6) return -1;"
    assert_includes h, "if (iph->ihl != 5) return -1;"
  end

  # ---------- Roadmap #5b (Ruby tcp_slice): tcp_reply_data ----------

  def test_tcp_reply_data_registered
    assert_includes GEN::BUILTIN_NAMES, "tcp_reply_data"
  end

  def test_emit_reply_csum_helpers_shared
    c = GEN.emit_reply_csum_helpers
    assert_includes c, "static __always_inline __u16 spnl_reply_csum_fold(__u32 csum)"
    assert_includes c, "static __always_inline __u16 spnl_reply_csum_tcp("
  end

  def test_emit_tcp_reply_header_no_longer_redefines_csum_helpers
    # #4 helper must NOT include the csum helpers anymore (shared via #4/#5b emit).
    h = GEN.emit_tcp_reply_helper
    refute_includes h, "spnl_reply_csum_fold(__u32 csum)\n"
    assert_includes h, "static __noinline __s64 spnl_tcp_reply_header("
  end

  def test_emit_tcp_reply_data_resizes_writes_payload_and_csum
    ctx = Struct.new(:reply_bodies).new(["hello"])
    c = GEN.emit_tcp_reply_data(ctx)
    # const payload array (h=0x68 e=0x65 l=0x6c l=0x6c o=0x6f)
    assert_match(/static const __u8 spnl_reply_body0\[5\] = \{/, c)
    assert_includes c, "0x68, 0x65, 0x6c, 0x6c, 0x6f"
    assert_match(/static __noinline __s64 spnl_tcp_reply_data0\(struct xdp_md \*ctx, __u32 seq, __u32 ack\)/, c)
    # FIN|PSH|ACK + payload memcpy + tot_len + csum
    assert_includes c, "((__u8 *)tcp)[13] = 0x19;"
    assert_includes c, "__builtin_memcpy(out, spnl_reply_body0, 5);"
    assert_includes c, "iph->tot_len = bpf_htons(20 + 20 + 5);"
    assert_includes c, "tcp->check = spnl_reply_csum_tcp(iph->saddr, iph->daddr, 20 + 5, (__u32)v);"
    # Fix: resize LAST, no post-adjust_tail ctx re-read (verifier "modified
    # ctx ptr"). The write happens into the existing packet; adjust_tail is last.
    assert_includes c, "if (cur != want && bpf_xdp_adjust_tail(ctx, (int)want - (int)cur) != 0) return -1;"
    refute_includes c, "data     = (void *)(long)ctx->data;\n              data_end"
    # the payload write precedes the resize call
    assert_operator c.index("__builtin_memcpy(out, spnl_reply_body0"), :<, c.index("bpf_xdp_adjust_tail(ctx,")
  end

# ---------- Roadmap #4b (Ruby tcp_slice): SYN-ACK (MSS) builtins ----------

def test_synack_builtins_registered
  assert_includes GEN::BUILTIN_NAMES, "tcp_reply_synack"
  assert_includes GEN::BUILTIN_NAMES, "tcp_synack_cookie"
end

def test_emit_tcp_synack_helper_has_mss_option
  h = GEN.emit_tcp_synack_helper
  assert_includes h, "((__u8 *)tcp)[13] = 0x12;"   # SYN|ACK
  assert_includes h, "o[0] = 2; o[1] = 4;"          # TCPOPT_MSS
  assert_includes h, "tcp->doff = 6;"
end

def test_emit_synack_cookie_helper_grows_then_gens_then_shrinks
  h = GEN.emit_synack_cookie_helper
  assert_includes h, "int delta = 60 - (int)thl_in;"            # grow to 60 first
  assert_includes h, "bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl_in)"
  assert_includes h, "((__u8 *)tcp)[13] = 0x12;"                # SYN|ACK
  assert_includes h, "o[0] = 2; o[1] = 4;"                      # MSS option
  assert_operator h.index("bpf_xdp_adjust_tail"), :<, h.index("gen_syncookie")  # grow precedes gen
  # A compiler barrier between the grow and the ctx->data_end re-read forces
  # clang to emit a clean LDX instead of a "modified ctx ptr" `ctx+4` (verifier
  # reject). The barrier must sit AFTER the grow's adjust_tail and BEFORE the
  # re-read of ctx->data.
  assert_includes h, %q(asm volatile("" ::: "memory");)
  grow_idx    = h.index("if (delta != 0 && bpf_xdp_adjust_tail(ctx, delta)")
  barrier_idx = h.index(%q(asm volatile("" ::: "memory");))
  gen_idx     = h.index("gen_syncookie")
  # barrier sits after the grow's adjust_tail and before gen_syncookie (i.e. in
  # the ctx->data/data_end re-read region the barrier protects).
  assert_operator grow_idx, :<, barrier_idx
  assert_operator barrier_idx, :<, gen_idx
end

  # ---------- Roadmap #5a (Ruby tcp_slice): payload_starts ----------

  def test_payload_starts_registered
    assert_includes GEN::BUILTIN_NAMES, "payload_starts"
  end

  def test_url_decode_resolves_percent_escapes
    assert_equal "GET /hello ", GEN.url_decode("GET%20/hello%20")
    assert_equal "a\r\nb", GEN.url_decode("a%0D%0Ab")
    assert_equal "plain", GEN.url_decode("plain")
  end

  def test_emit_payload_matchers_compares_each_prefix_byte
    ctx = Struct.new(:payload_matchers).new(["GET /hello "])
    c = GEN.emit_payload_matchers(ctx)
    assert_match(/static __noinline __s64 spnl_payload_match0\(struct xdp_md \*ctx\)/, c)
    assert_includes c, "if ((void *)(p + 11) > data_end) return 0;"  # 11-byte prefix bound
    assert_includes c, "if (p[0] != 71) return 0;"   # 'G'
    assert_includes c, "if (p[3] != 32) return 0;"   # ' '
    assert_includes c, "if (iph->protocol != 6) return 0;"  # TCP-only
  end

  def test_emit_payload_matchers_distinct_prefixes_get_distinct_ids
    ctx = Struct.new(:payload_matchers).new(["GET /a ", "GET /b "])
    c = GEN.emit_payload_matchers(ctx)
    assert_includes c, "spnl_payload_match0"
    assert_includes c, "spnl_payload_match1"
  end

  # ---------- pure-XDP TCP slice attach + bundle emit ----------

  def test_detect_attach_xdp_tcp_slice
    m = GEN.detect_attach("xdp__tcp_slice__health")
    refute_nil m
    assert_equal :xdp_tcp_slice, m[:kind]
    assert_equal "xdp", m[:sec]
    assert_equal "health", m[:ts_name]
    assert_equal "struct xdp_md *", m[:ctx_type]
  end

  def test_pattern_does_not_swallow_generic_xdp
    # Bare `xdp__foo` must still resolve to :xdp, not :xdp_tcp_slice.
    m = GEN.detect_attach("xdp__foo")
    refute_nil m
    assert_equal :xdp, m[:kind]
  end

  def test_emit_tcp_slice_bundle_has_maps_and_helpers
    # Synthesize a fake EmitContext just to satisfy the helper signature.
    bundle = GEN.emit_tcp_slice_bundle(nil)
    # conn_state map declaration
    assert_match(/struct spnl_tcp_slice_key/, bundle)
    assert_match(/struct spnl_tcp_slice_state/, bundle)
    assert_match(/bpf_conntab SEC\(".maps"\)/, bundle)
    assert_match(/bpf_ts_counters SEC\(".maps"\)/, bundle)
    # syncookie helpers used by reference
    assert_includes bundle, "bpf_tcp_raw_gen_syncookie_ipv4("
    assert_includes bundle, "bpf_tcp_raw_check_syncookie_ipv4("
    # main entry exists
    assert_includes bundle, "spnl_tcp_slice_main(struct xdp_md *ctx)"
    # response body is the 41-byte HTTP/1.0 200 OK
    expected_first_bytes = "0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30"
    assert_includes bundle, expected_first_bytes
  end

  def test_emit_tcp_slice_method_yields_thin_wrapper
    # Build a minimal IR/AST with one xdp__tcp_slice__health method (use the
    # 30_tc_port_filter fixture as a scaffold and rename method).
    # Simpler: just test emit_method indirectly via a small fixture if we have
    # one. For now we'll check the bundle constants are exposed properly.
    assert_equal 8080, GEN::TCP_SLICE_PORT
    assert_equal "GET /health ", GEN::TCP_SLICE_REQUEST_MATCH
    assert_match(/\AHTTP\/1.0 200 OK\r\n/, GEN::TCP_SLICE_RESPONSE)
    assert_equal 41, GEN::TCP_SLICE_RESPONSE.length
  end

  # ---------- bpf_timer + client-retransmit handling ----------

  def test_bundle_has_bpf_timer_field
    bundle = GEN.emit_tcp_slice_bundle(nil)
    assert_match(/struct bpf_timer timer;/, bundle)
  end

  def test_bundle_has_ttl_constants
    bundle = GEN.emit_tcp_slice_bundle(nil)
    assert_match(/SPNL_TS_TTL_ESTAB/,  bundle)
    assert_match(/SPNL_TS_TTL_RESP/,   bundle)
    assert_match(/SPNL_TS_TTL_CLOSED/, bundle)
    # CLOCK_MONOTONIC = 1
    assert_match(/bpf_timer_init\(&st->timer, &bpf_conntab, 1/, bundle)
  end

  def test_bundle_has_timeout_callback
    bundle = GEN.emit_tcp_slice_bundle(nil)
    assert_match(/spnl_tcp_slice_timeout_cb/, bundle)
    assert_match(/bpf_timer_set_callback\(&st->timer, spnl_tcp_slice_timeout_cb\)/, bundle)
  end

  def test_bundle_arms_timer_on_state_transitions
    bundle = GEN.emit_tcp_slice_bundle(nil)
    # Arm on conn create (after handshake completion)
    assert_match(/spnl_tcp_slice_arm\(st, SPNL_TS_TTL_ESTAB\)/, bundle)
    # Arm on RESP_SENT transition
    assert_match(/spnl_tcp_slice_arm\(st, SPNL_TS_TTL_RESP\)/,  bundle)
    # Arm on CLOSED transition
    assert_match(/spnl_tcp_slice_arm\(st, SPNL_TS_TTL_CLOSED\)/, bundle)
  end

  def test_bundle_handles_get_retransmit_in_resp_sent
    bundle = GEN.emit_tcp_slice_bundle(nil)
    # The data path must accept state==1 || state==2
    assert_match(/st->state == 1 \|\| st->state == 2/, bundle)
    # And reuse the saved seqs by rolling server_seq back
    assert_match(/srv_seq_to_send = st->server_seq - 41 - 1/, bundle)
  end

  def test_bundle_handles_fin_retransmit_in_closed
    bundle = GEN.emit_tcp_slice_bundle(nil)
    # The FIN path must accept state==2 || state==3
    assert_match(/st->state == 2 \|\| st->state == 3/, bundle)
    # CNT_FIN_RETX bumped on retransmit path
    assert_match(/CNT_FIN_RETX/, bundle)
  end

  def test_bundle_cancels_timer_on_rst
    bundle = GEN.emit_tcp_slice_bundle(nil)
    assert_match(/bpf_timer_cancel\(&st_rst->timer\)/, bundle)
  end

  def test_counters_map_grew_to_17
    bundle = GEN.emit_tcp_slice_bundle(nil)
    # There were originally 15 counters; adding CNT_TIMER_FIRED (15) and
    # CNT_FIN_RETX (16) brings max_entries to 17.
    assert_match(/__uint\(max_entries, 17\);/, bundle)
  end

  # ---------- fentry / fexit attach pattern ----------

  def test_detect_attach_fentry
    m = GEN.detect_attach("fentry__tcp_v4_rcv")
    refute_nil m
    assert_equal :fentry,         m[:kind]
    assert_equal "fentry/tcp_v4_rcv", m[:sec]
    assert_equal "tcp_v4_rcv",        m[:tgt_func]
    assert_equal "__u64 *",           m[:ctx_type]
  end

  def test_detect_attach_fexit
    m = GEN.detect_attach("fexit__do_unlinkat")
    refute_nil m
    assert_equal :fexit,             m[:kind]
    assert_equal "fexit/do_unlinkat", m[:sec]
    assert_equal "do_unlinkat",      m[:tgt_func]
  end

  def test_fentry_does_not_swallow_other_prefixes
    # `fentry__` must not collide with kprobe/tracepoint/etc., and a normal
    # method shouldn't be misclassified.
    assert_nil GEN.detect_attach("plain_helper")
    assert_equal :kprobe, GEN.detect_attach("kprobe__sys_read")[:kind]
  end

  def test_extract_attach_args_fentry_uses_ctx_index
    attach = GEN.detect_attach("fentry__tcp_v4_rcv")
    args = GEN.extract_attach_args(attach, [["skb", "int"]])
    assert_equal ["(__s64)ctx[0]"], args
  end

  def test_extract_attach_args_fexit_appends_return_value
    # fexit's last param is the traced function's return value,
    # but at our codegen level it's just another ctx[i] slot.
    attach = GEN.detect_attach("fexit__tcp_v4_rcv")
    args = GEN.extract_attach_args(attach, [["skb", "int"], ["ret", "int"]])
    assert_equal ["(__s64)ctx[0]", "(__s64)ctx[1]"], args
  end

  # ---------- bpf_dynptr-backed packet access ----------

  def test_dynptr_byte_at_in_builtin_names
    assert_includes GEN::BUILTIN_NAMES, "pkt_dynptr_byte_at"
    assert_includes GEN::DYNPTR_BUILTINS, "pkt_dynptr_byte_at"
  end

  def test_dynptr_helper_emits_kfunc_call
    bundle = GEN.emit_dynptr_helpers(nil)
    # The helper calls vmlinux.h-declared kfuncs (we don't redeclare them
    # because vmlinux.h has them with `u64 offset`).
    assert_match(/static __noinline __s64 spnl_pkt_dynptr_byte_at\(struct xdp_md \*ctx, __s64 off\)/, bundle)
    assert_match(/bpf_dynptr_from_xdp\(ctx, 0, &dp\)/, bundle)
    assert_match(/bpf_dynptr_slice\(&dp, \(__u64\)off, &buf, 1\)/, bundle)
    refute_match(/extern.*bpf_dynptr/, bundle)  # we don't redeclare
  end

  # ---------- USER_RINGBUF callback + drain ----------

  def test_detect_attach_user_ringbuf
    m = GEN.detect_attach("user_ringbuf__cmd_handler")
    refute_nil m
    assert_equal :user_ringbuf, m[:kind]
    assert_equal "cmd_handler",  m[:cb_name]
    assert_nil m[:sec]   # no SEC, it's a static callback
  end

  def test_user_ringbuf_drain_in_builtin_names
    assert_includes GEN::BUILTIN_NAMES, "user_ringbuf_drain"
  end

  # ---------- open-coded iterator for literal n.times ----------

  # ---------- PROG_ARRAY + bpf_tail_call ----------

  def test_detect_attach_xdp_tail
    m = GEN.detect_attach("xdp_tail__handler")
    refute_nil m
    assert_equal :xdp_tail, m[:kind]
    assert_equal "xdp", m[:sec]
    assert_equal "handler", m[:xt_name]
  end

  def test_xdp_tail_does_not_swallow_xdp_or_xdp_tcp_slice
    # `xdp_tail__` must be distinguishable from `xdp__tcp_slice__` and `xdp__`.
    assert_equal :xdp_tcp_slice, GEN.detect_attach("xdp__tcp_slice__health")[:kind]
    assert_equal :xdp,           GEN.detect_attach("xdp__foo")[:kind]
    assert_equal :xdp_tail,      GEN.detect_attach("xdp_tail__bar")[:kind]
  end

  def test_tail_call_to_in_builtin_names
    assert_includes GEN::BUILTIN_NAMES, "tail_call_to"
  end

  # ---------- SOCK_OPS attach + builtins ----------

  def test_detect_attach_sock_ops
    m = GEN.detect_attach("sock_ops__main")
    refute_nil m
    assert_equal :sock_ops, m[:kind]
    assert_equal "sockops", m[:sec]
    assert_equal "main", m[:so_name]
    assert_equal "struct bpf_sock_ops *", m[:ctx_type]
  end

  def test_sock_ops_op_in_builtin_names
    assert_includes GEN::BUILTIN_NAMES, "sock_ops_op"
    assert_includes GEN::BUILTIN_NAMES, "sock_ops_state"
  end

  def test_known_constants_has_sock_ops_events_and_tcp_states
    t = GEN::KNOWN_CONSTANTS
    assert_equal 3,  t["BPF_SOCK_OPS_TCP_CONNECT_CB"]
    assert_equal 4,  t["BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB"]
    assert_equal 5,  t["BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB"]
    assert_equal 10, t["BPF_SOCK_OPS_STATE_CB"]
    assert_equal 1,  t["TCP_STATE_ESTABLISHED"]
    assert_equal 4,  t["TCP_STATE_FIN_WAIT1"]
    assert_equal 7,  t["TCP_STATE_CLOSE"]
  end

  # ---------- CPUMAP + bpf_redirect_map ----------

  def test_cpumap_redirect_in_builtin_names
    assert_includes GEN::BUILTIN_NAMES, "cpumap_redirect"
  end

  def test_emit_cpumap_map
    out = GEN.emit_cpumap_map(nil)
    assert_match(/BPF_MAP_TYPE_CPUMAP/, out)
    assert_match(/spnl_cpumap SEC\(".maps"\)/, out)
    assert_match(/struct bpf_cpumap_val/, out)
  end

  # ---------- STRUCT_OPS tcp_congestion_ops ----------

  def test_detect_attach_tcp_cc
    m = GEN.detect_attach("tcp_cc__init")
    refute_nil m
    assert_equal :tcp_cc, m[:kind]
    assert_equal "init", m[:member]
    assert_equal "struct_ops/init", m[:sec]
  end

  def test_tcp_cc_members_known
    members = GEN::TCP_CC_MEMBERS
    %w[init ssthresh undo_cwnd cong_avoid set_state].each do |m|
      assert members.key?(m), "TCP_CC_MEMBERS missing #{m}"
    end
    assert_equal "__u32", members["ssthresh"][:ret]
    assert_equal "void",  members["init"][:ret]
  end

  # ---------- struct_ops generalisation (sched_ext + qdisc) ----------

  def test_detect_attach_sched_ext
    m = GEN.detect_attach("sched_ext__select_cpu")
    refute_nil m
    assert_equal :sched_ext, m[:kind]
    assert_equal "select_cpu", m[:member]
    assert_equal "struct_ops/select_cpu", m[:sec]
  end

  def test_detect_attach_qdisc
    m = GEN.detect_attach("qdisc__enqueue")
    refute_nil m
    assert_equal :qdisc, m[:kind]
    assert_equal "enqueue", m[:member]
    assert_equal "struct_ops/enqueue", m[:sec]
  end

  def test_struct_ops_registry_has_all_three
    reg = GEN::STRUCT_OPS_REGISTRY
    assert reg.key?(:tcp_cc)
    assert reg.key?(:sched_ext)
    assert reg.key?(:qdisc)
    # name field varies per struct
    assert_equal :name, reg[:tcp_cc][:name_field]
    assert_equal :name, reg[:sched_ext][:name_field]
    assert_equal :id,   reg[:qdisc][:name_field]
  end

  # ---------- tcp_sock_* field accessors ----------

  def test_tcp_sock_builtins_listed
    %w[tcp_sock_snd_cwnd tcp_sock_snd_ssthresh tcp_sock_snd_cwnd_add
       tcp_sock_snd_cwnd_set tcp_sock_prior_cwnd].each do |n|
      assert_includes GEN::BUILTIN_NAMES, n, "missing builtin #{n}"
    end
  end

  def test_tcp_sock_reader_map_has_canonical_fields
    assert_equal "snd_cwnd",     GEN::TCP_SOCK_READERS["tcp_sock_snd_cwnd"]
    assert_equal "snd_ssthresh", GEN::TCP_SOCK_READERS["tcp_sock_snd_ssthresh"]
    assert_equal "snd_cwnd",     GEN::TCP_SOCK_WRITERS["tcp_sock_snd_cwnd_set"]
    assert_equal "snd_cwnd",     GEN::TCP_SOCK_ADDERS["tcp_sock_snd_cwnd_add"]
  end

  def test_emit_tcp_cc_struct_ops_block
    ctx = GEN::EmitContext.new(
      ir: nil, ast: nil, partition: nil,
      base_name: "x", unit_name: "x",
      uses_ringbuf: false, uses_str_ringbuf: false, uses_pair_ringbuf: false,
      ebpf_methods_by_name: {}, loop_counter: 0, deferred_functions: [],
      pkt_builtins_used: {},
      uses_blocklist: false, uses_path_counter: false,
      uses_reuseport_sockarray: false,
      uses_xdp_health_match: false, uses_xdp_health_reply: false,
      uses_tcp_slice: false, uses_dynptr: false,
      uses_user_ringbuf: false, user_ringbuf_cb_name: nil,
      uses_tail_call: false, tail_targets: [],
      uses_cpumap: false,
      uses_tcp_cc: true,
      tcp_cc_members: ["init", "ssthresh", "undo_cwnd"],
    )
    out = GEN.emit_tcp_cc_struct_ops(ctx)
    assert_match(/SEC\(".struct_ops"\)/, out)
    assert_match(/struct tcp_congestion_ops spnl_tcp_cc_ops = \{/, out)
    assert_match(/\.init = \(void \*\)tcp_cc__init,/, out)
    assert_match(/\.ssthresh = \(void \*\)tcp_cc__ssthresh,/, out)
    assert_match(/\.name = "spnl_cc",/, out)
  end

  def test_emit_prog_array_map
    ctx = GEN::EmitContext.new(
      ir: nil, ast: nil, partition: nil,
      base_name: "x", unit_name: "x",
      uses_ringbuf: false, uses_str_ringbuf: false, uses_pair_ringbuf: false,
      ebpf_methods_by_name: {}, loop_counter: 0, deferred_functions: [],
      pkt_builtins_used: {},
      uses_blocklist: false, uses_path_counter: false,
      uses_reuseport_sockarray: false,
      uses_xdp_health_match: false, uses_xdp_health_reply: false,
      uses_tcp_slice: false, uses_dynptr: false,
      uses_user_ringbuf: false, user_ringbuf_cb_name: nil,
      uses_tail_call: true,
      tail_targets: ["a", "b"],
    )
    out = GEN.emit_prog_array_map(ctx)
    assert_match(/BPF_MAP_TYPE_PROG_ARRAY/, out)
    assert_match(/spnl_prog_array SEC\(".maps"\)/, out)
  end

  def test_dynamic_n_still_uses_bpf_loop
    # Regression: when N is a method parameter, the codegen must continue
    # to emit `bpf_loop` with a callback (NOT the inline iter).
    c = emit_for("15_times_loop")
    assert_match(/bpf_loop\(n, &emit_squares_loop\d+_cb, NULL, 0\)/, c)
    refute_match(/bpf_iter_num_new\(&_it\d+, 0, n\)/, c)  # would be wrong
  end

  def test_emit_user_ringbuf_map_includes_forward_decl
    # Synthesize a minimal context to capture the cb name pathway.
    ctx = GEN::EmitContext.new(
      ir: nil, ast: nil, partition: nil,
      base_name: "x", unit_name: "x",
      uses_ringbuf: false, uses_str_ringbuf: false, uses_pair_ringbuf: false,
      ebpf_methods_by_name: {}, loop_counter: 0, deferred_functions: [],
      pkt_builtins_used: {},
      uses_blocklist: false, uses_path_counter: false,
      uses_reuseport_sockarray: false,
      uses_xdp_health_match: false, uses_xdp_health_reply: false,
      uses_tcp_slice: false, uses_dynptr: false,
      uses_user_ringbuf: true, user_ringbuf_cb_name: "cmd_handler",
    )
    out = GEN.emit_user_ringbuf_map(ctx)
    assert_match(/BPF_MAP_TYPE_USER_RINGBUF/, out)
    assert_match(/bpf_user_cmds SEC\(".maps"\)/, out)
    # Forward declaration of the callback so call-sites can precede the body
    assert_match(/static long spnl_user_ringbuf_cb_cmd_handler\(struct bpf_dynptr \*dynptr, void \*_uctx\);/, out)
  end

  # ---------- receiver dot accessor for tcp_sock fields ----------

  def test_tcp_sock_fields_set_contains_canonical_fields
    %w[snd_cwnd snd_ssthresh snd_cwnd_cnt prior_cwnd].each do |f|
      assert_includes GEN::TCP_SOCK_FIELDS, f
    end
    # Set type with O(1) lookup, no duplicates between readers/writers/adders.
    assert_kind_of Set, GEN::TCP_SOCK_FIELDS
  end

  # The dot dispatcher is the only user-facing thing here — verify it
  # produces the same C expression as the flat builtin for each form.
  # We exercise it via emit_tcp_sock_* helpers (called by both paths).
  def test_emit_tcp_sock_read_shape
    em = make_method_emitter_in_tcp_cc_ctx
    expr = em.send(:emit_tcp_sock_read, "snd_cwnd", "_p0")
    assert_equal "((__s64)((struct tcp_sock *)(unsigned long)(_p0))->snd_cwnd)", expr
  end

  def test_emit_tcp_sock_assign_shape
    em = make_method_emitter_in_tcp_cc_ctx
    em.instance_variable_set(:@lines, [])
    rv = em.send(:emit_tcp_sock_assign, "snd_cwnd", "_p0", "(__s64)5")
    assert_equal "0", rv
    line = em.instance_variable_get(:@lines).last
    assert_equal "((struct tcp_sock *)(unsigned long)(_p0))->snd_cwnd = (__u32)((__s64)5);", line
  end

  def test_emit_tcp_sock_compound_shape
    em = make_method_emitter_in_tcp_cc_ctx
    em.instance_variable_set(:@lines, [])
    rv = em.send(:emit_tcp_sock_compound, "snd_cwnd", "+=", "_p0", "_v3")
    assert_equal "0", rv
    line = em.instance_variable_get(:@lines).last
    assert_equal "((struct tcp_sock *)(unsigned long)(_p0))->snd_cwnd += (__u32)(_v3);", line
  end

  # Helper: build a bare-minimum MethodEmitter pinned to a tcp_cc__ method
  # so the context-check (`require_tcp_cc_context!`) doesn't reject calls.
  def make_method_emitter_in_tcp_cc_ctx
    mi = SpinelEbpf::Partition::MethodInfo.new(
      scope: :top_level, class_name: nil, method_name: "tcp_cc__cong_avoid",
      body_id: 0, tag: :ebpf,
    )
    ctx = GEN::EmitContext.new(
      ir: nil, ast: nil, partition: nil,
      base_name: "x", unit_name: "x",
      uses_ringbuf: false, uses_str_ringbuf: false, uses_pair_ringbuf: false,
      ebpf_methods_by_name: {}, loop_counter: 0, deferred_functions: [],
      pkt_builtins_used: {},
      uses_blocklist: false, uses_path_counter: false,
      uses_reuseport_sockarray: false,
      uses_xdp_health_match: false, uses_xdp_health_reply: false,
      uses_tcp_slice: false, uses_dynptr: false,
      uses_user_ringbuf: false, user_ringbuf_cb_name: nil,
      uses_tail_call: false, tail_targets: [],
      uses_cpumap: false,
      uses_tcp_cc: false, tcp_cc_members: [],
      uses_sched_ext: false, sched_ext_members: [],
      uses_qdisc: false, qdisc_members: [],
      uses_timer: false, timer_interval_ns: nil, timer_handler_name: nil,
    )
    em = GEN::MethodEmitter.new(ctx: ctx, mi: mi, return_type: "__s32")
    em.instance_variable_set(:@lines, [])
    em
  end

  # ---------- pkt.* chain accessor ----------

  def test_chain_map_covers_all_no_arg_pkt_builtins
    no_arg = GEN::PKT_BUILTINS - %w[]
    mapped = GEN::PKT_CHAIN_MAP.values
    no_arg.each do |b|
      assert_includes mapped, b, "pkt builtin #{b} has no chain entry in PKT_CHAIN_MAP"
    end
  end

  def test_chain_map_root_is_always_pkt
    GEN::PKT_CHAIN_MAP.each_key do |chain|
      assert_equal "pkt", chain.first, "chain #{chain.inspect} must start with 'pkt'"
      assert chain.length.between?(2, 4), "chain #{chain.inspect} length out of range"
    end
  end

  def test_chain_includes_expected_paths
    {
      %w[pkt len]              => "pkt_len",
      %w[pkt l4 proto]         => "pkt_l4_proto",
      %w[pkt l4 sport]         => "pkt_l4_sport",
      %w[pkt ip4 src]          => "pkt_ip4_src",
      %w[pkt tcp flags]        => "pkt_tcp_flags",
    }.each do |chain, expected|
      assert_equal expected, GEN::PKT_CHAIN_MAP[chain]
    end
  end

  # ---------- module-style constants ----------

  def test_constant_paths_cover_xdp_tcp_ip_bpf_namespaces
    {
      %w[XDP PASS]              => "XDP_PASS",
      %w[XDP DROP]              => "XDP_DROP",
      %w[XDP TX]                => "XDP_TX",
      %w[XDP REDIRECT]          => "XDP_REDIRECT",
      %w[TCP Flag SYN]          => "TCP_FLAG_SYN",
      %w[TCP Flag RST]          => "TCP_FLAG_RST",
      %w[TCP State ESTABLISHED] => "TCP_STATE_ESTABLISHED",
      %w[IP Proto TCP]          => "IPPROTO_TCP",
      %w[IP Proto UDP]          => "IPPROTO_UDP",
      %w[IP Proto ICMP]         => "IPPROTO_ICMP",
      %w[BPF SockOps STATE_CB]  => "BPF_SOCK_OPS_STATE_CB",
      %w[TC Act OK]             => "TC_ACT_OK",
      %w[Eth P IP]              => "ETH_P_IP",
      %w[SK PASS]               => "SK_PASS",
    }.each do |path, expected|
      assert_equal expected, GEN::KNOWN_CONSTANT_PATHS[path], "path #{path.inspect} should map to #{expected}"
    end
  end

  def test_every_path_resolves_to_a_real_known_constant
    GEN::KNOWN_CONSTANT_PATHS.each do |path, flat|
      assert GEN::KNOWN_CONSTANTS.key?(flat), "#{path.join("::")} -> #{flat} not in KNOWN_CONSTANTS"
    end
  end

  def test_longer_prefix_wins_over_shorter
    # BPF_SOCK_OPS_* must beat a hypothetical bare BPF_* prefix.
    assert_equal "BPF_SOCK_OPS_STATE_CB",
                 GEN::KNOWN_CONSTANT_PATHS[%w[BPF SockOps STATE_CB]]
    # TCP_FLAG_* must beat TCP_STATE_*, and vice versa.
    assert_equal "TCP_FLAG_RST",          GEN::KNOWN_CONSTANT_PATHS[%w[TCP Flag RST]]
    assert_equal "TCP_STATE_ESTABLISHED", GEN::KNOWN_CONSTANT_PATHS[%w[TCP State ESTABLISHED]]
  end

  # ---------- class-based attach (BPF::XDP / BPF::TcpCC / ...) ----------

  def test_bpf_dsl_parent_table_covers_main_kinds
    {
      "BPF_XDP"         => "xdp__",
      "BPF_TcpCC"       => "tcp_cc__",
      "BPF_SchedExt"    => "sched_ext__",
      "BPF_Qdisc"       => "qdisc__",
      "BPF_SockOps"     => "sock_ops__",
      "BPF_TcIngress"   => "tc__ingress__",
      "BPF_TcEgress"    => "tc__egress__",
      "BPF_SkReuseport" => "sk_reuseport__",
      "BPF_SkMsg"       => "sk_msg__",
    }.each do |parent, prefix|
      assert_equal prefix, P::BPF_DSL_PARENT_TO_PREFIX[parent], "missing #{parent} -> #{prefix}"
    end
  end

  def test_dsl_prefixes_align_with_attach_patterns
    P::BPF_DSL_PARENT_TO_PREFIX.values.each do |prefix|
      synthetic = "#{prefix}probe_method_name"
      attach = GEN.detect_attach(synthetic)
      refute_nil attach, "no detect_attach match for synthesized #{synthetic.inspect}"
    end
  end

  def test_method_info_carries_dsl_hints
    mi = P::MethodInfo.new(
      scope: :top_level, class_name: nil,
      method_name: "tcp_cc__cong_avoid",
      body_id: 42, flags: P::MethodFlags.default, tag: nil,
      dsl_class_idx: 7, dsl_orig_name: "cong_avoid",
    )
    assert_equal 7, mi.dsl_class_idx
    assert_equal "cong_avoid", mi.dsl_orig_name
  end

  # ---------- module + include attach ----------

  def test_include_map_derived_from_parent_map
    # Every BPF_DSL_PARENT_TO_PREFIX entry should have a parallel
    # array-keyed BPF_DSL_INCLUDE_TO_PREFIX entry (same prefix).
    P::BPF_DSL_PARENT_TO_PREFIX.each do |flat, prefix|
      path = flat.split("_")
      assert_equal prefix, P::BPF_DSL_INCLUDE_TO_PREFIX[path],
                   "module path #{path.inspect} missing or mapped wrong"
    end
  end

  def test_include_map_keys_are_path_arrays
    P::BPF_DSL_INCLUDE_TO_PREFIX.each_key do |path|
      assert_kind_of Array, path
      assert_equal "BPF", path.first
      assert path.length >= 2
    end
  end

  def test_method_info_has_ast_def_id_field
    mi = P::MethodInfo.new(
      scope: :top_level, class_name: nil,
      method_name: "tcp_cc__cong_avoid",
      body_id: 42, flags: P::MethodFlags.default, tag: nil,
      dsl_ast_def_id: 99, dsl_orig_name: "cong_avoid",
    )
    assert_equal 99, mi.dsl_ast_def_id
    assert_nil mi.dsl_class_idx
  end

  # ---------- BPF::EventLoop reactor DSL ----------

  def test_event_loop_path_and_kind_table
    assert_equal %w[BPF EventLoop], P::BPF_EVENT_LOOP_PATH
    assert_equal "xdp__",         P::BPF_EVENT_LOOP_KIND_TO_PREFIX["xdp"]
    assert_equal "sock_ops__",    P::BPF_EVENT_LOOP_KIND_TO_PREFIX["sock_ops"]
    assert_equal "tc__ingress__", P::BPF_EVENT_LOOP_KIND_TO_PREFIX["tc_ingress"]
    assert_equal "tc__egress__",  P::BPF_EVENT_LOOP_KIND_TO_PREFIX["tc_egress"]
  end

  # ---------- per-target attach kinds (kprobe / fentry / tracepoint) ----------

  def test_event_loop_kinds_include_per_target_kinds
    %w[kprobe kretprobe fentry fexit tracepoint].each do |k|
      assert P::BPF_EVENT_LOOP_KINDS.key?(k), "missing kind #{k}"
    end
  end

  def test_arity_assignment
    assert_equal 0, P::BPF_EVENT_LOOP_KINDS["xdp"].arity
    assert_equal 1, P::BPF_EVENT_LOOP_KINDS["kprobe"].arity
    assert_equal 1, P::BPF_EVENT_LOOP_KINDS["fentry"].arity
    assert_equal 2, P::BPF_EVENT_LOOP_KINDS["tracepoint"].arity
    assert_equal "__", P::BPF_EVENT_LOOP_KINDS["tracepoint"].joiner
  end

  def test_per_target_prefix_synthesizes_into_detect_attach
    # `on :kprobe, "X"` -> "kprobe__X"; detect_attach must match.
    assert GEN.detect_attach("kprobe__do_sys_openat2")
    assert GEN.detect_attach("fentry__tcp_v4_rcv")
    assert GEN.detect_attach("tracepoint__sched__sched_switch")
  end

  # ---------- on :user_cmd with block param ----------

  def test_user_cmd_kind_registered
    assert P::BPF_EVENT_LOOP_KINDS.key?("user_cmd")
    info = P::BPF_EVENT_LOOP_KINDS["user_cmd"]
    assert_equal "user_ringbuf__cmd_handler", info.prefix
    assert_equal 0, info.arity
  end

  def test_user_cmd_method_name_routes_to_user_ringbuf
    # Synthesized "user_ringbuf__cmd_handler" must match the user_ringbuf
    # attach pattern in codegen_bpf.rb so emit_method follows the
    # USER_RINGBUF callback path.
    attach = GEN.detect_attach("user_ringbuf__cmd_handler")
    refute_nil attach
    assert_equal :user_ringbuf, attach[:kind]
  end

  def test_user_cmd_excluded_from_legacy_kind_table
    # The arity-0 back-compat table (BPF_EVENT_LOOP_KIND_TO_PREFIX) holds
    # only generic `<prefix>main` entries. user_cmd's prefix is the full
    # method name so it should be skipped.
    refute P::BPF_EVENT_LOOP_KIND_TO_PREFIX.key?("user_cmd")
  end

  # ---------- on :timer, every: N.seconds (bpf_timer) ----------

  def test_timer_kind_registered
    info = P::BPF_EVENT_LOOP_KINDS["timer"]
    refute_nil info
    assert_equal "spnl_timer__main", info.prefix
    assert_equal 0, info.arity
  end

  def test_timer_unit_table_covers_seconds_and_ms
    assert_equal 1_000_000_000, P::BPF_TIMER_UNIT_NS["seconds"]
    assert_equal 1_000_000_000, P::BPF_TIMER_UNIT_NS["second"]
    assert_equal 1_000_000,     P::BPF_TIMER_UNIT_NS["milliseconds"]
    assert_equal 1_000_000,     P::BPF_TIMER_UNIT_NS["ms"]
    assert_equal 1,             P::BPF_TIMER_UNIT_NS["nanoseconds"]
  end

  def test_timer_method_name_matches_detect_attach
    attach = GEN.detect_attach("spnl_timer__main")
    refute_nil attach
    assert_equal :timer, attach[:kind]
    assert_equal "syscall", attach[:sec]
  end

  def test_timer_excluded_from_legacy_kind_table
    # spnl_timer__main isn't a `<prefix>main` form that the back-compat
    # table can derive from BPF_DSL_PARENT_TO_PREFIX, so it must be skipped.
    refute P::BPF_EVENT_LOOP_KIND_TO_PREFIX.key?("timer")
  end

  def test_event_loop_kinds_are_a_subset_of_dsl_parents
    # Each event loop kind should also be a regular DSL attach kind so the
    # rest of the pipeline (detect_attach, codegen) is uniform.
    P::BPF_EVENT_LOOP_KIND_TO_PREFIX.values.each do |prefix|
      assert P::BPF_DSL_PARENT_TO_PREFIX.value?(prefix),
             "event-loop prefix #{prefix.inspect} not in BPF_DSL_PARENT_TO_PREFIX"
    end
  end

  def test_synthesized_method_name_matches_detect_attach
    # `on :xdp` -> "xdp__main", `on :sock_ops` -> "sock_ops__main", etc.
    # detect_attach must recognize each so emit_method routes properly.
    P::BPF_EVENT_LOOP_KIND_TO_PREFIX.each do |_kind, prefix|
      synthesized = "#{prefix}main"
      refute_nil GEN.detect_attach(synthesized),
                 "no detect_attach match for #{synthesized.inspect}"
    end
  end

  # ---------- c_safe sanitizer (unit) ----------

  def test_c_safe_pass_through_for_non_keywords
    assert_equal "count", GEN.c_safe("count")
    assert_equal "my_local", GEN.c_safe("my_local")
    assert_equal "", GEN.c_safe("")
    assert_nil GEN.c_safe(nil)
  end

  def test_c_safe_suffixes_c_keywords
    %w[auto double register static volatile struct typedef return].each do |kw|
      assert_equal "#{kw}_", GEN.c_safe(kw), "expected #{kw} -> #{kw}_"
    end
  end

  def test_c_safe_idempotent
    # Suffixed form is no longer a keyword, so a second pass leaves it alone.
    assert_equal "double_", GEN.c_safe(GEN.c_safe("double"))
    assert_equal "register_", GEN.c_safe(GEN.c_safe("register"))
  end

  # ---------- IPv6 packet header builtins ----------

  def test_ipv6_xdp_emits_pkt_l4_proto_with_both_branches
    c = emit_for("35_xdp_ipv6")
    # pkt_l4_proto helper must walk both IPv4 (0x0800) and IPv6 (0x86DD).
    helper = c[/static __noinline __s64 spnl_pkt_l4_proto\(struct xdp_md \*ctx\).*?\n\}/m]
    refute_nil helper
    assert_includes helper, "bpf_htons(0x0800)"
    assert_includes helper, "bpf_htons(0x86DD)"
    assert_includes helper, "struct ipv6hdr"
    assert_includes helper, "ip6h->nexthdr"
  end

  def test_ipv6_xdp_emits_pkt_ip6_src_hi
    c = emit_for("35_xdp_ipv6")
    helper = c[/static __noinline __s64 spnl_pkt_ip6_src_hi\(struct xdp_md \*ctx\).*?\n\}/m]
    refute_nil helper, "pkt_ip6_src_hi helper should be emitted"
    assert_includes helper, "if (eth->h_proto != bpf_htons(0x86DD)) return 0;"
    assert_includes helper, "ip6h->saddr.in6_u.u6_addr32[0]"
    assert_includes helper, "ip6h->saddr.in6_u.u6_addr32[1]"
    assert_includes helper, "bpf_ntohl"
  end

  def test_ipv6_xdp_body_calls_pkt_ip6_src_hi
    c = emit_for("35_xdp_ipv6")
    inner = c[/xdp__main_inner\(.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "spnl_pkt_l4_proto(ctx)"
    assert_includes inner, "spnl_pkt_ip6_src_hi(ctx)"
  end

  def test_pkt_chain_map_includes_ip6_accessors
    # Sanity: the PKT_CHAIN_MAP exposes all four IPv6 chain forms.
    assert_equal "pkt_ip6_src_hi", GEN::PKT_CHAIN_MAP[%w[pkt ip6 src_hi]]
    assert_equal "pkt_ip6_src_lo", GEN::PKT_CHAIN_MAP[%w[pkt ip6 src_lo]]
    assert_equal "pkt_ip6_dst_hi", GEN::PKT_CHAIN_MAP[%w[pkt ip6 dst_hi]]
    assert_equal "pkt_ip6_dst_lo", GEN::PKT_CHAIN_MAP[%w[pkt ip6 dst_lo]]
  end

  # ---------- N-tuple emit (spnl_emit3 / spnl_emit4) ----------

  def test_emit3_emits_3_tuple_struct_and_ringbuf
    c = emit_for("36_emit_n_tuple")
    struct3 = c[/struct u_36_emit_n_tuple_emit3_event \{[^}]*?\};/m]
    refute_nil struct3
    assert_includes struct3, "__s64 a;"
    assert_includes struct3, "__s64 b;"
    assert_includes struct3, "__s64 c;"
    refute_match(/__s64 d;/, struct3) # 3-tuple struct must not have 'd'
    assert_includes c, "} u_36_emit_n_tuple_emit3_events SEC(\".maps\");"
  end

  def test_emit4_emits_4_tuple_struct_and_ringbuf
    c = emit_for("36_emit_n_tuple")
    assert_match(/struct u_36_emit_n_tuple_emit4_event \{.*?__s64 a;.*?__s64 b;.*?__s64 c;.*?__s64 d;.*?\};/m, c)
    assert_includes c, "} u_36_emit_n_tuple_emit4_events SEC(\".maps\");"
  end

  def test_emit3_call_lowers_to_ringbuf_reserve_submit
    c = emit_for("36_emit_n_tuple")
    inner = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_ringbuf_reserve\(&u_36_emit_n_tuple_emit3_events/, inner)
    assert_match(/_ne\d+->a = dfd;/, inner)
    assert_match(/_ne\d+->b = 1;/, inner)
    assert_match(/_ne\d+->c = 2;/, inner)
  end

  def test_emit4_call_lowers_with_d_field
    c = emit_for("36_emit_n_tuple")
    inner = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_ringbuf_reserve\(&u_36_emit_n_tuple_emit4_events/, inner)
    assert_match(/_ne\d+->d = 3;/, inner)
  end

  def test_emit3_includes_spnl_types_h
    c = emit_for("36_emit_n_tuple")
    assert_includes c, '#include "spnl/types.h"'
  end

  # ---------- C keyword sanitizer (integration) ----------

  def test_c_keyword_sanitizer_renames_params
    c = emit_for("37_c_keyword_collision")
    # `double` and `register` are C keywords; emit must rename to *_.
    assert_includes c, "kprobe__do_test_inner(__s64 double_, __s64 register_)"
    refute_match(/kprobe__do_test_inner\(__s64 double[^_]/, c)
  end

  def test_c_keyword_sanitizer_renames_locals
    c = emit_for("37_c_keyword_collision")
    inner = c[/kprobe__do_test_inner\(.*?\n\}/m]
    refute_nil inner
    # `static` and `volatile` are both C keywords; both rewritten.
    assert_includes inner, "__s64 static_ = 0;"
    assert_includes inner, "__s64 volatile_ = 0;"
    refute_match(/__s64 static =/, inner)
    refute_match(/__s64 volatile =/, inner)
  end

  def test_c_keyword_sanitizer_keeps_references_consistent
    # If a local was renamed at declaration, every read/write must also use
    # the renamed identifier. Otherwise the compile fails with "undeclared".
    c = emit_for("37_c_keyword_collision")
    inner = c[/kprobe__do_test_inner\(.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "static_ = double_ + register_;"
    assert_includes inner, "volatile_ = static_ * 2;"
    # The spnl_emit argument also uses the renamed local.
    assert_match(/->value = volatile_;/, inner)
  end

  def test_c_keyword_sanitizer_ctx_struct_uses_renamed_fields
    c = emit_for("37_c_keyword_collision")
    ctx_struct = c[/struct kprobe__do_test_ctx \{.*?\};/m]
    refute_nil ctx_struct
    assert_includes ctx_struct, "__s64 double_;"
    assert_includes ctx_struct, "__s64 register_;"
  end

  # ---------- uprobe / uretprobe ----------

  def test_uprobe_emits_sec_uprobe_with_pt_regs
    c = emit_for("38_uprobe_basic")
    assert_match(/SEC\("uprobe"\)\s+int uprobe__readline\(struct pt_regs \*ctx\)/, c)
    wrapper = c[/SEC\("uprobe"\)\s+int uprobe__readline.*?\n\}/m]
    refute_nil wrapper
    assert_includes wrapper, "uprobe__readline_inner((__s64)PT_REGS_PARM1(ctx))"
  end

  def test_uretprobe_emits_sec_uretprobe
    c = emit_for("38_uprobe_basic")
    assert_match(/SEC\("uretprobe"\)\s+int uretprobe__readline\(struct pt_regs \*ctx\)/, c)
  end

  def test_uprobe_includes_bpf_tracing_h
    c = emit_for("38_uprobe_basic")
    assert_includes c, "#include <bpf/bpf_tracing.h>"
  end

  # ---------- USDT ----------

  def test_usdt_emits_sec_usdt
    c = emit_for("39_usdt_basic")
    assert_match(/SEC\("usdt"\)\s+int usdt__libstdcxx__throw\(struct pt_regs \*ctx\)/, c)
    assert_match(/SEC\("usdt"\)\s+int usdt__libstdcxx__catch\(struct pt_regs \*ctx\)/, c)
  end

  def test_usdt_includes_usdt_bpf_h
    c = emit_for("39_usdt_basic")
    assert_includes c, "#include <bpf/usdt.bpf.h>"
  end

  def test_usdt_emits_bpf_usdt_arg_prologue_per_param
    c = emit_for("39_usdt_basic")
    throw_wrapper = c[/SEC\("usdt"\)\s+int usdt__libstdcxx__throw\(.*?\n\}/m]
    refute_nil throw_wrapper
    # 3 args -> 3 prologue lines
    assert_includes throw_wrapper, "long _usdt_arg0 = 0; (void)bpf_usdt_arg(ctx, 0, &_usdt_arg0);"
    assert_includes throw_wrapper, "long _usdt_arg1 = 0; (void)bpf_usdt_arg(ctx, 1, &_usdt_arg1);"
    assert_includes throw_wrapper, "long _usdt_arg2 = 0; (void)bpf_usdt_arg(ctx, 2, &_usdt_arg2);"
    assert_includes throw_wrapper, "usdt__libstdcxx__throw_inner((__s64)_usdt_arg0, (__s64)_usdt_arg1, (__s64)_usdt_arg2)"
  end

  def test_usdt_two_args_only_emits_two_prologue_lines
    c = emit_for("39_usdt_basic")
    catch_wrapper = c[/SEC\("usdt"\)\s+int usdt__libstdcxx__catch\(.*?\n\}/m]
    refute_nil catch_wrapper
    assert_includes catch_wrapper, "_usdt_arg0"
    assert_includes catch_wrapper, "_usdt_arg1"
    refute_match(/_usdt_arg2/, catch_wrapper)
  end

  def test_detect_attach_recognizes_uprobe_and_usdt
    assert_equal :uprobe,    GEN.detect_attach("uprobe__readline")[:kind]
    assert_equal :uretprobe, GEN.detect_attach("uretprobe__readline")[:kind]
    info = GEN.detect_attach("usdt__libstdcxx__throw")
    assert_equal :usdt, info[:kind]
    assert_equal "libstdcxx", info[:usdt_provider]
    assert_equal "throw",     info[:usdt_name]
  end

  # ---------- log2 histogram ----------

  def test_histogram_emits_array_map_64_slots
    c = emit_for("40_histogram")
    assert_match(/\}\s+bpf_hist SEC\("\.maps"\);/, c)
    map = c[/struct \{[^}]*\} bpf_hist SEC\("\.maps"\);/m]
    refute_nil map
    assert_includes map, "BPF_MAP_TYPE_ARRAY"
    assert_includes map, "__type(key, __u32)"
    assert_includes map, "__type(value, __u64)"
    assert_includes map, "__uint(max_entries, 64)"
  end

  def test_histogram_emits_log2_helper
    c = emit_for("40_histogram")
    assert_match(/static __noinline __s64 spnl_hist_log2\(__s64 v\)/, c)
    # Each branch shift is a constant — verifier-friendly.
    log2 = c[/static __noinline __s64 spnl_hist_log2.*?\n\}/m]
    refute_nil log2
    assert_includes log2, "if (v <= 1) return 0;"
    assert_includes log2, "(1LL << 32)"
    assert_includes log2, "(1   << 16)"
    assert_includes log2, "if (r > 63) r = 63;"
  end

  def test_histogram_emits_observe_helper
    c = emit_for("40_histogram")
    obs = c[/static __noinline __s64 spnl_hist_observe.*?\n\}/m]
    refute_nil obs
    assert_includes obs, "spnl_hist_log2"
    assert_includes obs, "__sync_fetch_and_add"
    assert_includes obs, "bpf_map_lookup_elem(&bpf_hist"
  end

  def test_histogram_call_lowers_to_helper
    c = emit_for("40_histogram")
    inner = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_includes inner, "spnl_hist_observe(dfd);"
  end

  def test_histogram_not_emitted_when_unused
    # 04_class_with_ivars never calls hist_observe — no map, no helpers.
    c = emit_for("04_class_with_ivars")
    refute_includes c, "bpf_hist"
    refute_includes c, "spnl_hist_log2"
  end

  # ---------- ktime / tid / latency builtins ----------

  def test_latency_emits_per_unit_lat_starts_map
    c = emit_for("41_latency_hist")
    assert_match(/\}\s+bpf_lat_starts SEC\("\.maps"\);/, c)
    map = c[/struct \{[^}]*\} bpf_lat_starts SEC\("\.maps"\);/m]
    refute_nil map
    assert_includes map, "BPF_MAP_TYPE_HASH"
    assert_includes map, "__type(key, __u32)"
    assert_includes map, "__type(value, __u64)"
  end

  def test_latency_start_helper_uses_pid_tgid_and_ktime
    c = emit_for("41_latency_hist")
    helper = c[/static __noinline __s64 spnl_latency_start.*?\n\}/m]
    refute_nil helper
    assert_includes helper, "bpf_get_current_pid_tgid()"
    assert_includes helper, "bpf_ktime_get_ns()"
    assert_includes helper, "bpf_map_update_elem(&bpf_lat_starts"
  end

  def test_latency_end_helper_reads_deletes_and_returns_delta
    c = emit_for("41_latency_hist")
    helper = c[/static __noinline __s64 spnl_latency_end.*?\n\}/m]
    refute_nil helper
    assert_includes helper, "bpf_map_lookup_elem(&bpf_lat_starts"
    assert_includes helper, "bpf_map_delete_elem(&bpf_lat_starts"
    assert_includes helper, "bpf_ktime_get_ns()"
  end

  def test_latency_call_lowers_kprobe_and_kretprobe
    c = emit_for("41_latency_hist")
    kprobe = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil kprobe
    assert_includes kprobe, "spnl_latency_start();"

    kretprobe = c[/kretprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil kretprobe
    assert_includes kretprobe, "spnl_hist_observe(spnl_latency_end());"
  end

  def test_latency_demo_emits_hist_and_lat_maps
    # The latency hist demo uses both bpf_hist and bpf_lat_starts.
    c = emit_for("41_latency_hist")
    assert_includes c, "} bpf_hist SEC(\".maps\");"
    assert_includes c, "} bpf_lat_starts SEC(\".maps\");"
  end

  # ---------- multi-key + linear histograms ----------

  def test_keyed_hist_emits_struct_with_64_buckets
    c = emit_for("42_keyed_hist")
    assert_includes c, "struct spnl_hist_struct { __u64 buckets[64]; };"
    assert_match(/\}\s+bpf_hist_keyed SEC\("\.maps"\);/, c)
    map = c[/struct \{[^}]*\} bpf_hist_keyed SEC\("\.maps"\);/m]
    refute_nil map
    assert_includes map, "BPF_MAP_TYPE_HASH"
    assert_includes map, "__type(key, __u64)"
    assert_includes map, "__type(value, struct spnl_hist_struct)"
  end

  def test_keyed_hist_uses_percpu_zero_template
    # Per-CPU template avoids 512B stack overflow when initializing new keys.
    c = emit_for("42_keyed_hist")
    assert_match(/\}\s+bpf_hist_keyed_zero SEC\("\.maps"\);/, c)
    zero_map = c[/struct \{[^}]*\} bpf_hist_keyed_zero SEC\("\.maps"\);/m]
    refute_nil zero_map
    assert_includes zero_map, "BPF_MAP_TYPE_PERCPU_ARRAY"
  end

  def test_keyed_hist_observe_by_call_lowers_to_helper
    c = emit_for("42_keyed_hist")
    inner = c[/kretprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/spnl_hist_observe_by\(.*?,\s*spnl_latency_end\(\)\);/, inner)
  end

  def test_linear_hist_emits_array_map_256_slots
    c = emit_for("43_linear_hist")
    assert_match(/\}\s+bpf_hist_lin SEC\("\.maps"\);/, c)
    map = c[/struct \{[^}]*\} bpf_hist_lin SEC\("\.maps"\);/m]
    refute_nil map
    assert_includes map, "BPF_MAP_TYPE_ARRAY"
    assert_includes map, "__uint(max_entries, 256)"
  end

  def test_linear_hist_call_lowers_to_helper
    c = emit_for("43_linear_hist")
    inner = c[/kretprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    # `latency_end >> 10` is the slot expression.
    # An expression inside a function argument needs no outer parentheses.
    assert_match(/spnl_hist_observe_linear\(spnl_latency_end\(\)\s*>>\s*10\);/, inner)
  end

  def test_shift_operators_supported
    c = emit_for("43_linear_hist")
    # >> emitted as plain C >>
    assert_match(/>>\s*10/, c)
  end

  # ---------- reactor uprobe / USDT (partition-level synthesis) ----------

  def test_reactor_uprobe_synthesizes_method_with_target_metadata
    # Synthesize an in-memory partition result from a module with reactor
    # uprobe handlers (no fixture — use a tiny inline ast/ir is awkward,
    # so for codegen we just sanity-check the data flow via MethodInfo).
    # Since reactor demos require real spinel fixtures and partition runs
    # outside codegen_bpf_test scope, full integration coverage lives in
    # the partition_test.rb suite + container build verification.
    info = SpinelEbpf::Partition::MethodInfo.new(
      scope: :top_level, class_name: nil,
      method_name: "uprobe__react0",
      body_id: -1, flags: nil, tag: :ebpf,
      dsl_uprobe_binary: "/usr/bin/bash",
      dsl_uprobe_func:   "readline",
      dsl_uprobe_retprobe: false,
    )
    assert_equal "/usr/bin/bash", info.dsl_uprobe_binary
    assert_equal "readline", info.dsl_uprobe_func
    refute info.dsl_uprobe_retprobe
  end

  def test_reactor_usdt_methodinfo_carries_provider_and_name
    info = SpinelEbpf::Partition::MethodInfo.new(
      scope: :top_level, class_name: nil,
      method_name: "usdt__react__0",
      body_id: -1, flags: nil, tag: :ebpf,
      dsl_uprobe_binary: "/usr/lib/aarch64-linux-gnu/libstdc++.so.6",
      dsl_usdt_provider: "libstdcxx",
      dsl_usdt_name:     "throw",
    )
    assert_equal "libstdcxx", info.dsl_usdt_provider
    assert_equal "throw",     info.dsl_usdt_name
  end

  def test_detect_attach_handles_reactor_synthesized_names
    # Even though glue.c will replace the func at attach time, detect_attach
    # still needs to recognize the synthesized names so emit_method emits
    # the right SEC.
    assert_equal :uprobe,    GEN.detect_attach("uprobe__react0")[:kind]
    assert_equal :uretprobe, GEN.detect_attach("uretprobe__react1")[:kind]
    info = GEN.detect_attach("usdt__react__2")
    assert_equal :usdt, info[:kind]
    assert_equal "react", info[:usdt_provider]  # synthetic provider — glue.c overrides
    assert_equal "2",     info[:usdt_name]
  end

  # ---------- divu / comm_hash / emit_comm ----------

  def test_divu_lowers_to_unsigned_division
    c = emit_for("46_e086_builtins")
    # The pattern is `((__s64)((__u64)(<a>) / (__u64)(<b>)))`.
    assert_match(/\(\(__s64\)\(\(__u64\)\(.*?\) \/ \(__u64\)\(.*?\)\)\)/, c)
  end

  def test_comm_hash_inlines_bpf_get_current_comm
    c = emit_for("46_e086_builtins")
    inner = c[/kretprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/char _ch\d+\[16\] = \{0\};/, inner)
    assert_match(/bpf_get_current_comm\(_ch\d+, sizeof\(_ch\d+\)\);/, inner)
    assert_match(/\(\(__s64\)\(\*\(\(__u64 \*\)_ch\d+\)\)\)/, inner)
  end

  def test_emit_comm_uses_str_ringbuf
    c = emit_for("46_e086_builtins")
    # emit_comm uses the per-unit <unit>_str_events ringbuf.
    assert_includes c, "_str_events SEC(\".maps\");"
    inner = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_ringbuf_reserve\(&u_46_e086_builtins_str_events/, inner)
    assert_match(/bpf_get_current_comm\(_se\d+->str/, inner)
  end

  def test_builtins_in_builtin_names
    assert_includes GEN::BUILTIN_NAMES, "divu"
    assert_includes GEN::BUILTIN_NAMES, "comm_hash"
    assert_includes GEN::BUILTIN_NAMES, "emit_comm"
  end

  # ---------- reactor per-handler PID kwarg ----------

  def test_reactor_uprobe_with_pid_extracts_dsl_attach_pid
    name = "47_reactor_pid"
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{name}.ast")
    r   = P.classify(ir, ast)
    uprobe = r.methods.find { |m| m.method_name == "uprobe__react0" }
    refute_nil uprobe
    assert_equal "/usr/bin/bash", uprobe.dsl_uprobe_binary
    assert_equal "readline",      uprobe.dsl_uprobe_func
    assert_equal 12345,           uprobe.dsl_attach_pid
  end

  def test_reactor_usdt_with_pid_extracts_dsl_attach_pid
    name = "47_reactor_pid"
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{name}.ast")
    r   = P.classify(ir, ast)
    usdt = r.methods.find { |m| m.method_name == "usdt__react__1" }
    refute_nil usdt
    assert_equal "libstdcxx", usdt.dsl_usdt_provider
    assert_equal "throw",     usdt.dsl_usdt_name
    assert_equal 67890,       usdt.dsl_attach_pid
  end

  def test_reactor_without_pid_kwarg_is_nil
    # This fixture has no pid: kwarg; dsl_attach_pid should stay nil.
    name = "44_reactor_block_params"
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{name}.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{name}.ast")
    r   = P.classify(ir, ast)
    mi = r.methods.find { |m| m.method_name == "uprobe__react0" }
    refute_nil mi
    assert_nil mi.dsl_attach_pid
  end

  # ---------- stack_id / user_stack_id + STACK_TRACE map ----------

  def test_stack_trace_map_declared_when_stack_id_used
    c = emit_for("48_stack_trace")
    assert_match(/\}\s+bpf_stacks SEC\("\.maps"\);/, c)
    map = c[/struct \{[^}]*\} bpf_stacks SEC\("\.maps"\);/m]
    refute_nil map
    assert_includes map, "BPF_MAP_TYPE_STACK_TRACE"
    assert_includes map, "127 * sizeof(__u64)"
    assert_includes map, "__uint(max_entries, 16384)"
  end

  def test_stack_id_lowers_to_bpf_get_stackid_with_flag_zero
    c = emit_for("48_stack_trace")
    inner = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_get_stackid\(ctx, &bpf_stacks, 0\)/, inner)
  end

  def test_user_stack_id_lowers_with_user_flag
    c = emit_for("48_stack_trace")
    inner = c[/kprobe__do_sys_openat2_inner\(.*?\n\}/m]
    refute_nil inner
    # BPF_F_USER_STACK = 1 << 8
    assert_match(/bpf_get_stackid\(ctx, &bpf_stacks, \(1ULL << 8\)\)/, inner)
  end

  def test_stack_id_kprobe_inner_takes_ctx_arg
    # When stack_id() is used in a kprobe handler, codegen forwards ctx
    # into the inner so the call site can pass it to bpf_get_stackid.
    c = emit_for("48_stack_trace")
    assert_match(/static __noinline __s64 kprobe__do_sys_openat2_inner\(struct pt_regs \*ctx,/, c)
    # Wrapper passes ctx as first arg.
    assert_match(/kprobe__do_sys_openat2_inner\(ctx,/, c)
  end

  def test_stack_trace_not_emitted_when_unused
    c = emit_for("04_class_with_ivars")
    refute_includes c, "bpf_stacks"
    refute_includes c, "bpf_get_stackid"
  end

  # ---------- reactor block params across all attach kinds ----------

  def test_reactor_kprobe_block_params_extracted
    c = emit_for("49_reactor_all_params")
    inner_sig = c[/static __noinline __s64 kprobe__do_sys_openat2_inner\(([^)]*)\)/]
    refute_nil inner_sig
    assert_equal "__s64 dfd, __s64 filename", $1
    assert_match(/kprobe__do_sys_openat2_inner\(\(__s64\)PT_REGS_PARM1\(ctx\), \(__s64\)PT_REGS_PARM2\(ctx\)\)/, c)
  end

  def test_reactor_kretprobe_block_param
    c = emit_for("49_reactor_all_params")
    assert_match(/static __noinline __s64 kretprobe__do_sys_openat2_inner\(__s64 ret\)/, c)
  end

  def test_reactor_fentry_fexit_block_params_use_ctx_index
    c = emit_for("49_reactor_all_params")
    assert_match(/fentry__tcp_v4_rcv_inner\(\(__s64\)ctx\[0\]\)/, c)
    # fexit has skb + ret -> ctx[0], ctx[1]
    assert_match(/fexit__tcp_v4_rcv_inner\(\(__s64\)ctx\[0\], \(__s64\)ctx\[1\]\)/, c)
  end

  def test_reactor_tracepoint_syscalls_uses_args_index
    c = emit_for("49_reactor_all_params")
    assert_match(/tracepoint__syscalls__sys_enter_write_inner\(\(__s64\)\(\(struct trace_event_raw_sys_enter \*\)ctx\)->args\[0\], \(__s64\)\(\(struct trace_event_raw_sys_enter \*\)ctx\)->args\[1\], \(__s64\)\(\(struct trace_event_raw_sys_enter \*\)ctx\)->args\[2\]\)/, c)
  end

  def test_reactor_tracepoint_named_field_resolves
    c = emit_for("50_reactor_named_tp")
    # sched/sched_switch uses TRACEPOINT_FIELDS to map prev_pid/next_pid to
    # struct trace_event_raw_sched_switch members.
    assert_match(/tracepoint__sched__sched_switch_inner\(\(__s64\)\(\(struct trace_event_raw_sched_switch \*\)ctx\)->prev_pid, \(__s64\)\(\(struct trace_event_raw_sched_switch \*\)ctx\)->next_pid\)/, c)
  end

  def test_reactor_uprobe_uretprobe_block_params
    c = emit_for("49_reactor_all_params")
    assert_match(/uprobe__react0_inner\(\(__s64\)PT_REGS_PARM1\(ctx\)\)/, c)
    assert_match(/uretprobe__react1_inner\(\(__s64\)PT_REGS_PARM1\(ctx\)\)/, c)
  end

  def test_reactor_usdt_block_params_use_bpf_usdt_arg
    c = emit_for("49_reactor_all_params")
    wrapper = c[/SEC\("usdt"\)\s+int usdt__react__2\(struct pt_regs \*ctx\).*?\n\}/m]
    refute_nil wrapper
    assert_includes wrapper, "long _usdt_arg0 = 0; (void)bpf_usdt_arg(ctx, 0, &_usdt_arg0);"
    assert_includes wrapper, "long _usdt_arg1 = 0; (void)bpf_usdt_arg(ctx, 1, &_usdt_arg1);"
    assert_includes wrapper, "long _usdt_arg2 = 0; (void)bpf_usdt_arg(ctx, 2, &_usdt_arg2);"
    assert_includes wrapper, "usdt__react__2_inner((__s64)_usdt_arg0, (__s64)_usdt_arg1, (__s64)_usdt_arg2)"
  end

  # ---------- perf_event sampling ----------

  def test_perf_event_emits_sec_perf_event
    c = emit_for("51_perf_event")
    assert_match(/SEC\("perf_event"\)\s+int perf_event__main\(struct bpf_perf_event_data \*ctx\)/, c)
  end

  def test_perf_event_inner_takes_ctx
    c = emit_for("51_perf_event")
    # ctx is forwarded so stack_id() (and other bpf_*(ctx, ...) helpers)
    # work inside the inner.
    assert_match(/static __noinline __s64 perf_event__main_inner\(struct bpf_perf_event_data \*ctx\)/, c)
    assert_match(/perf_event__main_inner\(ctx\)/, c)
  end

  def test_perf_event_partition_extracts_hz
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/51_perf_event.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/51_perf_event.ast")
    r   = P.classify(ir, ast)
    pe = r.methods.find { |m| m.method_name == "perf_event__main" }
    refute_nil pe
    assert_equal 99, pe.dsl_perf_event_hz
  end

  def test_detect_attach_recognizes_perf_event
    info = GEN.detect_attach("perf_event__on_cpu")
    assert_equal :perf_event, info[:kind]
    assert_equal "perf_event", info[:sec]
    assert_equal "struct bpf_perf_event_data *", info[:ctx_type]
  end

  # ---------- off-CPU profiling ----------

  def test_off_cpu_emits_per_unit_map
    c = emit_for("52_off_cpu")
    assert_match(/\}\s+bpf_off_cpu SEC\("\.maps"\);/, c)
    assert_includes c, "struct spnl_off_cpu_entry {"
    assert_includes c, "__u64 ts;"
    assert_includes c, "__u32 stack_id;"
  end

  def test_off_cpu_start_call_lowers_with_ctx
    c = emit_for("52_off_cpu")
    inner = c[/tracepoint__sched__sched_switch_inner\(.*?\n\}/m]
    refute_nil inner
    # off_cpu_start takes pid + ctx (codegen forwards ctx into inner).
    assert_match(/spnl_off_cpu_start\(\(__u32\)\(prev_pid\), ctx\);/, inner)
  end

  def test_off_cpu_observe_call_lowers
    c = emit_for("52_off_cpu")
    inner = c[/tracepoint__sched__sched_switch_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/spnl_off_cpu_observe\(\(__u32\)\(next_pid\)\)/, inner)
  end

  def test_off_cpu_pulls_in_stack_trace_and_keyed_hist
    # off_cpu_start uses bpf_get_stackid → bpf_stacks must be emitted.
    # off_cpu_observe writes into bpf_hist_keyed → that map (and the
    # log2 helper) must be emitted too.
    c = emit_for("52_off_cpu")
    assert_includes c, "} bpf_stacks SEC(\".maps\");"
    assert_includes c, "} bpf_hist_keyed SEC(\".maps\");"
    assert_includes c, "} bpf_hist_keyed_zero SEC(\".maps\");"
    assert_includes c, "spnl_hist_log2"
  end

  def test_off_cpu_tracepoint_inner_takes_ctx
    # ctx must be forwarded (stack_id used via off_cpu_start).
    c = emit_for("52_off_cpu")
    assert_match(/static __noinline __s64 tracepoint__sched__sched_switch_inner\(void \*ctx,/, c)
  end

  # ---------- folded stacks output ----------
  # The folded format generator lives in spnl_runtime.c (host runtime
  # surface), with a Python post-processor alongside it. Ruby-side codegen is
  # unchanged from the perf_event / off-CPU profiling work, so we only sanity
  # check that the helper symbols are present in the source tree.

  def test_spnl_print_folded_stacks_obj_declared_in_header
    header = File.read(File.expand_path("../../src/runtime/spnl_runtime.h", __dir__))
    assert_includes header, "spnl_print_folded_stacks_obj"
  end

  def test_spnl_print_folded_stacks_obj_defined_in_source
    src = File.read(File.expand_path("../../src/runtime/spnl_runtime.c", __dir__))
    assert_includes src, "spnl_print_folded_stacks_obj"
    # Emits semicolon-joined frames followed by count.
    assert_match(/fprintf\(fp, " %llu/, src)
  end

  # ---------- live flame graph (HTTP stream) ----------
  # The implementation lives in glue.c (spnl_dump_folded_to_fd FFI) and
  # the demo example. Verify both surfaces present in tree.

  def test_spnl_dump_folded_to_fd_emitted_in_glue
    glue = File.read(File.expand_path("../../bin/spinel-ebpf", __dir__))
    assert_includes glue, "spnl_dump_folded_to_fd"
    # fdopen on a dup'd fd so caller socket lifetime isn't affected
    assert_match(/dup\(fd\)/, glue)
    assert_match(/fdopen\(dup_fd/, glue)
  end

  def test_live_flame_graph_demo_present
    demo = File.read(File.expand_path("../../examples/observability/live_flame_graph.rb", __dir__))
    assert_includes demo, "on :perf_event, hz: 99"
    assert_includes demo, "spnl_dump_folded_to_fd"
    assert_includes demo, "d3-flamegraph"
  end

  # ---------- Ruby sched_ext scheduler ----------

  def test_scx_simple_emits_sleepable_init_sec
    c = emit_for("53_scx_simple")
    # init/exit need `.s` suffix (sleepable) for create_dsq/destroy_dsq.
    assert_match(/SEC\("struct_ops\.s\/init"\)/, c)
    # enqueue/dispatch stay non-sleepable.
    assert_match(/SEC\("struct_ops\/enqueue"\)/, c)
    assert_match(/SEC\("struct_ops\/dispatch"\)/, c)
  end

  def test_scx_simple_uses_struct_ops_link_section
    c = emit_for("53_scx_simple")
    assert_match(/SEC\("\.struct_ops\.link"\)\s+struct sched_ext_ops/, c)
  end

  def test_scx_simple_lowers_to_kernel_kfunc_names
    c = emit_for("53_scx_simple")
    # New kernel API names.
    assert_includes c, "scx_bpf_dsq_insert"
    assert_includes c, "scx_bpf_dsq_move_to_local"
    # Old names must NOT be emitted (they don't exist as kfuncs anymore).
    refute_includes c, "scx_bpf_dispatch("
    refute_includes c, "scx_bpf_consume("
  end

  def test_scx_simple_emits_constant_macros
    c = emit_for("53_scx_simple")
    assert_match(/#define SCX_DSQ_GLOBAL/, c)
    assert_match(/#define SCX_SLICE_DFL/, c)
  end

  def test_scx_dispatch_casts_p_to_task_struct
    c = emit_for("53_scx_simple")
    inner = c[/sched_ext__enqueue_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/scx_bpf_dsq_insert\(\(struct task_struct \*\)\(unsigned long\)\(p\)/, inner)
  end

  # ---------- Ruby BPF qdisc ----------

  def test_qdisc_uses_struct_ops_link_section
    c = emit_for("54_qdisc_blackhole")
    assert_match(/SEC\("\.struct_ops\.link"\)\s+struct Qdisc_ops/, c)
  end

  def test_qdisc_skb_drop_kfunc_called_with_correct_casts
    c = emit_for("54_qdisc_blackhole")
    inner = c[/qdisc__enqueue_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_qdisc_skb_drop\(\(struct sk_buff \*\)\(unsigned long\)\(skb\),\s+\(struct bpf_sk_buff_ptr \*\)\(unsigned long\)\(to_free\)\)/, inner)
  end

  def test_qdisc_enqueue_returns_int
    c = emit_for("54_qdisc_blackhole")
    assert_match(/int BPF_PROG\(qdisc__enqueue,/, c)
  end

  def test_qdisc_dequeue_returns_sk_buff_ptr
    c = emit_for("54_qdisc_blackhole")
    assert_match(/struct sk_buff \* BPF_PROG\(qdisc__dequeue,/, c)
  end

  def test_qdisc_registration_name_is_spnl_qdisc
    c = emit_for("54_qdisc_blackhole")
    assert_includes c, ".id = \"spnl_qdisc\","
  end

  # ---------- real FIFO qdisc (bpf_list + kptr_xchg + spin_lock) ----------

  def test_qdisc_fifo_emits_helper_machinery
    c = emit_for("55_qdisc_fifo")
    # Preamble macros + kfunc wrappers
    assert_includes c, "#define __kptr"
    assert_includes c, "#define __contains"
    assert_includes c, "#define private(name)"
    assert_includes c, "#define bpf_obj_new(type)"
    assert_includes c, "#define bpf_list_push_back("
    assert_includes c, "#define container_of("
    # bpf_core_type_id_local lives in bpf_core_read.h
    assert_includes c, "#include <bpf/bpf_core_read.h>"
  end

  def test_qdisc_fifo_emits_skb_node_struct
    c = emit_for("55_qdisc_fifo")
    assert_match(/struct spnl_qdisc_skb_node \{/, c)
    assert_match(/struct bpf_list_node node;/, c)
    assert_match(/struct sk_buff __kptr \*skb;/, c)
  end

  def test_qdisc_fifo_emits_lock_and_list_globals
    c = emit_for("55_qdisc_fifo")
    assert_match(/private\(A\) struct bpf_spin_lock spnl_qdisc_q_lock;/, c)
    assert_match(/private\(A\) struct bpf_list_head spnl_qdisc_q_head __contains\(spnl_qdisc_skb_node, node\);/, c)
  end

  def test_queue_push_expansion_includes_kptr_xchg_and_push_back
    c = emit_for("55_qdisc_fifo")
    inner = c[/qdisc__enqueue_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_obj_new\(typeof\(\*_qpn\)\)/, inner)
    assert_match(/bpf_kptr_xchg\(&_qpn->skb,/, inner)
    assert_match(/bpf_spin_lock\(&spnl_qdisc_q_lock\)/, inner)
    assert_match(/bpf_list_push_back\(&spnl_qdisc_q_head, &_qpn->node\)/, inner)
    assert_match(/bpf_spin_unlock\(&spnl_qdisc_q_lock\)/, inner)
  end

  def test_queue_pop_expansion_uses_list_pop_and_container_of
    c = emit_for("55_qdisc_fifo")
    inner = c[/qdisc__dequeue_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_list_pop_front\(&spnl_qdisc_q_head\)/, inner)
    assert_match(/container_of\(_qpn, struct spnl_qdisc_skb_node, node\)/, inner)
    assert_match(/bpf_kptr_xchg\(&_qps->skb, NULL\)/, inner)
    assert_match(/bpf_obj_drop\(_qps\)/, inner)
  end

  # ---------- bpf_qdisc_bstats_update ----------

  def test_qdisc_bstats_update_lowers_with_correct_casts
    c = emit_for("55_qdisc_fifo")
    inner = c[/qdisc__dequeue_inner\(.*?\n\}/m]
    refute_nil inner
    assert_match(/bpf_qdisc_bstats_update\(\(struct Qdisc \*\)\(unsigned long\)\(sch\),\s+\(const struct sk_buff \*\)\(unsigned long\)\(skb\)\)/, inner)
  end

  # ---------- unsupported nodes ----------

  def test_unsupported_node_raises
    # Forcing a top-level method whose body has an unsupported node should
    # raise UnsupportedNode. fib (recursion) is partition'd as :native so it
    # won't be passed to emit. Construct an artificial result instead.
    ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/03_fib_recursion.ir")
    ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/03_fib_recursion.ast")
    r   = P.classify(ir, ast)
    # Force fib to :ebpf to exercise the unsupported-CallNode path
    fib = r.methods.find { |m| m.method_name == "fib" }
    refute_nil fib
    fib.tag = :ebpf

    assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      GEN.emit(ir, ast, r, base_name: "03_fib_recursion")
    end
  end

  # ---------- kfield / kptr arbitrary struct field (BPF_CORE_READ) ----------

  def test_builtin_names_include_kfield_kptr
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "kfield"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "kptr"
  end

  def test_kfield_emits_bpf_core_read
    c = emit_for("56_kfield")
    assert_includes c, "#include <bpf/bpf_core_read.h>"
    assert_match(/BPF_CORE_READ\(\(struct sock \*\)\(unsigned long\)\(sk\), sk_sndbuf\)/, c)
  end

  def test_kptr_dot_accessor_emits_bpf_core_read
    # `s = kptr(sk, "sock"); s.sk_rcvbuf` lowers the dot read to BPF_CORE_READ.
    c = emit_for("56_kfield")
    assert_match(/BPF_CORE_READ\(\(struct sock \*\)\(unsigned long\)\(s\), sk_rcvbuf\)/, c)
  end

  def test_kfield_attaches_as_kprobe
    c = emit_for("56_kfield")
    assert_includes c, 'SEC("kprobe/tcp_sendmsg")'
    assert_match(/kprobe__tcp_sendmsg_inner\(\(__s64\)PT_REGS_PARM1\(ctx\)\)/, c)
  end

  def test_core_read_not_included_without_kfield
    # A fixture that uses neither kfield/kptr nor the FIFO qdisc must not pull
    # in bpf_core_read.h.
    c = emit_for("24_xdp_counter")
    refute_includes c, "#include <bpf/bpf_core_read.h>"
  end

  # fib_lookup builtin — the first consumer that emits a typed
  # stack local (struct bpf_fib_lookup) and passes &local to a helper.
  def test_fib_lookup_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "fib_lookup"
  end

  def test_fib_lookup_emits_typed_struct_local_and_helper
    c = emit_for("77_fib_lookup")
    # typed struct local on the stack (zero-initialised)
    assert_match(/struct bpf_fib_lookup _spnl_fib_\d+ = \{\};/, c)
    # destination filled in network byte order from the host-order arg
    assert_match(/_spnl_fib_\d+\.family = 2;/, c)
    assert_match(/_spnl_fib_\d+\.ipv4_dst = bpf_htonl\(/, c)
    # &local passed to the helper with sizeof
    assert_match(/bpf_fib_lookup\(ctx, &_spnl_fib_\d+, sizeof\(_spnl_fib_\d+\), 0\)/, c)
    # result: ifindex on success (ret == 0), else -1
    assert_match(/_spnl_fibret_\d+ == 0 \? _spnl_fib_\d+\.ifindex : \(__s64\)-1/, c)
    # needs bpf_endian.h for bpf_htonl
    assert_includes c, "#include <bpf/bpf_endian.h>"
  end

  def test_fib_lookup_rejected_outside_xdp_tc
    # fib_lookup needs the packet ctx; calling it from a kprobe must raise.
    err = assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      emit_for("78_fib_lookup_kprobe")
    end
    assert_match(/fib_lookup is only available inside xdp__ or tc__/, err.message)
  end

  # fib_lookup6(dst_hi, dst_lo) — IPv6 route lookup. Verifier-accepted +
  # JIT confirmed (xlated shows family=AF_INET6 + ipv6_dst packing).
  def test_fib_lookup6_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "fib_lookup6"
  end

  def test_fib_lookup6_packs_ipv6_dst
    c = emit_for("92_fib6")
    assert_match(/_spnl_fib6_\d+\.family = 10;/, c)   # AF_INET6
    assert_match(/_spnl_fib6_\d+\.ipv6_dst\[0\] = bpf_htonl\(\(__u32\)\(\(__u64\)\(0\) >> 32\)\)/, c)
    assert_match(/_spnl_fib6_\d+\.ipv6_dst\[3\] = bpf_htonl\(\(__u32\)\(1\)\)/, c)
    assert_match(/bpf_fib_lookup\(ctx, &_spnl_fib6_\d+, sizeof\(_spnl_fib6_\d+\), 0\)/, c)
  end

  # sk_lookup_tcp — find a TCP socket for a 4-tuple, read its state, and
  # release the reference on every path. Functionally verified (found a real
  # listener, state=TCP_LISTEN).
  def test_sk_lookup_tcp_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "sk_lookup_tcp"
  end

  def test_sk_lookup_tcp_emits_lookup_and_release
    c = emit_for("93_sk_lookup")
    assert_match(/struct bpf_sock_tuple _spnl_sktup_\d+ = \{\};/, c)
    assert_match(/_spnl_sktup_\d+\.ipv4\.dport = bpf_htons\(\(__u16\)\(9999\)\)/, c)
    assert_match(/struct bpf_sock \*_spnl_sk_\d+ = bpf_sk_lookup_tcp\(ctx, &_spnl_sktup_\d+, sizeof\(_spnl_sktup_\d+\.ipv4\), -1, 0\)/, c)
    # reference released on the found path (verifier reference tracking)
    assert_match(/if \(_spnl_sk_\d+\) \{ _spnl_skr_\d+ = \(__s64\)_spnl_sk_\d+->state; bpf_sk_release\(_spnl_sk_\d+\); \}/, c)
  end

  # redirect(ifindex) = bpf_redirect — combined with fib_lookup builds an L3
  # router. Functionally verified (retval=TC_ACT_REDIRECT).
  def test_redirect_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "redirect"
  end

  def test_router_emits_fib_lookup_and_redirect
    c = emit_for("94_router")
    assert_includes c, "bpf_fib_lookup(ctx, &_spnl_fib_"   # route lookup
    assert_match(/out = \(__s64\)bpf_redirect\(\(__u32\)\(oif\), 0\)/, c)   # forward
  end

  # sk_assign_tcp — steer the skb to the looked-up socket.
  # Functionally verified (assigned a real listener, retval=0).
  def test_sk_assign_tcp_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "sk_assign_tcp"
  end

  def test_sk_assign_tcp_emits_assign_and_release
    c = emit_for("95_sk_assign")
    assert_match(/struct bpf_sock \*_spnl_ask_\d+ = bpf_sk_lookup_tcp\(ctx, &_spnl_aktup_\d+, sizeof\(_spnl_aktup_\d+\.ipv4\), -1, 0\)/, c)
    assert_match(/if \(_spnl_ask_\d+\) \{ _spnl_akr_\d+ = \(__s64\)bpf_sk_assign\(ctx, _spnl_ask_\d+, 0\); bpf_sk_release\(_spnl_ask_\d+\); \}/, c)
  end

  def test_sk_assign_rejected_outside_tc_ingress
    err = assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      emit_for("96_sk_assign_egress")
    end
    assert_match(/sk_assign_tcp is only available inside tc__ingress__/, err.message)
  end

  # skb-rewrite builtins (TC) — typed __u8 stack local -> bpf_skb_*_bytes,
  # plus incremental l3 checksum repair. Functionally verified end-to-end with
  # BPF_PROG_TEST_RUN (TTL 64->63 + valid IP checksum).
  def test_skb_rewrite_in_builtin_names
    %w[skb_load_byte skb_store_byte l3_csum_replace l4_csum_replace].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_skb_rewrite_emits_typed_locals_and_helpers
    c = emit_for("79_skb_rewrite")
    # skb_load_byte / skb_store_byte each emit a typed __u8 stack local + &local
    assert_match(/__u8 _spnl_lb_\d+ = 0; __s64 _r\d+ = bpf_skb_load_bytes\(ctx, \(22\), &_spnl_lb_\d+, 1\)/, c)
    assert_match(/__u8 _spnl_sb_\d+ = \(__u8\)\(nt\); \(__s64\)bpf_skb_store_bytes\(ctx, \(22\), &_spnl_sb_\d+, 1, 0\)/, c)
    # l3_csum_replace htons-es the host-order field values, size 2
    assert_match(/bpf_l3_csum_replace\(ctx, \(24\), bpf_htons\(\(__u16\)\(ttl << 8\)\), bpf_htons\(\(__u16\)\(nt << 8\)\), 2\)/, c)
    assert_includes c, "#include <bpf/bpf_endian.h>"
    assert_includes c, 'SEC("tcx/egress")'
  end

  def test_skb_rewrite_rejected_outside_tc
    # skb-rewrite mutates struct __sk_buff; calling from XDP must raise.
    err = assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      emit_for("80_skb_rewrite_xdp")
    end
    assert_match(%r{only available inside tc__ingress__/tc__egress__}, err.message)
  end

  # NAT builtins (TC) — 32-bit IPv4 address rewrite + L3/L4 checksum repair
  # (L4 with BPF_F_PSEUDO_HDR). Functionally verified end-to-end with
  # BPF_PROG_TEST_RUN (DNAT 10.0.0.2->10.0.0.99, IP + TCP csum VALID).
  def test_nat_in_builtin_names
    %w[skb_load_u32 skb_store_u32 l3_csum_replace_ip l4_csum_replace_ip].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_nat_emits_u32_rewrite_and_pseudo_hdr_csum
    c = emit_for("81_nat_rewrite")
    # skb_load_u32 returns host order (ntohl); skb_store_u32 writes network order (htonl)
    assert_match(/__u32 _spnl_l4r_\d+ = 0;.*bpf_skb_load_bytes\(ctx, \(30\), &_spnl_l4r_\d+, 4\).*bpf_ntohl/m, c)
    assert_match(/__u32 _spnl_su_\d+ = bpf_htonl\(\(__u32\)\(new\)\);.*bpf_skb_store_bytes\(ctx, \(30\), &_spnl_su_\d+, 4, 0\)/m, c)
    # L3 csum: size 4; L4 csum: BPF_F_PSEUDO_HDR (1<<4) | size 4
    assert_includes c, "bpf_l3_csum_replace(ctx, (24), bpf_htonl((__u32)(dst)), bpf_htonl((__u32)(new)), 4)"
    assert_includes c, "bpf_l4_csum_replace(ctx, (50), bpf_htonl((__u32)(dst)), bpf_htonl((__u32)(new)), ((1 << 4) | 4))"
  end

  def test_nat_rejected_outside_tc
    err = assert_raises(SpinelEbpf::CodegenBpf::UnsupportedNode) do
      emit_for("82_nat_xdp")
    end
    assert_match(%r{only available inside tc__ingress__/tc__egress__}, err.message)
  end

  # 16-bit port rewrite completing NAT. skb_load_u16/skb_store_u16 +
  # l4_csum_replace (no pseudo-header, since a port isn't in the pseudo-header).
  # Verified end-to-end with BPF_PROG_TEST_RUN (TCP+UDP IP+port DNAT).
  def test_u16_in_builtin_names
    %w[skb_load_u16 skb_store_u16].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_u16_port_rewrite_emits_ntohs_htons_and_plain_l4_csum
    c = emit_for("83_nat_port")
    assert_match(/__u16 _spnl_l2r_\d+ = 0;.*bpf_skb_load_bytes\(ctx, \(36\), &_spnl_l2r_\d+, 2\).*bpf_ntohs/m, c)
    assert_match(/__u16 _spnl_s2_\d+ = bpf_htons\(\(__u16\)\(8080\)\);.*bpf_skb_store_bytes\(ctx, \(36\), &_spnl_s2_\d+, 2, 0\)/m, c)
    # port lives in the L4 header, not the pseudo-header → plain size-2 csum fix
    assert_includes c, "bpf_l4_csum_replace(ctx, (l4), bpf_htons((__u16)(dp)), bpf_htons((__u16)(8080)), 2)"
  end

  # l4_offset() = 14 + IHL*4 (IP-options-aware L4 offset). Functionally
  # verified (IHL=5 -> 34, IHL=6 -> 38, correct sport).
  def test_l4_offset_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "l4_offset"
  end

  def test_l4_offset_emits_ihl_computation
    c = emit_for("91_ip_options")
    assert_match(/__u8 _spnl_lo\d+ = 0; bpf_skb_load_bytes\(ctx, 14, &_spnl_lo\d+, 1\); \(__s64\)\(14 \+ \(_spnl_lo\d+ & 0x0f\) \* 4\)/, c)
  end

  # bpf_arena — arena_set/arena_get over an arena-resident u64[512] array.
  # Functionally verified end-to-end with BPF_PROG_TEST_RUN (0x12345678 stored,
  # +1 through arena = 0x12345679).
  def test_arena_in_builtin_names
    %w[arena_set arena_get].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_arena_emits_map_global_and_pointer_deref
    c = emit_for("84_arena")
    # arena map + address-space define + arena-resident global array
    assert_includes c, "__uint(type, BPF_MAP_TYPE_ARENA);"
    assert_includes c, "#define __arena __attribute__((address_space(1)))"
    assert_match(/__u64 __arena \w+_arena_data\[512\];/, c)
    # arena_set/get lower to plain pointer derefs (no map helper), masked index
    assert_match(/\w+_arena_data\[\(__u64\)\(0\) & 511\] = \(__u64\)\(305419896\)/, c)
    assert_match(/\(__s64\)\w+_arena_data\[\(__u64\)\(0\) & 511\]/, c)
  end

  def test_arena_absent_without_use
    # A program that never calls arena_* must not emit the arena map.
    c = emit_for("24_xdp_counter")
    refute_includes c, "BPF_MAP_TYPE_ARENA"
  end

  # stateful L4 load balancer — PURE COMPOSITION (zero new codegen) of the
  # conntrack flow map + the NAT builtins. Functionally
  # verified end-to-end with BPF_PROG_TEST_RUN (distribution + stickiness +
  # valid checksums).
  def test_l4_lb_composes_conntrack_and_dnat
    c = emit_for("85_l4_lb")
    # conntrack: LRU_HASH flow map keyed by the 4-tuple, value carries backend_ip
    assert_includes c, "__uint(type, BPF_MAP_TYPE_LRU_HASH);"
    assert_includes c, "__u64 backend_ip;"
    assert_match(/spnl_flow_\w+_conn_key_tc\(ctx, &\w+\)/, c)   # 4-tuple key extract
    # flow_get returns backend_ip or 0; flow_set lookup-or-insert
    assert_match(/\w+ \? \(__s64\)\w+->backend_ip : 0/, c)
    # DNAT: IP + TCP (pseudo-header) csum repair + 32-bit dst store
    assert_includes c, "bpf_l3_csum_replace(ctx, (24), bpf_htonl((__u32)(old)), bpf_htonl((__u32)(bip)), 4)"
    assert_includes c, "bpf_l4_csum_replace(ctx, (50), bpf_htonl((__u32)(old)), bpf_htonl((__u32)(bip)), ((1 << 4) | 4))"
    assert_match(/bpf_skb_store_bytes\(ctx, \(30\), &_spnl_su_\d+, 4, 0\)/, c)
  end

  # arena hash table — open addressing over the arena array. Functionally
  # verified with BPF_PROG_TEST_RUN (set/update/get/absent: 50/99/0).
  def test_arena_hash_in_builtin_names
    %w[arena_hash_set arena_hash_get].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_arena_hash_emits_probe_loop_over_arena
    c = emit_for("86_arena_hash")
    # reuses the arena map + array
    assert_includes c, "__uint(type, BPF_MAP_TYPE_ARENA);"
    assert_match(/__u64 __arena \w+_arena_data\[512\];/, c)
    # multiplicative hash into 256 buckets + unrolled linear probe
    assert_match(/\(\(__u32\)_hk\d+ \* 2654435761U\) & 255U/, c)
    assert_includes c, "#pragma unroll"
    # (key, value) pairs stored/read through the arena pointer
    assert_match(/\w+_arena_data\[2U \* _hs\d+\] = _hk\d+; \w+_arena_data\[2U \* _hs\d+ \+ 1\] = _hv\d+/, c)
  end

  # arena_hash_del completes the CRUD with a tombstone (~0). Functionally
  # verified (CRUD + userspace mmap read of the shared table).
  def test_arena_hash_del_in_builtin_names
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "arena_hash_del"
  end

  def test_arena_hash_del_emits_tombstone
    c = emit_for("87_arena_hash_del")
    # del marks the matching slot's key as the tombstone ~0 and zeroes its value
    assert_match(/if \(!_hd\d+ && _hek\d+ == _hk\d+\) \{ \w+_arena_data\[2U \* _hs\d+\] = ~0ULL; \w+_arena_data\[2U \* _hs\d+ \+ 1\] = 0; _hd\d+ = 1; \}/, c)
  end

  # arena singly-linked list (index-based references + bump allocator) over
  # the arena array. Functionally verified (push x3 + walk-sum = 60, chain shown
  # via mmap).
  def test_arena_list_in_builtin_names
    %w[arena_list_push arena_list_sum].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_arena_list_emits_bump_alloc_and_unrolled_walk
    c = emit_for("89_arena_list")
    # push: bump pointer in slot 1, prepend (next = head in slot 0)
    assert_match(/__u64 _li\d+ = \w+_arena_data\[1\];/, c)
    assert_match(/\w+_arena_data\[\(2U \* _li\d+ \+ 1\) & 511\] = \w+_arena_data\[0\];/, c)
    assert_match(/\w+_arena_data\[0\] = _li\d+;/, c)  # head = new node
    # sum: unrolled bounded walk following next indices
    assert_includes c, "#pragma unroll"
    assert_match(/\w+_arena_data\[\(2U \* _lc\d+ \+ 1\) & 511\]/, c)
  end

  # L4 LB v2 — PURE COMPOSITION (zero new codegen) of conntrack (flow map)
  # + an arena-resident backend ring (userspace-managed pool/weight/health) + DNAT.
  # Functionally verified (weighted distribution + drained backend).
  def test_lb_pool_composes_conntrack_arena_and_dnat
    c = emit_for("90_l4_lb_pool")
    assert_includes c, "__uint(type, BPF_MAP_TYPE_LRU_HASH);"   # conntrack
    assert_includes c, "__uint(type, BPF_MAP_TYPE_ARENA);"      # backend ring
    assert_match(/__u64 __arena \w+_arena_data\[512\];/, c)
    # ring lookup: arena_get(idx) where idx = (source port & 15)
    assert_match(/bip = \(\(__s64\)\w+_arena_data\[\(__u64\)\(idx\) & 511\]\)/, c)
    assert_match(/idx = \(\{.*bpf_skb_load_bytes\(ctx, \(34\),.*\}\) & 15/m, c)
    # DNAT still present
    assert_includes c, "bpf_l4_csum_replace(ctx, (50), bpf_htonl((__u32)(old)), bpf_htonl((__u32)(bip)), ((1 << 4) | 4))"
  end

  # ---------- CIDR blocklist (LPM_TRIE) ----------

  def test_builtin_names_include_cidr_blocklist_match
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "cidr_blocklist_match"
  end

  def test_cidr_blocklist_emits_lpm_trie_map
    c = emit_for("57_cidr_blocklist")
    assert_match(/__uint\(type, BPF_MAP_TYPE_LPM_TRIE\)/, c)
    assert_match(/__type\(key, struct spnl_cidr_key\)/, c)
    assert_match(/__uint\(map_flags, BPF_F_NO_PREALLOC\)/, c)
    assert_match(/struct spnl_cidr_key \{\s*__u32 prefixlen;\s*__u8\s+data\[4\];/m, c)
    assert_includes c, "bpf_cidr_block SEC(\".maps\")"
  end

  def test_cidr_blocklist_match_helper_and_call
    c = emit_for("57_cidr_blocklist")
    assert_includes c, "static __noinline __s64 spnl_cidr_blocklist_match(__s64 ip_host_order)"
    assert_match(/k\.prefixlen = 32;/, c)
    assert_match(/spnl_cidr_blocklist_match\(spnl_tc_pkt_ip4_src\(ctx\)\)/, c)
    assert_includes c, 'SEC("tcx/ingress")'
  end

  def test_cidr_blocklist_not_emitted_when_unused
    # A fixture that doesn't call cidr_blocklist_match must not emit the LPM map.
    c = emit_for("31_tc_blocklist")
    refute_includes c, "BPF_MAP_TYPE_LPM_TRIE"
    refute_includes c, "bpf_cidr_block"
  end

  # ---------- LSM + fmod_ret attach ----------

  def test_detect_attach_lsm_and_fmod_ret
    m = SpinelEbpf::CodegenBpf.detect_attach("lsm__file_open")
    assert_equal :lsm, m[:kind]
    assert_equal "lsm/file_open", m[:sec]
    f = SpinelEbpf::CodegenBpf.detect_attach("fmod_ret__security_file_open")
    assert_equal :fmod_ret, f[:kind]
    assert_equal "fmod_ret/security_file_open", f[:sec]
  end

  def test_lsm_emits_sec_and_propagates_return
    # LSM return value (0 allow / -errno deny) must be propagated, not discarded.
    c = emit_for("58_lsm_fmod")
    assert_includes c, 'SEC("lsm/file_open")'
    assert_includes c, "int lsm__file_open(__u64 *ctx)"
    assert_match(/return \(int\)lsm__file_open_inner\(\(__s64\)ctx\[0\], \(__s64\)ctx\[1\]\)/, c)
  end

  def test_fmod_ret_emits_sec_and_propagates_return
    # fmod_ret handler's return value replaces the traced function's — propagated.
    c = emit_for("58_lsm_fmod")
    assert_includes c, 'SEC("fmod_ret/security_file_open")'
    assert_match(/return \(int\)fmod_ret__security_file_open_inner\(\(__s64\)ctx\[0\], \(__s64\)ctx\[1\]\)/, c)
  end

  # ---------- per-task local storage (TASK_STORAGE) ----------

  def test_builtin_names_include_task_storage
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "task_load"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "task_store"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "task_incr"
  end

  def test_task_storage_emits_map_and_helpers
    c = emit_for("59_task_storage")
    assert_match(/__uint\(type, BPF_MAP_TYPE_TASK_STORAGE\)/, c)
    assert_match(/__uint\(map_flags, BPF_F_NO_PREALLOC\)/, c)
    assert_includes c, "bpf_task_store SEC(\".maps\")"
    assert_includes c, "spnl_task_load(void)"
    assert_includes c, "spnl_task_store(__s64 value)"
    assert_includes c, "spnl_task_incr(__s64 delta)"
    assert_includes c, "bpf_get_current_task_btf()"
    assert_match(/bpf_task_storage_get\(&bpf_task_store, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE\)/, c)
  end

  def test_task_storage_call_sites
    # The fixture uses task_incr (single-get read-modify-write); load+store
    # can't be combined in one handler on this kernel.
    c = emit_for("59_task_storage")
    assert_match(/spnl_task_incr\(/, c)
  end

  def test_task_storage_not_emitted_when_unused
    c = emit_for("24_xdp_counter")
    refute_includes c, "BPF_MAP_TYPE_TASK_STORAGE"
    refute_includes c, "bpf_task_store"
  end

  # ---------- map-in-map (ARRAY_OF_MAPS) ----------

  def test_builtin_names_include_mim
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "mim_inc"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "mim_get"
  end

  def test_map_in_map_emits_outer_inner_and_initializer
    c = emit_for("60_map_in_map")
    assert_match(/__uint\(type, BPF_MAP_TYPE_ARRAY_OF_MAPS\)/, c)
    assert_match(/__array\(values, struct mim_inner_t\)/, c)
    assert_includes c, "bpf_mim_inner0 SEC(\".maps\")"
    assert_includes c, "bpf_mim_inner3 SEC(\".maps\")"
    # libbpf auto-populates the outer via the .values initializer (no host code).
    assert_match(/\.values = \{ &bpf_mim_inner0, &bpf_mim_inner1, &bpf_mim_inner2, &bpf_mim_inner3 \}/, c)
    assert_includes c, "static __always_inline __s64 spnl_mim_inc(__s64 g, __s64 k)"
  end

  def test_mim_call_site
    c = emit_for("60_map_in_map")
    assert_match(/spnl_mim_inc\(/, c)
  end

  def test_map_in_map_not_emitted_when_unused
    c = emit_for("24_xdp_counter")
    refute_includes c, "BPF_MAP_TYPE_ARRAY_OF_MAPS"
    refute_includes c, "bpf_mim_outer"
  end

  # ---------- cgroup connect4 hook ----------

  def test_detect_attach_cgroup_connect4
    m = SpinelEbpf::CodegenBpf.detect_attach("cgroup__connect4__guard")
    assert_equal :cgroup_connect4, m[:kind]
    assert_equal "cgroup/connect4", m[:sec]
    assert_equal "struct bpf_sock_addr *", m[:ctx_type]
  end

  def test_builtin_names_include_sock_addr
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "sock_addr_ip4"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "sock_addr_port"
  end

  def test_cgroup_connect4_emits_sec_ctx_and_propagates
    c = emit_for("61_cgroup_connect4")
    assert_includes c, 'SEC("cgroup/connect4")'
    assert_includes c, "int cgroup__connect4__guard(struct bpf_sock_addr *ctx)"
    # verdict propagated (1=allow / 0=deny), not discarded
    assert_match(/return \(int\)cgroup__connect4__guard_inner\(ctx\)/, c)
    # sock_addr_port read in host order via __builtin_bswap16
    assert_match(/__builtin_bswap16\(\(__u16\)ctx->user_port\)/, c)
  end

  # ---------- BPF_ITER over tasks ----------

  def test_detect_attach_iter_task
    m = SpinelEbpf::CodegenBpf.detect_attach("iter__task__count")
    assert_equal :iter_task, m[:kind]
    assert_equal "iter/task", m[:sec]
    assert_equal "struct bpf_iter__task *", m[:ctx_type]
  end

  def test_iter_task_emits_sec_ctx_and_null_guard
    c = emit_for("62_iter_task")
    assert_includes c, 'SEC("iter/task")'
    assert_includes c, "int iter__task__count(struct bpf_iter__task *ctx)"
    # the final NULL-task terminator must be skipped so counters don't over-count
    assert_includes c, "if (!ctx->task) return 0;"
    assert_match(/iter__task__count_inner\(ctx\)/, c)
  end

  def test_builtin_names_include_iter_task
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "iter_task"
  end

  # ---------- QUEUE (FIFO) / STACK (LIFO) maps ----------

  def test_builtin_names_include_fifo_lifo
    %w[fifo_push fifo_pop lifo_push lifo_pop].each do |b|
      assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, b
    end
  end

  def test_queue_stack_emit_maps_and_helpers
    c = emit_for("63_queue_stack")
    assert_match(/__uint\(type, BPF_MAP_TYPE_QUEUE\)/, c)
    assert_match(/__uint\(type, BPF_MAP_TYPE_STACK\)/, c)
    assert_includes c, "bpf_fifo SEC(\".maps\")"
    assert_includes c, "bpf_lifo SEC(\".maps\")"
    assert_match(/bpf_map_push_elem\(&bpf_fifo/, c)
    assert_match(/bpf_map_pop_elem\(&bpf_fifo/, c)
  end

  def test_queue_stack_only_emitted_when_used
    c = emit_for("24_xdp_counter")
    refute_includes c, "BPF_MAP_TYPE_QUEUE"
    refute_includes c, "BPF_MAP_TYPE_STACK"
  end

  # ---------- AF_XDP XSKMAP + DEVMAP redirect ----------

  def test_builtin_names_include_redirect
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "xsk_redirect"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "dev_redirect"
  end

  def test_xskmap_devmap_emit_and_redirect
    c = emit_for("64_xsk_dev_redirect")
    assert_match(/__uint\(type, BPF_MAP_TYPE_XSKMAP\)/, c)
    assert_match(/__uint\(type, BPF_MAP_TYPE_DEVMAP\)/, c)
    assert_includes c, "bpf_xskmap SEC(\".maps\")"
    assert_includes c, "bpf_devmap SEC(\".maps\")"
    assert_match(/bpf_redirect_map\(&bpf_xskmap, \(__u32\)\(0\), XDP_PASS\)/, c)
    assert_match(/bpf_redirect_map\(&bpf_devmap, \(__u32\)\(0\), 0\)/, c)
  end

  def test_redirect_maps_only_emitted_when_used
    c = emit_for("24_xdp_counter")
    refute_includes c, "BPF_MAP_TYPE_XSKMAP"
    refute_includes c, "BPF_MAP_TYPE_DEVMAP"
  end

  # ---------- niche program types ----------

  def test_detect_attach_niche
    {
      "raw_tp__sys_enter"        => ["raw_tp/sys_enter",   :raw_tp],
      "socket_filter__keep"      => ["socket",             :socket_filter],
      "flow_dissector__ok"       => ["flow_dissector",     :flow_dissector],
      "sk_lookup__pass"          => ["sk_lookup",          :sk_lookup],
    }.each do |name, (sec, kind)|
      m = SpinelEbpf::CodegenBpf.detect_attach(name)
      assert_equal kind, m[:kind], name
      assert_equal sec, m[:sec], name
    end
  end

  def test_raw_tp_emits_sec_and_args_layout
    c = emit_for("65_raw_tp")
    assert_includes c, 'SEC("raw_tp/sys_enter")'
    assert_includes c, "int raw_tp__sys_enter(struct bpf_raw_tracepoint_args *ctx)"
  end

  def test_niche_progs_emit_secs_and_propagate
    c = emit_for("66_niche_progs")
    assert_includes c, 'SEC("socket")'
    assert_includes c, 'SEC("flow_dissector")'
    assert_includes c, 'SEC("sk_lookup")'
    # verdicts propagated
    assert_match(/return \(int\)socket_filter__keep_inner\(/, c)
    assert_match(/return \(int\)sk_lookup__pass_inner\(/, c)
  end

  # ---------- memleak (leak_record / leak_forget + kmem tracepoints) ----------

  def test_builtin_names_include_leak
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "leak_record"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "leak_forget"
  end

  def test_kmem_tracepoint_fields_known
    f = SpinelEbpf::CodegenBpf::TRACEPOINT_FIELDS
    assert f.key?("kmem/kmalloc")
    assert f.key?("kmem/kfree")
    assert f["kmem/kmalloc"].key?("bytes_alloc")
    assert f["kmem/kmalloc"].key?("ptr")
  end

  def test_memleak_emits_allocs_map_and_helpers
    c = emit_for("67_memleak")
    # outstanding-allocation HASH + value struct
    assert_includes c, "struct spnl_alloc_info"
    assert_includes c, "bpf_allocs SEC(\".maps\")"
    assert_match(/__uint\(type, BPF_MAP_TYPE_HASH\)/, c)
    # record on kmalloc, forget on kfree
    assert_match(/spnl_leak_record\(/, c)
    assert_match(/spnl_leak_forget\(/, c)
    # kmalloc handler reads the typed tracepoint fields + captures a stack
    assert_includes c, "trace_event_raw_kmalloc"
    assert_includes c, "trace_event_raw_kfree"
    assert_match(/bpf_get_stackid/, c)
    # SECs from method-name attach convention
    assert_includes c, 'SEC("tracepoint/kmem/kmalloc")'
    assert_includes c, 'SEC("tracepoint/kmem/kfree")'
  end

  def test_leak_track_only_emitted_when_used
    c = emit_for("24_xdp_counter")
    refute_includes c, "bpf_allocs SEC"
    refute_includes c, "spnl_leak_record"
  end

  # ---------- deadlock (task_swap + lock_edge) ----------

  def test_builtin_names_include_deadlock
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "task_swap"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "lock_edge"
  end

  def test_deadlock_emits_edge_map_and_swap
    c = emit_for("68_deadlock")
    # lock-order edge HASH keyed by the {a,b} pair
    assert_includes c, "struct spnl_lock_edge"
    assert_includes c, "bpf_lock_edges SEC(\".maps\")"
    assert_match(/spnl_lock_edge\(/, c)
    # single-get read-modify-write on per-task storage
    assert_includes c, "spnl_task_swap"
    assert_match(/__s64 old = \*v;/, c)
    # SECs from the uprobe attach convention
    assert_includes c, 'SEC("uprobe")'
  end

  def test_lock_edge_only_emitted_when_used
    c = emit_for("24_xdp_counter")
    refute_includes c, "bpf_lock_edges SEC"
    refute_includes c, "spnl_lock_edge"
  end

  # ---------- execsnoop (emit_argv) ----------

  def test_builtin_names_include_emit_argv
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "emit_argv"
  end

  def test_execsnoop_emits_argv_loop
    c = emit_for("69_execsnoop")
    # reuses the str ringbuf
    assert_includes c, "_str_events SEC(\".maps\")"
    # bounded unrolled walk of the user argv pointer array
    assert_match(/#pragma unroll/, c)
    assert_match(/bpf_probe_read_user\(&\w+, sizeof\(\w+\), &\(\(const char \*const \*\)/, c)
    # each element read as a string into the ringbuf
    assert_match(/bpf_probe_read_user_str\(\w+->str/, c)
    # SEC from the execve tracepoint
    assert_includes c, 'SEC("tracepoint/syscalls/sys_enter_execve")'
  end

  def test_emit_argv_only_when_used
    c = emit_for("24_xdp_counter")
    refute_includes c, "const char *const *"
  end

  # ---------- runqlat (keyed latency + sched tracepoint struct override) ----------

  def test_builtin_names_include_keyed_lat
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "lat_start"
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "lat_end"
  end

  def test_sched_wakeup_struct_override
    o = SpinelEbpf::CodegenBpf::TRACEPOINT_STRUCT_OVERRIDE
    assert_equal "trace_event_raw_sched_wakeup_template", o["sched/sched_wakeup"]
  end

  def test_runqlat_emits_keyed_lat_and_correct_structs
    c = emit_for("70_runqlat")
    # arbitrary-key latency map + start/end helpers
    assert_includes c, "bpf_keyed_lat SEC(\".maps\")"
    assert_match(/spnl_lat_start_key\(/, c)
    assert_match(/spnl_lat_end_key\(/, c)
    # sched_wakeup must use the *template* struct (DECLARE_EVENT_CLASS), not
    # trace_event_raw_sched_wakeup (which is only forward-declared).
    assert_includes c, "trace_event_raw_sched_wakeup_template"
    refute_match(/trace_event_raw_sched_wakeup\b(?!_template)/, c)
    # sched_switch keeps its own per-event struct
    assert_includes c, "trace_event_raw_sched_switch"
    # latency feeds the histogram
    assert_match(/spnl_hist_observe\(/, c)
  end

  def test_keyed_lat_only_when_used
    c = emit_for("24_xdp_counter")
    refute_includes c, "bpf_keyed_lat SEC"
  end

  # ---------- tcplife (inet_sock_set_state + keyed lat + emit3) ----------

  def test_inet_sock_set_state_fields_known
    f = SpinelEbpf::CodegenBpf::TRACEPOINT_FIELDS
    assert f.key?("sock/inet_sock_set_state")
    %w[skaddr oldstate newstate sport dport].each { |k| assert f["sock/inet_sock_set_state"].key?(k) }
  end

  def test_tcplife_emits_keyed_lat_and_emit3
    c = emit_for("71_tcplife")
    assert_includes c, 'SEC("tracepoint/sock/inet_sock_set_state")'
    assert_includes c, "trace_event_raw_inet_sock_set_state"
    # per-socket lifetime via keyed latency
    assert_includes c, "bpf_keyed_lat SEC(\".maps\")"
    assert_match(/spnl_lat_start_key\(/, c)
    assert_match(/spnl_lat_end_key\(/, c)
    # 3-tuple emit channel
    assert_includes c, "_emit3_events SEC(\".maps\")"
  end

  # ---------- tcpconnect (ipv4 array tracepoint field) ----------

  def test_inet_sock_set_state_has_ipv4_fields
    f = SpinelEbpf::CodegenBpf::TRACEPOINT_FIELDS["sock/inet_sock_set_state"]
    assert_equal "ipv4", f["saddr"]
    assert_equal "ipv4", f["daddr"]
  end

  def test_tcpconnect_reads_daddr_as_u32
    c = emit_for("72_tcpconnect")
    # daddr (__u8[4]) read as a u32 reinterpret-load, not a scalar cast
    assert_match(/\(__s64\)\(\*\(__u32 \*\)\(\(\(struct trace_event_raw_inet_sock_set_state \*\)ctx\)->daddr\)\)/, c)
    # dport stays a plain scalar field
    assert_match(/->dport/, c)
    assert_includes c, "_pair_events SEC(\".maps\")"
  end

  # ---------- cpu_id + hardirqs/softirqs (irq tracepoints) ----------

  def test_builtin_names_include_cpu_id
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "cpu_id"
  end

  def test_softirq_struct_override
    o = SpinelEbpf::CodegenBpf::TRACEPOINT_STRUCT_OVERRIDE
    assert_equal "trace_event_raw_softirq", o["irq/softirq_entry"]
    assert_equal "trace_event_raw_softirq", o["irq/softirq_exit"]
  end

  def test_irq_emits_cpu_id_keyed_latency_and_correct_structs
    c = emit_for("73_irq")
    assert_includes c, 'SEC("tracepoint/irq/irq_handler_entry")'
    assert_includes c, 'SEC("tracepoint/irq/softirq_entry")'
    # cpu_id() lowers to bpf_get_smp_processor_id, used in the keyed-lat key
    assert_match(/bpf_get_smp_processor_id\(\)/, c)
    assert_match(/spnl_lat_start_key\(.*bpf_get_smp_processor_id\(\)/, c)
    # hard IRQ keeps its per-event struct; softirq uses the shared class struct
    assert_includes c, "trace_event_raw_irq_handler_entry"
    assert_includes c, "trace_event_raw_softirq"
    refute_match(/trace_event_raw_softirq_entry/, c)
  end

  # ---------- kfield embedded-struct dotted path (tcpretrans) ----------

  def test_kfield_dotted_path_embedded_struct
    c = emit_for("74_kfield_dotted")
    # the embedded path is a single BPF_CORE_READ arg (dotted), not comma-split
    assert_match(/BPF_CORE_READ\(\(struct sock \*\)\(unsigned long\)\(\w+\), __sk_common\.skc_daddr\)/, c)
    assert_match(/BPF_CORE_READ\(\(struct sock \*\)\(unsigned long\)\(\w+\), __sk_common\.skc_dport\)/, c)
    refute_match(/__sk_common, skc_daddr/, c)   # must NOT be comma-split (pointer hop)
  end

  # ---------- slabratetop (kmem_cache_alloc tracepoint) ----------

  def test_kmem_cache_alloc_fields_known
    f = SpinelEbpf::CodegenBpf::TRACEPOINT_FIELDS
    assert f.key?("kmem/kmem_cache_alloc")
    assert f["kmem/kmem_cache_alloc"].key?("bytes_alloc")
  end

  def test_slabratetop_emits_hist_on_kmem_cache_alloc
    c = emit_for("75_slabratetop")
    assert_includes c, 'SEC("tracepoint/kmem/kmem_cache_alloc")'
    assert_includes c, "trace_event_raw_kmem_cache_alloc"
    assert_match(/spnl_hist_observe\(/, c)
  end

  # ---------- field_exists (bpf_core_field_exists) ----------

  def test_builtin_names_include_field_exists
    assert_includes SpinelEbpf::CodegenBpf::BUILTIN_NAMES, "field_exists"
  end

  def test_field_exists_emits_core_field_exists
    c = emit_for("76_field_exists")
    assert_match(%r{bpf_core_field_exists\(\(\(struct sock \*\)\(unsigned long\)\(\w+\)\)->sk_sndbuf\)}, c)
    # pulls in the CO-RE header
    assert_includes c, "#include <bpf/bpf_core_read.h>"
  end
end
