# frozen_string_literal: true
#
# Kernel struct STRING fields -- emit_kfield_str (statement) and
# kfield_str_eq (expression).
#
# Drives the PRODUCTION C codegen (src/codegen_c/spinel_ebpf_cc.c) directly, the
# same binary tools/golden.rb pins. The golden files already lock the exact text;
# what this file locks is the handful of decisions that would be silently wrong
# rather than merely different if someone changed them -- each one measured, with
# the measurement named:
#
#   D2  one source form for both shapes of the last field. Choosing wrong is not
#       a build error, it is eight bytes of pointer read as a string (measured).
#   D3  the compare buffer is literal + NUL + ONE SPARE BYTE. path_eq's exact
#       sizing over-matches here because probe_read_kernel_str truncates silently
#       (measured: a buf[8] compare fires on "spnlabcdef").
#   D4  no hook gate -- measured LOAD_OK in all 24 program types, unlike
#       bpf_d_path.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/kfield_str_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/codegen_bpf"

class KfieldStrTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  GOLD = File.join(ROOT, "tests/golden")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CAP  = SpinelEbpf::Capabilities
  GEN  = SpinelEbpf::CodegenBpf

  # Same preflight as golden.rb / builtin_ctx_gate_test.rb: +x is not enough,
  # build/ is bind-mounted into the container so the binary may be built for the
  # other platform. A working binary prints its usage line with no args.
  def self.runnable?
    return @runnable if defined?(@runnable)
    return @runnable = false unless File.executable?(CC)
    out, err, = Open3.capture3(CC)
    @runnable = "#{out}#{err}".include?("usage:")
  rescue StandardError
    @runnable = false
  end

  def skip_unless_cc
    skip "C codegen binary not runnable on this host" unless self.class.runnable?
  end

  def run_cc(base)
    Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
  end

  def emit(base)
    skip_unless_cc
    out, err, st = run_cc(base)
    assert st.success?, "codegen refused #{base}: #{err}"
    out
  end

  # ---------- D2: one source form, two shapes ----------

  # The .rb says nothing about whether the last field is char[N] or char *, and
  # the emitted C for the two chains is the same call. What differs is only the
  # chain handed to SPNL_KSTR_IS_PTR, i.e. the type -- which is the whole point:
  # the author cannot pick wrong because the author does not pick.
  def test_both_field_shapes_come_from_one_surface
    src = File.read("#{FIX}/133_kfield_str.rb")
    assert_includes src, 'emit_kfield_str(file, "file", "f_path.dentry", "d_name.name")'
    assert_includes src, 'emit_kfield_str(file, "file", "f_path.dentry", "d_sb", "s_id")'

    c = emit("133_kfield_str")
    # pointer-shaped field (dentry->d_name.name is `const unsigned char *`)
    assert_includes c, 'SPNL_KFIELD_STR(_kse5->str, ((struct file *)0)->f_path.dentry->d_name.name, _ksp6, f_path.dentry, d_name.name);'
    # array-shaped field, three hops (super_block->s_id is `char[32]`)
    assert_includes c, 'SPNL_KFIELD_STR(_kse7->str, ((struct file *)0)->f_path.dentry->d_sb->s_id, _ksp8, f_path.dentry, d_sb, s_id);'
  end

  # The dispatch itself: a type question, answered at compile time, with both
  # branches present so clang can type-check them (measured: it does).
  def test_shape_is_decided_by_the_c_type_system
    c = emit("133_kfield_str")
    assert_includes c, "#define SPNL_KSTR_IS_PTR(chain)"
    assert_includes c, "__builtin_types_compatible_p(__typeof__(chain), __typeof__(&(chain)[0]))"
    assert_includes c, "__builtin_choose_expr(SPNL_KSTR_IS_PTR(chain)"
    # the pointer branch fetches the pointer first, the array branch reads at the field
    assert_includes c, "bpf_probe_read_kernel_str((dst), sizeof(dst),"
    assert_includes c, "BPF_CORE_READ_STR_INTO(&(dst), src, __VA_ARGS__)"
  end

  # The chain must be split exactly the way kfield splits it: a comma is a
  # pointer hop, a dot is an embedded member. If these two ever disagree the same
  # Ruby text would mean different things for the scalar and string builtins.
  def test_hop_convention_matches_kfield
    c = emit("133_kfield_str")
    # `f_path.dentry` stays one accessor (embedded `.` then the hop) and `d_sb`,
    # `s_id` are separate accessors -> `->` in the type chain, `,` in the read.
    assert_includes c, "((struct file *)0)->f_path.dentry->d_sb->s_id"
    assert_includes c, "_ksp8, f_path.dentry, d_sb, s_id"
    kf = emit("56_kfield")
    assert_includes kf, "BPF_CORE_READ((struct sock *)(unsigned long)(sk), sk_sndbuf)"
  end

  # Both asserts carry the call the AUTHOR wrote, not a fragment of the expansion:
  # one refuses a chain that is not indexable at all (a scalar field = kfield's
  # job), the other a chain whose elements are not bytes (it stopped on a struct
  # pointer). Both messages were measured from clang's own diagnostics.
  def test_shape_check_names_the_ruby_call
    c = emit("133_kfield_str")
    assert_includes c, "#define SPNL_KSTR_CHECK(chain, msg)"
    assert_includes c, "__builtin_classify_type(chain) == __builtin_classify_type((char *)0), msg"
    assert_includes c, "sizeof((chain)[0]) == 1, msg"
    assert_includes c, 'SPNL_KSTR_CHECK(((struct file *)0)->f_path.dentry->d_name.name,'
    assert_includes c, 'emit_kfield_str(file, \\"file\\", \\"f_path.dentry\\", \\"d_name.name\\"): ' \
                       "the last field must be characters"
  end

  # The negative fixture is the D2 guarantee as a permanent gate: the codegen
  # emits C for it (so it has a golden) and clang refuses that C (so its committed
  # compile status is clang_fail). Turning `ok` means the check was weakened.
  def test_wrong_shape_fixture_is_pinned_as_a_compile_failure
    assert_path_exists "#{GOLD}/135_kfield_str_wrong_shape.bpf.c"
    row = File.readlines("#{GOLD}/compile_status.tsv")
              .find { |l| l.start_with?("135_kfield_str_wrong_shape\t") }
    refute_nil row, "135 missing from the compile baseline"
    assert_equal "clang_fail", row.split("\t")[1]
    # ...and the C it refuses is the one-hop-short chain, not something else.
    c = emit("135_kfield_str_wrong_shape")
    assert_includes c, "SPNL_KSTR_CHECK(((struct file *)0)->f_path.dentry,"
  end

  # ---------- D3: the compare buffer ----------

  # 15-char literal -> 15 + NUL + 1 spare = 17 -> rounded to 24, and the guard is
  # ret == 16. NOT path_eq's 15 + NUL = 16: that buffer cannot tell "the value is
  # exactly this" from "the value starts with this and is longer".
  def test_compare_buffer_has_a_spare_byte_and_guards_on_the_exact_length
    c = emit("134_kfield_str_eq")
    lit = "spnl_target.txt"
    assert_equal 15, lit.length
    assert_includes c, "char _ksb1[24] = {0};"
    assert_includes c, "__s64 _ksm1 = (_ksr2 == 16);"
    refute_includes c, "char _ksb1[16] = {0};", "buffer sized to literal+NUL is path_eq's rule, which over-matches here (measured)"
    lit.each_char.with_index { |ch, i| assert_includes c, "(_ksb1[#{i}] == #{ch.ord});" }
  end

  # A literal whose length+1 lands exactly on the 8-byte rounding is the case
  # where path_eq's rule and this one differ in the emitted size, and it is the
  # case that was measured firing on the wrong file.
  def test_rounding_still_leaves_the_spare_byte_at_the_dangerous_length
    seven = "spnlabc"
    assert_equal 8, seven.length + 1, "the length where path_eq's rounding leaves no slack"
    # (len + 2) rounded up to 8 must exceed (len + 1) rounded up to 8.
    round8 = ->(n) { ((n + 7) / 8) * 8 }
    assert_operator round8.call(seven.length + 2), :>, round8.call(seven.length + 1)
  end

  # ---------- D4: no hook gate ----------

  # bpf_d_path is kernel-gated and the path builtins die at compile time outside
  # the measured hooks. bpf_probe_read_kernel_str is not, so kfield_str works in
  # a kprobe -- which is exactly where the full path is unreachable.
  def test_no_dpath_gate_so_it_works_where_path_eq_cannot
    src = File.read("#{FIX}/134_kfield_str_eq.rb")
    assert_includes src, "def kprobe__vfs_read"
    c = emit("134_kfield_str_eq")
    assert_includes c, 'SEC("kprobe/vfs_read")'
    refute_includes c, "bpf_d_path"
    # and the registry agrees: these two are not context-gated builtins.
    assert_nil CAP.gate_for("emit_kfield_str")
    assert_nil CAP.gate_for("kfield_str_eq")
    refute_includes CAP::DPATH_OK_SECS, "kprobe/vfs_read"
  end

  # ---------- surface / affordance ----------

  def test_registered_as_builtins_in_the_kernel_field_family
    %w[emit_kfield_str kfield_str_eq].each do |b|
      assert_includes GEN::BUILTIN_NAMES, b
      assert_equal :observability, CAP.domain_of(b), "same family as kfield (CO-RE field read), not the d_path selectors"
      sig = CAP.signature_for(b)
      assert_equal :variadic, sig[:arity], "the hop count is up to the author"
      refute sig[:opaque]
    end
    # the emit form is a str-ringbuf emitter, and both are cross-linked to kfield
    assert_includes CAP.related_for("emit_kfield_str"), "emit_comm"
    assert_includes CAP.related_for("emit_kfield_str"), "kfield"
    assert_includes CAP.related_for("kfield_str_eq"), "kfield"
    assert_includes CAP.related_for("kfield"), "emit_kfield_str"
  end

  # The one genuinely ambiguous thing about the eq form (every argument is a
  # string) has to be visible without reading the codegen.
  def test_affordance_states_that_the_last_string_is_the_literal
    e = CAP.builtin_entry("kfield_str_eq")
    assert_includes e[:summary], "last string argument is the value compared against"
    assert_includes e[:summary], "predicate"
    assert_includes e[:summary], "use-neutral"
    assert_equal 'kfield_str_eq(file, "file", "f_path.dentry", "d_name.name", "secret.txt")', e[:example]
    assert_equal 'emit_kfield_str(file, "file", "f_path.dentry", "d_name.name")',
                 CAP.builtin_entry("emit_kfield_str")[:example]
  end

  # ...and the codegen says the same thing when it refuses (the fixture that has
  # no field path at all).
  def test_arity_refusal_spells_out_the_shape
    skip_unless_cc
    _out, err, st = run_cc("136_kfield_str_arity")
    refute st.success?, "codegen accepted kfield_str_eq with no field path"
    assert_includes err, "kfield_str_eq expects"
    assert_includes err, "the LAST string is the value to compare"
    assert_includes err, "comma = pointer hop, dot = embedded member"
    # refused => no golden
    refute_path_exists "#{GOLD}/136_kfield_str_arity.bpf.c"
  end

  # ---------- the preamble is pay-per-use ----------

  def test_preamble_only_when_used
    with = emit("133_kfield_str")
    assert_includes with, "#define SPNL_KFIELD_STR("
    without = emit("56_kfield")
    refute_includes without, "SPNL_KFIELD_STR", "kfield alone must not drag in the string preamble"
    # the string form still needs the header kfield needs
    assert_includes with, "#include <bpf/bpf_core_read.h>"
  end

  # The emit form rides the existing per-unit string channel (no new ringbuf) and
  # accounts a full ring like every other emit.
  def test_emit_form_uses_the_shared_string_channel
    c = emit("133_kfield_str")
    assert_includes c, "struct u_133_kfield_str_str_event {"
    assert_includes c, "bpf_ringbuf_reserve(&u_133_kfield_str_str_events"
    assert_includes c, "} else spnl_lost_inc();"
    # zeroed first, so a faulting read emits an empty string rather than a stale one
    assert_includes c, "__builtin_memset(_kse5->str, 0, sizeof(_kse5->str));"
  end
end
