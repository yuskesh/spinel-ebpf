# frozen_string_literal: true
#
# The `clang -target bpf` argv is pinned, not inherited from the build host.
#
# Measured: with no -mcpu, clang 19 emits ISA v1 and clang 22 emits v3 for the
# SAME source (111/116 goldens differ in instructions), and the recorded paths
# made two builds of one probe from two output directories produce different
# .bpf.o bytes. The .bpf.o ships verbatim inside the generated skeleton that
# `--emit-sources` hands to a downstream builder, so both were shipping.
#
# bin/spinel-ebpf is a script with no `if __FILE__ == $0` guard, so it cannot be
# required. The pinning lives in two pure functions and two constants that form
# one contiguous region; this test evaluates exactly that region (with a stand-in
# PROJECT_ROOT) and asserts on the argv it builds -- behaviour, not a source grep.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/bpf_build_flags_test.rb

require "minitest/autorun"
require "tmpdir"

class BpfBuildFlagsTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  CLI  = File.join(ROOT, "bin/spinel-ebpf")

  # The contiguous slice: BPF_ISA_BASELINE .. the `def bpf_strip_maybe!` that
  # follows it (only comments sit between the two). Anchored on both ends so a
  # refactor that moves them apart fails here loudly instead of silently testing
  # nothing.
  def self.flag_module
    return @flag_module if defined?(@flag_module)
    src   = File.read(CLI)
    first = src.index('BPF_ISA_BASELINE = ')
    last  = src.index("def bpf_strip_maybe!")
    raise "bin/spinel-ebpf: BPF build-flag region not found (first=#{first.inspect} last=#{last.inspect})" \
      if first.nil? || last.nil? || last <= first
    m = Module.new
    m.const_set(:PROJECT_ROOT, "/repo/root")
    m.module_eval(src[first...last], CLI, src[0...first].count("\n") + 1)
    m.send(:module_function, :bpf_clang_argv, :bpf_repro_flags)
    @flag_module = m
  end

  def argv_for(body, build_dir: "/repo/root/build")
    Dir.mktmpdir do |dir|
      bpf_c = File.join(dir, "p.bpf.c")
      File.write(bpf_c, body)
      return self.class.flag_module.bpf_clang_argv("clang", bpf_c, "#{build_dir}/p.bpf.o", build_dir)
    end
  end

  # --- ISA baseline -------------------------------------------------------

  def test_isa_is_always_pinned_never_left_to_the_host
    argv = argv_for("int main(void) { return 0; }")
    assert_equal 1, argv.count { |a| a.start_with?("-mcpu=") },
                 "exactly one -mcpu must be present; leaving it out lets clang/the build host choose"
    assert_includes argv, "-mcpu=v1"
  end

  def test_arena_source_is_the_only_thing_that_raises_the_isa
    argv = argv_for("#define __arena __attribute__((address_space(1)))\nint x;\n")
    assert_includes argv, "-mcpu=v3"
    refute_includes argv, "-mcpu=v1"
  end

  def test_isa_choice_depends_on_the_source_not_the_environment
    body = "int main(void) { return 0; }"
    a = argv_for(body, build_dir: "/tmp/one")
    b = argv_for(body, build_dir: "/somewhere/else/two")
    assert_equal a.grep(/-mcpu=/), b.grep(/-mcpu=/)
  end

  # --- reproducibility flags ----------------------------------------------

  def test_recorded_paths_are_normalised
    argv = argv_for("int x;", build_dir: "/tmp/out")
    assert_includes argv, "-fdebug-prefix-map=/tmp/out=."
    assert_includes argv, "-fdebug-prefix-map=/repo/root=."
    assert_includes argv, "-fdebug-compilation-dir"
    assert_includes argv, "-fno-ident"
    # build_dir first: clang applies the first matching prefix, so a build dir
    # nested under the repo root must still collapse to "./<base>.bpf.c" rather
    # than "./build/<base>.bpf.c" -- that is what makes -o irrelevant to the bytes.
    flags = argv.grep(/^-fdebug-prefix-map=/)
    assert_equal "-fdebug-prefix-map=/tmp/out=.", flags.first
  end

  def test_build_dir_is_expanded_so_a_relative_o_still_maps
    argv = self.class.flag_module.bpf_clang_argv("clang", "/nonexistent.bpf.c", "b/p.bpf.o", "b")
    assert_includes argv, "-fdebug-prefix-map=#{File.expand_path("b")}=."
  end

  # --- the shared-argv invariant --------------------------------------------

  def test_compile_and_check_drive_the_same_builder
    src = File.read(CLI)
    calls = src.scan(/bpf_clang_argv\(/).size
    assert_operator calls, :>=, 3,
                    "expected the definition plus both call sites (build_binary and check) " \
                    "to go through bpf_clang_argv"
  end

  # --- the strip is opt-in, and says why when it cannot run ----------------

  def test_strip_is_opt_in_and_fails_loud
    src = File.read(CLI)
    assert_match(/ENV\["SPNL_BPF_STRIP"\] == "1"/, src,
                 "stripping must be opt-in: 'strip when llvm-strip happens to exist' " \
                 "reintroduces the host dependence this change removes")
    strip_body = src[src.index("def bpf_strip_maybe!")..]
    strip_body = strip_body[0, strip_body.index("\nend\n")]
    assert_match(/abort/, strip_body)
    assert_match(/why:/,  strip_body)
    assert_match(/fix:/,  strip_body)
    # DWARF only: .BTF / .BTF.ext must survive or CO-RE relocation is lost.
    assert_match(/"-g"/, strip_body)
    refute_match(/strip-all|--strip-unneeded/, strip_body)
  end
end
