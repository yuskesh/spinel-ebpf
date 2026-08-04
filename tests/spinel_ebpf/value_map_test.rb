# frozen_string_literal: true
#
# The contract test for type-driven derivations (value maps).
#
# One property is defended here: **a name put on a value from a closed set must
# be checkable against something**. A wrong mapping is invisible downstream --
# rendering `error=2` as "EPERM" and rendering `oldstate=2` as "SYN_RECV" both
# produce a plausible-looking name -- so this is the only place it can be caught.
# It is the record -> span side of the same silent error that the kernel-side
# gates close.
#
# Three layers:
#   (1) declaration and generated artifact agree (runs on the host)
#   (2) **agreement with the authority** -- checked against the BTF enum of the
#       running kernel (only where BTF is available)
#   (3) the generator's refusals (negative controls) -- does building a broken
#       declaration die
require "minitest/autorun"
require "json"
require "open3"
require "tmpdir"
require "fileutils"
require_relative "../../src/spinel_ebpf/capabilities"

class ValueMapTest < Minitest::Test
  ROOT       = File.expand_path("../..", __dir__)
  SCHEMA_H   = File.join(ROOT, "src/codegen_c/record_schema.h")
  GEN_C      = File.join(ROOT, "tools/gen_record_mirror.c")
  MIRROR_H   = File.join(ROOT, "src/runtime/otlp/record_mirror_gen.h")
  AGENT_C    = File.join(ROOT, "src/runtime/otlp/otlp_agent.c")

  def maps = SpinelEbpf::Capabilities.record_value_maps

  # ------------------------------------------------------------ (1) declaration

  def test_every_declared_map_is_named_by_a_property
    used = SpinelEbpf::Capabilities.record_channels.flat_map { |c|
      Array(c.dig(:consumer, :properties)).map { |p| p[:value_map] }
    }.compact.uniq
    assert_equal maps.map { |m| m[:id] }.sort, used.sort,
                 "the declared value maps and the ones actually used do not match " \
                 "(a type with no consumer is a dead table = exactly what this layer replaces)"
  end

  def test_every_map_declares_where_its_names_come_from
    refute_empty maps, "not a single value map is declared"
    maps.each do |m|
      refute_empty m[:authority].to_s, "#{m[:id]}: authority (where the names come from) is empty"
      refute_empty m[:unknown].to_s,   "#{m[:id]}: unknown (how an unnamed value renders) is empty"
      assert_equal true, m[:arch_invariant],
                   "#{m[:id]}: a table that is not architecture-invariant cannot be baked into a generated artifact"
      refute_empty Array(m[:values]), "#{m[:id]}: no values"
    end
  end

  # `unknown` must not look like a name. It is either a form that keeps the
  # number (one %ld) or a documented answer in its own right (conn's "other").
  def test_unknown_rendering_is_either_a_documented_literal_or_keeps_the_number
    maps.each do |m|
      u = m[:unknown].to_s
      convs = u.scan(/%[^%]/).map { |c| c }
      assert_operator u.scan("%ld").length, :<=, 1, "#{m[:id]}: unknown carries more than one %ld"
      assert_empty (convs - ["%l"]), "#{m[:id]}: unknown uses a conversion other than %ld (#{u})"
    end
    tcp = maps.find { |m| m[:id] == "tcp_state" }
    assert_includes tcp[:unknown], "%ld",
                    "an unknown value of a kernel enum must **keep the number** (borrowing a name would be a lie)"
  end

  def test_values_are_unique_in_both_directions
    maps.each do |m|
      vs = Array(m[:values])
      assert_equal vs.map { |v| v[:value] }.uniq.length, vs.length, "#{m[:id]}: one value with two names"
      assert_equal vs.map { |v| v[:name] }.uniq.length,  vs.length, "#{m[:id]}: one name on two values"
    end
  end

  # ------------------------------- (1b) declaration -> generated artifact -> runtime

  # The implementation of a type-driven derivation is a **generated artifact**,
  # not something hand-written in the runtime. Once that breaks there are two
  # tables: "the declared one" and "the one actually consulted".
  def test_lookup_is_generated_not_hand_written
    gen = File.read(MIRROR_H)
    agent = File.read(AGENT_C)
    maps.each do |m|
      assert_includes gen, "static inline void spnl_valmap_#{m[:id]}(long v, char *out, int cap)",
                      "#{m[:id]}: the lookup is not in the generated header"
      Array(m[:values]).each do |v|
        assert_includes gen, "case #{v[:value]}L: name = \"#{v[:name]}\"; break;",
                        "#{m[:id]}: declared #{v[:value]}=#{v[:name]} is missing from the generated switch"
      end
      refute_match(/^\s*(static\s+)?\w[\w \*]*\bspnl_valmap_#{Regexp.escape(m[:id])}\s*\(/, agent,
                   "#{m[:id]}: the runtime carries a hand-written lookup (there are two tables)")
    end
  end

  # The same invariant the other derived values carry, extended to type-driven
  # ones: **the value Ruby sees and the value that reaches the span are outputs
  # of the same function**. Pin that the accessor and the span builder call the
  # same spnl_valmap_*, from both sides.
  def test_accessor_and_span_builder_call_the_same_map
    gen     = File.read(MIRROR_H)
    builder = File.read(AGENT_C)[/static int conn_fill_span\(.*?\n\}\n/m]
    refute_nil builder, "conn_fill_span() could not be read"
    props = SpinelEbpf::Capabilities.record_properties("conn").select { |p| p[:value_map] }
    refute_empty props, "conn has no type-driven property"
    props.each do |p|
      acc = gen[/const char \*spnl_rec_conn_#{Regexp.escape(p[:name])}\(int i\) \{.*?\n\}\n/m]
      refute_nil acc, "the accessor spnl_rec_conn_#{p[:name]}() was not generated"
      assert_includes acc, "spnl_valmap_#{p[:value_map]}(",
                      "the accessor does not go through the declared value map"
      assert_includes builder, "spnl_valmap_#{p[:value_map]}(",
                      "the span builder does not go through the same value map as ev.#{p[:name]}"
    end
  end

  # For a type-driven derivation the cap rule is **computable** (a closed set
  # really does have a longest member, and the rendering of an unnamed value
  # really does have a maximum width). Check the declaration is at least that.
  def test_declared_cap_covers_the_closed_set_and_the_unnamed_rendering
    widths = { "__u8" => 3, "__u16" => 5, "__u32" => 10, "__u64" => 20,
               "__s8" => 4, "__s16" => 6, "__s32" => 11, "__s64" => 20 }
    SpinelEbpf::Capabilities.record_channels.each do |c|
      Array(c.dig(:consumer, :properties)).each do |p|
        next unless p[:value_map]
        m     = SpinelEbpf::Capabilities.record_value_map(p[:value_map])
        field = p[:source].to_s.sub(/\s*->.*\z/, "")
        f     = c[:fields].find { |x| x[:name] == field }
        refute_nil f, "#{c[:id]}.#{p[:name]}: the source field #{field} is not in the record"
        assert_equal 0, f[:count], "#{c[:id]}.#{p[:name]}: a code must be a single integer"
        dec  = widths[f[:ctype]]
        refute_nil dec, "#{c[:id]}.#{p[:name]}: #{f[:ctype]} is not an integer type"
        need = m[:unknown].to_s.sub("%ld", "9" * dec).length + 1
        Array(m[:values]).each { |v| need = [need, v[:name].to_s.length + 1].max }
        assert_operator p[:cap], :>=, need,
                        "#{c[:id]}.#{p[:name]}: cap #{p[:cap]} does not cover its own closed set (needs #{need})"
      end
    end
  end

  # ------------------------------------- (2) agreement with the authority (BTF)

  BTF_PATH = "/sys/kernel/btf/vmlinux"

  # Collect the enumerators of the ENUM block containing `anchor` out of
  # bpftool's raw dump. If several blocks carry the same anchor, they are
  # required to **agree** ("take the first one" is how an instrument lies).
  def btf_enum_containing(anchor)
    out, st = Open3.capture2e("bpftool", "btf", "dump", "file", BTF_PATH, "format", "raw")
    return nil unless st.success?
    blocks = []
    cur = nil
    out.each_line do |line|
      if line =~ /\A\[\d+\] ENUM /
        blocks << cur if cur
        cur = {}
      elsif cur && line =~ /\A\t'([A-Za-z_][A-Za-z0-9_]*)' val=(-?\d+)/
        cur[$1] = $2.to_i
      elsif line =~ /\A\[\d+\] /
        blocks << cur if cur
        cur = nil
      end
    end
    blocks << cur if cur
    hits = blocks.compact.select { |b| b.key?(anchor) }
    return nil if hits.empty?
    hits.each { |h| assert_equal hits.first, h, "two BTF enums with the same anchor disagree" }
    hits.first
  end

  def skip_without_btf
    skip "BTF authority check needs a running kernel with #{BTF_PATH} + bpftool " \
         "(it does not run on a macOS host -- run it in a Linux container)" unless File.exist?(BTF_PATH)
  end

  # The heart of this file: is the name we declared the name the running kernel
  # uses.
  #   btf_mode "names" -- the table IS the enum: every enumerator (minus
  #                       btf_omit) must be declared with the same value and the
  #                       same name (with the prefix stripped)
  #   btf_mode "keys"  -- the names are this project's, but **the keys are the
  #                       kernel's**: every declared value must really exist in
  #                       the enum
  def test_declared_names_match_the_kernel_enum
    skip_without_btf
    checked = 0
    maps.each do |m|
      next if m[:btf_mode].to_s.empty?
      enum = btf_enum_containing(m[:btf_anchor])
      refute_nil enum, "#{m[:id]}: BTF has no enum containing #{m[:btf_anchor]}"
      prefix = m[:btf_prefix].to_s
      omit   = m[:btf_omit].to_s.split
      declared = Array(m[:values]).to_h { |v| [v[:name], v[:value]] }
      case m[:btf_mode]
      when "names"
        want = enum.reject { |k, _| omit.include?(k) }
                   .to_h { |k, v| [k.sub(/\A#{Regexp.escape(prefix)}/, ""), v] }
        assert_equal want, declared,
                     "#{m[:id]}: the declaration disagrees with the enum of the running kernel " \
                     "(kernel = #{want.inspect})"
      when "keys"
        vals = enum.values.uniq
        declared.each do |name, v|
          assert_includes vals, v,
                          "#{m[:id]}: #{name}=#{v} is not a value in the kernel's #{m[:btf_anchor]} enum"
        end
      else
        flunk "#{m[:id]}: unknown btf_mode #{m[:btf_mode].inspect}"
      end
      checked += 1
    end
    assert_operator checked, :>, 0, "zero value maps were checked against BTF (the test is looking at nothing)"
  end

  # Can the comparator itself see a difference (the instrument's self-diagnosis)?
  # Feed it a declaration with **one deliberate mistake** against a real enum and
  # confirm it comes out unequal. Without this, the green above would mean "not
  # looking" rather than "agrees".
  def test_the_authority_check_detects_a_wrong_name
    skip_without_btf
    enum = btf_enum_containing("TCP_ESTABLISHED")
    refute_nil enum
    want = enum.reject { |k, _| k == "TCP_MAX_STATES" }.to_h { |k, v| [k.sub(/\ATCP_/, ""), v] }
    swapped = want.merge("SYN_SENT" => want["SYN_RECV"], "SYN_RECV" => want["SYN_SENT"])
    refute_equal want, swapped, "a swapped table was judged equal to the right one (the comparator is broken)"
    truncated = want.reject { |k, _| k == "BOUND_INACTIVE" }
    refute_equal want, truncated, "a table missing one entry was judged right"
  end

  # ---------------------------------- (3) the generator's refusals (negative)

  # Build the generator against a broken record_schema.h and see whether it
  # **dies**. Returns [ok(bool), output].
  def build_with_mutated_schema(&mutate)
    Dir.mktmpdir("valmap") do |dir|
      FileUtils.mkdir_p(File.join(dir, "tools"))
      FileUtils.mkdir_p(File.join(dir, "src/codegen_c"))
      FileUtils.cp(GEN_C, File.join(dir, "tools/gen_record_mirror.c"))
      File.write(File.join(dir, "src/codegen_c/record_schema.h"), mutate.call(File.read(SCHEMA_H)))
      bin = File.join(dir, "gen")
      out, st = Open3.capture2e(ENV["CC"] || "cc", "-O2", "-o", bin, File.join(dir, "tools/gen_record_mirror.c"))
      return [false, "compile failed:\n#{out}"] unless st.success?
      # Capture stdout and stderr separately: die() writes to stderr, but by the
      # time it is reached hundreds of lines of generated output are on stdout.
      # Mixed together, the diff of a failed assertion fills up with generated
      # text and "what did it refuse" becomes unreadable (an instrument's
      # legibility is part of the instrument).
      sout, serr, st2 = Open3.capture3(bin)
      [st2.success?, st2.success? ? sout : serr]
    end
  end

  # The instrument's self-diagnosis: unmutated, it must build and run. If this
  # fails, the refusals below mean "it never ran" rather than "it refused".
  def test_unmutated_schema_builds_and_runs
    ok, out = build_with_mutated_schema { |s| s }
    assert ok, "the generator failed on the unmodified declaration:\n#{out}"
    assert_includes out, "spnl_valmap_tcp_state", "no value map in the generated output"
  end

  # A table that differs per architecture cannot be baked into a generated
  # artifact -- baked on one, it renders a **plausible wrong name** on another
  # (measured: syscall 2 = io_submit on aarch64, open on x86_64, fork on
  # i386/arm/ppc/s390x).
  def test_generator_refuses_a_map_that_is_not_architecture_invariant
    ok, out = build_with_mutated_schema { |s|
      s.sub('.arch_invariant = 1,
  .btf_mode       = "names",', '.arch_invariant = 0,
  .btf_mode       = "names",')
    }
    refute ok, "a value map that is not architecture-invariant got through"
    assert_includes out, "architecture-invariant"
    assert_includes out, "syscall 2 = io_submit",
                    "the refusal must cite the measurement behind it"
  end

  def test_generator_refuses_an_undeclared_map
    ok, out = build_with_mutated_schema { |s| s.sub('"tcp_state", "code_to_name"', '"tcp_stat", "code_to_name"') }
    refute ok, "naming a value map that does not exist got through"
    assert_includes out, "names an undeclared value map"
  end

  def test_generator_refuses_a_cap_that_the_closed_set_does_not_fit
    ok, out = build_with_mutated_schema { |s| s.sub('"tcp_state", "code_to_name", 24,', '"tcp_state", "code_to_name", 8,') }
    refute ok, "a cap too small for the closed set got through"
    assert_includes out, "cap smaller than its own closed set"
  end

  def test_generator_refuses_a_code_read_from_an_array_field
    ok, out = build_with_mutated_schema { |s| s.sub('{ "tcp_state", "str", "oldstate", "tcp_state"', '{ "tcp_state", "str", "comm", "tcp_state"') }
    refute ok, "reading an array field as a code got through"
    assert_includes out, "reads an array field"
  end

  def test_generator_refuses_a_map_nobody_uses
    ok, out = build_with_mutated_schema { |s|
      s.sub(/\{ "tcp_state", "str", "oldstate", "tcp_state", "code_to_name", 24,.*?\},\n/m, "")
    }
    refute ok, "a value map nobody uses got through"
    assert_includes out, "named by no derivation"
  end

  def test_generator_refuses_an_unknown_rendering_that_is_not_a_number
    ok, out = build_with_mutated_schema { |s| s.sub('.unknown        = "unnamed(%ld)",', '.unknown        = "unnamed(%s)",') }
    refute ok, "an unknown rendering with a conversion other than %ld got through"
    assert_includes out, "may only use %ld"
  end

  def test_generator_refuses_two_names_for_one_value
    ok, out = build_with_mutated_schema { |s| s.sub('{  2, "SYN_SENT"    }', '{  1, "SYN_SENT"    }') }
    refute ok, "putting two names on one value got through"
    assert_includes out, "two names"
  end
end
