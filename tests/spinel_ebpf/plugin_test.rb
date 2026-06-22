# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/plugin_test.rb
#
# Plugin declaration / discovery / manifest / ABI.

require "minitest/autorun"
require "spinel_ebpf/plugin"
require "spinel_ebpf/partition"

class PluginTest < Minitest::Test
  PL  = SpinelEbpf::Plugin
  FIX = File.expand_path("../fixtures", __dir__)

  # ---------- detect_declarations ----------

  def test_detect_plain_and_paren_forms
    assert_equal [:ebpf], PL.detect_declarations("use_plugin :ebpf\nputs 1\n")
    assert_equal [:ebpf], PL.detect_declarations("  use_plugin(:ebpf)  \n")
    assert_equal [:ebpf], PL.detect_declarations("use_plugin :ebpf  # enable kernel paths\n")
  end

  def test_detect_dedups_and_orders
    assert_equal [:ebpf, :gpu], PL.detect_declarations("use_plugin :ebpf\nuse_plugin :gpu\nuse_plugin :ebpf\n")
  end

  def test_detect_ignores_commented_or_nondeclaration_lines
    assert_empty PL.detect_declarations("# use_plugin :ebpf\nx = use_plugin_helper(:ebpf)\n")
    assert_empty PL.detect_declarations("def use_plugin(x); end\n") # not a bare call form
  end

  # ---------- strip_declarations ----------

  def test_strip_preserves_line_count_and_comments_directive
    src = "use_plugin :ebpf\ndef xdp__c\n  XDP::PASS\nend\n"
    out = PL.strip_declarations(src)
    assert_equal src.lines.size, out.lines.size, "line count must be preserved"
    refute_match(/^\s*use_plugin/, out, "directive must no longer be a bare statement")
    assert_match(/# \[spinel-ebpf plugin directive\] use_plugin :ebpf/, out)
    assert_includes out, "def xdp__c" # body untouched
  end

  # ---------- minimal TOML parse ----------

  def test_parse_toml_value_shapes
    assert_equal "ebpf", PL.parse_toml_value('"ebpf"')
    assert_equal 1, PL.parse_toml_value("1")
    assert_equal %w[a b], PL.parse_toml_value('["a", "b"]')
    assert_equal({ "init" => "pre_main", "fini" => "detach" },
                 PL.parse_toml_value('{ init = "pre_main", fini = "detach" }'))
  end

  def test_parse_toml_ignores_comments_and_sections
    t = "# header\nname = \"ebpf\"\n[section]\nabi_version = \"1\"\n"
    d = PL.parse_toml(t)
    assert_equal "ebpf", d["name"]
    assert_equal "1", d["abi_version"]
  end

  # ---------- discovery + manifest (bundled self) ----------

  def test_discover_bundled_ebpf_manifest
    m = PL.discover(:ebpf)
    refute_nil m, "the in-tree plugin.toml (name=ebpf) must be discoverable"
    assert_equal "ebpf", m.name
    assert_equal "1", m.abi_version
    assert_equal "bin/spinel-ebpf", m.entrypoint
    assert_includes m.owns_namespace, "BPF"
    assert_includes m.link_libs, "bpf"
    assert_equal "pre_main", m.lifecycle["init"]
  end

  def test_discover_unknown_returns_nil
    assert_nil PL.discover(:definitely_not_a_plugin)
  end

  # ---------- ABI validation ----------

  def test_validate_accepts_supported_abi
    m = PL.discover(:ebpf)
    assert_same m, PL.validate!(m)
  end

  def test_validate_rejects_abi_mismatch
    bad = PL::Manifest.new(name: "ebpf", abi_version: "999", entrypoint: "x",
                           owns_namespace: [], link_libs: [], lifecycle: {}, root: "/tmp")
    e = assert_raises(PL::LoadError) { PL.validate!(bad) }
    assert_match(/abi_version "999".*!= driver "1"/, e.message)
  end

  # ---------- uses_bpf_namespace? (real partition result) ----------

  def test_uses_bpf_namespace_true_when_ebpf_methods
    r = SpinelEbpf::Partition.classify_files("#{FIX}/02_integer_arith.ir", "#{FIX}/02_integer_arith.ast")
    assert PL.uses_bpf_namespace?(r), "02_integer_arith has :ebpf methods"
  end

  def test_uses_bpf_namespace_false_for_pure_native
    r = SpinelEbpf::Partition.classify_files("#{FIX}/01_hello.ir", "#{FIX}/01_hello.ast")
    refute PL.uses_bpf_namespace?(r), "01_hello is all :native (puts)"
  end

  # ---------- build-time arbiter ----------

  def manifest(name, ns, drive: "source", lifecycle: {})
    PL::Manifest.new(name: name, abi_version: "1", entrypoint: "x",
                     owns_namespace: ns, link_libs: [], lifecycle: lifecycle,
                     drive: drive, root: "/tmp/#{name}")
  end

  def test_arbitrate_single_plugin_ok
    assert PL.arbitrate!([manifest("ebpf", %w[BPF xdp__*])])
  end

  def test_arbitrate_disjoint_namespaces_ok
    ms = [manifest("ebpf", %w[BPF xdp__*]), manifest("gpu", %w[GPU kernel__*])]
    assert_equal ms, PL.arbitrate!(ms)
  end

  def test_arbitrate_conflicting_namespace_raises
    ms = [manifest("ebpf", %w[BPF xdp__*]), manifest("other", %w[GPU xdp__*])]
    e = assert_raises(PL::ArbitrationError) { PL.arbitrate!(ms) }
    assert_match(/`xdp__\*` is claimed by both 'ebpf' and 'other'/, e.message)
  end

  def test_arbitrate_idempotent_same_owner
    # the same plugin listing a token twice is not a conflict
    assert PL.arbitrate!([manifest("ebpf", %w[BPF BPF xdp__*])])
  end

  def test_resolve_all_discovers_and_arbitrates_bundled
    ms = PL.resolve_all([:ebpf])
    assert_equal 1, ms.size
    assert_equal "ebpf", ms.first.name
  end

  def test_resolve_all_raises_on_missing
    assert_raises(PL::LoadError) { PL.resolve_all([:definitely_absent]) }
  end

  # ---------- run-loop owner + lifecycle order ----------

  def test_single_loop_owner_ok
    ms = [manifest("ui", %w[UI], drive: "loop-owning"), manifest("ebpf", %w[BPF], drive: "source")]
    assert_equal ms, PL.arbitrate!(ms)
  end

  def test_two_loop_owners_conflict
    ms = [manifest("ui", %w[UI], drive: "loop-owning"), manifest("net", %w[NET], drive: "loop-owning")]
    e = assert_raises(PL::ArbitrationError) { PL.arbitrate!(ms) }
    assert_match(/run-loop conflict/, e.message)
    assert_match(/'ui' and 'net'/, e.message)
  end

  def test_validate_rejects_unknown_drive
    bad = manifest("x", %w[X], drive: "bogus")
    e = assert_raises(PL::LoadError) { PL.validate!(bad) }
    assert_match(/drive "bogus" unknown/, e.message)
  end

  def test_bundled_ebpf_drive_is_source
    assert_equal "source", PL.discover(:ebpf).drive
  end

  def test_lifecycle_order_groups_by_phase_then_declaration
    a = manifest("a", %w[A], lifecycle: { "init" => "pre_main", "fini" => "detach" })
    b = manifest("b", %w[B], lifecycle: { "init" => "pre_main", "fork" => "before_fork" })
    plan = PL.lifecycle_order([a, b])
    # pre_main bucket first (a then b by declaration), then before_fork (b), then detach (a)
    assert_equal [["pre_main", "a", "init"], ["pre_main", "b", "init"],
                  ["before_fork", "b", "fork"], ["detach", "a", "fini"]], plan
  end
end
