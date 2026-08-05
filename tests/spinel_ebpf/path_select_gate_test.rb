# frozen_string_literal: true
#
# The ASYMMETRIC half of the bpf_d_path gate.
#
# All 32 gated hooks were measured to actual firing. Four of them
# (fentry|fexit / dentry_open|vfs_getattr) came back in a state the usual
# vocabulary has no word for: not dead (they fire), not healthy (the path they
# hand you is rendered from overlayfs's INTERNAL mount, so a control file in a
# different directory rendered to the same `/f`). That was first written down as
# an affordance `caveat` and left there, because "not dead" ruled out withdrawing
# the hook.
#
# Loud is better, and both facts the refusal needs are known at compile time:
# WHICH builtin the author wrote, and WHICH SEC they wrote it in. So the codegen
# refuses -- but only for the three path SELECTORS. This is the point of the
# whole exercise and the thing this file exists to pin:
#
#   refused   path_eq / path_starts_with / path_contains  -- DECIDE on the path
#                                                             the hook hands you
#   allowed   emit_path                                   -- RECORD it (a real
#                                                             overlayfs copy-up)
#   allowed   parent_path_eq / emit_parent_path           -- the path comes from
#                                                             the TASK chain, so
#                                                             the rendering
#                                                             finding never
#                                                             reaches it
#
# A gate that refused the hook outright would be indistinguishable from this one
# in every "N refusals" count, which is why the allowed half is tested too (and
# why fixture 182 is committed with a golden).
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/path_select_gate_test.rb

require "minitest/autorun"
require "open3"
require "tmpdir"
require "spinel_ebpf/capabilities"

class PathSelectGateTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")            # text mode (.ir/.ast)
  INPROC = ENV["SPNL_INPROC_CC"] || File.join(ROOT, "build/codegen_c/spinel-ebpf-cc")
  CAP  = SpinelEbpf::Capabilities

  # The same preflight golden.rb uses: +x is not enough, because build/ can be
  # bind-mounted into a container and hold the other platform's ELF. A working
  # binary prints a usage line with no args.
  def self.runnable?(bin)
    (@runnable ||= {}).fetch(bin) do
      ok = File.executable?(bin) &&
           begin
             o, e, = Open3.capture3(bin)
             "#{o}#{e}".include?("usage:")
           rescue StandardError
             false
           end
      @runnable[bin] = ok
    end
  end

  def skip_unless(bin, how)
    skip "#{bin} not runnable on this host (#{how})" unless self.class.runnable?(bin)
  end

  def run_fixture(base)
    Open3.capture3(CC, "#{FIX}/#{base}.ir", "#{FIX}/#{base}.ast", base)
  end

  # --- the committed fixtures -------------------------------------------------

  # One per SEC, rotating the selector so all three spellings and all four hooks
  # appear. (The full 4x3 cross product is swept below, where the in-process
  # binary lets us write probes without committing .ast/.ir for each.)
  REFUSED = {
    "178_path_eq_overlay_hook"           => %w[path_eq          fentry/dentry_open],
    "179_path_starts_with_overlay_hook"  => %w[path_starts_with fentry/vfs_getattr],
    "180_path_contains_overlay_hook"     => %w[path_contains    fexit/dentry_open],
    "181_path_eq_overlay_getattr_fexit"  => %w[path_eq          fexit/vfs_getattr],
  }.freeze

  def test_the_four_selectors_are_refused_with_a_usable_message
    skip_unless(CC, "cc -O2 -o #{CC} src/codegen_c/spinel_ebpf_cc.c")
    REFUSED.each do |base, (builtin, sec)|
      out, err, st = run_fixture(base)
      refute st.success?, "#{base}: the codegen accepted a path selector on #{sec}"
      msg = "#{err}#{out}"
      # what is wrong, why, and how to fix it -- plus the two facts only the
      # compiler knows: which builtin, and which hook.
      assert_includes msg, builtin,       "#{base}: the message must name the builtin the author wrote"
      assert_includes msg, sec,           "#{base}: the message must name the SEC the author wrote"
      assert_includes msg, "overlayfs",   "#{base}: the message must say WHY (the rendering, not just 'no')"
      assert_includes msg, "measured",    "#{base}: the message must say the reason was measured, not assumed"
      assert_includes msg, "emit_path",   "#{base}: the message must say what still works here"
      assert_match(/def (lsm|fmod_ret)__/, msg,
                   "#{base}: the message must name a hook that DOES render the caller's path")
    end
  end

  # The other half. Without this a gate that simply removed the four hooks from
  # CC_DPATH_OK would pass every check above.
  def test_recording_the_path_is_still_allowed_on_the_same_hook
    skip_unless(CC, "cc -O2 -o #{CC} src/codegen_c/spinel_ebpf_cc.c")
    _out, err, st = run_fixture("182_emit_path_overlay_hook")
    assert st.success?,
           "182 uses emit_path + parent_path_eq on fentry/dentry_open, the same SEC 178 " \
           "refuses. If this stops compiling the gate has become symmetric and the hook " \
           "is effectively withdrawn -- which was explicitly decided against:\n#{err}"
  end

  def test_the_refused_fixtures_have_no_golden
    # A fixture that is both refused and committed with a golden is a
    # contradiction. tools/golden.rb enforces this over the whole corpus; naming
    # it here keeps these fixtures from drifting out of that rule.
    REFUSED.each_key do |base|
      refute File.exist?(File.join(ROOT, "tests/golden/#{base}.bpf.c")),
             "#{base} is refused by the codegen and must not also have a golden"
    end
    assert File.exist?(File.join(ROOT, "tests/golden/182_emit_path_overlay_hook.bpf.c")),
           "182 is the ALLOWED half and must keep its golden -- it is the only committed " \
           "artifact that distinguishes an asymmetric gate from a withdrawn hook"
  end

  # --- the full cross product (in-process binary; container) ------------------

  SELECTOR_CALL = {
    "path_eq"          => 'path_eq(path, "/etc/shadow")',
    "path_starts_with" => 'path_starts_with(path, "/etc/")',
    "path_contains"    => 'path_contains(path, "/.ssh/")',
  }.freeze

  # `def <prefix>__<func>(args...)`: dentry_open(path, flags, cred),
  # vfs_getattr(path, stat, request_mask, query_flags); fexit adds `ret`.
  def probe_for(sec, body)
    pre, func = sec.split("/")
    args = func == "dentry_open" ? %w[path flags cred] : %w[path stat request_mask query_flags]
    args << "ret" if pre == "fexit"
    <<~RB
      @hits = 0

      def #{pre}__#{func}(#{args.join(', ')})
        #{body}
        0
      end
    RB
  end

  def compile_probe(dir, name, src)
    path = File.join(dir, "#{name}.rb")
    File.write(path, src)
    out, err, st = Open3.capture3(INPROC, path, name)
    [st.success?, "#{err}#{out}"]
  end

  def test_every_selector_is_refused_on_every_no_select_hook
    skip_unless(INPROC, "built by tools/stage2_verify.sh; Linux only")
    assert_equal 4, CAP::DPATH_NO_SELECT_SECS.length, "the no_select set changed shape"
    Dir.mktmpdir("path-select") do |dir|
      CAP::DPATH_NO_SELECT_SECS.each do |sec|
        SELECTOR_CALL.each do |builtin, call|
          body = "if #{call}\n    @hits = @hits + 1\n  end"
          ok, msg = compile_probe(dir, "sel_#{sec.tr('/', '_')}_#{builtin}", probe_for(sec, body))
          refute ok, "#{builtin} on #{sec} compiled -- the refusal is not per-SEC-per-builtin"
          assert_includes msg, builtin
          assert_includes msg, sec
        end
      end
    end
  end

  def test_the_non_selectors_compile_on_every_no_select_hook
    skip_unless(INPROC, "built by tools/stage2_verify.sh; Linux only")
    Dir.mktmpdir("path-observe") do |dir|
      CAP::DPATH_NO_SELECT_SECS.each do |sec|
        {
          "emit_path"      => "emit_path(path)",
          "parent_path_eq" => "if parent_path_eq(\"/usr/bin/ovl\")\n    @hits = @hits + 1\n  end",
        }.each do |builtin, body|
          ok, msg = compile_probe(dir, "obs_#{sec.tr('/', '_')}_#{builtin}", probe_for(sec, body))
          assert ok, "#{builtin} on #{sec} was refused. It must not be: #{builtin} does not " \
                     "decide on the path this hook renders (emit_path records it; " \
                     "parent_path_eq reads the task chain).\n#{msg}"
        end
      end
    end
  end

  # The gate must still be a GATE: the same selector on a hook that renders the
  # caller's path has to compile, or "refused" would just mean "the d_path gate
  # is broken everywhere".
  def test_the_same_selector_compiles_on_a_hook_that_renders_the_callers_path
    skip_unless(INPROC, "built by tools/stage2_verify.sh; Linux only")
    Dir.mktmpdir("path-control") do |dir|
      src = <<~RB
        @denied = 0

        def lsm__file_open(file, ret)
          if path_eq(file, "/etc/shadow")
            @denied = @denied + 1
          end
          0
        end
      RB
      ok, msg = compile_probe(dir, "ctl_lsm_file_open", src)
      assert ok, "path_eq on lsm/file_open must still compile:\n#{msg}"
    end
  end
end
