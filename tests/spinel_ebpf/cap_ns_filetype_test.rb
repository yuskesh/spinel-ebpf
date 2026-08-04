# frozen_string_literal: true
#
# has_cap / ns_id / in_host_ns / file_type.
#
# Drives the PRODUCTION C codegen (src/codegen_c/spinel_ebpf_cc.c) directly, the
# same binary tools/golden.rb pins. The golden already locks the exact text; what
# this file locks is the decisions that would be SILENTLY wrong rather than
# merely different, each one measured:
#
#   D2  the raw value cannot be compared correctly by the caller, in all three
#       cases, and every wrong form returns a small plausible number:
#         `caps & CAP_SYS_ADMIN` returns 21 whether or not the bit is set
#           (measured: slot 5 is identical in both runs)
#         `i_mode == S_IFREG` is false for every regular file, and
#           `i_mode & S_IFDIR` is TRUE for a socket
#           (both measured)
#   D3  ns_id(:pid) walks thread_pid. nsproxy->pid_ns_for_children is the
#       namespace this task's CHILDREN get and differs for a task that unshared
#       without forking (measured: 4026532241 vs the correct 4026532240 --
#       both ordinary inode numbers).
#       in_host_ns reads init_nsproxy via an UNTYPED ksym; the typed form does
#       not load and /proc/1/ns is the container's init, not the host's
#       (both measured).
#   D4  the six current-task builtins are gated to process context and file_type
#       is not. The gate is about meaning, not loadability: measured, all of them
#       load in all 24 program types, and in XDP the answer is a real capability
#       set belonging to the wrong task.
#
# Run:
#   ruby -Isrc -Itests tests/spinel_ebpf/cap_ns_filetype_test.rb

require "minitest/autorun"
require "open3"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/codegen_bpf"

class CapNsFiletypeTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  FIX  = File.join(ROOT, "tests/fixtures")
  CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
  CAP  = SpinelEbpf::Capabilities
  GEN  = SpinelEbpf::CodegenBpf

  CURRENT_TASK = %w[has_cap has_cap_permitted has_cap_inheritable
                    cap_effective ns_id in_host_ns].freeze
  ALL = (CURRENT_TASK + %w[file_type]).freeze
  NS_KEYS = %w[mnt net uts ipc cgroup time user pid].freeze

  # Same preflight as golden.rb: +x is not enough, build/ is bind-mounted into
  # the container so the binary may be built for the other platform.
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

  def emit(base = "150_cap_ns_filetype")
    skip_unless_cc
    out, err, st = run_cc(base)
    assert st.success?, "codegen refused #{base}: #{err}"
    out
  end

  # ---------- D2: the predicate does the comparison, not the caller ----------

  # The load-bearing assertion. A capability is a BIT INDEX, so the test has to
  # be a shift or a mask by (1 << n) -- never `caps & n`, which was measured
  # returning the same 21 for a process that has CAP_SYS_ADMIN and one that does
  # not. The generated form here is `(caps >> 21) & 1`, which the verifier's own
  # view shows folded to `r1 &= 2097152` (measured in the xlated program).
  def test_capability_is_tested_as_a_bit_not_compared_as_a_number
    c = emit
    assert_includes c, "SPNL_HAS_CAP(cap_effective, 21)",
                    "CAP::SYS_ADMIN must reach the accessor as the bit index 21"
    assert_includes c, "#define SPNL_HAS_CAP(set, n)  ((__s64)((SPNL_CAPS(set) >> (n)) & 1))",
                    "the shift must live in the accessor: `caps & 21` tests bits 0/2/4 and " \
                    "returns 21 in BOTH directions (measured: slot 5 is identical in both runs)"
  end

  # And the constant must stay the capability NUMBER, matching the kernel macro,
  # capsh and `man 7 capabilities`. Redefining it as a mask would make
  # `caps & CAP_SYS_ADMIN` accidentally work at the price of the constant lying
  # about what it is.
  def test_capability_constants_are_bit_indices_not_masks
    c = emit
    assert_includes c, "SPNL_HAS_CAP(cap_permitted, 12)",  "CAP::NET_ADMIN == 12"
    assert_includes c, "SPNL_HAS_CAP(cap_inheritable, 19)", "CAP_SYS_PTRACE == 19"
    refute_includes c, "2097152", "the surface must not pre-expand the constant into a mask"
  end

  # file_type returns the ALREADY-MASKED type. If the mask moved to the caller,
  # both wrong spellings compile and return plausible numbers: `i_mode ==
  # S_IFREG` is false for every regular file (33188 != 32768) and `i_mode &
  # S_IFDIR` is true for a socket (49645 & 16384 != 0) -- both measured directly
  # and again through the real codegen.
  def test_file_type_masks_with_s_ifmt_before_the_caller_sees_it
    c = emit
    assert_includes c, "f_inode, i_mode) & 0170000",
                    "the S_IFMT mask belongs in the accessor (measured: both wrong " \
                    "spellings compile and return plausible numbers)"
    assert_includes c, ") == 32768", "FileType::REG must lower to S_IFREG"
    assert_includes c, ") == 16384", "FileType::DIR must lower to S_IFDIR"
  end

  # The three values whose meaning cannot be read off the spelling must say so
  # in the affordance -- that is the only place an author (or an AI) sees it.
  def test_the_unreadable_values_declare_what_they_are
    assert_includes CAP.value_semantics_for("cap_effective"), "bit set"
    assert_includes CAP.value_semantics_for("cap_effective"), "has_cap",
                    "the value has to point at the predicate that reads it correctly"
    assert_includes CAP.value_semantics_for("ns_id"), "inode"
    assert_includes CAP.value_semantics_for("file_type"), "S_IFMT"
  end

  # ---------- D3: pid namespace, and where the host number comes from ----------

  # nsproxy is the obvious place to look for "my pid namespace" and it is the
  # wrong place: pid_ns_for_children is what this task's CHILDREN get. A task
  # that unshared without forking was measured with the two disagreeing, both
  # answers looking like ordinary inode numbers, so nothing downstream could
  # have noticed.
  def test_pid_namespace_walks_thread_pid_not_pid_ns_for_children
    c = emit
    assert_includes c, "spnl_pid_ns_inum()"
    assert_includes c, "BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), thread_pid)"
    refute_match(/bpf_get_current_task\(\), nsproxy, pid_ns_for_children/, c,
                 "ns_id(:pid) must not use pid_ns_for_children (measured: the two " \
                 "disagree for a task that unshared without forking)")
  end

  # The user namespace is not in nsproxy at all.
  def test_user_namespace_comes_from_cred
    c = emit
    assert_includes c, "bpf_get_current_task(), cred, user_ns, ns.inum"
  end

  # The initial namespace inode is read from the kernel, by an UNTYPED ksym.
  # The typed form is not merely stylistically different -- it does not load
  # ("not found in kernel BTF": 0 of the 334 vmlinux BTF VARs is an init_*).
  def test_host_namespace_uses_an_untyped_ksym
    c = emit
    assert_includes c, "extern const void init_nsproxy __ksym;"
    assert_includes c, "extern const void init_user_ns __ksym;"
    refute_match(/^extern struct nsproxy init_nsproxy/, c,
                 "the typed form LOAD_FAILs on 7.1.5 (measured); it appears in the " \
                 "preamble comment as the rejected alternative, never as a declaration")
    assert_includes c, "SPNL_HOST_NS(mnt_ns)"
  end

  # The ksym externs must not appear in a unit that never asks about the host:
  # an extern nobody references is still an extern libbpf has to resolve, so
  # emitting them unconditionally would make every probe depend on kallsyms.
  def test_ksyms_are_emitted_only_when_in_host_ns_is_used
    c = emit("137_sock_accessors")
    refute_includes c, "init_nsproxy"
  end

  # ---------- D4: the gate follows "reads the current task", not "is new" ----

  # Refused in a packet program. The read LOADS there (measured: 24/24 program
  # types), and it was measured answering TRUE about a CPU burner for packets
  # sent by another machine while the real actor answered FALSE in a kprobe in
  # the same run. Nothing downstream distinguishes those.
  def test_current_task_builtins_are_refused_in_a_packet_program
    skip_unless_cc
    _out, err, st = run_cc("151_has_cap_packet_ctx")
    refute st.success?, "has_cap in XDP must be refused at compile time"
    assert_match(/CURRENT TASK/, err)
    assert_match(/kprobe/, err, "the message must list where it CAN be written")
    assert_match(/kfield/, err, "and how to read a different task instead")
  end

  # ... and file_type is deliberately NOT gated: it reads the pointer the hook
  # hands it, exactly like kfield. Fixture 150 uses it inside lsm/file_open, and
  # the affordance must agree with the codegen about which of the two it is.
  def test_the_gate_splits_the_family_and_the_affordance_says_so
    CURRENT_TASK.each do |b|
      req = CAP::CONTEXT_REQUIREMENTS[b]
      refute_nil req, "#{b} reads the current task and must be gated"
      assert_includes req[:kinds], :kprobe
      assert_includes req[:kinds], :lsm
      refute_includes req[:kinds], :xdp, "a packet program has no meaningful current task"
      refute_includes req[:kinds], :tc_ingress
      assert CAP.builtin_entry(b)[:gated], "capabilities --json must report the gate"
    end
    assert_nil CAP::CONTEXT_REQUIREMENTS["file_type"],
               "file_type reads the hook's own pointer: ungated, like kfield"
    refute CAP.builtin_entry("file_type")[:gated]
  end

  # cgroup/connect4 is the one SEC allowed out of AK_SK_VERDICT, which otherwise
  # covers six softirq program types. It is there because it was measured
  # reporting the connecting process -- not because connect(2) "should" be a
  # syscall path.
  def test_cgroup_sock_addr_is_allowed_because_it_was_measured
    CURRENT_TASK.each do |b|
      k = CAP::CONTEXT_REQUIREMENTS[b][:kinds]
      assert_includes k, :cgroup_connect4
      assert_includes k, :cgroup_bind4
      refute_includes k, :sk_reuseport, "same AttachKind, but softirq"
      refute_includes k, :sk_msg
    end
  end

  # ---------- namespace keys ----------

  # The key picks a kernel struct member at compile time, so the set is closed
  # and a typo has to be loud: ns_id(:mount) silently returning 0 would read as
  # "this task is in no mount namespace".
  def test_unknown_namespace_key_is_refused_with_the_accepted_set
    skip_unless_cc
    _out, err, st = run_cc("152_ns_id_unknown_key")
    refute st.success?
    assert_match(/accepted keys are/, err)
    NS_KEYS.each { |k| assert_match(/\b#{k}\b/, err, "the message must list #{k}") }
  end

  # ---------- registration ----------

  def test_registered_as_enforcement_builtins_in_their_own_groups
    ALL.each do |b|
      assert_includes GEN::BUILTIN_NAMES, b
      assert_equal :enforcement, CAP.domain_of(b), "these are selectors, like path_eq"
      assert_nil CAP.gate_for(b), "the d_path SEC allowlist does not apply to any of them"
      refute_nil CAP.builtin_entry(b)[:example], "an AI reads the example, so it must exist"
    end
    caps = CAP::BUILTIN_GROUPS.find { |g| g[:name] == "task_capability" }
    ns   = CAP::BUILTIN_GROUPS.find { |g| g[:name] == "task_namespace" }
    file = CAP::BUILTIN_GROUPS.find { |g| g[:name] == "file_selector" }
    refute_nil caps
    refute_nil ns
    refute_nil file
    assert_includes caps[:note], "bit"
    assert_includes ns[:note], "cgroup_id", "the cheaper answer for container attribution"
    assert_includes file[:members], "path_eq", "the gated sibling belongs in the same group"
    assert_includes file[:members], "file_type"
  end

  # A capability that is off by one is not detectable by reading the output, so
  # pin the ends and a few load-bearing middles against `man 7 capabilities`.
  def test_capability_numbers_match_the_kernel
    c = emit
    src = File.read("#{FIX}/150_cap_ns_filetype.rb")
    assert_includes src, "CAP::SYS_ADMIN"
    assert_includes src, "CAP_SYS_PTRACE", "the flat spelling must work too"
    # 21 / 12 / 19 asserted above; here just confirm both spellings coexist
    assert_includes c, "SPNL_HAS_CAP(cap_effective, 21)"
    assert_includes c, "SPNL_HAS_CAP(cap_inheritable, 19)"
  end
end
