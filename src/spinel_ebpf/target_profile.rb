# frozen_string_literal: true
#
# A compilation target as a first-class profile.
#
# Before this file, partition eligibility was a single hardcoded impossibility
# set (the historical ebpf_impossible?), and the AMP target rode on top of it:
# a per-unit CLI flag, an env var into codegen, and a SECOND eligibility
# mechanism (amp_scan_supported's builtin allowlist) living in C with no
# Ruby-side counterpart. Two eligibility implementations with no lockstep is
# the same drift surface the two-partitioner discipline exists to close.
#
# A TargetProfile carries the two dimensions eligibility actually has:
#
#   fatal_flags     which MethodFlags kill a method for this target
#                   (floats are fatal on eBPF, fine on a GPU; IO is fatal on both)
#   call_allowlist  for restricted targets (AMP v0), which identifier-shaped
#                   calls the target's codegen can lower at all. nil = the
#                   target has a full builtin surface and flags alone decide.
#
# The C-side AMP check (amp_scan_supported in src/codegen_c/spinel_ebpf_cc.c)
# stays as the backstop on the direct in-process path -- the regression harness
# drives that binary without Ruby in front. The lockstep between this file's
# AMP allowlist and the C source is pinned by
# tests/spinel_ebpf/target_profile_test.rb; change either side and the test
# names the drift.

module SpinelEbpf
  class TargetProfile
    attr_reader :name, :fatal_flags, :call_allowlist, :supported_summary

    def initialize(name:, fatal_flags:, call_allowlist: nil, supported_summary: nil)
      @name = name
      @fatal_flags = fatal_flags.freeze
      @call_allowlist = call_allowlist&.freeze
      @supported_summary = supported_summary
      freeze
    end

    # Operator calls (`a + b` arrives as a CallNode named "+") are lowered
    # structurally on every target; the allowlist governs identifier-shaped
    # calls only.
    def identifier_call?(name)
      name.match?(/\A[A-Za-z_]/)
    end

    def allows_call?(name)
      return true if @call_allowlist.nil?
      return true unless identifier_call?(name)
      @call_allowlist.include?(name)
    end

    # The reason strings for MethodFlags#reasons, in their long-standing order.
    # A profile prints only the reasons for flags it actually treats as fatal,
    # so the linux profile reproduces the historical output byte for byte.
    FLAG_REASONS = [
      [:uses_float,                "uses Float arithmetic (no FPU in BPF)"],
      [:uses_regex,                "uses regex (no regex helper in BPF)"],
      [:uses_io,                   "performs I/O (host-side only)"],
      [:uses_thread,               "creates Thread (kernel cannot create threads)"],
      [:uses_fiber,                "uses Fiber (no fiber concept in BPF)"],
      [:uses_closure,              "uses closure with captured outer vars"],
      [:uses_recursion,            "calls itself recursively (BPF call graph is a DAG)"],
      [:uses_bignum,               "uses bignum (BPF integers are 64-bit max)"],
      [:uses_unbounded_loop,       "has loop without static upper bound"],
      [:uses_unsupported_type,     "signature uses non-int type (string/array/hash/...)"],
      [:inherits_unsupported,      "calls another method that is eBPF-impossible"],
    ].freeze

    ALL_FLAGS = FLAG_REASONS.map(&:first).freeze

    # The Linux eBPF target: the historical impossibility set, unchanged.
    LINUX_EBPF = new(
      name: "linux-ebpf",
      fatal_flags: ALL_FLAGS,
    )

    # AMP v0 (--target amp-m7 / amp-m33): same structural constraints as eBPF
    # plus a closed builtin surface. Mirrors amp_scan_supported: CallNodes may
    # be binary operators, spnl_emit or ktime_ns; everything else (including
    # calls to the author's own methods -- v0 handlers have no BPF-to-BPF
    # equivalent) has nothing to lower to on an M-core.
    AMP = new(
      name: "amp",
      fatal_flags: ALL_FLAGS,
      call_allowlist: %w[spnl_emit ktime_ns],
      supported_summary: "ivar RMW (@x/@x += n), integer arithmetic, if/locals, spnl_emit, ktime_ns",
    )
  end
end
