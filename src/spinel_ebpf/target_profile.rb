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
# drives that binary without Ruby in front. Both sides now derive from one
# declaration: the backstop walks cc_builtin_targets through
# cc_builtin_on_target(), and the allowlist below reads the same table's
# generated JSON. tests/spinel_ebpf/target_profile_test.rb pins both halves of
# that -- the allowlist against the table, and the backstop against the fact
# that it consults it.

module SpinelEbpf
  class TargetProfile
    # The per-target existence axis is declared once in
    # src/codegen_c/builtin_schema.h (the same table the C backstop walks through
    # cc_builtin_on_target) and rendered by `make -C src/codegen_c
    # builtin-schema`. The allowlists below are READ from that artifact --
    # writing them here as literals was a second spelling of one fact. The prose
    # half (supported_summary) stays here: it is not a shared fact.
    BUILTIN_SCHEMA = begin
      require "json"
      path = File.expand_path("builtin_schema_gen.json", __dir__)
      unless File.exist?(path)
        raise "builtin schema artifact missing: #{path} " \
              "(run: make -C src/codegen_c builtin-schema)"
      end
      JSON.parse(File.read(path)).freeze
    end

    # The builtins declared to exist on target `tname` ("amp"), in declaration
    # order. Names absent from the table are linux-only (the default).
    def self.schema_allowlist(tname)
      BUILTIN_SCHEMA.fetch("targets")
                    .select { |r| r.fetch("targets").include?(tname) }
                    .map { |r| r.fetch("name") }.freeze
    end

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
      return true if syntax_on_target?(name)   # syntax is outside the builtin allowlist
      @call_allowlist.include?(name)
    end

    # A construct like `n.times` arrives at the partition as an identifier-shaped
    # CallNode, but it is SYNTAX, not a builtin: whether a target can lower it is
    # a separate per-target fact with its own table. The authority is
    # cc_syntax_targets in src/codegen_c/builtin_schema.h -- the C scan walks the
    # same table through cc_syntax_on_target(). The table is empty in this tree
    # (see the header for why), so this answers false for everything today; what
    # it buys is that a construct arriving on a restricted target is one row in
    # one place rather than a second spelling here.
    def syntax_on_target?(name)
      row = self.class::BUILTIN_SCHEMA.fetch("syntax_targets").find { |r| r["name"] == name }
      row ? row.fetch("targets").include?(@name.sub("linux-ebpf", "linux")) : false
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
      call_allowlist: schema_allowlist("amp"),   # authority: builtin_schema.h
      supported_summary: "ivar RMW (@x/@x += n), integer arithmetic, if/locals, spnl_emit, ktime_ns",
    )
  end
end
