# frozen_string_literal: true
#
# SpinelEbpf::Check -- the fast verify loop, aimed at a machine author.
#
# `spinel-ebpf check <file>` runs a probe through the pipeline stage by stage and
# returns, machine-readably, *where it fell over and why*:
#
#   partition -> codegen -> clang(-target bpf) -> load+verifier
#
# read the affordances -> write -> fix what the loud errors say -> **verify**:
# that last step is what closes the loop. The loud errors come before codegen; this
# takes the surviving program all the way to `clang -target bpf` and the *kernel
# verifier* (the second, kernel-side harness) and surfaces each verdict as a clean
# `{stage, ok, error, detail}` record. The pipeline stops at the first failing
# stage so the AI gets exactly one "next thing to fix".
#
# This module holds the *pure* pieces (verdict shaping, verifier-log summary,
# result assembly, formatting, environment predicates) so they are host-testable
# without the Linux frontend / kernel. bin/spinel-ebpf owns the I/O orchestration
# (frontend, in-process codegen, clang, the load-only loader).

require "json"
require "rbconfig"

require "spinel_ebpf/validate"

module SpinelEbpf
  module Check
    # Pipeline order. Stop at the first stage with ok == false.
    STAGES = %w[partition codegen clang verifier].freeze

    # ---- stage-result constructors --------------------------------------------
    # A stage result is { stage:, ok:, error:, detail:, skipped: } where
    #   ok == true  -> passed
    #   ok == false -> the probe failed *here* (error/detail explain it) -> stop
    #   ok == nil   -> skipped (skipped: reason) — this environment can't run it
    #                  (e.g. verifier with no kernel/BTF), not a probe failure.
    module_function

    def ok_stage(name, detail: nil)
      { stage: name, ok: true, error: nil, detail: detail, skipped: nil }
    end

    def fail_stage(name, error, detail: nil)
      { stage: name, ok: false, error: error, detail: detail, skipped: nil }
    end

    def skip_stage(name, reason)
      { stage: name, ok: nil, error: nil, detail: nil, skipped: reason }
    end

    # ---- partition/validate verdict -------------------------------------------
    # Pure: given the partitioned AST and result, run the loud validate gate.
    # A Validate::Error (attach silent-native / heap / unknown builtin / incomplete
    # required set) becomes a partition-stage failure carrying that same message.
    # Host-testable with the committed .ast/.ir fixtures.
    def partition_verdict(ast, result)
      SpinelEbpf::Validate.validate!(ast, result)
      ebpf = result.methods.count { |m| m.tag == :ebpf }
      ok_stage("partition", detail: "#{result.methods.length} methods -> #{ebpf} eBPF")
    rescue SpinelEbpf::Validate::Error => e
      fail_stage("partition", e.message)
    end

    # ---- environment predicates (host-testable) -------------------------------
    def linux?
      !(RbConfig::CONFIG["host_os"] =~ /linux/i).nil?
    end

    def default_btf_path
      ENV["SPNL_BTF_PATH"] || "/sys/kernel/btf/vmlinux"
    end

    # Stage 4 (load+verifier) needs a live kernel with BTF. On macOS / a Linux box
    # without /sys/kernel/btf, it gracefully skips ("no kernel/BTF") rather than
    # crashing.
    def verifier_available?(btf_path: default_btf_path)
      linux? && File.exist?(btf_path)
    end

    # ---- verifier log summary -------------------------------------------------
    # From a libbpf load log, pull (short verdict, trimmed tail). The short verdict
    # is what the AI reads to know *why* the verifier rejected the program; the
    # detail is the log tail (the numbered instruction trace lives there).
    def summarize_verifier_log(log)
      lines = log.to_s.lines.map(&:chomp)
      prog  = lines.reverse.find { |l| l =~ /libbpf: prog '.*': failed to load/ }
      idx   = lines.rindex { |l| l =~ /^processed \d+ insns/ }
      verdict = nil
      if idx
        (idx - 1).downto(0) do |i|
          l = lines[i].strip
          next if l.empty?
          next if l =~ /^\d+: /          # numbered instruction trace
          next if l =~ /^R\d+\w* ?=/     # pure register dump (e.g. "0: R1=ctx()")
          next if l.start_with?("; ")    # source annotation
          verdict = l
          break
        end
      end
      verdict ||= lines.reverse.find do |l|
        l =~ /invalid|not allowed|unbounded|too (many|large)|back-edge|leaks|
              unreachable|permission|min value|max value|reference|misaligned/xi
      end
      short = [verdict, prog && prog.sub(/^libbpf:\s*/, "")].compact.join(" | ")
      short = "verifier rejected the program" if short.empty?
      tail  = lines.last([lines.size, 24].min).join("\n")
      [short, tail]
    end

    # ---- result assembly + formatting -----------------------------------------
    def assemble(file, stages)
      failed = stages.find { |s| s[:ok] == false }
      {
        file: file,
        ok: failed.nil?,
        failed_stage: failed && failed[:stage],
        stages: stages,
      }
    end

    def to_json(result)
      JSON.generate(result)
    end

    def human(result)
      out = +"spinel-ebpf check #{result[:file]}\n"
      result[:stages].each do |s|
        mark = if s[:ok] == true then "ok"
               elsif s[:ok] == false then "FAIL"
               else "skip"
               end
        note = if s[:ok] == false then s[:error]
               elsif s[:ok].nil? then s[:skipped]
               else s[:detail]
               end
        out << format("  [%-4s] %-10s %s\n", mark, s[:stage], note)
      end
      if result[:ok]
        conclusive = result[:stages].any? { |s| s[:stage] == "verifier" && s[:ok] == true }
        out << (conclusive ? "  => OK (verifier accepted)\n" : "  => OK (no failure; some stages skipped)\n")
      else
        f = result[:stages].find { |s| s[:ok] == false }
        out << "  => FAILED at #{f[:stage]}: #{f[:error]}\n"
      end
      out
    end
  end
end
