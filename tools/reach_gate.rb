#!/usr/bin/env ruby
# frozen_string_literal: true
#
# The third axis — can the PRODUCT still emit what tools/golden.rb pins?
#
#   1. tools/golden.rb          does the codegen still emit this TEXT?
#   2. tools/golden_compile.sh  does that text BUILD and LOAD?
#   3. this                     does `spinel-ebpf compile` REACH it?
#
# WHY A THIRD AXIS ------------------------------------------------------------
# tools/golden.rb drives the codegen directly: it reads tests/fixtures/*.ir +
# *.ast and passes no environment. That is deliberate and stays that way: it
# pins the COMPONENT contract, and exercising a component with inputs the
# integrated product filters out is a legitimate way to pin that contract
# independently.
#
# But the product is not the component. `bin/spinel-ebpf compile` runs the Ruby
# partition first, and that partition can decide two things golden.rb cannot see:
#
#   * every method is :native  -> the CLI never calls the codegen at all
#                                 ("no eBPF programs to emit"), so no .bpf.c
#   * some methods are :native -> it hands the codegen $SPNL_PARTITION_NATIVE,
#                                 which can change what comes out
#
# Until that variable existed every golden happened to be reachable. Nothing
# guaranteed it, and when one stopped being reachable there was no way to find
# out. This is the shape the capability audits in this tree found four times
# with the direction reversed: not "advertised but absent" but "present but not
# advertised". The coverage direction (implementation -> claim) in
# tools/affordance_gate.rb exists for exactly this reason — it is the only
# direction that sees silence.
#
# WHAT IS MEASURED ------------------------------------------------------------
# Both kinds of fact tools/golden.rb pins, because the product can lose either:
#
#   kind=golden   the 142 tests/golden/*.bpf.c        -> can the CLI emit it?
#   kind=refusal  the 34 tests/golden/codegen_reject  -> does the CLI refuse it?
#
# The second half is not decoration. A negative fixture whose partition rules
# every method :native never reaches the codegen, so its refusal — the whole
# point of the fixture — never fires for a user. Measured: that is the state of
# 163_timer_no_interval today (see the note in the baseline).
#
# REACHABLE MEANS ------------------------------------------------------------
# There is a documented `spinel-ebpf compile` invocation that produces the
# artifact. The search space is bounded to the invocations the CLI itself names
# — the default, and `--ebpf-dispatch` when the CLI refuses and says to add it.
# Handing the codegen a hand-built environment is not "using the product".
#
#   ruby tools/reach_gate.rb            # gate
#   ruby tools/reach_gate.rb --update   # move the baseline (REVIEW THE DIFF)
#   ruby tools/reach_gate.rb <artifact> # one artifact, verbose
#
# Run INSIDE the build container (it runs the real CLI, which needs upstream
# spinel and the in-process codegen), cwd anywhere:
#   container exec spnl715 sh -c 'cd /work && LANG=C.UTF-8 ruby tools/reach_gate.rb'
require "open3"
require "fileutils"
require "tmpdir"

ROOT     = File.expand_path("..", __dir__)
GOLD     = File.join(ROOT, "tests/golden")
REJECT   = File.join(GOLD, "codegen_reject.tsv")
BASELINE = File.join(GOLD, "product_reach.tsv")
CLI      = File.join(ROOT, "bin/spinel-ebpf")

# Values of the `product` column. The plain one per kind needs no prose; every
# other value is a fact somebody has to have looked at (see NOTE_REQUIRED).
PLAIN = { "golden" => "default", "refusal" => "refused" }.freeze
# `differs` is never written to the baseline: it means the product and the
# component emitted different bytes for the same fixture, which is the exact
# disagreement tools/stage2_verify.sh exists to make impossible. Recording it as
# accepted would let two gates disagree about one file forever.
NEVER_BASELINE = ["differs"].freeze

update = !ARGV.delete("--update").nil?
only   = ARGV[0]

# --- preflight ---------------------------------------------------------------
# The CLI has a fallback: when the in-process codegen cannot be built it emits
# with the RETIRED Ruby oracle (bin/spinel-ebpf, `SpinelEbpf::CodegenBpf.emit`).
# That path produces different bytes, so a host without upstream spinel objects
# would report 142 x `differs` — a number about the environment wearing the
# costume of a finding. Refuse to run instead.
abort "reach: #{CLI} not found" unless File.exist?(CLI)
_objs = Dir[File.join(ROOT, "deps/spinel/build/csrc/*.o")]
if _objs.empty? || !File.exist?(File.join(ROOT, "deps/spinel/build/libprism.a"))
  abort "reach: upstream spinel is not built (deps/spinel/build/csrc/*.o missing).\n" \
        "  Without it `spinel-ebpf compile` silently falls back to the retired Ruby codegen,\n" \
        "  and every artifact would be reported as `differs`. Build it first:\n" \
        "    make -C deps/spinel"
end

WORK = Dir.mktmpdir("reach")
at_exit { FileUtils.rm_rf(WORK) }

def cli(rb, base, extra)
  o = File.join(WORK, "#{base}#{extra.empty? ? '' : '_d'}")
  FileUtils.mkdir_p(o)
  _out, err, st = Open3.capture3({ "LANG" => "C.UTF-8" },
                                 "ruby", CLI, "compile", rb, "-o", o, *extra, chdir: ROOT)
  [st.exitstatus, File.join(o, "#{base}.bpf.c"), err]
end

def first_error(*errs)
  errs.each do |e|
    l = e.to_s.lines.grep(/^error:/).first
    return l.strip if l
  end
  ""
end

# Classify one golden. `golden_text` nil means "there is no golden" (used by the
# self-check), in which case only the no-ebpf / refused arms can fire.
def classify_golden(base, golden_text, rb = nil)
  rb ||= File.join(ROOT, "tests/fixtures/#{base}.rb")
  rc, bpf, err = cli(rb, base, [])
  if rc.zero? && File.exist?(bpf)
    return ["default", ""] if golden_text && File.read(bpf) == golden_text
    return ["differs", "the CLI wrote a .bpf.c that is not the golden"]
  end
  return ["no-ebpf", "the CLI emitted no .bpf.c (every method is :native)"] if rc.zero?

  rc2, bpf2, err2 = cli(rb, base, ["--ebpf-dispatch"])
  if rc2.zero? && File.exist?(bpf2)
    return ["ebpf-dispatch", first_error(err)] if golden_text && File.read(bpf2) == golden_text
    return ["differs", "even with --ebpf-dispatch the .bpf.c is not the golden"]
  end
  ["refused", first_error(err, err2)]
end

def classify_refusal(base)
  rc, _bpf, err = cli(File.join(ROOT, "tests/fixtures/#{base}.rb"), base, [])
  return ["refused", first_error(err)] unless rc.zero?
  ["no-ebpf", "the CLI exited 0: the codegen it would have refused was never called"]
end

# --- measure -----------------------------------------------------------------
goldens  = Dir["#{GOLD}/*.bpf.c"].map { |f| File.basename(f, ".bpf.c") }.sort
refusals = File.readlines(REJECT).reject { |l| l.start_with?("#") || l.strip.empty? }
               .map { |l| l.chomp.split("\t", 2).first }.sort

now  = {}   # artifact -> [kind, product]
diag = {}   # artifact -> the CLI's own first error line, for the report
goldens.each do |b|
  next if only && only != b
  v, d = classify_golden(b, File.read(File.join(GOLD, "#{b}.bpf.c")))
  now[b] = ["golden", v]
  diag[b] = d
  $stderr.print(v == "default" ? "." : "!")
end
refusals.each do |b|
  next if only && only != b
  v, d = classify_refusal(b)
  now[b] = ["refusal", v]
  diag[b] = d
  $stderr.print(v == "refused" ? "." : "!")
end
$stderr.puts

# A run that measured nothing is not a pass (same guard as tools/golden.rb).
abort "reach: nothing was measured#{only ? " (no artifact named '#{only}')" : ''}" if now.empty?

# --- self-checks: can this gate still say no? --------------------------------
# Two arms produced every non-plain verdict in the corpus, so both are checked
# every run. Not in the baseline, not skippable: a gate whose detector has gone
# flat reports `broken=0` forever.
selfcheck = []
unless only
  # (1) byte comparison. Compare one golden's product output against a DIFFERENT
  #     golden's text and demand `differs`.
  a, b = goldens.select { |g| now[g] && now[g][1] == "default" }.first(2)
  if a && b
    v, = classify_golden(a, File.read(File.join(GOLD, "#{b}.bpf.c")))
    selfcheck << ["byte-compare", v, "differs"]
  end
  # (2) the no-ebpf arm — the one that found 03_fib_recursion and
  #     163_timer_no_interval. Synthesise an all-native probe; demand `no-ebpf`.
  Dir.mktmpdir("reachsc") do |d|
    rb = File.join(d, "sc_all_native.rb")
    File.write(rb, "puts 1\n")
    v, = classify_golden("sc_all_native", File.read(File.join(GOLD, "#{goldens.first}.bpf.c")), rb)
    selfcheck << ["no-ebpf-arm", v, "no-ebpf"]
  end
end

# --- baseline ----------------------------------------------------------------
want  = {}
notes = {}
if File.exist?(BASELINE)
  File.foreach(BASELINE) do |line|
    next if line.start_with?("#") || line.strip.empty?
    art, kind, prod, note = line.chomp.split("\t", 4)
    want[art]  = [kind, prod]
    notes[art] = note.to_s
  end
end

if update
  abort "reach: --update measures the whole corpus; drop the filter" if only
  bad = now.select { |_a, (_k, p)| NEVER_BASELINE.include?(p) }
  unless bad.empty?
    shown = bad.keys.sort.first(5).join(", ")
    shown += ", ... (#{bad.size} total)" if bad.size > 5
    abort "reach: refusing to baseline #{shown} (#{bad.values.map(&:last).uniq.join(',')}).\n" \
          "  `differs` means the product and the codegen emitted different bytes for one fixture —\n" \
          "  the disagreement tools/stage2_verify.sh exists to prevent. Fix it; do not record it."
  end
  missing = now.reject { |a, (k, p)| p == PLAIN[k] || !notes[a].to_s.strip.empty? }
  unless missing.empty?
    abort "reach: #{missing.keys.join(', ')} need a note before they can be baselined.\n" \
          "  Add a line to #{File.basename(BASELINE)} explaining why the product cannot reach it\n" \
          "  AND what would make it reachable again — that is what tells a later reader\n" \
          "  \"kept on purpose\" from \"forgotten\"."
  end
  File.open(BASELINE, "w") do |f|
    f.puts <<~HDR
      # spinel-ebpf product-reachability baseline.
      #
      # The third axis over the tools/golden.rb corpus. golden.rb pins what the
      # CODEGEN emits (component); tools/golden_compile.sh pins whether that text
      # builds and loads; this pins whether `bin/spinel-ebpf compile` — the
      # PRODUCT — still reaches it at all.
      #
      # kind=golden   product: default        the default CLI run emits this golden
      #                        ebpf-dispatch  ... only with --ebpf-dispatch
      #                        no-ebpf        the CLI never calls the codegen
      #                        refused        the CLI refuses the program
      # kind=refusal  product: refused        the CLI refuses it too (gate fires for a user)
      #                        no-ebpf        the CLI exits 0: the refusal never fires
      #
      # `note` is prose and is NOT compared, but it is REQUIRED on every row whose
      # product value is not the plain one (default / refused). An unreachable
      # artifact with no note is indistinguishable from a forgotten one, so the
      # note must say why it is kept and what would make it reachable again.
      #
      # Unlike tests/golden/compile_status.tsv this does not move with the
      # toolchain: no clang, no kernel, no verifier is involved. It moves when a
      # partition rule or a CLI check moves — which is why it is a separate file
      # with a separate --update.
      #
      # Refresh: ruby tools/reach_gate.rb --update   (and review the diff.)
      #
      # artifact\tkind\tproduct\tnote
    HDR
    now.keys.sort.each do |a|
      k, p = now[a]
      f.puts [a, k, p, notes[a].to_s].join("\t")
    end
  end
  puts "reach: wrote #{File.basename(BASELINE)} — #{now.size} artifacts — REVIEW THE DIFF"
  exit 0
end

abort "reach: #{BASELINE} is missing (create it with: ruby tools/reach_gate.rb --update)" unless File.exist?(BASELINE)

problems = []
now.each do |a, (k, p)|
  if NEVER_BASELINE.include?(p)
    problems << "PRODUCT DIVERGED  #{a}  (#{diag[a]})\n" \
                "               The CLI and the codegen emitted different bytes for one fixture.\n" \
                "               This is not baselineable — see tools/stage2_verify.sh."
    next
  end
  unless want.key?(a)
    problems << "NEW ARTIFACT      #{a}  #{k}/#{p}  (not in the baseline; run --update)"
    next
  end
  wk, wp = want[a]
  next if [wk, wp] == [k, p]
  verb =
    if wp == PLAIN[k] then "LOST"          # the product could reach it; now it cannot
    elsif p == PLAIN[k] then "REGAINED"    # ... and the other direction
    else "CHANGED"
    end
  problems << "#{verb.ljust(17)} #{a}  #{wk}/#{wp} -> #{k}/#{p}#{diag[a].to_s.empty? ? '' : "\n               #{diag[a]}"}\n" \
              "               If intended, move the baseline: ruby tools/reach_gate.rb --update"
end
unless only
  (want.keys - now.keys).sort.each do |a|
    problems << "REMOVED ARTIFACT  #{a}  (was #{want[a].join('/')}; no golden and no refusal — run --update)"
  end
end
# The note rule (D4) is structural, not prose review: a non-plain row with an
# empty note cannot be told from one nobody remembers. Artifacts already
# reported above are skipped -- an artifact that just moved has no note yet by
# construction, and repeating it once per rule buries the rule that matters.
reported = problems.map { |m| m.split(/\s+/)[1] }
now.each do |a, (k, p)|
  next if p == PLAIN[k] || NEVER_BASELINE.include?(p)
  next unless notes[a].to_s.strip.empty?
  next if reported.include?(a)
  problems << "NOTE MISSING      #{a}  #{k}/#{p}\n" \
              "               A non-reachable artifact needs a note saying why it is kept and what\n" \
              "               would make it reachable again (#{File.basename(BASELINE)})."
end

sc_bad = selfcheck.reject { |(_n, got, wantv)| got == wantv }

byk = now.group_by { |_a, (k, _p)| k }
puts "-" * 60
["golden", "refusal"].each do |k|
  rows = (byk[k] || [])
  tally = rows.group_by { |_a, (_kk, p)| p }.transform_values(&:size)
  puts "#{k}s: n=#{rows.size}  " + tally.sort.map { |p, c| "#{p}=#{c}" }.join("  ")
end
# Always printed, pass or fail: a gate that hides the known holes behind "OK" is
# how they get forgotten (which is the failure this whole axis is about).
#
# The two are counted apart on purpose. "Reachable only with --ebpf-dispatch" is
# a documented invocation the CLI names in its own refusal, not a lost artifact;
# folding it into the headline would make the number this gate defends wrong by
# one on day one.
comp = now.reject { |a, (k, p)| p == PLAIN[k] || p == "ebpf-dispatch" }
flag = now.select { |_a, (_k, p)| p == "ebpf-dispatch" }
puts "component-only (NO product invocation reaches it): #{comp.size}"
comp.sort.each { |a, (k, p)| puts "    #{a}  [#{k}/#{p}]" }
puts "reachable only with a non-default invocation: #{flag.size}"
flag.sort.each { |a, (k, p)| puts "    #{a}  [#{k}/#{p}]" }
selfcheck.each { |(n, got, wantv)| puts "self-check #{n}: #{got}#{got == wantv ? '' : " (WANTED #{wantv})"}" }
unless problems.empty?
  puts
  problems.each { |m| puts "  #{m}" }
end
unless sc_bad.empty?
  abort "\nreach: self-check failed (#{sc_bad.map(&:first).join(', ')}).\n" \
        "  The gate can no longer detect the thing it exists to detect, so `component-only=#{comp.size}`\n" \
        "  means nothing. Fix the gate before trusting this run."
end
exit(problems.empty? ? 0 : 1)
