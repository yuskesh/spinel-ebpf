# frozen_string_literal: true
#
# Intent-independent invariants -- the properties that can be checked without
# knowing what a probe is trying to measure.
#
#   determinism  the same workload twice produces the same count
#   monotonicity narrowing the filter never increases the count
#   halting      after the probe ends, no BPF trace of it is left
#
# ## Why being a single file is the requirement
#
# A semantic check -- "does this probe measure DNS, or does it measure UDP and
# call it DNS" -- has to encode the intent, so there is no general one of those:
# write it per probe and you end up with as many variants as probes. That is the
# correct way for such a check to grow, because the intent really is different
# each time.
#
# What is collected here is the opposite kind of property. All three can be
# written **without knowing anything about what the probe measures**, so this
# file does not grow when probes do. If it starts growing, that is evidence that
# intent has been mixed in, not evidence of a missing feature. Before adding
# something, ask whether it can be written without knowing the probe.
#
# ## What it does not promise
#
# All three passing is **not** evidence that a probe measures what it was meant
# to. A probe that measures generic UDP while believing it measures DNS is
# deterministic, monotonic, and tears down cleanly. That region needs intent,
# and stays a job for a per-probe semantic check or for a person.
#
# ## Usage
#
#   ruby tools/invariants.rb --probe P.rb --workload 'CMD'
#   ruby tools/invariants.rb --probe P.rb --narrower Q.rb --workload 'CMD'
#
#   --probe      the .rb under test
#   --narrower   a .rb with a strictly tighter condition (monotonicity only)
#   --workload   the command to run each time. **Determinism cannot be measured
#                unless this is itself deterministic.**
#   --settle     seconds to wait before the workload, for attach (default 1)
#   --drain      seconds to wait after it, for the drain to catch up (default 2)
#   --repeat     determinism trials (default 2)
#   --keep       do not delete build artifacts
#
# Judgements are conservative: a violation is "suspicious", not "wrong". On a
# noisy host determinism cannot be measured in principle, and the tool says so.
# Exit status is 1 if anything broke -- this is a check rather than a diagnosis,
# so unlike the channel balance report it is fine to gate on.

require "open3"
require "set"
require "tmpdir"
require "fileutils"

ROOT = File.expand_path("..", __dir__)

def die(msg)
  warn "invariants: #{msg}"
  exit 2
end

# ---- arguments --------------------------------------------------------------

opts = { settle: 1, drain: 2, repeat: 2, keep: false }
argv = ARGV.dup
until argv.empty?
  case (a = argv.shift)
  when "--probe"    then opts[:probe]    = argv.shift
  when "--narrower" then opts[:narrower] = argv.shift
  when "--workload" then opts[:workload] = argv.shift
  when "--settle"   then opts[:settle]   = argv.shift.to_f
  when "--drain"    then opts[:drain]    = argv.shift.to_f
  when "--repeat"   then opts[:repeat]   = argv.shift.to_i
  when "--keep"     then opts[:keep]     = true
  when "-h", "--help" then puts File.read(__FILE__)[/\A(#.*\n)+/].gsub(/^# ?/, ""); exit 0
  else die("unknown argument #{a}")
  end
end
die("--probe is required")    unless opts[:probe]
die("--workload is required") unless opts[:workload]
die("#{opts[:probe]}: no such file") unless File.file?(opts[:probe])
die("#{opts[:narrower]}: no such file") if opts[:narrower] && !File.file?(opts[:narrower])
die("--repeat must be >= 2") if opts[:repeat] < 2

# ---- build and run a probe --------------------------------------------------

def build(rb, outdir)
  cmd = ["ruby", File.join(ROOT, "bin", "spinel-ebpf"), "compile", rb, "-o", outdir, "--build"]
  out, st = Open3.capture2e(*cmd, chdir: ROOT)
  die("build failed for #{rb}\n#{out}") unless st.success?
  bin = File.join(outdir, File.basename(rb, ".rb"))
  die("build produced no binary for #{rb}") unless File.executable?(bin)
  bin
end

# Start the probe -> settle -> workload -> drain -> SIGTERM.
#
# Counts are read from the key/value form of the channel balance report
# (SPNL_CHANNEL_REPORT=kv), never from its prose. The prose exists to be
# improved, and a tool that parsed it would turn every improvement into a
# breaking change.
def run_once(bin, workload, settle, drain)
  err_r, err_w = IO.pipe
  pid = Process.spawn(
    { "SPNL_CHANNEL_REPORT" => "kv" }, bin,
    out: File::NULL, err: err_w
  )
  err_w.close
  sleep settle
  system(workload, out: File::NULL, err: File::NULL)
  sleep drain
  Process.kill("TERM", pid)
  Process.wait(pid)
  err = err_r.read
  err_r.close

  counts = {}
  err.each_line do |ln|
    next unless ln.start_with?("spnl.channel ")
    f = ln.split
    name = f[1]
    kv = f[2..].to_h { |p| k, v = p.split("="); [k, v.to_i] }
    counts[name] = kv
  end
  die("no channel report from #{bin}. does the probe have a ringbuf channel?") if counts.empty?
  counts
end

# ---- halting: does the BPF trace go back to what it was? --------------------
#
# What is compared is **the whole host's BPF state**, not the probe's, so
# anything else that loads a program during the run also shows up as residue
# (observed, not assumed). Measure on a quiet host. Put the other way round:
# this is the same before == after comparison used to claim that a one-shot
# probe injection leaves no trace behind.
#
# Hosts without bpftool skip this invariant only; the other two still work.
def bpf_ids
  out, st = Open3.capture2e("bpftool", "prog", "show")
  return nil unless st.success?
  progs = out.scan(/^(\d+):/).flatten.to_set
  out, st = Open3.capture2e("bpftool", "map", "show")
  return nil unless st.success?
  [progs, out.scan(/^(\d+):/).flatten.to_set]
end

# ---- run --------------------------------------------------------------------

results = []   # [name, ok(true/false/nil=skipped), detail]
work = opts[:keep] ? File.join(ROOT, "build", "invariants") : Dir.mktmpdir("spnl-inv")
FileUtils.mkdir_p(work)

begin
  puts "invariants: building #{opts[:probe]}"
  wide = build(opts[:probe], File.join(work, "wide"))

  # --- halting --------------------------------------------------------------
  before = bpf_ids
  runs = []
  opts[:repeat].times do |i|
    puts "invariants: run #{i + 1}/#{opts[:repeat]}"
    runs << run_once(wide, opts[:workload], opts[:settle], opts[:drain])
  end
  after = bpf_ids

  if before.nil? || after.nil?
    results << ["halting", nil, "bpftool is not available, so this was not measured"]
  else
    leaked_p = after[0] - before[0]
    leaked_m = after[1] - before[1]
    if leaked_p.empty? && leaked_m.empty?
      results << ["halting", true, "prog/map ids are back to the set from before the run"]
    else
      results << ["halting", false,
                  "residue prog=#{leaked_p.to_a.join(',')} map=#{leaked_m.to_a.join(',')} " \
                  "-- BPF is still loaded after the probe ended. The glue destructor is not " \
                  "detaching, or something is pinned. **This looks at the whole host, so also " \
                  "check that nothing else loaded BPF during the run.**"]
    end
  end

  # --- determinism ----------------------------------------------------------
  chans = runs.flat_map(&:keys).uniq
  bad = []
  chans.each do |c|
    ins = runs.map { |r| r.dig(c, "in") || 0 }
    bad << "#{c}: #{ins.join(' / ')}" if ins.uniq.size > 1
  end
  if bad.empty?
    detail = chans.map { |c| "#{c}=#{runs[0].dig(c, 'in')}" }.join(" ")
    results << ["determinism", true, "same count on all #{opts[:repeat]} runs (#{detail})"]
  else
    results << ["determinism", false,
                "counts differ between runs: #{bad.join(', ')} -- either the probe is " \
                "non-deterministic (a race, or state not reset), or the workload is not " \
                "deterministic, or the host is not quiet. **Suspect the last two first.**"]
  end

  if runs[0].values.all? { |v| v["in"].zero? }
    results << ["premise", nil,
                "every run drained 0 records. **All three invariants then hold vacuously**, " \
                "so nothing has been shown. Look at the channel balance report " \
                "(SPNL_CHANNEL_REPORT with its default value) and get records flowing first."]
  end

  # --- monotonicity ---------------------------------------------------------
  if opts[:narrower]
    puts "invariants: building #{opts[:narrower]} (narrower)"
    narrow = build(opts[:narrower], File.join(work, "narrow"))
    puts "invariants: run narrower"
    nr = run_once(narrow, opts[:workload], opts[:settle], opts[:drain])

    # Channel names are `<unit>_<kind>_events`, where unit is the .rb basename.
    # Two different probes therefore have different channel names, so drop the
    # unit and pair them up by kind. That mapping comes from the filename rather
    # than from guessing, which is what keeps this from needing to know the probe.
    strip = lambda do |rb, h|
      unit = File.basename(rb, ".rb")
      h.to_h { |k, v| [k.sub(/\A#{Regexp.escape(unit)}_/, ""), v] }
    end
    wide_by = strip.(opts[:probe], runs[0])
    narr_by = strip.(opts[:narrower], nr)
    common  = wide_by.keys & narr_by.keys

    if common.empty?
      results << ["monotonicity", nil,
                  "the two probes have no corresponding channel (#{wide_by.keys.join(',')} / " \
                  "#{narr_by.keys.join(',')}). Check that they use the same kind of emit."]
    else
      viol = common.reject { |c| narr_by[c]["in"] <= wide_by[c]["in"] }
      if viol.empty?
        d = common.map { |c| "#{c}: #{wide_by[c]['in']} -> #{narr_by[c]['in']}" }.join(", ")
        results << ["monotonicity", true, "the narrower probe did not count more (#{d})"]
      else
        d = viol.map { |c| "#{c}: #{wide_by[c]['in']} -> #{narr_by[c]['in']}" }.join(", ")
        results << ["monotonicity", false,
                    "the narrower probe counted **more**: #{d} -- either the filter has no " \
                    "effect, or the condition that was meant to narrow admits something else"]
      end
    end
  end
ensure
  FileUtils.remove_entry(work) if !opts[:keep] && Dir.exist?(work)
end

# ---- report -----------------------------------------------------------------

puts
puts "intent-independent invariants"
broke = 0
results.each do |name, ok, detail|
  mark = ok.nil? ? "--" : (ok ? "OK" : "**")
  broke += 1 if ok == false
  puts format("  %-13s %-4s %s", name, mark, detail)
end
puts
puts "  note: all three passing is not evidence that the probe measures what it was " \
     "meant to. That needs intent, and stays a job for a per-probe semantic check or a person."
exit(broke.zero? ? 0 : 1)
