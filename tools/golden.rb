#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Golden-snapshot regression gate.
#
# Replaces the Ruby byte-identity *lockstep*: now that the C codegen is the
# production source of truth and is gaining structured emission (a C AST layer
# instead of raw string building), pinning its output to the Ruby codegen forced
# every change to drag Ruby along. Instead we pin the C codegen's output to committed goldens
# under tests/golden/. The C codegen is free to evolve -- an intentional output
# change is a reviewable golden diff (regenerate with --update). The Ruby codegen
# (tools/cgen_oracle.rb) is retired from the gate; it stays only as a historical
# port-parity check, run on demand.
#
#   ruby tools/golden.rb            # gate: C codegen output == tests/golden/*.bpf.c
#   ruby tools/golden.rb --update   # regenerate goldens from the current C codegen
#   ruby tools/golden.rb <base>     # one fixture, show the diff
#
# Exit non-zero if any golden DIFFERS (regression) or is MISSING.
#
# The run also pins WHICH fixtures the codegen refuses. Before that, a fixture
# the codegen rejected just vanished into the skip bucket, which is how four
# negative fixtures (78/80/82/96 -- "codegen must reject this") ended up with
# committed goldens instead: their gates had been lost in the C port and
# nothing said so. A rejection is now a fact with a name in
# tests/golden/codegen_reject.tsv, and a rejected fixture may not also have a
# golden. (Whether the goldens that DO exist actually build and load is a
# different question, and needs a toolchain: tools/golden_compile.sh.)
require "open3"

ROOT   = File.expand_path("..", __dir__)
FIX    = File.join(ROOT, "tests/fixtures")
GOLD   = File.join(ROOT, "tests/golden")
REJECT = File.join(GOLD, "codegen_reject.tsv")
CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
abort "C codegen not built: #{CC}\n  (cc -O2 -o #{CC} src/codegen_c/spinel_ebpf_cc.c)" unless File.executable?(CC)

# Preflight: +x is not enough. build/ is shared with the container via the bind
# mount, so a container build can leave a Linux ELF here (or vice versa) that this
# host cannot exec. Every fixture then "fails" and lands in the no-ebpf skip bucket,
# which used to report `PASS=0 ... skip(no-ebpf)=99` and **exit 0** -- a green that
# proves nothing ran. A working binary prints its usage line when given no args.
_pre_out, _pre_err, _pre_st = Open3.capture3(CC)
unless "#{_pre_out}#{_pre_err}".include?("usage:")
  abort "golden: #{CC} exists but does not run here (no usage line; exit " \
        "#{_pre_st.exitstatus.inspect}).\n" \
        "  Likely built for the other platform (build/ is bind-mounted into the container).\n" \
        "  Rebuild for this host: cc -O2 -o #{CC} src/codegen_c/spinel_ebpf_cc.c"
end

update = !ARGV.delete("--update").nil?
only   = ARGV[0]
bases  = Dir["#{FIX}/*.ir"].map { |f| File.basename(f, ".ir") }.sort
bases.select! { |b| b == only } if only

Dir.mkdir(GOLD) unless Dir.exist?(GOLD)

pass = diff = skip = miss = 0
diffs = []
rejected = {}   # base -> first line of the codegen's refusal
bases.each do |b|
  # SPNL_ATTACH_MULTI is a measurement knob (it redirects `on :kprobe,
  # %w[...]` handlers that did not declare `via:`). A gate that a stray shell
  # export can steer is not a gate, so it is cleared here and the corpus is
  # measured against the compiled-in default.
  cout, cerr, st = Open3.capture3({ "SPNL_ATTACH_MULTI" => nil },
                                  CC, "#{FIX}/#{b}.ir", "#{FIX}/#{b}.ast", b)
  # Two different non-goldens, which used to share one bucket:
  #   exit != 0        -> the codegen REFUSED the program. That is a claim worth
  #                       pinning: a refusal that appears or disappears is a
  #                       behaviour change, not a skip.
  #   exit 0, no _inner-> nothing eBPF-eligible in it. Production writes no
  #                       .bpf.c either, so there is no golden to compare.
  unless st.success?
    rejected[b] = cerr.lines.first.to_s.strip
    next
  end
  unless cout.include?("_inner")
    skip += 1
    next
  end
  gpath = File.join(GOLD, "#{b}.bpf.c")
  if update
    File.write(gpath, cout)
    pass += 1
    next
  end
  unless File.exist?(gpath)
    miss += 1
    puts format("  MISSING %s  (run: ruby tools/golden.rb --update)", b)
    next
  end
  if cout == File.read(gpath)
    pass += 1
  else
    diff += 1
    diffs << [b, File.read(gpath), cout]
    puts format("  DIFF    %s", b)
  end
end

# --- the refusal set is part of the contract ---------------------------------
#
# Only meaningful over the whole corpus, so a single-fixture run skips it.
reject_problems = []
unless only
  want = {}
  if File.exist?(REJECT)
    File.foreach(REJECT) do |line|
      next if line.start_with?("#") || line.strip.empty?
      name, note = line.chomp.split("\t", 2)
      want[name] = note.to_s
    end
  end
  if update
    header = <<~HDR
      # Fixtures the production C codegen REFUSES (exit != 0), and why.
      #
      # A fixture here must have NO tests/golden/*.bpf.c: refusing it and also
      # shipping a golden for it is a contradiction -- 78/80/82/96 each say
      # "codegen must reject this" in their own comments, yet had goldens.
      #
      # The reason column is prose for the reviewer and is NOT compared -- only the
      # SET of refused fixtures is. Message wording is the business of
      # tests/spinel_ebpf/builtin_ctx_gate_test.rb, which asserts the parts an
      # author needs (what, why, which contexts work, where they wrote it).
      #
      # Refresh: ruby tools/golden.rb --update   (and review the diff: a fixture
      # appearing here means the codegen started refusing something it compiled.)
      #
    HDR
    rows = rejected.keys.sort.map do |b|
      note = want[b].to_s.empty? ? rejected[b] : want[b]
      "#{b}\t#{note}"
    end
    File.write(REJECT, header + rows.join("\n") + "\n")
  else
    (rejected.keys - want.keys).sort.each do |b|
      reject_problems << "NEW REFUSAL  #{b}  (#{rejected[b]})\n" \
                         "               If intended, record it: ruby tools/golden.rb --update"
    end
    (want.keys - rejected.keys).sort.each do |b|
      reject_problems << "NO LONGER REFUSED  #{b}  (was: #{want[b]})\n" \
                         "               A gate stopped firing, or the node type got ported. Either way the " \
                         "baseline must move: ruby tools/golden.rb --update"
    end
  end
  rejected.each_key do |b|
    next unless File.exist?(File.join(GOLD, "#{b}.bpf.c"))
    reject_problems << "REFUSED BUT HAS GOLDEN  #{b}\n" \
                       "               tests/golden/#{b}.bpf.c is output the codegen no longer produces -- delete it."
  end
  # Orphans: a golden whose fixture is gone reviews as \"still covered\" forever.
  Dir["#{GOLD}/*.bpf.c"].map { |f| File.basename(f, ".bpf.c") }.sort.each do |b|
    next if File.exist?("#{FIX}/#{b}.ir")
    reject_problems << "ORPHAN GOLDEN  #{b}  (no tests/fixtures/#{b}.ir) -- delete it or restore the fixture."
  end
end

puts "-" * 60
puts "PASS=#{pass}  DIFF=#{diff}  MISSING=#{miss}  skip(no-ebpf)=#{skip}  refused=#{rejected.size}" \
     "#{update ? '   (goldens written)' : ''}"
unless reject_problems.empty?
  puts
  reject_problems.each { |m| puts "  #{m}" }
end

# A gate that compared nothing is not a pass. The skip bucket is meant for the few
# fixtures with no eBPF-eligible method; if it swallowed *everything*, the codegen is
# broken, not the corpus. (Belt-and-braces with the preflight above: that catches a
# non-runnable binary, this catches any other way the whole run turns into skips.)
if pass + diff + miss == 0
  abort "\ngolden: nothing was compared -- all #{skip + rejected.size} fixtures skipped.\n" \
        "  That is a broken gate, not a pass: the C codegen rejected every fixture.\n" \
        "  Check that #{CC} is current and runs on this host."
end

if only && diffs.any?
  b, golden, cout = diffs.first
  require "tempfile"
  Tempfile.create("g") do |g|
    Tempfile.create("c") do |c|
      g.write(golden); g.flush; c.write(cout); c.flush
      puts "--- diff (golden | current) for #{b} ---"
      system("diff", g.path, c.path)
    end
  end
end

exit((diff + miss + reject_problems.size).zero? ? 0 : 1)
