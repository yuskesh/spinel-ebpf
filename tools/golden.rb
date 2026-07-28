#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Golden-snapshot regression gate.
#
# Replaces the Ruby byte-identity *lockstep*: now that the C codegen is the
# production source of truth and is gaining structured emission (a C AST layer
# instead of raw string building), pinning its output to the Ruby codegen forced
# every change to drag Ruby along. Instead we pin the C codegen's output to committed goldens
# under tests/golden/. The C codegen is free to evolve — an intentional output
# change is a reviewable golden diff (regenerate with --update). The Ruby codegen
# (tools/cgen_oracle.rb) is retired from the gate; it stays only as a historical
# port-parity check, run on demand.
#
#   ruby tools/golden.rb            # gate: C codegen output == tests/golden/*.bpf.c
#   ruby tools/golden.rb --update   # regenerate goldens from the current C codegen
#   ruby tools/golden.rb <base>     # one fixture, show the diff
#
# Exit non-zero if any golden DIFFERS (regression) or is MISSING.
require "open3"

ROOT = File.expand_path("..", __dir__)
FIX  = File.join(ROOT, "tests/fixtures")
GOLD = File.join(ROOT, "tests/golden")
CC   = File.join(ROOT, "build/codegen_c/spinel_ebpf_cc")
abort "C codegen not built: #{CC}\n  (cc -O2 -o #{CC} src/codegen_c/spinel_ebpf_cc.c)" unless File.executable?(CC)

# Preflight: +x is not enough. build/ is shared with the container via the bind
# mount, so a container build can leave a Linux ELF here (or vice versa) that this
# host cannot exec. Every fixture then "fails" and lands in the no-ebpf skip bucket,
# which used to report `PASS=0 ... skip(no-ebpf)=99` and **exit 0** — a green that
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
bases.each do |b|
  cout, _cerr, st = Open3.capture3(CC, "#{FIX}/#{b}.ir", "#{FIX}/#{b}.ast", b)
  # The C codegen rejects (exit != 0) programs with no eBPF-eligible method, and
  # emits only a trivial header for ones with eBPF content absent (no `_inner`).
  # Neither is a meaningful golden target — production only writes .bpf.c when
  # there are eBPF programs.
  unless st.success? && cout.include?("_inner")
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

puts "-" * 60
puts "PASS=#{pass}  DIFF=#{diff}  MISSING=#{miss}  skip(no-ebpf)=#{skip}" \
     "#{update ? '   (goldens written)' : ''}"

# A gate that compared nothing is not a pass. The skip bucket is meant for the few
# fixtures with no eBPF-eligible method; if it swallowed *everything*, the codegen is
# broken, not the corpus. (Belt-and-braces with the preflight above: that catches a
# non-runnable binary, this catches any other way the whole run turns into skips.)
if pass + diff + miss == 0
  abort "\ngolden: nothing was compared — all #{skip} fixtures skipped.\n" \
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

exit((diff + miss).zero? ? 0 : 1)
