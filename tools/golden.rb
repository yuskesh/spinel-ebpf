#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Golden-snapshot regression gate.
#
# Replaces the Ruby byte-identity *lockstep*: now that the C codegen is the
# production source of truth and is gaining structured emission (the C AST
# emitter), pinning its output to the Ruby codegen forced every change to
# drag Ruby along. Instead we pin the C codegen's output to committed goldens
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
