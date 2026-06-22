#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby-parity check — HISTORICAL, no longer the gate.
#
# This harness verified the C port by diffing the Ruby `CodegenBpf.emit` output
# against the C codegen (byte-identical = faithful port). It drove the whole
# initial port to PASS=84/DIFF=0. The C codegen is now the production source of
# truth and the regression gate is tools/golden.rb (C output == committed
# tests/golden/*.bpf.c). The Ruby codegen is no longer kept in lockstep, so this
# check WILL diverge as the C codegen evolves — keep it only to inspect where C
# and the frozen Ruby reference differ.
#
#   ruby tools/cgen_oracle.rb            # board over all fixtures (informational)
#   ruby tools/cgen_oracle.rb 02_integer_arith   # one fixture, show diff
#
# NOTE: exits non-zero on any DIFF, but this is NOT a CI gate anymore — use
# tools/golden.rb for regression and expect DIFFs here once the codegens diverge.
$LOAD_PATH.unshift File.expand_path("../src", __dir__)
require "spinel_ebpf/parse_spinel_ir"
require "spinel_ebpf/parse_spinel_ast"
require "spinel_ebpf/partition"
require "spinel_ebpf/codegen_bpf"
require "open3"

FIX = File.expand_path("../tests/fixtures", __dir__)
CC  = File.expand_path("../build/codegen_c/spinel_ebpf_cc", __dir__)
abort "C codegen not built: #{CC}\n  (cc -O2 -o #{CC} src/codegen_c/spinel_ebpf_cc.c)" unless File.executable?(CC)

only  = ARGV[0]
bases = Dir["#{FIX}/*.ir"].map { |f| File.basename(f, ".ir") }.sort
bases.select! { |b| b == only } if only

pass = diff = err = skip = rub = 0
diffs = []
bases.each do |b|
  ir  = SpinelEbpf::ParseSpinelIR.parse_file("#{FIX}/#{b}.ir")
  ast = SpinelEbpf::ParseSpinelAst.parse_file("#{FIX}/#{b}.ast")
  res = SpinelEbpf::Partition.classify(ir, ast)
  if res.methods.none? { |m| m.tag == :ebpf }
    skip += 1
    next
  end
  # The Ruby codegen itself raises UnsupportedNode on features its MVP doesn't
  # cover — those fixtures aren't a valid oracle target.
  begin
    golden = SpinelEbpf::CodegenBpf.emit(ir, ast, res, base_name: b)
  rescue StandardError => e
    rub += 1
    puts format("  RUBY?  %-28s %s", b, e.message.lines.first&.strip)
    next
  end
  cout, cerr, st = Open3.capture3(CC, "#{FIX}/#{b}.ir", "#{FIX}/#{b}.ast", b)
  if !st.success?
    err += 1
    puts format("  C-ERR  %-28s %s", b, cerr.strip.lines.last&.strip)
  elsif cout == golden
    pass += 1
    puts format("  PASS   %s", b)
  else
    diff += 1
    diffs << [b, golden, cout]
    puts format("  DIFF   %s", b)
  end
end

puts "-" * 60
puts "PASS=#{pass}  DIFF=#{diff}  C-ERR(unported)=#{err}  skip(no-ebpf)=#{skip}  ruby-unsup=#{rub}"

# When a single fixture is requested, show the diff to drive porting.
if only && diffs.any?
  b, golden, cout = diffs.first
  require "tempfile"
  Tempfile.create("g") do |g|
    Tempfile.create("c") do |c|
      g.write(golden); g.flush; c.write(cout); c.flush
      puts "--- diff (golden Ruby | C) for #{b} ---"
      system("diff", g.path, c.path)
    end
  end
end

exit(diff.zero? ? 0 : 1)
