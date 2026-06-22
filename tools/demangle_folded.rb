#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Demangle spinel C symbols (`sp_<...>`) in a folded-stack file to Ruby names +
# source location, using an upstream `--emit-symbol-map` JSON. Pairs the eBPF
# self-profiler's user-stack flame graph with spinel's symbol map so frames read
# `fib (app.rb:1)` instead of `sp_fib`.
#
#   build/spinel app.rb --emit-symbol-map -o syms.json   # (or build/<base>.symmap.json from --instrument)
#   ./profiler ... > folded.txt                          # user-stack folded output
#   ruby tools/demangle_folded.rb syms.json folded.txt > folded.ruby.txt
#   flamegraph.pl < folded.ruby.txt > flame.svg
#
# Folded format: `frameA;frameB;... <count>` per line. Only `sp_<ident>` tokens
# that appear in the symbol map are rewritten; kernel/libc frames pass through.
require "json"

def build_map(json_path)
  syms = JSON.parse(File.read(json_path))["symbols"] || []
  syms.each_with_object({}) do |s, h|
    next unless s["c"] && s["ruby"]
    h[s["c"]] = if s["line"]
                  "#{s['ruby']} (#{File.basename(s['file'].to_s)}:#{s['line']})"
                else
                  s["ruby"]
                end
  end
end

# Rewrite every `sp_<ident>` token found in the symbol map; leave the rest
# (offsets like `+0x10`, `[binary]`, kernel/libc names) untouched.
def demangle_line(line, c2ruby)
  line.gsub(/sp_[A-Za-z0-9_]+/) { |sym| c2ruby[sym] || sym }
end

if $PROGRAM_NAME == __FILE__
  map_path = ARGV.shift or abort "usage: demangle_folded.rb <symmap.json> [folded.txt]"
  c2ruby = build_map(map_path)
  io = ARGV.empty? ? $stdin : File.open(ARGV[0])
  io.each_line { |line| print demangle_line(line, c2ruby) }
end
