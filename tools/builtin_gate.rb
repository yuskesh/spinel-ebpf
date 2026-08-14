#!/usr/bin/env ruby
# frozen_string_literal: true
#
# builtin_gate.rb -- the builtin-schema contract gate.
#
# src/codegen_c/builtin_schema.h declares two axes (declared arity, per-target
# existence) and three consumers derive from it: the C codegen includes the
# header directly, target_profile.rb and capabilities.rb read the generated
# JSON. This gate asks:
#   1. freshness -- is the committed JSON what the header generates now?
#   2. shape     -- names unique per table; every targets row is a non-default,
#                   non-empty set (the generator refuses these too; the gate
#                   re-checks the committed artifact so a hand-edit cannot pass)
#   3. mirror    -- TargetProfile's allowlists equal the schema's selection
#                   (they are sourced from it; this catches a re-literalization)
# The arity/Ruby-signature lockstep lives in capabilities_test; the empirical
# halves (what the backstop actually refuses) live in tools/affordance_gate.rb
# and the target runtime harnesses.

require "json"
require "open3"
require "tmpdir"

ROOT   = File.expand_path("..", __dir__)
GEN    = File.join(ROOT, "tools/gen_builtin_schema.c")
JSON_P = File.join(ROOT, "src/spinel_ebpf/builtin_schema_gen.json")

$fail = 0
def bad(msg)
  warn "builtin_gate: #{msg}"
  $fail += 1
end

def regenerate
  Dir.mktmpdir do |d|
    bin = File.join(d, "gen_builtin_schema")
    out, st = Open3.capture2e("cc", "-O2", "-Wall", "-Wextra", "-o", bin, GEN)
    abort "builtin_gate: generator does not build (that is itself the failure):\n#{out}" unless st.success?
    out, st = Open3.capture2(bin)
    abort "builtin_gate: generator failed: exit #{st.exitstatus}" unless st.success?
    out
  end
end

fresh = regenerate
committed = File.exist?(JSON_P) ? File.read(JSON_P) : nil
if committed.nil?
  bad "#{JSON_P} missing -- run: make -C src/codegen_c builtin-schema"
elsif committed != fresh
  bad "#{JSON_P} is stale or hand-edited -- run: make -C src/codegen_c builtin-schema and commit"
end

doc = JSON.parse(fresh)

def shape_violations(doc)
  v = []
  %w[declared_arity targets].each do |tbl|
    dup = doc.fetch(tbl).map { |r| r["name"] }.tally.select { |_, n| n > 1 }.keys
    v << "#{tbl}: duplicate name(s): #{dup.join(', ')}" unless dup.empty?
  end
  doc.fetch("targets").each do |r|
    ts = r.fetch("targets")
    v << "#{r['name']}: empty target set" if ts.empty?
    v << "#{r['name']}: plain default #{ts.inspect} (scope rule: default rows are not listed)" if ts == ["linux"]
  end
  v
end

def mirror_violations(doc, profiles)
  sel = lambda do |tname|
    doc.fetch("targets").select { |r| r["targets"].include?(tname) }.map { |r| r["name"] }.sort
  end
  v = []
  { "amp" => profiles[:amp] }.each do |tname, allow|
    got = sel.call(tname)
    v << "#{tname}: profile allowlist #{allow.sort.inspect} != schema #{got.inspect}" unless allow.sort == got
  end
  v
end

shape_violations(doc).each { |m| bad "shape: #{m}" }

$LOAD_PATH.unshift File.join(ROOT, "src")
require "spinel_ebpf/target_profile"
profiles = { amp: SpinelEbpf::TargetProfile::AMP.call_allowlist }
mirror_violations(doc, profiles).each { |m| bad "mirror: #{m}" }

MUTATIONS = {
  "dropped_target_row_caught" => lambda { |doc, profiles|
    mut = JSON.parse(JSON.generate(doc))
    mut["targets"].reject! { |r| r["name"] == "ktime_ns" }
    mirror_violations(mut, profiles).any?
  },
  "default_row_caught" => lambda { |doc, _|
    mut = JSON.parse(JSON.generate(doc))
    mut["targets"] << { "name" => "pid", "targets" => ["linux"] }
    shape_violations(mut).any?
  },
}.freeze

MUTATIONS.each do |name, m|
  next if m.call(doc, profiles)
  abort "builtin_gate: SELF-CHECK FAILED: mutation #{name} was not caught -- " \
        "the gate cannot say no, so its green is meaningless"
end

if $fail.zero?
  puts "builtin_gate: arity_rows=#{doc['declared_arity'].size} target_rows=#{doc['targets'].size} " \
       "fresh=yes shape=ok mirror=ok self-check=#{MUTATIONS.size}/#{MUTATIONS.size}"
else
  abort "builtin_gate: #{$fail} violation(s)"
end
