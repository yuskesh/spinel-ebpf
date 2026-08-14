#!/usr/bin/env ruby
# frozen_string_literal: true
#
# attach_gate.rb -- the attach-vocabulary contract gate.
#
# The attach vocabulary is declared once in src/codegen_c/attach_schema.h;
# cc_detect_attach() walks that table and the Ruby side reads its JSON rendering
# (src/spinel_ebpf/attach_schema_gen.json). Generating the second view removed
# the duplicate declaration, but not the need to measure -- what changes is WHAT
# the gate audits. This gate asks four questions, none of which the golden gate
# or the affordance gate ask:
#
#   1. freshness  -- is the committed JSON what attach_schema.h generates NOW?
#                    (the generator failing to build is itself a loud failure)
#   2. shadowing  -- table order is match order; a row whose prefix extends an
#                    EARLIER row's prefix is unreachable, which is the
#                    false-negative class where "present" is answered from the
#                    shorter prefix
#   3. uniqueness -- kinds, knames and prefixes each name exactly one row
#   4. mirror     -- the Ruby ATTACH_KINDS (which keeps the affordance prose)
#                    agrees with the schema on the machine axes it does not
#                    source directly: same kind set both ways, sec equal (it is
#                    sourced -- this catches a future re-literalization), and
#                    ctx_type either equal to the schema's or extending it as an
#                    annotation ("__u64 * (arm prog ...)" may say more, never
#                    something else; where the schema has none, prose is free)
#
# Self-check: the gate re-proves it can say NO by mutating an in-memory copy of
# the schema four ways and requiring each mutation to be caught. Controls that
# depend on live inventory dry up; synthesized ones do not.

require "json"
require "open3"
require "tmpdir"

ROOT   = File.expand_path("..", __dir__)
HEADER = File.join(ROOT, "src/codegen_c/attach_schema.h")
GEN    = File.join(ROOT, "tools/gen_attach_schema.c")
JSON_P = File.join(ROOT, "src/spinel_ebpf/attach_schema_gen.json")

$fail = 0
def bad(msg)
  warn "attach_gate: #{msg}"
  $fail += 1
end

# ---------- 1. freshness ----------
def regenerate
  Dir.mktmpdir do |d|
    bin = File.join(d, "gen_attach_schema")
    out, st = Open3.capture2e("cc", "-O2", "-Wall", "-Wextra", "-o", bin, GEN)
    abort "attach_gate: generator does not build (that is itself the failure):\n#{out}" unless st.success?
    out, st = Open3.capture2(bin)
    abort "attach_gate: generator failed: exit #{st.exitstatus}" unless st.success?
    out
  end
end

fresh = regenerate
committed = File.exist?(JSON_P) ? File.read(JSON_P) : nil
if committed.nil?
  bad "#{JSON_P} missing -- run: make -C src/codegen_c attach-schema"
elsif committed != fresh
  bad "#{JSON_P} is stale or hand-edited -- run: make -C src/codegen_c attach-schema and commit"
end

rows = JSON.parse(fresh)

# ---------- 2 + 3. schema invariants (pure functions so self-check can reuse) ----------
def shadow_violations(rows)
  prefixes = rows.select { |r| r["detect"] == "prefix" }.map { |r| [r["kind"], r["prefix"]] }
  v = []
  prefixes.each_with_index do |(k, p), j|
    prefixes[0...j].each do |(ek, ep)|
      v << "#{k} (#{p}) is shadowed by earlier row #{ek} (#{ep})" if p.start_with?(ep)
    end
  end
  v
end

def uniqueness_violations(rows)
  v = []
  %w[kind kname].each do |f|
    dup = rows.map { |r| r[f] }.tally.select { |_, n| n > 1 }.keys
    v << "duplicate #{f}: #{dup.join(', ')}" unless dup.empty?
  end
  dup = rows.map { |r| r["prefix"] }.compact.tally.select { |_, n| n > 1 }.keys
  v << "duplicate prefix: #{dup.join(', ')}" unless dup.empty?
  v
end

shadow_violations(rows).each { |m| bad "shadowing: #{m}" }
uniqueness_violations(rows).each { |m| bad "uniqueness: #{m}" }

# ---------- 4. mirror (Ruby ATTACH_KINDS vs schema) ----------
$LOAD_PATH.unshift File.join(ROOT, "src")
require "spinel_ebpf/capabilities"
CAP = SpinelEbpf::Capabilities

def mirror_violations(rows, attach_kinds)
  v = []
  schema_kinds = rows.map { |r| r["kind"] }.sort
  ruby_kinds   = attach_kinds.map { |a| a[:kind].to_s }.sort
  v << "kind sets differ: schema-only=#{(schema_kinds - ruby_kinds).join(',')} " \
       "ruby-only=#{(ruby_kinds - schema_kinds).join(',')}" if schema_kinds != ruby_kinds
  by_kind = rows.map { |r| [r["kind"], r] }.to_h
  attach_kinds.each do |a|
    row = by_kind[a[:kind].to_s] or next
    v << "#{a[:kind]}: sec #{a[:sec].inspect} != schema #{row['sec'].inspect}" if a[:sec] != row["sec"]
    sc = row["ctx_type"]
    rc = a[:ctx_type]
    if sc && !(rc.is_a?(String) && rc.start_with?(sc))
      v << "#{a[:kind]}: ctx_type #{rc.inspect} does not extend schema #{sc.inspect}"
    end
  end
  v
end

mirror_violations(rows, CAP::ATTACH_KINDS).each { |m| bad "mirror: #{m}" }

# ---------- self-check: prove the gate can say NO ----------
MUTATIONS = {
  "dropped_row_caught" => lambda { |rows, ak|
    mirror_violations(rows.reject { |r| r["kind"] == "kprobe" }, ak).any?
  },
  "shadow_caught" => lambda { |rows, _ak|
    # move the plain xdp__ row in front of xdp__tcp_slice__ -- the exact shape
    # of the false negative this ordering exists to prevent
    mut = rows.sort_by.with_index { |r, i| r["kind"] == "xdp" ? -1 : i }
    shadow_violations(mut).any?
  },
  "sec_change_caught" => lambda { |rows, ak|
    mut = rows.map { |r| r["kind"] == "lsm" ? r.merge("sec" => "lsm.wrong/<hook>") : r }
    mirror_violations(mut, ak).any?
  },
  "ctx_type_change_caught" => lambda { |rows, ak|
    mut = rows.map { |r| r["kind"] == "kprobe" ? r.merge("ctx_type" => "struct sk_buff *") : r }
    mirror_violations(mut, ak).any?
  },
}.freeze

MUTATIONS.each do |name, m|
  next if m.call(rows.map(&:dup), CAP::ATTACH_KINDS)
  abort "attach_gate: SELF-CHECK FAILED: mutation #{name} was not caught -- " \
        "the gate cannot say no, so its green is meaningless"
end

if $fail.zero?
  puts "attach_gate: rows=#{rows.size} (prefix=#{rows.count { |r| r['detect'] == 'prefix' }} " \
       "class=#{rows.count { |r| r['detect'] == 'class' }}) fresh=yes shadowed=0 " \
       "mirror=ok self-check=#{MUTATIONS.size}/#{MUTATIONS.size}"
else
  abort "attach_gate: #{$fail} violation(s)"
end
