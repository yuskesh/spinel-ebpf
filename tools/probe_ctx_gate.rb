#!/usr/bin/env ruby
# frozen_string_literal: true
#
# probe_ctx_gate.rb -- the evolution gate for the probe context contract.
#
#   ruby tools/probe_ctx_gate.rb            # exit 1 on any problem
#   ruby tools/probe_ctx_gate.rb --update   # move the baseline (REVIEW THE DIFF)
#
# Two checks, the same pair tools/record_gate.rb runs over the ringbuf contract:
#
#   (1) FRESH -- the committed artifacts are what the generator currently emits.
#       Forgetting `make -C src/codegen_c probe-ctx` after editing the schema is
#       the normal way for a generated file to go stale, so it fails here rather
#       than in a firmware that reads a field id nobody else agrees about.
#
#   (2) APPEND-ONLY -- against tests/golden/probe_ctx_schema.snapshot.json.
#
# Why append-only is stricter here than "don't break the build": a field id is
# an immediate operand baked into every AOT blob that ever called ctx_field on
# it. Renumbering one does not fail to compile; it silently makes an old probe
# read a different value. The same holds one level up -- withdrawing a field from
# an attach point breaks probes that were admitted against the capability that
# published it, and they, too, fail by reading something else rather than by
# failing to load.
#
# Breaking (refused):
#   - a field removed, renumbered, retyped, resized, or its signedness flipped
#   - a field that was exposed becoming unexposed, or changing its Ruby type
#   - an attach point removed or renumbered
#   - a field withdrawn from an attach point
#   - exec_class changed (the budget and fault policies read it)
#   - max_cycle_budget lowered (already-admitted probes would no longer fit)
#   - a slot state renumbered or removed
#
# Additive (allowed, but the baseline must move so the next diff is honest):
#   - a new field, a new attach point, a field added to an attach point
#   - a field gaining exposure, max_cycle_budget raised
#
# Prose (`note`, `hook`, `kconfig`) is deliberately outside the projection:
# explaining a field better must never be a gate event.
require "json"
require "open3"

module ProbeCtxGate
  module_function

  ROOT = File.expand_path("..", __dir__)
  SCHEMA_H = File.join(ROOT, "src/codegen_c/probe_ctx_schema.h")
  GEN_C    = File.join(ROOT, "tools/gen_probe_ctx.c")
  GEN_H    = File.join(ROOT, "src/runtime/amp/probe_ctx_gen.h")
  JSON_OUT = File.join(ROOT, "src/spinel_ebpf/probe_ctx_schema_gen.json")
  SNAPSHOT = File.join(ROOT, "tests/golden/probe_ctx_schema.snapshot.json")

  SNAPSHOT_SCHEMA = "spinel-ebpf.probe-ctx-snapshot/1"

  def rel(path) = path.sub("#{ROOT}/", "")

  # Build the generator into a temp dir and capture both outputs. Compiling is
  # itself part of the check: probe_ctx_schema.h carries assertions the generator
  # runs (duplicate ids, unknown exec_class, a field an attach point names but
  # nobody declared), and a schema that cannot produce output is a failure worth
  # reporting loudly rather than skipping.
  def regenerate
    bin = File.join(Dir.tmpdir, "gen_probe_ctx_gate_#{Process.pid}")
    cc = ENV["CC"] || "cc"
    out, st = Open3.capture2e(cc, "-O2", "-Wall", "-Wextra", "-o", bin, GEN_C)
    raise "probe-ctx gate: generator failed to build:\n#{out}" unless st.success?

    hdr, st1 = Open3.capture2e(bin)
    raise "probe-ctx gate: generator failed:\n#{hdr}" unless st1.success?
    js, st2 = Open3.capture2e(bin, "--json")
    raise "probe-ctx gate: generator --json failed:\n#{js}" unless st2.success?
    [hdr, js]
  ensure
    File.delete(bin) if bin && File.exist?(bin)
  end

  def regen_violations(hdr, js)
    problems = []
    { GEN_H => hdr, JSON_OUT => js }.each do |path, fresh|
      unless File.exist?(path)
        problems << "#{rel(path)} is missing (run `make -C src/codegen_c probe-ctx`)"
        next
      end
      next if File.read(path) == fresh

      problems << "#{rel(path)} is stale — it is not what tools/gen_probe_ctx.c emits now " \
                  "(run `make -C src/codegen_c probe-ctx` and commit)"
    end
    problems
  end

  # The projection: contract terms only. Everything a consumer could observe,
  # nothing that only a reader observes.
  def project(doc)
    {
      "schema" => SNAPSHOT_SCHEMA,
      "format_version" => doc["format_version"],
      "bitmap_words" => doc["bitmap_words"],
      "fields" => doc["fields"].to_h do |f|
        [f["name"], {
          "id" => f["id"], "ctype" => f["ctype"], "size" => f["size"],
          "signed" => f["signed"], "expose" => f["expose"]
        }]
      end,
      "attaches" => doc["attaches"].to_h do |a|
        [a["name"], {
          "id" => a["id"], "exec_class" => a["exec_class"],
          "max_cycle_budget" => a["max_cycle_budget"],
          "fields" => a["fields"], "bitmap" => a["bitmap"]
        }]
      end,
      "slot_states" => doc["slot_states"].to_h { |s| [s["name"], s["value"]] }
    }
  end

  def violations(old, new)
    v = []

    if old["bitmap_words"] != new["bitmap_words"]
      v << "bitmap_words changed #{old['bitmap_words']} -> #{new['bitmap_words']} " \
           "(the capability table is a fixed-layout struct read by another core)"
    end

    of = old["fields"] || {}
    nf = new["fields"] || {}
    (of.keys - nf.keys).each do |name|
      v << "field `#{name}` was removed (its id is baked into every blob that called ctx_field on it)"
    end
    of.each do |name, o|
      n = nf[name]
      next unless n

      %w[id ctype size signed].each do |k|
        next if o[k] == n[k]
        v << "field `#{name}` #{k} changed #{o[k].inspect} -> #{n[k].inspect} " \
             "(an existing blob reads it at the old #{k})"
      end
      next if o["expose"] == n["expose"]

      if o["expose"].nil?
        # not exposed -> exposed: additive
      else
        v << "field `#{name}` expose changed #{o['expose'].inspect} -> #{n['expose'].inspect} " \
             "(a probe reading it changes type or stops compiling)"
      end
    end

    oa = old["attaches"] || {}
    na = new["attaches"] || {}
    (oa.keys - na.keys).each do |name|
      v << "attach point `#{name}` was removed (probes admitted against it lose their contract)"
    end
    oa.each do |name, o|
      n = na[name]
      next unless n

      if o["id"] != n["id"]
        v << "attach point `#{name}` id changed #{o['id']} -> #{n['id']} " \
             "(a staged manifest names the old id)"
      end
      if o["exec_class"] != n["exec_class"]
        v << "attach point `#{name}` exec_class changed #{o['exec_class'].inspect} -> " \
             "#{n['exec_class'].inspect} (the cycle-budget and fault policies read it)"
      end
      if n["max_cycle_budget"].to_i < o["max_cycle_budget"].to_i
        v << "attach point `#{name}` max_cycle_budget fell #{o['max_cycle_budget']} -> " \
             "#{n['max_cycle_budget']} (probes already admitted at the old ceiling no longer fit)"
      end
      (Array(o["fields"]) - Array(n["fields"])).each do |f|
        v << "attach point `#{name}` no longer provides `#{f}` " \
             "(a probe admitted against it reads an unprovided field)"
      end
    end

    os = old["slot_states"] || {}
    ns = new["slot_states"] || {}
    (os.keys - ns.keys).each { |s| v << "slot state `#{s}` was removed" }
    os.each do |name, val|
      next unless ns.key?(name)
      next if ns[name] == val

      v << "slot state `#{name}` changed #{val} -> #{ns[name]} (both sides name the same numbers)"
    end

    v
  end

  def snapshot_text(proj) = JSON.pretty_generate(proj) + "\n"

  def run(update: false)
    hdr, js = regenerate
    problems = []

    regen = regen_violations(hdr, js)
    problems.concat(regen)

    proj = project(JSON.parse(js))
    if update
      File.write(SNAPSHOT, snapshot_text(proj))
      puts "probe-ctx gate: wrote #{rel(SNAPSHOT)} " \
           "(#{proj['fields'].length} fields / #{proj['attaches'].length} attach points) — REVIEW THE DIFF"
      return 0 if regen.empty?

      puts_problems(regen)
      return 1
    end

    unless File.exist?(SNAPSHOT)
      puts_problems(["#{rel(SNAPSHOT)} is missing (create it with `ruby tools/probe_ctx_gate.rb --update`)"])
      return 1
    end

    old = JSON.parse(File.read(SNAPSHOT))
    if old["schema"] != SNAPSHOT_SCHEMA
      problems << "#{rel(SNAPSHOT)}: unknown snapshot schema #{old['schema'].inspect}"
    else
      problems.concat(violations(old, proj))
      if snapshot_text(proj) != File.read(SNAPSHOT) && violations(old, proj).empty?
        problems << "#{rel(SNAPSHOT)} is out of date (the change is append-only and allowed — " \
                    "refresh with `ruby tools/probe_ctx_gate.rb --update` and commit)"
      end
    end

    if problems.empty?
      puts "probe-ctx gate: OK — #{proj['fields'].length} fields / " \
           "#{proj['attaches'].length} attach points; artifacts fresh, evolution append-only"
      return 0
    end
    puts_problems(problems)
    1
  end

  def puts_problems(list)
    puts "probe-ctx gate: #{list.length} problem(s)"
    list.each { |m| puts "  - #{m}" }
    puts "\nThe probe context contract may only grow: a field id is an immediate baked into every"
    puts "blob that read it, and an attach point's field set is what admitted probes were checked"
    puts "against. New fields and new attach points are appended; nothing already published moves."
    puts "If the change really is intended, move the baseline explicitly:"
    puts "  make -C src/codegen_c probe-ctx && ruby tools/probe_ctx_gate.rb --update"
  end
end

require "tmpdir"
exit ProbeCtxGate.run(update: ARGV.include?("--update")) if $PROGRAM_NAME == __FILE__
