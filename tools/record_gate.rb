#!/usr/bin/env ruby
# frozen_string_literal: true
#
# record_gate.rb -- the ringbuf record contracts may only evolve
# append-only, and the committed derived artifacts must match the declaration.
#
# Two checks, both of which used to be human work:
#
#   (1) REGEN — src/runtime/otlp/record_mirror_gen.h and
#       src/spinel_ebpf/record_schema_gen.json are committed derived artifacts.
#       Editing src/codegen_c/record_schema.h without re-running
#       `make -C src/codegen_c mirror` leaves the runtime and the Ruby affordance
#       surface describing an older contract than the kernel emits. This rebuilds
#       the generator and diffs its output against what is checked in.
#
#   (2) APPEND-ONLY — the Cap'n Proto / SBE rule the project had been applying by
#       hand every time a field was added (cgid for cgroup/pod attribution,
#       duration_ns, start_ktime and hdr_ext): a published field never moves,
#       never changes type, never disappears; new fields go at the END and read
#       as zero on an older producer. Same for what Ruby can see (`expose` /
#       typed-consumer properties) and for what leaves the process
#       (egress attribute keys, span kind, push_fn). Violating any of those
#       breaks somebody: a running probe, an existing consumer program, or a
#       dashboard query.
#
#       The reference is tests/golden/record_schema.snapshot.json — a distilled
#       projection of the contract (ids, offsets, widths, exposure, property
#       names, attribute keys). Prose (`note` / `condition` / `source`) is
#       deliberately NOT in the snapshot, so documenting a field better is not a
#       gate event.
#
#   ruby tools/record_gate.rb            # gate (exit non-zero on violation)
#   ruby tools/record_gate.rb --update   # accept the current contract as the new
#                                        # baseline (review the snapshot diff!)
#
# An intentional breaking change is still possible — it just cannot be silent:
# it becomes a reviewable diff in the snapshot, exactly like tests/golden/.
require "json"
require "open3"
require "tmpdir"

module RecordGate
  ROOT     = File.expand_path("..", __dir__)
  SCHEMA_H = File.join(ROOT, "src/codegen_c/record_schema.h")
  GEN_C    = File.join(ROOT, "tools/gen_record_mirror.c")
  MIRROR_H = File.join(ROOT, "src/runtime/otlp/record_mirror_gen.h")
  JSON_OUT = File.join(ROOT, "src/spinel_ebpf/record_schema_gen.json")
  SNAPSHOT = File.join(ROOT, "tests/golden/record_schema.snapshot.json")

  SNAPSHOT_SCHEMA = "spinel-ebpf.record-contract-snapshot/1"

  module_function

  # --- (1) regen ------------------------------------------------------------

  # Build tools/gen_record_mirror.c and run it; returns [header_text, json_text].
  # Raises if the generator does not build or run (a schema table that does not
  # compile is itself a failure worth reporting loudly).
  def regenerate
    Dir.mktmpdir("spnl-recgate") do |dir|
      bin = File.join(dir, "gen_record_mirror")
      cc  = ENV["CC"] || "cc"
      out, st = Open3.capture2e(cc, "-O2", "-Wall", "-Wextra", "-o", bin, GEN_C)
      raise "record gate: generator does not build:\n#{out}" unless st.success?
      hdr, st1 = Open3.capture2e(bin)
      raise "record gate: generator failed:\n#{hdr}" unless st1.success?
      js, st2 = Open3.capture2e(bin, "--json")
      raise "record gate: generator --json failed:\n#{js}" unless st2.success?
      return [hdr, js]
    end
  end

  # [] when the committed artifacts are what the generator produces now.
  def regen_violations(hdr, js)
    v = []
    { MIRROR_H => hdr, JSON_OUT => js }.each do |path, want|
      got = File.exist?(path) ? File.read(path) : nil
      if got.nil?
        v << "#{rel(path)} is missing (run `make -C src/codegen_c mirror`)"
      elsif got != want
        v << "#{rel(path)} is stale: it does not match what the current " \
             "record_schema.h generates (run `make -C src/codegen_c mirror` and commit)"
      end
    end
    v
  end

  def rel(p) = p.sub("#{ROOT}/", "")

  # --- (2) append-only ------------------------------------------------------

  # Distil the generated JSON into the part that is a *contract*: everything a
  # downstream (kernel producer, userspace mirror, Ruby consumer, dashboard) can
  # break on. Prose is dropped on purpose.
  def project(doc)
    chans = {}
    Array(doc["channels"]).each do |c|
      e = c["egress"]
      cons = c["consumer"]
      chans[c["id"]] = {
        "record_struct"    => c["record_struct"],
        "ringbuf_map"      => c["ringbuf_map"],
        "record_bytes"     => c["record_bytes"],
        "record_min_bytes" => c["record_min_bytes"],
        "producers"        => Array(c["producers"]),
        "fields"           => Array(c["fields"]).map { |f|
          { "name" => f["name"], "ctype" => f["ctype"], "count" => f["count"],
            "offset" => f["offset"], "bytes" => f["bytes"], "expose" => f["expose"].to_s }
        },
        "egress"           => e && {
          "push_fn"    => e["push_fn"],
          "span_name"  => e["span_name"],
          "span_kind"  => e["span_kind"],
          "attributes" => Array(e["attributes"]).map { |a| a["key"] },
          "enrichers"  => Array(e["enrichers"]),
        },
        "consumer"         => cons && {
          "drain_fn"   => cons["drain_fn"],
          "to_span_fn" => cons["to_span_fn"],
          # `cap` is in the snapshot because it is a contract term, not an
          # implementation detail: it is the width BOTH the accessor and the span
          # builder hand the derivation, so shrinking it starts truncating values
          # that used to arrive whole — on `ev.<name>` and on the attribute at once.
          # nil for a field property (it reads the record's bytes; its width is the
          # field's `bytes`, already snapshotted above).
          "properties" => Array(cons["properties"]).map { |p|
            { "name" => p["name"], "kind" => p["kind"], "expose" => p["expose"],
              "ffi" => p["ffi"], "cap" => p["cap"] }
          },
        },
      }
    end
    { "schema" => SNAPSHOT_SCHEMA,
      "note"   => "Distilled contract of the ringbuf record channels. Refresh with " \
                  "`ruby tools/record_gate.rb --update` and REVIEW the diff: anything that moves, " \
                  "retypes or removes a published entry is a breaking change for a running probe, " \
                  "an existing consumer program, or a dashboard query.",
      "channels" => chans }
  end

  # Compare an old projection with a new one and return the list of append-only
  # violations (empty = the change is backward compatible).
  def violations(old, new)
    v = []
    oc = old["channels"] || {}
    nc = new["channels"] || {}

    (oc.keys - nc.keys).each do |id|
      v << "channel `#{id}` was removed (a probe that emits it loses its contract)"
    end

    nc.each do |id, nch|
      och = oc[id]
      next unless och   # brand-new channel: additive, nothing to check

      %w[record_struct ringbuf_map].each do |k|
        next if och[k] == nch[k]
        v << "channel `#{id}`: #{k} changed #{och[k].inspect} -> #{nch[k].inspect} " \
             "(the runtime looks the map up by name)"
      end

      # -- fields: append-only ------------------------------------------------
      of = och["fields"] || []
      nf = nch["fields"] || []
      oname = of.map { |f| f["name"] }
      nname = nf.map { |f| f["name"] }
      (oname - nname).each do |f|
        v << "channel `#{id}`: field `#{f}` was removed (existing records still carry it)"
      end
      if nname.first(oname.length) != oname && !(oname - nname).any?
        v << "channel `#{id}`: fields were reordered (#{oname.join(' ')} -> " \
             "#{nname.first(oname.length).join(' ')}); new fields must be APPENDED"
      end
      of.each do |o|
        n = nf.find { |x| x["name"] == o["name"] }
        next unless n
        %w[offset bytes ctype count].each do |k|
          next if o[k] == n[k]
          v << "channel `#{id}`: field `#{o['name']}` #{k} changed #{o[k].inspect} -> #{n[k].inspect} " \
               "(a record already on the wire is decoded at the old #{k})"
        end
        next if o["expose"] == n["expose"]
        if o["expose"].to_s.empty?
          # not exposed -> exposed: additive (a new `ev.<name>` appears)
        else
          v << "channel `#{id}`: field `#{o['name']}` expose changed " \
               "#{o['expose'].inspect} -> #{n['expose'].inspect} " \
               "(a Ruby consumer reading ev.#{o['name']} changes type or stops compiling)"
        end
      end

      # -- a shorter record used to be accepted; it must stay accepted --------
      if nch["record_min_bytes"].to_i > och["record_min_bytes"].to_i
        v << "channel `#{id}`: record_min_bytes rose #{och['record_min_bytes']} -> " \
             "#{nch['record_min_bytes']} (records an older producer writes would now be dropped; " \
             "append fields after `required_through` instead)"
      end

      (Array(och["producers"]) - Array(nch["producers"])).each do |p|
        v << "channel `#{id}`: producer `#{p}` no longer writes this channel"
      end

      # -- egress: what leaves the process ------------------------------------
      oe, ne = och["egress"], nch["egress"]
      if oe && !ne
        v << "channel `#{id}`: the egress binding was removed (#{oe['push_fn']} no longer declared)"
      elsif oe && ne
        %w[push_fn span_name span_kind].each do |k|
          next if oe[k] == ne[k]
          v << "channel `#{id}`: egress #{k} changed #{oe[k].inspect} -> #{ne[k].inspect}"
        end
        (Array(oe["attributes"]) - Array(ne["attributes"])).each do |k|
          v << "channel `#{id}`: egress attribute `#{k}` was removed (queries and dashboards use it)"
        end
        (Array(oe["enrichers"]) - Array(ne["enrichers"])).each do |k|
          v << "channel `#{id}`: layer-2 enricher `#{k}` no longer applies"
        end
      end

      # -- typed consumer: what a Ruby program may write ----------------------
      ocons, ncons = och["consumer"], nch["consumer"]
      if ocons && !ncons
        v << "channel `#{id}`: the typed consumer was withdrawn " \
             "(`on_emit :#{id} do |ev|` programs stop compiling)"
      elsif ocons && ncons
        %w[drain_fn to_span_fn].each do |k|
          next if ocons[k] == ncons[k]
          v << "channel `#{id}`: consumer #{k} changed #{ocons[k].inspect} -> #{ncons[k].inspect}"
        end
        op = Array(ocons["properties"])
        np = Array(ncons["properties"])
        (op.map { |p| p["name"] } - np.map { |p| p["name"] }).each do |n|
          v << "channel `#{id}`: consumer property `ev.#{n}` was removed"
        end
        op.each do |o|
          n = np.find { |x| x["name"] == o["name"] }
          next unless n
          %w[expose kind ffi].each do |k|
            next if o[k] == n[k]
            v << "channel `#{id}`: consumer property `ev.#{o['name']}` #{k} changed " \
                 "#{o[k].inspect} -> #{n[k].inspect}"
          end
          # A derivation's output capacity may grow (nothing that fitted stops
          # fitting) but never shrink — a narrower cap silently truncates values that
          # a consumer and a dashboard were both getting whole.
          ocap, ncap = o["cap"], n["cap"]
          next unless ocap.is_a?(Integer) && ncap.is_a?(Integer)
          next unless ncap < ocap
          v << "channel `#{id}`: consumer property `ev.#{o['name']}` cap shrank #{ocap} -> #{ncap} " \
               "(values longer than #{ncap - 1} bytes start truncating, in `ev.#{o['name']}` and in " \
               "the span attribute it feeds)"
        end
      end
    end
    v
  end

  # --- driver ---------------------------------------------------------------

  def snapshot_text(proj) = JSON.pretty_generate(proj) + "\n"

  def run(update: false)
    hdr, js = regenerate
    problems = []

    # (1) the committed artifacts must be the generator's current output.
    regen = regen_violations(hdr, js)
    problems.concat(regen)

    # (2) append-only, against the committed snapshot. Compare the freshly
    # generated JSON (not the committed one) so a stale artifact cannot hide a
    # contract change behind the regen failure.
    proj = project(JSON.parse(js))
    if update
      File.write(SNAPSHOT, snapshot_text(proj))
      puts "record gate: wrote #{rel(SNAPSHOT)} (#{proj['channels'].length} channels) — REVIEW THE DIFF"
      return regen.empty? ? 0 : (puts_problems(regen); 1)
    end

    unless File.exist?(SNAPSHOT)
      puts_problems(["#{rel(SNAPSHOT)} is missing (create it with `ruby tools/record_gate.rb --update`)"])
      return 1
    end
    old = JSON.parse(File.read(SNAPSHOT))
    if old["schema"] != SNAPSHOT_SCHEMA
      problems << "#{rel(SNAPSHOT)}: unknown snapshot schema #{old['schema'].inspect}"
    else
      problems.concat(violations(old, proj))
      if snapshot_text(proj) != File.read(SNAPSHOT) && violations(old, proj).empty?
        # additive change (new channel / appended field / new attribute): allowed,
        # but the baseline has to move or the next change compares against stale data.
        problems << "#{rel(SNAPSHOT)} is out of date (the change is append-only and allowed — " \
                    "refresh with `ruby tools/record_gate.rb --update` and commit)"
      end
    end

    if problems.empty?
      nch = proj["channels"].length
      nfl = proj["channels"].values.sum { |c| c["fields"].length }
      puts "record gate: OK — #{nch} channels / #{nfl} fields; artifacts fresh, evolution append-only"
      return 0
    end
    puts_problems(problems)
    1
  end

  def puts_problems(list)
    puts "record gate: #{list.length} problem(s)"
    list.each { |m| puts "  - #{m}" }
    puts "\nThe ringbuf record contract may only grow: existing fields keep their offset and type,"
    puts "new fields go at the end and read as zero on an older producer (Cap'n Proto / SBE rule)."
    puts "If the change really is intended, move the baseline explicitly:"
    puts "  make -C src/codegen_c mirror && ruby tools/record_gate.rb --update"
  end
end

exit RecordGate.run(update: ARGV.include?("--update")) if $PROGRAM_NAME == __FILE__
