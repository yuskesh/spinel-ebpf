#!/usr/bin/env ruby
# frozen_string_literal: true
#
# reader_gate.rb -- everything a READER of these records has to act on
# is stated in a form a reader can act on, or the contract says it cannot be.
#
# WHAT THIS IS FOR. src/spinel_ebpf/record_schema_gen.json is the whole contract
# a consumer outside this repository gets. Handing the same .bpf.o to a consumer
# written elsewhere and measuring what did not come with it turned up four things
# it had to re-implement from prose: a derivation's body, the ktime -> wall clock
# conversion, the rule for when an attribute is on the span, and the rule for
# when a record produces no span. Three of those are declarations now.
#
# A one-off cleanup decays. What decays it is not somebody deleting a
# declaration -- it is somebody ADDING a channel, or an attribute, or a
# derivation, and writing the new rule as a sentence, because a sentence is
# always accepted. So this gate does not count what is declared today; it fixes
# the STRUCTURE:
#
#   1. Every egress attribute's presence rule PARSES in the closed grammar, or
#      says `unexpressible(<reason>)` with a real reason.
#   2. Every span's timing PARSES: a start form from the closed set, naming a
#      clock the contract declares, and an end form from the closed set.
#   3. Every predicate operand names a field or a derived property OF THAT
#      CHANNEL -- so the rule is checkable against the record, not decorative.
#   4. Every derivation declares a residue class, and the class agrees with where
#      the body actually lives: a "declared" one has NO C implementation in
#      src/runtime, and a parse/render/ambient one has EXACTLY ONE.
#
# (4) is the structural half and the reason this is not an inventory: it says a
# derivation is implemented in exactly one place and the declaration names which
# place. It holds for one derivation or a hundred, and it fails the moment the
# two disagree -- which is the failure that put a generated reader in front of
# thirteen identical panics.
#
# Rules 1-3 are quantified over "every", which is what keeps a NEW rule written
# as prose from passing: there is no spelling of a sentence that parses.
#
#   ruby tools/reader_gate.rb              # gate
#   ruby tools/reader_gate.rb --self-check # prove the gate can fail
#   ruby tools/reader_gate.rb --verbose    # print every rule it accepted
require "json"

module ReaderGate
  ROOT     = File.expand_path("..", __dir__)
  JSON_OUT = File.join(ROOT, "src/spinel_ebpf/record_schema_gen.json")
  RUNTIME  = File.join(ROOT, "src/runtime")

  START_FORMS = %w[record_ktime wall_now_minus].freeze
  END_FORMS   = ["start", "start_plus"].freeze
  UNARY       = %w[nonempty empty nonzero zero].freeze
  RESIDUE     = %w[declared parse render ambient].freeze

  # A derivation whose body the generator emits. Kept as the JSON's own words
  # rather than a second list of impl_forms: `residue` is the declared answer and
  # this gate's job is to check it against reality, not to re-derive it.
  DECLARED = "declared"

  module_function

  def parse_pred(text, props, where, errs)
    t = text.to_s.strip
    if t.empty?
      errs << "#{where}: presence rule is empty (say `always`, or `unexpressible(<reason>)`)"
      return
    end
    if t.start_with?("unexpressible(")
      unless t.end_with?(")")
        errs << "#{where}: unexpressible(...) is missing its ')'"
        return
      end
      reason = t[14..-2].to_s.strip
      # A refusal with no reason is worse than prose: it looks handled.
      errs << "#{where}: unexpressible(...) carries no real reason" if reason.length < 20
      return
    end
    rest = pred_one(t, props, where, errs)
    errs << "#{where}: trailing text after the predicate: #{rest.inspect}" unless rest.to_s.strip.empty?
  end

  # Parses one predicate at the head of `s`; returns what is left.
  def pred_one(s, props, where, errs)
    s = s.lstrip
    return s[6..] if s.start_with?("always")
    return s[5..] if s.start_with?("never")

    if (m = s.match(/\A(all|any)\(/))
      rest = s[m[0].length..]
      n = 0
      loop do
        rest = pred_one(rest, props, where, errs)
        n += 1
        rest = rest.lstrip
        break unless rest.start_with?(",")
        rest = rest[1..]
      end
      errs << "#{where}: #{m[1]}() with fewer than two operands" if n < 2
      unless rest.lstrip.start_with?(")")
        errs << "#{where}: #{m[1]}() is missing its ')'"
        return ""
      end
      return rest.lstrip[1..]
    end

    if (m = s.match(/\Abyte_eq\(\s*(\w+)\s*,\s*(\d+)\s*,\s*'(.)'\s*\)/))
      f = props[m[1]]
      if f.nil?
        errs << "#{where}: byte_eq names `#{m[1]}`, which is not a property of this channel"
      elsif f[:kind] != :field || f[:count].to_i <= m[2].to_i
        errs << "#{where}: byte_eq(#{m[1]}, #{m[2]}) is not a byte inside that field"
      end
      return s[m[0].length..]
    end

    if (m = s.match(/\A(#{UNARY.join('|')})\(\s*(\w+)\s*\)/))
      op, name = m[1], m[2]
      p = props[name]
      if p.nil?
        errs << "#{where}: #{op}() names `#{name}`, which is not a field or derived property of this channel"
      else
        wants_str = %w[nonempty empty].include?(op)
        errs << "#{where}: #{op}(#{name}) is the wrong shape for a #{p[:str] ? 'string' : 'scalar'} property" if p[:str] != wants_str
      end
      return s[m[0].length..]
    end

    errs << "#{where}: #{s.split(/[,)]/).first.to_s.strip.inspect} is not a form of the closed grammar"
    ""
  end

  # name -> { kind:, str:, count: } for one channel (fields AND derivations).
  def properties(chan)
    out = {}
    Array(chan["fields"]).each do |f|
      out[f["name"]] = { kind: :field, str: f["count"].to_i > 0, count: f["count"].to_i }
    end
    Array((chan["consumer"] || {})["properties"]).each do |p|
      next unless p["kind"] == "derived"
      out[p["name"]] = { kind: :derived, str: p["expose"] == "str", count: 0 }
    end
    out
  end

  # Every C definition of a symbol under src/runtime (the "exactly one place").
  def runtime_defs
    @runtime_defs ||= begin
      defs = Hash.new { |h, k| h[k] = [] }
      Dir.glob(File.join(RUNTIME, "**/*.{c,h}")).sort.each do |path|
        next if path.end_with?("record_mirror_gen.h")   # the generated side
        File.read(path).scan(/^\s*(?:static\s+)?(?:inline\s+)?(?:void|long|int|const char \*)\s+(\w+)\s*\([^;]*\)\s*\{/) do |(sym)|
          defs[sym] << path.sub("#{ROOT}/", "")
        end
      end
      defs
    end
  end

  def check(doc, errs, accepted)
    clocks = Array(doc["clocks"]).map { |c| c["id"] }
    errs << "the contract declares no clock (a record's ktime cannot be converted)" if clocks.empty?

    Array(doc["channels"]).each do |chan|
      props = properties(chan)

      # (4) derivations: the class, and where the body actually is.
      Array((chan["consumer"] || {})["properties"]).each do |p|
        next unless p["kind"] == "derived"
        where = "#{chan['id']}.#{p['name']}"
        cls = p["residue"]
        unless RESIDUE.include?(cls)
          errs << "#{where}: residue #{cls.inspect} is not one of #{RESIDUE.join('/')}"
          next
        end
        errs << "#{where}: residue #{cls} carries no explanation" if p["residue_means"].to_s.length < 20
        impl = p["source"].to_s[/->\s*(\w+)\(\)/, 1]
        if cls == DECLARED && p["value_map"].to_s.empty? && !p["expr_ast"].is_a?(Hash)
          errs << "#{where}: declared as generated but publishes neither a value map nor an " \
                  "expression tree -- a consumer has nothing to walk"
        end
        if cls == DECLARED
          if impl
            errs << "#{where}: declared as generated, but its source names the C function #{impl}()"
          elsif !runtime_defs[p["name"]].empty?
            errs << "#{where}: declared as generated, but src/runtime also defines #{p['name']}()"
          end
        else
          if impl.nil?
            errs << "#{where}: residue #{cls} says a consumer implements it, but the declaration " \
                    "names no implementation"
          else
            n = runtime_defs[impl].length
            errs << "#{where}: residue #{cls} names #{impl}(), which src/runtime defines #{n} times " \
                    "(a derivation must have exactly one implementation)" unless n == 1
          end
        end
        accepted << "#{where} residue=#{cls}"
      end

      e = chan["egress"]
      next unless e

      # (1)+(3) presence rules
      Array(e["attributes"]).each do |a|
        where = "#{chan['id']}/#{a['key']}"
        parse_pred(a["present"], props, where, errs)
        # A closed grammar published only as text asks every consumer to write a
        # parser for it -- which would be a new hand-written thing, not a removed
        # one. The tree comes out of the same parse as the C, so this checks that
        # it was published, not that it agrees (it cannot disagree).
        errs << "#{where}: presence rule has no machine-walkable tree (present_ast)" unless a["present_ast"].is_a?(Hash)
        accepted << "#{where} present=#{a['present']}"
      end

      # (2) timing
      tf = e["timing_form"]
      if tf.nil?
        errs << "#{chan['id']}: the span declares no timing_form"
      else
        st = tf["start"].to_s
        kind, arg = st.split(":", 2)
        if !START_FORMS.include?(kind) || arg.to_s.empty?
          errs << "#{chan['id']}: start form #{st.inspect} is not #{START_FORMS.join(' / ')} with an operand"
        elsif kind == "record_ktime"
          errs << "#{chan['id']}: start clock #{tf['clock'].inspect} is not a declared clock" unless clocks.include?(tf["clock"])
          errs << "#{chan['id']}: start reads #{arg.inspect}, which this channel does not declare" \
            unless props.key?(arg) || arg == "hdr.timestamp"
        else
          errs << "#{chan['id']}: a wall_now_minus start must not name a record clock" unless tf["clock"].to_s.empty?
          errs << "#{chan['id']}: start reads #{arg.inspect}, which this channel does not declare" unless props.key?(arg)
        end
        en = tf["end"].to_s
        ekind, earg = en.split(":", 2)
        if !END_FORMS.include?(ekind)
          errs << "#{chan['id']}: end form #{en.inspect} is not #{END_FORMS.join(' / ')}"
        elsif ekind == "start_plus" && !props.key?(earg.to_s)
          errs << "#{chan['id']}: end reads #{earg.inspect}, which this channel does not declare"
        end
        accepted << "#{chan['id']} timing #{st} -> #{en}"
      end

      # the drop rule is a predicate like any other
      parse_pred(e["drop_when"], props, "#{chan['id']}/drop_when", errs)
      errs << "#{chan['id']}: drop rule has no machine-walkable tree (drop_when_ast)" unless e["drop_when_ast"].is_a?(Hash)
      accepted << "#{chan['id']} drop_when=#{e['drop_when']}"
    end
  end

  # --- self-check: the gate must be able to fail ----------------------------
  #
  # Each mutation is one way the structure decays in real life. If any of them
  # passes, the gate is decorative and says so loudly.
  MUTATIONS = {
    "an attribute's presence rule written as prose" =>
      ->(d) { d["channels"][0]["egress"]["attributes"][0]["present"] = "when the name parses" },
    "a refusal with no reason" =>
      ->(d) { d["channels"][0]["egress"]["attributes"][0]["present"] = "unexpressible(dunno)" },
    "a predicate over a property the channel does not have" =>
      ->(d) { d["channels"][0]["egress"]["attributes"][0]["present"] = "nonempty(hostname)" },
    "a predicate of the wrong shape for its property" =>
      ->(d) { d["channels"][0]["egress"]["attributes"][1]["present"] = "nonzero(comm)" },
    "a span with no timing form" =>
      ->(d) { d["channels"][0]["egress"].delete("timing_form") },
    "a start form outside the closed set" =>
      ->(d) { d["channels"][0]["egress"]["timing_form"]["start"] = "whenever_the_drain_ran" },
    "a start on a clock the contract does not declare" =>
      ->(d) { d["channels"][0]["egress"]["timing_form"]["clock"] = "tai" },
    "a drop rule written as prose" =>
      ->(d) { d["channels"][0]["egress"]["drop_when"] = "if the qname is empty" },
    "a derivation with no residue class" =>
      ->(d) { derived(d)["residue"] = "" },
    "a derivation that claims to be generated while C implements it" =>
      ->(d) { p = derived(d, "parse"); p["residue"] = "declared" },
    "a derivation that claims a C body it does not name" =>
      ->(d) { p = derived(d, "declared"); p["residue"] = "parse" },
    "a derivation naming an implementation src/runtime does not define" =>
      ->(d) { p = derived(d, "parse"); p["source"] = "raw -> spnl_dns_qname_v2()" },
    "a presence rule published as text with no tree" =>
      ->(d) { d["channels"][0]["egress"]["attributes"][0].delete("present_ast") },
    "a drop rule published as text with no tree" =>
      ->(d) { d["channels"][0]["egress"].delete("drop_when_ast") },
    "a generated derivation with nothing to walk" =>
      ->(d) { p = derived(d, "declared"); p.delete("expr_ast"); p.delete("value_map") },
  }.freeze

  def derived(doc, cls = nil)
    doc["channels"].each do |c|
      Array((c["consumer"] || {})["properties"]).each do |p|
        next unless p["kind"] == "derived"
        return p if cls.nil? || p["residue"] == cls
      end
    end
    raise "self-check: no #{cls} derivation to mutate"
  end

  def self_check(doc)
    armed = 0
    MUTATIONS.each do |name, mutate|
      copy = JSON.parse(JSON.generate(doc))
      mutate.call(copy)
      errs = []
      check(copy, errs, [])
      if errs.empty?
        puts "  NOT ARMED  #{name}"
      else
        armed += 1
        puts "  armed      #{name}  ->  #{errs.first}"
      end
    end
    puts "\nself-check: #{armed}/#{MUTATIONS.size} mutations detected"
    armed == MUTATIONS.size
  end

  def run(argv)
    doc = JSON.parse(File.read(JSON_OUT))
    errs = []
    accepted = []
    check(doc, errs, accepted)

    if argv.include?("--self-check")
      puts "reader gate self-check (a gate that cannot fail is not a gate)\n\n"
      good = self_check(doc)
      puts(errs.empty? ? "\nthe unmutated contract passes" : "\nthe unmutated contract FAILS: #{errs.first}")
      return (good && errs.empty?) ? 0 : 1
    end

    puts accepted.map { |a| "  ok  #{a}" } if argv.include?("--verbose")
    if errs.empty?
      puts "reader gate OK: #{accepted.size} rules, all machine-readable or declared unexpressible"
      0
    else
      warn "reader gate FAILED (#{errs.size}):"
      errs.each { |e| warn "  #{e}" }
      1
    end
  end
end

exit ReaderGate.run(ARGV) if $PROGRAM_NAME == __FILE__
