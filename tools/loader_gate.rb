#!/usr/bin/env ruby
# frozen_string_literal: true
#
# loader_gate.rb -- the gate for the codegen <-> loader seam.
#
#   ruby tools/loader_gate.rb                  # exit 1 on any problem
#   ruby tools/loader_gate.rb --section fresh|producer|coverage|rule|shape
#
# WHY THIS EXISTS. The loader is a 2,200-line heredoc inside bin/spinel-ebpf and
# no gate in this tree compiles it. Three stages measured, independently, that a
# one-token disagreement between what the codegen emits and what the loader looks
# for passes EVERY gate:
#
#   loader's PROG_ARRAY slot counter starts at 1             -> all green
#   loader looks up "bpf_worker_sox"                         -> all green
#   loader looks up "bpf_user_cmds_x"                        -> all green
#   loader reserves 4 bytes, the callback reads 8            -> all green,
#     and silent at RUN time too: the callback fires, the count is right,
#     only the value is 0
#
# Making the seam data (src/codegen_c/loader_contract.h) and generating the
# loader's half from it takes those four out of the glue, where they are no
# longer writable. What is left for a gate is the half that can still be written
# wrong: the DECLARATION itself. Every check below therefore compares the
# declaration against a party that already knows the same fact for its own
# reasons.
#
#   fresh     the committed generated artifacts are what the declaration emits
#             (the ordinary way a derived file rots -- record_gate.rb's check 1)
#   producer  every declared token really is produced, by the authority the
#             declaration names: a committed golden, record_schema_gen.json,
#             Capabilities::ATTACH_KINDS, or a literal in spinel_ebpf_cc.c.
#             Declared orphans must stay orphans (and a new one is refused).
#   coverage  THE OTHER DIRECTION, and the reason the census cannot rot: scan
#             build_glue_c for every name-carrying site and refuse a token that
#             is not declared. Without this, a new surface added later goes back
#             to writing raw literals and the gate stays green (a claim-side-only
#             gate is green when the claim table is empty).
#   rule      the PROG_ARRAY slot base, which is not a token and cannot be read
#             out of any text: the gate RUNS the codegen and reads back which
#             literal slots it accepts.
#   shape     declared record widths against the kernel side that reads them.
#
# Each section carries a SELF-CHECK: an in-memory perturbation proving the
# section can still say no. A gate whose checks have quietly become vacuous is
# the failure this whole line of work is about.
require "json"
require "open3"
require "tmpdir"

module LoaderGate
  ROOT       = File.expand_path("..", __dir__)
  DECL       = File.join(ROOT, "src/codegen_c/loader_contract.h")
  GEN_C      = File.join(ROOT, "tools/gen_loader_contract.c")
  GEN_RB     = File.join(ROOT, "src/spinel_ebpf/loader_contract_gen.rb")
  GEN_JSON   = File.join(ROOT, "src/spinel_ebpf/loader_contract_gen.json")
  GLUE       = File.join(ROOT, "bin/spinel-ebpf")
  CC_SOURCE  = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
  TEMPLATES  = File.join(ROOT, "src/codegen_c/templates_gen.h")
  GOLDEN_DIR = File.join(ROOT, "tests/golden")
  REC_JSON   = File.join(ROOT, "src/spinel_ebpf/record_schema_gen.json")
  CC         = ENV["SPNL_INPROC_CC"] || File.join(ROOT, "build/codegen_c/spinel-ebpf-cc")

  module_function

  def read(path) = File.read(path).dup.force_encoding("UTF-8").scrub

  # ---- the declaration, as the generator sees it -----------------------------
  def contract = @contract ||= JSON.parse(read(GEN_JSON))
  def entries  = contract["entries"]

  # ---- 1. FRESH --------------------------------------------------------------
  # Regenerate into a temp dir and byte-compare. Needs a C compiler, which every
  # environment that can build this tree has.
  def check_fresh
    bin = File.join(Dir.tmpdir, "spnl_gen_loader_contract_#{Process.pid}")
    out, err, st = Open3.capture3(ENV["CC"] || "cc", "-O2", "-o", bin, GEN_C)
    return [["fresh", "the generator does not build: #{(err + out).lines.first}"]] unless st.success?
    begin
      rb,   = Open3.capture2(bin)
      json, = Open3.capture2(bin, "--json")
      bad = []
      bad << ["fresh", "#{rel(GEN_RB)} is stale -- run `make -C src/codegen_c loader-contract`"] \
        if rb != read(GEN_RB)
      bad << ["fresh", "#{rel(GEN_JSON)} is stale -- run `make -C src/codegen_c loader-contract`"] \
        if json != read(GEN_JSON)
      bad
    ensure
      File.unlink(bin) if File.exist?(bin)
    end
  end

  # ---- 2. PRODUCER -----------------------------------------------------------
  # "Is this token actually emitted, by the party the declaration names?"
  def golden(name) = read(File.join(GOLDEN_DIR, "#{name}.bpf.c"))

  def golden_maps(src)
    # `} <name> SEC(".maps");` -- the one form every map in this tree uses. The
    # richer 5-form scanner lives in affordance_gate.rb; here the question
    # is only "does this exact name exist", plus the declared properties, which
    # are read out of the 8 lines above the closing brace.
    out = {}
    src.scan(/struct\s*\{([^{}]*)\}\s*(\w+)\s+SEC\("\.maps"\)/m) { |body, n| out[n] = body }
    out
  end

  def all_emitted_text
    @all_emitted_text ||= begin
      t = read(TEMPLATES) + read(CC_SOURCE)
      Dir[File.join(GOLDEN_DIR, "*.bpf.c")].sort.each { |f| t << read(f) }
      t
    end
  end

  def attach_kinds
    @attach_kinds ||= begin
      $LOAD_PATH.unshift(File.join(ROOT, "src")) unless $LOAD_PATH.include?(File.join(ROOT, "src"))
      require "spinel_ebpf/capabilities"
      SpinelEbpf::Capabilities::ATTACH_KINDS.to_h { |a| [a[:kind].to_s, a[:sec]] }
    end
  end

  def record_channels
    @record_channels ||= JSON.parse(read(REC_JSON))["channels"].to_h { |c| [c["id"], c["ringbuf_map"]] }
  end

  # `entry` is a hash from the JSON; `over` lets the self-check perturb it.
  def check_producer(e)
    tok = e["token"]
    case e["authority"]
    when "golden"
      w = e["witness"]
      return "declares authority `golden` but names no witness" if w.nil?
      path = File.join(GOLDEN_DIR, "#{w}.bpf.c")
      return "witness golden #{w}.bpf.c does not exist" unless File.exist?(path)
      src = golden(w)
      case e["kind"]
      when "map_name"
        maps = golden_maps(src)
        body = maps[tok]
        return "witness #{w} declares no map named #{tok} (it has: #{maps.keys.sort.join(' ')})" if body.nil?
        if e["map_type"] && body !~ /BPF_MAP_TYPE_#{Regexp.escape(e['map_type'])}\b/
          return "#{tok} in #{w} is not BPF_MAP_TYPE_#{e['map_type']}"
        end
        # A ringbuf-family map declares neither key nor value: it is a byte ring.
        # For those `value_ctype` describes the RECORD, whose author is the
        # generated callback, and check_shape asks that question instead. Said
        # here rather than letting the loop quietly find nothing to compare.
        unless %w[RINGBUF USER_RINGBUF].include?(e["map_type"])
          %w[key value].each do |slot|
            want = e["#{slot}_ctype"]
            next if want.nil?
            ok = body.include?("__type(#{slot}, #{want})") ||
                 body.include?("__uint(#{slot}_size, sizeof(#{want}))")
            return "#{tok} in #{w} does not declare #{slot} #{want}" unless ok
          end
        end
      when "prog_prefix"
        return "witness #{w} has no program named #{tok}*" unless src =~ /^(?:static\s+)?\w[\w \*]*\b#{Regexp.escape(tok)}\w/
      when "rodata_prefix"
        return "witness #{w} emits no `volatile const` #{tok}*" unless src =~ /volatile const [^;\n]*\b#{Regexp.escape(tok)}\w/
      when "map_suffix"
        return "witness #{w} declares no map ending in #{tok}" unless golden_maps(src).keys.any? { |n| n.end_with?(tok) }
      end
    when "record_schema"
      want = record_channels[e["witness"]]
      return "record_schema_gen.json has no channel #{e['witness'].inspect}" if want.nil?
      return "record_schema says the #{e['witness']} ringbuf is #{want.inspect}, " \
             "not <unit>#{tok}" unless want == "<unit>#{tok}"
    when "attach_kinds"
      want = attach_kinds[e["witness"]]
      return "Capabilities::ATTACH_KINDS has no kind #{e['witness'].inspect}" if want.nil?
      return "ATTACH_KINDS[:#{e['witness']}][:sec] is #{want.inspect}, not #{tok.inspect}" unless want == tok
    when "codegen_c"
      return "no literal #{tok.inspect} in spinel_ebpf_cc.c" unless read(CC_SOURCE).include?(tok)
      w = e["witness"]
      if w && File.exist?(File.join(GOLDEN_DIR, "#{w}.bpf.c"))
        src = golden(w)
        ok = case e["kind"]
             when "map_suffix"     then golden_maps(src).keys.any? { |n| n.end_with?(tok) }
             when "rodata_prefix"  then src =~ /volatile const [^;\n]*\b#{Regexp.escape(tok)}\w/
             else                       src.include?(tok)
             end
        return "witness golden #{w} does not show #{tok}" unless ok
      end
    when "none"
      # An ORPHAN. The claim is that NOTHING produces it -- if that stops being
      # true the declaration is out of date in the direction that matters least
      # for safety and most for honesty, so it fails rather than silently
      # upgrading itself.
      return "declared an ORPHAN but #{tok} now appears in the emitted C -- " \
             "give it an authority and a witness" if produced?(tok, e["kind"])
    else
      return "unknown authority #{e['authority'].inspect}"
    end
    nil
  end

  def produced?(tok, kind)
    case kind
    when "map_name"   then all_emitted_text =~ /\}\s*#{Regexp.escape(tok)}\s+SEC\("\.maps"\)/
    when "map_suffix" then all_emitted_text =~ /\}\s*\w*#{Regexp.escape(tok)}\s+SEC\("\.maps"\)/
    else                   all_emitted_text.include?(tok)
    end
  end

  # ---- 3. COVERAGE (loader -> declaration) -----------------------------------
  # Every way build_glue_c can name a BPF object the codegen emitted. The set of
  # MECHANISMS is closed: it is exactly the libbpf entry points the heredoc calls
  # that take or return a name, enumerated once when this table was built. A site
  # whose token is not declared fails, and an unrecognised name-carrying call
  # fails too -- silence is the failure mode, so an unknown form must be loud,
  # not skipped (the rule affordance_gate.rb's map scanner learned).
  SITE_PATTERNS = [
    [:map_name,      /bpf_object__find_map_by_name\([^,]+,\s*"([^"]*)"\)/],
    [:map_suffix,    /strstr\(\s*nm\s*,\s*"([^"]*)"\)/],
    [:prog_separator, /strstr\(\s*rest\s*,\s*"([^"]*)"\)/],
    [:map_suffix,    /strcmp\(\s*_mn \+ _ml - [^,]+,\s*"([^"]*)"\)/],
    [:prog_prefix,   /strncmp\(\s*name\s*,\s*"([^"]*)"/],
    [:sec_name,      /strcmp\(\s*sec\s*,\s*"([^"]*)"\)/],
  ].freeze

  # Two sites carry a contract that is not a token, so the scan above cannot see
  # them -- and they are exactly the two historical drifts that were NOT map
  # names (the PROG_ARRAY slot base and the user-command record width). They are
  # checked with the same rule as a token: the value at the site must be an
  # interpolation of a declared constant, never a literal. `want` names the
  # constant that belongs there, so a right-shaped interpolation of the WRONG
  # constant fails too.
  VALUE_SITES = [
    [:width, /user_ring_buffer__reserve\([^,]+,\s*([^)]+)\)/,       "MAP_USER_CMDS_BYTES"],
    [:alloc, /__u32 slot = ([^;]+);/,                              "PROG_ARRAY_SLOT_BASE"],
  ].freeze

  # A raw literal at a name-carrying site is what this declaration removed; after
  # the rewrite every one of them is an interpolation, so ANY surviving literal
  # is either a new undeclared token or a regression. Both are reported the same
  # way.
  def glue_source
    @glue_source ||= begin
      lines = read(GLUE).lines
      a = lines.index { |l| l.start_with?("def build_glue_c") } or
        raise "loader gate: build_glue_c not found in #{rel(GLUE)}"
      b = (a...lines.size).find { |i| lines[i] == "end\n" } or
        raise "loader gate: build_glue_c has no end"
      [lines[a..b].join, a + 1]
    end
  end

  def check_coverage
    src, off = glue_source
    declared = entries.to_h { |e| [[e["kind"], e["token"]], e] }
    known_consts = entries.to_h { |e| [e["const"], e] }
    bad = []
    src.each_line.with_index do |line, i|
      SITE_PATTERNS.each do |kind, re|
        line.scan(re) do |m|
          raw = m[0]
          if (c = raw[/\A\#\{lc::(\w+)\}\z/, 1])
            unless known_consts.key?(c)
              bad << ["coverage", "#{rel(GLUE)}:#{off + i}: uses lc::#{c}, which loader_contract.h does not declare"]
            end
            next
          end
          bad << ["coverage",
                  "#{rel(GLUE)}:#{off + i}: a #{kind} site names #{raw.inspect} as a raw literal.\n" \
                  "      Every token this heredoc shares with the generated .bpf.c must come from\n" \
                  "      src/codegen_c/loader_contract.h (declare it, run `make -C src/codegen_c\n" \
                  "      loader-contract`, then interpolate the constant). Negative controls\n" \
                  "      measured a wrong literal here passing every other gate in the tree."] \
            unless declared.key?([kind.to_s, raw])
        end
      end
    end
    src.each_line.with_index do |line, i|
      VALUE_SITES.each do |kind, re, want|
        line.scan(re) do |m|
          got = m[0].strip
          next if got == "\#{lc::#{want}}"
          bad << ["coverage",
                  "#{rel(GLUE)}:#{off + i}: a #{kind} site reads #{got.inspect}, not " \
                  "\#{lc::#{want}}.\n" \
                  "      This is not a name, so nothing else in this gate can see it, and\n" \
                  "      neither can any other gate in the tree: a slot base of 0 -> 1 and a\n" \
                  "      record width of 8 -> 4 bytes were both measured passing everything.\n" \
                  "      The value must come from src/codegen_c/loader_contract.h."]
        end
      end
    end
    bad
  end

  # ---- 4. RULE: the PROG_ARRAY slot base -------------------------------------
  # Not a token, so nothing above can see it. The only other party that knows the
  # base is the codegen's own literal-slot bound (`slot < 0 || slot >=
  # g_n_tail_targets`), so read it back by RUNNING the codegen: with two declared
  # targets it must accept exactly two consecutive literals, and the smaller is
  # the base.
  def slot_probe(k)
    <<~RB
      def xdp_tail__a
        XDP_PASS
      end

      def xdp_tail__b
        XDP_PASS
      end

      def xdp__d
        tail_call_to(#{k})
        XDP_PASS
      end
    RB
  end

  def check_rule
    accepted = []
    Dir.mktmpdir("spnl_loader_gate") do |dir|
      (-1..3).each do |k|
        path = File.join(dir, "p#{k}.rb")
        File.write(path, slot_probe(k))
        _o, _e, st = Open3.capture3(CC, path, "p")
        accepted << k if st.success?
      end
    end
    want = contract["prog_array_slot_base"]
    if accepted.empty?
      return [["rule", "the codegen accepted no tail_call_to() literal at all with 2 targets " \
                       "declared -- the probe or the surface changed shape"]]
    end
    unless accepted == (accepted.min..accepted.max).to_a && accepted.size == 2
      return [["rule", "the codegen accepts tail_call_to#{accepted.inspect} with 2 targets " \
                       "declared; expected exactly 2 consecutive slots"]]
    end
    return [] if accepted.min == want
    [["rule",
      "loader_contract.h declares LC_PROG_ARRAY_SLOT_BASE #{want}, but the codegen accepts " \
      "slots #{accepted.min}..#{accepted.max}.\n" \
      "      The loader writes the Nth `def xdp_tail__<name>` at index base+N. If the two\n" \
      "      disagree, a tail call lands in an unpopulated slot, which FALLS THROUGH\n" \
      "      silently -- a negative control measured every gate staying green while\n" \
      "      ICMP ran the TCP handler."]]
  end

  # ---- 5. SHAPE --------------------------------------------------------------
  # The declared width of a record the LOADER moves, against the kernel side that
  # reads it. Only bpf_user_cmds has a loader-moved record today; the check is
  # written against the declaration rather than that name so a second one is
  # covered the day it is declared.
  C_WIDTH = { "__s64" => 8, "__u64" => 8, "__u32" => 4, "__u8" => 1, "__s32" => 4,
              "volatile const __s64" => 8 }.freeze

  def check_shape
    bad = []
    entries.each do |e|
      next if e["value_bytes"].zero? || e["value_ctype"].nil?
      w = C_WIDTH[e["value_ctype"]]
      if w.nil?
        bad << ["shape", "#{e['token']}: no known width for value_ctype #{e['value_ctype'].inspect} " \
                         "-- add it to LoaderGate::C_WIDTH rather than leaving the pair unchecked"]
        next
      end
      bad << ["shape", "#{e['token']}: declares value_bytes #{e['value_bytes']} but value_ctype " \
                       "#{e['value_ctype']} is #{w} bytes"] if w != e["value_bytes"]
    end
    # The kernel side of the one record the loader moves: the generated callback
    # reads sizeof(<value_ctype>) out of the dynptr. A negative control had
    # exactly this pair disagreeing, and it is silent at run time.
    uc = entries.find { |e| e["const"] == "MAP_USER_CMDS" }
    if uc && uc["witness"]
      src = golden(uc["witness"])
      unless src =~ /#{Regexp.escape(uc['value_ctype'])}\s+value\s*=\s*0;\s*\n\s*bpf_dynptr_read\(&value,\s*sizeof\(value\)/
        bad << ["shape", "the #{uc['witness']} callback does not read sizeof(#{uc['value_ctype']}) " \
                         "from the dynptr -- the declared #{uc['value_bytes']}-byte record width " \
                         "has lost its kernel-side witness"]
      end
    end
    bad
  end

  # ---- self-checks -----------------------------------------------------------
  # Each proves the section can still produce its verdict, by perturbing the
  # gate's own inputs in memory. Reported, and an outright abort when one stops
  # firing: "0 problems" from a check that cannot fail is worth nothing.
  def self_checks
    out = {}
    # Keyed on the CONSTANT, not the token: a negative control that renames the
    # token must still leave the self-check able to run, or "the gate crashed"
    # gets mistaken for "the gate caught it".
    e = entries.find { |x| x["const"] == "MAP_USER_CMDS" } or
      raise "loader gate: self-check needs the MAP_USER_CMDS entry"
    out[:producer_wrong_type] = check_producer(e.merge("map_type" => "HASH")) ? :caught : :MISSED
    out[:producer_wrong_name] = check_producer(e.merge("token" => "bpf_user_cmds_x")) ? :caught : :MISSED
    # SYNTHESISED, not found. This used to be
    #   entries.find { |x| x["authority"] == "none" }
    # and it crashed the moment the last orphan left (the three kernel_cache maps
    # went with the surface that reached them): `undefined method merge for nil`.
    # That is the same finding one gate over -- a control anchored on an
    # INVENTORY dies when the inventory is fixed, and the "0 problems" it used to
    # print was underwritten by dead code being present. The orphan rule
    # ("declared as produced by nothing, but something produces it") does not
    # need a real orphan to be exercised: build one out of the MAP_USER_CMDS
    # entry, which is produced, and demand the catch.
    out[:orphan_gains_producer] =
      check_producer(e.merge("authority" => "none", "witness" => nil)) ? :caught : :MISSED
    out[:shape_width] = begin
      saved = @contract
      @contract = JSON.parse(JSON.generate(contract))
      @contract["entries"].find { |x| x["const"] == "MAP_USER_CMDS" }["value_bytes"] = 4
      r = check_shape.empty? ? :MISSED : :caught
      @contract = saved
      r
    end
    out[:coverage_raw_literal] = with_glue(%{bpf_object__find_map_by_name(_spnl_skel->obj, "bpf_not_declared")\n})
    # The two value sites get their own self-checks because they are the two
    # historical drifts that were NOT names: a check that only proved it can see
    # an undeclared map name would leave both of them unmeasured (a self-check
    # that tests one stage of two proves less than it looks).
    out[:coverage_width]     = with_glue(%{    long long *slot = user_ring_buffer__reserve(_spnl_user_cmds_rb, 4);\n})
    out[:coverage_slot_base] = with_glue(%{        __u32 slot = 1;\n})
    out
  end

  # Run check_coverage over a synthetic glue body, then put the real one back.
  def with_glue(text)
    saved = @glue_source
    @glue_source = [text, 1]
    r = check_coverage.empty? ? :MISSED : :caught
    @glue_source = saved
    r
  end

  def rel(p) = p.sub("#{ROOT}/", "")
end

# ---------------------------------------------------------------------------
section = nil
ARGV.each_with_index { |a, i| section = ARGV[i + 1] if a == "--section" }
VALID = %w[fresh producer coverage rule shape].freeze
abort "loader gate: unknown --section #{section.inspect} (valid: #{VALID.join(' ')})" \
  if section && !VALID.include?(section)

want = ->(s) { section.nil? || section == s }

unless File.exist?(LoaderGate::GEN_JSON)
  abort "loader gate: #{LoaderGate.rel(LoaderGate::GEN_JSON)} is missing.\n" \
        "  Run `make -C src/codegen_c loader-contract` and commit the result."
end

problems = []
problems += LoaderGate.check_fresh    if want.call("fresh")

if want.call("producer")
  LoaderGate.entries.each do |e|
    msg = LoaderGate.check_producer(e)
    problems << ["producer", "#{e['token']} (#{e['kind']}, authority #{e['authority']}): #{msg}"] if msg
  end
end

problems += LoaderGate.check_coverage if want.call("coverage")
problems += LoaderGate.check_shape    if want.call("shape")

if want.call("rule")
  unless File.executable?(LoaderGate::CC)
    abort "loader gate: production codegen missing: #{LoaderGate::CC}\n" \
          "  The `rule` section reads the PROG_ARRAY slot base back OUT of the codegen;\n" \
          "  there is no text anywhere else that states it. Run this in the build container:\n" \
          "    container exec spnl715 sh -c 'cd /work && LANG=C.UTF-8 ruby tools/loader_gate.rb'\n" \
          "  (or `--section fresh,producer,coverage,shape` individually on the host)."
  end
  _o, _e, _st = Open3.capture3(LoaderGate::CC)
  unless "#{_o}#{_e}".include?("usage:")
    abort "loader gate: #{LoaderGate::CC} exists but does not run here (no usage line).\n" \
          "  build/ is bind-mounted into the container, so this is usually the other\n" \
          "  platform's binary. A gate that cannot run the codegen must not report a pass."
  end
  problems += LoaderGate.check_rule
end

selfck = LoaderGate.self_checks
counts = LoaderGate.entries.group_by { |e| e["kind"] }.transform_values(&:size)
orphans = LoaderGate.entries.count { |e| e["authority"] == "none" }

puts "loader contract: #{LoaderGate.entries.size} tokens " \
     "(#{counts.sort.map { |k, v| "#{k}:#{v}" }.join(' ')}), #{orphans} declared orphan"
puts "  self-check     #{selfck.map { |k, v| "#{k}=#{v}" }.join('  ')}"

if selfck.value?(:MISSED)
  puts
  puts "A LOADER-GATE SELF-CHECK STOPPED FIRING. One of the checks above no longer"
  puts "produces its verdict when its input is deliberately broken, so its \"0 problems\""
  puts "means nothing. Fix the check before trusting this run."
  exit 1
end

if problems.empty?
  puts "loader gate: OK -- every declared token has a producer, every name-carrying site " \
       "in build_glue_c is declared" + (want.call("rule") ? ", slot base agrees with the codegen" : "")
  exit 0
end

puts
puts "THE CODEGEN AND THE LOADER DISAGREE (or the declaration does):"
problems.each { |sec, msg| puts "  [#{sec}] #{msg}" }
puts
puts "The seam is declared in src/codegen_c/loader_contract.h and the loader's half is"
puts "generated from it (make -C src/codegen_c loader-contract). Nothing in this tree"
puts "compiles the glue, so a disagreement here has no other symptom: negative controls"
puts "measured all four kinds passing every gate, and one of them (a short record"
puts "reservation) is silent even at run time."
exit 1
