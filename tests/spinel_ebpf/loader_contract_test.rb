# frozen_string_literal: true
#
# The codegen <-> loader seam, declared once.
#
# WHAT THIS FILE IS FOR, and what it deliberately is NOT for.
#
# tools/loader_gate.rb answers "does the declaration agree with the codegen"; it
# reads committed goldens, record_schema_gen.json, Capabilities::ATTACH_KINDS,
# and (for the PROG_ARRAY slot base) the codegen itself. None of that belongs
# here -- duplicating it would make two authors of the same check, which is the
# shape of problem this single declaration exists to remove.
#
# What is here is the set of invariants the GATE relies on and cannot check
# about itself:
#
#   * the generated Ruby the loader interpolates and the generated JSON the gate
#     reads are two views of one table, and they agree
#   * every declared constant is actually reachable through the module (a token
#     nobody can interpolate is a declaration with no consumer)
#   * lengths are DERIVED, never typed (the reason `strncmp(name, "x", 9)` is
#     no longer writable by hand)
#   * the loader really does interpolate rather than restate -- measured as
#     "there is no bare occurrence of a declared map name in build_glue_c"
#   * a declared orphan carries a note saying why (a hole recorded without a
#     reason rots into a hole nobody remembers is a hole)
#
# The last one is the same rule affordance_gate's tests apply to a weakened
# tier: you may declare something the gate cannot fully check, but you must say
# so in the artifact a reader will find.
require "minitest/autorun"
require "json"
require "spinel_ebpf/loader_contract_gen"

class LoaderContractTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  LC   = SpinelEbpf::LoaderContract
  JSON_PATH = File.join(ROOT, "src/spinel_ebpf/loader_contract_gen.json")
  GLUE = File.join(ROOT, "bin/spinel-ebpf")

  def json  = @json  ||= JSON.parse(File.read(JSON_PATH))
  def glue  = @glue  ||= File.read(GLUE).dup.force_encoding("UTF-8").scrub
  def build_glue_c
    @build_glue_c ||= begin
      lines = glue.lines
      a = lines.index { |l| l.start_with?("def build_glue_c") }
      b = (a...lines.size).find { |i| lines[i] == "end\n" }
      lines[a..b].join
    end
  end

  # --- the two generated views are one table --------------------------------

  def test_ruby_and_json_describe_the_same_table
    assert_equal json["entries"].map { |e| e["token"] }, LC::ENTRIES.map { |e| e[:token] },
                 "the Ruby the loader reads and the JSON the gate reads disagree; " \
                 "both come out of one generator run, so this means one is stale"
    assert_equal json["prog_array_slot_base"], LC::PROG_ARRAY_SLOT_BASE
  end

  def test_every_declared_token_is_reachable_as_a_constant
    LC::ENTRIES.each do |e|
      assert LC.const_defined?(e[:const]),
             "#{e[:token]} is declared but #{e[:const]} is not defined -- nothing can " \
             "interpolate it, so the declaration has no consumer"
      assert_equal e[:token], LC.const_get(e[:const])
    end
  end

  def test_constant_names_are_unique
    names = LC::ENTRIES.map { |e| e[:const] }
    assert_equal names.uniq, names, "two entries publish the same constant; the later " \
                                    "one silently wins and its token becomes unwritable"
  end

  # --- lengths are derived, never typed --------------------------------------

  def test_prefix_and_suffix_lengths_come_from_the_token
    n = 0
    LC::ENTRIES.each do |e|
      next unless %i[prog_prefix map_suffix].include?(e[:kind])
      c = "#{e[:const]}_LEN"
      assert LC.const_defined?(c), "#{e[:token]} has no derived length; the loader would " \
                                   "have to type the strncmp/strcmp length by hand"
      assert_equal e[:token].length, LC.const_get(c)
      n += 1
    end
    assert_operator n, :>, 0, "no prefix or suffix is declared -- this test became vacuous"
  end

  def test_declared_widths_are_published_as_bytes_constants
    LC::ENTRIES.select { |e| e[:value_bytes].positive? }.each do |e|
      c = "#{e[:const]}_BYTES"
      assert LC.const_defined?(c), "#{e[:token]} declares a width the loader cannot read"
      assert_equal e[:value_bytes], LC.const_get(c)
    end
  end

  # --- the loader interpolates instead of restating --------------------------

  # Strip C block comments and Ruby comment lines. Prose is allowed to NAME a map
  # -- several comments here show the reader an FFI call by example -- so the
  # claim is about code, and saying which is which beats a rule that silently
  # tolerates a real lookup because it looked like prose.
  def glue_code
    @glue_code ||= begin
      out = +""
      in_c = false
      build_glue_c.each_line do |l|
        next if l =~ /\A\s*#[^{]/            # a Ruby comment (not "#{")
        t = l.dup
        loop do
          if in_c
            i = t.index("*/") or (t = ""; break)
            t = t[(i + 2)..]
            in_c = false
          else
            i = t.index("/*") or break
            j = t.index("*/", i + 2)
            if j then t = t[0...i] + t[(j + 2)..]
            else      t = t[0...i]; in_c = true; break
            end
          end
        end
        out << t << "\n"
      end
      out
    end
  end

  # The claim being made is not "the names agree" but "there is only one place to
  # write them". That is checkable: after the rewrite, no declared map name may
  # appear in build_glue_c's CODE as a whole string literal -- which is the only
  # form a libbpf lookup can take. (Prefixes and section names are excluded:
  # `uprobe`, `usdt` and the like are ordinary words inside diagnostics, so a
  # literal rule over them would be noise, and the gate's coverage scan checks
  # them at their call sites instead.)
  def test_the_glue_holds_no_bare_copy_of_a_declared_map_name
    offenders = LC::ENTRIES.select { |e| e[:kind] == :map_name }.filter_map do |e|
      hits = glue_code.lines.each_with_index.select { |l, _| l.include?(%("#{e[:token]}")) }
      next if hits.empty?
      "#{e[:token]} (#{hits.size} site(s))"
    end
    assert_empty offenders,
                 "build_glue_c still writes a declared map name as a string literal. " \
                 "Two negative controls each changed one such literal and every gate " \
                 "stayed green; the point of declaring the seam once is that there is " \
                 "nowhere left to make that mistake."
  end

  # ...and the check above is only meaningful if it can still see one.
  def test_the_bare_copy_check_can_still_fail
    @glue_code = %(bpf_object__find_map_by_name(obj, "bpf_user_cmds");\n)
    err = assert_raises(Minitest::Assertion) { test_the_glue_holds_no_bare_copy_of_a_declared_map_name }
    assert_match(/bpf_user_cmds/, err.message)
  ensure
    @glue_code = nil
  end

  def test_the_two_non_name_contracts_are_interpolated_too
    # The two historical drifts that were not names (the PROG_ARRAY slot base
    # and the user-command record width). Named individually because a generic
    # scan cannot tell a contract number from an ordinary one.
    assert_includes build_glue_c, '__u32 slot = #{lc::PROG_ARRAY_SLOT_BASE};'
    assert_includes build_glue_c,
                    'user_ring_buffer__reserve(_spnl_user_cmds_rb, #{lc::MAP_USER_CMDS_BYTES})'
  end

  # --- honesty about what is not covered ------------------------------------

  # This REPLACES (does not delete -- the rule the previous version's own message
  # asked for) a test that REQUIRED at least one orphan. There are none now: the
  # three kernel_cache maps left with the surface that reached them, because that
  # surface was measured to be a silent no-op (an empty .bpf.c, exit 0, and a demo
  # printing success) and is refused at compile time instead.
  #
  # So this is about the RULE, not the inventory. It is vacuous today by design --
  # the detection power moved to the gate, which now synthesises its orphan rather
  # than finding one (asserted below, because that is the part that would rot).
  def test_an_orphan_if_ever_declared_says_why_it_is_one
    LC::ENTRIES.select { |e| e[:authority] == :none }.each do |e|
      refute_nil e[:note], "#{e[:token]} is declared an orphan with no note"
      assert_match(/oracle|not ported|no production/i, e[:note],
                   "#{e[:token]}'s note does not say WHY nothing produces it; " \
                   "an unexplained hole stops being recognised as a hole")
      assert_nil e[:witness], "#{e[:token]} is an orphan, so it cannot have a witness"
    end
  end

  # An entry whose meaning is not fixed by its shape must say what the bytes
  # mean. The gate cannot check that the sentence is TRUE -- this is the fifth
  # kind of contract in the census of this seam, and the only one with no
  # mechanical authority anywhere -- but it can insist the sentence exists where
  # the shape alone is known to be insufficient.
  def test_the_encoding_is_stated_where_shape_does_not_fix_it
    %w[MAP_BLOCKLIST MAP_CIDR_BLOCK MAP_WORKER_SOCKS MAP_PROG_ARRAY].each do |c|
      e = LC[c]
      refute_nil e[:encoding],
                 "#{e[:token]} carries bytes whose meaning is not implied by their type " \
                 "(host vs network order, an fd the kernel turns into something else). " \
                 "The census counted that as the fifth kind of contract precisely " \
                 "because nothing detects it; the least that is owed is a sentence."
    end
  end

  # The above is allowed to be vacuous only because the gate's control is not.
  # The self-check used to do `entries.find { |x| x["authority"] == "none" }` and
  # crashed outright (`undefined method merge for nil`) the moment the last orphan
  # left -- i.e. the check was underwritten by dead code being present, the same
  # finding one gate over. Pin the shape, since a future edit that "simplifies" it
  # back would restore that coupling silently.
  def test_the_gates_orphan_control_is_synthesised_not_found
    src = File.read(File.expand_path("../../tools/loader_gate.rb", __dir__))
    body = src[/def self_checks(.*?)\n  end/m]
    refute_nil body, "loader_gate.rb: self_checks is not where it was (structure changed?)"
    # The comments quote the old form on purpose (that is how the reason
    # survives); strip them, or this test reports the explanation as the offence.
    body = body.lines.reject { |l| l =~ /\A\s*#/ }.join
    refute_match(/authority"\] == "none"/, body,
                 "the orphan self-check is anchored on a LIVE orphan again. There are none, " \
                 "so this control would either crash or quietly stop testing the orphan rule. " \
                 "Synthesise it: merge \"authority\" => \"none\" onto an entry that IS produced.")
    assert_match(/"authority" => "none"/, body,
                 "the orphan self-check no longer builds an orphan at all")
  end

  # An `encoding` sentence was once written off as uncheckable, and that turned
  # out to be the wrong word: byte order and fd reinterpretation ROUND TRIP. Six of
  # the eight were measured (with the control that a wrong encoding fails), and the
  # two that could not be were the two belonging to ORPHANS -- a map nothing
  # produces has no round trip to run. Those left with the surface, so every
  # surviving sentence has a measurement, and this is what keeps a NEW one from
  # arriving without one.
  #
  # It cannot check that the sentence is true (nothing derives it). It checks the
  # rule this tree applies to a weak-tier claim: say how it was measured, in a form
  # a reader can act on.
  def test_every_encoding_claim_names_its_measurement
    stated = LC::ENTRIES.select { |e| e[:encoding] }
    assert_equal 6, stated.length,
                 "the number of ENCODING claims changed. Six were measured and two deleted " \
                 "(the kernel_cache orphans); a new one needs its own round trip, and a " \
                 "missing one needs a reason written down."
    stated.each do |e|
      m = e[:encoding_measured].to_s
      refute_empty m,
                   "#{e[:token]}: an `encoding` with no `encoding_measured`. This is the one " \
                   "kind of contract nothing derives, so a sentence that was never " \
                   "round-tripped is indistinguishable from a sentence that is wrong."
      assert_match(/[Rr]ound-tripped/, m,
                   "#{e[:token]}: the measurement must say what was written and read back")
      assert_operator m.length, :>, 60,
                     "#{e[:token]}: too short to be a measurement anyone could repeat"
    end
  end

  # ...and the converse: no entry may carry evidence for a claim it does not make.
  def test_no_measurement_without_a_claim
    orphaned = LC::ENTRIES.select { |e| e[:encoding_measured] && e[:encoding].nil? }
    assert_empty orphaned.map { |e| e[:token] },
                 "an `encoding_measured` with no `encoding`: the evidence outlived the sentence"
  end

  def test_lookup_by_constant_name_fails_loudly
    err = assert_raises(KeyError) { LC["NO_SUCH_CONSTANT"] }
    assert_match(/loader contract has no NO_SUCH_CONSTANT/, err.message)
    assert_match(/MAP_PROG_ARRAY/, err.message, "the refusal must list the real set")
  end
end
