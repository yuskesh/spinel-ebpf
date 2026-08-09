# frozen_string_literal: true
#
# Keep the error surface from getting worse, without counting it.
#
# tests/spinel_ebpf/error_quality_test.rb enumerates 21 diagnostics and
# asserts what each one says. That is worth having and it stays -- but an
# enumeration cannot notice the 362nd error site, and 361 is what the surface
# actually is. So the regression barrier is a RULE, quantified over all of them,
# and it lives in tools/error_gate.rb:
#
#   every user-facing error site names the SUBJECT (what in the author's file
#   went wrong) and a REMEDY (a different concrete spelling to write next).
#
# tests/golden/error_actionability.tsv is not a census of the surface. It is the
# list of sites that do not meet the rule yet, each with a reason. A new error
# site that fails the rule fails the gate; it does not quietly join a count. The
# number 361 appears in no assertion here, and neither does 89.
#
# What this file pins is that the gate can still say no -- the failure mode the
# other audits in this tree kept running into, where a detector goes flat and
# reports `broken=0` forever.
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/error_actionability_test.rb

require "minitest/autorun"
require "open3"

class ErrorActionabilityTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  GATE = File.join(ROOT, "tools/error_gate.rb")
  DEBT = File.join(ROOT, "tests/golden/error_actionability.tsv")

  # One process per MODE for the whole file: the gate re-parses an 8k-line C file
  # and every Ruby module in the product, so calling it per test made this the
  # slowest file in the suite by an order of magnitude.
  def gate(*args)
    @@cache ||= {}
    @@cache[args] ||= Open3.capture3({ "LANG" => "C.UTF-8" }, "ruby", GATE, *args, chdir: ROOT)
  end

  def debt_rows
    File.readlines(DEBT).reject { |l| l.start_with?("#") || l.strip.empty? }
        .map { |l| l.chomp.split("\t", 4) }
  end

  # ---- the gate's own detectors are armed -----------------------------------

  # The four that matter are the ones that show the definition of `actionable`
  # cannot be satisfied by writing a template. If any of them goes flat the
  # headline number stops meaning anything, so the gate aborts -- and so does
  # this.
  def test_self_checks_are_all_armed
    out, err, st = gate("--self-check")
    assert_equal 0, st.exitstatus, "error_gate self-check failed:\n#{out}#{err}"
    %w[decoration noise citation-is-free detection fake-enumeration fabricated-shape].each do |n|
      assert_match(/self-check #{Regexp.escape(n)}: (?!.*WANTED)/, out,
                   "self-check `#{n}` is not armed:\n#{out}")
    end
  end

  # Decoration is the whole point: a pass that adds "Why:"/"Fix:"/an E-number to
  # every message must not move the score. The gate measures this by rewriting
  # the entire corpus into that template; assert the measured answer is zero, not
  # merely "no worse".
  def test_boilerplate_scores_zero
    out, = gate("--self-check")
    assert_match(/self-check decoration: 0$/, out,
                 "a fully decorated template scored above zero, so the definition is a label check")
  end

  # ---- the debt list is a debt list, not a census ----------------------------

  def test_every_debt_row_says_what_is_missing_and_why
    rows = debt_rows
    refute_empty rows, "an empty debt list would mean the surface is perfect; verify before believing it"
    known = %w[subject remedy subject+remedy remedy-claimed-in-slot subject+remedy-claimed-in-slot]
    rows.each do |id, file, klass, note|
      assert_includes known, klass, "#{id}: unknown debt class `#{klass}`"
      refute_nil note, "#{id}: no note"
      assert_operator note.to_s.strip.length, :>, 40,
                      "#{id}: the note has to say why this one cannot name a remedy yet, not label it"
      assert_match(%r{\A(src/|bin/|tools/)}, file.to_s, "#{id}: debt row points outside the product")
    end
  end

  # `remedy-claimed-in-slot` exists so that "the message does name a fix, we just
  # cannot verify it from the text" is never spelled the same way as "there is no
  # fix here". If the class disappeared, those would merge
  # back into `remedy` and somebody would go rewrite a message that is fine.
  def test_the_unverifiable_class_is_kept_apart
    klasses = debt_rows.map { |r| r[2] }
    assert_includes klasses, "remedy-claimed-in-slot",
                    "the class that separates `cannot verify` from `nothing there` has gone empty; " \
                    "check that the distinction still exists before removing it"
  end

  # ---- the denominator excludes what it says it excludes ---------------------

  # The retired Ruby oracle raises ~197 times. It is reached only when the
  # in-process C codegen cannot be built -- the state tools/reach_gate.rb refuses
  # to run in -- so counting it would inflate the denominator with text no user
  # of a working install can see. This is the D0 decision; pin it, because it is
  # the difference between "304 errors" and a number about the product.
  def test_the_retired_oracle_is_not_counted
    out, _err, st = gate("--list")
    assert_equal 0, st.exitstatus
    refute_match(%r{codegen_bpf\.rb}, out,
                 "the retired Ruby codegen is being counted as product error surface")
    assert_match(%r{spinel_ebpf_cc\.c}, out, "the production codegen must be counted")
    assert_match(%r{bin/spinel-ebpf}, out, "the CLI's own aborts must be counted")
  end

  # An audience split is only honest if every site lands in exactly one bucket
  # and the buckets are the declared ones.
  def test_every_site_has_one_declared_audience
    out, = gate("--list")
    rows = out.lines.drop(1).map { |l| l.split("\t") }
    refute_empty rows
    auds = rows.map { |r| r[2] }.uniq.sort
    assert_equal %w[environment forwarded infra internal user], auds,
                 "an undeclared audience appeared (or one vanished)"
  end
end
