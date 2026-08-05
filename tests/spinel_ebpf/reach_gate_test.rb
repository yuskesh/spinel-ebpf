# frozen_string_literal: true
#
# Invariants of the product-reachability record itself.
#
# tools/reach_gate.rb needs the container (it runs the real CLI, ~180 compiles).
# These are the things that can rot WITHOUT the gate running: the baseline losing
# a row, gaining an orphan, drifting from the vocabulary its own header declares,
# or an unreachable row quietly losing the prose that tells "kept on purpose"
# from "forgotten". They are host-cheap, so they run every time.
require "minitest/autorun"

class ReachGateRecordTest < Minitest::Test
  ROOT     = File.expand_path("../..", __dir__)
  BASELINE = File.join(ROOT, "tests/golden/product_reach.tsv")
  REJECT   = File.join(ROOT, "tests/golden/codegen_reject.tsv")
  GATE     = File.join(ROOT, "tools/reach_gate.rb")

  def rows
    @rows ||= File.readlines(BASELINE)
                  .reject { |l| l.start_with?("#") || l.strip.empty? }
                  .map { |l| l.chomp.split("\t", 4) }
  end

  def goldens
    @goldens ||= Dir[File.join(ROOT, "tests/golden/*.bpf.c")].map { |f| File.basename(f, ".bpf.c") }.sort
  end

  def refusals
    @refusals ||= File.readlines(REJECT).reject { |l| l.start_with?("#") || l.strip.empty? }
                      .map { |l| l.chomp.split("\t", 2).first }.sort
  end

  def test_every_row_has_four_fields
    rows.each_with_index do |r, i|
      assert_equal 4, r.size,
                   "row #{i + 1} of product_reach.tsv is not artifact\\tkind\\tproduct\\tnote: #{r.inspect}"
    end
  end

  # The record covers BOTH kinds of fact tools/golden.rb pins. Coverage is
  # checked in both directions on purpose: a record that only has to be a
  # subset of reality is green when it is empty, which is the exact silence this
  # axis exists to break.
  def test_record_covers_every_golden_and_only_goldens
    have = rows.select { |r| r[1] == "golden" }.map(&:first).sort
    assert_equal goldens, have,
                 "product_reach.tsv must have exactly one row per tests/golden/*.bpf.c " \
                 "(missing: #{(goldens - have).inspect}, orphan: #{(have - goldens).inspect}) — " \
                 "refresh with: ruby tools/reach_gate.rb --update"
  end

  def test_record_covers_every_refusal_and_only_refusals
    have = rows.select { |r| r[1] == "refusal" }.map(&:first).sort
    assert_equal refusals, have,
                 "product_reach.tsv must have exactly one row per codegen_reject.tsv entry " \
                 "(missing: #{(refusals - have).inspect}, orphan: #{(have - refusals).inspect})"
  end

  # The vocabulary lives in two places (the gate's PLAIN table and the header
  # that a human reads). Two readers of one declaration: pin them together or
  # they drift, and the header is the half nobody runs.
  def test_product_vocabulary_is_the_declared_one
    declared = %w[default ebpf-dispatch no-ebpf refused]
    rows.each { |r| assert_includes declared, r[2], "#{r[0]}: unknown product value #{r[2].inspect}" }
    header = File.read(BASELINE)[/\A(#.*\n)+/]
    declared.each do |v|
      assert_includes header, v, "the baseline header does not document the value #{v.inspect}"
    end
  end

  # `differs` = the product and the codegen emitted different bytes for one
  # fixture. tools/stage2_verify.sh exists to make that impossible, so recording
  # it here would let two gates disagree about one file forever. The gate refuses
  # to write it; this pins that nobody hand-edits it in.
  def test_differs_is_never_recorded
    refute_includes rows.map { |r| r[2] }, "differs",
                    "a `differs` row means the product and the codegen disagree on bytes — fix it, do not record it"
    assert_includes File.read(GATE), "NEVER_BASELINE",
                    "tools/reach_gate.rb lost the rule that keeps `differs` out of the baseline"
  end

  # D4: the difference between "unreachable but alive as the rationale for a
  # rule" and "unreachable and forgotten" is whether anyone wrote down why. That
  # cannot be checked as prose, but its PRESENCE can, and a row that must carry
  # prose is a row somebody had to look at.
  def test_non_plain_rows_carry_prose
    plain = { "golden" => "default", "refusal" => "refused" }
    rows.each do |art, kind, prod, note|
      next if prod == plain[kind]
      refute_nil note
      refute_empty note.to_s.strip,
                   "#{art} (#{kind}/#{prod}) has no note. An artifact the product cannot reach by its " \
                   "default invocation needs one saying why it is kept and what would make it reachable again."
    end
  end

  # A note that only says "unreachable" restates the column. What makes the row
  # readable a year later is the second half: the condition under which it comes
  # back. Checked as a floor on substance, not as wording.
  def test_prose_says_what_would_make_it_reachable
    plain = { "golden" => "default", "refusal" => "refused" }
    rows.each do |art, kind, prod, note|
      next if prod == plain[kind]
      assert_operator note.to_s.length, :>, 120,
                      "#{art}: the note is too short to carry both halves (why it is kept, and what would revive it)"
      assert_match(/reachable again|Reachable|Closing it|fires/i, note.to_s,
                   "#{art}: the note does not say what would change this verdict")
    end
  end

  # The artifacts not reachable by the default invocation. Pinned by name so
  # that "the set is empty now" cannot be reached by deleting rows instead of
  # fixing or re-measuring them.
  #
  # Three were measured at first, then one left: `163_timer_no_interval` was
  # `refusal/no-ebpf` — the codegen refused it but the CLI never asked, because
  # the partition dropped the handler with a warning and emitted no eBPF. The
  # partition now refuses instead, so the fixture's own claim ("a timer that
  # cannot fire must not compile") is finally true of the product. The row moved
  # to the plain value `refused`, which is why it leaves this list rather than
  # changing its verdict here.
  def test_the_measured_component_only_set
    plain = { "golden" => "default", "refusal" => "refused" }
    non_plain = rows.reject { |_a, k, p, _n| p == plain[k] }.map { |r| [r[0], r[2]] }.sort
    assert_equal([["03_fib_recursion", "no-ebpf"],
                  ["32_path_counter", "ebpf-dispatch"]].sort,
                 non_plain,
                 "the set of artifacts the default `spinel-ebpf compile` does not reach changed. " \
                 "That is a real event: re-measure with `ruby tools/reach_gate.rb` in the " \
                 "container and move this list with the reason.")
  end
end
