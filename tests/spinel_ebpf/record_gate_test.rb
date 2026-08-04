# frozen_string_literal: true
#
# The ringbuf record contract's evolution gate.
#
# Two things are pinned here:
#
#   (1) the LIVE gate -- the committed derived artifacts are what the current
#       src/codegen_c/record_schema.h generates, and the contract is append-only
#       with respect to tests/golden/record_schema.snapshot.json. This is the
#       same check `ruby tools/record_gate.rb` performs, run as part of the unit
#       suite so a schema edit cannot land without it.
#
#   (2) the RULES themselves -- negative controls fed to RecordGate.violations()
#       as synthetic projections. Each asserts that one class of breaking change
#       is caught: a moved field, a retyped field, a removed field, a withdrawn
#       Ruby property, a tightened accepted prefix, a dropped egress key, a
#       withdrawn typed consumer. Without these, a bug in the checker would make
#       the gate silently permissive (green means nothing).
require "minitest/autorun"
require "json"
require_relative "../../tools/record_gate"

class RecordGateTest < Minitest::Test
  GATE = RecordGate

  # --- (1) the live gate ----------------------------------------------------

  def test_committed_artifacts_match_the_declaration
    hdr, js = GATE.regenerate
    assert_empty GATE.regen_violations(hdr, js),
                 "the generated artifacts are a different generation from the declaration " \
                 "(run `make -C src/codegen_c mirror` and commit the result)"
  end

  def test_current_contract_is_append_only_against_the_snapshot
    assert File.exist?(GATE::SNAPSHOT), "the snapshot is missing (run `ruby tools/record_gate.rb --update`)"
    _hdr, js = GATE.regenerate
    old = JSON.parse(File.read(GATE::SNAPSHOT))
    assert_equal GATE::SNAPSHOT_SCHEMA, old["schema"]
    assert_empty GATE.violations(old, GATE.project(JSON.parse(js))),
                 "the record contract changed in a way that is not append-only"
  end

  def test_snapshot_is_the_current_contract
    _hdr, js = GATE.regenerate
    # Compare STRUCTURE, not text. `JSON.pretty_generate` writes an empty array
    # as `[]` from json 2.12 on and as `[\n\n]` before that, so a text comparison
    # can only be green on one of the two hosts this suite runs on (measured:
    # json 2.12.2 on the development host, 2.7.2 in the build container). The
    # contract is the structure; where the generator puts whitespace is not part
    # of it.
    assert_equal JSON.parse(File.read(GATE::SNAPSHOT)),
                 JSON.parse(GATE.snapshot_text(GATE.project(JSON.parse(js)))),
                 "the snapshot is out of date (even an append-only change updates the baseline, " \
                 "which is then committed)"
  end

  # --- (2) negative controls: each rule must actually bite ------------------

  # The smallest legal projection. Each test below breaks it in exactly one place.
  def base
    { "schema" => GATE::SNAPSHOT_SCHEMA,
      "channels" => {
        "demo" => {
          "record_struct" => "<unit>_demo_event",
          "ringbuf_map" => "<unit>_demo_events",
          "record_bytes" => 32, "record_min_bytes" => 32,
          "producers" => ["emit_demo"],
          "fields" => [
            { "name" => "hdr", "ctype" => "struct spnl_event_hdr", "count" => 0,
              "offset" => 0, "bytes" => 16, "expose" => "" },
            { "name" => "pid", "ctype" => "__u32", "count" => 0,
              "offset" => 16, "bytes" => 4, "expose" => "int" },
            { "name" => "cgid", "ctype" => "__u64", "count" => 0,
              "offset" => 24, "bytes" => 8, "expose" => "" },
          ],
          "egress" => { "push_fn" => "spnl_otlp_demo_span_push", "span_name" => "demo {x}",
                        "span_kind" => "INTERNAL", "attributes" => %w[a.b c.d],
                        "enrichers" => %w[k8s] },
          "metrics" => [
            { "id" => "count", "name" => "spnl.demo.count", "kind" => "counter",
              "unit" => "{demo}", "value_from" => "", "bounds" => "", "series_bound" => 3,
              "labels" => [{ "key" => "spnl.demo.kind", "from" => "kind", "bound" => 3,
                             "bound_from" => "value_map", "fallback" => "other" }] },
          ],
          "consumer" => { "drain_fn" => "spnl_rec_demo_drain", "to_span_fn" => "spnl_rec_demo_to_span",
                          "properties" => [{ "name" => "pid", "kind" => "field",
                                             "expose" => "int", "ffi" => "spnl_rec_demo_pid" }] },
        },
      } }
  end

  def mutate
    d = JSON.parse(JSON.generate(base))   # deep copy
    yield d
    GATE.violations(base, d)
  end

  def test_unchanged_contract_is_clean
    assert_empty GATE.violations(base, base)
  end

  def test_moving_an_existing_field_is_rejected
    v = mutate { |d| d["channels"]["demo"]["fields"][2]["offset"] = 32 }
    assert_match(/field `cgid` offset changed 24 -> 32/, v.join("\n"))
  end

  def test_retyping_an_existing_field_is_rejected
    v = mutate do |d|
      f = d["channels"]["demo"]["fields"][1]
      f["ctype"] = "__u64"; f["bytes"] = 8
    end
    assert_match(/field `pid` ctype changed "__u32" -> "__u64"/, v.join("\n"))
    assert_match(/field `pid` bytes changed 4 -> 8/, v.join("\n"))
  end

  def test_removing_a_field_is_rejected
    v = mutate { |d| d["channels"]["demo"]["fields"].delete_at(2) }
    assert_match(/field `cgid` was removed/, v.join("\n"))
  end

  def test_inserting_a_field_before_an_existing_one_is_rejected
    v = mutate do |d|
      d["channels"]["demo"]["fields"].insert(2, { "name" => "flags", "ctype" => "__u32",
                                                  "count" => 0, "offset" => 20, "bytes" => 4,
                                                  "expose" => "" })
    end
    assert_match(/fields were reordered/, v.join("\n"))
  end

  # Appending at the end is allowed (rejecting it would keep the contract from growing)
  def test_appending_a_field_at_the_end_is_allowed
    v = mutate do |d|
      c = d["channels"]["demo"]
      c["fields"] << { "name" => "retries", "ctype" => "__u32", "count" => 0,
                       "offset" => 32, "bytes" => 4, "expose" => "" }
      c["record_bytes"] = 40   # min stays put, so records from an older producer still fit
    end
    assert_empty v
  end

  # But a half-done append -- fields added at the end without relaxing the accepted
  # prefix, so records from an older producer are dropped -- is rejected (the second
  # half of the Cap'n Proto evolution rule).
  def test_appending_without_relaxing_the_accepted_prefix_is_rejected
    v = mutate do |d|
      c = d["channels"]["demo"]
      c["fields"] << { "name" => "retries", "ctype" => "__u32", "count" => 0,
                       "offset" => 32, "bytes" => 4, "expose" => "" }
      c["record_bytes"] = 40
      c["record_min_bytes"] = 40
    end
    assert_match(/record_min_bytes rose 32 -> 40/, v.join("\n"))
  end

  def test_withdrawing_a_ruby_visible_property_is_rejected
    v = mutate do |d|
      d["channels"]["demo"]["fields"][1]["expose"] = ""
      d["channels"]["demo"]["consumer"]["properties"] = []
    end
    assert_match(/field `pid` expose changed "int" -> ""/, v.join("\n"))
    assert_match(/consumer property `ev\.pid` was removed/, v.join("\n"))
  end

  # The other direction (hidden -> exposed) is an addition, so it is allowed
  def test_exposing_a_previously_hidden_field_is_allowed
    v = mutate do |d|
      d["channels"]["demo"]["fields"][2]["expose"] = "int"
      d["channels"]["demo"]["consumer"]["properties"] << {
        "name" => "cgid", "kind" => "field", "expose" => "int", "ffi" => "spnl_rec_demo_cgid"
      }
    end
    assert_empty v
  end

  def test_changing_a_property_type_is_rejected
    v = mutate { |d| d["channels"]["demo"]["consumer"]["properties"][0]["expose"] = "str" }
    assert_match(/consumer property `ev\.pid` expose changed "int" -> "str"/, v.join("\n"))
  end

  # Withdrawing a raw field's expose and re-attaching **a derivation of the same
  # name** (to line the unit up with the span, say) leaves the name, the Ruby type
  # and the FFI symbol all unchanged, yet it **trips two rules**. Failing is the
  # right outcome -- a change that changes values must not pass silently, so the
  # gate does its job by saying "come and look". **But the gate reads shape, not
  # values** (a projection carries no values), so what this means for a consumer
  # that is already running is left to a human to judge.
  def test_reclassifying_a_field_property_as_derived_is_flagged
    v = mutate do |d|
      d["channels"]["demo"]["fields"][1]["expose"] = ""            # drop the field's exposure
      d["channels"]["demo"]["consumer"]["properties"][0]["kind"] = "derived"   # same name, now derived
    end
    assert_match(/field `pid` expose changed "int" -> ""/, v.join("\n"))
    assert_match(/consumer property `ev\.pid` kind changed "field" -> "derived"/, v.join("\n"))
    assert_equal 2, v.length, "this re-attachment trips exactly 2 rules (the name and the type " \
                              "are unchanged, so nothing else fires)"
  end

  # --- the output capacity of a derivation ----------------------------------
  #
  # cap is *the width* that both sides -- the generated accessor and the span
  # builder -- pass. Widening it is additive (whatever fitted before still fits),
  # but narrowing it **truncates values that used to arrive whole** -- in
  # `ev.<name>` and in the span attribute it feeds, at the same time. So it counts
  # as a breaking change.
  def with_derived_cap(cap)
    d = JSON.parse(JSON.generate(base))
    p = { "name" => "label", "kind" => "derived", "expose" => "str",
          "ffi" => "spnl_rec_demo_label" }
    p["cap"] = cap unless cap.nil?
    d["channels"]["demo"]["consumer"]["properties"] << p
    d
  end

  def test_narrowing_a_derivation_cap_is_rejected
    v = GATE.violations(with_derived_cap(256), with_derived_cap(64))
    assert_match(/consumer property `ev\.label` cap shrank 256 -> 64/, v.join("\n"))
  end

  def test_widening_a_derivation_cap_is_allowed
    assert_empty GATE.violations(with_derived_cap(64), with_derived_cap(256))
  end

  # A snapshot taken before caps existed does not carry one. That is simply nothing
  # to compare against, so it is not a violation (the next --update puts it in the
  # baseline, and it is protected from there on).
  def test_a_snapshot_without_caps_is_not_a_violation
    assert_empty GATE.violations(with_derived_cap(nil), with_derived_cap(64))
  end

  # A property backed by a raw field has no cap (it reads the record's bytes as they
  # are, so its width is the field's `bytes`, which the snapshot already carries).
  # Comparing null against null must not raise a false positive.
  def test_field_properties_have_no_cap_rule
    assert_empty GATE.violations(base, base)
    assert_nil base["channels"]["demo"]["consumer"]["properties"][0]["cap"]
  end

  def test_dropping_an_egress_attribute_is_rejected
    v = mutate { |d| d["channels"]["demo"]["egress"]["attributes"] = %w[a.b] }
    assert_match(/egress attribute `c\.d` was removed/, v.join("\n"))
  end

  def test_adding_an_egress_attribute_is_allowed
    v = mutate { |d| d["channels"]["demo"]["egress"]["attributes"] << "e.f" }
    assert_empty v
  end

  def test_renaming_the_push_fn_is_rejected
    v = mutate { |d| d["channels"]["demo"]["egress"]["push_fn"] = "spnl_otlp_demo2_span_push" }
    assert_match(/egress push_fn changed/, v.join("\n"))
  end

  def test_withdrawing_the_typed_consumer_is_rejected
    v = mutate { |d| d["channels"]["demo"]["consumer"] = nil }
    assert_match(/typed consumer was withdrawn/, v.join("\n"))
  end

  # Adding a typed consumer to a channel that did not have one is an addition, so
  # it is allowed
  def test_adding_a_typed_consumer_is_allowed
    old = JSON.parse(JSON.generate(base))
    old["channels"]["demo"].delete("consumer")
    assert_empty GATE.violations(old, base)
  end

  # --- the metric contract --------------------------------------------------
  #
  # A metric is queried by name from outside the process, so the breaking changes
  # are the ones that make a dashboard stop finding it (removed / renamed /
  # re-typed) or start answering a different question (a label that vanishes
  # merges series that were distinguished; a label that keeps its key and changes
  # its source keeps the query working and changes what it means -- the worst of
  # the three, because it is the only one nothing else can notice).

  def test_removing_a_metric_is_rejected
    v = mutate { |d| d["channels"]["demo"]["metrics"] = [] }
    assert_match(/metric `count` was removed/, v.join("\n"))
  end

  def test_renaming_a_metric_is_rejected
    v = mutate { |d| d["channels"]["demo"]["metrics"][0]["name"] = "spnl.demo.total" }
    assert_match(/metric `count` name changed/, v.join("\n"))
  end

  def test_changing_a_metric_kind_is_rejected
    v = mutate { |d| d["channels"]["demo"]["metrics"][0]["kind"] = "histogram" }
    assert_match(/metric `count` kind changed/, v.join("\n"))
  end

  def test_changing_a_metric_unit_is_rejected
    v = mutate { |d| d["channels"]["demo"]["metrics"][0]["unit"] = "s" }
    assert_match(/metric `count` unit changed/, v.join("\n"))
  end

  def test_removing_a_metric_label_is_rejected
    v = mutate { |d| d["channels"]["demo"]["metrics"][0]["labels"] = [] }
    assert_match(/lost label `spnl.demo.kind`/, v.join("\n"))
  end

  def test_repointing_a_label_at_another_property_is_rejected
    v = mutate { |d| d["channels"]["demo"]["metrics"][0]["labels"][0]["from"] = "pid" }
    assert_match(/label `spnl.demo.kind` now reads `pid`/, v.join("\n"))
  end

  def test_adding_a_metric_is_allowed
    v = mutate do |d|
      d["channels"]["demo"]["metrics"] << {
        "id" => "dur", "name" => "spnl.demo.duration", "kind" => "histogram", "unit" => "s",
        "value_from" => "duration_ns", "bounds" => "otel_duration_s", "series_bound" => 1,
        "labels" => [],
      }
    end
    assert_empty v
  end

  # Widening a permitted set raises the ceiling. That is allowed -- it is how a
  # status code gets added -- but the number lands in the snapshot, so it can only
  # move through a reviewed diff. This test pins that it is allowed, so that the
  # rule above is not read as "the bound may never change".
  def test_widening_a_labels_bound_is_allowed_but_visible
    v = mutate do |d|
      m = d["channels"]["demo"]["metrics"][0]
      m["labels"][0]["bound"] = 5
      m["series_bound"] = 5
    end
    assert_empty v
    refute_equal base["channels"]["demo"]["metrics"][0]["series_bound"], 5,
                 "this test depends on series_bound being carried in the snapshot"
  end

  # The centre of the metric contract: series_bound has to be a number that can be
  # computed from the declaration alone. Check that on the **committed** generated
  # artifact rather than on a synthetic projection -- the product of the label
  # bounds must be the declared series_bound.
  def test_declared_series_bound_is_the_product_of_its_label_bounds
    doc = JSON.parse(File.read(File.expand_path("../../src/spinel_ebpf/record_schema_gen.json", __dir__)))
    seen = 0
    doc["channels"].each do |c|
      Array(c["metrics"]).each do |m|
        want = Array(m["labels"]).map { |l| l["bound"] }.reduce(1, :*)
        assert_equal want, m["series_bound"],
                     "#{c['id']}.#{m['id']}: series_bound is not the product of its label bounds"
        Array(m["labels"]).each do |l|
          assert_includes %w[declared_set value_map], l["bound_from"],
                          "#{l['key']}: the bound does not say where it comes from"
          if l["bound_from"] == "declared_set"
            assert_equal Array(l["values"]).length + 1, l["bound"],
                         "#{l['key']}: bound does not equal \"the set plus its fallback\""
            refute_empty l["fallback"].to_s, "#{l['key']}: nothing outside the set has anywhere to go"
          end
        end
        seen += 1
      end
    end
    assert_operator seen, :>, 0, "no metric is declared at all (this test would be idling)"
  end

  def test_removing_a_channel_is_rejected
    v = mutate { |d| d["channels"].delete("demo") }
    assert_match(/channel `demo` was removed/, v.join("\n"))
  end

  def test_adding_a_channel_is_allowed
    v = mutate do |d|
      d["channels"]["other"] = d["channels"]["demo"].merge(
        "record_struct" => "<unit>_other_event", "ringbuf_map" => "<unit>_other_events"
      )
    end
    assert_empty v
  end

  def test_renaming_the_ringbuf_map_is_rejected
    v = mutate { |d| d["channels"]["demo"]["ringbuf_map"] = "<unit>_demo_ring" }
    assert_match(/ringbuf_map changed/, v.join("\n"))
  end

  def test_dropping_a_producer_is_rejected
    v = mutate { |d| d["channels"]["demo"]["producers"] = [] }
    assert_match(/producer `emit_demo` no longer writes this channel/, v.join("\n"))
  end
end
