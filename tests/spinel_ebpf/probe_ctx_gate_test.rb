# frozen_string_literal: true
#
# The probe context + attach-point contract and its evolution gate.
#
# Two things are pinned here, in the shape record_gate_test.rb established:
#
#   (1) the LIVE gate — the committed artifacts are what the current
#       src/codegen_c/probe_ctx_schema.h generates, and the contract is
#       append-only against tests/golden/probe_ctx_schema.snapshot.json.
#
#   (2) the RULES themselves — negative controls fed to ProbeCtxGate.violations()
#       as synthetic projections. A gate that never fires is indistinguishable
#       from no gate, and every rule below exists because the corresponding
#       change would break silently rather than loudly: a renumbered field id is
#       an immediate already baked into shipped blobs, and a withdrawn attach
#       field is read by probes that were admitted against it.
require "minitest/autorun"
require "json"
require_relative "../../tools/probe_ctx_gate"

class ProbeCtxGateTest < Minitest::Test
  GATE = ProbeCtxGate

  # --- (1) the live contract ------------------------------------------------

  def test_committed_artifacts_match_the_declaration
    hdr, js = GATE.regenerate
    assert_empty GATE.regen_violations(hdr, js),
                 "generated artefacts are a different generation from the declaration " \
                 "(run `make -C src/codegen_c probe-ctx` and commit the result)"
  end

  def test_current_contract_is_append_only_against_the_snapshot
    assert File.exist?(GATE::SNAPSHOT), "no snapshot yet (run `ruby tools/probe_ctx_gate.rb --update`)"
    _hdr, js = GATE.regenerate
    old = JSON.parse(File.read(GATE::SNAPSHOT))
    assert_equal GATE::SNAPSHOT_SCHEMA, old["schema"]
    assert_empty GATE.violations(old, GATE.project(JSON.parse(js))),
                 "the probe context contract changed in a way that is not append-only"
  end

  def test_snapshot_is_the_current_contract
    _hdr, js = GATE.regenerate
    assert_equal File.read(GATE::SNAPSHOT), GATE.snapshot_text(GATE.project(JSON.parse(js))),
                 "the snapshot does not match the current contract (--update, then review the diff)"
  end

  # every declared attach point must only name fields that exist, and its bitmap
  # must be exactly those fields — the generator asserts this too, but the bitmap
  # is what the other core reads, so it is worth checking against the field ids
  # rather than trusting the generator's own arithmetic.
  def test_attach_bitmaps_agree_with_the_field_ids_they_claim
    _hdr, js = GATE.regenerate
    doc = JSON.parse(js)
    ids = doc["fields"].to_h { |f| [f["name"], f["id"]] }
    doc["attaches"].each do |at|
      expected = Array.new(doc["bitmap_words"], 0)
      at["fields"].each do |name|
        id = ids.fetch(name)
        expected[id / 64] |= 1 << (id % 64)
      end
      assert_equal expected, at["bitmap"],
                   "attach `#{at['name']}` has a bitmap that disagrees with its field ids"
    end
  end

  # --- (2) negative controls ------------------------------------------------

  def base
    {
      "schema" => GATE::SNAPSHOT_SCHEMA, "format_version" => 1, "bitmap_words" => 4,
      "fields" => {
        "thread.current.id" => { "id" => 1, "ctype" => "uint32_t", "size" => 4, "signed" => 0, "expose" => "int" },
        "timestamp.cycles"  => { "id" => 2, "ctype" => "uint64_t", "size" => 8, "signed" => 0, "expose" => "int" }
      },
      "attaches" => {
        "thread.switched_in" => {
          "id" => 1, "exec_class" => "SCHED_LOCKED", "max_cycle_budget" => 500,
          "fields" => ["thread.current.id", "timestamp.cycles"], "bitmap" => [6, 0, 0, 0]
        }
      },
      "slot_states" => { "EMPTY" => 0, "ACTIVE" => 3 }
    }
  end

  def refute_allowed(mutated, msg)
    v = GATE.violations(base, mutated)
    refute_empty v, "#{msg} was accepted"
    v
  end

  def test_removing_a_field_is_refused
    m = base
    m["fields"] = m["fields"].reject { |k, _| k == "timestamp.cycles" }
    assert_match(/was removed/, refute_allowed(m, "removing a field").join)
  end

  def test_renumbering_a_field_is_refused
    m = base
    m["fields"]["timestamp.cycles"] = m["fields"]["timestamp.cycles"].merge("id" => 9)
    assert_match(/id changed 2 -> 9/, refute_allowed(m, "renumbering a field id").join)
  end

  def test_retyping_or_resizing_a_field_is_refused
    m = base
    m["fields"]["thread.current.id"] =
      m["fields"]["thread.current.id"].merge("ctype" => "uint64_t", "size" => 8)
    v = refute_allowed(m, "changing a field type or width")
    assert_match(/ctype changed/, v.join)
    assert_match(/size changed/, v.join)
  end

  def test_flipping_signedness_is_refused
    m = base
    m["fields"]["thread.current.id"] = m["fields"]["thread.current.id"].merge("signed" => 1)
    assert_match(/signed changed/, refute_allowed(m, "flipping signedness").join)
  end

  def test_withdrawing_exposure_is_refused
    m = base
    m["fields"]["timestamp.cycles"] = m["fields"]["timestamp.cycles"].merge("expose" => nil)
    assert_match(/expose changed/, refute_allowed(m, "withdrawing expose").join)
  end

  def test_removing_an_attach_point_is_refused
    m = base
    m["attaches"] = {}
    assert_match(/attach point .* was removed/, refute_allowed(m, "removing an attach point").join)
  end

  def test_renumbering_an_attach_point_is_refused
    m = base
    m["attaches"]["thread.switched_in"] = m["attaches"]["thread.switched_in"].merge("id" => 2)
    assert_match(/id changed 1 -> 2/, refute_allowed(m, "renumbering an attach id").join)
  end

  # the one the plan calls out: capability published a field, probes were
  # admitted against it, and withdrawing it makes them read something unprovided.
  def test_withdrawing_a_field_from_an_attach_point_is_refused
    m = base
    m["attaches"]["thread.switched_in"] =
      m["attaches"]["thread.switched_in"].merge("fields" => ["thread.current.id"], "bitmap" => [2, 0, 0, 0])
    assert_match(/no longer provides `timestamp.cycles`/, refute_allowed(m, "withdrawing a field from an attach point").join)
  end

  # exec_class drives both the budget policy and the fault policy, so
  # changing it silently changes how every admitted probe is treated.
  def test_changing_exec_class_is_refused
    m = base
    m["attaches"]["thread.switched_in"] = m["attaches"]["thread.switched_in"].merge("exec_class" => "THREAD")
    assert_match(/exec_class changed/, refute_allowed(m, "changing exec_class").join)
  end

  def test_lowering_the_cycle_ceiling_is_refused
    m = base
    m["attaches"]["thread.switched_in"] = m["attaches"]["thread.switched_in"].merge("max_cycle_budget" => 200)
    assert_match(/max_cycle_budget fell/, refute_allowed(m, "lowering the budget ceiling").join)
  end

  def test_renumbering_a_slot_state_is_refused
    m = base
    m["slot_states"] = m["slot_states"].merge("ACTIVE" => 7)
    assert_match(/slot state `ACTIVE` changed/, refute_allowed(m, "renumbering a slot state").join)
  end

  def test_narrowing_the_bitmap_is_refused
    m = base
    m["bitmap_words"] = 2
    assert_match(/bitmap_words changed/, refute_allowed(m, "changing the bitmap width").join)
  end

  # --- the additive side: these must NOT fire -------------------------------

  def test_appending_a_field_is_allowed
    m = base
    m["fields"]["thread.previous.id"] =
      { "id" => 3, "ctype" => "uint32_t", "size" => 4, "signed" => 0, "expose" => "int" }
    assert_empty GATE.violations(base, m), "appending a field was rejected"
  end

  def test_adding_a_field_to_an_attach_point_is_allowed
    m = base
    m["fields"]["thread.previous.id"] =
      { "id" => 3, "ctype" => "uint32_t", "size" => 4, "signed" => 0, "expose" => "int" }
    m["attaches"]["thread.switched_in"] = m["attaches"]["thread.switched_in"]
                                          .merge("fields" => ["thread.current.id", "timestamp.cycles", "thread.previous.id"],
                                                 "bitmap" => [14, 0, 0, 0])
    assert_empty GATE.violations(base, m), "appending a field to an attach point was rejected"
  end

  def test_adding_an_attach_point_is_allowed
    m = base
    m["attaches"]["isr.enter"] = {
      "id" => 2, "exec_class" => "ISR", "max_cycle_budget" => 100,
      "fields" => ["timestamp.cycles"], "bitmap" => [4, 0, 0, 0]
    }
    assert_empty GATE.violations(base, m), "appending an attach point was rejected"
  end

  def test_raising_the_cycle_ceiling_is_allowed
    m = base
    m["attaches"]["thread.switched_in"] = m["attaches"]["thread.switched_in"].merge("max_cycle_budget" => 800)
    assert_empty GATE.violations(base, m), "raising the budget ceiling was rejected"
  end

  # a field declared but not yet readable can become readable later: that adds a
  # property, it does not change one anybody was already reading.
  def test_granting_exposure_is_allowed
    before = base
    before["fields"]["unexposed.thing"] =
      { "id" => 3, "ctype" => "uint32_t", "size" => 4, "signed" => 0, "expose" => nil }
    after = Marshal.load(Marshal.dump(before))
    after["fields"]["unexposed.thing"]["expose"] = "int"
    assert_empty GATE.violations(before, after), "granting exposure was rejected"
  end
end
