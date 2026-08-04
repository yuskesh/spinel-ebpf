# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/affordance_gate_test.rb
#
# The affordance gate's own invariants.
#
# The gate itself (tools/affordance_gate.rb) needs the production in-process
# codegen, which is Linux + a built upstream spinel; these tests deliberately
# need neither. They check the part that decides WHAT gets compiled -- because a
# gate that quietly stops covering a builtin looks exactly like a gate that
# passes. The finding that produced this gate was a check nobody was running;
# the second-order version of that mistake is a check that runs but no longer
# reaches anything.

require "minitest/autorun"
require "spinel_ebpf/capabilities"
require_relative "../../tools/affordance_gate"

class AffordanceGateTest < Minitest::Test
  CAP = SpinelEbpf::Capabilities
  G   = AffordanceGate

  # ---------- coverage: the gate must be able to probe every claim ----------

  # Every advertised builtin resolves to a probe shape the gate can actually
  # write. A name resolving to an unknown shape would raise mid-run (or, worse,
  # be skipped by a future `next`), which is how coverage silently shrinks.
  def test_every_advertised_builtin_has_a_writable_shape
    bad = CAP.all_builtins.reject { |b| SHAPES.key?(G.shape_for(b)) }
    assert_empty bad, "builtin with no probe shape (the gate cannot measure it): #{bad.inspect}"
  end

  def test_every_withdrawn_builtin_has_a_writable_shape
    bad = CAP::WITHDRAWN.keys.reject { |b| SHAPES.key?(G.shape_for(b)) }
    assert_empty bad, "withdrawn builtin with no probe shape: #{bad.inspect}"
  end

  # Nothing is silently skipped: the two sets together are what the gate checks,
  # and the advertised half must be the whole affordance.
  def test_gate_covers_the_whole_affordance
    refute_empty CAP.all_builtins
    refute_empty CAP::WITHDRAWN, "with an empty negative control the gate cannot detect its own decay"
    assert_empty(CAP.all_builtins & CAP::WITHDRAWN.keys)
  end

  # ---------- the probe text ----------

  # The call the gate compiles is the affordance's own published example, not a
  # separately-maintained snippet. If these ever diverge the gate would be
  # proving something about a probe nobody was ever told to write.
  def test_call_text_is_the_published_example
    %w[pid kfield path_eq flow_get spnl_emit].each do |b|
      assert_equal CAP.example_for(b), G.call_text(b), "#{b}: the gate's probe differs from the affordance's example"
    end
  end

  # opaque kfuncs publish no example (params honestly unknown); the gate must
  # still be able to call them, at the known arity.
  def test_opaque_builtins_get_a_synthesised_call
    assert_nil CAP.example_for("scx_dispatch")
    assert_equal "scx_dispatch(a0, a1, a2, a3)", G.call_text("scx_dispatch")
  end

  def test_withdrawn_builtins_get_a_call_even_without_a_signature
    # They are out of SIGNATURES entirely, so the arity comes from WITHDRAWN.
    refute_includes CAP::SIGNATURES.keys, "tail_call_to"
    assert_equal "tail_call_to(a0)", G.call_text("tail_call_to")
    assert_equal 'payload_starts("GET ")', G.call_text("payload_starts")
  end

  def test_free_vars_skips_literals
    assert_equal %w[sk], G.free_vars("kfield", 'kfield(sk, "sock", "sk_sndbuf")')
    assert_equal [], G.free_vars("flow_get", "flow_get(:conn, :backend_ip)")
    assert_equal %w[a b], G.free_vars("divu", "divu(a, b)")
  end

  # ---------- the generated probe is a probe ----------

  def test_probe_binds_free_vars_as_params_where_the_kind_takes_them
    src = G.source(:kprobe, 'kfield(sk, "sock", "sk_sndbuf")', %w[sk])
    assert_includes src, "def kprobe__do_sys_openat2(sk)"
    assert_includes src, 'kfield(sk, "sock", "sk_sndbuf")'
  end

  def test_probe_binds_free_vars_as_locals_where_the_kind_does_not
    src = G.source(:xdp, "cpumap_redirect(cpu)", %w[cpu])
    assert_includes src, "def xdp__probe\n"
    assert_includes src, "  cpu = 0"
    assert_includes src, "  XDP_PASS"   # a verdict kind still returns a verdict
  end

  def test_probe_uses_the_gated_handler_for_dpath_builtins
    src = G.source(G.shape_for("path_eq"), G.call_text("path_eq"), G.free_vars("path_eq", G.call_text("path_eq")))
    assert_includes src, "def lsm__file_open(file, ret)"
    assert_includes src, 'path_eq(file, "/usr/bin/curl")'
  end

  def test_struct_ops_probe_is_wrapped_in_its_class
    src = G.source(:tcp_cc, "tcp_sock_snd_cwnd(sk)", %w[sk])
    assert_includes src, "class ProbeCC < BPF::TcpCC"
    assert_includes src, "  def cong_avoid(sk, ack, acked)"
    assert src.rstrip.end_with?("end"), "the class is left unclosed"
  end

  # The call is never the last statement, so a value-returning builtin cannot be
  # mistaken for the handler's verdict -- and a statement-only builtin still
  # emits. (Both forms have to survive the same probe template.)
  def test_call_is_not_the_return_value
    src = G.source(:kprobe, "spnl_emit(value)", %w[value])
    lines = src.lines.map(&:strip).reject(&:empty?)
    tail = lines[-2..]   # last body statement, then `end`
    assert_equal "end", tail[1]
    assert_equal "0", tail[0], "the builtin call sits in the return position (it would collide with a void builtin)"
  end

  # ---------- shape metadata does not rot ----------

  # SHAPE_OVERRIDE is hand-maintained, so it is the part most likely to go stale.
  # Every key must still be a builtin, and it must be doing work (an override
  # that agrees with the derived shape is dead weight that reads as coverage).
  def test_shape_overrides_all_name_real_builtins
    unknown = SHAPE_OVERRIDE.keys.reject { |b| CAP.all_builtins.include?(b) }
    assert_empty unknown, "SHAPE_OVERRIDE names a builtin that does not exist: #{unknown.inspect}"
    bad = SHAPE_OVERRIDE.values.reject { |v| SHAPES.key?(v) }
    assert_empty bad, "SHAPE_OVERRIDE names an undefined shape: #{bad.inspect}"
  end

  # A builtin with a declared context requirement must take its shape from the
  # requirement, not from a hand-written override (otherwise the gate stops
  # testing the documented context and starts testing whatever we typed here).
  def test_gated_builtins_are_not_shape_overridden
    overridden = SHAPE_OVERRIDE.keys.select { |b| CAP::CONTEXT_REQUIREMENTS.key?(b) }
    assert_empty overridden,
                 "these declare a context and are overridden anyway (the gate would measure a context other than the declared one): #{overridden.inspect}"
  end

  # ---------- the attach-kind half ----------

  # Same coverage invariant as the builtins: a kind with no probe shape is a kind
  # nothing checks. The gate aborts on this at run time; here it is caught without
  # needing the Linux codegen.
  def test_every_advertised_attach_kind_has_a_probe_shape
    missing = CAP::ATTACH_KINDS.map { |a| a[:kind] } - G::ATTACH_SHAPES.keys
    assert_empty missing, "attach kind with no probe shape (the gate cannot measure it): #{missing.inspect}"
  end

  def test_no_probe_shape_for_a_withdrawn_or_unknown_attach_kind
    stale = G::ATTACH_SHAPES.keys - CAP::ATTACH_KINDS.map { |a| a[:kind] }
    assert_empty stale, "a probe shape is left over for an attach kind that is not advertised: #{stale.inspect}"
  end

  def test_attach_gate_covers_both_directions
    refute_empty CAP::ATTACH_KINDS
    refute_empty CAP::WITHDRAWN_ATTACH,
                 "an empty withdrawn set leaves the attach half with no negative control " \
                 "(an unimplemented attach raises nothing and degrades to SEC(\"syscall\"), so a " \
                 "decayed gate and a healthy one both report broken=0)"
    assert_empty(CAP::ATTACH_KINDS.map { |a| a[:kind] } & CAP::WITHDRAWN_ATTACH.keys)
  end

  # The expected SEC is the affordance's own `sec:` field with this shape's
  # concrete names substituted -- never a string typed into the gate. If they
  # diverged, the gate would be enforcing a promise nobody published.
  def test_promised_sec_comes_from_the_affordance
    assert_equal "kprobe/do_sys_openat2", G.promised_sec(:kprobe)
    assert_equal "tracepoint/syscalls/sys_enter_openat", G.promised_sec(:tracepoint)
    assert_equal "struct_ops/cong_avoid", G.promised_sec(:tcp_cc)
    assert_equal "sockops", G.promised_sec(:sock_ops)
    # no unsubstituted placeholder may survive into an expectation
    CAP::ATTACH_KINDS.each do |a|
      refute_match(/[<>]/, G.promised_sec(a[:kind]).to_s,
                   "#{a[:kind]}: a placeholder in `sec` was never filled in (ATTACH_SHAPES is missing a substitution)")
    end
  end

  def test_attach_probe_is_written_in_the_advertised_surface
    src = G.attach_source(:sock_ops, "zzm")
    assert_includes src, "def sock_ops__probe"
    assert_includes src, "@zzm = @zzm + 1", "without a body marker there is no way to measure whether the body reached the output"

    cls = G.attach_source(:qdisc, "zzq")
    assert_includes cls, "class ProbeQ < BPF::Qdisc"
    assert_includes cls, "  def enqueue(skb, sch, to_free)"
  end

  # The withdrawn probes come from the affordance's own record, so the negative
  # control is the shape a reader of WITHDRAWN_ATTACH would actually type.
  def test_withdrawn_attach_probe_uses_the_recorded_surface
    CAP::WITHDRAWN_ATTACH.each_key do |k|
      src = G.withdrawn_attach_source(k, "zzw")
      assert_includes src, CAP::WITHDRAWN_ATTACH[k][:probe].lines.first.chomp
      assert src.rstrip.end_with?("end"), "#{k}: the probe is left unclosed"
    end
  end

  # SEC("license") / SEC(".maps") / SEC(".struct_ops") are not attach points; a
  # gate that counted them would call any output "has a SEC".
  def test_prog_secs_ignores_non_program_sections
    out = %(char LICENSE[] SEC("license") = "GPL";\n} u_top SEC(".maps");\nSEC("sockops")\nSEC(".struct_ops.link")\n)
    assert_equal ["sockops"], G.prog_secs(out)
  end

  # ---------- surface sugar ----------

  # A sugar claim the gate cannot write is a claim nothing checks -- the
  # second-order version of the finding that produced this section.
  def test_every_sugar_claim_has_a_writable_shape
    bad = CAP.surface_sugar.reject do |s|
      s[:form] == :attach || G::SUGAR_SHAPES.key?(s[:shape])
    end
    assert_empty bad.map { |s| [s[:id], s[:shape]] },
                 "sugar claim with no probe shape (the gate cannot measure it)"
  end

  # ids name the failures, so a duplicate would hide one behind the other.
  def test_sugar_claim_ids_are_unique
    dups = CAP.surface_sugar.map { |s| s[:id] }.tally.select { |_, v| v > 1 }
    assert_empty dups, "duplicate sugar claim id"
  end

  # Every claim is a PAIR. One-sided entries would silently degrade the section
  # into "does it compile", which is the criterion this section exists to replace.
  def test_every_sugar_claim_has_both_spellings
    CAP.surface_sugar.each do |s|
      refute_nil s[:sugar], "#{s[:id]}: no sugar spelling"
      refute_nil s[:flat],  "#{s[:id]}: no flat equivalent"
      refute_equal s[:sugar], s[:flat], "#{s[:id]}: the two spellings are identical (there is no claim)"
      assert_includes %i[identical compiles], s[:equiv], "#{s[:id]}: equiv is not stated"
    end
  end

  # :compiles is the weaker tier and cannot see `diverged`, so an entry may only
  # sit there with a written reason. Silent weakening is how a gate rots.
  def test_weaker_equivalence_tier_states_its_reason
    CAP.surface_sugar.select { |s| s[:equiv] == :compiles }.each do |s|
      refute_nil s[:note], "#{s[:id]}: sits in equiv: :compiles with no reason"
      assert_operator s[:note].length, :>, 40, "#{s[:id]}: the reason is too short"
    end
  end

  # :attach claims are whole probe fragments; both sides must have the hole the
  # shared body goes into, or the two probes would not be running the same code.
  def test_attach_sugar_fragments_carry_the_body_hole
    CAP.surface_sugar.select { |s| s[:form] == :attach }.each do |s|
      assert_includes s[:sugar], "<BODY>", "#{s[:id]}: the sugar side has no <BODY>"
      assert_includes s[:flat],  "<BODY>", "#{s[:id]}: the flat side has no <BODY>"
      refute_nil s[:ret], "#{s[:id]}: without a return value the handler does not close"
    end
  end

  # Both directions, same rule as builtins/attach: without a withdrawn set the
  # sugar section could degenerate into a yes-machine and stay green.
  def test_sugar_gate_covers_both_directions
    refute_empty CAP.surface_sugar
    refute_empty CAP::WITHDRAWN_SUGAR, "with an empty negative control the gate cannot detect its own decay"
    assert_empty(CAP.surface_sugar.map { |s| s[:sugar] } & CAP::WITHDRAWN_SUGAR.keys)
    CAP::WITHDRAWN_SUGAR.each do |spelling, info|
      assert G::SUGAR_SHAPES.key?(info[:shape]), "#{spelling}: no probe shape"
      refute_nil info[:why]
      refute_nil info[:instead], "#{spelling}: does not say what to write instead"
    end
  end

  # The pkt.* chain claims are derived from the flat reader names, so the chain
  # surface cannot name a reader the flat surface does not have.
  def test_pkt_chain_claims_are_derived_from_the_flat_builtins
    CAP.surface_sugar.select { |s| s[:id].to_s.start_with?("pkt_chain_") }.each do |s|
      assert_equal s[:sugar].tr(".", "_"), s[:flat]
      assert_includes CAP.all_builtins, s[:flat], "#{s[:id]}: the flat side is not advertised as a builtin"
    end
  end

  # The class and module surfaces of one DSL parent must claim the SAME flat
  # twin: they are two spellings of one binding, and the failure this section was
  # written for was precisely that only one of them was implemented.
  def test_class_and_module_surfaces_claim_the_same_flat_form
    by_flat = CAP.surface_sugar.select { |s| s[:id].to_s.start_with?("attach_class_", "attach_module_") }
                 .group_by { |s| s[:flat] }
    assert_equal CAP::SUGAR_DSL_PARENTS.size, by_flat.size
    by_flat.each_value { |pair| assert_equal 2, pair.size, "only one of the class/module spellings is claimed" }
  end

  # ---------- maps ----------

  # Every map claim must be probeable by the gate, and the probe must be one of
  # the surfaces that actually make the map. A claim whose probe is not in its
  # own created_by would be measuring some other surface's output.
  def test_every_map_claim_is_probeable
    CAP::MAPS.each do |m|
      assert_includes m[:created_by], m[:probe], "#{m[:id]}: the probe is not in its own created_by"
      case m[:probe_kind]
      when :builtin then assert_includes CAP.all_builtins, m[:probe], "#{m[:id]}: the probe is not advertised as a builtin"
      when :attach  then assert_includes CAP::ATTACH_KINDS.map { |a| a[:kind].to_s }, m[:probe]
      when :syntax  then assert G::MAP_SYNTAX_PROBES.key?(m[:probe].to_sym), "#{m[:id]}: no syntax probe defined"
      else flunk "#{m[:id]}: the gate cannot write a probe for probe_kind #{m[:probe_kind].inspect}"
      end
    end
  end

  # created_by is the whole point of the table -- "which surface makes this" --
  # so every name in it must be a surface the affordance actually publishes.
  def test_map_created_by_names_are_real_surfaces
    known = CAP.all_builtins + CAP::ATTACH_KINDS.map { |a| a[:kind].to_s } + G::MAP_SYNTAX_PROBES.keys.map(&:to_s)
    CAP::MAPS.each do |m|
      (m[:created_by] - known).each { |n| flunk "#{m[:id]}: created_by names #{n}, which is not an advertised surface" }
    end
  end

  # The four non-.maps forms create a map the emitted C does not describe, so the
  # gate can only check that the form is present. An entry may sit in that weaker
  # tier ONLY with a recorded kernel-side measurement -- the same rule the sugar
  # section puts on equiv: :compiles. Silent weakening is how a gate rots.
  def test_undeclared_map_forms_carry_a_measurement
    CAP::MAPS.reject { |m| m[:declared_as] == :maps }.each do |m|
      refute_nil m[:measured], "#{m[:id]}: declared_as=#{m[:declared_as]} but there is no `measured` (the kernel-side evidence)"
      assert_operator m[:measured].length, :>, 30, "#{m[:id]}: `measured` is too short"
    end
  end

  # Capacity and overflow behaviour are the load-bearing fields: they are what an
  # AI needs to decide whether a probe will quietly drop events.
  def test_every_map_states_its_role_and_what_happens_when_full
    CAP::MAPS.each do |m|
      refute_nil m[:role], "#{m[:id]}: no role"
      refute_nil m[:when_full], "#{m[:id]}: does not say what happens when it is full (capacity alone is not enough to decide)"
      refute_nil m[:type]
    end
  end

  def test_map_ids_and_names_are_unique
    assert_equal CAP::MAPS.size, CAP::MAPS.map { |m| m[:id] }.uniq.size
    assert_equal CAP::MAPS.size, CAP::MAPS.map { |m| m[:map] }.uniq.size
  end

  # Both directions again: withdrawn types are the record of what left with the
  # builtin and attach surfaces, and a type cannot be advertised and withdrawn at
  # once.
  def test_withdrawn_map_types_are_disjoint_and_documented
    refute_empty CAP::WITHDRAWN_MAPS
    assert_empty(CAP::MAPS.map { |m| m[:type] }.uniq & CAP::WITHDRAWN_MAPS.keys)
    CAP::WITHDRAWN_MAPS.each do |t, info|
      refute_nil info[:went_with], "#{t}: does not record which surface it left with"
      refute_nil info[:why]
    end
  end

  # ---------- the scanner ----------
  # It knows five map-creating forms. Four of them do not look like maps, and the
  # last two were found only by loading the objects, so each one gets a test:
  # a form the scanner forgets is a map nobody is told about.
  def test_scanner_finds_the_dot_maps_form_with_its_properties
    d = G.map_decls(<<~C).first
      struct {
          __uint(type, BPF_MAP_TYPE_HASH);
          __type(key, __u32);
          __type(value, __s64);
          __uint(max_entries, 4096);
      } u_thing SEC(".maps");
    C
    assert_equal ["u_thing", "HASH", :maps, "4096", "__u32", "__s64"],
                 [d.name, d.type, d.form, d.max_entries, d.key, d.value]
  end

  # `__uint(value_size, sizeof(struct bpf_cpumap_val))` -- a [^)]* capture would
  # truncate this into a plausible-looking lie.
  def test_scanner_balances_parentheses_in_attribute_arguments
    d = G.map_decls(<<~C).first
      struct {
          __uint(type, BPF_MAP_TYPE_CPUMAP);
          __uint(key_size, sizeof(__u32));
          __uint(value_size, sizeof(struct bpf_cpumap_val));
          __uint(max_entries, 64);
      } spnl_cpumap SEC(".maps");
    C
    assert_equal "sizeof(struct bpf_cpumap_val)", d.value_size
  end

  def test_scanner_finds_struct_ops_rodata_data_section_and_header_forms
    src = <<~C
      #include <bpf/usdt.bpf.h>
      #define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
      volatile const __s64 spnl_param_x = 0;
      private(A) struct bpf_spin_lock lk;
      SEC(".struct_ops.link")
      struct Qdisc_ops spnl_qdisc_ops = { .id = "spnl_qdisc" };
    C
    got = G.map_decls(src).map { |d| [d.name, d.form] }
    assert_includes got, ["spnl_qdisc_ops", :struct_ops]
    assert_includes got, [".rodata", :rodata]
    assert_includes got, [".data.A", :data_section]
    assert_includes got, ["__bpf_usdt_specs", :libbpf_header]
    assert_includes got, [".kconfig", :libbpf_header]
  end

  # The macro DEFINITION is not a use; counting it would invent a .data. map for
  # every program that includes the qdisc preamble.
  def test_scanner_ignores_the_macro_definition_line
    src = "#define private(name) SEC(\".data.\" #name) __hidden\n"
    assert_empty G.map_decls(src)
  end

  # A section form nobody taught the scanner is reported, not ignored: silence is
  # the failure this vocabulary had, so an unknown form must be loud.
  def test_scanner_reports_an_unknown_section_form
    d = G.map_decls("int zz SEC(\".weird_new_thing\") = 0;\n").first
    assert_equal :unknown, d.form
  end

  # `<unit>` is substituted, `<ivar>`/`<class>`/`<N>` are wildcards, everything
  # else must match literally -- otherwise a claim would cover maps it never saw.
  def test_map_name_patterns_match_only_what_they_mean
    assert_match G.map_name_re("<unit>_top_<ivar>"), "u_top_hits"
    refute_match G.map_name_re("<unit>_top_<ivar>"), "other_top_hits"
    assert_match G.map_name_re("bpf_mim_inner<N>"), "bpf_mim_inner3"
    refute_match G.map_name_re("bpf_mim_inner<N>"), "bpf_mim_innerX"
    assert_match G.map_name_re("spnl_flow_<unit>_conn"), "spnl_flow_u_conn"
  end

  # The three verdicts the gate acts on, without needing the codegen.
  def test_check_map_distinguishes_missing_mismatch_and_ok
    entry = { id: :t, map: "bpf_hist", type: "ARRAY", declared_as: :maps, max_entries: "64",
              key: "__u32", value: "__u64", created_by: %w[hist_observe], probe: "hist_observe" }
    good = G::MapDecl.new(name: "bpf_hist", type: "ARRAY", form: :maps, max_entries: "64",
                          key: "__u32", value: "__u64")
    assert_equal :ok, G.check_map(entry, [good]).first
    assert_equal :missing, G.check_map(entry, []).first
    assert_equal :mismatch, G.check_map(entry, [good.dup.tap { |d| d.max_entries = "32" }]).first
    assert_equal :other, G.check_map(entry, nil).first
  end

  # ---------- it must not pass vacuously ----------

  # A gate whose codegen is unavailable has to abort, not report success. This is
  # the failure mode tools/golden.rb hit (a wrong-platform binary turned every
  # fixture into a skip and still exited 0), and build/ is bind-mounted into the
  # container, so it is not hypothetical.
  def test_gate_aborts_when_the_codegen_is_missing
    out = `SPNL_INPROC_CC=/nonexistent/spinel-ebpf-cc ruby #{File.expand_path('../../tools/affordance_gate.rb', __dir__)} 2>&1`
    refute_predicate $?, :success?, "exited successfully with no codegen present"
    assert_match(/production codegen missing/, out)
  end
end
