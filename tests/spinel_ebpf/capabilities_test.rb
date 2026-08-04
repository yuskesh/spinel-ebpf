# frozen_string_literal: true
#
# Run: ruby -Isrc -Itests tests/spinel_ebpf/capabilities_test.rb
#
# Capability registry for the layer 1 (probe DSL builtin) surface, grouped by domain.
# Guards three things: the classification is exhaustive (governance), the d_path
# context gate has one central allowlist, and the introspection wiring stays connected.

require "minitest/autorun"
require "json"
require "ripper"
require "spinel_ebpf/capabilities"
require "spinel_ebpf/codegen_bpf"
require "spinel_ebpf/introspect"

class CapabilitiesTest < Minitest::Test
  CAP = SpinelEbpf::Capabilities
  GEN = SpinelEbpf::CodegenBpf
  I   = SpinelEbpf::Introspect

  # The authoritative set of all builtins is **what the affordance advertises**
  # (Capabilities itself).
  #
  # It used to be `GEN::BUILTIN_NAMES + GEN::DYNPTR_BUILTINS`, i.e. the list held by
  # the retired Ruby oracle codegen. That pinned the "exhaustive partition"
  # governance to a **dead implementation**: eighteen builtins that the production
  # C codegen does not have were still required to be classified, so taking them
  # out honestly was the thing that made this test fail.
  #
  # Authority moved to the affordance. The delta against the Ruby oracle is kept as
  # a fact by test_withdrawn_is_exactly_the_retired_oracle_delta -- history stays
  # connected, it just stops being the authority. Whether what is advertised
  # actually works is measured against the production codegen by
  # tools/affordance_gate.rb; this test runs in Ruby alone and cannot see that far.
  ALL_BUILTINS = CAP.all_builtins.freeze
  RETIRED_ORACLE_BUILTINS = (GEN::BUILTIN_NAMES + GEN::DYNPTR_BUILTINS).uniq.freeze

  # ---------- exhaustive partition (the core governance rule) ----------

  # Every builtin belongs to exactly one domain. Adding a new builtin without
  # classifying it fails this test -- the forcing function that keeps the
  # capability matrix current.
  def test_every_builtin_classified_exactly_once
    classified = CAP::DOMAINS.values.flat_map { |d| d[:builtins] }
    missing = ALL_BUILTINS - classified
    extra   = classified - ALL_BUILTINS
    assert_empty missing, "unclassified builtin (add it to capabilities.rb): #{missing.inspect}"
    assert_empty extra,   "classifies a builtin that does not exist: #{extra.inspect}"
    dups = classified.tally.select { |_, n| n > 1 }
    assert_empty dups, "builtin listed in more than one domain: #{dups.keys.inspect}"
    assert_equal ALL_BUILTINS.length, classified.length
    assert_equal ALL_BUILTINS.length, CAP.all_builtins.length
  end

  # The delta against the retired Ruby oracle is exactly the set that was taken out.
  #
  # Both directions matter, not just one: in the oracle but not in the affordance
  # means WITHDRAWN; in the affordance but not in the oracle means a builtin the C
  # codegen added, which is allowed to grow. If the first set drifts, something was
  # either removed or reinstated without saying so.
  def test_withdrawn_is_exactly_the_retired_oracle_delta
    lost = (RETIRED_ORACLE_BUILTINS - ALL_BUILTINS).sort
    assert_equal CAP::WITHDRAWN.keys.sort, lost,
                 "a builtin in the Ruby oracle but not in the affordance must be listed as " \
                 "WITHDRAWN (nothing disappears quietly, nothing comes back quietly)"
    assert_empty(CAP::WITHDRAWN.keys & ALL_BUILTINS,
                 "a name is both withdrawn and advertised (it has to be one or the other)")
    CAP::WITHDRAWN.each do |name, rec|
      assert rec[:why].is_a?(String) && rec[:why].length > 20, "#{name}: needs a reason it was taken out"
      assert rec[:ctx].is_a?(Symbol), "#{name}: needs the ctx a gate builds its minimal probe from"
      assert rec[:arity].is_a?(Integer), "#{name}: needs the arity it had"
    end
  end

  def test_domains_are_the_four_layer1_plus_core
    assert_equal %i[observability enforcement net l7 core], CAP::DOMAINS.keys
  end

  def test_domain_of_and_builtins_for
    assert_equal :observability, CAP.domain_of("hist_observe")
    assert_equal :enforcement,   CAP.domain_of("emit_path")
    assert_equal :net,           CAP.domain_of("pkt_l4_proto")
    assert_equal :l7,            CAP.domain_of("http_emit")
    assert_equal :core,          CAP.domain_of("cgroup_id")
    assert_nil   CAP.domain_of("definitely_not_a_builtin")
    assert_includes CAP.builtins_for(:l7), "ssl_req_start"
  end

  # ---------- one central context gate (a single authority) ----------

  # The registry's CONTEXT_GATES and the codegen (Ruby oracle) DPATH_OK_SECS must
  # name the same allowlist. Both refer to the same constant
  # (Capabilities::DPATH_OK_SECS).
  def test_dpath_gate_is_centralized_and_consistent
    # The three hooks this started from stay at the head of the list, so the code
    # generated for them is unchanged.
    assert_equal %w[lsm/file_open fmod_ret/security_file_open fmod_ret/security_file_permission],
                 CAP::DPATH_OK_SECS.first(3)
    # The allowlist widened by measurement, and it is now literally the keys of
    # DPATH_HOOKS (SEC -> which argument supplies the path).
    assert_equal CAP::DPATH_HOOKS.keys, CAP::DPATH_OK_SECS
    assert_includes CAP::DPATH_OK_SECS, "lsm/path_unlink"
    assert_includes CAP::DPATH_OK_SECS, "lsm/bprm_check_security"
    assert_includes CAP::DPATH_OK_SECS, "lsm/mmap_file"
    # The codegen oracle refers to the registry (the same object).
    assert_same CAP::DPATH_OK_SECS, GEN::MethodEmitter::DPATH_OK_SECS
    # All four d_path builtins are gated and share the same allowlist.
    %w[emit_path emit_parent_path path_eq parent_path_eq].each do |b|
      g = CAP.gate_for(b)
      refute_nil g, "#{b} is missing from the context gate"
      assert_equal :enforcement, g[:domain]
      assert_equal CAP::DPATH_OK_SECS, g[:valid_secs]
    end
    assert_nil CAP.gate_for("hist_observe"), "gate_for must be nil for an ungated builtin"
  end

  # The allowlist became a table of "SEC -> which argument carries the path". Pin
  # both that the table is well formed and that a hook measured to fail is never in
  # it -- nothing gets added by guessing.
  def test_dpath_hooks_table_is_well_formed_and_measured
    CAP::DPATH_HOOKS.each do |sec, spec|
      assert_includes %i[file path binprm], spec[:form], "#{sec}: unknown path-supplying form"
      assert_includes [true, false], spec[:guard], "#{sec}: guard must be true/false"
      refute_empty spec[:measured].to_s, "#{sec}: needs to say which measurement found it LOAD_OK"
      assert_match(%r{\A(lsm|fmod_ret|fentry|fexit)/}, sec, "#{sec}: malformed SEC")
    end
    # The three original hooks are file-form with no guard, which is what keeps the
    # code generated for them byte-identical to what it was.
    %w[lsm/file_open fmod_ret/security_file_open fmod_ret/security_file_permission].each do |sec|
      assert_equal :file, CAP::DPATH_HOOKS[sec][:form]
      refute CAP::DPATH_HOOKS[sec][:guard], "adding a guard to #{sec} would change its output"
    end
    # lsm/mmap_file's argument is file__nullable in BTF. Its guard is not
    # defensiveness, it is what makes the program load at all.
    assert CAP::DPATH_HOOKS["lsm/mmap_file"][:guard]
    assert_equal :path,   CAP::DPATH_HOOKS["lsm/path_unlink"][:form]
    assert_equal :binprm, CAP::DPATH_HOOKS["lsm/bprm_check_security"][:form]
    # The measured-rejected side does not intersect the allowlist.
    refute_empty CAP::DPATH_MEASURED_REJECTED
    CAP::DPATH_MEASURED_REJECTED.each do |sec, why|
      refute_includes CAP::DPATH_OK_SECS, sec, "#{sec} was measured REJECTED"
      refute_empty why.to_s, "#{sec}: keep the reason it failed (the verifier's own wording)"
    end
  end

  # The gate lives in two places -- the production C codegen and the Ruby registry.
  # Widening one alone gives "compiles under C, dies under the Ruby fallback", so
  # parse the table out of the C source and compare.
  def test_c_codegen_gate_table_matches_the_registry
    src = File.read(File.expand_path("../../src/codegen_c/spinel_ebpf_cc.c", __dir__))
    table = src[/static const CcDpathHook CC_DPATH_OK\[\] = \{(.*?)\n\};/m, 1]
    refute_nil table, "the C-side CC_DPATH_OK table is not there (did its shape change?)"
    c_hooks = table.scan(/\{\s*"([^"]+)",\s*CC_DP_(FILE|PATH|BINPRM),\s*([01])\s*,/)
                   .to_h { |sec, form, guard| [sec, { form: form.downcase.to_sym, guard: guard == "1" }] }
    assert_equal CAP::DPATH_HOOKS.keys, c_hooks.keys, "the gate's hook set differs between C and Ruby"
    c_hooks.each do |sec, spec|
      assert_equal CAP::DPATH_HOOKS[sec][:form],  spec[:form],  "#{sec}: the path-supplying form differs between C and Ruby"
      assert_equal CAP::DPATH_HOOKS[sec][:guard], spec[:guard], "#{sec}: the NULL guard differs between C and Ruby"
    end
  end

  def test_gated_builtins_are_all_enforcement_domain
    CAP::CONTEXT_GATES.each_key do |b|
      assert_equal :enforcement, CAP.domain_of(b), "#{b} should be in the enforcement domain"
    end
  end

  # ---------- agreement with the kubectl plugin probe catalog ----------

  def test_krew_probe_domains_align
    assert_equal %i[l7 enforcement l7 net],
                 %w[dns file l7 net].map { |p| CAP::KREW_PROBE_DOMAINS[p] }
    CAP::KREW_PROBE_DOMAINS.each_value do |dom|
      assert_includes CAP::DOMAINS.keys, dom, "the kubectl plugin catalog names unknown domain #{dom}"
    end
  end

  # ---------- introspection wiring (Introspect / catalog) ----------

  def test_domains_used_filters_to_present_names
    used = CAP.domains_used(%w[hist_observe emit_path pkt_len])
    assert_equal %i[observability enforcement net], used.keys
    assert_equal %w[emit_path], used[:enforcement]
  end

  def test_introspect_builtin_domains_scans_source
    src = <<~RUBY
      def lsm__file_open(file, ret)
        emit_path(file)          # enforcement
        hist_observe(latency_end) # observability + core-ish
      end
      def xdp__main
        @rx += 1 if pkt_l4_proto == IPPROTO_TCP
        XDP_PASS
      end
    RUBY
    doms = I.builtin_domains(src)
    assert_includes doms[:enforcement], "emit_path"
    assert_includes doms[:observability], "hist_observe"
    assert_includes doms[:net], "pkt_l4_proto"
  end

  # path_eq must NOT match inside parent_path_eq (lookbehind on `_`).
  def test_builtin_domains_word_boundary
    doms = I.builtin_domains("parent_path_eq(\"/x\")\n")
    assert_includes doms[:enforcement], "parent_path_eq"
    refute_includes(doms[:enforcement] || [], "path_eq")
  end

  def test_describe_report_shows_capability_domains
    src = "def kprobe__do_sys_openat2(dfd)\n  spnl_emit(dfd)\nend\n"
    r = I.report(src, "t.rb")
    assert_match(/capability domains:/, r)
    assert_match(/observability\s+spnl_emit/, r)
  end

  def test_catalog_report_lists_all_domains_and_gates
    r = CAP.catalog_report
    %i[observability enforcement net l7 core].each { |d| assert_match(/#{d}/, r) }
    assert_match(/context gates/, r)
    # Builtins that share an allowlist print as one group, and the hooks inside it
    # are grouped by which argument carries the path -- six builtins across thirty
    # hooks listed flat is unreadable.
    assert_match(%r{emit_path.*path_eq.*\n.*lsm/file_open}, r)
    assert_match(%r{argument is a struct path \*.*lsm/path_unlink}, r)
    assert_match(%r{tried and rejected.*\n.*lsm/file_permission}, r)
    assert_match(/--probe file\s+-> enforcement/, r)
  end

  # ================================================================
  # Machine-readable affordance: completeness plus codegen drift detection.
  # An AI author reads the affordance instead of the source, so it has to cover
  # every builtin and must not drift away from what codegen actually accepts.
  # ================================================================

  CODEGEN_SRC = File.expand_path("../../src/spinel_ebpf/codegen_bpf.rb", __dir__)
  PARTITION_SRC = File.expand_path("../../src/spinel_ebpf/partition.rb", __dir__)

  # (completeness) Every builtin has a signature entry; a new uncovered one fails here.
  def test_every_builtin_has_a_signature
    missing = ALL_BUILTINS - CAP::SIGNATURES.keys
    extra   = CAP::SIGNATURES.keys - ALL_BUILTINS
    assert_empty missing, "builtin with no registered signature: #{missing.inspect}"
    assert_empty extra,   "signature for a builtin that does not exist: #{extra.inspect}"
    assert_equal ALL_BUILTINS.length, CAP::SIGNATURES.length
  end

  # (completeness) --json is valid JSON and covers every builtin and attach kind.
  def test_affordance_json_is_valid_and_complete
    require "json"
    doc = JSON.parse(CAP.affordance_json)
    assert_equal "spinel-ebpf.affordance/1", doc["schema"]
    names = doc["builtins"].map { |b| b["name"] }
    assert_equal ALL_BUILTINS.sort, names.sort, "JSON builtins != all builtins (the affordance is incomplete)"
    # Required fields on every builtin entry.
    doc["builtins"].each do |b|
      assert b.key?("domain") && !b["domain"].nil?, "#{b['name']} has no domain"
      assert b.key?("arity"),          "#{b['name']} has no arity"
      assert b.key?("params"),         "#{b['name']} has no params"
      assert b.key?("opaque"),         "#{b['name']} has no opaque"
      assert b.key?("valid_contexts"), "#{b['name']} has no valid_contexts"
      # params is null only for opaque builtins -- an honest marker, not a hole.
      assert_nil b["params"], "params for opaque builtin #{b['name']} should be null" if b["opaque"]
      refute_nil b["params"], "non-opaque builtin #{b['name']} should carry params" unless b["opaque"]
    end
    assert_equal CAP.all_builtins.count { |x| CAP.signature_for(x)[:opaque] },
                 doc["summary"]["opaque_builtins"]
  end

  # (completeness) every attach kind fills in its how-to-write-it fields, and the
  # main kinds are present.
  #
  # The authority is **the affordance itself** (ATTACH_KINDS), not the retired Ruby
  # oracle's ATTACH_PATTERNS. This is the same shape the builtin side turned out to
  # have: the test used to demand that every kind in the oracle also be advertised,
  # which meant **taking the four measured-dead kinds out honestly made it fail**.
  # That is the structural reason a silent unported attach could survive for a year.
  # History stays connected -- the test below pins the delta against
  # WITHDRAWN_ATTACH.
  def test_attach_kinds_are_well_formed
    json_kinds = CAP::ATTACH_KINDS.map { |a| a[:kind] }
    assert_equal json_kinds.length, json_kinds.uniq.length, "duplicate attach kind"
    # Cover the main kinds -- the affordance is what shows an author which attach
    # points exist. timer is not among them: it was withdrawn (WITHDRAWN_ATTACH).
    %i[kprobe kretprobe tracepoint fentry fexit lsm fmod_ret uprobe uretprobe usdt
       xdp tc_ingress tc_egress sk_reuseport sk_msg sock_ops tcp_cc sched_ext qdisc
       cgroup_connect4 iter_task raw_tp perf_event].each do |k|
      assert_includes json_kinds, k, "main attach kind #{k} is missing from the affordance"
    end
    CAP::ATTACH_KINDS.each do |a|
      assert a[:method_prefix], "#{a[:kind]} has no method_prefix"
      assert a[:args_convention], "#{a[:kind]} has no args_convention"
      # Exactly one of the two promises. `sec:` is a program SEC; `emits:`
      # is a C symbol, for the one kind that emits no program at all (a
      # USER_RINGBUF callback). Writing "syscall" there would have been worse
      # than useless: that is the exact string a silently degraded attach kind
      # produces, so a SEC comparison would have been satisfied by the very
      # failure it exists to catch.
      assert a[:sec] || a[:emits],
             "#{a[:kind]} has neither sec nor emits (the affordance gate uses one as the expected value)"
      # Only a kind that declares `body: :discarded` may carry **both**. The
      # gate's second stage asks whether the body an author wrote reached the
      # output, and for a kind that throws the body away that question has no
      # answer -- so the affordance names what to look for instead, which is the
      # second use of `emits:`. Carrying both WITHOUT declaring the discard stays
      # forbidden: the gate would have no way to decide which one to read.
      if a[:sec] && a[:emits]
        assert_equal :discarded, a[:body],
                     "#{a[:kind]} claims both sec and emits but does not declare body: :discarded"
      end
      # And the other direction: a kind that says it discards the body has to
      # supply the thing to look for in its place.
      if a[:body] == :discarded
        assert a[:emits], "#{a[:kind]} declares body: :discarded but has no emits (the gate's second stage would have nothing to look for)"
        assert_match(/body/, a[:args_convention].to_s + a[:context_note].to_s,
                     "#{a[:kind]} discards the body without saying so to a human reader")
      end
    end
  end

  # The delta against the retired Ruby oracle is exactly WITHDRAWN_ATTACH. History
  # is not the authority, but it stays on the record -- and it can only move one
  # way: in the oracle and not advertised means withdrawn; the reverse does not
  # exist.
  def test_withdrawn_attach_is_exactly_the_retired_oracle_delta
    oracle = GEN::ATTACH_PATTERNS.map { |_re, kind| kind }.uniq
    advertised = CAP::ATTACH_KINDS.map { |a| a[:kind] }
    assert_equal CAP::WITHDRAWN_ATTACH.keys.sort, (oracle - advertised).sort,
                 "WITHDRAWN_ATTACH is not the set that is in the Ruby oracle and not in the affordance"
    assert_empty advertised - oracle,
                 "an attach kind is advertised that the oracle never had (if it is genuinely new, update this test)"
    assert_empty advertised & CAP::WITHDRAWN_ATTACH.keys,
                 "the same kind is both advertised and withdrawn"
  end

  # A withdrawn attach kind says **why** and **what to write instead**. Removing
  # one silently is not allowed -- the same contract the withdrawn builtins carry.
  #
  # Being non-empty is no longer required. Porting the demoted surfaces back
  # empties this set, so requiring otherwise would be pressure to **leave a lie in
  # the shipped affordance** just to keep the gate armed -- putting an invented
  # name into the artifact readers depend on, for the gate's convenience.
  # Detection power moved to the self-checks in tools/affordance_gate.rb (which
  # corrupt a live claim in memory) and to the correspondence with
  # CC_WITHDRAWN_ATTACH in the C generator.
  def test_withdrawn_attach_entries_carry_reason_and_alternative
    CAP::WITHDRAWN_ATTACH.each do |kind, w|
      assert w[:method_prefix], "#{kind}: no method_prefix"
      assert w[:probe], "#{kind}: no probe (a gate cannot write the minimal program without one)"
      assert w[:why] && w[:why].length > 40, "#{kind}: why is too short"
      assert w[:instead], "#{kind}: no instead (a withdrawal with no alternative is a dead end)"
    end
  end

  # (drift) SIGNATURES arity agrees with codegen (expects N / expect_no_args).
  # The codegen arity check is the single authority; if the affordance goes stale
  # this test fails.
  def test_signature_arity_matches_codegen
    src = File.read(CODEGEN_SRC)
    checked = 0
    # 0-arity: expect_no_args(node, "NAME")
    src.scan(/expect_no_args\(node, "([a-z_0-9]+)"\)/) do |(name)|
      next unless CAP::SIGNATURES.key?(name)
      assert_equal 0, CAP::SIGNATURES[name][:arity], "#{name}: codegen says 0-arity (expect_no_args)"
      checked += 1
    end
    # N-arity: "NAME expects N arg(s)" (an interpolated #{name} carries no digit, so it is skipped)
    src.scan(/"([a-z_0-9]+) expects (\d+) args?/) do |(name, n)|
      next unless CAP::SIGNATURES.key?(name)
      assert_equal n.to_i, CAP::SIGNATURES[name][:arity], "#{name}: codegen says #{n}-arity"
      checked += 1
    end
    assert_operator checked, :>=, 50, "too few arities scraped from codegen (the scan probably broke)"
  end

  # (drift) SIGNATURES param names agree with codegen's "expects (a, b, c)".
  def test_signature_params_match_codegen_named
    src = File.read(CODEGEN_SRC)
    checked = 0
    src.scan(/"([a-z_0-9]+) expects \(([a-z0-9_, ]+)\), got/) do |(name, plist)|
      next unless CAP::SIGNATURES.key?(name)
      params = plist.split(",").map(&:strip)
      assert_equal params, CAP::SIGNATURES[name][:params],
                   "#{name}: param names have drifted from codegen (codegen=#{params.inspect})"
      checked += 1
    end
    assert_operator checked, :>=, 15, "too few builtins with scraped param names"
  end

  # (honesty) opaque is only the scx_*/qdisc_* kfunc passthroughs (arity is still known).
  def test_opaque_builtins_are_kfunc_passthroughs_with_known_arity
    opaque = ALL_BUILTINS.select { |b| CAP.signature_for(b)[:opaque] }
    assert_equal CAP::OPAQUE_KFUNC_BUILTINS.sort, opaque.sort
    opaque.each do |b|
      assert_nil CAP.signature_for(b)[:params], "#{b}: opaque means params=nil"
      refute_nil CAP.signature_for(b)[:arity], "#{b}: arity should still be known"
      assert_match(/\A(scx|qdisc)_/, b)
    end
    # The opaque share stays small -- past that the affordance loses its value.
    assert_operator opaque.length.to_f / ALL_BUILTINS.length, :<, 0.10
  end

  # (context gate) valid_contexts for the d_path builtins is DPATH_OK_SECS.
  def test_context_gates_expose_valid_secs
    %w[emit_path emit_parent_path path_eq parent_path_eq].each do |b|
      assert_equal CAP::DPATH_OK_SECS, CAP.context_strings(b), "valid_contexts for #{b} is not the d_path allowlist"
      assert CAP.builtin_entry(b)[:gated], "#{b} should be gated"
    end
    # Attach-kind gates show up in valid_contexts too, so they are machine-readable.
    assert_equal %w[iter_task], CAP.context_strings("iter_task")
    assert_equal %w[tcp_cc], CAP.context_strings("tcp_sock_snd_cwnd")
    assert_equal %w[cgroup_connect4 cgroup_bind4], CAP.context_strings("sock_addr_ip4")
    # The packet-context gates show up there as well. The codegen had been dying on
    # these outside a packet program for a long time while the affordance still said
    # `gated: false` -- an understated constraint, drift in the opposite direction
    # from advertising something that does not exist.
    assert_equal %w[xdp tc_ingress tc_egress], CAP.context_strings("fib_lookup")
    assert_equal %w[tc_ingress tc_egress], CAP.context_strings("l4_offset")
    assert_equal %w[tc_ingress], CAP.context_strings("sk_assign_tcp")
    assert CAP.builtin_entry("l4_offset")[:gated]
    # An ungated builtin has valid_contexts=nil plus a best-effort note.
    assert_nil CAP.context_strings("hist_observe")
    refute CAP.builtin_entry("hist_observe")[:gated]
    refute_nil CAP.builtin_entry("hist_observe")[:context_note]
  end

  # The DNS builtins' context_note names the canonical hook (udp_*).
  # The l7 domain's generic "tcp_*/SSL_*" note misleads for DNS, so
  # CONTEXT_NOTE_OVERRIDES corrects it.
  def test_dns_builtins_context_note_names_udp_hooks
    { "dns_req_start" => "udp_sendmsg", "dns_resp_stash" => "udp_recvmsg",
      "dns_emit" => "udp_recvmsg", "emit_dns" => "udp_sendmsg" }.each do |b, hook|
      note = CAP.context_note(b)
      assert_includes note, hook, "context_note for #{b} does not name the canonical hook #{hook}"
      refute_includes note, "tcp_*", "context_note for #{b} still carries the misleading tcp_* (the override should have replaced it)"
      # It also shows through in builtin_entry, the shape the affordance publishes.
      assert_includes CAP.builtin_entry(b)[:context_note], hook
    end
    # The override is limited to the DNS family -- the l7 domain note (for http/ssl) keeps tcp_*/SSL_*.
    assert_includes CAP::DOMAIN_CONTEXT_NOTE[:l7], "tcp_*"
  end

  # The affordance has to teach that an LSM handler's non-deny branch returns the
  # prior verdict (the trailing param), not a literal 0. Steering to a literal 0
  # (= allow) does two things: it silently swallows a prior deny, and combined with
  # path_eq/emit_path it blows up verifier state (measured at the 1M instruction
  # limit). fmod_ret is unaffected -- its trailing param is ret.
  def test_lsm_attach_kind_guides_prior_verdict_not_literal_zero
    lsm = CAP::ATTACH_KINDS.find { |a| a[:kind] == :lsm }
    refute_nil lsm, "there is no lsm attach_kind"
    note = lsm[:context_note]
    assert_includes note, "prior verdict", "the lsm note does not say allow = return the prior verdict"
    refute_includes note, "0=allow", "the lsm note still carries the misleading '0=allow'"
    assert_includes note, "deny", "the lsm note is missing the deny convention"
  end

  # lsm/* enforcement is a silent no-op unless the kernel booted with lsm=...,bpf:
  # the attach succeeds but the hook never fires, the worst kind of silent failure.
  # So the affordance must (a) warn about that in the lsm note and point at
  # fmod_ret, and (b) state in the fmod_ret note that fmod_ret is a portable deny
  # that does not depend on boot flags.
  def test_enforcement_deny_warns_lsm_silent_noop_and_prefers_fmod_ret
    lsm = CAP::ATTACH_KINDS.find { |a| a[:kind] == :lsm }
    fmr = CAP::ATTACH_KINDS.find { |a| a[:kind] == :fmod_ret }
    refute_nil lsm; refute_nil fmr
    # lsm: the silent no-op hazard, the lsm=,bpf prerequisite, and the pointer to fmod_ret.
    assert_includes lsm[:context_note], "silent no-op", "the lsm note does not warn about the silent no-op"
    assert_includes lsm[:context_note], "lsm=", "the lsm note does not state the boot prerequisite (lsm=...,bpf)"
    assert_includes lsm[:context_note], "fmod_ret", "the lsm note does not point at the portable fmod_ret"
    # fmod_ret: says outright that portable means boot-independent.
    assert_includes fmr[:context_note], "portable", "the fmod_ret note does not say it is a portable deny"
  end

  # Over-reach guard: path_eq / parent_path_eq are described as use-neutral
  # predicates and are never framed around one particular use (deny only). An A/B
  # measurement showed that writing path_eq as a deny-specific tool hijacks the
  # model's choice of action on an ambiguous task -- it blocks where the task only
  # asked to audit. So the description states the builtin's type and contract (a
  # predicate) and leaves the use to the caller: a dictionary entry, not an
  # encyclopedia entry.
  def test_path_predicates_are_use_neutral_not_deny_framed
    %w[path_eq parent_path_eq].each do |b|
      e = CAP.builtin_entry(b)
      s = e[:summary].to_s
      assert_includes s, "predicate", "the #{b} summary does not say it is a predicate"
      assert_includes s, "use-neutral", "the #{b} summary does not say it is use-neutral"
      # Forbid framing that over-reaches into use = deny (never describe the
      # predicate as "deny only" / "in order to block").
      # Note: listing deny as one of several uses, as in "use-neutral:
      # deny/audit/routing", is neutral and fine. Only phrases that pin the builtin
      # to deny are forbidden.
      ["deny only", "in order to deny", "for denying", "in order to block", "in order to cut off", "blocking predicate"].each do |bad|
        refute_includes s, bad, "the #{b} summary contains deny-specific framing '#{bad}' (over-reach)"
      end
      # The example must not bake in an action either (no deny's -1) -- also use-neutral.
      refute_match(/-\s*1/, e[:example].to_s, "the #{b} example bakes in a deny action (-1) -- over-reach")
    end
  end

  # The IP set-membership builtins (blocklist_match / cidr_blocklist_match) are
  # described as use-neutral predicates too. The same map and builtin were reused
  # for an allowlist egress policy (match -> allow), which showed that blocklist
  # (match -> deny) and allowlist (match -> allow) differ only in the handler's
  # return value. So even though the name says "blocklist", the description does
  # not frame a use -- the same line drawn for the path predicates, applied to the
  # network domain.
  def test_ip_set_predicates_are_use_neutral
    %w[blocklist_match cidr_blocklist_match].each do |b|
      e = CAP.builtin_entry(b)
      s = e[:summary].to_s
      assert_includes s, "predicate", "the #{b} summary does not say it is a predicate"
      assert_includes s, "use-neutral", "the #{b} summary does not say it is use-neutral"
      assert_includes s, "allowlist", "the #{b} summary does not mention the allowlist use (blocklist-only framing)"
      # Surface the userspace FFI that seeds the set, so an authoring agent can
      # write a policy without reading example programs it is not allowed to see.
      # A re-run showed that an `ffi_func` fragment alone is not enough -- the agent
      # got the class/module choice and the argument types wrong (it used `class`
      # and the build failed) -- so require the complete invocation pattern: an
      # explicit `module`, the FFI name, and a call with an integer literal.
      assert_includes s, "ffi_func", "the #{b} summary does not show the userspace FFI that seeds the set"
      assert_includes s, "sp_bpf", "the #{b} summary does not name the FFI (sp_bpf_*)"
      assert_includes s, "module", "the #{b} summary does not say where to declare it -- a module, not a class"
    end
  end

  # The affordance shows a concrete example of the handler arity for the main
  # enforcement hook, fmod_ret/security_file_open, so an authoring agent does not
  # have to guess (file, ret) from fixtures it cannot read.
  def test_fmod_ret_surfaces_security_file_open_arity
    fmr = CAP::ATTACH_KINDS.find { |a| a[:kind] == :fmod_ret }
    refute_nil fmr
    assert_includes fmr[:args_convention], "security_file_open", "fmod_ret does not show the security_file_open example"
    assert_includes fmr[:args_convention], "(file, ret)", "fmod_ret does not show the (file, ret) arity"
  end

  # struct_ops (tcp_cc/sched_ext/qdisc) recommends the class-inheritance form.
  # Originally a flat `def <kind>__<member>` fell through to SEC("syscall") and was
  # never registered (every model iteration failed on it), so the affordance spells
  # out the class form and surfaces the qdisc required members and its
  # skb-reference constraint. Codegen later learned to register the flat form as
  # struct_ops as well, so the affordance recommends the class form while no longer
  # carrying the now-false warning that the flat form is not registered.
  def test_struct_ops_attach_kinds_guide_class_form
    %i[tcp_cc sched_ext qdisc].each do |k|
      a = CAP::ATTACH_KINDS.find { |x| x[:kind] == k }
      refute_nil a, "there is no #{k} attach_kind"
      blob = "#{a[:method_prefix]} #{a[:args_convention]} #{a[:context_note]}"
      assert_includes blob, "class", "#{k} does not show the class-inheritance form"
      assert_includes blob, "BPF::", "#{k} does not show the parent class (BPF::...)"
      refute_includes blob, "is not registered", "#{k} still carries the false failure warning about the flat form (the flat form registers too)"
    end
    # qdisc spells out the required members and the skb-reference release.
    q = CAP::ATTACH_KINDS.find { |x| x[:kind] == :qdisc }
    %w[enqueue dequeue init reset destroy].each do |m|
      assert_includes q[:args_convention], m, "qdisc does not show the required member #{m}"
    end
    assert_includes q[:args_convention], "skb", "qdisc does not show the skb-reference release constraint"
    assert_match(/qdisc_skb_drop|queue_push/, q[:args_convention], "qdisc does not name the builtin that releases the skb")
  end

  # (loud failure) The rejected list is non-empty and matches partition's impossible flags.
  def test_ruby_subset_rejected_matches_partition_flags
    refute_empty CAP::RUBY_SUBSET[:supported]
    refute_empty CAP::RUBY_SUBSET[:rejected]
    src = File.read(PARTITION_SRC)
    body = src[/def ebpf_impossible\?(.+?)end/m, 1]
    refute_nil body, "could not parse partition's ebpf_impossible?"
    partition_flags = body.scan(/uses_[a-z_]+|inherits_unsupported/).uniq.map(&:to_sym)
    # inherits_unsupported is derived (it propagates from other methods), so it is
    # not one of the directly rejected constructs.
    construct_flags = partition_flags - [:inherits_unsupported]
    rejected_flags = CAP::RUBY_SUBSET[:rejected].map { |r| r[:flag] }
    assert_equal construct_flags.sort, rejected_flags.sort,
                 "the rejected loud-failure list has drifted from partition's impossible flags"
    # Every rejected flag really exists (drift guard) and carries a human-readable reason.
    CAP::RUBY_SUBSET[:rejected].each do |r|
      assert_includes partition_flags, r[:flag], "#{r[:flag]} is not a flag partition has"
      assert r[:reason] && !r[:reason].empty?, "#{r[:flag]} has no reason"
    end
  end

  # (layer 2 reference) The enrichers state, machine-readably, that these
  # attributes get added without touching the probe.
  def test_enrichers_reference_present
    names = CAP::ENRICHERS.map { |e| e[:name] }
    assert_includes names, "k8s"
    assert_includes names, "peer"
    CAP::ENRICHERS.each do |e|
      assert_equal 2, e[:layer]
      refute_empty e[:attributes]
      assert e[:signal_scope]
    end
  end

  # Each affordance domain also shows up in the JSON, for discoverability.
  def test_affordance_domains_present
    doc = JSON.parse(CAP.affordance_json)
    %w[observability enforcement net l7 core].each do |d|
      assert doc["domains"].key?(d), "#{d} is missing from the JSON domains"
    end
  end

  # ================================================================
  # Call examples plus related builtins -- the two things an authoring agent most
  # often had to guess when it had only names and arities to work from.
  # ================================================================

  # (completeness) Every non-opaque builtin has an example; opaque ones have
  # example=nil. example.nil? iff opaque, so the omission is deliberate -- the same
  # honesty as params -- and not an accidental hole.
  def test_every_non_opaque_builtin_has_example
    ALL_BUILTINS.each do |b|
      opaque = CAP.signature_for(b)[:opaque]
      ex = CAP.example_for(b)
      if opaque
        assert_nil ex, "opaque builtin #{b} should have example=nil (omit rather than invent)"
      else
        refute_nil ex, "non-opaque builtin #{b} has no example"
        assert_kind_of String, ex
        assert ex.start_with?(b), "the #{b} example should start with the builtin name: #{ex.inspect}"
      end
    end
  end

  # (honesty) The builtins with no example are exactly the opaque kfuncs -- a deliberate list.
  def test_omitted_examples_are_exactly_opaque
    omitted = ALL_BUILTINS.select { |b| CAP.example_for(b).nil? }
    assert_equal CAP::OPAQUE_KFUNC_BUILTINS.sort, omitted.sort,
                 "only opaque kfuncs may omit an example"
  end

  # (correctness floor) Every example is a valid Ruby fragment -- parsed with
  # Ripper, so no example can be a lie.
  def test_examples_are_valid_ruby_syntax
    checked = 0
    ALL_BUILTINS.each do |b|
      ex = CAP.example_for(b)
      next if ex.nil?
      refute_nil Ripper.sexp(ex), "example is not valid Ruby: #{b} -> #{ex.inspect}"
      checked += 1
    end
    assert_operator checked, :>=, 140, "too few builtins with a parseable example"
  end

  # (generated form) arity 0 is bare, arity N is the name(params) form.
  def test_generated_examples_match_arity
    # arity 0 (empty params, non-opaque, no override) is a bare `name`.
    assert_equal "pid",           CAP.example_for("pid")
    assert_equal "latency_start", CAP.example_for("latency_start")
    assert_equal "emit_comm",     CAP.example_for("emit_comm")
    # arity N is a call with the params as placeholders.
    assert_equal "hist_observe_by(key, value)", CAP.example_for("hist_observe_by")
    assert_equal "spnl_emit(value)",            CAP.example_for("spnl_emit")
    assert_equal "emit_path(file)",             CAP.example_for("emit_path")
  end

  # (hand-written overrides) The special syntax for symbols, string literals and
  # struct names comes out right.
  def test_example_overrides_apply
    assert_equal "flow_get(:conn, :backend_ip)",           CAP.example_for("flow_get")
    assert_equal 'path_eq(file, "/usr/bin/curl")',         CAP.example_for("path_eq")
    assert_equal 'parent_path_eq("/usr/bin/curl")',        CAP.example_for("parent_path_eq")
    assert_equal 'kfield(sk, "sock", "sk_sndbuf")',        CAP.example_for("kfield")
    assert_equal 'path_starts_with(file, "/etc/secret/")',  CAP.example_for("path_starts_with")
    # An override always names a real, non-opaque builtin (drift guard).
    CAP::EXAMPLE_OVERRIDES.each_key do |b|
      assert_includes ALL_BUILTINS, b, "override #{b} is not an existing builtin"
      refute CAP.signature_for(b)[:opaque], "override #{b} is opaque"
    end
  end

  # (JSON completeness) Every builtin entry has example + related; opaque has example=null.
  def test_affordance_json_has_example_and_related
    doc = JSON.parse(CAP.affordance_json)
    doc["builtins"].each do |b|
      assert b.key?("example"), "#{b['name']} has no example key"
      assert b.key?("related"), "#{b['name']} has no related key"
      assert_kind_of Array, b["related"], "related for #{b['name']} must be an array"
      if b["opaque"]
        assert_nil b["example"], "example for opaque #{b['name']} should be null"
      else
        assert_kind_of String, b["example"], "non-opaque #{b['name']} should have an example"
      end
    end
    # builtin_groups shows up in the JSON too, for discoverability.
    assert doc.key?("builtin_groups"), "builtin_groups is missing from the JSON"
    assert_equal CAP::BUILTIN_GROUPS.length, doc["builtin_groups"].length
  end

  # (consistency) Group members are real builtins, no duplicates within a group,
  # group names are unique, and every group has a note.
  def test_builtin_groups_well_formed
    refute_empty CAP::BUILTIN_GROUPS
    names = CAP::BUILTIN_GROUPS.map { |g| g[:name] }
    assert_equal names.length, names.uniq.length, "duplicate group name"
    CAP::BUILTIN_GROUPS.each do |g|
      assert g[:note] && !g[:note].empty?, "#{g[:name]} has no note"
      assert_operator g[:members].length, :>=, 2, "#{g[:name]} needs at least 2 members for 'related' to mean anything"
      assert_equal g[:members].length, g[:members].uniq.length, "duplicate member within #{g[:name]}"
      g[:members].each do |m|
        assert_includes ALL_BUILTINS, m, "member #{m} of #{g[:name]} is not an existing builtin"
      end
    end
  end

  # (derivation) related is derived from BUILTIN_GROUPS -- a single authority.
  def test_related_is_derived_from_groups
    # A group member has the other members of its group as related.
    assert_equal %w[tgid tid], CAP.related_for("pid")
    assert_equal %w[latency_end], CAP.related_for("latency_start")
    assert_includes CAP.related_for("hist_observe"), "hist_observe_by"
    # A builtin that is in no group has related=[].
    assert_equal [], CAP.related_for("cgroup_id")
    assert_equal [], CAP.related_for("divu")
    # related is symmetric (a in related_for(b) <=> b in related_for(a)).
    CAP::BUILTIN_GROUPS.each do |g|
      g[:members].combination(2).each do |a, b|
        assert_includes CAP.related_for(a), b
        assert_includes CAP.related_for(b), a
      end
    end
  end

  # pid/tgid/tid are packed into one kernel value; the affordance has to say so,
  # because an author who does not know that picks the wrong grouping key.
  def test_pid_tgid_tid_group_states_granularity
    grp = CAP::BUILTIN_GROUPS.find { |g| g[:name] == "process_thread_identity" }
    refute_nil grp, "there is no process_thread_identity group"
    assert_equal %w[pid tgid tid], grp[:members]
    # The note says which one is process granularity -- a fact needed to choose,
    # not logic.
    assert_match(/process granularity/, grp[:note])
    assert_match(/thread granularity/, grp[:note])
  end

  # (human-readable) The catalog has a builtin groups section, with call examples and notes.
  def test_catalog_report_shows_builtin_groups
    r = CAP.catalog_report
    assert_match(/builtin groups/, r)
    assert_match(/process_thread_identity/, r)
    assert_match(/hist_observe_by\(key, value\)/, r) # the call example shows up
    assert_match(/process granularity/, r)           # the relationship note shows up
  end

  # ===================================================================
  # The packed-record contract surface.
  #
  # What these guard is that THE RUBY SIDE KEEPS NO CONTRACT OF ITS OWN. The JSON is
  # generated from src/codegen_c/record_schema.h and the offsets come from the
  # generator (layout()). Each test below catches a different desync:
  #   (a) the table was edited but the JSON not regenerated -> compare names/types
  #   (b) the two generated artifacts come from different runs -> compare against
  #       the mirror header's enum
  #   (c) the runtime wrote an attribute key by hand -> check for hard-coded literals
  # ===================================================================

  SCHEMA_TABLE_SRC = File.expand_path("../../src/codegen_c/record_schema.h", __dir__)
  MIRROR_GEN_SRC   = File.expand_path("../../src/runtime/otlp/record_mirror_gen.h", __dir__)
  OTLP_AGENT_SRC   = File.expand_path("../../src/runtime/otlp/otlp_agent.c", __dir__)

  # The declared channels. Every channel is declared in the table, not just DNS, so
  # this doubles as a pin on which ones are present.
  DECLARED_CHANNELS = %w[dns conn l7 http redis offcpu l7stream].freeze

  def test_record_channels_load_from_the_generated_artifact
    chans = CAP.record_channels
    assert_equal DECLARED_CHANNELS, chans.map { |c| c[:id] },
                 "the set of declared channels changed (cc_rec_all in record_schema.h)"
    dns = CAP.record_channel("dns")
    refute_nil dns, "there is no dns channel"
    assert_equal "<unit>_dns_event", dns[:record_struct]
    assert_equal "<unit>_dns_events", dns[:ringbuf_map]
    assert_equal 120, dns[:record_bytes]
    assert_equal %w[emit_dns dns_emit], dns[:producers]
    # Every channel has a record struct, a ringbuf map and a producer -- the minimum contract
    chans.each do |c|
      assert_equal "<unit>_#{c[:id]}_event", c[:record_struct], "#{c[:id]}: struct naming convention"
      assert_equal "<unit>_#{c[:id]}_events", c[:ringbuf_map], "#{c[:id]}: map naming convention"
      refute_empty Array(c[:producers]), "#{c[:id]}: no producer"
      assert_operator c[:record_bytes], :>, 0, "#{c[:id]}: record_bytes"
      assert_operator c[:record_min_bytes], :<=, c[:record_bytes], "#{c[:id]}: min <= size"
    end
  end

  # (a) The generated JSON and the declaration table (record_schema.h) agree on
  # fields. Offsets are deliberately NOT compared here: Ruby must not carry its own
  # alignment rules, which would re-create the very second contract this design
  # removes. Names, types and counts only.
  def test_record_json_fields_match_the_declaration_table
    src = File.read(SCHEMA_TABLE_SRC)
    DECLARED_CHANNELS.each do |id|
      body = src[/cc_rec_#{id}_fields\[\]\s*=\s*\{(.*?)\n\};/m, 1]
      refute_nil body, "cannot read cc_rec_#{id}_fields from record_schema.h"
      declared = body.scan(/\{\s*"([^"]+)",\s*"([^"]+)",\s*(\d+),\s*(\d+),\s*(\d+),/)
                     .map { |n, t, c, _s, _a| [n, t, c.to_i] }
      from_json = CAP.record_channel(id)[:fields].map { |f| [f[:name], f[:ctype], f[:count]] }
      assert_equal declared, from_json,
                   "#{id}: record_schema.h and record_schema_gen.json have drifted (make -C src/codegen_c mirror)"
    end
  end

  # (b) The two generated artifacts -- the JSON Ruby reads and the header the
  # runtime reads -- come from the same generation. The header's enum holds exactly
  # the offsets the generator computed.
  def test_record_json_offsets_match_the_generated_mirror_header
    hdr = File.read(MIRROR_GEN_SRC)
    DECLARED_CHANNELS.each do |id|
      up = id.upcase
      CAP.record_channel(id)[:fields].each do |f|
        macro = "SPNL_REC_#{up}_OFF_#{f[:name].upcase}"
        m = hdr[/#{Regexp.escape(macro)}\s*=\s*(\d+)/, 1]
        refute_nil m, "#{macro} is missing from the mirror header"
        assert_equal f[:offset], m.to_i, "the offset of #{id}.#{f[:name]} differs between JSON and header"
      end
      assert_equal CAP.record_channel(id)[:record_bytes],
                   hdr[/SPNL_REC_#{up}_SIZE\s*=\s*(\d+)/, 1].to_i, "#{id}: SIZE"
      assert_equal CAP.record_channel(id)[:record_min_bytes],
                   hdr[/SPNL_REC_#{up}_MIN\s*=\s*(\d+)/, 1].to_i, "#{id}: MIN (append-only read)"
    end
  end

  # --- metrics, and the cardinality facts the surface must carry -------------

  def test_metrics_are_published_with_their_series_bound
    ms = CAP.record_metrics
    refute_empty ms, "not one metric is published"
    ms.each do |m|
      assert_includes %w[counter histogram], m[:kind]
      refute_empty m[:name].to_s
      refute_empty m[:unit].to_s
      assert_operator m[:series_bound].to_i, :>, 0,
                      "#{m[:name]}: no bound on the number of series means the cost is unreadable"
    end
  end

  def test_every_metric_label_says_where_its_bound_comes_from
    # "bound 3" on its own does not say whether the 3 is the result of a **declared
    # coarsening** (values outside the set fold into a fallback, and only the span
    # keeps the exact one) or of a set that was closed to begin with. Without that,
    # the first sign of coarsening is `_OTHER` appearing on a dashboard.
    CAP.record_metrics.each do |m|
      Array(m[:labels]).each do |l|
        assert_includes %w[declared_set value_map], l[:bound_from],
                        "#{m[:name]} / #{l[:key]}: the bound does not say where it comes from"
        assert_operator l[:bound].to_i, :>, 0
        if l[:bound_from] == "declared_set"
          refute_empty l[:fallback].to_s, "#{l[:key]}: nothing outside the set has anywhere to go"
          assert_equal Array(l[:values]).length + 1, l[:bound]
        end
      end
    end
  end

  def test_capabilities_json_carries_the_cardinality_ceiling
    j = JSON.parse(CAP.affordance_json, symbolize_names: true)
    assert_operator j[:summary][:record_metric_count], :>, 0
    assert_equal CAP.record_metrics.sum { |m| m[:series_bound].to_i },
                 j[:summary][:record_metric_series_bound]
    refute_empty Array(j[:record_bounds_sets]), "the histogram bucket boundaries are not published"
  end

  def test_metric_report_shows_the_bound_and_the_coarsening
    r = CAP.record_channels_report
    assert_includes r, "metrics:"
    assert_includes r, "series <="
    assert_match(/the span keeps the exact value/, r,
                 "the human-readable surface does not say that a coarsening is happening")
  end

  def test_metric_value_and_labels_are_consumer_properties
    CAP.record_metrics.each do |m|
      props = Array(CAP.record_properties(m[:channel])).map { |p| p[:name].to_s }
      Array(m[:labels]).each { |l| assert_includes props, l[:from].to_s }
      next if m[:value_from].to_s.empty?
      assert_includes props, m[:value_from].to_s
    end
  end

  def test_record_producers_are_registered_builtins
    prods = CAP.record_producers
    assert_equal %w[dns_emit emit_connect emit_dns emit_l7 emit_tcp_payload emit_tcp_stream
                    http_emit offcpu_emit redis_emit ssl_emit], prods
    (prods - ALL_BUILTINS).tap { |x| assert_empty x, "unregistered builtin used as a producer: #{x.inspect}" }
    assert_equal "dns", CAP.record_channel_for("emit_dns")[:id]
    assert_equal "dns", CAP.record_channel_for("dns_emit")[:id]
    assert_nil CAP.record_channel_for("hist_observe"), "a scalar emit has no record channel"
  end

  # (c) The declaration table is the source of truth for attribute keys. The
  # runtime is a CONSUMER of the generated macros, not their author. This covers
  # every channel that declares an egress: it names that channel's "turn one record
  # into a span" function and requires that (1) every declared key exists as a
  # generated macro, (2) the function uses the macro, and (3) no hard-coded copy of
  # the same key is left behind.
  # (3) is the important one: a single hard-coded key lets the declaration and the
  # wire format diverge silently.
  CHANNEL_CONSUMER_FNS = {
    "dns"    => %w[dns_fill_span otlp_tree_fill_dns],
    # conn was factored into a builder too (the short-form push now just calls conn_fill_span)
    "conn"   => %w[conn_fill_span otlp_tree_fill_conn],
    # l7/http were factored into the same "one record -> one span" builder as dns,
    # so the short-form push and the typed consumer's `to_span` go through one place.
    "l7"     => %w[l7_fill_span],
    "http"   => %w[http_fill_span],
    "redis"  => %w[spnl_otlp_redis_span_push_obj],
    "offcpu" => %w[spnl_otlp_offcpu_span_push_obj spnl_otlp_request_tree_push_obj],
  }.freeze

  # Extract a function body: from a definition line at column 0 to the `}` at column 0.
  def consumer_fn_text(src, names)
    names.map do |n|
      m = src[/^[a-z ]*int #{Regexp.escape(n)}\(.*?\n\}\n/m]
      refute_nil m, "#{n}() not found in the runtime (was it renamed?)"
      m
    end.join("\n")
  end

  def test_egress_keys_are_generated_macros_the_runtime_consumes
    hdr = File.read(MIRROR_GEN_SRC)
    src = File.read(OTLP_AGENT_SRC)
    checked = 0
    CAP.record_channels.each do |c|
      e = c[:egress]
      next unless e
      id  = c[:id]
      up  = id.upcase
      fns = consumer_fn_text(src, CHANNEL_CONSUMER_FNS.fetch(id))
      e[:attributes].each do |a|
        macro = "SPNL_EGRESS_#{up}_ATTR_#{a[:key].upcase.gsub(/[^A-Z0-9]/, '_')}"
        assert_match(/#define\s+#{Regexp.escape(macro)}\s+"#{Regexp.escape(a[:key])}"/, hdr,
                     "#{macro} is missing from the generated header")
        assert_includes fns, macro, "the #{id} consumer does not use #{macro}"
        refute_match(/"#{Regexp.escape(a[:key])}"/, fns,
                     "the #{id} consumer still hard-codes #{a[:key]} (the declaration stops being the source of truth)")
        checked += 1
      end
      # The span name goes the same route (fmt is a macro; the JSON carries the readable {arg} form).
      fmt_macro = "SPNL_EGRESS_#{up}_SPAN_NAME_FMT"
      assert_match(/#define\s+#{Regexp.escape(fmt_macro)}\s+"/, hdr, "#{fmt_macro} is missing")
      assert_includes fns, fmt_macro, "the #{id} consumer does not use the span-name macro"
    end
    total = CAP.record_channels.sum { |c| Array(c.dig(:egress, :attributes)).length }
    assert_equal total, checked, "some channel that declares an egress escaped the check"
    assert_operator checked, :>=, 39, "too few attribute keys checked (did a channel drop out?)"
    # Keep the concrete DNS shape as a pin
    assert_equal %w[dns.question.name process.executable.name spnl.dns.latency_ns],
                 CAP.record_channel("dns")[:egress][:attributes].map { |a| a[:key] }
    assert_equal "resolve {dns.question.name}", CAP.record_channel("dns")[:egress][:span_name]
    assert_equal "connect {network.peer.address}:{network.peer.port}",
                 CAP.record_channel("conn")[:egress][:span_name]
  end

  # The typed consumer is OPT-IN PER CHANNEL. A channel that is merely declared
  # must not change what `on_emit :<id>` means -- it stays a plain named event.
  # The list grew as each channel became expressible: l7 and http, then conn (its
  # destination `ev.peer` needs a derivation that sees the whole record, which took
  # a third impl_form, record_to_str), then offcpu (three of its egress attributes
  # CANNOT be exposed as raw fields -- a clamp for spnl.offcpu_ns, a computed value
  # for spnl.oncpu_ns, and a kallsyms classification that lives outside the record
  # for spnl.wait.kind -- so only after making those derivations does "the value
  # Ruby sees == the value on the span" hold).
  # redis / l7stream stay declaration-only, so `on_emit :redis` is still a plain
  # named event.
  # This list is A PIN ON INTENT, not something derived -- before adding to it, ask
  # whether `on_emit :<id>` in an existing program would change meaning.
  TYPED_CHANNELS = %w[dns conn l7 http offcpu].freeze

  def test_typed_consumer_is_opt_in_per_channel
    assert_equal TYPED_CHANNELS, CAP.typed_record_channel_ids,
                 "the set of channels publishing a typed consumer changed"
    CAP.record_channels.each do |c|
      next if TYPED_CHANNELS.include?(c[:id])
      assert_nil c[:consumer],
                 "#{c[:id]} publishes a consumer contract -- `on_emit :#{c[:id]}` changes meaning"
    end
  end

  # ===================================================================
  # The typed consumer contract. Guards that the set of `ev.<prop>` comes from the
  # declaration, that the generated accessors really exist, and that the runtime
  # provides what the generated block requires. Miss any one of those and the type
  # Ruby sees drifts away from the thing itself.
  # ===================================================================

  def test_record_consumer_contract_is_published
    cons = CAP.record_channel("dns")[:consumer]
    refute_nil cons, "the consumer contract is missing from the JSON (make -C src/codegen_c mirror)"
    assert_equal "on_emit :dns do |ev| ... end", cons[:form]
    assert_equal "spnl_rec_dns_drain",   cons[:drain_fn]
    assert_equal "spnl_rec_dns_to_span", cons[:to_span_fn]
    assert_equal "spnl_otlp_span_send",  cons[:send_fn]
    assert_equal "spnl_otlp_span_flush", cons[:flush_fn]
    assert_equal %w[pid comm cgid duration_ns qname], CAP.record_properties("dns").map { |p| p[:name] }
    # Every opted-in channel has the same shape (form and *_fn derive from the id;
    # send/flush are channel-independent).
    TYPED_CHANNELS.each do |id|
      c = CAP.record_channel(id)[:consumer]
      refute_nil c, "the consumer contract for #{id} is missing from the JSON"
      assert_equal "on_emit :#{id} do |ev| ... end", c[:form]
      assert_equal "spnl_rec_#{id}_drain",   c[:drain_fn]
      assert_equal "spnl_rec_#{id}_to_span", c[:to_span_fn]
      assert_equal "spnl_otlp_span_send",    c[:send_fn]   # sending is channel-independent (one batch)
      assert_equal "spnl_otlp_span_flush",   c[:flush_fn]
      refute_empty CAP.record_properties(id)
    end
    # For HTTP the L7 decision material (method/path/status) surfaces as derived properties.
    assert_equal %w[pid comm dport duration_ns cgid method path status],
                 CAP.record_properties("http").map { |p| p[:name] }
    assert_equal "int", CAP.record_properties("http").find { |p| p[:name] == "status" }[:expose]
  end

  # The declaration is the source of truth for what is exposed (the expose column
  # in record_schema.h plus the derived table). If the JSON drifts from it, the type
  # Ruby sees and the declaration disagree.
  # This covers every opted-in channel, not just dns.
  def test_record_consumer_properties_match_the_declaration_table
    src = File.read(SCHEMA_TABLE_SRC)
    TYPED_CHANNELS.each do |id|
      body = src[/cc_rec_#{id}_fields\[\]\s*=\s*\{(.*?)\n\};/m, 1]
      refute_nil body, "cannot read cc_rec_#{id}_fields from record_schema.h"
      # `{ name, ctype, count, size, align, note, expose[, kfilter] }` -- the
      # trailing kfilter column is optional, so the row shape here is "note,
      # expose, and possibly one more literal".
      declared_fields = body.scan(/\{\s*"([^"]+)",.*?,\s*(?:"(?:[^"\\]|\\.)*"|NULL)\s*,\s*(NULL|"int"|"str")\s*(?:,\s*(?:NULL|"[^"]*")\s*)?\}/m)
                            .reject { |_n, e| e == "NULL" }.map { |n, e| [n, e.delete('"')] }
      dbody = src[/cc_rec_#{id}_derived\[\]\s*=\s*\{(.*?)\n\};/m, 1]
      declared_derived = dbody ? dbody.scan(/\{\s*"([^"]+)",\s*"([^"]+)",/).map { |n, e| [n, e] } : []

      props = CAP.record_properties(id)
      assert_equal declared_fields,
                   props.select { |p| p[:kind] == "field" }.map { |p| [p[:name], p[:expose]] },
                   "#{id}: the exposed fields drifted from the declaration table"
      assert_equal declared_derived,
                   props.select { |p| p[:kind] == "derived" }.map { |p| [p[:name], p[:expose]] },
                   "#{id}: the derived properties drifted from the declaration table"
    end
  end

  # Every declared property has a generated accessor that really exists WITH THE
  # RIGHT C TYPE (:long -> long, :str -> const char *). If it disagreed with the
  # extern declaration spinel emits, the C would not compile at all, so this
  # correspondence is the foundation of the harness.
  def test_record_consumer_accessors_are_generated_with_matching_types
    hdr = File.read(MIRROR_GEN_SRC)
    TYPED_CHANNELS.each do |id|
      CAP.record_properties(id).each do |p|
        ctype = { "int" => "long", "str" => "const char *" }.fetch(p[:expose])
        assert_match(/#{Regexp.escape(ctype)}\s*#{Regexp.escape(p[:ffi])}\(int i\)/, hdr,
                     "no generated accessor for #{p[:ffi]}, or its C type is not #{ctype}")
        assert_equal({ "int" => ":long", "str" => ":str" }.fetch(p[:expose]), p[:ffi_ret])
      end
    end
    assert_match(/#ifdef SPNL_REC_CONSUME_IMPL/, hdr, "the accessors are not confined to a single translation unit")
  end

  # Does the runtime actually define the functions the generated block requires
  # (record lookup plus each declared derivation)? A missing one is a link error, so
  # it does not break silently, but this catches "declared it and nobody implemented
  # it" before it can be committed.
  # There are four derivation calling conventions -- the four cells of two axes
  # (what you pass in x what you get back): bytes_to_str, bytes_to_int,
  # record_to_str (takes the whole record, for a derivation a single field cannot
  # express) and record_to_int. This checks the C SIGNATURE matches the declared
  # impl_form.
  DERIV_PROTO = { "bytes_to_str"  => /^void %s\(const unsigned char \*/,
                  "bytes_to_int"  => /^long %s\(const unsigned char \*/,
                  "record_to_str" => /^void %s\(const spnl_rec_[a-z0-9]+_t \*/,
                  "record_to_int" => /^long %s\(const spnl_rec_[a-z0-9]+_t \*/ }.freeze

  # The fifth form, code_to_name, is **different in kind** from the four above: what
  # its impl column names is not a runtime function but a declared value map, and
  # the lookup is generated. So the thing to look in is the generated header rather
  # than the agent -- and the check also has to establish that the runtime does NOT
  # carry one of its own, because two tables mean the declared one and the one
  # actually consulted can be different tables, which is precisely the failure this
  # layer exists to remove.
  DERIV_GENERATED = { "code_to_name" => "static inline void spnl_valmap_%s(long v, char *out, int cap)" }.freeze

  def test_runtime_provides_what_the_generated_consumer_requires
    agent = File.read(OTLP_AGENT_SRC)
    src   = File.read(SCHEMA_TABLE_SRC)
    assert_includes agent, "#define SPNL_REC_CONSUME_IMPL"
    assert_match(/int spnl_otlp_span_send\(int handle, const char \*endpoint\)/, agent)
    assert_match(/int spnl_otlp_span_flush\(void\)/, agent)
    TYPED_CHANNELS.each do |id|
      assert_match(/const spnl_rec_#{id}_t \*spnl_rec_#{id}_at\(int i\)\s*\{/, agent)
      assert_match(/int spnl_rec_#{id}_drain_obj\(/, agent)
      assert_match(/int spnl_rec_#{id}_to_span\(int i\)/, agent)
      # The implementation of each declared derivation (the function in the impl
      # column) is non-static and has the type of the declared form
      dbody = src[/cc_rec_#{id}_derived\[\]\s*=\s*\{(.*?)\n\};/m, 1]
      next unless dbody
      dbody.scan(/\{\s*"[^"]+",\s*"[^"]+",\s*"[^"]+",\s*"([^"]+)",\s*"([^"]+)"/).each do |impl, form|
        if (gen = DERIV_GENERATED[form])
          hdr = File.read(MIRROR_GEN_SRC)
          assert_includes hdr, format(gen, impl),
                          "the lookup for value map #{impl} (#{form}) is not in the generated header"
          refute_match(/^\s*(static\s+)?\w[\w \*]*\bspnl_valmap_#{Regexp.escape(impl)}\s*\(/, agent,
                       "the runtime carries a hand-written copy of value map #{impl} (two tables)")
          next
        end
        pat = DERIV_PROTO.fetch(form) { flunk "unknown impl_form #{form} (the generator should have died)" }
        assert_match(Regexp.new(format(pat.source, Regexp.escape(impl))), agent,
                     "derivation #{impl} (#{form}) has no implementation in the runtime, or its signature differs")
      end
    end
  end

  # The short form and the explicit form go through THE SAME span builder -- the
  # structural guarantee behind "strip the sugar and you get the explicit form".
  # If either started building a span of its own, the attributes could quietly
  # diverge. The constraint applies to each channel as it is added.
  def test_both_consumer_forms_share_one_span_builder
    agent = File.read(OTLP_AGENT_SRC)
    TYPED_CHANNELS.each do |id|
      assert_match(/static int #{id}_fill_span\(/, agent, "#{id}: no shared builder")
      ["spnl_otlp_#{id}_span_push_obj", "spnl_rec_#{id}_to_span"].each do |fn|
        body = agent[/^(?:static )?(?:int|const char \*) #{Regexp.escape(fn)}\(.*?\n\}\n/m]
        refute_nil body, "cannot read #{fn}"
        assert_includes body, "#{id}_fill_span", "#{fn} does not go through the shared builder"
      end
    end
  end

  # The value Ruby reads and the value that lands on the span are OUTPUT OF THE SAME
  # FUNCTION. http's method/path/status are the impls of the derived declarations,
  # and the span builder calls those same impls -- if the two started parsing
  # separately, `ev.status` and http.response.status_code could quietly drift apart.
  def test_derived_property_and_span_attribute_share_one_parser
    agent = File.read(OTLP_AGENT_SRC)
    src   = File.read(SCHEMA_TABLE_SRC)
    dbody = src[/cc_rec_http_derived\[\]\s*=\s*\{(.*?)\n\};/m, 1]
    impls = dbody.scan(/\{\s*"[^"]+",\s*"[^"]+",\s*"[^"]+",\s*"([^"]+)"/).flatten
    assert_equal %w[spnl_http_method spnl_http_path spnl_http_status], impls
    builder = agent[/static int http_fill_span\(.*?\n\}\n/m]
    refute_nil builder
    impls.each { |i| assert_includes builder, "#{i}(", "the span builder does not go through derivation #{i}" }
  end

  # conn's two derivations look at THE WHOLE RECORD (record_to_str). The same "one
  # shared output" property, pinned in the shape conn takes:
  #   - `ev.direction` is OUTPUT OF THE SAME FUNCTION as the span attribute
  #     spnl.conn.direction (the builder calls it)
  #   - `ev.peer` is "<address>:<port>", and its address part goes through THE SAME
  #     address formatter that builds network.peer.address (the port part is the
  #     same dport). The span name, declared as "connect %s:%u", puts those same two
  #     values side by side, so it is the identical string to ev.peer.
  #   - the v4/v6 choice exists in exactly one place in the agent (two places could
  #     drift silently)
  def test_conn_derivations_share_one_renderer_with_the_span
    agent   = File.read(OTLP_AGENT_SRC)
    builder = agent[/static int conn_fill_span\(.*?\n\}\n/m]
    peer    = agent[/^void spnl_conn_peer\(.*?\n\}\n/m]
    refute_nil builder, "cannot read conn_fill_span()"
    refute_nil peer,    "cannot read spnl_conn_peer()"
    # The mapping behind `direction` went from a hand-written switch to a **declared
    # value map**. The invariant worth holding is unchanged (the span builder goes
    # through the same implementation as ev.direction), but the implementation's
    # name is derived from the declaration -- a test that hard-codes it would end up
    # demanding the old implementation the moment the declaration moves.
    dir_prop = SpinelEbpf::Capabilities.record_properties("conn").find { |p| p[:name] == "direction" }
    refute_nil dir_prop, "conn has no ev.direction"
    assert_equal "conn_direction", dir_prop[:value_map],
                 "ev.direction does not come from a value map"
    assert_includes builder, "spnl_valmap_#{dir_prop[:value_map]}(",
                    "the span does not go through ev.direction's impl (the generated value map)"
    assert_includes peer,    "conn_peer_addr(",      "ev.peer formats the address on its own"
    assert_includes builder, "conn_peer_addr(",      "the span formats the address on its own"
    assert_equal 1, agent.scan(/inet_ntop\(AF_INET6/).length,
                 "IPv6 formatting appears in more than one place (the v4/v6 choice belongs in exactly one)"
  end

  # OUTPUT CAPACITY IS PART OF A DERIVATION'S CONTRACT. Even with the same function,
  # passing a different cap makes a long value truncate at a different point
  # (measured: on a 64-byte HTTP head with no whitespace, `ev.method` came out 64
  # characters while the span attribute was 15 -- reachable, because the
  # kernel-side filter spnl_is_http_req only looks at the first 4 bytes).
  #
  # So the capacity is declared PER DERIVATION. With one shared constant the number
  # is nobody's bound -- just whatever the generator happened to use. Two invariants
  # are pinned here:
  #   (1) every str derivation has its own cap macro and the accessor uses it (no
  #       numeric literals)
  #   (2) the buffer a runtime call passes is declared with THAT derivation's cap
  #       macro (borrowing another derivation's cap is wrong too -- the width stops
  #       being that function's bound)
  def test_derived_string_capacity_has_one_author
    hdr   = File.read(MIRROR_GEN_SRC)
    agent = File.read(OTLP_AGENT_SRC)
    src   = File.read(SCHEMA_TABLE_SRC)
    refute_match(/SPNL_REC_DERIVED_STR_CAP/, hdr,
                 "a shared cap constant is still present (the cap is declared per derivation)")
    assert_equal 0, hdr.scan(/static char buf\[\d+\]/).length,
                 "an accessor carries a numeric literal width (breaking the one-declaration rule)"
    # Collect the declared str derivations as (channel, name, impl).
    derived = TYPED_CHANNELS.flat_map { |id|
      body = src[/cc_rec_#{id}_derived\[\]\s*=\s*\{(.*?)\n\};/m, 1] || ""
      body.scan(/\{\s*"([^"]+)",\s*"str",\s*"[^"]+",\s*"([^"]+)"/).map { |name, impl|
        [id, name, impl, "SPNL_REC_DERIVED_#{id.upcase}_#{name.upcase}_CAP"]
      }
    }
    assert_equal 10, derived.length,
                 "the number of str derivations changed (expected: qname/peer/direction/conn.tcp_state/" \
                 "http.method/http.path/offcpu.method/offcpu.path/offcpu.wait_kind/offcpu.wait_stack_trace)"
    caps = {}
    derived.each do |id, name, _impl, macro|
      m = hdr[/^#define #{macro}\s+(\d+)$/, 1]
      refute_nil m, "#{macro} is missing from the generated header (no declared output capacity for #{id}.#{name})"
      caps[macro] = m.to_i
      assert_includes hdr, "static char buf[#{macro}];",
                      "the accessor spnl_rec_#{id}_#{name}() does not use #{macro}"
    end
    # A cap should be at least "the longest value it can return + NUL". Only the
    # weak form is pinned here (positive, and fits the attribute value buffer
    # otlp_kv_t.val) -- the real bound is checked by the _Static_assert on the C
    # side and by tests/runtime/run_record_span_parity.sh, which feeds inputs as
    # wide as the source allows.
    val_cap = File.read(File.expand_path("../../src/runtime/otlp/otlp_http.h", __dir__))[
      /char val\[(\d+)\]/, 1].to_i
    assert_operator val_cap, :>, 0
    caps.each { |macro, n|
      assert_operator n, :>, 1, "#{macro} is not a capacity"
      assert_operator n, :<=, val_cap, "#{macro} does not fit the attribute value buffer (#{val_cap}B)"
    }
    # TWO CHANNELS CAN SHARE ONE IMPL (offcpu's method/path are literally http's
    # derivations). Each channel declaring its own bound is still right -- a cap is
    # that derivation's bound, not a shared constant -- but if different widths get
    # passed to the shared function, the "same function, different width" bug comes
    # back. So:
    #   (a) caps that point at the same impl must have THE SAME VALUE (paired with
    #       the _Static_assert on the C side)
    #   (b) the caller's buffer is declared with one of that impl's cap macros
    #       (which are therefore equal)
    by_impl = derived.group_by { |_id, _name, impl, _macro| impl }
    by_impl.each do |impl, group|
      values = group.map { |_id, _n, _i, macro| caps[macro] }.uniq
      assert_equal 1, values.length,
                   "channels sharing #{impl}() declare different caps " \
                   "(#{group.map { |id, n, _i, m| "#{id}.#{n}=#{m}(#{caps[m]})" }.join(' / ')})"
    end
    # Scan function by function, since a local buffer of the same name can exist in
    # another function. offcpu shares http's derivations, so it is covered by the
    # same check.
    seen = 0
    agent.split(/^\}$/).each do |body|
      widths = {}   # pick up the second declarator too, as in `char a[N] = {0}, b[M];`
      body = body.gsub(%r{/\*.*?\*/}m, "")   # do not pick up "method[16]" inside a comment
      body.scan(/\bchar\s+([^;]+);/) do |decl|
        Array(decl).first.split(",").each do |d|
          widths[$1] = $2 if d =~ /(\w+)\s*\[\s*([^\]]+?)\s*\]/
        end
      end
      by_impl.each do |impl, group|
        macros = group.map { |_id, _n, _i, macro| macro }
        names  = group.map { |id, n, _i, _m| "#{id}.#{n}" }
        body.scan(/#{Regexp.escape(impl)}\(\s*[^;]*?,\s*(\w+),\s*(?:\(int\))?sizeof \1/).flatten.each do |buf|
          seen += 1
          assert_includes macros, widths[buf],
                          "#{impl}() is passed #{buf} of width #{widths[buf].inspect} " \
                          "(the accessor uses #{macros.join(' / ')} = the declared capacity of " \
                          "ev.#{names.join(' / ev.')} -- a long value would truncate differently)"
        end
      end
    end
    assert_operator seen, :>=, 6,
                    "found no derivation calls in the span builder at all (the check is a no-op)"
  end

  # A SECOND CONSUMER OF THE SAME RECORD SHAPE USES THE SAME DERIVATIONS.
  # The offcpu channel reads req[64]/resp[16] exactly the way http does. There used
  # to be a copy of the HTTP head parser in otlp_agent.c where (a) the width was
  # stale (method[16] against the declared cap) and (b) the path start was computed
  # from the strlen of the already-truncated method -- so THE SAME HEAD could yield
  # different values on the http span and on the offcpu span. To keep that copy from
  # coming back, pin that low-level HTTP head scanning happens only inside the
  # declared derivations.
  # offcpu's short-form push goes through the shared builder (offcpu_fill_span), so
  # there are two places to check for "goes through the derivation": the builder and
  # the request tree.
  def test_http_head_is_parsed_only_by_the_declared_derivations
    agent = File.read(OTLP_AGENT_SRC).gsub(%r{/\*.*?\*/}m, "")
    owners = %w[spnl_http_method spnl_http_path spnl_http_status]
    # Only the declared derivations (plus its own definition) may call the low-level
    # scanner http_token(). A call from anywhere else means a second parser has grown.
    agent.split(/^\}$/).each do |body|
      fn = body[/^(?:static\s+)?\w[\w \*]*?\b(\w+)\(/m, 1]
      next unless body.include?("http_token(")
      next if owners.include?(fn) || fn == "http_token"
      flunk "#{fn}() calls http_token() directly (HTTP head parsing belongs only " \
            "inside the declared derivations #{owners.join(' / ')})"
    end
    # Both offcpu span paths go through the derivations: the push (now via the
    # shared builder) and the request tree that nests child spans.
    { "offcpu_fill_span"                => /^static int offcpu_fill_span\(.*?\n\}\n/m,
      "spnl_otlp_request_tree_push_obj" => /^int spnl_otlp_request_tree_push_obj\(.*?\n\}\n/m }.each do |fn, re|
      body = agent[re]
      refute_nil body, "cannot read #{fn}()"
      owners.each { |i| assert_includes body, "#{i}(", "#{fn}() does not go through derivation #{i}" }
    end
  end

  # offcpu's three own derivations -- the ones where EXPOSING THE RAW FIELD WOULD
  # DISAGREE WITH THE SPAN. What is pinned here is a structure in which they cannot
  # disagree:
  #   - the clamp (min(offcpu_ns, duration_ns)) exists in exactly one place in the
  #     agent, inside spnl_offcpu_offcpu_ns (two places and `ev.offcpu_ns` could
  #     quietly drift from spnl.offcpu_ns -- the same shape as the srtt shift below)
  #   - oncpu is the difference of the CLAMPED value (= the attribute
  #     spnl.oncpu_ns), not a difference of raw fields
  #   - the wait.kind classification lives in one function in the agent
  #     (_oc_wait_kind), and both the span and ev reach it through the declared
  #     derivation spnl_offcpu_wait_kind
  def test_offcpu_derivations_have_one_author
    agent = File.read(OTLP_AGENT_SRC)
    bare  = agent.gsub(%r{/\*.*?\*/}m, "")
    clamp = bare.scan(/offcpu_ns\s*>\s*[\w>-]*duration_ns/)
    assert_equal 1, clamp.length,
                 "the off-CPU clamp appears in #{clamp.length} places (ev.offcpu_ns and spnl.offcpu_ns could drift)"
    impl = bare[/^long spnl_offcpu_offcpu_ns\(const spnl_rec_offcpu_t \*r\).*?\n\}\n/m]
    refute_nil impl, "spnl_offcpu_offcpu_ns() does not have the declared C signature"
    assert_match(/offcpu_ns\s*>\s*r->duration_ns/, impl, "the clamp is not inside the derivation")
    on = bare[/^long spnl_offcpu_oncpu_ns\(const spnl_rec_offcpu_t \*r\).*?\n\}\n/m]
    refute_nil on, "spnl_offcpu_oncpu_ns() does not have the declared C signature"
    assert_includes on, "spnl_offcpu_offcpu_ns(", "oncpu subtracts the raw field instead of the clamped value"
    # One classifier, and one door to it (the derivation).
    assert_equal 1, bare.scan(/^static const char \*_oc_wait_kind\(/).length
    kind = bare[/^void spnl_offcpu_wait_kind\(const spnl_rec_offcpu_t \*r.*?\n\}\n/m]
    refute_nil kind, "spnl_offcpu_wait_kind() does not have the declared C signature"
    assert_includes kind, "_oc_wait_kind(", "the derivation does not go through the classifier"
    # The span side (the builder shared by the short and explicit forms) and the
    # child span in the request tree go through the same derivations.
    builder = bare[/^static int offcpu_fill_span\(.*?\n\}\n/m]
    %w[spnl_offcpu_offcpu_ns( spnl_offcpu_oncpu_ns( spnl_offcpu_wait_kind(].each do |i|
      assert_includes builder, i, "the span builder does not go through derivation #{i}"
    end
    tree = bare[/^int spnl_otlp_request_tree_push_obj\(.*?\n\}\n/m]
    %w[spnl_offcpu_offcpu_ns( spnl_offcpu_oncpu_ns( spnl_offcpu_wait_kind(].each do |i|
      assert_includes tree, i, "the request tree computes it on its own (#{i} not used)"
    end
    # Declaration side: all three are derived, not raw exposed fields.
    props = CAP.record_properties("offcpu")
    %w[offcpu_ns oncpu_ns wait_kind].each do |n|
      p = props.find { |x| x[:name] == n }
      refute_nil p, "ev.#{n} is missing"
      assert_equal "derived", p[:kind], "ev.#{n} is a raw exposed field"
    end
    # Raw fields that Ruby could not act on stay unexposed (deliberate minimalism).
    %w[wait_stack start_ktime hdr_ext req resp].each do |n|
      assert_nil props.find { |x| x[:name] == n }, "ev.#{n} became public, against the minimalism intent"
    end
  end

  # **The frames and the kind are two readings of ONE fetch.**
  #
  # This pins the structure that keeps the failure removed for values from being
  # rebuilt for stacks. Write a second frame walk next to the classifier and the two
  # readings can disagree **about which stack they read** -- the lookup is against a
  # live BPF map, so reading it twice gives two moments. Hence:
  #   - fetching the frames (_oc_frames) is one function in the whole agent,
  #   - classification (_oc_classify) and rendering (_oc_render) both take its output,
  #   - the span builder and the child "wait" span both go through the declared
  #     derivation,
  #   - the depth limit (SPNL_STACK_FRAMES) is read from one place only (two places
  #     and ev and the span can carry a different number of frames -- the depth
  #     version of the output-capacity problem).
  def test_offcpu_wait_stack_shares_one_frame_fetch
    agent = File.read(OTLP_AGENT_SRC)
    bare  = agent.gsub(%r{/\*.*?\*/}m, "")
    assert_equal 1, bare.scan(/^static int _oc_frames\(/).length,
                 "the frame fetch is not one function (kind and frames could read different stacks)"
    kind = bare[/^static const char \*_oc_wait_kind\(.*?\n\}\n/m]
    refute_nil kind, "cannot read _oc_wait_kind()"
    assert_includes kind, "_oc_frames(", "the classifier does not go through the shared frame fetch"
    stack = bare[/^void spnl_offcpu_wait_stack\(const spnl_rec_offcpu_t \*r.*?\n\}\n/m]
    refute_nil stack, "spnl_offcpu_wait_stack() does not have the C signature it declares"
    assert_includes stack, "_oc_frames(", "the rendering side does not go through the shared frame fetch"
    assert_includes stack, "_oc_render(", "the rendering does not go through the shared renderer"
    # The depth limit is read in exactly one place (inside _oc_render).
    assert_equal 1, bare.scan(/getenv\("SPNL_STACK_FRAMES"\)/).length,
                 "SPNL_STACK_FRAMES is read in more than one place (ev and the span could differ in depth)"
    # The parent span (shared builder) and the child wait span both go through the
    # declared derivation.
    builder = bare[/^static int offcpu_fill_span\(.*?\n\}\n/m]
    assert_includes builder, "spnl_offcpu_wait_stack(", "the span builder does not go through the derivation"
    push = bare[/^int spnl_otlp_offcpu_span_push_obj\(.*?\n\}\n/m]
    assert_includes push, "spnl_offcpu_wait_stack(",
                    "the child wait span builds its frames by a different route than the parent"
    # The declaration side: it is derived, and the raw stack id stays unexposed.
    props = CAP.record_properties("offcpu")
    p = props.find { |x| x[:name] == "wait_stack_trace" }
    refute_nil p, "ev.wait_stack_trace is missing"
    assert_equal "derived", p[:kind]
    assert_nil props.find { |x| x[:name] == "wait_stack" },
               "the stack id (an index into a map) became public"
    # egress: the attribute is declared as a sibling of spnl.wait.kind, and its
    # condition says it is opt-in.
    attrs = CAP.record_channels.find { |c| c[:id] == "offcpu" }[:egress][:attributes]
    st = attrs.find { |a| a[:key] == "spnl.wait.stack" }
    refute_nil st, "spnl.wait.stack is not in the egress declaration"
    assert_match(/SPNL_STACK_FRAMES/, st[:condition],
                 "the condition does not say it is opt-in (so it reads as emitted by default)")
    refute_nil attrs.find { |a| a[:key] == "spnl.wait.kind" }, "its sibling spnl.wait.kind is gone"
  end

  # UNITS ARE PART OF "output of the same function" TOO. On the wire srtt is the
  # kernel's 1/8-microsecond value while the span carries microseconds, so exposing
  # the field raw would make `ev.srtt_us` alone differ from the span attribute.
  # Making it a derivation lets three things be pinned:
  #   - the span builder (short form plus the explicit to_span) goes through the
  #     derivation's impl
  #   - the request tree -- the second consumer, which turns the same record into a
  #     child span -- goes through that same impl
  #   - `>> 3` EXISTS IN EXACTLY ONE PLACE in the agent (two and it could drift)
  # The third is the real one: one place that divides means one unit, checked
  # mechanically.
  def test_conn_srtt_scaling_has_one_author
    agent = File.read(OTLP_AGENT_SRC)
    impl  = agent[/^long spnl_conn_srtt_us\(const spnl_rec_conn_t \*r\).*?\n\}\n/m]
    refute_nil impl, "spnl_conn_srtt_us() does not have the declared C signature"
    assert_match(/srtt_us\s*>>\s*3/, impl, "the derivation does not convert 1/8 us -> us")
    assert_equal 1, agent.scan(/srtt_us\s*>>\s*3/).length,
                 "the srtt unit conversion appears in more than one place (ev.srtt_us and the span attribute could drift)"
    builder = agent[/static int conn_fill_span\(.*?\n\}\n/m]
    assert_includes builder, "spnl_conn_srtt_us(", "the span does not go through the impl behind ev.srtt_us"
    tree = agent[/static int otlp_tree_fill_conn\(.*?\n\}\n/m]
    refute_nil tree, "cannot read otlp_tree_fill_conn()"
    assert_includes tree, "spnl_conn_srtt_us(", "the child span converts on its own"
    # Declaration side: srtt_us is derived (not a raw exposed field) and an Integer
    p = CAP.record_properties("conn").find { |x| x[:name] == "srtt_us" }
    refute_nil p, "ev.srtt_us disappeared (existing consumers break)"
    assert_equal "derived", p[:kind]
    assert_equal "int",     p[:expose]
    assert_equal "spnl_rec_conn_srtt_us", p[:ffi], "the FFI symbol stays the same as in the field form"
    assert_match(/MICROSECONDS/, p[:note], "the unit is not written into the contract")
  end

  # An egress push_fn is the userspace_export companion in the required-set rule:
  # the same counterpart is named in two places, so the two must agree.
  def test_egress_push_fn_matches_required_set_companion
    rule = CAP::REQUIRED_SETS.find { |r| r[:name] == "dns_span" }
    refute_nil rule
    assert_equal rule[:userspace_export][:fn], CAP.record_channel("dns")[:egress][:push_fn]
  end

  # Layer 2 enrichers are applied by the environment, not by the channel, so a
  # channel only names them by id. Every named id must exist in the ENRICHERS registry.
  def test_egress_enrichers_reference_registry_entries
    known = CAP::ENRICHERS.map { |e| e[:name] }
    CAP.record_channels.each do |c|
      Array(c.dig(:egress, :enrichers)).each do |id|
        assert_includes known, id, "unknown enricher id: #{id}"
      end
    end
  end

  # The record contract rides in the affordance JSON (additive only -- the existing
  # schema is unchanged).
  def test_affordance_json_carries_record_schema
    require "json"
    doc = JSON.parse(CAP.affordance_json)
    assert_equal "spinel-ebpf.affordance/1", doc["schema"], "the existing schema name is unchanged"
    assert_equal DECLARED_CHANNELS.length, doc["summary"]["record_channel_count"]
    dns = doc["record_channels"].find { |c| c["id"] == "dns" }
    refute_nil dns, "record_channels is missing from the affordance"
    assert_equal 120, dns["record_bytes"]
    e = doc["builtins"].find { |b| b["name"] == "emit_dns" }
    assert_equal "dns", e["record_channel"]
    assert_equal %w[hdr pid comm raw cgid duration_ns], e["record_schema"]["fields"].map { |f| f["name"] }
    assert_equal "spnl_otlp_dns_span_push", e["record_schema"]["egress"]["push_fn"]
    # A builtin that writes no record gets null -- do not invent a contract.
    assert_nil doc["builtins"].find { |b| b["name"] == "hist_observe" }["record_channel"]
  end

  # Surface sugar is published as a **machine-readable equivalence claim**. While it
  # lived only in the Ruby-subset prose, `pkt.l4.proto` was advertised for a year
  # although the production codegen did not have it (measured) -- prose does not
  # define anything for a checker to check.
  def test_affordance_json_carries_surface_sugar_claims
    require "json"
    doc = JSON.parse(CAP.affordance_json)
    sugar = doc["surface_sugar"]
    refute_nil sugar, "surface_sugar is missing from the affordance"
    assert_equal CAP.surface_sugar.size, sugar.size

    chain = sugar.find { |s| s["sugar"] == "pkt.l4.proto" }
    refute_nil chain, "the pkt.* chain is not listed -- the very surface measured dead"
    assert_equal "pkt_l4_proto", chain["flat"]
    assert_equal "identical", chain["equiv"], "the claim for the chain form is byte-identical output"

    # "a spelling that has an equivalent" is the invariant over every entry, which
    # is the shape a gate can act on.
    sugar.each do |s|
      refute_nil s["sugar"]; refute_nil s["flat"]
      assert_includes %w[identical compiles], s["equiv"], "#{s['id']}: equiv is unclear"
    end

    # `pkt.byte_at(off)` is the chain's only one-argument member, and its flat
    # name is not `pkt_byte_at`, so it is not covered by the derivation rule
    # above. It was withdrawn once and ported back, so **that it is back** is
    # measured explicitly.
    ba = sugar.find { |s| s["sugar"] == "pkt.byte_at(14)" }
    refute_nil ba, "pkt.byte_at is not among the sugar claims (it is a surface that was ported back)"
    assert_equal "pkt_dynptr_byte_at(14)", ba["flat"]
    assert_equal "identical", ba["equiv"]
    assert_includes CAP.all_builtins, "pkt_dynptr_byte_at",
                    "the chain side came back but the flat side is not advertised"

    # Withdrawn spellings are published too: nothing disappears silently, the
    # same convention the withdrawn builtins and attach kinds follow.
    #
    # **The non-empty requirement was dropped.** It rested on the same assumption
    # as the gate's old abort -- that the withdrawn set doubles as the negative
    # control -- and that assumption was separated out precisely because it made
    # fixing things weaken the gate (detection power now belongs to synthesised
    # self-checks). The last entry has since been ported back, so **empty is the
    # correct answer here**. What is left is the shape: an entry that exists
    # carries `instead`, and an entry that came back is gone.
    wd = doc["withdrawn_sugar"]
    refute_nil wd, "withdrawn_sugar is missing from the affordance"
    refute wd.key?("pkt.byte_at(0)"), "pkt.byte_at was ported back, so it must not remain in the withdrawn record"
    refute wd.key?("on :user_cmd do |cmd| ... end"),
           "on :user_cmd was ported back, so it must not remain in the withdrawn record"
    wd.each_value { |v| refute_nil v["instead"] }
  end

  # The `to_span` resolution rule is published MACHINE-READABLY, the same way the
  # emit_path context gate is. If a model cannot read "why it failed and how to
  # write it instead" out of the affordance, a loud error is no better than a syntax
  # error with no line number.
  def test_consumer_dsl_surface_publishes_the_to_span_resolution_rule
    require "json"
    doc = JSON.parse(CAP.affordance_json)
    dsl = doc["consumer_dsl"]
    refute_nil dsl, "consumer_dsl is missing from the affordance"
    assert_equal TYPED_CHANNELS, dsl["typed_channels"]
    verbs = dsl["verbs"].to_h { |v| [v["name"], v] }
    assert_equal %w[on_emit :<channel>].join(" "), verbs.keys.first   # first in the vocabulary = the entry point
    ts = verbs.fetch("to_span")
    assert_match(/on_emit :<channel>/, ts["context_note"], "the resolution scope is not written down")
    assert_match(/compile error/, ts["context_note"], "the consequence of failing to resolve is not written down")
    assert_match(/<channel>_span/, ts["context_note"], "the escape hatch is not pointed out")
    # State outright that there is no API for adding to a span's contents from Ruby
    assert_match(/the egress declaration decides what it contains/, ts["gotcha"])
    assert_match(/escape hatch, not the usual way/, verbs.fetch("<channel>_span")["context_note"])
    # The "forgot to drain" bug class stays in consume_records' context note
    assert_match(/Without it the handler never runs/, verbs.fetch("consume_records")["context_note"])
    # The same content shows up on the human-readable side
    r = CAP.catalog_report
    assert_match(/userspace consumer DSL/, r)
    assert_match(/typed channels .*: dns, conn, l7, http/, r)
  end

  # ---------- the map vocabulary ----------

  # What this project ships to an author is the affordance. With not one word about
  # maps in it, a model could not read that writing `@x += 1` brings a map into
  # being, or that a ring buffer drops records silently when it overflows -- which
  # is how the affordance stood until this section existed. Pin that it is in the
  # JSON.
  def test_affordance_json_carries_the_map_vocabulary
    a = JSON.parse(CAP.affordance_json)
    maps = a.fetch("maps")
    refute_empty maps
    assert_equal maps.size, a["summary"]["map_count"]
    assert_equal maps.map { |m| m["type"] }.uniq.size, a["summary"]["map_type_count"]
    # One entry = "which surface creates which map, in what shape"
    hist = maps.find { |m| m["id"] == "hist" }
    assert_equal "bpf_hist", hist["map"]
    assert_equal "ARRAY", hist["type"]
    assert_equal "64", hist["max_entries"]
    assert_includes hist["created_by"], "hist_observe"
    # Capacity alone is not enough to judge by; what happens when it fills up is the
    # substance
    maps.each { |m| refute_nil m["when_full"], "#{m['id']}: does not say what happens when full" }
    # The ring buffer's "drops silently" is written with the measurement behind it
    rb = maps.find { |m| m["id"] == "dns_events" }
    assert_equal "RINGBUF", rb["type"]
    assert_match(/lost/, rb["when_full"])
    # per-CPU is unreadable unless it also says "userspace sums them"
    lost = maps.find { |m| m["id"] == "ringbuf_lost" }
    assert_equal true, lost["per_cpu"]
    assert_match(/per-CPU/, lost["note"])
    # `withdrawn_maps` is now **empty**, because the map types came back with the
    # surfaces that create them. The old non-empty assertion treated the withdrawn
    # inventory as a negative control, and that assumption has been dropped, so
    # what is required here is only that the key is published.
    wm = a.fetch("withdrawn_maps")
    refute_nil wm, "withdrawn_maps is missing from the affordance"
    refute wm.key?("USER_RINGBUF"), "USER_RINGBUF was ported back, so it must not remain in the withdrawn record"
  end

  # The four forms that never appear in `SEC(".maps")` -- struct_ops, .rodata,
  # private(A) and the libbpf headers -- are listed too. Leaving them out would ship
  # the same misreading a text scanner makes first: "no declaration means no map".
  def test_affordance_covers_maps_that_are_not_declared_as_maps
    forms = CAP::MAPS.group_by { |m| m[:declared_as] }
    %i[maps struct_ops rodata data_section libbpf_header].each do |f|
      refute_nil forms[f], "no entry with declared_as: #{f}"
    end
    assert_equal %w[param filter_by], forms[:rodata].first[:created_by]
    # Writing one usdt handler adds three maps (nothing declares them in the emitted C)
    assert_equal 3, forms[:libbpf_header].size
    forms[:libbpf_header].each { |m| assert_equal %w[usdt], m[:created_by] }
  end

  # "the set of builtins this probe uses -> the maps that come into being" is
  # queryable, which is the interface describe needs.
  def test_maps_created_by_resolves_surfaces_to_maps
    ids = CAP.maps_created_by(%w[emit_dns]).map { |m| m[:id] }
    assert_includes ids, :dns_events
    assert_includes ids, :ringbuf_lost, "an emit builtin also creates the lost counter"
    assert_empty CAP.maps_created_by(%w[pid])
  end

  # (human-readable) The catalog has a maps section.
  def test_catalog_report_shows_maps
    r = CAP.catalog_report
    assert_match(/maps \(what writing a surface creates/, r)
    assert_match(/bpf_hist\s+ARRAY\s+max_entries=64/, r)
    assert_match(/\[struct_ops\]/, r)
    assert_match(/when full: /, r)
  end

  # (human-readable) The catalog has a record channel section (byte layout + egress).
  def test_catalog_report_shows_record_channels
    r = CAP.catalog_report
    assert_match(/record channels/, r)
    assert_match(/<unit>_dns_event \(120 B\)/, r)
    assert_match(/@112\s+duration_ns/, r)
    assert_match(/egress: spnl_otlp_dns_span_push -> span "resolve \{dns\.question\.name\}"/, r)
    assert_match(/spnl\.dns\.latency_ns\s+spinel/, r)
  end
end
