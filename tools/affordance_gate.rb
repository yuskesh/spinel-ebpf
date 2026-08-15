#!/usr/bin/env ruby
# frozen_string_literal: true
#
# affordance_gate.rb -- one invariant over five vocabularies: builtins, attach
# kinds, surface sugar, syntax and maps. Everything the affordance advertises must
# actually work in the production codegen, and -- since the map section was
# added -- everything the production codegen creates must actually be advertised.
#
#   ruby tools/affordance_gate.rb            # exit 1 on any problem
#   ruby tools/affordance_gate.rb --list     # show the plan without compiling
#   ruby tools/affordance_gate.rb --only NAME
#   ruby tools/affordance_gate.rb --section builtins|attach|sugar|syntax|maps
#
# THE SYNTAX SECTION IS THE FIFTH VOCABULARY
#
# Prose was already diagnosed as the reason `pkt.*` could be advertised for a
# year while dead, and the SUGAR half of that prose was made machine-readable
# then. RUBY_SUBSET[:supported] itself stayed fourteen strings -- and two
# constructs inside them were dead: a literal `n.times` (the open-coded iterator)
# and `x = if ... end`. Neither is a builtin, an attach kind, a sugar pair or a
# map, so none of the four sections above swept them. A syntax claim is one
# construct, its declared `lowers_to`, and a construct-free twin that proves the
# needle is load-bearing; the section also runs the direction the map section
# taught (the node types and operators the codegen ACCEPTS must all be exercised
# by some claim) and, in a third part, the REJECTED half of the same prose --
# which turned out to be advertising one refusal that never happened.
#
# WHY ALL FIVE SECTIONS LIVE HERE
#
# They are one invariant measured over five vocabularies, and the vocabularies
# are entangled: sock_ops_op exists only because the sock_ops KIND does;
# `a > 1 ? 1 : 2` only became writable once the EXPRESSION-position IfNode was
# ported, and it is claimed as sugar (same C as `if ... end`) while `if_value` is
# claimed as syntax -- one port, two vocabularies; the syntax probes are written
# with sugar's own harness (SUGAR_SHAPES/sugar_source);
# tail_call_to is withdrawn BECAUSE xdp_tail is; `pkt.l4.proto` is a claim about
# the builtin `pkt_l4_proto`, and `pkt.byte_at` is withdrawn BECAUSE
# pkt_dynptr_byte_at is; the PROG_ARRAY map type is gone BECAUSE both of those
# are. Split across files, a port that revives one half and forgets the other is
# green in both. Here the run reports "advertised N broken=0 / withdrawn M
# revived=0" for each vocabulary, plus a self-check per vocabulary that re-proves
# on every run that this gate can still produce each negative verdict -- so no
# half can quietly become a gate that only knows how to say yes.
#
# THE NEGATIVE CONTROL IS NOT THE WITHDRAWN SET ANY MORE
#
# It used to be, and that made the gate's detection power a function of how much
# was still broken: as the demoted surfaces get re-ported, two of the four
# withdrawn sets reach zero. The sugar half hit it first -- it printed all-green
# numbers and then aborted with "no negative control". The pressure that creates
# is the wrong one: keep a fake entry in the SHIPPED affordance so the gate stays
# armed (the affordance IS the shipped artifact, and a whole round of work went
# into taking names out of it that were not real).
#
# So the two jobs the withdrawn set was doing are split by lifetime -- see the
# block after `check`:
#   capability      "can this gate still say no?"     synthesised, never depletes
#   correspondence  "the record and the refusals agree"  vacuous when both are
#                                                        empty, and correctly so
# An empty withdrawn set is now a printed note stating a true fact, not an abort.
#
# THE MAP SECTION MEASURES THE OTHER DIRECTION
#
# The first three ask whether a CLAIM holds. Maps failed the opposite way: the
# implementation was healthy and the affordance said nothing at all -- zero map
# constants, so an AI reading the affordance could not learn that `@x += 1`
# creates a map, that a ringbuf holds 256 KiB, or that a full one drops records
# silently. So this section also sweeps every advertised surface and
# requires that every map that comes OUT is covered by a claim. Silence is a
# defect, and only the coverage direction can see it.
#
# THE SUGAR SECTION MEASURES A DIFFERENT THING
#
# The first two ask "does the claim hold for THIS name". Sugar claims are about
# a PAIR: two spellings that must reach the same generated C. So the sugar
# section compiles both and compares, which catches one failure the other two
# structurally cannot -- a surface that compiles into something ELSE. Because
# that state is new here, the sugar section also runs a deliberately mismatched
# pair on every invocation and refuses to pass unless it is reported as
# diverged: the gate re-proves it can see divergence before it claims there is
# none.
#
# WHY THIS EXISTS
#
# The affordance (`spinel-ebpf capabilities` / `describe`) is the shipped
# artifact: it is what an AI reads to decide what it may write. A sweep of it
# found 18 of the 186 advertised builtins dead -- lost in the port from the Ruby
# codegen to the in-process C one, and advertised as working for a year because
# nothing ever called them. tools/golden.rb could not see it: a builtin with no
# fixture has no golden, and a comparison you never make cannot fail.
#
# So the gate is not "did the output change" but "does the claim hold", and it
# holds it over the SET of claims, which is the thing that was drifting.
#
# TWO DIRECTIONS, AND WHY BOTH
#
#   advertised  every name in Capabilities.all_builtins must COMPILE.
#   withdrawn   every name in Capabilities::WITHDRAWN must still FAIL.
#
# The second is not decoration. A gate that has degenerated into "everything is
# fine" -- wrong binary, probes that never reach the codegen, a classifier that
# swallows errors -- stays green forever on the first check alone. That is
# exactly how the corpus's four negative fixtures kept passing while their gates
# were gone. Running both directions means the gate re-derives its own ability to
# tell the two answers apart on every single run: an always-ok gate fails the
# withdrawn set, an always-fail gate fails the advertised set. There is no
# degenerate state that is green.
#
# It also catches the opposite mistake: porting a withdrawn builtin
# and forgetting to re-advertise it. The gate says so instead of leaving a
# working feature invisible.
#
# HOW A PROBE IS BUILT
#
# From the affordance itself: the call text is `example_for(name)` (the very
# syntax the affordance publishes), and the context is CONTEXT_REQUIREMENTS.
# So a failure here reads as "the documented call, in the documented context,
# does not compile" -- which is the only failure mode worth a gate.
#
# WHERE IT RUNS
#
# The production codegen is in-process and needs the upstream spinel objects,
# i.e. Linux plus a built deps/spinel (scripts/setup.sh). In the build
# container:
#   container exec spnlbuild sh -c 'cd /work && ruby tools/affordance_gate.rb'
# On a host without it, the gate ABORTS rather than passing vacuously.

require "open3"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "src"))
require "spinel_ebpf/capabilities"

CAP = SpinelEbpf::Capabilities
CC  = ENV["SPNL_INPROC_CC"] || File.join(ROOT, "build/codegen_c/spinel-ebpf-cc")

# --- probe shapes ---------------------------------------------------------
# One entry per context this gate can write. `params` are the handler's declared
# parameters; free identifiers from the call that are not among them become
# either extra params (kinds that take them) or locals.
# `preamble`: a companion declaration the probe needs to be LEGAL, not
# scaffolding for the call itself -- `user_ringbuf_drain` is refused unless the
# unit also declares the `def user_ringbuf__<name>(value)` it drains into (and
# the callback is refused unless something drains it, so neither half can be
# probed alone). Emitted verbatim before the handler; the sugar table carries
# the same idea as `companion_sugar` / `companion_flat`.
Shape = Struct.new(:def_line, :params, :takes_params, :ret, :open, :close,
                   :reactor, :preamble, keyword_init: true)

SHAPES = {
  kprobe:          Shape.new(def_line: "def kprobe__do_sys_openat2", takes_params: true,  ret: "0"),
  # The drain needs a callback to call. Written as a kprobe drain site
  # on purpose -- the affordance says the drain point is the author's choice and
  # is not restricted to any hook (measured: 12 program types, all LOAD_OK).
  user_ringbuf:    Shape.new(def_line: "def kprobe__do_sys_openat2", takes_params: true, ret: "0",
                             preamble: "def user_ringbuf__cmd_handler(value)\n" \
                                       "  @hits = @hits + value\nend\n"),
  # attached_index / attached_symbol_eq only exist inside a multi-symbol
  # handler, whose only surface is the reactor form (a symbol list cannot live in
  # a method name). `reactor` is the probe text up to the body; `source` appends
  # the call and the two `end`s.
  kprobe_multi:    Shape.new(reactor: "module ProbeKM\n  include BPF::EventLoop\n" \
                                      "  on :kprobe, %w[vfs_read vfs_write] do\n",
                             ret: "0"),
  lsm:             Shape.new(def_line: "def lsm__file_open", params: %w[file ret], ret: "ret"),
  fmod_ret:        Shape.new(def_line: "def fmod_ret__security_file_open", params: %w[file ret], ret: "ret"),
  xdp:             Shape.new(def_line: "def xdp__probe", ret: "XDP_PASS"),
  xdp_tail:        Shape.new(def_line: "def xdp_tail__probe", ret: "XDP_PASS"),
  tc_ingress:      Shape.new(def_line: "def tc__ingress__probe", ret: "TC_ACT_OK"),
  tc_egress:       Shape.new(def_line: "def tc__egress__probe", ret: "TC_ACT_OK"),
  sk_reuseport:    Shape.new(def_line: "def sk_reuseport__probe", ret: "SK_PASS"),
  sock_ops:        Shape.new(def_line: "def sock_ops__probe", ret: "0"),
  cgroup_connect4: Shape.new(def_line: "def cgroup__connect4__probe", ret: "1"),
  cgroup_bind4:    Shape.new(def_line: "def cgroup__bind4__probe", ret: "1"),
  iter_task:       Shape.new(def_line: "def iter__task__probe", ret: "0"),
  tcp_cc:          Shape.new(def_line: "  def cong_avoid", params: %w[sk ack acked], ret: "0",
                             open: "class ProbeCC < BPF::TcpCC", close: "end"),
  sched_ext:       Shape.new(def_line: "  def dispatch", params: %w[cpu prev], ret: "0",
                             open: "class ProbeSX < BPF::SchedExt", close: "end"),
  qdisc:           Shape.new(def_line: "  def enqueue", params: %w[skb sch to_free], ret: "0",
                             open: "class ProbeQ < BPF::Qdisc", close: "end"),
}.freeze

# A builtin with no declared context requirement is written where its domain
# says it belongs. These are not gates -- they are the shape that makes a
# minimal probe legal, nothing more.
DOMAIN_SHAPE = { observability: :kprobe, enforcement: :lsm, l7: :kprobe,
                 core: :kprobe, net: :xdp }.freeze

# Builtins with no declared context whose domain shape is wrong for them. Kept
# tiny on purpose: a long list here would mean the affordance's own context
# metadata is what needs fixing, not this table.
SHAPE_OVERRIDE = {
  # net domain, but these are ungated helpers that only make sense elsewhere
  "queue_push" => :qdisc, "queue_pop" => :qdisc,
  "emit_connect" => :kprobe, "sock_owner_set" => :kprobe,
  "blocklist_match" => :xdp, "cidr_blocklist_match" => :xdp,
  "arena_set" => :kprobe, "arena_get" => :kprobe,
  "arena_hash_set" => :kprobe, "arena_hash_get" => :kprobe, "arena_hash_del" => :kprobe,
  "arena_list_push" => :kprobe, "arena_list_sum" => :kprobe,
  # sock_* accessors take a `struct sock *` from a probe argument
  "sock_sport" => :kprobe, "sock_dport" => :kprobe, "sock_saddr" => :kprobe,
  "sock_daddr" => :kprobe, "sock_family" => :kprobe, "sock_state" => :kprobe,
  "sock_protocol" => :kprobe, "sock_saddr6_hi" => :kprobe, "sock_saddr6_lo" => :kprobe,
  "sock_daddr6_hi" => :kprobe, "sock_daddr6_lo" => :kprobe,
  # same -- a socket and a msghdr, both handed over by a probe argument
  "udp_dport" => :kprobe, "udp_daddr" => :kprobe,
  # observability domain, but the drain is only legal beside the
  # callback it drains into -- the `user_ringbuf` shape carries that declaration.
  "user_ringbuf_drain" => :user_ringbuf,
}.freeze

KIND_TO_SHAPE = SHAPES.keys.to_h { |k| [k, k] }.freeze

PRELUDE = <<~RB
  XDP_ABORTED  = 0
  XDP_DROP     = 1
  XDP_PASS     = 2
  XDP_TX       = 3
  XDP_REDIRECT = 4
  TC_ACT_OK    = 0
  SK_DROP      = 0
  SK_PASS      = 1

  @hits = 0
RB

module AffordanceGate
  module_function

  # The affordance's own published call syntax. Opaque kfuncs publish no example
  # (params honestly unknown), so synthesise a positional call at the known arity.
  def call_text(name)
    ex = CAP.example_for(name) rescue nil
    return ex if ex
    w = CAP::WITHDRAWN[name]
    return w[:example] if w && w[:example]
    arity = if w then w[:arity]
            else (CAP.signature_for(name)[:arity] rescue 0)
            end
    arity = 2 unless arity.is_a?(Integer)
    arity.zero? ? name : "#{name}(#{(0...arity).map { |i| "a#{i}" }.join(', ')})"
  end

  def free_vars(name, text)
    m = text.match(/\A#{Regexp.escape(name)}\((.*)\)\z/m)
    return [] unless m
    m[1].split(",").map(&:strip).select { |a| a.match?(/\A[a-z_][A-Za-z0-9_]*\z/) }.uniq
  end

  def shape_for(name)
    return SHAPE_OVERRIDE[name] if SHAPE_OVERRIDE.key?(name)
    if (w = CAP::WITHDRAWN[name])
      return w[:ctx]
    end
    if (req = CAP::CONTEXT_REQUIREMENTS[name])
      if req[:kinds]
        k = req[:kinds].map { |x| KIND_TO_SHAPE[x] }.compact.first
        return k if k
      elsif req[:secs]
        return :lsm if req[:secs].include?("lsm/file_open")
        return :fmod_ret if req[:secs].include?("fmod_ret/security_file_open")
      end
    end
    DOMAIN_SHAPE[CAP.domain_of(name)] || :kprobe
  end

  def source(shape_key, call, vars)
    sh = SHAPES.fetch(shape_key)
    if sh.reactor
      body = (vars.map { |v| "    #{v} = 0" } + ["    @hits = @hits + 1", "    #{call}"]).join("\n")
      return "#{PRELUDE}\n#{sh.preamble}#{sh.reactor}#{body}\n  end\nend\n"
    end
    fixed = (sh.params || []).dup
    extra = vars - fixed
    params = fixed + (sh.takes_params ? extra : [])
    locals = sh.takes_params ? [] : extra
    ind = sh.open ? "  " : ""
    body = locals.map { |v| "#{ind}  #{v} = 0" }
    body << "#{ind}  @hits = @hits + 1"
    body << "#{ind}  #{call}"
    body << "#{ind}  #{sh.ret}"
    src = +PRELUDE
    src << "\n"
    src << sh.preamble << "\n" if sh.preamble
    src << "#{sh.open}\n" if sh.open
    src << sh.def_line
    src << "(#{params.join(', ')})" unless params.empty?
    src << "\n" << body.join("\n") << "\n#{ind}end\n"
    src << "#{sh.close}\n" if sh.close
    src
  end

  # ---- attach kinds -------------------------------------------------------
  # An unported BUILTIN dies loudly. An unported ATTACH KIND does not: its
  # method name matches nothing, so the codegen wraps it in SEC("syscall") and
  # emits a program that loads, attaches to nothing and never fires -- exit 0,
  # no diagnostic. So "did it die" cannot be the question here. The question is
  # "did the SEC the affordance PROMISED come out", and the promise is a field
  # the affordance already publishes: ATTACH_KINDS[:sec].
  #
  # ATTACH_SHAPES supplies only the concrete names that fill the <placeholders>
  # shared by :method_prefix and :sec, plus the handler's params/return. The
  # expected string is never written here -- it is computed from :sec, so an
  # affordance that changes its claim changes what the gate demands.
  AttachShape = Struct.new(:open, :def_line, :params, :ret, :close, :subst,
                           :reactor, keyword_init: true)

  def aflat(def_line, params: [], ret: "0", subst: {})
    AttachShape.new(def_line: "def #{def_line}", params: params, ret: ret, subst: subst)
  end

  # A kind whose ONLY surface is the reactor form -- a symbol list cannot
  # live in a method name. `reactor` is the probe text up to the handler body;
  # the marker assignment and the two `end`s are appended by attach_source.
  def areactor(text, subst)
    AttachShape.new(reactor: text, subst: subst)
  end

  def aclass(open, member, params, subst)
    AttachShape.new(open: open, def_line: "  def #{member}", params: params, ret: "0",
                    close: "end", subst: subst)
  end

  ATTACH_SHAPES = {
    kprobe:        aflat("kprobe__do_sys_openat2", subst: { "<func>" => "do_sys_openat2" }),
    # `via: :multi` rather than a list long enough to trip the auto threshold:
    # the gate asserts the SEC the affordance PROMISED, so it must not depend on
    # a number that a later measurement is allowed to move.
    kprobe_multi:  areactor("module ProbeKM\n  include BPF::EventLoop\n" \
                            "  on :kprobe, %w[vfs_read vfs_write], via: :multi do\n", {}),
    kretprobe:     aflat("kretprobe__do_sys_openat2", params: %w[ret], subst: { "<func>" => "do_sys_openat2" }),
    uprobe:        aflat("uprobe__readline"),
    uretprobe:     aflat("uretprobe__readline", params: %w[ret]),
    usdt:          aflat("usdt__libstdcxx__throw", params: %w[obj]),
    tracepoint:    aflat("tracepoint__syscalls__sys_enter_openat", params: %w[dfd],
                         subst: { "<cat>" => "syscalls", "<event>" => "sys_enter_openat" }),
    fentry:        aflat("fentry__tcp_v4_rcv", params: %w[skb], subst: { "<func>" => "tcp_v4_rcv" }),
    fexit:         aflat("fexit__tcp_v4_rcv", params: %w[skb ret], subst: { "<func>" => "tcp_v4_rcv" }),
    lsm:           aflat("lsm__file_open", params: %w[file ret], ret: "ret", subst: { "<hook>" => "file_open" }),
    fmod_ret:      aflat("fmod_ret__security_file_open", params: %w[file ret], ret: "ret",
                         subst: { "<func>" => "security_file_open" }),
    sock_ops:      aflat("sock_ops__probe"),
    cgroup_connect4: aflat("cgroup__connect4__probe", ret: "1"),
    cgroup_bind4:  aflat("cgroup__bind4__probe", ret: "1"),
    iter_task:     aflat("iter__task__probe"),
    raw_tp:        aflat("raw_tp__sys_enter", params: %w[a0], subst: { "<event>" => "sys_enter" }),
    socket_filter: aflat("socket_filter__probe"),
    flow_dissector: aflat("flow_dissector__probe"),
    sk_lookup:     aflat("sk_lookup__probe", ret: "SK_PASS"),
    tcp_cc:        aclass("class ProbeCC < BPF::TcpCC", "cong_avoid", %w[sk ack acked], "<member>" => "cong_avoid"),
    sched_ext:     aclass("class ProbeSX < BPF::SchedExt", "dispatch", %w[cpu prev], "<member>" => "dispatch"),
    qdisc:         aclass("class ProbeQ < BPF::Qdisc", "enqueue", %w[skb sch to_free], "<member>" => "enqueue"),
    xdp:           aflat("xdp__probe", ret: "XDP_PASS"),
    # a tail-call TARGET, written on its own. That is deliberate and
    # it is also what a unit legitimately looks like before its dispatcher is
    # written: the promise this kind makes is SEC("xdp") plus a slot in
    # `spnl_prog_array`, and both hold with nobody jumping. (It is also the probe
    # the map section compiles for the PROG_ARRAY claim, so if a lone target
    # stopped emitting the map, two sections would say so.)
    xdp_tail:      aflat("xdp_tail__probe", ret: "XDP_PASS"),
    # the ONE kind whose body is thrown away (the affordance says so with
    # `body: :discarded`). `ret:` is still written the way an author would write
    # the marker -- the point of the probe is that it is the surface, not a
    # minimal input -- but the marker cannot survive into the C, so check_attach
    # looks for the declared `emits:` symbol instead. See the note there.
    xdp_tcp_slice: aflat("xdp__tcp_slice__probe", ret: "XDP_PASS"),
    tc_ingress:    aflat("tc__ingress__probe", ret: "TC_ACT_OK"),
    tc_egress:     aflat("tc__egress__probe", ret: "TC_ACT_OK"),
    sk_reuseport:  aflat("sk_reuseport__probe", ret: "SK_PASS"),
    sk_msg:        aflat("sk_msg__probe", ret: "SK_PASS"),
    sk_skb_verdict: aflat("sk_skb__verdict__probe", ret: "SK_PASS"),
    sk_skb_parser: aflat("sk_skb__parser__probe", ret: "SK_PASS"),
    perf_event:    aflat("perf_event__sample"),
    # reactor-only, like kprobe_multi -- there is no `def` form,
    # because the interval arrives as a keyword on the `on` call. This is the
    # kind stage 2 of check_attach exists for: its promised SEC is "syscall",
    # which is also what the silent degradation emits, so only "did the body
    # reach the output" tells the two apart.
    timer:         areactor("module ProbeTimer\n  include BPF::EventLoop\n" \
                            "  on :timer, every: 1.seconds do\n", {}),
    # the only kind that emits NO program, so the affordance publishes
    # `emits:` (a C symbol) where the others publish `sec:`. The probe still has
    # to be a legal unit: a callback with nothing draining it is refused, so the
    # drain site comes along. Its own SEC("xdp") is not what is being asserted --
    # `promised_needle` reads the affordance and asks for the callback symbol.
    user_ringbuf:  AttachShape.new(def_line: "def user_ringbuf__cmd_handler", params: %w[value],
                                   ret: "0", subst: { "<name>" => "cmd_handler" },
                                   close: "\ndef xdp__drain\n  user_ringbuf_drain\n  XDP_PASS\nend"),
  }.freeze

  # The withdrawn kinds' surfaces come from the affordance's own record, so the
  # negative control is the shape a reader of WITHDRAWN_ATTACH would type.
  def withdrawn_attach_source(kind, marker)
    w = CAP::WITHDRAWN_ATTACH.fetch(kind)
    probe = w[:probe]
    src = +"@#{marker} = 0\n\n#{PRELUDE}\n"
    if probe.start_with?("module ")           # reactor surface (`on :timer, ...`)
      src << probe << "    @#{marker} = @#{marker} + 1\n  end\nend\n"
    else
      src << probe << "\n  @#{marker} = @#{marker} + 1\n  0\nend\n"
    end
    src
  end

  # The marker the body carries is a LITERAL, not the ivar's name.
  #
  # It used to be the name, and that made stage 2 much weaker than it read: the
  # probe declares `@<marker> = 0` at top level, the codegen turns every
  # top-level ivar into a per-unit map called `<unit>_top_<marker>`, and so the
  # NAME appears in the emitted C whether or not the body survived. Measured
  # while porting the one kind that legitimately discards its body
  # (`xdp__tcp_slice__probe`): body gone, marker name present twice, stage 2
  # satisfied. The self-check never noticed because it asks for a name that
  # appears NOWHERE, which proves the comparison runs, not that the needle can
  # only come from the body.
  #
  # BODY_MARK is emitted only by the increment, so its presence is evidence
  # about the body and nothing else. The ivar stays (a handler that assigns
  # nothing is not the shape an author writes) but it is no longer the needle.
  BODY_MARK = "416416"

  def attach_source(kind, marker)
    sh = ATTACH_SHAPES.fetch(kind)
    if sh.reactor
      return "@#{marker} = 0\n\n#{PRELUDE}\n#{sh.reactor}" \
             "    @#{marker} = @#{marker} + #{BODY_MARK}\n  end\nend\n"
    end
    ind = sh.open ? "  " : ""
    src = +"@#{marker} = 0\n\n#{PRELUDE}\n"
    src << "#{sh.open}\n" if sh.open
    src << sh.def_line
    src << "(#{sh.params.join(', ')})" unless (sh.params || []).empty?
    src << "\n#{ind}  @#{marker} = @#{marker} + #{BODY_MARK}\n#{ind}  #{sh.ret}\n#{ind}end\n"
    src << "#{sh.close}\n" if sh.close
    src
  end

  # The affordance's promise, with this shape's concrete names substituted in.
  #
  # Every kind publishes exactly one of two promises, and the gate reads whichever
  # the entry carries: `sec:` -- a program SEC, checked against prog_secs;
  # or `emits:` -- a C symbol, for the one kind that emits no program at all
  # (a USER_RINGBUF callback). Writing "syscall" for that one would have been
  # worse than useless: it is the exact string the silent degradation produced.
  def promised_sec(kind)
    entry = CAP::ATTACH_KINDS.find { |a| a[:kind] == kind } or return nil
    promise = entry[:sec] || entry[:emits] or return nil
    ATTACH_SHAPES.fetch(kind).subst.reduce(promise.dup) { |s, (ph, v)| s.gsub(ph, v) }
  end

  # true when this kind throws the handler body away (so the marker cannot
  # appear in the output and stage 2 has to ask a different question).
  def discards_body?(kind)
    e = CAP::ATTACH_KINDS.find { |a| a[:kind] == kind }
    !!(e && e[:body] == :discarded && e[:emits])
  end

  # true when this kind's promise is a C symbol rather than a program SEC.
  def emits_symbol?(kind)
    e = CAP::ATTACH_KINDS.find { |a| a[:kind] == kind }
    !!(e && e[:sec].nil? && e[:emits])
  end

  # Run the codegen and hand back text we can actually scan.
  #
  # Open3 tags the child's output with the default external encoding, which in
  # the container is US-ASCII (the image sets no LANG). The emitted C carries
  # non-ASCII bytes -- diagnostics, and comments copied from the probe -- so a
  # bare `scan` raises `invalid byte sequence in US-ASCII` and the gate dies with
  # a backtrace instead of a verdict. Third time this root cause has bitten
  # (twice before, in `check` and in `check --json`), so fix it where they enter.
  def cap3(*argv)
    out, err, st = Open3.capture3(*argv)
    [out.dup.force_encoding("UTF-8").scrub, err.dup.force_encoding("UTF-8").scrub, st]
  end

  # Program SECs only: license / .maps / .struct_ops* are not attach points.
  def prog_secs(out)
    out.scan(/SEC\("([^"]+)"\)/).flatten.reject { |s| s == "license" || s.start_with?(".") }.uniq
  end

  # [:kept | :broken, message, promised_sec, reason]. "Kept" needs the promised
  # SEC AND the handler body in the output: `on :timer` degraded to a body that
  # never reached the C at all, and its advertised SEC ("syscall") is the same
  # string a silent degradation produces -- a SEC check alone would have called it
  # fine. The two stages fail with different `reason`s so the self-check can
  # demand each of them separately; a self-check that only asserted :broken would
  # pass with stage 2 deleted, i.e. it would reopen that same hole.
  #
  # `want_sec` / `want_marker` exist ONLY for that self-check: they perturb the
  # gate's own expectation in memory (the sugar self-check's move) so the
  # run re-proves it can still produce each verdict.
  def check_attach(dir, tag, kind, want_sec: nil, want_marker: nil)
    marker = "zz#{tag}"
    path = File.join(dir, "#{tag}.rb")
    File.write(path, attach_source(kind, marker))
    out, err, st = cap3(CC, path, tag)
    want = want_sec || promised_sec(kind)
    needle = want_marker || BODY_MARK
    return [:broken, "refused: #{err.lines.map(&:strip).reject(&:empty?).first}", want, :refused] unless st.success?
    # for a kind that DISCARDS the body, "the body reached the C" is false
    # by design, so stage 2 asks the question the affordance says is the right
    # one for it: did the machine the body was replaced BY come out? Which symbol
    # to look for is declared (`emits:`), not written here -- same rule as the
    # SEC, and the same reason: an expectation the gate owns is an expectation
    # that stops testing the affordance.
    #
    # This is the second time a kind has not fitted the SEC+body pair (the first
    # had no SEC at all). Both were handled by letting the affordance
    # say what to look for rather than by special-casing a name in the gate.
    if !want_marker && discards_body?(kind)
      sym = CAP::ATTACH_KINDS.find { |a| a[:kind] == kind }[:emits]
      return [:broken, "declares body: :discarded and emits #{sym.inspect}, but that symbol " \
                       "is not in the output -- the body was dropped and nothing replaced it, " \
                       "which is the silent degradation with an extra step", want, :no_body] unless out.include?(sym)
    elsif !out.include?(needle)
      return [:broken, "compiled, but the handler body never reached the emitted C " \
                       "(the kind was skipped, not merely unattached)", want, :no_body]
    end
    got = prog_secs(out)
    # a kind that promises a SYMBOL instead of a SEC. Both halves are the
    # same question the SEC check asks -- did the promised thing come out, and is
    # the measured degradation absent -- but the degradation here is a program
    # where there should be none, so it is named rather than inferred.
    if want_sec.nil? && emits_symbol?(kind)
      return [:broken, "promised to emit #{want.inspect}, and it is not in the output",
              want, :wrong_sec] unless out.include?(want)
      return [:broken, "emitted SEC(\"syscall\") -- the plain-method wrapper. This kind emits " \
                       "no program of its own; a syscall wrapper is what the silent degradation " \
                       "produced", want, :wrong_sec] if got.include?("syscall")
      return [:kept, nil, want, nil]
    end
    return [:broken, "promised SEC(#{want.inspect}), emitted #{got.inspect}" +
                     (got == ["syscall"] ? " -- the plain-method wrapper, i.e. a program that loads and never fires" : ""),
            want, :wrong_sec] unless got.include?(want)
    [:kept, nil, want, nil]
  end

  # A withdrawn kind must be REFUSED. Withdrawing it from the affordance is only
  # half the fix; if the codegen still accepts the name, an author working from
  # an older doc (or one of the committed examples) still gets the silent no-op.
  def check_withdrawn_attach(dir, tag, kind)
    path = File.join(dir, "#{tag}.rb")
    File.write(path, withdrawn_attach_source(kind, "zz#{tag}"))
    _out, err, st = cap3(CC, path, tag)
    return [:refused, err.lines.map(&:strip).reject(&:empty?).first.to_s] unless st.success?
    [:accepted, nil]
  end

  # ---- surface sugar ------------------------------------------------------
  # A sugar claim is a claim about a PAIR. `Capabilities.surface_sugar` publishes
  # both spellings; this only writes the minimal probe each goes in and compares
  # the emitted C. Nothing here says what the output should be.
  #
  # equiv: :identical  the two must produce byte-identical C (what each family
  #                    of sugar claims in its own words)
  # equiv: :compiles   both must compile; the C legitimately differs and the
  #                    affordance entry says why. Only one entry is in this
  #                    tier, and it is the one place `diverged` cannot be seen.
  SUGAR_SHAPES = {
    kprobe:       { def_line: "def kprobe__do_sys_openat2", params: [], ret: "0" },
    # The same hook with one declared argument. Most syntax claims need an operand
    # that is a LOCAL -- `a % 3` with `a` undefined is not even parsed as a binary
    # operator (measured: the `%` claim's probe contained no CallNode named "%"
    # until `a` became a parameter), so a claim written against a param-less shape
    # would be testing something else.
    kprobe_arg:   { def_line: "def kprobe__do_sys_openat2", params: %w[a], ret: "0" },
    kprobe_sk:    { def_line: "def kprobe__tcp_sendmsg", params: %w[sk], ret: "0" },
    xdp:          { def_line: "def xdp__probe", params: [], ret: "XDP_PASS" },
    tc_ingress:   { def_line: "def tc__ingress__probe", params: [], ret: "TC_ACT_OK" },
    sk_reuseport: { def_line: "def sk_reuseport__probe", params: [], ret: "SK_PASS" },
    sock_ops:     { def_line: "def sock_ops__probe", params: [], ret: "0" },
    tcp_cc:       { open: "class ProbeCC < BPF::TcpCC", def_line: "  def cong_avoid",
                    params: %w[sk ack acked], ret: "0", close: "end" },
  }.freeze

  SUGAR_PRELUDE = PRELUDE.sub("@hits = 0\n", "") + "TC_ACT_SHOT  = 2\n"

  def sugar_source(entry, which)
    text = entry.fetch(which)
    if entry[:form] == :attach
      ind  = text.start_with?("module ", "class ") ? "    " : "  "
      body = ["#{ind}n = 1", "#{ind}n + #{entry[:ret]} - n"]
      return SUGAR_PRELUDE + "\n" + text.sub("<BODY>", body.join("\n")) + "\n"
    end
    sh  = SUGAR_SHAPES.fetch(entry[:shape])
    ind = sh[:open] ? "  " : ""
    lines = case entry[:form]
            when :expr then ["#{ind}  n = #{text}", "#{ind}  n"]
            when :stmt then text.lines.map { |l| "#{ind}  #{l.chomp.sub(/\A  /, '')}" }
            else raise "affordance gate: unknown sugar form #{entry[:form].inspect}"
            end
    src = +SUGAR_PRELUDE.dup
    src << "\n"
    src << "#{sh[:open]}\n" if sh[:open]
    src << sh[:def_line]
    src << "(#{sh[:params].join(', ')})" unless sh[:params].empty?
    src << "\n" << lines.join("\n") << "\n#{ind}  #{sh[:ret]}\n#{ind}end\n"
    src << "#{sh[:close]}\n" if sh[:close]
    src
  end

  # [:ok | :die | :diverged | :other, message]. `other` (the FLAT spelling also
  # failed) is never conflated with a real failure -- it means this gate wrote a
  # bad pair, which is the gate's bug, not the codegen's.
  def check_sugar(dir, tag, entry)
    sp = File.join(dir, "#{tag}_s.rb")
    fp = File.join(dir, "#{tag}_f.rb")
    File.write(sp, sugar_source(entry, :sugar))
    File.write(fp, sugar_source(entry, :flat))
    sout, serr, sst = cap3(CC, sp, tag)
    fout, ferr, fst = cap3(CC, fp, tag)
    unless fst.success?
      return [:other, "the FLAT spelling failed too, so this gate wrote a bad pair: " \
                      "#{ferr.lines.map(&:strip).reject(&:empty?).first}"]
    end
    unless sst.success?
      return [:die, serr.lines.map(&:strip).reject(&:empty?).first.to_s]
    end
    return [:ok, nil] if entry[:equiv] == :compiles || sout == fout
    al = sout.lines
    bl = fout.lines
    i = 0
    i += 1 while i < al.size && i < bl.size && al[i] == bl[i]
    [:diverged, "line #{i + 1}: sugar #{al[i].to_s.strip[0, 70].inspect} " \
                "vs flat #{bl[i].to_s.strip[0, 70].inspect}"]
  end

  # A withdrawn sugar must be REFUSED, for the same reason a withdrawn attach
  # kind is: taking it out of the affordance does not stop the codegen
  # from accepting it, and an author working from an older doc still gets
  # whatever it silently becomes.
  #
  # The entry carries its own `form` (and, for :attach, its own probe text
  # and return literal), because the withdrawn set is not guaranteed to be an
  # expression: un-withdrawing the last expression entry (`pkt.byte_at`) left the
  # reactor spelling of a withdrawn attach kind as the control.
  def check_withdrawn_sugar(dir, tag, spelling, info)
    e = { form: info[:form] || :expr, shape: info[:ctx] || info[:shape],
          sugar: info[:sugar] || spelling, ret: info[:ret] }
    path = File.join(dir, "#{tag}.rb")
    File.write(path, sugar_source(e, :sugar))
    _o, err, st = cap3(CC, path, tag)
    return [:refused, err.lines.map(&:strip).reject(&:empty?).first.to_s] unless st.success?
    [:accepted, nil]
  end

  # ---- syntax -------------------------------------------------------------
  # The fifth vocabulary, and the one that was still fourteen prose strings after
  # prose had been diagnosed as the reason `pkt.*` could lie for a year. Two dead
  # constructs were sitting in it (a literal `n.times`, `x = if ... end`), and
  # none of the four gates above sweeps this vocabulary: a construct is not a
  # builtin, an attach kind, a sugar pair or a map.
  #
  # A syntax claim is a claim about ONE construct and what it becomes:
  #   1. the advertised spelling must COMPILE          (both dead ones fail here)
  #   2. the declared `lowers_to` must be IN the emitted C, and NOT in the
  #      construct-free twin (`without`)
  #
  # Stage 2 is not decoration. `3.times` and `a.times` are both advertised and
  # both compile, and they must reach DIFFERENT machinery (`bpf_iter_num_*` vs
  # `bpf_loop`) with different kernel floors -- lose the open-coded path and a
  # literal count silently becomes a bpf_loop: exit 0, same semantics, wrong
  # floor. Stage 1 cannot see that. The twin is what makes the needle
  # load-bearing: `%`, `else` and `if (` all occur in boilerplate, so a needle
  # that is not required to be ABSENT from the twin can be satisfied by the
  # scaffolding.
  #
  # The probe harness is SUGAR_SHAPES/sugar_source, unchanged -- syntax and sugar
  # write the same three probe forms, which is one of the measured reasons this
  # section lives in this file rather than its own.
  SYNTAX_UNIT = "u"   # fixed so a claim can name `u_top_h` in its `lowers_to`

  def syntax_source(entry, which)
    sugar_source(entry.merge(sugar: entry.fetch(which)), :sugar)
  end

  # [:ok | :die | :wrong_lowering | :not_load_bearing | :other, message].
  # `other` (the twin failed too) is the gate's own bug, never the codegen's --
  # same rule as check_sugar.
  #
  # `want` is overridable ONLY for the self-checks, which perturb the gate's own
  # expectation in memory so the run re-proves it can still produce each verdict.
  def check_syntax(dir, tag, entry, want: nil)
    ap = File.join(dir, "#{tag}_a.rb")
    bp = File.join(dir, "#{tag}_b.rb")
    File.write(ap, syntax_source(entry, :syntax))
    File.write(bp, syntax_source(entry, :without))
    aout, aerr, ast = cap3(CC, ap, SYNTAX_UNIT)
    needle = want || entry.fetch(:lowers_to)
    unless ast.success?
      return [:die, aerr.lines.map(&:strip).reject(&:empty?).first.to_s]
    end
    bout, berr, bst = cap3(CC, bp, SYNTAX_UNIT)
    unless bst.success?
      return [:other, "the `without` twin did not compile either, so this gate wrote a bad " \
                      "pair: #{berr.lines.map(&:strip).reject(&:empty?).first}"]
    end
    unless aout.include?(needle)
      return [:wrong_lowering, "compiled, but #{needle.inspect} is not in the emitted C -- " \
                               "the construct was accepted and lowered to something else"]
    end
    if bout.include?(needle)
      return [:not_load_bearing, "#{needle.inspect} is also in the twin that does NOT contain " \
                                 "the construct, so the needle is satisfied by boilerplate and " \
                                 "proves nothing about #{entry[:syntax].to_s.lines.first.to_s.strip.inspect}"]
    end
    [:ok, nil]
  end

  # A withdrawn construct must be REFUSED (the attach section's rule: taking it
  # out of the affordance does not stop the codegen from accepting it).
  def check_withdrawn_syntax(dir, tag, spelling, info)
    e = { form: info[:form] || :expr, shape: info[:shape] || :kprobe,
          syntax: info[:syntax] || spelling, ret: info[:ret] }
    path = File.join(dir, "#{tag}.rb")
    File.write(path, syntax_source(e, :syntax))
    _o, err, st = cap3(CC, path, SYNTAX_UNIT)
    return [:refused, err.lines.map(&:strip).reject(&:empty?).first.to_s] unless st.success?
    [:accepted, nil]
  end

  # ---- the direction that sees SILENCE ------------------------------------
  # The map section's lesson: a gate that only asks "does the claim hold" is
  # green while the affordance says nothing at all. For syntax the
  # implementation-side authority is the codegen's own lowering dispatch -- the
  # node types it accepts, read out of the C source, and the binary-operator
  # table.
  #
  # Both authorities are named by the affordance (SYNTAX_COVERAGE_AUTHORITIES);
  # what follows is only how to read them.
  def cc_function_body(name)
    return nil unless File.exist?(CC_SOURCE)
    src = File.read(CC_SOURCE)
    # `[^;{]*\)\s*\{` and not just `\(`: cc_lower_stmt has TWO forward
    # declarations before its definition (it is mutually recursive with
    # cc_lower_expr), and matching one of those made `src.index("{")` land in a
    # completely different function's body. Measured, not reasoned about -- the
    # bad extractor reported 11 accepted node types instead of 16, i.e. it made
    # the coverage direction quietly weaker rather than failing.
    i = src.index(/^static [A-Za-z_]+ \*?#{name}\([^;{]*\)\s*\{/) or return nil
    j = src.index("{", i) or return nil
    depth = 0
    k = j
    while k < src.length
      depth += 1 if src[k] == "{"
      if src[k] == "}"
        depth -= 1
        break if depth.zero?
      end
      k += 1
    end
    src[j..k]
  end

  # ---- builtin existence coverage -----------------------------------------
  # Like cc_function_body but for any `static <words> *?name(` return type --
  # the recognition helpers return `const char *`, which the one-word pattern
  # above cannot see. Same brace counting, same nil-on-unreadable rule.
  def cc_fn_body_general(name)
    return nil unless File.exist?(CC_SOURCE)
    src = File.read(CC_SOURCE)
    i = src.index(/^static [A-Za-z_][A-Za-z_ ]*? \*?#{name}\([^;{]*\)\s*\{/) or return nil
    j = src.index("{", i) or return nil
    depth = 0
    k = j
    while k < src.length
      depth += 1 if src[k] == "{"
      if src[k] == "}"
        depth -= 1
        break if depth.zero?
      end
      k += 1
    end
    src[j..k]
  end

  # Extract every builtin name the codegen recognizes, from EXACTLY the
  # mechanisms declared in Capabilities::BUILTIN_COVERAGE_AUTHORITIES. Returns
  # nil if any declared authority is unreadable (never a silently smaller set).
  # `auth` is a parameter so the self-check can drop a mechanism and prove the
  # forward direction notices.
  def builtin_extracted_names(auth = CAP::BUILTIN_COVERAGE_AUTHORITIES)
    src = File.read(CC_SOURCE)
    names = []
    ((auth.dig(:lower_fns, :functions) || []) + (auth.dig(:helper_fns, :functions) || [])).each do |fn|
      body = cc_function_body(fn) || cc_fn_body_general(fn)
      return nil unless body
      body.each_line do |ln|
        # No line filter for target-only builtins: they are DECLARED (the
        # targets axis of builtin_schema.h) and subtracted as data by
        # existence_violations, instead of pattern-matched out of the source.
        names += ln.scan(/!strcmp\((?:name|nm), "([a-z0-9_]+)"\)/).flatten
      end
    end
    (auth.dig(:string_tables, :arrays) || []).each do |arr|
      block = src[/static const [^\n]*#{arr}\[\] = \{(.*?)\n\};/m, 1]
      return nil unless block
      names += block.scan(/"([a-z0-9_]+)"/).flatten
    end
    (auth.dig(:name_tables, :arrays) || []).each do |arr|
      block = src[/static const [^\n]*#{arr}\[\] = \{(.*?)\n\};/m, 1]
      return nil unless block
      names += block.scan(/\{\s*"([a-z0-9_]+)"/).flatten
    end
    names.uniq
  end

  # Pure so the self-checks can call it on mutated inputs.
  #   uncovered: recognized by the codegen, claimed by nothing (reverse direction)
  #   unfound:   claimed, but no declared mechanism recognizes it -- either the
  #              claim is stale or a recognition mechanism is missing from the
  #              authority declaration (forward direction)
  # Target-only builtins (declared in builtin_schema.h, not on the linux
  # surface) are part of `known` -- and get their own forward direction: a
  # declared target-only name nothing recognizes is a stale declaration.
  def existence_violations(extracted, claimed, withdrawn, exclusions, target_only = [])
    known = claimed + withdrawn + exclusions + target_only
    [extracted - known, claimed - extracted, target_only - extracted]
  end

  # nil (not []) when unreadable: an empty authority and an unreadable one must
  # not look alike, or coverage passes vacuously -- the same rule the C refusal
  # table is read under.
  def cc_lowering_node_types
    out = []
    CAP::SYNTAX_COVERAGE_AUTHORITIES[:node_types][:functions].each do |fn|
      body = cc_function_body(fn) or return nil
      out.concat(body.scan(/strcmp\(ty,\s*"([A-Za-z]+Node)"\)/).flatten)
    end
    out.uniq.sort
  end

  def cc_binary_ops
    body = cc_function_body(CAP::SYNTAX_COVERAGE_AUTHORITIES[:binary_ops][:functions].first) or return nil
    decl = body[/static const char \*ops\[\][^;]*;/m] or return nil
    decl.scan(/"([^"]+)"/).flatten
  end

  # The parser the codegen itself uses (`spinel --dump-ast`), so "which node types
  # does this probe contain" is answered by the same front end that will lower it,
  # not by a second parser that could disagree.
  SPINEL = ENV["SPNL_SPINEL_BIN"] ||
           [File.join(ROOT, "deps/spinel/bin/spinel"),
            File.join(ROOT, "deps/spinel/build/spinel")].find { |p| File.executable?(p) }.to_s

  # The dump is space-separated, so string attributes are percent-encoded: the
  # modulo operator arrives as `%25`. Measured -- without this the `%` claim's
  # probe looked as though it contained no modulo at all, and the coverage half
  # reported the operator uncovered while a claim was exercising it. Its own
  # function so a unit test can pin it without the front end.
  def decode_dump_str(s)
    s.to_s.strip.gsub(/%([0-9A-Fa-f]{2})/) { $1.hex.chr }
  end

  # [node types, operator names] present in one probe source, or nil if the dump
  # failed. Dump format is one `N <id> <TypeName>` per node and `S <id> name <v>`
  # for its string attributes.
  def probe_vocab(dir, tag, src)
    path = File.join(dir, "#{tag}.rb")
    File.write(path, src)
    out, _err, st = cap3(SPINEL, "--dump-ast", "--no-line-map", path)
    return nil unless st.success?
    types = {}
    names = {}
    out.each_line do |l|
      if (m = l.match(/\AN (\d+) (\w+)/)) then types[m[1]] = m[2]
      elsif (m = l.match(/\AS (\d+) name (.*)\n?\z/)) then names[m[1]] = decode_dump_str(m[2])
      end
    end
    ops = names.select { |id, _| types[id] == "CallNode" }.values
    [types.values.uniq, ops.uniq]
  end

  # ---- the REJECTED half of the vocabulary --------------------------------
  # RUBY_SUBSET[:rejected] has been machine-readable since it was written (ten
  # `flag`/`construct`/`reason` rows) and says each one corresponds to a loud
  # partition failure. That is a CLAIM, and measuring it found nine holding and
  # `uses_bignum` exiting 0 with a different number baked into the kernel program.
  # A gate that only measures the SUPPORTED half is the syntax version of what the
  # map section named -- checking one direction and calling it coverage.
  #
  # This half needs the whole product, not just the codegen: the refusal is a
  # partition decision, and the codegen never sees the construct (spinel's front
  # end has already clamped the literal). So the probe goes through
  # `bin/spinel-ebpf compile`, and the expected refusal text is a field the
  # affordance publishes (`refusal:`), never a string written here.
  #
  # The construct is placed in an ATTACH HANDLER on purpose: a plain method that
  # cannot be lowered is correctly and quietly kept native, so "loud" is only
  # meaningful where there is no native path to fall back to.
  CLI = File.join(ROOT, "bin/spinel-ebpf")

  def check_rejected(dir, tag, entry)
    path = File.join(dir, "#{tag}.rb")
    File.write(path, entry.fetch(:probe))
    out, err, st = cap3("ruby", CLI, "compile", path, "-o", File.join(dir, "#{tag}_out"))
    txt = out + err
    if st.success?
      hint = txt[/n = (-?\d+);/, 1]
      return [:accepted, "compiled with exit 0 -- the construct the affordance calls impossible " \
                         "was accepted#{hint ? ", and the emitted C carries #{hint}" : ''}"]
    end
    want = entry[:refusal].to_s
    unless want.empty? || txt.include?(want)
      return [:wrong_reason, "refused, but the diagnostic never says #{want.inspect} -- " \
                             "the affordance attributes this to #{entry[:flag]}, and something " \
                             "else refused it, so the flag may still be dead " \
                             "(first line: #{txt.lines.map(&:strip).reject(&:empty?).first.to_s[0, 120]})"]
    end
    [:refused, nil]
  end

  # ---- controls that do not depend on anything being broken ---------------
  SELFCHECK_SYNTAX = :op_mod          # live, :expr, a needle unique to the probe
  # The "can this gate still see a construct that is simply not there" control.
  # It cannot be a name nobody implements (the builtin half's move) because node
  # types come from Ruby's grammar and cannot be invented. So it is anchored on
  # the affordance's OWN rejection claim: `while` is unbounded iteration, which
  # RUBY_SUBSET[:rejected] declares impossible under the verifier. If that claim
  # ever leaves, the anchor aborts -- which is right, because then this control
  # would be betting on an accidental gap instead of a stated one.
  SELFCHECK_SYNTAX_REJECT_FLAG = :uses_unbounded_loop
  SELFCHECK_SYNTAX_ABSENT = { form: :stmt, shape: :kprobe,
                              syntax: "while a < 3\n    a = a + 1\n  end",
                              without: "a = a + 1", lowers_to: "while" }.freeze

  def selfcheck_syntax_absent(dir)
    v, = check_syntax(dir, "ysc_absent", SELFCHECK_SYNTAX_ABSENT)
    v
  end

  # Stage 2, half one: a corrupted promise must come back :wrong_lowering.
  def selfcheck_syntax_wrong(dir, live)
    v, = check_syntax(dir, "ysc_wrong", live, want: "#{live[:lowers_to]}_zz_never_emitted")
    v
  end

  # Stage 2, half two: the TWIN. A needle that also appears without the construct
  # must be rejected as proving nothing. Delete the twin and this half goes green
  # -- which is exactly what it is here to notice (the builtin half's `no_effect`
  # witness, transposed to syntax).
  def selfcheck_syntax_not_load_bearing(dir, live)
    v, = check_syntax(dir, "ysc_bear", live, want: "__s64")
    v
  end

  # The rejected half's controls. Half one: a probe that is perfectly legal must
  # come back :accepted -- otherwise "all ten refused" could be produced by a
  # pipeline that refuses everything (a missing binary, a bad -o path, anything).
  SELFCHECK_REJECT_LEGAL = "def kprobe__do_sys_openat2(a)\n  n = a + 1\n  n\nend\n"

  def selfcheck_rejected_accepts_legal(dir)
    v, = check_rejected(dir, "rsc_legal", { flag: :zz_selfcheck_legal, probe: SELFCHECK_REJECT_LEGAL,
                                            refusal: "" })
    v
  end

  # Half two: the REASON. A refusal for the wrong reason is how `uses_bignum`
  # half-hid for so long -- a bignum in signature position did fail, but as
  # uses_unsupported_type, so the flag was dead and the claim still looked kept.
  # Corrupt a live entry's expected text and demand :wrong_reason.
  def selfcheck_rejected_wrong_reason(dir, live)
    v, = check_rejected(dir, "rsc_reason", live.merge(refusal: "#{live[:refusal]}_zz_never_printed"))
    v
  end

  # ---- maps ---------------------------------------------------------------
  # Nobody writes BPF_MAP_TYPE_HASH in a probe; they write `@x += 1` or
  # `hist_observe(v)`. So a map claim is a claim about a SURFACE: this surface,
  # compiled, produces this map with these properties. The affordance holds the
  # expectation (Capabilities::MAPS, itself derived from the emitted C);
  # nothing about a specific map is written here.
  #
  # THE SCANNER KNOWS FIVE FORMS, AND THAT IS THE INTERESTING PART.
  # `SEC(".maps")` is the obvious one and the only one whose properties are
  # readable from the text. Four others create a map without looking like one:
  # `SEC(".struct_ops[.link]")`, `volatile const` globals (libbpf makes .rodata),
  # the `private(A)` macro (expands to SEC(".data.A")), and an included libbpf
  # header (usdt.bpf.h brings three). The last two turned up only by loading the
  # objects and asking libbpf -- a text scanner that knew three forms called
  # them "no maps". Anything else that looks section-like is reported as an
  # UNKNOWN form rather than ignored, because the failure mode being defended
  # against here is silence, and a form nobody taught the scanner is silence.
  MapDecl = Struct.new(:name, :type, :form, :max_entries, :key, :value,
                       :key_size, :value_size, :flags, :values_of, keyword_init: true)

  # Sections that look section-like but create no map. Each entry is a CLAIM and
  # needs a measurement, because the catch-all below is the only thing standing
  # between "a new form appeared" and silence.
  #
  #   license / maps / struct_ops[.link]  handled by their own branches above
  #   spnl_records                        the record type witnesses. libbpf says
  #     "elf: skipping unrecognized data section" and creates nothing: measured
  #     with `bpftool gen skeleton`, which lists the same maps before and after
  #     the witness is added, and with `bpftool map show` on a running probe.
  #     Contrast the .bss spelling of the same idea, which DOES add a map -- that
  #     is why this list is a claim about a specific section and not a blanket
  #     "unknown sections are fine".
  MAP_SEC_NOT_A_MAP = %w[license maps struct_ops struct_ops.link spnl_records].freeze
  LIBBPF_HEADER_MAPS = {
    "bpf/usdt.bpf.h" => [["__bpf_usdt_specs", "ARRAY"], ["__bpf_usdt_ip_to_spec_id", "HASH"],
                         [".kconfig", "ARRAY"]],
  }.freeze

  # `__uint(value_size, sizeof(struct bpf_cpumap_val))` -- the argument has its
  # own parentheses, so a [^)]* capture silently truncates it. Balance.
  def attr_arg(body, macro, key)
    i = body.index(/#{macro}\(\s*#{key}\s*,/) or return nil
    j = body.index(",", i) + 1
    depth = 1
    k = j
    while k < body.length
      depth += 1 if body[k] == "("
      (depth -= 1; break if depth.zero?) if body[k] == ")"
      k += 1
    end
    body[j...k].strip.gsub(/\s+/, " ")
  end

  def map_body(body, name, form)
    MapDecl.new(name: name, form: form,
                type: body[/__uint\(\s*type\s*,\s*BPF_MAP_TYPE_([A-Za-z_0-9]+)/, 1],
                key: attr_arg(body, "__type", "key"), value: attr_arg(body, "__type", "value"),
                key_size: attr_arg(body, "__uint", "key_size"),
                value_size: attr_arg(body, "__uint", "value_size"),
                max_entries: attr_arg(body, "__uint", "max_entries"),
                flags: attr_arg(body, "__uint", "map_flags"),
                values_of: attr_arg(body, "__array", "values"))
  end

  def map_decls(src)
    # #define lines carry the macro TEXT (`SEC(".data." #name)`), not a use.
    text = src.lines.reject { |l| l =~ /\A\s*#\s*define/ }.join
    named = {}
    text.scan(/struct\s+(\w+)\s*\{([^{}]*)\}\s*;/m) { |n, b| named[n] = b }
    out = []
    text.scan(/struct\s*\{([^{}]*)\}\s*(\w+)\s+SEC\("\.maps"\)/m) { |b, n| out << map_body(b, n, :maps) }
    text.scan(/struct\s+(\w+)\s+(\w+)\s+SEC\("\.maps"\)/) do |t, n|
      out << map_body(named[t], n, :maps) if named[t]
    end
    text.scan(/SEC\("\.struct_ops(?:\.link)?"\)\s*struct\s+\w+\s+(\w+)/m) do |n|
      out << MapDecl.new(name: n[0], type: "STRUCT_OPS", form: :struct_ops)
    end
    out << MapDecl.new(name: ".rodata", type: "ARRAY", form: :rodata) if text =~ /^\s*volatile const /
    text.scan(/^\s*private\((\w+)\)/) do |n|
      out << MapDecl.new(name: ".data.#{n[0]}", type: "ARRAY", form: :data_section)
    end
    LIBBPF_HEADER_MAPS.each do |hdr, maps|
      next unless text.include?("#include <#{hdr}>")
      maps.each { |n, t| out << MapDecl.new(name: n, type: t, form: :libbpf_header) }
    end
    text.scan(/SEC\("(\.[^"]*)"\)/) do |s|
      sec = s[0].sub(/\A\./, "")
      next if MAP_SEC_NOT_A_MAP.include?(sec) || sec.start_with?("data.")
      out << MapDecl.new(name: s[0], type: nil, form: :unknown)
    end
    out.uniq { |d| [d.name, d.form] }
  end

  # The probes the map sweep compiles for syntax that creates a map without
  # naming a builtin. Kept here rather than in a separate script, so the gate
  # owns every surface it measures.
  MAP_SYNTAX_PROBES = {
    top_ivar:   "@n = 0\n\ndef kprobe__do_sys_openat2\n  @n = @n + 1\n  0\nend\n",
    class_ivar: "class C\n  def incr(d)\n    @x = @x + d\n    @x\n  end\nend\n",
    param:      "param :target_pid, default: 0\n\ndef kprobe__do_sys_openat2\n  n = target_pid\n  n\nend\n",
    filter_by:  "filter_by :pid\n\n@n = 0\n\ndef kprobe__do_sys_openat2\n  @n = @n + 1\n  0\nend\n",
  }.freeze

  MAP_UNIT = "u"   # fixed so <unit> in an advertised map name is substitutable

  def map_probe_source(kind, name)
    case kind
    when :builtin
      call = call_text(name)
      source(shape_for(name), call, free_vars(name, call))
    when :syntax then MAP_SYNTAX_PROBES.fetch(name.to_sym)
    when :attach then attach_source(name.to_sym, "zzmap")
    else raise "affordance gate: unknown map probe kind #{kind.inspect}"
    end
  end

  # `<unit>` is the program's unit name; `<ivar>`/`<class>`/`<N>` vary with what
  # the author wrote. Everything else must match literally.
  def map_name_re(pattern)
    parts = pattern.split(/(<unit>|<ivar>|<class>|<N>)/).map do |p|
      case p
      when "<unit>" then Regexp.escape(MAP_UNIT)
      when "<ivar>", "<class>" then "[A-Za-z0-9_]+"
      when "<N>" then "[0-9]+"
      else Regexp.escape(p)
      end
    end
    /\A#{parts.join}\z/
  end

  # [:ok | :missing | :mismatch | :other, message]. Only `declared_as: :maps`
  # entries have their properties compared: the other four forms create a map
  # that the emitted C does not describe (libbpf or a macro does), so the gate
  # can check that the form is present and no more -- which is why those entries
  # must carry `measured`, and why a unit test refuses one that does not.
  MAP_COMPARED = %i[type max_entries key value key_size value_size flags values_of].freeze

  def check_map(entry, decls)
    return [:other, "the probe surface did not compile"] if decls.nil?
    re   = map_name_re(entry[:map])
    hits = decls.select { |d| d.name =~ re }
    want = entry[:count] || 1
    if hits.empty?
      near = decls.map(&:name).sort.first(6).join(" ")
      return [:missing, "probe #{entry[:probe]} emitted no map named #{entry[:map]} " \
                        "(saw: #{near.empty? ? '(none)' : near})"]
    end
    return [:mismatch, "expected #{want} map(s) matching #{entry[:map]}, found #{hits.size}"] if hits.size != want
    return [:ok, nil] unless entry[:declared_as] == :maps
    hits.each do |d|
      MAP_COMPARED.each do |f|
        got = d[f]
        # The unit name is in the map's own symbol AND in the record struct types
        # it carries (`struct <unit>_http_pending_st`), so expand it on both.
        exp = entry[f].is_a?(String) ? entry[f].gsub("<unit>", MAP_UNIT) : entry[f]
        next if exp.nil? && got.nil?
        next if exp.to_s == got.to_s
        return [:mismatch, "#{d.name}: affordance says #{f}=#{exp.inspect}, codegen emitted #{got.inspect}"]
      end
    end
    [:ok, nil]
  end

  # Compile the probe; return [:compiled | :refused, message, shape, call, reason].
  # "Compiled" also requires that the call PRODUCED something: a call the codegen
  # silently drops is not evidence that the builtin exists. The witness is the
  # same probe with the call deleted -- identical output means the call was air.
  #
  # `call` / `vars` are overridable only for the self-check, which needs to
  # hand this method an input whose correct verdict is known in advance.
  def check(dir, tag, name, call: nil, vars: nil)
    call ||= call_text(name)
    vars ||= free_vars(name, call)
    shape = shape_for(name)
    with    = File.join(dir, "#{tag}_a.rb")
    without = File.join(dir, "#{tag}_b.rb")
    File.write(with, source(shape, call, vars))
    out, err, st = cap3(CC, with, "#{tag}_a")
    unless st.success?
      return [:refused, err.lines.map(&:strip).reject(&:empty?).first.to_s, shape, call, :died]
    end
    File.write(without, source(shape, "@hits = @hits + 0", vars))
    out2, _e2, st2 = cap3(CC, without, "#{tag}_a")
    if st2.success? && out2 == out
      return [:refused, "compiled, but emitted C identical to the call-less twin (the call produced nothing)",
              shape, call, :no_effect]
    end
    unless out.include?("_inner")
      return [:refused, "compiled, but no _inner was emitted (the method was not eBPF-eligible)",
              shape, call, :no_inner]
    end
    [:compiled, nil, shape, call, nil]
  end

  # ---- arity audit --------------------------------------------------------
  # The declared arity (the signature table) is a claim about a BOUNDARY: "this
  # builtin takes N arguments". The C handlers enforce it with inline
  # `if (na != N) die(...)` checks -- per handler, not from a table -- so the
  # claim and the enforcement can drift per builtin, and an axis with no
  # lockstep is the kind that does. This probe asks the codegen directly:
  # compile the affordance's own example (positive control), then the same call
  # with one surplus argument appended.
  #   :enforced          surplus die'd (the boundary is real)
  #   :accepted          surplus compiled and CHANGED the output (it went somewhere)
  #   :ignored           surplus compiled and the output is byte-identical
  #                      (the argument silently vanished -- the worst shape)
  #   :shape_unsupported the positive control itself does not compile in this
  #                      harness (counted, never silently dropped)
  def arity_probe(dir, tag, name, plus_override: nil)
    call = call_text(name)
    vars = free_vars(name, call)
    shape = shape_for(name)
    plus = plus_override ||
           if call =~ /\(\s*\)\z/ then call.sub(/\(\s*\)\z/, "(0)")
           elsif call.end_with?(")") then call.sub(/\)\z/, ", 0)")
           else "#{call}(0)"
           end
    a = File.join(dir, "#{tag}_a.rb")
    File.write(a, source(shape, call, vars))
    oa, ea, sa = cap3(CC, a, "#{tag}_a")
    return [:shape_unsupported, ea.lines.map(&:strip).reject(&:empty?).first.to_s, call] unless sa.success?
    b = File.join(dir, "#{tag}_b.rb")
    File.write(b, source(shape, plus, vars))
    # same base name as the control on purpose: the unit name is baked into the
    # generated C (map names, header comment), so a different base would make
    # every pair "differ" and the :ignored verdict unreachable (measured).
    ob, eb, sb = cap3(CC, b, "#{tag}_a")
    return [:enforced, eb.lines.map(&:strip).reject(&:empty?).first.to_s, plus] unless sb.success?
    ob == oa ? [:ignored, nil, plus] : [:accepted, nil, plus]
  end

  # ---- per-target positive claims -----------------------------------------
  # A row in the targets table claims "this builtin exists on target T". The
  # negative half -- it must NOT compile under the linux codegen -- has been
  # measured since the table landed. This is the positive half, and until it
  # existed nobody asked it: the claim's own example must COMPILE under target
  # T's codegen, and the call must be load-bearing there (the call-less twin
  # must differ, the same :ignored trap the arity probe closes).
  #
  # Each target is driven through its codegen's env switch; a target with no
  # mapping here aborts the run rather than being skipped, because a target the
  # gate cannot drive is a target nothing checks.
  TARGET_CCENV = { "amp" => "SPNL_AMP_M7" }.freeze

  # The smallest program each target's codegen accepts, with the call spliced
  # in. AMP: one handler with an ivar RMW (the M-core path needs an eligible
  # handler and gives the twin something to keep). Free variables in the example
  # are declared rather than left dangling -- an undeclared local dies for a
  # reason that has nothing to do with the claim under test.
  def target_probe_source(target, call, vars = [])
    decls = vars.map { |v| "  #{v} = 0\n" }.join
    case target
    when "amp"
      "def kprobe__vfs_read\n  @h = @h + 1\n#{decls}  #{call}\nend\n"
    end
  end

  def target_claim_probe(dir, tag, target, envk, call, vars = [])
    src = target_probe_source(target, call, vars) or return [:no_shape, nil]
    a = File.join(dir, "#{tag}_a.rb")
    File.write(a, src)
    oa, ea, sa = cap3({ envk => "1" }, CC, a, "#{tag}_a")
    return [:died, ea.lines.map(&:strip).reject(&:empty?).first.to_s] unless sa.success?
    b = File.join(dir, "#{tag}_b.rb")
    File.write(b, target_probe_source(target, "@h = @h + 0", vars))
    # same base name as the control, for the reason arity_probe spells out: the
    # unit name is baked into the generated C, so a different base would make
    # every pair differ and the no-effect verdict unreachable.
    ob, _eb, sb = cap3({ envk => "1" }, CC, b, "#{tag}_a")
    return [:no_effect, "call-less twin emitted identical output"] if sb.success? && ob == oa
    [:compiled, nil]
  end

  # ---- hook-legality matrix -----------------------------------------------
  # CONTEXT_REQUIREMENTS' :kinds axis claims, per builtin, WHERE it may be
  # written. That axis was measured drifting wherever nothing checked it, and
  # only two groups gained a lockstep test; the rest still rest on prose. This
  # probe asks the codegen directly, both ways:
  #   claimed kind, probe dies       -> the claim advertises a place that refuses
  #   unclaimed kind, probe compiles -> the claim hides a legal move, or a gate
  #                                     is missing
  # A die in an unclaimed kind needs no reason check: any refusal counts, the
  # only violation on that side is silent acceptance.
  def kind_probe(dir, tag, name, kind)
    call = call_text(name)
    vars = free_vars(name, call)
    shape = KIND_TO_SHAPE[kind] or return [:no_shape, nil]
    f = File.join(dir, "#{tag}.rb")
    File.write(f, source(shape, call, vars))
    _o, err, st = cap3(CC, f, tag)
    st.success? ? [:compiled, nil] : [:died, err.lines.map(&:strip).reject(&:empty?).first.to_s]
  end

  # ---- the controls that do NOT deplete -----------------------------------
  #
  # The WITHDRAWN sets used to BE the negative control: "a demoted surface must
  # still fail". That works, and it is EXHAUSTED BY SUCCESS -- as those surfaces
  # get re-ported, two of the four sets reach zero (the sugar half already hit it:
  # it printed all-green numbers and then aborted). A gate whose detection power
  # is backed by an inventory of broken things gets weaker as the tree gets
  # healthier, and it pushes each implementer to leave a fake entry in the
  # SHIPPED affordance to keep the gate armed -- the exact kind of lie the
  # affordance must not contain.
  #
  # So the two jobs the withdrawn set was doing are separated by lifetime:
  #
  #   capability      "can this gate still say no?" -- synthesised in memory,
  #                   never depletes. That is what these self-checks are.
  #   correspondence  "the affordance's withdrawn record and the codegen's
  #                   refusals are the same set" -- a statement ABOUT the
  #                   inventory, so it is vacuously true when the inventory is
  #                   empty, and that is the CORRECT answer: nothing is withdrawn.
  #
  # The substitution is only EXACT for one vocabulary, so it was MEASURED, per
  # vocabulary, rather than assumed:
  #
  #   builtin  a withdrawn name and a name that never existed hit the SAME C path
  #            (`CallNode not yet ported (Stage 1): <name>`) -- the synthetic
  #            control is a full substitute.
  #   attach   NOT the same. A withdrawn kind hits CC_WITHDRAWN_ATTACH (exit 1,
  #            loud); an unknown prefix is exit 0 + SEC("syscall") -- the silent
  #            degradation itself. So the self-check covers the gate's comparison
  #            and cc_withdrawn_attach_prefixes covers the table's existence.
  #   sugar    NOT the same (its one entry's refusal IS the attach table's),
  #            though an unknown pkt.* member is refused by its own C path.
  #   map      WITHDRAWN_MAPS never tested a refusal path at all -- `mrevived` is
  #            a set intersection, so it was never a detection control. The map
  #            half's real controls are already the two self-checks.
  #
  # Each self-check is anchored to a LIVE claim and aborts if that claim is gone,
  # so the control cannot quietly stop referring to anything -- which is the
  # failure this whole section is about.
  SELFCHECK_BUILTIN = "hist_observe"   # live, arity 1, domain-shaped kprobe
  SELFCHECK_ATTACH  = :xdp             # live, flat surface, stable SEC
  SELFCHECK_SUGAR   = "pkt.l4.proto"   # live; anchors the pkt.* chain family

  # A name nothing implements, written in the documented shape of one that works.
  # Must be REFUSED, and refused with :died -- the loud shape.
  def selfcheck_builtin_absent(dir)
    absent = "#{SELFCHECK_BUILTIN}_zz_absent_name"
    call   = call_text(SELFCHECK_BUILTIN).sub(SELFCHECK_BUILTIN, absent)
    v, _m, _s, _c, reason = check(dir, "bsc_absent", SELFCHECK_BUILTIN,
                                  call: call, vars: free_vars(absent, call))
    v == :refused ? reason : v
  end

  # A "call" that emits nothing. The probe and its call-less twin are the same
  # text BY CONSTRUCTION, so the only thing that can report this is the twin
  # witness inside `check`. Delete that witness and this half goes green -- which
  # is precisely what it is here to notice. (Tautological input on purpose: like
  # the sugar half's deliberately mismatched pair, it tests the gate's logic, not
  # the C.)
  def selfcheck_builtin_no_effect(dir)
    v, _m, _s, _c, reason = check(dir, "bsc_noop", SELFCHECK_BUILTIN, call: "@hits = @hits + 0")
    v == :refused ? reason : v
  end

  # Stage 1 of the attach verdict: the emitted SEC is compared against the
  # affordance's promise. Corrupt the promise in memory (the sugar self-check's
  # move) and the run must come back :wrong_sec.
  def selfcheck_attach_wrong_sec(dir)
    _v, _m, _w, reason = check_attach(dir, "asc_sec", SELFCHECK_ATTACH,
                                      want_sec: "#{promised_sec(SELFCHECK_ATTACH)}_zz_never_promised")
    reason
  end

  # Stage 2, and the reason there are two: stage 1 alone was MEASURED to miss
  # `on :timer`, whose advertised SEC ("syscall") is the same string the
  # silent degradation emits -- the tell is that the BODY never reaches the C.
  # Ask for a marker the probe provably does not contain; must be :no_body.
  def selfcheck_attach_no_body(dir)
    _v, _m, _w, reason = check_attach(dir, "asc_body", SELFCHECK_ATTACH,
                                      want_marker: "zz_marker_never_written")
    reason
  end

  # Absence, for the sugar half: a chain member nobody implements must be refused
  # the same way a withdrawn spelling is. Anchored on the pkt.* family existing.
  def selfcheck_sugar_absent(dir)
    v, = check_withdrawn_sugar(dir, "ssc_absent", "pkt.zz_absent_member", { shape: :xdp })
    v
  end

  # ---- the attach refusal lives in TWO places -----------------------------
  # The affordance table says WHAT is withdrawn (and is what this gate probes);
  # CC_WITHDRAWN_ATTACH in the C codegen is what actually refuses. If an entry
  # leaves the affordance and its C prefix stays, nothing probes it any more and
  # nothing says so -- the control disappears silently, which is this section's
  # own problem one level down. Requiring the two to be the SAME SET is an invariant
  # that keeps its meaning (and stays cheap) when both are empty.
  CC_SOURCE = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")

  # nil means "could not read the table" -- never [] , because an empty list and
  # an unreadable one must not look alike to the caller.
  def cc_withdrawn_attach_prefixes
    return nil unless File.exist?(CC_SOURCE)
    body = File.read(CC_SOURCE)[/CC_WITHDRAWN_ATTACH\[\][^{]*\{(.*?)\n\};/m] or return nil
    body.scan(/\{\s*"([^"]+)"/).flatten
  end

  # The comparison itself, lifted out of main so the self-check can drive it with
  # perturbed inputs. `cc` = prefixes the codegen refuses on;
  # `aff` = {kind => method_prefix} the affordance records as withdrawn.
  # Matching is by SUBSTRING in both directions because a C refusal prefix is the
  # `def` prefix without its trailing separator (`xdp_tail` vs `xdp_tail__`).
  def correspondence(cc, aff)
    out = []
    cc.each { |p| out << [:codegen_only, p] unless aff.values.any? { |m| m.to_s.include?(p) } }
    aff.each { |k, m| out << [:affordance_only, k] unless cc.any? { |p| m.to_s.include?(p) } }
    out
  end

  # ---- the THIRD storey ------------------------------------------------------
  # This gate already separates "can it still say no?" (a self-check, synthesised,
  # never depletes) from "do the record and the refusals agree?" (correspondence,
  # a statement ABOUT an inventory, vacuously true when the inventory is empty --
  # and that is the correct answer). It then left the correspondence check itself
  # with no control, and said so.
  #
  # That gap closed the moment the demoted surfaces were re-ported: BOTH sides are
  # empty today, so the check compares [] with [] every run and prints orphan=0. A
  # comparison that has quietly stopped comparing -- a broken regex, an `any?`
  # that became `all?`, the substring rule inverted -- prints the identical line.
  # The other four vocabularies have had this control for a while; this one is the
  # asymmetry that was named in the gate's own follow-ups.
  #
  # The fix is the same move one storey up: do not anchor on a live entry (there
  # are none, by design). SYNTHESISE one side and demand the named verdict. Both
  # directions, because they are different code paths, and the failure this whole
  # section exists for -- a refusal in the C that nothing probes any more -- is
  # the `codegen_only` one.
  SELFCHECK_CORR_PREFIX = "zz_selfcheck_no_such_prefix__"
  def selfcheck_correspondence(cc, aff)
    { codegen_only:
        correspondence(cc + [SELFCHECK_CORR_PREFIX], aff)
          .any? { |d, w| d == :codegen_only && w == SELFCHECK_CORR_PREFIX } ? :codegen_only : :MISSED,
      affordance_only:
        correspondence(cc, aff.merge(:zz_selfcheck_kind => SELFCHECK_CORR_PREFIX))
          .any? { |d, w| d == :affordance_only && w == :zz_selfcheck_kind } ? :affordance_only : :MISSED }
  end
end

# --- main -----------------------------------------------------------------
# Guarded so a unit test can load the module and check the gate's own invariants
# (every builtin resolves to a shape it can actually write, the probe is
# well-formed, an unavailable codegen aborts instead of passing) without needing
# the Linux in-process binary.
if $PROGRAM_NAME == __FILE__
only = nil
list = false
section = "all"
args = ARGV.dup
while (a = args.shift)
  case a
  when "--only" then only = args.shift
  when "--list" then list = true
  when "--section" then section = args.shift
  else abort "usage: affordance_gate.rb [--only NAME] [--list] " \
             "[--section builtins|attach|sugar|syntax|maps|arity|ctxgate]"
  end
end
abort "usage: --section builtins|attach|sugar|syntax|maps|arity|ctxgate|all" unless
  %w[all builtins attach sugar syntax maps arity ctxgate].include?(section)
do_builtins = %w[all builtins].include?(section)
# The declared-arity boundary. Audited first (157 handlers enforced it, 38 were
# silent), folded into the declared-arity table in
# src/codegen_c/builtin_schema.h, enforcing since -- a builtin that silently
# swallows a surplus argument fails the gate until it gets a row there or its
# handler grows its own (richer) check.
do_arity    = %w[all arity].include?(section)
# The hook-legality matrix. Audited first (73 silent acceptances across four
# ungated families: the redirect-map trio, the sock_addr readers, the scx
# kfuncs and the qdisc kfuncs), folded into context gates in the codegen,
# enforcing since -- a builtin that compiles in a kind its claim excludes fails
# the gate until it gets a gate or the claim widens (whichever the C semantics
# say is true).
do_ctxgate  = %w[all ctxgate].include?(section)
do_attach   = %w[all attach].include?(section)
do_sugar    = %w[all sugar].include?(section)
do_syntax   = %w[all syntax].include?(section)
do_maps     = %w[all maps].include?(section)

# The codegen is what this gate is ABOUT, so its absence is reported before any
# section's own preconditions -- otherwise the message a caller sees depends on
# which other tool happens to be missing too (CI builds spinel in a later job,
# so the syntax section's spinel check fired first and masked this one).
abort "affordance gate: production codegen missing: #{CC}\n" \
      "  It is the in-process codegen binary and needs a built deps/spinel on Linux.\n" \
      "  Run this in the build container:\n" \
      "    container exec spnlbuild sh -c 'cd /work && ruby tools/affordance_gate.rb'" unless File.executable?(CC)

advertised = (do_builtins || do_arity) ? CAP.all_builtins.sort : []
withdrawn  = do_builtins ? CAP::WITHDRAWN.keys.sort : []
akinds     = do_attach ? CAP::ATTACH_KINDS.map { |a| a[:kind] } : []
awithdrawn = do_attach ? CAP::WITHDRAWN_ATTACH.keys : []
sugars     = do_sugar ? CAP.surface_sugar : []
swithdrawn = do_sugar ? CAP::WITHDRAWN_SUGAR.keys : []
syntaxes   = do_syntax ? CAP::SYNTAX : []
ywithdrawn = do_syntax ? CAP::WITHDRAWN_SYNTAX.keys : []
rejects    = do_syntax ? CAP::RUBY_SUBSET[:rejected].select { |r| r[:probe] } : []
maps       = do_maps ? CAP::MAPS : []
if only
  advertised.select! { |b| b == only }
  withdrawn.select! { |b| b == only }
  akinds.select! { |k| k.to_s == only }
  awithdrawn.select! { |k| k.to_s == only }
  sugars = sugars.select { |s| s[:id].to_s == only }
  swithdrawn.select! { |s| s == only }
  syntaxes = syntaxes.select { |s| s[:id].to_s == only }
  ywithdrawn.select! { |s| s == only }
  rejects = rejects.select { |r| r[:flag].to_s == only }
  maps = maps.select { |m| m[:id].to_s == only }
end

if list
  (advertised.map { |b| [b, :advertised] } + withdrawn.map { |b| [b, :withdrawn] }).each do |b, kind|
    puts format("  %-10s %-26s shape=%-16s %s", kind, b, AffordanceGate.shape_for(b), AffordanceGate.call_text(b))
  end
  akinds.each { |k| puts format("  %-10s %-26s promises SEC(%s)", "attach", k, AffordanceGate.promised_sec(k).inspect) }
  awithdrawn.each { |k| puts format("  %-10s %-26s must be REFUSED", "attach-wd", k) }
  sugars.each do |s|
    puts format("  %-10s %-26s %-9s %s <=> %s", "sugar", s[:id], s[:equiv],
                s[:sugar].to_s.lines.first.to_s.strip, s[:flat].to_s.lines.first.to_s.strip)
  end
  swithdrawn.each { |s| puts format("  %-10s %-26s must be REFUSED", "sugar-wd", s) }
  syntaxes.each do |s|
    puts format("  %-10s %-26s %-8s lowers_to %s", "syntax", s[:id], s[:form],
                s[:lowers_to].inspect)
  end
  ywithdrawn.each { |s| puts format("  %-10s %-26s must be REFUSED", "syntax-wd", s) }
  maps.each do |m|
    puts format("  %-10s %-26s %-14s %-12s <- %s %s", "map", m[:id], m[:type],
                m[:declared_as], m[:probe_kind], m[:probe])
  end
  exit 0
end

# A name in both sets is a contradiction the gate cannot resolve, so say so
# rather than pick one.
both = CAP.all_builtins & CAP::WITHDRAWN.keys
unless both.empty?
  abort "affordance gate: #{both.join(', ')} are BOTH advertised and withdrawn.\n" \
        "  Pick one: implement it and drop it from Capabilities::WITHDRAWN, or\n" \
        "  drop it from SIG_TABLE/DOMAINS."
end
aboth = CAP::ATTACH_KINDS.map { |a| a[:kind] } & CAP::WITHDRAWN_ATTACH.keys
unless aboth.empty?
  abort "affordance gate: attach kind(s) #{aboth.join(', ')} are BOTH advertised and withdrawn."
end
# Every advertised kind must be probeable, or the gate silently stops covering it.
noshape = CAP::ATTACH_KINDS.map { |a| a[:kind] } - AffordanceGate::ATTACH_SHAPES.keys
unless noshape.empty? || !do_attach
  abort "affordance gate: no probe shape for attach kind(s) #{noshape.join(', ')}.\n" \
        "  Add one to ATTACH_SHAPES. A kind the gate cannot write is a kind nothing checks,\n" \
        "  which is exactly how four attach kinds stayed advertised while silently dead."
end
# The affordance's withdrawn ATTACH record and the codegen's refusal table must
# be the same set. This is the half of the old empty-set abort that is actually
# about the inventory -- and unlike that abort it stays meaningful when both are
# empty, which is where re-porting the demoted surfaces is heading.
cc_prefixes = nil
aorphan = []   # a refusal and its record that no longer point at each other
corrself = {}  # the correspondence check's own control (the third storey)
if do_attach
  cc_prefixes = AffordanceGate.cc_withdrawn_attach_prefixes
  abort "affordance gate: could not read CC_WITHDRAWN_ATTACH out of\n" \
        "  #{AffordanceGate::CC_SOURCE}\n" \
        "  That table is what actually refuses a withdrawn attach kind; if the gate cannot\n" \
        "  see it, it cannot tell an empty refusal set from an unreadable one." if cc_prefixes.nil?
  aff_prefixes = CAP::WITHDRAWN_ATTACH.transform_values { |w| w[:method_prefix].to_s }
  aorphan = AffordanceGate.correspondence(cc_prefixes, aff_prefixes)
  # ...and prove, this run, that the comparison above can still produce each of
  # its two verdicts. Both sides are empty in the current tree, so without this
  # the line "orphan=0" is printed by a check that never compared anything.
  corrself = AffordanceGate.selfcheck_correspondence(cc_prefixes, aff_prefixes) unless only
end
# Same rule for sugar: a claim this gate cannot write is a claim nothing checks.
if do_sugar
  bad = CAP.surface_sugar.reject { |s| s[:form] == :attach || AffordanceGate::SUGAR_SHAPES.key?(s[:shape]) }
  unless bad.empty?
    abort "affordance gate: no probe shape for sugar claim(s) " \
          "#{bad.map { |s| "#{s[:id]} (shape=#{s[:shape].inspect})" }.join(', ')}.\n" \
          "  Add one to SUGAR_SHAPES."
  end
  dups = CAP.surface_sugar.map { |s| s[:id] }.tally.select { |_, v| v > 1 }.keys
  abort "affordance gate: duplicate sugar claim id(s) #{dups.join(', ')}" unless dups.empty?
end
# Same rule again for syntax, plus the two coverage authorities: a claim the gate
# cannot write, or an authority it cannot read, is silence -- which is the failure
# this vocabulary was in for a year.
cc_nodes = nil
cc_ops = nil
if do_syntax
  dups = CAP::SYNTAX.map { |s| s[:id] }.tally.select { |_, v| v > 1 }.keys
  abort "affordance gate: duplicate syntax claim id(s) #{dups.join(', ')}" unless dups.empty?
  bad = CAP::SYNTAX.reject { |s| s[:form] == :attach || AffordanceGate::SUGAR_SHAPES.key?(s[:shape]) }
  unless bad.empty?
    abort "affordance gate: no probe shape for syntax claim(s) " \
          "#{bad.map { |s| "#{s[:id]} (shape=#{s[:shape].inspect})" }.join(', ')}.\n" \
          "  Add one to SUGAR_SHAPES (syntax and sugar share the harness)."
  end
  bad = CAP::SYNTAX.reject { |s| s[:lowers_to].is_a?(String) && !s[:lowers_to].empty? }
  unless bad.empty?
    abort "affordance gate: syntax claim(s) #{bad.map { |s| s[:id] }.join(', ')} declare no\n" \
          "  `lowers_to`. Without it the claim is only \"it compiles\", which is stage 1 --\n" \
          "  and stage 1 cannot tell a literal `n.times` from a silent fall back to bpf_loop."
  end
  cc_nodes = AffordanceGate.cc_lowering_node_types
  cc_ops   = AffordanceGate.cc_binary_ops
  if cc_nodes.nil? || cc_ops.nil?
    abort "affordance gate: could not read the syntax coverage authorities out of\n" \
          "  #{AffordanceGate::CC_SOURCE}\n" \
          "  (#{CAP::SYNTAX_COVERAGE_AUTHORITIES.values.map { |a| a[:functions].join('/') }.join(' and ')}).\n" \
          "  Those are what the reverse direction compares against; unreadable and empty must\n" \
          "  not look alike, or `uncovered=0` is a vacuous pass."
  end
  unless File.executable?(AffordanceGate::SPINEL)
    abort "affordance gate: spinel (--dump-ast) not found: #{AffordanceGate::SPINEL.inspect}\n" \
          "  The coverage direction asks which AST node types each probe contains, and it uses\n" \
          "  the SAME front end the codegen lowers with. Build deps/spinel (scripts/setup.sh),\n" \
          "  or point $SPNL_SPINEL_BIN at it."
  end
end
if do_maps
  dups = CAP::MAPS.map { |m| m[:id] }.tally.select { |_, v| v > 1 }.keys
  abort "affordance gate: duplicate map id(s) #{dups.join(', ')}" unless dups.empty?
  bad = CAP::MAPS.reject { |m| m[:created_by].include?(m[:probe]) }
  unless bad.empty?
    abort "affordance gate: map claim(s) #{bad.map { |m| m[:id] }.join(', ')} name a `probe` that is\n" \
          "  not in their own `created_by`. The probe must be one of the surfaces that make the map."
  end
end

_o, _e, _st = Open3.capture3(CC)
unless "#{_o}#{_e}".include?("usage:")
  abort "affordance gate: #{CC} exists but does not run here (no usage line, exit #{_st.exitstatus.inspect}).\n" \
        "  build/ is bind-mounted into the container, so this is usually the other platform's binary.\n" \
        "  A gate that cannot run the codegen must not report a pass."
end

broken = []   # advertised but refused  -- the builtin failure
revived = []  # withdrawn but compiles  -- the opposite mistake
abroken = []  # advertised kind, promised SEC not emitted -- the attach failure
arevived = [] # withdrawn kind still accepted -- the silent no-op is back
sbroken = []  # advertised sugar: died, diverged, or the gate wrote a bad pair
srevived = [] # withdrawn sugar still accepted
selfcheck = nil
bself = {}    # builtin self-check
aself = {}    # attach self-check (both stages)
sself = nil   # sugar absence half
# NB: aorphan is declared with the correspondence check ABOVE, not here. Ruby
# creates a local at the point the assignment is PARSED, so a declaration below
# its first use is a NameError -- and one that only fires when the list is
# non-empty, i.e. exactly when the check has something to report. Caught by
# actually running the gate against a simulated depleted tree, which is the whole
# argument for running that world instead of reasoning about it.
ybroken = []   # advertised syntax: died, lowered elsewhere, or a needle that proves nothing
yrevived = []  # withdrawn syntax still accepted
yuncov_nodes = []  # a node type the lowering accepts that no claim exercises -- the SILENT one
yuncov_ops = []    # ditto for the binary-operator table
yreject = []   # a construct RUBY_SUBSET[:rejected] calls impossible that the product accepts
yself = {}
mbroken = []   # advertised map: not emitted, or emitted with other properties
muncovered = [] # a map came out that the affordance never mentions -- the SILENT one
mrevived = []  # a withdrawn map type is back without being re-advertised
msweep = 0
mseen = []    # every distinct map the sweep saw -- printed so a scanner that
              # stopped finding anything cannot look like "nothing uncovered"
mselfcheck = []
Dir.mktmpdir("affordance-gate") do |dir|
  if do_ctxgate
    scope = CAP::CONTEXT_REQUIREMENTS.select { |_, r| r[:kinds] }
    shapeable = SHAPES.keys
    sets = scope.group_by { |_, r| r[:kinds] }
    viol = Hash.new { |h, k| h[k] = [] }
    probes = 0
    # (1) representative x full kind space: one builtin per distinct kind-set,
    # probed in EVERY shapeable kind -- catches claim-narrower drift anywhere.
    sets.each_with_index do |(kset, entries), si|
      rep = entries.map(&:first).sort.first
      shapeable.each_with_index do |k, ki|
        v, msg = AffordanceGate.kind_probe(dir, "cg#{si}_#{ki}", rep, k)
        probes += 1
        if kset.include?(k) && v == :died
          viol[:claimed_kind_died] << [rep, k, msg]
        elsif !kset.include?(k) && v == :compiled
          viol[:undeclared_kind_accepted] << [rep, k]
        end
      end
    end
    # (2) per-builtin membership: every entry gets one claimed-kind probe and
    # one unclaimed-kind probe (a builtin whose gate differs from its group's
    # representative would slip a matrix that only samples representatives).
    scope.each_with_index do |(b, r), i|
      ak = (r[:kinds] & shapeable).first
      dk = (%i[kprobe xdp tc_ingress sock_ops] - r[:kinds]).find { |k| shapeable.include?(k) }
      if ak
        v, msg = AffordanceGate.kind_probe(dir, "cm#{i}a", b, ak)
        probes += 1
        viol[:claimed_kind_died] << [b, ak, msg] if v == :died
      end
      if dk
        v, = AffordanceGate.kind_probe(dir, "cm#{i}d", b, dk)
        probes += 1
        viol[:undeclared_kind_accepted] << [b, dk] if v == :compiled
      end
    end
    puts format("  ctxgate  probed %4d  (%d builtins, %d kind-sets x %d shapeable kinds)  " \
                "claimed_died=%d  undeclared_accepted=%d",
                probes, scope.size, sets.size, shapeable.size,
                viol[:claimed_kind_died].size, viol[:undeclared_kind_accepted].size)
    viol[:claimed_kind_died].uniq.each do |b, k, msg|
      puts format("  -- claimed_kind_died:      %-24s in %-16s %s", b, k, msg.to_s[0, 80])
    end
    viol[:undeclared_kind_accepted].uniq.each do |b, k|
      puts format("  -- undeclared_kind_accepted: %-24s in %s", b, k)
    end
    # Synthesized self-checks. The classification predicate itself is a one-line
    # set test, so what actually needs re-proving each run is the arm underneath
    # it: that kind_probe can still SEE an acceptance and a refusal.
    # (a) has_cap in :kprobe compiles (a known-legal pair must read :compiled --
    #     if it reads :died, every acceptance is invisible and the matrix would
    #     report a clean 0 while measuring nothing)
    # (b) pkt_len in :kprobe dies (a known-illegal pair must read :died)
    sca_v, = AffordanceGate.kind_probe(dir, "cgsc_a", "has_cap", :kprobe)
    scb_v, = AffordanceGate.kind_probe(dir, "cgsc_b", "pkt_len", :kprobe)
    sc_a = sca_v == :compiled ? "caught" : "MISSED"
    sc_b = scb_v == :died ? "caught" : "MISSED"
    puts format("  ctxgate  self-check       undeclared_arm=%s claimed_arm=%s", sc_a, sc_b)
    abort "affordance gate: ctxgate self-check broken (undeclared_arm=#{sc_a}, claimed_arm=#{sc_b})" \
      unless sc_a == "caught" && sc_b == "caught"
    unless viol[:claimed_kind_died].empty?
      abort "affordance gate: #{viol[:claimed_kind_died].size} claim(s) advertise a kind that refuses " \
            "the builtin -- narrow the claim in CONTEXT_REQUIREMENTS, or fix the codegen gate."
    end
    unless viol[:undeclared_kind_accepted].empty?
      abort "affordance gate: #{viol[:undeclared_kind_accepted].size} builtin/kind pair(s) compile " \
            "where the claim says they cannot -- either the C gate is missing (add one) or the " \
            "claim hides a legal move (widen it)."
    end
    exit 0 if section == "ctxgate"
  end
  if do_arity
    tally = Hash.new { |h, k| h[k] = [] }
    advertised.each_with_index do |b, i|
      verdict, msg, probe = AffordanceGate.arity_probe(dir, "ar#{i}", b)
      tally[verdict] << [b, probe, msg]
    end
    puts "  arity    probed      #{advertised.size}  enforced=#{tally[:enforced].size}  " \
         "silent=#{tally[:accepted].size + tally[:ignored].size}  " \
         "shape_unsupported=#{tally[:shape_unsupported].size}"
    %i[ignored accepted shape_unsupported].each do |k|
      next if tally[k].empty?
      puts "  -- #{k}:"
      tally[k].each { |b, probe, _| puts format("     %-28s %s", b, probe) }
    end
    # Synthesized controls: the gate must re-prove it can say NO.
    # (a) the byte-comparison arm: probe with the surplus call FORCED equal to
    #     the control -- outputs are identical by construction, so anything but
    #     :ignored means the comparison is dead.
    # (b) the die-detection arm: a handler-enforced builtin with a surplus arg
    #     must come back :enforced.
    sc_ig, = AffordanceGate.arity_probe(dir, "arsc1", "ktime_ns",
                                        plus_override: AffordanceGate.call_text("ktime_ns"))
    sc_en, = AffordanceGate.arity_probe(dir, "arsc2", "has_cap")
    puts "  arity    self-check       identical_pair=#{sc_ig} surplus_on_enforced=#{sc_en}"
    abort "affordance gate: arity self-check broken (identical_pair=#{sc_ig}, want ignored) -- " \
          "the byte-comparison arm cannot detect a silently ignored argument" unless sc_ig == :ignored
    abort "affordance gate: arity self-check broken (surplus_on_enforced=#{sc_en}, want enforced)" unless sc_en == :enforced
    bad = tally[:accepted] + tally[:ignored]
    unless bad.empty?
      abort "affordance gate: #{bad.size} builtin(s) silently swallow a surplus argument -- " \
            "add each to cc_declared_arity in src/codegen_c/builtin_schema.h, or give " \
            "the handler its own (richer) check: #{bad.map(&:first).join(', ')}"
    end
    unless tally[:shape_unsupported].empty?
      abort "affordance gate: #{tally[:shape_unsupported].size} builtin(s) not probeable -- " \
            "a builtin the gate cannot write is a builtin nothing checks"
    end
    exit 0 if section == "arity"
  end
  # Before trusting "diverged=0", prove this run can still SEE a
  # divergence. A pair that is deliberately not equivalent (XDP::PASS vs
  # XDP_DROP) must come back diverged. Unlike the withdrawn sets -- which prove
  # the gate can still detect ABSENCE -- this proves it can detect a surface
  # that is present and wrong, which is the state sugar fails in.
  if do_sugar && !only
    live = CAP.surface_sugar.find { |s| s[:id] == :const_path_xdp_pass } or
      abort "affordance gate: the sugar self-check's reference claim is gone."
    v, m = AffordanceGate.check_sugar(dir, "selfchk", live.merge(flat: "XDP_DROP"))
    selfcheck = [v, m]
    # The other half -- absence. Until now the sugar section got that from
    # WITHDRAWN_SUGAR, an inventory that re-porting empties.
    CAP.surface_sugar.any? { |s| s[:sugar] == AffordanceGate::SELFCHECK_SUGAR } or
      abort "affordance gate: the sugar absence self-check's reference family is gone\n" \
            "  (#{AffordanceGate::SELFCHECK_SUGAR} is no longer an advertised sugar claim, so\n" \
            "  `pkt.zz_absent_member` is no longer a probe of the pkt.* chain's refusal)."
    sself = AffordanceGate.selfcheck_sugar_absent(dir)
  end
  # The builtin half's own controls, so it no longer depends on there being
  # broken builtins left. Two halves because `check` can say no in two shapes, and
  # the silent one (a call that emits nothing) is the one a text gate cannot see.
  if do_builtins && !only
    CAP.all_builtins.include?(AffordanceGate::SELFCHECK_BUILTIN) or
      abort "affordance gate: the builtin self-check's reference claim " \
            "(#{AffordanceGate::SELFCHECK_BUILTIN}) is no longer advertised.\n" \
            "  Point SELFCHECK_BUILTIN at another live builtin that takes an argument."
    bself[:absent_name]    = AffordanceGate.selfcheck_builtin_absent(dir)
    bself[:no_effect_call] = AffordanceGate.selfcheck_builtin_no_effect(dir)
  end
  # Both STAGES of the attach verdict. A one-stage self-check would
  # pass with the body check deleted, i.e. it would reproduce the `on :timer` hole.
  if do_attach && !only
    CAP::ATTACH_KINDS.any? { |a| a[:kind] == AffordanceGate::SELFCHECK_ATTACH } or
      abort "affordance gate: the attach self-check's reference kind " \
            "(#{AffordanceGate::SELFCHECK_ATTACH}) is no longer advertised.\n" \
            "  Point SELFCHECK_ATTACH at another live kind with a flat surface."
    aself[:wrong_sec]    = AffordanceGate.selfcheck_attach_wrong_sec(dir)
    aself[:body_missing] = AffordanceGate.selfcheck_attach_no_body(dir)
  end
  advertised.each_with_index do |b, i|
    verdict, msg, shape, call = AffordanceGate.check(dir, "adv#{i}", b)
    broken << [b, shape, call, msg] if verdict == :refused
  end
  withdrawn.each_with_index do |b, i|
    verdict, _msg, shape, call = AffordanceGate.check(dir, "wd#{i}", b)
    revived << [b, shape, call] if verdict == :compiled
  end
  akinds.each_with_index do |k, i|
    verdict, msg, want = AffordanceGate.check_attach(dir, "ak#{i}", k)
    abroken << [k, want, msg] if verdict == :broken
  end
  awithdrawn.each_with_index do |k, i|
    verdict, = AffordanceGate.check_withdrawn_attach(dir, "awd#{i}", k)
    arevived << k if verdict == :accepted
  end
  sugars.each_with_index do |s, i|
    verdict, msg = AffordanceGate.check_sugar(dir, "sg#{i}", s)
    sbroken << [s, verdict, msg] unless verdict == :ok
  end
  swithdrawn.each_with_index do |s, i|
    verdict, = AffordanceGate.check_withdrawn_sugar(dir, "swd#{i}", s, CAP::WITHDRAWN_SUGAR[s])
    srevived << s if verdict == :accepted
  end

  # The fifth vocabulary, both directions.
  #
  #   advertised  each SYNTAX claim compiles AND reaches its declared lowering,
  #               with the needle proven load-bearing by the construct-free twin.
  #   coverage    every node type the codegen's lowering dispatch accepts, and
  #               every operator in its binary-op table, must be exercised by some
  #               claim. This is the direction that sees SILENCE -- the way this
  #               vocabulary failed, and the lesson the map section taught.
  if do_syntax
    unless only
      CAP::SYNTAX.any? { |s| s[:id] == AffordanceGate::SELFCHECK_SYNTAX } or
        abort "affordance gate: the syntax self-check's reference claim " \
              "(#{AffordanceGate::SELFCHECK_SYNTAX}) is gone.\n" \
              "  Point SELFCHECK_SYNTAX at another live :expr claim."
      CAP::RUBY_SUBSET[:rejected].any? { |r| r[:flag] == AffordanceGate::SELFCHECK_SYNTAX_REJECT_FLAG } or
        abort "affordance gate: the syntax absence self-check is anchored on the affordance's\n" \
              "  own rejection of #{AffordanceGate::SELFCHECK_SYNTAX_REJECT_FLAG} (unbounded iteration), and that claim\n" \
              "  is gone. Without it, `while` being refused is an accidental gap rather than a\n" \
              "  stated one, and the control would be betting on the gap staying."
      live = CAP::SYNTAX.find { |s| s[:id] == AffordanceGate::SELFCHECK_SYNTAX }
      yself[:absent_construct]  = AffordanceGate.selfcheck_syntax_absent(dir)
      yself[:wrong_lowering]    = AffordanceGate.selfcheck_syntax_wrong(dir, live)
      yself[:needle_not_bearing] = AffordanceGate.selfcheck_syntax_not_load_bearing(dir, live)
      rlive = CAP::RUBY_SUBSET[:rejected].find { |r| r[:probe] && !r[:refusal].to_s.empty? } or
        abort "affordance gate: no RUBY_SUBSET[:rejected] entry carries both a `probe` and a\n" \
              "  `refusal`, so the rejected half has nothing to drive its reason self-check with."
      yself[:legal_accepted]  = AffordanceGate.selfcheck_rejected_accepts_legal(dir)
      yself[:reject_reason]   = AffordanceGate.selfcheck_rejected_wrong_reason(dir, rlive)
    end
    rejects.each_with_index do |r, i|
      verdict, msg = AffordanceGate.check_rejected(dir, "rj#{i}", r)
      yreject << [r, verdict, msg] unless verdict == :refused
    end
    syntaxes.each_with_index do |s, i|
      verdict, msg = AffordanceGate.check_syntax(dir, "sy#{i}", s)
      ybroken << [s, verdict, msg] unless verdict == :ok
    end
    ywithdrawn.each_with_index do |s, i|
      verdict, = AffordanceGate.check_withdrawn_syntax(dir, "ywd#{i}", s, CAP::WITHDRAWN_SYNTAX[s])
      yrevived << s if verdict == :accepted
    end

    # Coverage. Ask the codegen's own front end which node types (and which
    # operator names) each advertised claim's probe actually contains.
    vocab = {}
    CAP::SYNTAX.each_with_index do |s, i|
      v = AffordanceGate.probe_vocab(dir, "syv#{i}", AffordanceGate.syntax_source(s, :syntax))
      vocab[s[:id]] = v || [[], []]
    end
    seen_nodes = vocab.values.flat_map(&:first).uniq
    seen_ops   = vocab.values.flat_map(&:last).uniq
    yuncov_nodes = cc_nodes - seen_nodes
    yuncov_ops   = cc_ops - seen_ops

    # Self-check for the coverage half, the same shape the map section uses: hide
    # one claim and require the thing only it covers to be reported uncovered. The
    # claim to hide is COMPUTED (a node type exercised by exactly one claim), so
    # the control does not quietly stop referring to anything as the table grows.
    unless only
      solo = cc_nodes.map { |t| [t, vocab.select { |_, v| v[0].include?(t) }.keys] }
                     .find { |_, ids| ids.size == 1 }
      if solo.nil?
        abort "affordance gate: the syntax coverage self-check needs one node type that exactly\n" \
              "  one claim exercises, and there is none. Without it the run cannot re-prove that\n" \
              "  hiding a claim makes its node type uncovered, so `uncovered=0` means nothing."
      end
      t, ids = solo
      hidden = vocab.reject { |id, _| id == ids.first }
      yself[:hidden_claim] = hidden.values.flat_map(&:first).include?(t) ? :covered : :uncovered
    end
  end

  # One sweep, two directions.
  #
  # The sweep compiles EVERY surface the affordance advertises (builtins, the
  # map-creating syntax, attach kinds) and records the maps each one emits. From
  # it:
  #   advertised  each MAPS entry's probe must produce that map, with the
  #               properties the affordance states (declaration forms only).
  #   coverage    every map that came out of ANY surface must be covered by an
  #               entry. This is the direction that catches SILENCE, which is
  #               how this vocabulary failed: the implementation was healthy and
  #               the affordance simply said nothing.
  #   withdrawn   the map types that left with the withdrawn builtin and attach
  #               surfaces must not reappear un-advertised (half-revival).
  if do_maps
    triggers = {}
    CAP.all_builtins.each { |b| triggers[[:builtin, b]] = true }
    AffordanceGate::MAP_SYNTAX_PROBES.each_key { |s| triggers[[:syntax, s.to_s]] = true }
    CAP::ATTACH_KINDS.each { |a| triggers[[:attach, a[:kind].to_s]] = true }
    decls = {}
    triggers.each_key.with_index do |(kind, name), i|
      path = File.join(dir, "mp#{i}.rb")
      File.write(path, AffordanceGate.map_probe_source(kind, name))
      out, _err, st = AffordanceGate.cap3(CC, path, AffordanceGate::MAP_UNIT)
      decls[[kind, name]] = st.success? ? AffordanceGate.map_decls(out) : nil
    end
    msweep = decls.size

    maps.each do |m|
      v, msg = AffordanceGate.check_map(m, decls[[m[:probe_kind], m[:probe]]])
      mbroken << [m, v, msg] unless v == :ok
    end

    # Coverage. A map is covered when some entry's name pattern matches it AND
    # claims the same type -- a name that matches while the type disagrees is
    # not coverage, it is a second failure wearing the first one's name.
    covered = lambda do |d|
      CAP::MAPS.any? do |m|
        d.name =~ AffordanceGate.map_name_re(m[:map]) && (d.type.nil? || m[:type] == d.type)
      end
    end
    decls.each do |(kind, name), ds|
      Array(ds).each do |d|
        mseen << d
        muncovered << [kind, name, d] unless covered.call(d)
      end
    end
    muncovered.uniq! { |_k, _n, d| [d.name, d.type, d.form] }
    mseen.uniq! { |d| [d.name, d.form] }

    seen_types = decls.values.compact.flatten.map(&:type).compact.uniq
    mrevived = CAP::WITHDRAWN_MAPS.keys & seen_types

    # Self-check, two halves, because the two directions fail differently and a
    # degenerate gate is green on both counts. Unlike the withdrawn sets (which
    # prove the gate can still see ABSENCE), these prove it can still see a
    # WRONG property and an UNADVERTISED map -- the two states this vocabulary
    # actually fails in. Both are in-memory perturbations: nothing is written.
    unless only
      ref = CAP::MAPS.find { |m| m[:id] == :hist } or
        abort "affordance gate: the map self-check's reference claim (:hist) is gone."
      v, = AffordanceGate.check_map(ref.merge(max_entries: "999999"), decls[[ref[:probe_kind], ref[:probe]]])
      mselfcheck << [:wrong_property, v]
      probe_decls = Array(decls[[ref[:probe_kind], ref[:probe]]])
      hidden = CAP::MAPS.reject { |m| m[:id] == :hist }
      still_covered = probe_decls.any? do |d|
        d.name =~ AffordanceGate.map_name_re(ref[:map]) &&
          hidden.any? { |m| d.name =~ AffordanceGate.map_name_re(m[:map]) && m[:type] == d.type }
      end
      mselfcheck << [:unadvertised_map, still_covered ? :covered : :uncovered]
    end
  end
end

puts "-" * 72
puts "affordance gate (builtins / attach kinds / surface sugar / syntax / maps)"
# An empty withdrawn set is a true statement about the tree (nothing is
# withdrawn), not a hole in the gate -- the detection power lives in the
# self-checks now. Say which it is on the line itself, so the number cannot be
# read as "control missing".
EMPTY_NOTE = "  (record empty: nothing is withdrawn -- absence is the self-check's job)"
if do_builtins
  # existence coverage -- both directions from one extraction.
  ex = AffordanceGate.builtin_extracted_names
  abort "affordance gate: a declared builtin-coverage authority is unreadable " \
        "(BUILTIN_COVERAGE_AUTHORITIES names a function/array the extractor cannot find). " \
        "An unreadable authority must not look like an empty one." if ex.nil?
  excl = CAP::BUILTIN_COVERAGE_EXCLUSIONS.keys
  tonly = CAP.target_only_builtins.values.flatten.uniq
  uncov, unfound, tstale = AffordanceGate.existence_violations(ex, advertised, withdrawn, excl, tonly)
  n_mech = CAP::BUILTIN_COVERAGE_AUTHORITIES.sum { |_, a| (a[:functions] || a[:arrays]).size }
  puts format("  builtin  existence  %3d names from %d declared mechanisms  uncovered=%d  unfound=%d  " \
              "target_only=%d (stale=%d)",
              ex.size, n_mech, uncov.size, unfound.size, tonly.size, tstale.size)
  # A target-only builtin must REFUSE under this (linux) codegen -- if it
  # compiles here, the target declaration lies about the linux surface. And,
  # the other way round, each target row's claim must COMPILE under its own
  # target's codegen: without that half a row is only ever checked for what it
  # is NOT. (This summary block runs outside the sweep tmpdir, so the probes
  # get their own.)
  tleak = nil
  tclaims = { probed: 0, ok: 0, broken: [] }
  Dir.mktmpdir("affordance-tgl") do |tdir|
    tleak = tonly.reject do |b|
      v, = AffordanceGate.kind_probe(tdir, "tgl_#{b}", b, :kprobe)
      v == :died
    end
    # -- positive direction: every non-default (name, target) pair --
    CAP::BUILTIN_SCHEMA_JSON.fetch("targets").each_with_index do |row, ri|
      row.fetch("targets").each do |tgt|
        next if tgt == "linux"
        envk = AffordanceGate::TARGET_CCENV[tgt] or
          abort "affordance gate: no CC env mapping for target #{tgt} -- a target the " \
                "gate cannot drive is a target nothing checks; add it to TARGET_CCENV"
        exm = CAP::TARGET_BUILTIN_EXAMPLES[row["name"]]
        exm = CAP.example_for(row["name"]) if exm.nil? && CAP.all_builtins.include?(row["name"])
        abort "affordance gate: no probe example for target builtin #{row['name']} -- " \
              "add it to Capabilities::TARGET_BUILTIN_EXAMPLES (a claim the gate cannot " \
              "write is a claim nothing checks)" if exm.nil?
        vs = AffordanceGate.free_vars(row["name"], exm)
        v, msg = AffordanceGate.target_claim_probe(tdir, "tc#{ri}_#{tgt}", tgt, envk, exm, vs)
        tclaims[:probed] += 1
        if v == :compiled then tclaims[:ok] += 1
        else tclaims[:broken] << [row["name"], tgt, v, msg]
        end
      end
    end
    # -- self-check: the positive arm must be able to SEE a refusal. A
    # linux-only builtin under a restricted target's codegen must come back
    # :died; if it does not, every green above is vacuous.
    tsc, = AffordanceGate.target_claim_probe(tdir, "tsc", "amp", "SPNL_AMP_M7", "p = pid")
    @tclaim_sc = tsc == :died ? "caught" : "MISSED"
  end
  puts format("  builtin  target-only       linux-refusal %d/%d", tonly.size - tleak.size, tonly.size)
  puts format("  builtin  target-claims     %d/%d compiled under their target CC  refusal-visible=%s",
              tclaims[:ok], tclaims[:probed], @tclaim_sc)
  tclaims[:broken].each do |n, t, v, m|
    puts format("  -- target-claim broken:   %-20s on %-10s %s %s", n, t, v, m.to_s[0, 70])
  end
  abort "affordance gate: target-claims self-check broken (refusal-visible=#{@tclaim_sc}) -- " \
        "a positive arm that cannot see a refusal proves nothing" unless @tclaim_sc == "caught"
  unless tclaims[:broken].empty?
    abort "affordance gate: #{tclaims[:broken].size} target claim(s) do not hold under their " \
          "own target's codegen -- either the targets row is a lie (remove it) or the " \
          "lowering broke (fix it); the example lives in Capabilities::TARGET_BUILTIN_EXAMPLES " \
          "or, for a builtin linux also carries, in its ordinary affordance example."
  end
  # self-checks (synthesized, inventory-independent): (a) hide a claim that is
  # certainly recognized -> the reverse arm must flag it; (b) drop a whole
  # mechanism -> the forward arm must notice its builtins going unfound.
  sc_hidden = AffordanceGate.existence_violations(ex, advertised - ["ktime_ns"], withdrawn, excl, tonly)
                            .first.include?("ktime_ns") ? "caught" : "MISSED"
  ex_wo = AffordanceGate.builtin_extracted_names(
    CAP::BUILTIN_COVERAGE_AUTHORITIES.reject { |k, _| k == :helper_fns })
  sc_mech = AffordanceGate.existence_violations(ex_wo || [], advertised, withdrawn, excl, tonly)[1]
                          .include?("has_cap") ? "caught" : "MISSED"
  puts format("  builtin  self-check       hidden_claim=%s dropped_mechanism=%s", sc_hidden, sc_mech)
  abort "affordance gate: existence self-check broken (hidden_claim=#{sc_hidden}, " \
        "dropped_mechanism=#{sc_mech}) -- a coverage that cannot say no is vacuous" \
    unless sc_hidden == "caught" && sc_mech == "caught"
  unless uncov.empty?
    abort "affordance gate: #{uncov.size} name(s) the codegen recognizes but nothing claims: " \
          "#{uncov.sort.join(', ')}\n" \
          "  Advertise each in Capabilities (the domains and the signature table), or add a " \
          "reasoned BUILTIN_COVERAGE_EXCLUSIONS entry, or delete the dead handler."
  end
  unless unfound.empty?
    abort "affordance gate: #{unfound.size} claimed builtin(s) no declared mechanism recognizes: " \
          "#{unfound.sort.join(', ')}\n" \
          "  Either the claim is stale, or a recognition mechanism is missing from " \
          "BUILTIN_COVERAGE_AUTHORITIES (register it -- an unregistered mechanism is a " \
          "coverage hole)."
  end
  unless tstale.empty?
    abort "affordance gate: #{tstale.size} target-only builtin(s) declared in builtin_schema.h " \
          "that nothing recognizes: #{tstale.sort.join(', ')} -- stale declaration."
  end
  unless tleak.empty?
    abort "affordance gate: #{tleak.size} target-only builtin(s) COMPILE under the linux codegen: " \
          "#{tleak.sort.join(', ')}\n" \
          "  The targets declaration says they are not on the linux surface; either guard the " \
          "recognizing strcmp or add \"linux\" to the row."
  end
  puts format("  builtin  advertised  %3d  broken=%d", advertised.size, broken.size)
  puts format("  builtin  withdrawn   %3d  revived=%d%s", withdrawn.size, revived.size,
              withdrawn.empty? && !only ? EMPTY_NOTE : "")
  puts format("  builtin  self-check       %s",
              bself.empty? ? "(skipped: --only)" : bself.map { |k, v| "#{k}=#{v}" }.join(" "))
end
if do_attach
  puts format("  attach   advertised  %3d  broken=%d", akinds.size, abroken.size)
  puts format("  attach   withdrawn   %3d  revived=%d%s", awithdrawn.size, arevived.size,
              awithdrawn.empty? && !only ? EMPTY_NOTE : "")
  puts format("  attach   refusals    %3d in CC_WITHDRAWN_ATTACH  orphan=%d",
              cc_prefixes.size, aorphan.size)
  puts format("  attach   self-check       %s",
              aself.empty? ? "(skipped: --only)" : aself.map { |k, v| "#{k}=#{v}" }.join(" "))
  # The correspondence check's own control. Printed on its own line rather than
  # folded into `attach self-check` because it is a different STOREY: the line
  # above proves the gate can still probe a surface, this one proves the
  # comparison between the two inventories still compares. Both sides being empty
  # is exactly when the difference stops being visible.
  puts format("  attach   corr-check       %s",
              corrself.empty? ? "(skipped: --only)" : corrself.map { |k, v| "#{k}=#{v}" }.join(" "))
end
if do_sugar
  puts format("  sugar    advertised  %3d  broken=%d", sugars.size, sbroken.size)
  puts format("  sugar    withdrawn   %3d  revived=%d%s", swithdrawn.size, srevived.size,
              swithdrawn.empty? && !only ? EMPTY_NOTE : "")
  puts format("  sugar    self-check       %s",
              selfcheck ? "diverged_pair=#{selfcheck[0]} absent_member=#{sself}" : "(skipped: --only)")
end
if do_syntax
  puts format("  syntax   advertised  %3d  broken=%d", syntaxes.size, ybroken.size)
  puts format("  syntax   coverage        %d node types / %d binary ops accepted by the codegen, " \
              "uncovered=%d/%d", cc_nodes.size, cc_ops.size, yuncov_nodes.size, yuncov_ops.size)
  puts format("  syntax   rejected    %3d  not-refused=%d", rejects.size, yreject.size)
  puts format("  syntax   withdrawn   %3d  revived=%d%s", ywithdrawn.size, yrevived.size,
              ywithdrawn.empty? && !only ? EMPTY_NOTE : "")
  puts format("  syntax   self-check       %s",
              yself.empty? ? "(skipped: --only)" : yself.map { |k, v| "#{k}=#{v}" }.join(" "))
end
if do_maps
  puts format("  map      advertised  %3d  broken=%d", maps.size, mbroken.size)
  puts format("  map      coverage    %3d surfaces swept, %d maps seen (%s)  uncovered=%d",
              msweep, mseen.size,
              mseen.group_by(&:form).map { |f, v| "#{f}:#{v.size}" }.sort.join(" "), muncovered.size)
  puts format("  map      withdrawn   %3d types  revived=%d%s", CAP::WITHDRAWN_MAPS.size, mrevived.size,
              CAP::WITHDRAWN_MAPS.empty? && !only ? EMPTY_NOTE : "")
  puts format("  map      self-check       %s",
              mselfcheck.empty? ? "(skipped: --only)" : mselfcheck.map { |k, v| "#{k}=#{v}" }.join(" "))
end

unless abroken.empty?
  puts "\nADVERTISED ATTACH KIND, PROMISE NOT KEPT -- this is the SILENT failure:"
  puts "an attach kind the codegen does not implement does not die. It becomes a"
  puts "plain SEC(\"syscall\") wrapper: a program that loads, attaches to nothing,"
  puts "and never fires."
  abroken.each do |k, want, msg|
    puts "  #{k}"
    puts "      affordance promises: SEC(#{want.inspect})"
    puts "      codegen: #{msg}"
  end
  puts "\n  Either implement it in src/codegen_c/spinel_ebpf_cc.c (cc_detect_attach),"
  puts "  or take it out of Capabilities::ATTACH_KINDS and record it in"
  puts "  Capabilities::WITHDRAWN_ATTACH -- and add its prefix to CC_WITHDRAWN_ATTACH"
  puts "  so the codegen REFUSES it instead of silently degrading."
end

unless aorphan.empty?
  puts "\nTHE WITHDRAWN ATTACH RECORD AND THE CODEGEN'S REFUSALS DISAGREE. The"
  puts "affordance table says what is withdrawn and is what this gate probes;"
  puts "CC_WITHDRAWN_ATTACH is what actually refuses. When they drift, the surface stops"
  puts "being checked and nothing says so -- the control disappears silently."
  aorphan.each do |dir_, what|
    if dir_ == :codegen_only
      puts "  #{what}   refused by the codegen, but not in Capabilities::WITHDRAWN_ATTACH"
      puts "      Nothing probes this refusal any more. Either record it again, or -- if the"
      puts "      kind was re-ported -- delete the entry from CC_WITHDRAWN_ATTACH"
      puts "      and advertise the kind in ATTACH_KINDS."
    else
      puts "  #{what}   recorded as withdrawn, but no CC_WITHDRAWN_ATTACH prefix matches"
      puts "      method_prefix: #{CAP::WITHDRAWN_ATTACH[what][:method_prefix].inspect}"
      puts "      Withdrawing it from the affordance is only half the fix: without the"
      puts "      codegen refusal the name still compiles to a silent SEC(\"syscall\") no-op."
    end
  end
end

unless arevived.empty?
  puts "\nWITHDRAWN ATTACH KIND STILL ACCEPTED -- either it was implemented, or the"
  puts "codegen's refusal was lost, which puts the silent no-op back (read that"
  puts "second possibility first):"
  arevived.each { |k| puts "  #{k}   (#{CAP::WITHDRAWN_ATTACH[k][:method_prefix]})" }
  puts "\n  If it really was implemented, advertise it again (ATTACH_KINDS + a probe"
  puts "  shape here) and remove it from WITHDRAWN_ATTACH and CC_WITHDRAWN_ATTACH."
end

unless broken.empty?
  puts "\nADVERTISED BUT NOT IMPLEMENTED -- the affordance is lying:"
  broken.each do |b, shape, call, msg|
    puts "  #{b}"
    puts "      probe: #{call}   in #{shape}"
    puts "      codegen: #{msg}"
  end
  puts "\n  Either implement it in src/codegen_c/spinel_ebpf_cc.c, or take it out of"
  puts "  Capabilities (SIG_TABLE + DOMAINS + CONTEXT_REQUIREMENTS) and record it in"
  puts "  Capabilities::WITHDRAWN with the reason. Both are honest; silence is not."
end

unless sbroken.empty?
  puts "\nADVERTISED SUGAR, EQUIVALENCE NOT KEPT -- two spellings that must reach the"
  puts "same generated C do not. `diverged` is the silent one: both spellings"
  puts "compile, so nothing anywhere says the sugar became a different program."
  sbroken.each do |s, verdict, msg|
    puts "  #{s[:id]}  [#{verdict}]  (#{s[:family]})"
    puts "      sugar: #{s[:sugar].to_s.lines.first.to_s.strip}"
    puts "      flat : #{s[:flat].to_s.lines.first.to_s.strip}"
    puts "      #{msg}"
  end
  puts "\n  Either fix src/codegen_c/spinel_ebpf_cc.c so the surface lowers to the same"
  puts "  thing the flat spelling does, or take the claim out of Capabilities"
  puts "  (SUGAR_* tables / SUGAR_SINGLES) and record it in WITHDRAWN_SUGAR -- and make"
  puts "  the codegen REFUSE it, or a withdrawn surface just goes back to being silent."
end

unless srevived.empty?
  puts "\nWITHDRAWN SUGAR STILL ACCEPTED -- either it was implemented, or the codegen's"
  puts "refusal was lost (read that second possibility first):"
  srevived.each { |s| puts "  #{s}   (#{CAP::WITHDRAWN_SUGAR[s][:why].to_s[0, 100]})" }
end

unless ybroken.empty?
  puts "\nADVERTISED SYNTAX, CLAIM NOT KEPT -- a construct the affordance says can be"
  puts "written either does not compile (two of those were found sitting in prose) or"
  puts "compiles into something other than what it claims to become."
  ybroken.each do |s, verdict, msg|
    puts "  #{s[:id]}  [#{verdict}]  (#{s[:family]})"
    puts "      syntax   : #{s[:syntax].to_s.lines.first.to_s.strip}"
    puts "      lowers_to: #{s[:lowers_to].inspect}"
    puts "      #{msg}"
  end
  puts "\n  Either implement it in src/codegen_c/spinel_ebpf_cc.c, or take the claim out of"
  puts "  Capabilities::SYNTAX and record it in WITHDRAWN_SYNTAX -- and make the codegen"
  puts "  REFUSE it, so an author working from an older doc does not get whatever it"
  puts "  silently becomes."
end

unless yrevived.empty?
  puts "\nWITHDRAWN SYNTAX STILL ACCEPTED -- either it was implemented, or the codegen's"
  puts "refusal was lost (read that second possibility first):"
  yrevived.each { |s| puts "  #{s}   (#{CAP::WITHDRAWN_SYNTAX[s][:why].to_s[0, 100]})" }
end

unless yreject.empty?
  puts "\nA CONSTRUCT THE AFFORDANCE CALLS IMPOSSIBLE WAS NOT REFUSED. The rejected list"
  puts "has been machine-readable all along, and \"it corresponds to a partition flag\" is"
  puts "a claim, not a measurement. `uses_bignum` held that shape: the flag matched a type"
  puts "name spinel does not use, so nothing ever set it, and a 30-digit literal reached"
  puts "the kernel program as 9223372036854775807 -- exit 0."
  yreject.each do |r, verdict, msg|
    puts "  #{r[:flag]}  [#{verdict}]  (#{r[:construct]} -- #{r[:reason]})"
    puts "      #{msg}"
  end
  puts "\n  Either make partition set the flag (src/spinel_ebpf/partition.rb), or take the"
  puts "  row out of RUBY_SUBSET[:rejected]. Advertising a refusal that does not happen is"
  puts "  worse than advertising nothing: it is what an AI reads as \"this is guarded\"."
end

unless yuncov_nodes.empty? && yuncov_ops.empty?
  puts "\nTHE CODEGEN ACCEPTS SYNTAX THE AFFORDANCE NEVER MENTIONS -- this is the SILENT"
  puts "direction. Nothing is broken; an AI reading the affordance simply cannot learn"
  puts "that this can be written, and nothing measures it, which is how a literal"
  puts "`n.times` and `x = if ... end` stayed advertised-but-dead."
  yuncov_nodes.each { |t| puts "  node type  #{t}   accepted by the lowering dispatch, exercised by no claim" }
  yuncov_ops.each { |o| puts "  binary op  #{o.inspect}   in cc_is_binary_op(), exercised by no claim" }
  puts "\n  Add a Capabilities::SYNTAX claim with its `lowers_to` and a construct-free twin."
end

unless mbroken.empty?
  puts "\nADVERTISED MAP, CLAIM NOT KEPT -- the affordance says this surface makes this"
  puts "map with these properties, and the emitted C says otherwise. Capacity is"
  puts "not decoration: it is what decides whether a probe drops events."
  mbroken.each do |m, verdict, msg|
    puts "  #{m[:id]}  [#{verdict}]  (#{m[:declared_as]})"
    puts "      claim: #{m[:map]} #{m[:type]} max_entries=#{m[:max_entries].inspect} <- #{m[:probe]}"
    puts "      #{msg}"
  end
  puts "\n  Either fix the codegen, or update Capabilities::MAPS to say what it now does."
end

unless muncovered.empty?
  puts "\nA MAP CAME OUT THAT THE AFFORDANCE NEVER MENTIONS -- this is the SILENT"
  puts "failure this section exists for. The program is not broken; it just creates"
  puts "storage nobody told the author (or the AI) about: capacity unknown, overflow"
  puts "behaviour unknown, per-CPU or not unknown."
  muncovered.each do |kind, name, d|
    puts "  #{d.name}  type=#{d.type.inspect} form=#{d.form}   from #{kind} #{name}"
    if d.form == :unknown
      puts "      (an unrecognised section -- the scanner knows five map-creating forms;"
      puts "       this looks like a sixth, so it is reported rather than ignored)"
    end
  end
  puts "\n  Add it to Capabilities::MAPS with its capacity and what happens when it fills."
end

unless mrevived.empty?
  puts "\nWITHDRAWN MAP TYPE IS BACK -- a type that left with a withdrawn surface is"
  puts "being emitted again while still recorded as withdrawn:"
  mrevived.each { |t| puts "  #{t}   (went with #{CAP::WITHDRAWN_MAPS[t][:went_with]})" }
  puts "\n  If the surface really was re-implemented, advertise it (MAPS + the surface's"
  puts "  own table) and drop it from WITHDRAWN_MAPS."
end

unless revived.empty?
  puts "\nWITHDRAWN BUT IT COMPILES -- either it was implemented, or this gate has"
  puts "stopped being able to detect a missing builtin at all (read that second"
  puts "possibility first: it makes every line above meaningless):"
  revived.each { |b, shape, call| puts "  #{b}   probe: #{call}   in #{shape}" }
  puts "\n  If it really was implemented, advertise it again (SIG_TABLE + DOMAINS)"
  puts "  and remove it from WITHDRAWN."
end

# Refuse to be a green light that measured nothing.
if advertised.empty? && withdrawn.empty? && akinds.empty? && awithdrawn.empty? &&
   sugars.empty? && syntaxes.empty? && rejects.empty? && maps.empty?
  abort "\naffordance gate: nothing was checked."
end
unless only
  # The four "the withdrawn set is empty" aborts are gone. They claimed the
  # run had NO negative control, and that claim is now false: every
  # section carries a synthesised control that cannot be exhausted by fixing
  # things. What is left below is the capability half -- if a self-check stops
  # being able to produce its verdict, every `broken=0` above means nothing, so
  # that still aborts.
  if do_builtins
    if bself[:absent_name] != :died
      abort "\naffordance gate: the builtin self-check did not catch an absent name (got\n" \
            "  #{bself[:absent_name].inspect}). A call to a builtin that does not exist, written in\n" \
            "  the documented shape, was accepted -- so every `broken=0` above means nothing:\n" \
            "  this gate can no longer tell an implemented builtin from a missing one."
    end
    if bself[:no_effect_call] != :no_effect
      abort "\naffordance gate: the builtin self-check did not catch a call that emits nothing\n" \
            "  (got #{bself[:no_effect_call].inspect}). The probe and its call-less twin were the same\n" \
            "  text, and the gate still called it compiled -- so the twin witness is gone and a\n" \
            "  builtin the codegen silently drops would now read as working."
    end
  end
  if do_attach
    if aself[:wrong_sec] != :wrong_sec
      abort "\naffordance gate: the attach self-check did not catch a wrong SEC (got\n" \
            "  #{aself[:wrong_sec].inspect}). A deliberately corrupted promise was reported as kept, so\n" \
            "  every attach `broken=0` above means nothing."
    end
    if aself[:body_missing] != :no_body
      abort "\naffordance gate: the attach self-check did not catch a missing handler body (got\n" \
            "  #{aself[:body_missing].inspect}). This is stage 2 of the attach verdict and it is the only\n" \
            "  one that sees `on :timer`: its advertised SEC (\"syscall\") is the same string the\n" \
            "  silent degradation emits, so a SEC comparison alone calls it fine."
    end
    # The third storey. Not "can the gate probe a surface" but "does the
    # comparison between the affordance's record and the codegen's refusals still
    # compare". Today both sides are EMPTY, so `orphan=0` is printed by a check
    # with no live input -- a broken regex or an inverted match reads identically.
    if corrself[:codegen_only] != :codegen_only
      abort "\naffordance gate: the correspondence self-check did not catch a codegen-only refusal\n" \
            "  (got #{corrself[:codegen_only].inspect}). A prefix the codegen refuses on, which no\n" \
            "  affordance entry records, was reported as corresponding -- so `orphan=0` above means\n" \
            "  nothing. That direction is the failure this section exists for: a refusal nothing\n" \
            "  probes any more, and nothing says so."
    end
    if corrself[:affordance_only] != :affordance_only
      abort "\naffordance gate: the correspondence self-check did not catch an affordance-only\n" \
            "  record (got #{corrself[:affordance_only].inspect}). A withdrawn entry with no refusal\n" \
            "  behind it was reported as corresponding, so the affordance could advertise a\n" \
            "  refusal the codegen does not perform."
    end
  end
  if do_maps
    wrong = mselfcheck.to_h
    if wrong[:wrong_property] != :mismatch
      abort "\naffordance gate: the map self-check did not catch a wrong property (got\n" \
            "  #{wrong[:wrong_property].inspect}). A claim deliberately given the wrong max_entries\n" \
            "  was accepted, so every `broken=0` above means nothing: this gate can no longer\n" \
            "  tell a correct capacity from an invented one."
    end
    if mseen.empty?
      abort "\naffordance gate: the map sweep found no maps at all. Either the codegen stopped\n" \
            "  emitting them or map_decls stopped recognising them -- both make `uncovered=0`\n" \
            "  a vacuous pass."
    end
    if wrong[:unadvertised_map] != :uncovered
      abort "\naffordance gate: the map self-check did not catch an unadvertised map (got\n" \
            "  #{wrong[:unadvertised_map].inspect}). With one claim hidden, the map it covers was\n" \
            "  still reported as covered -- so `uncovered=0` above means nothing, and silence\n" \
            "  (the way this vocabulary failed) would go unnoticed."
    end
  end
  if do_sugar && sself != :refused
    abort "\naffordance gate: the sugar self-check did not catch an absent chain member (got\n" \
          "  #{sself.inspect}). `pkt.zz_absent_member` -- a spelling nothing implements -- was\n" \
          "  accepted, so the sugar half can no longer see a surface that is simply not there.\n" \
          "  (This is the half WITHDRAWN_SUGAR used to provide, before re-porting the demoted\n" \
          "  surfaces began emptying it.)"
  end
  if do_syntax
    # Three verdicts, three abilities, and they are genuinely different: seeing a
    # construct that is NOT THERE (both dead constructs), seeing one that is there
    # and lowers ELSEWHERE (the silent form -- a literal `n.times` falling back to
    # bpf_loop), and refusing a needle that BOILERPLATE would satisfy (without
    # which stage 2 is decoration).
    if yself[:absent_construct] != :die
      abort "\naffordance gate: the syntax self-check did not catch an absent construct (got\n" \
            "  #{yself[:absent_construct].inspect}). `while` -- which RUBY_SUBSET[:rejected] itself calls\n" \
            "  impossible under the verifier -- was accepted, so every syntax `broken=0` above\n" \
            "  means nothing: this gate can no longer tell a live construct from a dead one."
    end
    if yself[:wrong_lowering] != :wrong_lowering
      abort "\naffordance gate: the syntax self-check did not catch a wrong lowering (got\n" \
            "  #{yself[:wrong_lowering].inspect}). A deliberately corrupted `lowers_to` was reported as\n" \
            "  kept, so stage 2 is gone -- and stage 2 is the only thing that separates a literal\n" \
            "  `n.times` (open-coded, kernel floor 6.4) from a silent fall back to bpf_loop."
    end
    if yself[:needle_not_bearing] != :not_load_bearing
      abort "\naffordance gate: the syntax self-check did not catch a needle that boilerplate\n" \
            "  satisfies (got #{yself[:needle_not_bearing].inspect}). `\"__s64\"` is in every probe including the\n" \
            "  construct-free twin, and the gate still called the claim kept -- so the twin\n" \
            "  witness is gone and any needle at all would now read as a lowering."
    end
    if yself[:legal_accepted] != :accepted
      abort "\naffordance gate: the rejected-half self-check did not accept a legal probe (got\n" \
            "  #{yself[:legal_accepted].inspect}). `n = a + 1` in a kprobe handler was not compiled, so\n" \
            "  \"all N refused\" above could be produced by a pipeline that refuses everything --\n" \
            "  a missing binary, a bad output path, anything. Fix that before reading the count."
    end
    if yself[:reject_reason] != :wrong_reason
      abort "\naffordance gate: the rejected-half self-check did not catch a wrong reason (got\n" \
            "  #{yself[:reject_reason].inspect}). A deliberately corrupted `refusal:` was reported as kept, so\n" \
            "  the gate is only checking THAT the product refused, not that the flag the affordance\n" \
            "  names is the one that did it -- which is exactly how `uses_bignum` stayed dead while\n" \
            "  a bignum in signature position failed for a different reason."
    end
    if yself[:hidden_claim] != :uncovered
      abort "\naffordance gate: the syntax coverage self-check did not catch a hidden claim (got\n" \
            "  #{yself[:hidden_claim].inspect}). With the only claim that exercises one node type removed, that\n" \
            "  node type was still reported as covered -- so `uncovered=0` means nothing, and\n" \
            "  silence (the way this vocabulary failed) would go unnoticed."
    end
  end
  if selfcheck && selfcheck[0] != :diverged
    abort "\naffordance gate: the sugar self-check did not report a divergence (got\n" \
          "  #{selfcheck[0].inspect}). A deliberately mismatched pair (XDP::PASS vs XDP_DROP)\n" \
          "  came back as agreeing, so every `diverged=0` printed above means nothing:\n" \
          "  this gate can no longer tell a working surface from one that lowers to\n" \
          "  something else. Fix check_sugar before reading any verdict."
  end
end

exit((broken.size + revived.size + abroken.size + arevived.size + aorphan.size +
      sbroken.size + srevived.size +
      ybroken.size + yrevived.size + yuncov_nodes.size + yuncov_ops.size + yreject.size +
      mbroken.size + muncovered.size + mrevived.size).zero? ? 0 : 1)
end
