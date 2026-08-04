#!/usr/bin/env ruby
# frozen_string_literal: true
#
# affordance_gate.rb -- one invariant over four vocabularies: builtins, attach
# kinds, surface sugar and maps. Everything the affordance advertises must
# actually work in the production codegen, and -- since the map section was
# added -- everything the production codegen creates must actually be advertised.
#
#   ruby tools/affordance_gate.rb            # exit 1 on any problem
#   ruby tools/affordance_gate.rb --list     # show the plan without compiling
#   ruby tools/affordance_gate.rb --only NAME
#   ruby tools/affordance_gate.rb --section builtins|attach|sugar|maps
#
# WHY ALL FOUR SECTIONS LIVE HERE
#
# They are one invariant measured over four vocabularies, and the vocabularies
# are entangled: sock_ops_op exists only because the sock_ops KIND does;
# tail_call_to is withdrawn BECAUSE xdp_tail is; `pkt.l4.proto` is a claim about
# the builtin `pkt_l4_proto`, and `pkt.byte_at` is withdrawn BECAUSE
# pkt_dynptr_byte_at is; the PROG_ARRAY map type is gone BECAUSE both of those
# are. Split across files, a port that revives one half and forgets the other is
# green in both. Here the run reports "advertised N broken=0 / withdrawn M
# revived=0" for each vocabulary, and refuses to pass if any negative-control
# set is empty -- so no half can quietly become a gate that only knows how to
# say yes.
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
Shape = Struct.new(:def_line, :params, :takes_params, :ret, :open, :close,
                   :reactor, keyword_init: true)

SHAPES = {
  kprobe:          Shape.new(def_line: "def kprobe__do_sys_openat2", takes_params: true,  ret: "0"),
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
      return "#{PRELUDE}\n#{sh.reactor}#{body}\n  end\nend\n"
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
    tc_ingress:    aflat("tc__ingress__probe", ret: "TC_ACT_OK"),
    tc_egress:     aflat("tc__egress__probe", ret: "TC_ACT_OK"),
    sk_reuseport:  aflat("sk_reuseport__probe", ret: "SK_PASS"),
    sk_msg:        aflat("sk_msg__probe", ret: "SK_PASS"),
    sk_skb_verdict: aflat("sk_skb__verdict__probe", ret: "SK_PASS"),
    sk_skb_parser: aflat("sk_skb__parser__probe", ret: "SK_PASS"),
    perf_event:    aflat("perf_event__sample"),
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

  def attach_source(kind, marker)
    sh = ATTACH_SHAPES.fetch(kind)
    if sh.reactor
      return "@#{marker} = 0\n\n#{PRELUDE}\n#{sh.reactor}" \
             "    @#{marker} = @#{marker} + 1\n  end\nend\n"
    end
    ind = sh.open ? "  " : ""
    src = +"@#{marker} = 0\n\n#{PRELUDE}\n"
    src << "#{sh.open}\n" if sh.open
    src << sh.def_line
    src << "(#{sh.params.join(', ')})" unless (sh.params || []).empty?
    src << "\n#{ind}  @#{marker} = @#{marker} + 1\n#{ind}  #{sh.ret}\n#{ind}end\n"
    src << "#{sh.close}\n" if sh.close
    src
  end

  # The affordance's promise, with this shape's concrete names substituted in.
  def promised_sec(kind)
    entry = CAP::ATTACH_KINDS.find { |a| a[:kind] == kind } or return nil
    ATTACH_SHAPES.fetch(kind).subst.reduce(entry[:sec].dup) { |s, (ph, v)| s.gsub(ph, v) }
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

  # [:kept | :broken, message]. "Kept" needs the promised SEC AND the handler
  # body in the output: `on :timer` degraded to a body that never reached the C
  # at all, and its advertised SEC ("syscall") is the same string a silent
  # degradation produces -- a SEC check alone would have called it fine.
  def check_attach(dir, tag, kind)
    marker = "zz#{tag}"
    path = File.join(dir, "#{tag}.rb")
    File.write(path, attach_source(kind, marker))
    out, err, st = cap3(CC, path, tag)
    want = promised_sec(kind)
    return [:broken, "refused: #{err.lines.map(&:strip).reject(&:empty?).first}", want] unless st.success?
    return [:broken, "compiled, but the handler body never reached the emitted C " \
                     "(the kind was skipped, not merely unattached)", want] unless out.include?(marker)
    got = prog_secs(out)
    return [:broken, "promised SEC(#{want.inspect}), emitted #{got.inspect}" +
                     (got == ["syscall"] ? " -- the plain-method wrapper, i.e. a program that loads and never fires" : ""),
            want] unless got.include?(want)
    [:kept, nil, want]
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
  def check_withdrawn_sugar(dir, tag, spelling, info)
    e = { form: :expr, shape: info[:ctx] || info[:shape], sugar: spelling }
    path = File.join(dir, "#{tag}.rb")
    File.write(path, sugar_source(e, :sugar))
    _o, err, st = cap3(CC, path, tag)
    return [:refused, err.lines.map(&:strip).reject(&:empty?).first.to_s] unless st.success?
    [:accepted, nil]
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

  MAP_SEC_NOT_A_MAP = %w[license maps struct_ops struct_ops.link].freeze
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

  # Compile the probe; return [:compiled | :refused, message].
  # "Compiled" also requires that the call PRODUCED something: a call the codegen
  # silently drops is not evidence that the builtin exists. The witness is the
  # same probe with the call deleted -- identical output means the call was air.
  def check(dir, tag, name)
    call  = call_text(name)
    vars  = free_vars(name, call)
    shape = shape_for(name)
    with    = File.join(dir, "#{tag}_a.rb")
    without = File.join(dir, "#{tag}_b.rb")
    File.write(with, source(shape, call, vars))
    out, err, st = cap3(CC, with, "#{tag}_a")
    unless st.success?
      return [:refused, err.lines.map(&:strip).reject(&:empty?).first.to_s, shape, call]
    end
    File.write(without, source(shape, "@hits = @hits + 0", vars))
    out2, _e2, st2 = cap3(CC, without, "#{tag}_a")
    if st2.success? && out2 == out
      return [:refused, "compiled, but emitted C identical to the call-less twin (the call produced nothing)", shape, call]
    end
    unless out.include?("_inner")
      return [:refused, "compiled, but no _inner was emitted (the method was not eBPF-eligible)", shape, call]
    end
    [:compiled, nil, shape, call]
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
  else abort "usage: affordance_gate.rb [--only NAME] [--list] [--section builtins|attach|sugar|maps]"
  end
end
abort "usage: --section builtins|attach|sugar|maps|all" unless %w[all builtins attach sugar maps].include?(section)
do_builtins = %w[all builtins].include?(section)
do_attach   = %w[all attach].include?(section)
do_sugar    = %w[all sugar].include?(section)
do_maps     = %w[all maps].include?(section)

advertised = do_builtins ? CAP.all_builtins.sort : []
withdrawn  = do_builtins ? CAP::WITHDRAWN.keys.sort : []
akinds     = do_attach ? CAP::ATTACH_KINDS.map { |a| a[:kind] } : []
awithdrawn = do_attach ? CAP::WITHDRAWN_ATTACH.keys : []
sugars     = do_sugar ? CAP.surface_sugar : []
swithdrawn = do_sugar ? CAP::WITHDRAWN_SUGAR.keys : []
maps       = do_maps ? CAP::MAPS : []
if only
  advertised.select! { |b| b == only }
  withdrawn.select! { |b| b == only }
  akinds.select! { |k| k.to_s == only }
  awithdrawn.select! { |k| k.to_s == only }
  sugars = sugars.select { |s| s[:id].to_s == only }
  swithdrawn.select! { |s| s == only }
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
if do_maps
  dups = CAP::MAPS.map { |m| m[:id] }.tally.select { |_, v| v > 1 }.keys
  abort "affordance gate: duplicate map id(s) #{dups.join(', ')}" unless dups.empty?
  bad = CAP::MAPS.reject { |m| m[:created_by].include?(m[:probe]) }
  unless bad.empty?
    abort "affordance gate: map claim(s) #{bad.map { |m| m[:id] }.join(', ')} name a `probe` that is\n" \
          "  not in their own `created_by`. The probe must be one of the surfaces that make the map."
  end
end

abort "affordance gate: production codegen missing: #{CC}\n" \
      "  It is the in-process codegen binary and needs a built deps/spinel on Linux.\n" \
      "  Run this in the build container:\n" \
      "    container exec spnlbuild sh -c 'cd /work && ruby tools/affordance_gate.rb'" unless File.executable?(CC)
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
mbroken = []   # advertised map: not emitted, or emitted with other properties
muncovered = [] # a map came out that the affordance never mentions -- the SILENT one
mrevived = []  # a withdrawn map type is back without being re-advertised
msweep = 0
mseen = []    # every distinct map the sweep saw -- printed so a scanner that
              # stopped finding anything cannot look like "nothing uncovered"
mselfcheck = []
Dir.mktmpdir("affordance-gate") do |dir|
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
puts "affordance gate (builtins / attach kinds / surface sugar / maps)"
if do_builtins
  puts format("  builtin  advertised  %3d  broken=%d", advertised.size, broken.size)
  puts format("  builtin  withdrawn   %3d  revived=%d", withdrawn.size, revived.size)
end
if do_attach
  puts format("  attach   advertised  %3d  broken=%d", akinds.size, abroken.size)
  puts format("  attach   withdrawn   %3d  revived=%d", awithdrawn.size, arevived.size)
end
if do_sugar
  puts format("  sugar    advertised  %3d  broken=%d", sugars.size, sbroken.size)
  puts format("  sugar    withdrawn   %3d  revived=%d", swithdrawn.size, srevived.size)
  puts format("  sugar    self-check       %s", selfcheck ? selfcheck[0] : "(skipped: --only)")
end
if do_maps
  puts format("  map      advertised  %3d  broken=%d", maps.size, mbroken.size)
  puts format("  map      coverage    %3d surfaces swept, %d maps seen (%s)  uncovered=%d",
              msweep, mseen.size,
              mseen.group_by(&:form).map { |f, v| "#{f}:#{v.size}" }.sort.join(" "), muncovered.size)
  puts format("  map      withdrawn   %3d types  revived=%d", CAP::WITHDRAWN_MAPS.size, mrevived.size)
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
if advertised.empty? && withdrawn.empty? && akinds.empty? && awithdrawn.empty? && sugars.empty? && maps.empty?
  abort "\naffordance gate: nothing was checked."
end
unless only
  if do_maps
    if CAP::WITHDRAWN_MAPS.empty?
      abort "\naffordance gate: WITHDRAWN_MAPS is empty, so the map half lost the record of\n" \
            "  which types left with the withdrawn builtin and attach surfaces.\n" \
            "  Keep at least one entry."
    end
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
  if do_sugar && swithdrawn.empty?
    abort "\naffordance gate: the withdrawn SUGAR set is empty, so the sugar half had no\n" \
          "  negative control for absence. Keep at least one entry, or delete this\n" \
          "  section deliberately."
  end
  if selfcheck && selfcheck[0] != :diverged
    abort "\naffordance gate: the sugar self-check did not report a divergence (got\n" \
          "  #{selfcheck[0].inspect}). A deliberately mismatched pair (XDP::PASS vs XDP_DROP)\n" \
          "  came back as agreeing, so every `diverged=0` printed above means nothing:\n" \
          "  this gate can no longer tell a working surface from one that lowers to\n" \
          "  something else. Fix check_sugar before reading any verdict."
  end
  if do_builtins && withdrawn.empty?
    abort "\naffordance gate: the withdrawn BUILTIN set is empty, so this run had no\n" \
          "  negative control -- it cannot distinguish 'every builtin works' from 'this\n" \
          "  gate can no longer detect a broken one'. Keep at least one entry, or delete\n" \
          "  this gate deliberately."
  end
  if do_attach && awithdrawn.empty?
    abort "\naffordance gate: the withdrawn ATTACH set is empty, so the attach half had\n" \
          "  no negative control. It matters more here than for builtins: an unimplemented\n" \
          "  attach kind does not raise, it degrades to SEC(\"syscall\"), so a degenerate\n" \
          "  gate and a healthy one both print 'broken=0'."
  end
end

exit((broken.size + revived.size + abroken.size + arevived.size +
      sbroken.size + srevived.size +
      mbroken.size + muncovered.size + mrevived.size).zero? ? 0 : 1)
end
