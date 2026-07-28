# Receive the off-CPU breakdown through a typed consumer -- send only the requests
# that were actually kept waiting.
#
# The concise form in audit_offcpu.rb gets from drain, to a span per record, to
# sending, in the single word `spnl_otlp_offcpu_span_push(ep)`. This file breaks
# that word apart so that **a Ruby decision can be made before sending**:
#
#     on_emit :offcpu do |ev| ... send_otlp(to_span(ev), @ep) ... end
#
# **The span content is byte-for-byte identical to the concise form**: `to_span`
# only builds the span the egress declaration prescribes. The freedom Ruby has
# here is whether to send, when, and how many times.
#
# On this channel there are three values where **exposing the raw field would
# disagree with the span**, which is why it was the last channel to get a typed
# consumer. All three are made the output of the same function the span attribute
# uses:
#   ev.duration_ns ... the whole request window (recv -> send) = the span's length
#   ev.offcpu_ns   ... how many of those ns were **not running**, **after clamping**
#                      to min(offcpu, duration), so it equals the attribute
#                      spnl.offcpu_ns. It is not the raw field: the wait is a sum
#                      over sched_switch events while the window is measured by
#                      the recv/send pair, so a record whose sum exceeds its
#                      window is possible.
#   ev.oncpu_ns    ... ns spent running (= duration - offcpu). **A computed value
#                      that is not a field at all**, equal to spnl.oncpu_ns.
#   ev.wait_kind   ... what it was waiting on: "io" / "lock" / "sleep" / "net" /
#                      "other" / "none" (it never waited) / "unknown" (the stack
#                      map or kallsyms could not be read). Equal to spnl.wait.kind.
#   ev.method / ev.path / ev.status ... L7, derived the same way as on the http channel
#   ev.pid / ev.comm / ev.cgid      ... fields of the record (cgid is the input to
#                                       the enricher that adds the k8s.* attributes)
# `ev.wait_stack` (an index into the stack map) and `ev.hdr_ext` (the raw header)
# are **deliberately not exposed**: having them in Ruby would not help you decide
# anything. To read the contract:
#   spinel-ebpf describe examples/observability/otlp/audit_offcpu_typed.rb
#
# What this buys you over the concise form: you can pick out "only the requests
# that were slow" or "only the ones whose wait was I/O" **without dropping any
# event coming from the kernel**. Unlike sending everything and filtering at the
# backend, the volume sent goes down, which matters when the SaaS bills per event
# or bandwidth is tight.
#
# ── Build & run ──────────────────────────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_offcpu_typed.rb --build -o build/audit_offcpu_typed
#   # Send only requests that waited 100ms or more:
#   OFFCPU_MIN_MS=100 OTLP_ENDPOINT=http://127.0.0.1:4318 \
#     ./build/audit_offcpu_typed/audit_offcpu_typed
#   # Narrow it to I/O waits only (the kind is a kallsyms classification, best-effort):
#   OFFCPU_MIN_MS=1 OFFCPU_WAIT_KIND=io OTLP_ENDPOINT=http://127.0.0.1:4318 \
#     ./build/audit_offcpu_typed/audit_offcpu_typed
#
# The same caveats as audit_offcpu.rb: system-wide, SERVER point of view
# (recv = request, send = response), assuming one request per handler tid.
# sched_switch is a high-frequency hook, so the overhead has not been measured.
# wait_kind classifies the top frame of the last wait and is best-effort.
# The explicit form returns one span, **the request window (the parent)** -- the
# "off-CPU wait (<kind>)" child span that the concise form adds does not appear.
# The wait values spnl.offcpu_ns and spnl.wait.kind are on the parent too, so you
# can see the same numbers either way.

# --- kernel side: the same producer as audit_offcpu.rb; the probe is shared
# --- with the concise form -------------------------------------------------
def kprobe__tcp_recvmsg(sk, msg)
  offcpu_recv_stash(sk, msg)   # stash the request receive buffer
  0
end

def kretprobe__tcp_recvmsg(ret)
  offcpu_begin(ret)            # open the off-CPU window if this is an HTTP request
  0
end

def tracepoint__sched__sched_switch(prev_pid, prev_state, next_pid)
  offcpu_account(prev_pid, prev_state, next_pid)   # accumulate voluntary off-CPU inside the window
  0
end

def kprobe__tcp_sendmsg(sk, msg)
  offcpu_emit(sk, msg)         # sending the response closes the window and emits the record with its breakdown
  0
end

# --- userspace side: receive the offcpu channel with types ------------------
@ep       = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
            "http://127.0.0.1:4318"
@min_ns   = (ENV["OFFCPU_MIN_MS"] || "100").to_i * 1000000   # only send windows that waited at least this long
@only_kind = ENV["OFFCPU_WAIT_KIND"] || ""                   # "" = do not filter on the kind of wait
@seen     = 0
@sent     = 0

# A helper that takes a **value** rather than the handle -- the result of
# `ev.wait_kind` is an ordinary String.
def kind_ok?(k)
  return true if @only_kind.length == 0
  k == @only_kind
end

on_emit :offcpu do |ev|
  @seen = @seen + 1
  next if ev.offcpu_ns < @min_ns        # skip windows that merely burned CPU
  next unless kind_ok?(ev.wait_kind)    # filter on the kind of wait
  send_otlp(to_span(ev), @ep)           # <- resolves to offcpu, from this block's ev
  @sent = @sent + 1
  # The values printed here equal the span attributes spnl.offcpu_ns,
  # spnl.oncpu_ns and spnl.wait.kind.
  puts "  [slow] " + ev.method + " " + ev.path + " -> " + ev.status.to_s +
       "  dur=" + (ev.duration_ns / 1000000).to_s + "ms" +
       " off=" + (ev.offcpu_ns / 1000000).to_s + "ms" +
       " on=" + (ev.oncpu_ns / 1000000).to_s + "ms" +
       " wait=" + ev.wait_kind + "  (" + ev.comm + ")"
end

secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[offcpu-typed] on_emit :offcpu (off-CPU >= " + (@min_ns / 1000000).to_s +
     "ms, wait_kind=\"" + @only_kind + "\") -> " + @ep

loop do
  sleep secs
  st = consume_records(200)
  puts "[offcpu-typed] sent " + @sent.to_s + "/" + @seen.to_s + "  HTTP " + st.to_s
end
