# Receive network connects through a typed consumer -- filter on where to and
# which direction.
#
# The concise form in audit_net.rb gets from drain, to a span per record, to
# sending, in the single word `spnl_otlp_conn_span_push(ep)`. This file breaks
# that word apart so that **a Ruby decision can be made before sending**:
#
#     on_emit :conn do |ev| ... send_otlp(to_span(ev), @ep) ... end
#
# **The span content is byte-for-byte identical to the concise form**: `to_span`
# only builds the span the egress declaration prescribes. The freedom Ruby has
# here is whether to send, when, and how many times.
#
# The set of properties on `ev` comes from the channel declaration in
# src/codegen_c/record_schema.h, from which the accessors are generated:
#   ev.pid / ev.comm / ev.dport / ev.cgid   ... fields of the record
#   ev.peer       ... "<address>:<port>". **The v4/v6 branch is already done in C.**
#   ev.direction  ... "active" (we opened it) / "passive" (we accepted it) / "other"
#   ev.srtt_us    ... smoothed RTT in microseconds. **The same value as the span
#                     attribute net.peer.srtt_us.** The kernel's raw value is in
#                     1/8 us units, and converting that is the C side's job.
# Raw bytes such as `ev.daddr` are **deliberately not exposed**: choosing between
# daddr and daddr6_hi/lo based on family is a question of meaning, and meaning
# lives in the C layer. Ruby just writes `ev.peer`. A typo (`ev.peor`) is a
# compile error that names the valid alternatives. To read the contract:
#   spinel-ebpf describe examples/observability/otlp/audit_net_typed.rb
#
# ── Build & run ──────────────────────────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_net_typed.rb --build -o build/audit_net_typed
#   OTLP_ENDPOINT=http://127.0.0.1:4318 ./build/audit_net_typed/audit_net_typed
#   # Send a subset: drop our own exporter's connections and keep only outbound:
#   CONN_DIRECTION=active CONN_SKIP_PORT=4318 OTLP_ENDPOINT=http://127.0.0.1:4318 \
#     ./build/audit_net_typed/audit_net_typed

# --- kernel side: the same producer as audit_net.rb; the probe is shared with
# --- the concise form ------------------------------------------------------
def tracepoint__sock__inet_sock_set_state(skaddr, daddr, dport, family, oldstate, newstate, daddr6_hi, daddr6_lo)
  if newstate == 1   # TCP_ESTABLISHED
    emit_connect(skaddr, daddr, dport, family, oldstate, daddr6_hi, daddr6_lo)   # + direction, + IPv6
  end
  0
end

# --- userspace side: receive the conn channel with types --------------------
@ep        = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
             "http://127.0.0.1:4318"
@only_dir  = ENV["CONN_DIRECTION"] || ""            # "" = do not filter on direction
@skip_port = (ENV["CONN_SKIP_PORT"] || "0").to_i    # 0 = drop nothing; a real connect never has dport 0
@seen      = 0
@sent      = 0

# A helper that takes a **value** rather than the handle -- the result of
# `ev.direction` is an ordinary String.
def direction_ok?(d)
  return true if @only_dir.length == 0
  d == @only_dir
end

on_emit :conn do |ev|
  @seen = @seen + 1
  next if ev.dport == @skip_port                    # our own exporter's connect: self-observation
  next unless direction_ok?(ev.direction)           # outbound only, or inbound only
  send_otlp(to_span(ev), @ep)                       # <- resolves to conn, from this block's ev
  @sent = @sent + 1
  # ev.srtt_us is in **microseconds** and equals the span attribute
  # net.peer.srtt_us -- both are the output of the same function.
  puts "  [conn] " + ev.comm + "(" + ev.pid.to_s + ") -> " + ev.peer +
       " " + ev.direction + " srtt=" + ev.srtt_us.to_s + "us"
end

secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[conn-typed] on_emit :conn (direction=\"" + @only_dir + "\", skip_port=" +
     @skip_port.to_s + ") -> " + @ep

loop do
  sleep secs
  st = consume_records(200)
  puts "[conn-typed] sent " + @sent.to_s + "/" + @seen.to_s + "  HTTP " + st.to_s
end
