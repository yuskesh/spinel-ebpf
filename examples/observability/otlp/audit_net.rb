# Network audit span: which process talked to where, plus the L4 srtt, in Splunk APM.
#
# The network counterpart of the file audit examples. The TCP transition into
# ESTABLISHED is caught on the `inet_sock_set_state` tracepoint and turned into
# **one packed record per event** by emit_connect. Because a single tracepoint
# fire carries (skaddr, daddr, dport, family) atomically, the desync that a
# triple of separate string records is exposed to cannot happen here. That
# matters for network: concurrent connects are the normal case, so this is the
# technically load-bearing part of the design.
#
# emit_connect packs into each record:
#   pid / comm (bpf_get_current_pid_tgid / _comm; note these pids are in the init
#               namespace and do not match a container's /proc)
#   daddr / dport (remote endpoint; daddr is raw be32, dport is host order)
#   family (2=INET / 10=INET6)
#   srtt_us (tcp_sock->srtt_us read via CO-RE; it is in 1/8 us units, so userspace
#            divides by 8 to get microseconds)
#
# Userspace drains with spnl_otlp_conn_span_push and turns each record into one
# network span:
#   name="connect <daddr>:<dport>", timestamped from the real ktime converted to
#   unix time
#   attributes: network.peer.address / network.peer.port / network.transport=tcp /
#         network.type=ipv4|ipv6 (standard semconv) + net.peer.srtt_us (own key) +
#         process.executable.name=comm (semconv)
#
# Notes, all measured:
#   - ESTABLISHED for an active connect can fire in softirq context, so a
#     connection to an external address reports pid=0 / comm=swapper. Loopback
#     and same-host connections do yield the connecting process. The sibling
#     audit_net_correlated.rb recovers the real process for the external case.
#   - direction (active/passive): oldstate is passed through and userspace maps
#     SYN_SENT to active and SYN_RECV to passive, into the span attribute
#     spnl.conn.direction.
#   - IPv6: daddr6_hi/lo carry the tracepoint's daddr_v6[16] split into two u64s,
#     and when family is AF_INET6 userspace formats network.peer.address in v6
#     notation.
#   - The handler takes 8 parameters (skaddr, daddr, dport, family, oldstate,
#     newstate, daddr6_hi, daddr6_lo). BPF allows only 5 registers for arguments,
#     so the wrapper packs the extractors into a stack struct and passes one
#     pointer to the inner function.
#   - The srtt here is read from L4. Measuring an L7 request/response round trip
#     (for instance with an SSL uprobe) is a different example.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_net.rb --build -o build/audit_net
#   OTEL_SERVICE_NAME=spinel-net-audit \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_net/audit_net
#   # In another terminal run something like `curl http://127.0.0.1:<port>` and
#   # that connect becomes a span.

module Otlp
  ffi_func :spnl_otlp_conn_span_push, [:str], :int
end

def tracepoint__sock__inet_sock_set_state(skaddr, daddr, dport, family, oldstate, newstate, daddr6_hi, daddr6_lo)
  if newstate == 1   # TCP_ESTABLISHED
    emit_connect(skaddr, daddr, dport, family, oldstate, daddr6_hi, daddr6_lo)   # + direction, + IPv6
  end
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-net] TCP ESTABLISHED (inet_sock_set_state) -> OTLP network span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_conn_span_push(ep)
  puts "[audit-net] conn spans pushed -> " + ep + " HTTP " + st.to_s
end
