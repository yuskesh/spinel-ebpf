# Network audit span that names the real process even for external destinations,
# by correlating on the socket pointer.
#
# This lifts a limitation of audit_net.rb. That example turns the ESTABLISHED
# transition of inet_sock_set_state into one record, but **the ESTABLISHED for an
# outbound connect fires in softirq context**, so bpf_get_current_comm returns
# swapper/0 (pid 0) and the "who" is missing. Loopback happens to run in process
# context, so it was fine there.
#
# The fix uses the fact that **calling connect is always in process context**:
#   1. A kprobe on tcp_v4_connect (process ctx) records sock ptr -> {pid, comm}
#      in a correlation map (sock_owner_set).
#   2. On the ESTABLISHED from inet_sock_set_state (softirq), emit_connect **looks
#      up that same sock pointer** in the correlation map and replaces swapper/0
#      with the real process. Measurement confirmed skaddr is the same sk seen at
#      connect time: 10 out of 10 external connections hit.
#
# The correlation only kicks in for a unit that uses sock_owner_set, so
# emit_connect on its own still generates byte-identical code and stays backward
# compatible. This socket-keyed map is general infrastructure: it holds the
# process for the life of the connection, and any later probe can look it up by
# sock pointer -- which is what pairing sends and receives for L7 latency needs.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_net_correlated.rb --build -o build/audit_net_correlated
#   OTEL_SERVICE_NAME=spinel-net-correlated \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_net_correlated/audit_net_correlated
#   # In another terminal, an external `curl https://1.1.1.1/` produces a span
#   # with process.executable.name=curl rather than swapper/0.
#
# Notes, all measured:
#   - A passive open (accept on the server side) never goes through connect, so
#     there is no correlation entry and the process stays whatever the
#     ESTABLISHED context reports. That is correct: it is not "who connected".
#   - process.executable.path and the parent cannot be read in the kernel here.
#     bpf_d_path is rejected by the verifier (-22) in a connect kprobe, since it
#     is only allowed in a few hooks. Correlating the comm is what this example
#     delivers.
#   - Map lifecycle: this version never removes the entry written at connect; the
#     map reclaims by capacity. Deleting explicitly on CLOSE, so the entry lives
#     exactly as long as the connection, is a tightening left for the L7 latency
#     example.

module Otlp
  ffi_func :spnl_otlp_conn_span_push, [:str], :int
end

def kprobe__tcp_v4_connect(sk, uaddr, addr_len)
  sock_owner_set(sk)   # process ctx: record who owns this socket
  0
end

def tracepoint__sock__inet_sock_set_state(skaddr, daddr, dport, family, oldstate, newstate, daddr6_hi, daddr6_lo)
  if newstate == 1   # TCP_ESTABLISHED
    emit_connect(skaddr, daddr, dport, family, oldstate, daddr6_hi, daddr6_lo)   # correlate by sock ptr; + direction, + IPv6
  end
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-net-corr] TCP ESTABLISHED + connect correlation -> OTLP network span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_conn_span_push(ep)
  puts "[audit-net-corr] conn spans pushed -> " + ep + " HTTP " + st.to_s
end
