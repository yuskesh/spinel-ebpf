# L7 request/response latency span -- the round-trip time of another process's
# TCP traffic.
#
# Measures "from sending a request to the response coming back" in a
# **protocol-independent** way, and puts it into Splunk APM as the **span
# duration**. The connect spans in audit_net.rb and audit_net_correlated.rb have
# duration=0 because they represent a connection event; here the duration is the
# whole point.
#
# How it works, extending the socket-keyed correlation to send and receive:
#   1. tcp_sendmsg (process ctx) records **the time of the request's first send**,
#      keyed by sock pointer (req_start). Later sends belonging to the same
#      request do not overwrite it -- only the first one counts as the request
#      start.
#   2. tcp_cleanup_rbuf (**after the data has been copied to the application**,
#      i.e. once the response is visible) looks up req_start, turns the delta --
#      the **round-trip latency** -- into a span (emit_l7), and deletes the entry,
#      so the next send starts the next request.
#
# Why tcp_cleanup_rbuf, as measured:
#   - A kprobe on the **entry** of tcp_recvmsg fires when the application calls
#     read, which blocks before the data arrives, so the delta comes out at
#     roughly 0, which is wrong. tcp_recvmsg has static linkage, so fexit is not
#     available on it either (-EPERM).
#   - tcp_cleanup_rbuf is called inside tcp_recvmsg **after the data is copied**,
#     that is, when the response becomes visible to the application, which is the
#     semantically correct L7 receive point. Measured: against a server that
#     delays 500ms, the duration comes out at about 500ms.
#
# Scope: one request is one send burst and one response is the receive that
#   follows it. **Pipelining and HTTP/2 multiplexing (several concurrent requests
#   on one socket) are not handled here.** Plain request/response first.
#
# semconv: the right place for a latency is the **span duration**; it is a
#   different quantity from srtt, which is a continuous L4 RTT. The process is the
#   real one seen at send time (process context), same as in
#   audit_net_correlated.rb.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_l7.rb --build -o build/audit_l7
#   OTEL_SERVICE_NAME=spinel-l7-latency \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_l7/audit_l7
#   # In another terminal, `curl http://<host>/` turns that request/response round
#   # trip into a span whose duration is the real latency. The slower the
#   # endpoint, the longer the duration.
#
# Notes, all measured:
#   - It is system-wide, so it picks up both the client-side and the server-side
#     socket; both are genuine send-to-receive round trips.
#   - Multiplexing (HTTP/2) puts several concurrent requests on one socket, which
#     breaks the "one round trip" definition used here.
#   - TLS plaintext (SSL_read/write) and L7 protocol parsing (method, path,
#     status) are handled by the sibling audit_https.rb and audit_http.rb.

module Otlp
  ffi_func :spnl_otlp_l7_span_push, [:str], :int
end

def kprobe__tcp_sendmsg(sk, msg, size)
  req_start(sk)   # process ctx: record the request start time, keyed by sock
  0
end

def kprobe__tcp_cleanup_rbuf(sk, copied)
  if i32(copied) > 0   # copied is a 32-bit int; the upper 32 bits of a kprobe arg are garbage, so read it through i32()
    emit_l7(sk)        # the data reached the application (the response is visible) -> span the round trip
  end
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-l7] L7 request/response latency (tcp_sendmsg -> tcp_cleanup_rbuf) -> OTLP span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_l7_span_push(ep)
  puts "[audit-l7] l7 spans pushed -> " + ep + " HTTP " + st.to_s
end
