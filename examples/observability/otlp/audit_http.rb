# Zero-code HTTP L7 RED: span another process's HTTP traffic with method, path,
# status and duration.
#
# The core of what OBI/Beyla does, written in Ruby. Without changing a line of the
# application, another process's HTTP traffic lands in Splunk APM as **RED**
# (Rate = number of spans, Error = status >= 500, Duration = round-trip time).
# All this adds over the L7 latency example is an **HTTP parser** on top of the
# same send/receive correlation.
#
# How it works, reusing the socket-keyed correlation:
#   1. tcp_sendmsg (process ctx): http_req_start reads the first 64 bytes of the
#      send buffer, and if it is an HTTP request (a real method; "HTTP" responses
#      and non-HTTP traffic are excluded) it records {start, raw method/path
#      bytes} keyed by sock. **A server's response-send begins with "HTTP", so it
#      never matches** -- only client requests are picked up. Non-HTTP traffic
#      produces no span at all, so there are no false positives.
#   2. tcp_recvmsg entry: http_resp_stash stashes {sk, head of the receive buffer}
#      keyed by tid. The response bytes only exist after the copy, so they are
#      read in the kretprobe; tcp_recvmsg has static linkage, so fexit is not
#      available on it.
#   3. kretprobe/tcp_recvmsg: http_emit reads the stashed receive buffer (the
#      status), correlates it with the request by sock, and emits **one span**
#      with method, path, status and duration. Parsing the method, path and status
#      happens in userspace; the kernel only does a bounded copy, the same
#      arrangement as for DNS.
#
# semconv (interoperating with OBI/Beyla): `http.request.method` / `url.path` /
#   `http.response.status_code` (standard semconv) + `network.peer.address/port` +
#   `process.executable.name`. The span is named "<METHOD> <path>" with
#   kind=CLIENT (the curl point of view), and **status >= 500 sets
#   Span.status=ERROR**, which APM colours red and which is the error axis of RED.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_http.rb --build -o build/audit_http
#   OTEL_SERVICE_NAME=spinel-http-red \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_http/audit_http
#   # In another terminal, `curl http://<host>/path` produces an HTTP GET /path
#   # span carrying the status and the duration. Hitting an endpoint that returns
#   # 500 makes the span ERROR (red).
#
# Notes, all measured:
#   - It is system-wide, so the client-side request/response becomes one span; the
#     server side is excluded by the method filter.
#   - With keep-alive, several requests arrive in sequence on one socket, and each
#     request/response becomes its own span.
#   - HTTP/2 multiplexing and pipelining (several concurrent requests on one
#     socket) are not handled. TLS plaintext (SSL_read/write) is handled by the
#     sibling audit_https.rb.
#   - http.response.status_code is a string attribute in this implementation,
#     because it goes through the generic span path. Making it an int is future work.

module Otlp
  ffi_func :spnl_otlp_http_span_push, [:str], :int
end

def kprobe__tcp_sendmsg(sk, msg, size)
  http_req_start(sk, msg)   # capture the request method/path (HTTP only)
  0
end

def kprobe__tcp_recvmsg(sk, msg)
  http_resp_stash(sk, msg)  # stash the receive buffer, to be read in the kretprobe
  0
end

def kretprobe__tcp_recvmsg(ret)
  http_emit(ret)            # read the status, correlate, and emit one span (method/path/status/duration)
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-http] HTTP L7 RED (tcp_sendmsg + kretprobe/tcp_recvmsg) -> OTLP span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_http_span_push(ep)
  puts "[audit-http] http spans pushed -> " + ep + " HTTP " + st.to_s
end
