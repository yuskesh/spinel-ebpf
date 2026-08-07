# DNS resolution latency span: which process resolved what, and how long it took,
# independent of the resolver.
#
# The sibling audit_dns.rb only **captures the query**, so its spans have
# duration=0. This example correlates the send with the receive by **transaction
# ID**, which makes the **span duration the DNS resolution round trip**. Even when
# an A and an AAAA query go out over the same UDP socket, the txid separates them
# -- the multiplexing is resolved by ID.
#
# Three hooks, the UDP counterpart of the TCP arrangement used for HTTP:
#   1. kprobe/udp_sendmsg   : read the txid of the query bound for :53 and record
#                             the start time under (sock<<16|txid) (dns_req_start)
#   2. kprobe/udp_recvmsg   : the response payload only exists after the copy, so
#                             stash {sk, buf} keyed by tid (dns_resp_stash)
#   3. kretprobe/udp_recvmsg: read the txid of the response, correlate, and emit a
#                             dns_event carrying duration_ns (dns_emit)
#
# span: name="resolve <hostname>", attributes dns.question.name /
#   process.executable.name + **spnl.dns.latency_ns** (the RTT), and the span
#   duration is the RTT. QNAME is parsed in userspace out of the question section
#   echoed back in the response, for the same reason as in audit_dns.rb: walking
#   labels in the kernel explodes verifier state.
#
# Notes, all measured:
#   - Resolver-independent, because it watches the socket layer on :53. Go native
#     resolution is picked up too.
#   - **A cache hit is invisible**, since no query goes out. **A query with no
#     response (SERVFAIL, timeout, drop) gets no duration**; the pending entry
#     ages out of the LRU. DoH/DoT (:443 over TCP) is outside this :53 UDP hook.
#   - One name resolution issues an A and an AAAA query, so it produces two spans,
#     each with its own RTT.
#   - This is a separate builtin from the query-only emit_dns, and the two can
#     coexist; emit_dns spans just have duration 0.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_dns_latency.rb --build -o build/audit_dns_latency
#   OTEL_SERVICE_NAME=spinel-dns-latency \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_dns_latency/audit_dns_latency
#   # In another terminal run `getent hosts <unique-name>`, curl, or a Go binary
#   # built with CGO_ENABLED=0, and each resolution becomes a span with an RTT.

module Otlp
  ffi_func :spnl_otlp_dns_span_push, [:str], :int
end

def kprobe__udp_sendmsg(sk, msg, len)
  if udp_dport(sk, msg) == 53   # the destination of THIS datagram
    dns_req_start(sk, msg)
  end
  0
end

# The receive side cannot ask the same question. `msg_name` here is an OUTPUT --
# the kernel writes the sender's address into it after the copy -- so the only
# thing available at entry is the socket's connected peer. That means the RTT
# half of this probe still needs a resolver that connect()s; an unconnected
# forwarder gets its queries recorded (above) but never a duration. That limit is
# named rather than hidden: sock_dport is the right accessor here, and its
# ceiling is the real one.
def kprobe__udp_recvmsg(sk, msg, len, flags, addr_len)
  if sock_dport(sk) == 53
    dns_resp_stash(sk, msg)
  end
  0
end

def kretprobe__udp_recvmsg(ret)
  dns_emit(ret)   # ret>0 guarded inside; correlates by response txid -> DNS RTT
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-dns-lat] udp_sendmsg/udp_recvmsg :53 (txid-correlated RTT) -> OTLP resolve span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_dns_span_push(ep)
  puts "[audit-dns-lat] dns spans pushed -> " + ep + " HTTP " + st.to_s
end
