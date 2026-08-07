# DNS audit span: which process resolved which name, independent of the resolver.
#
# A uprobe on libc getaddrinfo only catches glibc callers, so it misses the Go
# native resolver, musl and DoH. This example watches the **socket layer, port
# 53** instead, which makes it resolver-independent -- Go native resolution shows
# up too. A `udp_sendmsg` kprobe catches DNS queries bound for :53 (that hook
# runs in process context, so the softirq problem does not arise) and emit_dns
# copies the DNS payload into one packed record. The copy is raw and QNAME is
# parsed in userspace, because walking length-prefixed labels inside the kernel
# is a nested loop that explodes verifier state.
#
# span: name="resolve <hostname>", timestamped from the kernel ktime converted to
# unix time, with the attributes
#   dns.question.name (standard semconv) / process.executable.name (comm, semconv)
#
# Notes, all measured:
#   - Resolver independence is the whole point. In a controlled comparison the
#     same Go resolution was absent from the libc uprobe and present on socket :53.
#   - The RANGE of that independence was measured separately and is wider than it
#     used to be: not just the resolver's implementation language, but also how it
#     sends -- connected or not, one iovec or several. (Before that measurement,
#     only connected single-buffer sends were read; a dnsmasq forwarding upstream
#     with a bare sendto produced no spans at all.) What still cannot be read is a
#     send whose bytes are not in user memory (splice/vmsplice); such a record is
#     reported as `unreadable_payload` rather than turned into an empty span.
#   - This example captures the query -- who resolved what. It does not measure
#     resolution latency, so the query span has duration=0; getting the latency
#     needs access to the payload on the receive side. A libc uprobe (getaddrinfo
#     entry to exit) can measure latency but only for glibc, so the two approaches
#     complement each other.
#   - DoH/DoT (TCP 443) is invisible to this :53 UDP hook. So is a cache hit,
#     because no query is sent.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_dns.rb --build -o build/audit_dns
#   OTEL_SERVICE_NAME=spinel-dns-audit \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_dns/audit_dns
#   # In another terminal run `getent hosts x`, `curl`, or a Go LookupHost built
#   # with CGO_ENABLED=0, and each one turns into a span.

module Otlp
  ffi_func :spnl_otlp_dns_span_push, [:str], :int
end

def kprobe__udp_sendmsg(sk, msg, len)
  # udp_dport is the destination of THIS datagram, not of the socket. An
  # unconnected sender -- one that passes the address on every send, which is how
  # dnsmasq forwards upstream -- leaves the socket's peer port at 0, so
  # `sock_dport(sk) == 53` is simply false and the probe reports nothing at all.
  # Both spellings return host order, so the port is written as the port; the raw
  # __be16 read would have to be compared against 13568 (0x3500).
  if udp_dport(sk, msg) == 53
    emit_dns(msg)
  end
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-dns] udp_sendmsg :53 (resolver-independent) -> OTLP resolve span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_dns_span_push(ep)
  puts "[audit-dns] dns spans pushed -> " + ep + " HTTP " + st.to_s
end
