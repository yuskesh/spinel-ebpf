# DNS audit span -- the **typed consumer** version. It does the same thing as
# audit_dns.rb, but written as **a Ruby loop that receives records** rather than
# as one opaque push.
#
# The concise form (audit_dns.rb) is written like this:
#
#     Otlp.spnl_otlp_dns_span_push(ep)     # drain, build spans and send, in one word
#
# The explicit form (this file) breaks that one word into three:
#
#     on_emit :dns do |ev|                 # 1. typed receive (ev.qname / ev.comm / ev.pid / ...)
#       next unless interesting?(ev.qname) # 2. your own logic goes here
#       send_otlp(to_span(ev), @ep)        # 3. convert (per the egress declaration) and send
#     end
#
# **The set of properties on `ev` comes from the declaration** in
# src/codegen_c/record_schema.h, from which the accessors are generated. A typo
# such as `ev.qnam` fails at compile time, naming the alternatives: "valid ones
# are ev.pid, ev.comm, ev.cgid, ev.duration_ns, ev.qname". It is neither a link
# error nor a silent 0. To read the contract:
#   spinel-ebpf describe examples/observability/otlp/audit_dns_typed.rb
#
# **The span is byte-for-byte the same as in the concise form**: to_span goes
# through the same builder (dns_fill_span), so the attributes
# (dns.question.name / process.executable.name / spnl.dns.latency_ns), the
# SpanKind and the timestamps are identical. The only thing that differs is which
# records get sent.
#
# Unchanged from audit_dns.rb: watching the socket layer on :53 makes this
# resolver-independent, so Go native resolution is picked up. DoH/DoT (TCP 443)
# and cache hits are invisible. emit_dns captures the query only, so duration=0;
# the version with latency is the three-hook dns_req_start/dns_emit arrangement in
# audit_dns_latency.rb.
#
# ── Build & run ──────────────────────────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_dns_typed.rb --build -o build/audit_dns_typed
#   OTLP_ENDPOINT=http://127.0.0.1:4318 ./build/audit_dns_typed/audit_dns_typed
#   # Send only a particular domain, to show what the extra step buys you:
#   DNS_SUFFIX=.invalid OTLP_ENDPOINT=http://127.0.0.1:4318 ./build/audit_dns_typed/audit_dns_typed

def kprobe__udp_sendmsg(sk, msg, len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568   # 0x3500 = be16 of port 53
    emit_dns(msg)
  end
  0
end

# Keep the default on https. At build time, whether TLS gets linked in is decided
# by whether an https:// literal appears in the generated C, so if the default
# were http, passing an https endpoint through the environment would still leave
# mbedTLS unlinked and nothing could be sent. This matches the default in the
# concise form (audit_dns.rb).
#
# When actually sending to Splunk, **pass the endpoint via the environment
# variable OTEL_EXPORTER_OTLP_TRACES_ENDPOINT**. Using this default string
# directly does not take the branch that treats the endpoint verbatim including
# its path, so the signal path is appended and the request 404s. The concise form
# behaves the same way -- this is not specific to the typed consumer.
@ep     = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
          "http://127.0.0.1:4318"
@suffix = ENV["DNS_SUFFIX"] || ""     # "" = send everything, same as the concise form
@seen   = 0
@sent   = 0

# The decision before sending, which a fixed FFI call gave you no way to write.
# ev.qname is a derived property of the record declaration (a walk over the DNS
# labels in raw[64]) and is an ordinary Ruby String.
def interesting?(name)
  return true if @suffix.length == 0
  name.end_with?(@suffix)
end

on_emit :dns do |ev|
  @seen = @seen + 1
  next unless interesting?(ev.qname)
  send_otlp(to_span(ev), @ep)
  @sent = @sent + 1
  puts "  [send] " + ev.comm + "(" + ev.pid.to_s + ") -> " + ev.qname
end

secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[typed-dns] udp_sendmsg :53 -> on_emit :dns (suffix=\"" + @suffix + "\") -> " + @ep

loop do
  sleep secs
  st = consume_records(200)
  puts "[typed-dns] seen=" + @seen.to_s + " sent=" + @sent.to_s + " HTTP " + st.to_s
end
