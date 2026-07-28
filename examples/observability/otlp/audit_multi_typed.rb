# Multi-channel typed consumer -- one probe producing **separate spans for DNS
# and for HTTP**.
#
# audit_dns_typed.rb handles a single channel. This file receives two at once:
#
#     on_emit :dns  do |ev| ... send_otlp(to_span(ev), @ep) ... end   # -> resolve span
#     on_emit :http do |ev| ... send_otlp(to_span(ev), @ep) ... end   # -> HTTP RED span
#
# **`to_span` stays one word**: it does not grow a new name per channel. Which
# channel's span it builds is decided by **which `on_emit :<ch>` block it appears
# in, and whether it is applied to that block's block parameter**. Writing across
# blocks -- copying the handle into another variable, or passing it to a helper --
# **fails at compile time**; it will not quietly build a span for the wrong
# channel. In that case use the explicit form, `dns_span(ev)` / `http_span(ev)`,
# as an escape hatch.
#
# The set of properties on `ev` comes from the channel declaration in
# src/codegen_c/record_schema.h, from which the accessors are generated:
#   dns  : ev.pid / ev.comm / ev.cgid / ev.duration_ns / ev.qname
#   http : ev.pid / ev.comm / ev.dport / ev.duration_ns / ev.cgid / ev.method / ev.path / ev.status
# A typo such as `ev.statu` is a compile error naming the valid alternatives.
# To read the contract:
#   spinel-ebpf describe examples/observability/otlp/audit_multi_typed.rb
#   spinel-ebpf capabilities            # the userspace consumer DSL section
#                                       # documents how to_span resolves
#
# **The span content is identical to the concise form**: to_span only builds the
# span the egress declaration prescribes. The freedom Ruby has is whether to send,
# when, and how many times -- which here amounts to the two filters below.
#
# ── Build & run ──────────────────────────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_multi_typed.rb --build -o build/audit_multi
#   OTLP_ENDPOINT=http://127.0.0.1:4318 ./build/audit_multi/audit_multi_typed
#   # Send a subset, to show what the extra step buys you:
#   DNS_SUFFIX=.invalid HTTP_MIN_STATUS=500 OTLP_ENDPOINT=http://127.0.0.1:4318 \
#     ./build/audit_multi/audit_multi_typed

# --- kernel side: put the DNS and HTTP producers together in one unit -------
def kprobe__udp_sendmsg(sk, msg, len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568   # 0x3500 = be16 of port 53
    emit_dns(msg)
  end
  0
end

def kprobe__tcp_sendmsg(sk, msg, size)
  http_req_start(sk, msg)    # record the first 64B of the request (method/path), keyed by sock
  0
end

def kprobe__tcp_recvmsg(sk, msg)
  http_resp_stash(sk, msg)   # stash the receive buffer by tid; its contents are only readable in the kretprobe
  0
end

def kretprobe__tcp_recvmsg(ret)
  http_emit(ret)             # read the status, correlate by sock, and produce one record
  0
end

# --- userspace side: receive both channels with types -----------------------
@ep          = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
               "http://127.0.0.1:4318"
@suffix      = ENV["DNS_SUFFIX"] || ""          # "" = send everything
@min_status  = (ENV["HTTP_MIN_STATUS"] || "0").to_i
@dns_seen    = 0
@dns_sent    = 0
@http_seen   = 0
@http_sent   = 0

def interesting_name?(name)
  return true if @suffix.length == 0
  name.end_with?(@suffix)
end

on_emit :dns do |ev|
  @dns_seen = @dns_seen + 1
  next unless interesting_name?(ev.qname)
  send_otlp(to_span(ev), @ep)                    # <- resolves to dns, from this block's ev
  @dns_sent = @dns_sent + 1
  puts "  [dns ] " + ev.comm + "(" + ev.pid.to_s + ") -> " + ev.qname
end

on_emit :http do |ev|
  @http_seen = @http_seen + 1
  # Our own exporter's POST /v1/traces is not what we are here to observe; a
  # system-wide hook sees itself.
  next if ev.path == "/v1/traces"
  next if ev.status < @min_status
  send_otlp(to_span(ev), @ep)                    # <- same spelling, but resolves to http
  @http_sent = @http_sent + 1
  puts "  [http] " + ev.method + " " + ev.path + " -> " + ev.status.to_s +
       " (" + (ev.duration_ns / 1000000).to_s + "ms)"
end

secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[multi-typed] on_emit :dns + on_emit :http (suffix=\"" + @suffix +
     "\", min_status=" + @min_status.to_s + ") -> " + @ep

loop do
  sleep secs
  st = consume_records(200)
  puts "[multi-typed] dns " + @dns_sent.to_s + "/" + @dns_seen.to_s +
       "  http " + @http_sent.to_s + "/" + @http_seen.to_s + "  HTTP " + st.to_s
end
