# Cross-layer (L2 to L8) correlation into a single record, joined in userspace.
#
# One spinel-compiled binary is at once an HTTP/1.0 server (L7, native), a TCP
# probe (L3/L4, eBPF) and an OTLP exporter, so that **one connection produces one
# span record carrying L3/L4, L7 and L8 together**.
#
#   L3/L4 : client.address / server.port (already on the span) plus
#           net.tcp.established / net.tcp.state_changes -- values the tracepoint
#           accumulated in a 4-tuple keyed histogram, joined by userspace
#   L7    : http.request.method / url.path / http.route /
#           http.response.status_code / latency (the span duration)
#   L8    : tenant (the X-Tenant header, falling back to the route) and W3C
#           traceparent inheritance
#
# How it works:
#   - eBPF: the `sock:inet_sock_set_state` tracepoint reads the 4-tuple of each TCP
#     state transition (saddr/daddr/sport/dport) and turns it into a deterministic
#     u64 key -- byte-identical to the one computed on the C side in
#     otlp_xlayer.c -- which is passed to hist_observe_by. metric_id=1 is
#     state_changes (every transition); metric_id=2 is established (the transition
#     into ESTABLISHED, one per connection, which is what proves the 4-tuple join
#     works).
#   - userspace: derives the same 4-tuple from the accepted fd with
#     getsockname/getpeername, reads the keyed histogram map (bpf_hist_keyed) under
#     the same key through a dedicated FFI call, and puts the L3/L4 values into
#     span attributes.
#
#   Note on using a tracepoint rather than a kprobe: under this hypervisor,
#   attaching a kprobe (which patches text at run time) hangs, while a static
#   tracepoint attaches normally. So the 4-tuple is taken from the
#   `inet_sock_set_state` tracepoint rather than from a `tcp_retransmit_skb`
#   kprobe. Attaching a tracepoint requires tracefs (/sys/kernel/tracing) to be
#   mounted.
#
# build: bin/spinel-ebpf compile examples/observability/otlp/xlayer_correlate.rb --build -o build
# run:   OTLP_ENDPOINT=http://127.0.0.1:4318 SPINEL_HTTP_PORT=8080 ./build/xlayer_correlate
# test:  curl -H 'traceparent: 00-<32hex>-<16hex>-01' -H 'X-Tenant: acme' http://127.0.0.1:8080/hello
module Net
  ffi_func :sp_net_listen,    [:int, :int], :int
  ffi_func :sp_net_accept,    [:int],       :int
  ffi_func :sp_net_read_line, [:int],       :str
  ffi_func :sp_net_write_str, [:int, :str], :int
  ffi_func :sp_net_rl_close,  [:int],       :int
end

module Otlp
  ffi_func :spnl_otlp_now_unix_ns,        [],                                                          :int
  # HTTP server span with the cross-layer join: L7 plus L3/L4
  # established/state_changes plus the L8 tenant, all in one span.
  ffi_func :spnl_otlp_http_span_fd_x,       [:int, :str, :str, :str, :str, :int, :int, :int, :str, :int, :int, :str], :int
  # Look up the L3/L4 metrics in the keyed histogram from the accepted fd's
  # 4-tuple, deriving the key exactly as the kernel does.
  ffi_func :spnl_otlp_xlayer_established,    [:int],                                                    :int
  ffi_func :spnl_otlp_xlayer_state_changes,  [:int],                                                    :int
end

# ---- eBPF (L3/L4): accumulate TCP state metrics keyed by the connection 4-tuple ----
# sock:inet_sock_set_state reads the 4-tuple from named fields on every TCP state
# transition. On an accepted server-side socket the orientation is saddr=server,
# daddr=client, sport=server_port, dport=client_port, which matches what userspace
# gets from getsockname (local = server) and getpeername (peer = client). That is
# why the key derived below (ci=client, si=server, cp=client_port, sp=server_port)
# comes out byte-identical on both sides.
#   - metric_id=1 : every state transition for this 4-tuple (state_changes)
#   - metric_id=2 : transitions into ESTABLISHED (newstate==1), one per connection
#                   established, which is what demonstrates the join
# saddr/daddr are raw be32, matching s_addr from getsockname/getpeername, while
# sport/dport are in host order because the tracepoint has already applied ntohs.
# Userspace applies ntohs to its ports to match.
def tracepoint__sock__inet_sock_set_state(saddr, daddr, sport, dport, newstate)
  ci = daddr & 0xFFFFFFFF   # client ip  (raw be, = getpeername s_addr)
  si = saddr & 0xFFFFFFFF   # server ip  (raw be, = getsockname s_addr)
  cp = dport & 0xFFFF       # client port(host,   = ntohs(getpeername port))
  sp = sport & 0xFFFF       # server port(host,   = ntohs(getsockname port))
  base = ci
  base = base * 1099511628211 + si
  base = base * 1099511628211 + cp
  base = base * 1099511628211 + sp
  # metric_id=1: every state transition
  h1 = base * 1099511628211 + 1
  hist_observe_by(h1, 1)
  # metric_id=2: ESTABLISHED (TCP_ESTABLISHED == 1)
  if newstate == 1
    h2 = base * 1099511628211 + 2
    hist_observe_by(h2, 1)
  end
  0
end

# ---- L7 (native): HTTP server ----
def route_for(path)
  if path == "/hello"
    "/hello"
  else
    "/other"
  end
end

# L8: derive the tenant from the route, as a fallback when there is no X-Tenant header.
def tenant_for(route)
  if route == "/hello"
    "public"
  else
    "unknown"
  end
end

def build_response(status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

port = (ENV["SPINEL_HTTP_PORT"] || "8080").to_i
endpoint = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[xlayer] listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[xlayer] HTTP/1.0 on 127.0.0.1:" + port.to_s + " -> OTLP " + endpoint

loop do
  client = Net.sp_net_accept(listen_fd)
  break if client < 0

  t0 = Otlp.spnl_otlp_now_unix_ns
  line = Net.sp_net_read_line(client)
  parts = line.split(" ")
  verb = parts[0]
  path = parts[1]

  # Scan the headers for traceparent (L7 correlation) and X-Tenant (L8).
  tp = ""
  tenant = ""
  loop do
    hline = Net.sp_net_read_line(client)
    break if hline.length == 0
    hparts = hline.split(": ")
    if hparts.length >= 2
      if hparts[0] == "traceparent"
        tp = hparts[1]
      end
      if hparts[0] == "X-Tenant"
        tenant = hparts[1]
      end
    end
  end

  route = route_for(path)
  if tenant.length == 0
    tenant = tenant_for(route)
  end

  Net.sp_net_write_str(client, build_response("200 OK", "hello\n"))
  t1 = Otlp.spnl_otlp_now_unix_ns

  # Join the L3/L4 values after responding but before closing, while the fd is
  # still alive. This reads what the tracepoint accumulated under the same
  # 4-tuple key.
  est = Otlp.spnl_otlp_xlayer_established(client)
  chg = Otlp.spnl_otlp_xlayer_state_changes(client)

  # One span = L7 + L3/L4 (client.address/server.port + established/state_changes)
  # + L8 (tenant) + the inherited trace.
  st = Otlp.spnl_otlp_http_span_fd_x(client, tp, verb, path, route, 200, t0, t1, tenant, est, chg, endpoint)
  Net.sp_net_rl_close(client)
  puts "[xlayer] " + verb + " " + path + " tenant=" + tenant + " established=" + est.to_s +
       " state_changes=" + chg.to_s + " tp=[" + tp + "] -> otlp " + st.to_s
end

Net.sp_net_rl_close(listen_fd)
