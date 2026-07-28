# Assemble a multi-span trace: turn the breakdown of a request into a parent/child
# tree, so Span Performance has something to work with.
#
# This combines the off-CPU breakdown, TCP connect and DNS examples into **one
# tree per request**, from the SERVER point of view (one tid per request, the
# window from recv to send). While a single handler is processing a request:
#   - the time it spent waiting off-CPU (a child derived from the same record)
#   - downstream DNS resolution (udp_sendmsg to :53)
#   - downstream TCP connect (inet_sock_set_state reaching ESTABLISHED)
# are correlated by the runtime with the parent (the request span) on **(same
# tgid, ktime inside the window)**, producing a **tree** with a shared trace_id and
# a parent_span_id. A child that does not correlate falls back to a standalone
# span, which is safer than inventing the wrong parent.
#
# That gives Splunk APM's Span Performance (waterfall + critical path) enough to
# draw "of this 300ms, DNS was Xms, connect Yms and off-CPU wait Zms". Flattening
# everything into a single span hides that breakdown.
#
# On the probe and codegen side, the only change is additive: the off-CPU record
# gained start_ktime, the real start of the window. The DNS and connect records
# already carry pid=tgid and hdr.timestamp and were left alone. All of the
# assembly happens in the runtime.
#
# ── Build & send (straight to Splunk) ────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_request_tree.rb --build -o build/audit_request_tree
#   OTEL_SERVICE_NAME=spinel-request-tree \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_request_tree/audit_request_tree
#   # Point it at a cleartext HTTP server (not one going through OpenSSL). Hit a
#   # request whose handler does DNS and connect while processing (say /fetch) and
#   # resolve / connect / off-CPU wait nest underneath that request's span.
#
# Notes, all measured:
#   - Assumes the SERVER point of view and one tid per request (a synchronous
#     handler). Thread pools and async handlers are best-effort.
#   - The correlation is a heuristic on (tgid, ktime inside the window).
#     Concurrent requests in the same process can be mixed up, which is why a
#     child that does not correlate falls back to a standalone span.

module Otlp
  ffi_func :spnl_otlp_request_tree_push, [:str], :int
end

# --- parent window: off-CPU ---
def kprobe__tcp_recvmsg(sk, msg)
  offcpu_recv_stash(sk, msg)   # stash the request receive buffer
  0
end

def kretprobe__tcp_recvmsg(ret)
  offcpu_begin(ret)            # open the off-CPU window if this is an HTTP request (records start_ktime)
  0
end

def tracepoint__sched__sched_switch(prev_pid, prev_state, next_pid)
  offcpu_account(prev_pid, prev_state, next_pid)   # accumulate voluntary off-CPU inside the window
  0
end

def kprobe__tcp_sendmsg(sk, msg)
  offcpu_emit(sk, msg)         # sending the response closes the window and emits the window record (with start_ktime)
  0
end

# --- child: DNS resolution + RTT (send and recv correlated by txid) ---
def kprobe__udp_sendmsg(sk, msg, len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568   # 0x3500 = be16 of port 53
    dns_req_start(sk, msg)     # record the start time under the txid of the query bound for :53
  end
  0
end

def kprobe__udp_recvmsg(sk, msg, len, flags, addr_len)
  if kfield(sk, "sock", "__sk_common.skc_dport") == 13568
    dns_resp_stash(sk, msg)    # the response payload only exists after the copy, so stash it
  end
  0
end

def kretprobe__udp_recvmsg(ret)
  dns_emit(ret)                # correlate by response txid -> a dns_event carrying duration_ns (the RTT)
  0
end

# --- child: TCP connect ---
def tracepoint__sock__inet_sock_set_state(skaddr, daddr, dport, family, oldstate, newstate, daddr6_hi, daddr6_lo)
  if newstate == 1   # TCP_ESTABLISHED
    emit_connect(skaddr, daddr, dport, family, oldstate, daddr6_hi, daddr6_lo)
  end
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-tree] request window + off-CPU/DNS/connect into one tree -> OTLP span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_request_tree_push(ep)
  puts "[audit-tree] request-tree spans pushed -> " + ep + " HTTP " + st.to_s
end
