# Classify inbound traffic in place with XDP, **block one class on the spot with
# XDP_DROP**, and send both the passed and the dropped counts as per-class rates
# in OTLP metrics -- either straight to Splunk or via a Collector.
#
# The heart of spinel-ebpf is **observing and enforcing from one binary**. This
# combines the XDP classifier that feeds OTLP with dropping a packet before it
# becomes an skb, so that classify, act and report all happen at the kernel's
# receive hook. Nothing is copied or mirrored, no agent is resident, the raw
# packet is inspected and discarded immediately, and an outside system such as
# Splunk can still tell how many were dropped from how many were passed.
#
# The parts, all existing builtins with no codegen change:
#   - XDP                       ... attaches to the receive hook via `SPNL_XDP_IFACE=lo`.
#   - pkt_l4_proto              ... the L4 protocol (ICMP/TCP/UDP/other).
#   - pkt_tcp_flags             ... the TCP SYN/ACK bits, to tell "connection
#                                   opening (SYN)" from "established/data".
#   - XDP_DROP                  ... frees the frame before an sk_buff is built, so
#                                   the IP stack is never entered: the fastest
#                                   possible drop.
#   - hist_observe_by(key, 1)   ... the class is the series key. A value of 1 adds
#                                   to bucket 0 of the log2 histogram, so the count
#                                   is how many times that class occurred, which is
#                                   what the rate is derived from. A keyed
#                                   histogram cannot overflow.
#   - spnl_otlp_series_label / spnl_otlp_metric_push ... attach fixed labels to
#                                   each series key (proto / tcp_state /
#                                   **action=pass|drop**), then read bpf_hist_keyed
#                                   and push it as OTLP metrics.
#
# ---- Policy (static) --------------------------------------------------------
# **XDP_DROP for ICMP, XDP_PASS for everything else (TCP/UDP/other).** Every class
# is counted through hist_observe_by regardless, and the series labels carry an
# `action` (pass/drop), so in OTLP **the passed and dropped counts are separated
# along the action dimension** -- the dropped count is the ICMP count, which
# matches the number of pings sent.
#
# ---- Hard constraint (safety) -----------------------------------------------
# **Never DROP TCP or UDP. ICMP is the only thing that may be dropped.**
# Why: this classifier's own OTLP export leaves over TCP (HTTP or gRPC). Dropping
# TCP would kill its own telemetry, which is self-defeating. Dropping UDP would
# take DNS and other traffic down with it. An ICMP echo is harmless for a demo and
# completely reversible -- stopping the enforcer runs the destructor, which
# detaches the XDP program, and ping starts working again immediately -- so the
# drop is restricted to ICMP.
#
# ---- Cardinality discipline, as in the classifier ---------------------------
# The classes are proto x tcp_state, a finite fixed set, so they are safe as
# metric dimensions. A high-cardinality dimension such as **the source address
# (src_ip)** must not become a metric key; the map and the number of time series
# both explode. If you need the source, fold it into CIDR buckets or a top-N, or
# move it to logs.
#
# The class set (series key -> labels):
#   key 1 = ICMP            (action=drop)  <- the only thing blocked
#   key 2 = UDP             (action=pass)
#   key 3 = TCP SYN-only    (action=pass)  SYN set, ACK clear = a new connection
#                                          opening, the signal for a SYN surge
#   key 4 = TCP established (action=pass)  any other TCP = established session,
#                                          data, ACK, FIN, RST
#   key 5 = other           (action=pass)  not IPv4, or not ICMP/TCP/UDP
#
# build: SPINEL_C_BIN=deps/spinel/bin/spinel \
#        ruby bin/spinel-ebpf compile examples/observability/otlp/access_enforcer.rb --build -o build_enforcer
# run:   SPNL_XDP_IFACE=lo OTLP_ENDPOINT=http://127.0.0.1:4318 PROBE_SECONDS=3 ./build_enforcer/access_enforcer
module Otlp
  ffi_func :spnl_otlp_series_label, [:int, :str, :str], :int
  ffi_func :spnl_otlp_metric_push,  [:str, :str],       :int
end

# ---- XDP: sort received packets into the fixed classes, blocking only ICMP ----
def xdp__enforce
  proto = pkt_l4_proto
  if proto == IPPROTO_ICMP
    # DROP ICMP only -- harmless and reversible. TCP and UDP are never dropped,
    # which is what protects this program's own telemetry.
    hist_observe_by(1, 1)
    XDP_DROP
  elsif proto == IPPROTO_UDP
    hist_observe_by(2, 1)
    XDP_PASS
  elsif proto == IPPROTO_TCP
    flags = pkt_tcp_flags
    if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0
      hist_observe_by(3, 1)   # SYN-only = a connection opening
    else
      hist_observe_by(4, 1)   # established / data
    end
    XDP_PASS
  else
    hist_observe_by(5, 1)
    XDP_PASS
  end
end

ep   = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "3").to_i

# Pre-register the fixed, low-cardinality class set as series labels; userspace
# knows every key up front. The `action` dimension separates pass from drop, and
# the only thing dropped is ICMP.
Otlp.spnl_otlp_series_label(1, "proto", "icmp")
Otlp.spnl_otlp_series_label(1, "action", "drop")
Otlp.spnl_otlp_series_label(2, "proto", "udp")
Otlp.spnl_otlp_series_label(2, "action", "pass")
Otlp.spnl_otlp_series_label(3, "proto", "tcp")
Otlp.spnl_otlp_series_label(3, "tcp_state", "syn")
Otlp.spnl_otlp_series_label(3, "action", "pass")
Otlp.spnl_otlp_series_label(4, "proto", "tcp")
Otlp.spnl_otlp_series_label(4, "tcp_state", "established")
Otlp.spnl_otlp_series_label(4, "action", "pass")
Otlp.spnl_otlp_series_label(5, "proto", "other")
Otlp.spnl_otlp_series_label(5, "action", "pass")

puts "[access-enforce] XDP classify+drop on " + (ENV["SPNL_XDP_IFACE"] || "lo") +
     " (policy: DROP icmp / PASS tcp,udp,other) -> OTLP " + ep + " every " + secs.to_s + "s"

loop do
  sleep secs
  st = Otlp.spnl_otlp_metric_push("access_class", ep)
  puts "[access-enforce] access_class (pass+drop) pushed -> " + ep + " HTTP " + st.to_s
end
