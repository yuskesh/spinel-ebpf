# Classify inbound traffic to a server under load in place with XDP, and send the
# per-class rate as OTLP metrics -- either straight to Splunk or via a Collector.
#
# The question is "classify the burst of traffic arriving right now". During an
# outage, an attack or a spike, sort packets into a small fixed set of classes and
# count them **directly at the kernel's receive hook**, without copying or
# mirroring the raw packets. High-cardinality dimensions such as src_ip do not go
# into metrics; see the discipline note below.
#
# The parts, all existing builtins with no codegen change:
#   - XDP                       ... attaches to the receive hook via `SPNL_XDP_IFACE=lo`.
#   - pkt_l4_proto              ... the L4 protocol (ICMP/TCP/UDP/other).
#   - pkt_tcp_flags             ... the TCP SYN/ACK bits, to tell "connection
#                                   opening (SYN)" from "established/data".
#   - hist_observe_by(key, 1)   ... the class is the series key. A value of 1 adds
#                                   to bucket 0 of the log2 histogram, so the count
#                                   is how many times that class occurred, which is
#                                   what the rate is derived from. A keyed
#                                   histogram cannot overflow, and it works under
#                                   XDP as a HASH lookup plus an atomic add.
#   - spnl_otlp_series_label / spnl_otlp_metric_push ... attach fixed labels to
#                                   each series key, then read bpf_hist_keyed and
#                                   push it as labelled OTLP metrics.
#
# The class set is small and fixed, which is what lets userspace pre-register
# every key and use the labelled-metrics path:
#   key 1 = ICMP
#   key 2 = UDP
#   key 3 = TCP SYN-only        (SYN set, ACK clear = a new connection opening,
#                                the signal for a burst or a SYN surge)
#   key 4 = TCP established     (any other TCP = established session, data, ACK,
#                                FIN, RST)
#   key 5 = other               (not IPv4, or not ICMP/TCP/UDP)
#
# Cardinality discipline, and it matters:
#   The classes in this demo are finite and fixed, so they are safe as metric
#   dimensions. A high-cardinality dimension such as **the source address
#   (src_ip)** must not become a metric key -- the map and the number of time
#   series both explode. If you need the source in production, fold it into CIDR
#   buckets or a top-N, or move it to events (logs). This example stays with the
#   L3/L4 proto and tcp_state only.
#
# build: SPINEL_C_BIN=deps/spinel/bin/spinel \
#        ruby bin/spinel-ebpf compile examples/observability/otlp/access_classifier.rb --build -o build
# run:   SPNL_XDP_IFACE=lo OTLP_ENDPOINT=http://127.0.0.1:4318 PROBE_SECONDS=3 ./build/access_classifier
module Otlp
  ffi_func :spnl_otlp_series_label, [:int, :str, :str], :int
  ffi_func :spnl_otlp_metric_push,  [:str, :str],       :int
end

# ---- XDP: sort received packets into the fixed classes and count them ----
def xdp__classify
  proto = pkt_l4_proto
  if proto == IPPROTO_ICMP
    hist_observe_by(1, 1)
  elsif proto == IPPROTO_UDP
    hist_observe_by(2, 1)
  elsif proto == IPPROTO_TCP
    flags = pkt_tcp_flags
    if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0
      hist_observe_by(3, 1)   # SYN-only = a connection opening
    else
      hist_observe_by(4, 1)   # established / data
    end
  else
    hist_observe_by(5, 1)
  end
  XDP_PASS
end

ep   = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "3").to_i

# Pre-register the fixed, low-cardinality class set as series labels; userspace
# knows every key up front.
Otlp.spnl_otlp_series_label(1, "proto", "icmp")
Otlp.spnl_otlp_series_label(2, "proto", "udp")
Otlp.spnl_otlp_series_label(3, "proto", "tcp")
Otlp.spnl_otlp_series_label(3, "tcp_state", "syn")
Otlp.spnl_otlp_series_label(4, "proto", "tcp")
Otlp.spnl_otlp_series_label(4, "tcp_state", "established")
Otlp.spnl_otlp_series_label(5, "proto", "other")

puts "[access-class] XDP classifier on " + (ENV["SPNL_XDP_IFACE"] || "lo") +
     " -> OTLP " + ep + " every " + secs.to_s + "s"

loop do
  sleep secs
  st = Otlp.spnl_otlp_metric_push("access_class", ep)
  puts "[access-class] access_class pushed -> " + ep + " HTTP " + st.to_s
end
