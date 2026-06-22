# Packet-length aggregation.
#
# Adds a second top-level ivar (@rx_bytes) that accumulates pkt_len for every
# packet seen on the XDP rx hook. Combined with the @rx_pkts counter this
# gives a 2-cell "rx stats" demo. pkt_len is one of the pkt_* builtins — it
# lowers to `spnl_pkt_len(ctx)`, an inlined helper that returns
# ctx->data_end - ctx->data.

XDP_PASS = 2

@rx_pkts  = 0
@rx_bytes = 0

def xdp__main
  @rx_pkts  = @rx_pkts + 1
  @rx_bytes = @rx_bytes + pkt_len
  XDP_PASS
end

puts "[demo] XDP attached; sleeping 10s. Dump counters via bpftool."
sleep 10
puts "[demo] exiting."
