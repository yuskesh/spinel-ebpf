# Kernel load-check: XDP packet counter (network datapath).
#
# Counts every received packet in a per-unit HASH map, then passes it on.
# Exercises XDP program emission and a top-level ivar map.
@rx_pkts = 0
def xdp__count
  @rx_pkts += 1
  XDP_PASS
end
