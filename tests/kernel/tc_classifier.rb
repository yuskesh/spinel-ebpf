# Kernel load-check: TC ingress classifier (network datapath + packet headers).
#
# Counts TCP packets on ingress. Exercises TC program emission and the
# verifier-safe, bounds-checked packet-header accessors (pkt_l4_proto).
@tcp = 0
def tc__ingress__classify
  if pkt_l4_proto == IPPROTO_TCP
    @tcp += 1
  end
  TC_ACT_OK
end
