# Negative fixture. `pkt.byte_at(off)` is the one member of the pkt.* chain that
# was never a pkt_* reader: the chain form routed it to the `pkt_dynptr_byte_at`
# builtin, and that builtin has been withdrawn (bpf_dynptr_from_xdp /
# bpf_dynptr_slice did not survive the port to the C codegen).
#
# It used to die with the generic `CallNode not yet ported (Stage 1): byte_at`
# -- the SAME message the fifteen WORKING chain readers produced, so the
# diagnostic could not tell an author which of the two situations they were in.
# Now the packet surface answers for itself: it names the withdrawn builtin, says
# where that was decided, and gives the readers that do exist.
XDP_PASS = 2

def xdp__probe
  if pkt.byte_at(14) == 69
    @ipv4 = @ipv4 + 1
  end
  XDP_PASS
end
