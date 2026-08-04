# PROG_ARRAY + bpf_tail_call, in the shape the feature originally shipped in.
#
# History, because this file changed sides. The original work gave
# `xdp_tail__<name>` (the jump TARGET), `tail_call_to(slot)` (the jump) and the
# per-unit PROG_ARRAY (the table). All three were lost in the port to the C code
# generator, and three separate audits withdrew one piece each: the builtin, the
# attach kind, the map type. This fixture was the NEGATIVE one for the attach
# kind, pinned in codegen_reject.tsv -- before that refusal existed the same
# source compiled with exit 0 into a plain SEC("syscall") wrapper: not an XDP
# program, not a tail-call target.
#
# All three have since been ported, so the fixture is positive now. It is
# deliberately the original demo (same method names, same declaration order,
# same discriminator byte) so the golden can be compared against the retired
# Ruby generator's own output and the port shown not to have changed the shape.
#
XDP_PASS = 2

@tcp_pkts = 0
@other_pkts = 0

# Slot 0: the loader assigns slots in declaration order.
def xdp_tail__tcp_handler
  @tcp_pkts = @tcp_pkts + 1
  XDP_PASS
end

# Slot 1.
def xdp_tail__other_handler
  @other_pkts = @other_pkts + 1
  XDP_PASS
end

# Byte 23 of an Ethernet frame is the protocol field of a vanilla 20-byte IPv4
# header. 6 = TCP.
def xdp__dispatcher
  proto = pkt_dynptr_byte_at(23)
  if proto == 6
    tail_call_to(0)
  else
    tail_call_to(1)
  end
  # Reached only when the tail call did NOT happen (empty slot) -- the jump
  # itself never returns here.
  XDP_PASS
end
