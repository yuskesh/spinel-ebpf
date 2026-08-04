# The pkt.* chain accessor -- the same packet readers as the flat pkt_*
# builtins, spelled with dots.
#
# All fifteen chain readers were measured DEAD in the production C codegen:
# `pkt.l4.proto` died with `CallNode not yet ported (Stage 1): proto` while
# `pkt_l4_proto` worked. The chain form had shipped with a byte-identity claim
# ("the emitted .bpf.c is byte-identical") and six examples used it, but NO
# FIXTURE DID -- and a golden gate compares text, so a comparison never made
# cannot fail. That is the same shape as builtins with no fixture, and as attach
# kinds probed only through their flat spelling.
#
# This fixture exists so the chain surface is generated at all. The equivalence
# itself is gated separately (tools/affordance_gate.rb --section sugar), because
# a golden pins THIS text, not "the two spellings agree".
@icmp = 0
@from_lo = 0
@syn = 0
@bytes = 0

def xdp__chain_probe
  @bytes = @bytes + pkt.len
  if pkt.eth.proto == ETH_P_IP
    if pkt.l4.proto == IPPROTO_ICMP
      @icmp = @icmp + 1
    end
    if pkt.ip4.src == 2130706433
      @from_lo = @from_lo + 1
    end
    if pkt.l4.proto == IPPROTO_TCP
      if (pkt.tcp.flags & TCP_FLAG_SYN) != 0
        @syn = @syn + 1
      end
    end
  end
  XDP_PASS
end
