# Class-based attach -- `class N < BPF::XDP` binds every method of N to the XDP
# attach kind, and the emitted .bpf.c is meant to be byte-identical to the flat
# `def xdp__<member>`.
#
# Six of the nine class parents (XDP, SockOps, TcIngress, TcEgress, SkReuseport,
# SkMsg) were measured SILENTLY dead: exit 0, SEC("syscall"), a program that
# loads and never fires. Only the struct_ops trio (TcpCC/SchedExt/Qdisc)
# survived the port to the C codegen, because those three are bound during IR
# construction and the other six were never added there.
#
# An audit of all 33 attach kinds did not see this: it probed every kind through
# its FLAT spelling, which works. The failure lives in the surface.
XDP_PASS = 2

class ProtoCounter < BPF::XDP
  def count
    n = pkt_l4_proto
    if n == IPPROTO_TCP
      @tcp = @tcp + 1
    end
    XDP_PASS
  end
end
