# TC-ingress IPv4 DNAT — rewrite the destination address 10.0.0.2 -> 10.0.0.99
# and repair BOTH checksums: the IP header checksum (l3) and the TCP checksum,
# whose pseudo-header includes the IP address (l4 with BPF_F_PSEUDO_HDR).
#
# This is the NAT-grade follow-up to the TTL demo: a 32-bit field rewrite that
# composes skb_load_u32 / skb_store_u32 (typed __u32 stack local <-> helper) with
# l3_csum_replace_ip / l4_csum_replace_ip. The kernel-side connection rewriting
# the spinel-ebpf HTTP-server mission needs.
#
# Offsets (Ethernet 14 + IPv4 20, no options): dst IP = 30, IP csum = 24,
# TCP csum = 14 + 20 + 16 = 50. Values are host byte order.
#
# Verified with BPF_PROG_TEST_RUN.
@rewrites = 0

def tc__ingress__dnat
  dst = skb_load_u32(30)
  if dst == 167772162           # 10.0.0.2
    new = 167772259             # 10.0.0.99
    l3_csum_replace_ip(24, dst, new)
    l4_csum_replace_ip(50, dst, new)
    skb_store_u32(30, new)
    @rewrites = @rewrites + 1
  end
  TC_ACT_OK
end

puts "tc_dnat loaded (SPNL_TCX_IFACE=lo)"
sleep 3600
