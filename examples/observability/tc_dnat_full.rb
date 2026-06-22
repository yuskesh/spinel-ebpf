# Full IPv4 DNAT — rewrite destination 10.0.0.2:80 -> 10.0.0.99:8080 for
# both TCP and UDP, the realistic load-balancer / redirect operation.
#
# Three NAT subtleties handled in Ruby:
#   1. IP address change  -> fix IP header csum (l3) AND L4 pseudo csum (l4 _ip).
#   2. Port change (16-bit) -> fix L4 csum only (a port is NOT in the pseudo-
#      header), via skb_load_u16/skb_store_u16 + l4_csum_replace (no pseudo).
#   3. proto auto-detect  -> the L4 checksum offset differs (TCP=+16, UDP=+6), so
#      read the IP protocol byte and pick the right offset.
#
# Offsets (Ethernet 14 + IPv4 20, no options): proto = 23, IP csum = 24,
# dst IP = 30, dst port = 36, TCP csum = 50, UDP csum = 40. Host byte order.
#
# Verified with BPF_PROG_TEST_RUN.
@rewrites = 0

def tc__ingress__dnat
  proto = skb_load_byte(23)
  dst = skb_load_u32(30)
  if dst == 167772162                 # 10.0.0.2
    new_ip = 167772259                # 10.0.0.99
    if proto == 6                     # TCP
      l4 = 50
    else                              # UDP
      l4 = 40
    end
    l3_csum_replace_ip(24, dst, new_ip)
    l4_csum_replace_ip(l4, dst, new_ip)
    skb_store_u32(30, new_ip)
    dport = skb_load_u16(36)
    l4_csum_replace(l4, dport, 8080)  # port is in the L4 header, not pseudo-hdr
    skb_store_u16(36, 8080)
    @rewrites = @rewrites + 1
  end
  TC_ACT_OK
end

puts "tc_dnat_full loaded (SPNL_TCX_IFACE=lo)"
sleep 3600
