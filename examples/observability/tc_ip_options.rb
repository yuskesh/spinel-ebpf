# IP-options-aware L4 parsing. l4_offset() returns 14 + IHL*4 — the byte
# offset where the TCP/UDP header actually starts — so NAT/LB code works on
# packets that carry IPv4 options (IHL > 5), not just the common IHL=5 case where
# L4 sits at a fixed offset 34. Here we read the TCP source port at the dynamic
# offset and mirror it to an ivar.
#
# Build: spinel-ebpf compile examples/observability/tc_ip_options.rb -o build/opt --build
@sport = 0

def tc__ingress__demo
  l4 = l4_offset()             # 34 for IHL=5, 38 for IHL=6, ...
  @sport = skb_load_u16(l4)    # TCP source port, options-aware
  TC_ACT_OK
end

puts "tc_ip_options loaded"
sleep 3600
