# XDP_DROP — block ICMP at the XDP hook (= before skb allocation).
#
# All ICMP packets are dropped at the earliest possible point in the kernel
# datapath. `ping` against the attached interface returns 100% packet loss
# while non-ICMP traffic (TCP, UDP) flows through normally. The drop counter
# proves the path goes through XDP_DROP rather than the kernel ICMP code.

XDP_PASS     = 2
XDP_DROP     = 1
IPPROTO_ICMP = 1

@icmp_dropped = 0
@other_passed = 0

def xdp__main
  if pkt_l4_proto == IPPROTO_ICMP
    @icmp_dropped = @icmp_dropped + 1
    XDP_DROP
  else
    @other_passed = @other_passed + 1
    XDP_PASS
  end
end

puts "[demo] XDP ICMP drop attached. ping will time out; counters via bpftool."
sleep 15
puts "[demo] exiting; ping should work again after destructor detaches."
