# Socket steering — completes the socket-lookup story. For an
# incoming packet, sk_assign_tcp(saddr, daddr, sport, dport) looks up the TCP
# socket for the 4-tuple and STEERS the skb to it via bpf_sk_assign, so the
# packet is delivered to that socket regardless of the normal routing. This is
# the building block for transparent proxies / TPROXY-style redirection.
# Returns 0 if the skb was assigned, -1 if no socket matched. TC ingress only.
#
# Here we steer to a listener on 127.0.0.1:9999 (the harness creates it).
@assigned = 0

def tc__ingress__steer
  @assigned = sk_assign_tcp(2130706433, 2130706433, 12345, 9999)
  TC_ACT_OK
end

puts "tc_sk_steer loaded"
sleep 3600
