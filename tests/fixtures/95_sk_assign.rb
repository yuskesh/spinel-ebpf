# socket steering — sk_assign_tcp(saddr, daddr, sport, dport) assigns the
# skb to the looked-up TCP socket (bpf_sk_assign + sk_release).
@assigned = 0

def tc__ingress__steer
  @assigned = sk_assign_tcp(2130706433, 2130706433, 12345, 9999)
  TC_ACT_OK
end
