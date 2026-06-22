# socket lookup — sk_lookup_tcp(saddr, daddr, sport, dport) -> TCP state.
@state = 0

def tc__ingress__sklook
  @state = sk_lookup_tcp(2130706433, 2130706433, 12345, 9999)
  TC_ACT_OK
end
