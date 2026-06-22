# IP-options-aware L4 offset — l4_offset() = 14 + IHL*4.
@sport = 0

def tc__ingress__demo
  l4 = l4_offset()
  @sport = skb_load_u16(l4)
  TC_ACT_OK
end
