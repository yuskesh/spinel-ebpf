# skb-rewrite builtins mutate struct __sk_buff, so they must be rejected
# outside a TC classifier. This fixture calls skb_store_byte from XDP so codegen
# raises UnsupportedNode.
@x = 0

def xdp__main
  @x = skb_store_byte(22, 5)
  XDP_PASS
end
