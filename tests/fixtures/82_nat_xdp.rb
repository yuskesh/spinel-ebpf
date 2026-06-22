# NAT builtins mutate struct __sk_buff and must be rejected outside a TC
# classifier. This calls skb_load_u32 from XDP so codegen raises UnsupportedNode.
@x = 0

def xdp__main
  @x = skb_load_u32(30)
  XDP_PASS
end
