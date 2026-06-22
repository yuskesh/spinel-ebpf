# sk_assign steers an ingress skb to a socket, so it must be rejected
# outside tc__ingress__. This calls it from tc__egress__ -> UnsupportedNode.
@x = 0

def tc__egress__steer
  @x = sk_assign_tcp(1, 1, 1, 1)
  TC_ACT_OK
end
