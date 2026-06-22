# IPv6 FIB lookup — fib_lookup6(dst_hi, dst_lo) -> egress ifindex.
@oif = 0

def tc__ingress__r6
  @oif = fib_lookup6(0, 1)
  TC_ACT_OK
end
