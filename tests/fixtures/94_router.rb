# TC L3 router — fib_lookup(dst) -> redirect(ifindex). arena config fallback
# for the egress so the redirect path is exercisable under test_run.
@redirects = 0

def tc__ingress__router
  oif = fib_lookup(pkt_ip4_dst)
  if oif < 0
    oif = arena_get(0)
  end
  out = 0
  if oif > 0
    @redirects = @redirects + 1
    out = redirect(oif)
  end
  out
end
