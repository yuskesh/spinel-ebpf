# A real L3 router in Ruby. For each IPv4 packet, look up the egress
# interface for the destination in the kernel FIB (fib_lookup), then
# forward the packet out that interface with bpf_redirect (redirect()).
#
# In this build container fib_lookup doesn't resolve routes under test_run,
# so we fall back to a userspace-injected egress (arena slot 0) to exercise
# the redirect path deterministically. On a real kernel + attach, fib_lookup
# supplies the ifindex directly.
#
# Build: spinel-ebpf compile examples/observability/tc_router.rb -o build/rt --build
@redirects = 0

def tc__ingress__router
  oif = fib_lookup(pkt_ip4_dst)     # FIB egress ifindex for the dst (or -1)
  if oif < 0
    oif = arena_get(0)              # fallback: userspace-configured egress
  end
  out = 0                           # TC_ACT_OK (no route -> pass)
  if oif > 0
    @redirects = @redirects + 1
    out = redirect(oif)             # forward -> TC_ACT_REDIRECT
  end
  out
end

puts "tc_router loaded"
sleep 3600
