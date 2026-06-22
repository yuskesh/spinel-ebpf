# fib_lookup builtin — kernel FIB route lookup from XDP.
# Emits a typed `struct bpf_fib_lookup` stack local and passes &local to the
# bpf_fib_lookup helper (the first typed-local-to-helper builtin).
@routed = 0

def xdp__fib
  oif = fib_lookup(pkt_ip4_dst)
  if oif >= 0
    @routed = @routed + 1
  end
  XDP_PASS
end
