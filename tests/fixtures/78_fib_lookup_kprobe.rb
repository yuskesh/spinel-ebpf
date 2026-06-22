# fib_lookup outside an xdp/tc context must be rejected (it needs
# the packet ctx). This fixture calls it from a kprobe so codegen raises
# UnsupportedNode.
@x = 0

def kprobe__tcp_sendmsg(sk)
  @x = fib_lookup(sk)
end
