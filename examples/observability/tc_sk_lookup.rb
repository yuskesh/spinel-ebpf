# Socket lookup from TC. sk_lookup_tcp(saddr, daddr, sport, dport) finds a
# TCP socket for the 4-tuple (host byte order) in the current netns and returns
# its TCP state (e.g. TCP_LISTEN=10), or -1 if none. The bpf_sock reference is
# released on every path (verifier reference tracking). Useful for connection
# steering / "is there a listener?" decisions in the datapath.
#
# Here we look up a listener on 127.0.0.1:9999 (the harness creates it).
# 127.0.0.1 = 0x7f000001 = 2130706433.
@state = 0

def tc__ingress__sklook
  @state = sk_lookup_tcp(2130706433, 2130706433, 12345, 9999)
  TC_ACT_OK
end

puts "tc_sk_lookup loaded"
sleep 3600
