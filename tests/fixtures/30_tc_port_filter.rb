# TC ingress port filter.
#
# Drops every incoming packet whose IPv4 + TCP/UDP destination port is NOT 8080,
# letting through only HTTP server traffic (an HTTP server building block). Demonstrates:
#   - tc__ingress__<name> attach pattern (SEC("tcx/ingress"))
#   - pkt_l4_dport builtin in TC context (struct __sk_buff *)
#   - TC_ACT_OK / TC_ACT_SHOT return values via KNOWN_CONSTANTS

TC_ACT_OK   = 0
TC_ACT_SHOT = 2

@allowed_8080 = 0
@dropped      = 0

# Loopback shows both directions on the ingress hook. A real 8080 session has:
#   client -> server  : dport=8080
#   server -> client  : sport=8080 (dst is the client's ephemeral port)
# Allow if EITHER end is 8080 so the TCP handshake completes.
def tc__ingress__http_filter
  if pkt_l4_dport == 8080 || pkt_l4_sport == 8080
    @allowed_8080 = @allowed_8080 + 1
    TC_ACT_OK
  else
    @dropped = @dropped + 1
    TC_ACT_SHOT
  end
end

puts "[demo] TC ingress filter attached: only TCP/UDP dport=8080 passes."
sleep 15
puts "[demo] exiting; TC link released at destructor."
