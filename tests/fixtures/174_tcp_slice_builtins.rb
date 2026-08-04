# The SEVEN pure-XDP TCP slice builtins -- the HAND-WRITTEN form of the same
# machine `xdp__tcp_slice__` (fixture 144) generates.
#
# All seven in one unit on purpose. The audit withdrew them as a set, on the
# stated ground that they only made sense together with the bundle attach kind;
# this fixture is where "they come back as a set" is pinned. It also fixes the
# section ORDER in the golden: the two syncookie helpers, then the shared
# checksum pair, then reply_header / reply_synack / synack_cookie, then the
# reply bodies, then the payload matchers. That order is not cosmetic -- the
# emitted C has no forward declarations, so a helper has to precede its caller.
#
# The two literal-bearing builtins appear TWICE each with the same literal, so
# the golden shows one helper per DISTINCT literal (spnl_payload_match0/1,
# spnl_reply_data0) rather than one per call site.
XDP_PASS    = 2
XDP_DROP    = 1
XDP_TX      = 3
XDP_ABORTED = 0

def xdp__slice
  flags = pkt.tcp.flags
  if (flags & TCP::Flag::SYN) != 0 && (flags & TCP::Flag::ACK) == 0
    # #3 gen + #4b: cookie first, then the SYN-ACK that carries it in the MSS
    # option. The one-step spelling of the same sequence is tcp_synack_cookie.
    cookie = tcp_syncookie_gen
    if cookie < 0
      XDP_ABORTED
    elsif tcp_reply_synack(cookie) < 0
      XDP_ABORTED
    else
      XDP_TX
    end
  elsif (flags & TCP::Flag::ACK) == 0
    XDP_DROP
  elsif pkt.l4.payload_len == 0
    # #3 check: validate the cookie the client echoed back in the handshake ACK.
    if tcp_syncookie_check < 0
      XDP_DROP
    else
      flow_set(:conn, :state, 1)
      XDP_DROP
    end
  elsif payload_starts("GET /health ")
    # #5b: data response. Same literal twice below -> ONE const body in the golden.
    if tcp_reply_data(pkt.tcp.ack, pkt.tcp.seq + pkt.l4.payload_len,
                      "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n") < 0
      XDP_ABORTED
    else
      flow_set(:conn, :state, 3)
      XDP_TX
    end
  elsif payload_starts("GET /health ")
    # deliberately the SAME prefix as above: the matcher is interned, not re-emitted.
    XDP_DROP
  elsif payload_starts("GET /ping ")
    if tcp_reply_data(pkt.tcp.ack, pkt.tcp.seq + pkt.l4.payload_len,
                      "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n") < 0
      XDP_ABORTED
    else
      XDP_TX
    end
  elsif (flags & TCP::Flag::FIN) != 0
    # #4: header-only reply (no payload) -- the FIN-ACK that closes the flow.
    if tcp_reply_header(pkt.tcp.ack, pkt.tcp.seq + 1,
                        TCP::Flag::FIN | TCP::Flag::ACK) < 0
      XDP_ABORTED
    else
      XDP_TX
    end
  else
    XDP_DROP
  end
end

# #4b': the integrated SYN -> SYN-ACK+cookie step, in its own program so the
# golden shows it emitted independently of the gen/reply_synack pair above.
def xdp__slice_oneshot
  if tcp_synack_cookie < 0
    XDP_ABORTED
  else
    XDP_TX
  end
end

puts "[174] pure-XDP TCP slice builtins"
