# L7 request/response latency via send->recv correlation on the TCP stream.
# tcp_sendmsg (process ctx) records the send time keyed by the sock ptr (req_start,
# first send of a request only); tcp_cleanup_rbuf (fires AFTER data is copied to the
# app = "response visible") looks it up and emits the round-trip latency (emit_l7),
# then deletes the entry so the next send is a new request.
#
# tcp_cleanup_rbuf is the correct recv point: an ENTRY kprobe on tcp_recvmsg would
# fire when the app CALLS read (blocks before data), giving ~0; tcp_recvmsg is
# static-linkage so fexit is denied. Verified: a slow endpoint makes duration grow.
#
# MVP boundary: 1 request = 1 send burst, 1 response = the following recv. Pipelining
# / HTTP-2 multiplexing (multiple outstanding requests on one sock) is handled separately.
def kprobe__tcp_sendmsg(sk, msg, size)
  req_start(sk)
  0
end

def kprobe__tcp_cleanup_rbuf(sk, copied)
  if i32(copied) > 0   # `copied` is a 32-bit int; i32() reads it correctly (upper bits are garbage)
    emit_l7(sk)
  end
  0
end
