# Redis L7 RED -- command/error/duration span for other processes' Redis (RESP) traffic.
# Generalizes the HTTP L7 RED to a non-HTTP wire protocol. Same send/recv correlation and
# the same three TCP hooks; only the kernel filter (RESP command sniff instead of HTTP method)
# and the userspace parse (RESP command / -ERR reply instead of method/path/status) differ.
#
#   send (tcp_sendmsg, process ctx): redis_req_start reads the first `size` bytes (bounded to the
#     actual send length -- Redis messages are short, so a fixed 64B read would -EFAULT); if it looks
#     like a RESP command (array-of-bulk-strings "*<digit>"), stores {start, req[64]} keyed by sock.
#   recv entry (tcp_recvmsg): redis_resp_stash stashes {sk, buffer-start} by tid (reply bytes are
#     only in the user buffer AFTER the copy, read in the kretprobe).
#   recv return (kretprobe/tcp_recvmsg): redis_emit reads the stashed reply, correlates with the
#     pending request by sock, and emits ONE combined record. command (rate) / -ERR reply (error) /
#     duration parsing is done in userspace (kernel does a bounded copy).
def kprobe__tcp_sendmsg(sk, msg, size)
  redis_req_start(sk, msg, size)
  0
end

def kprobe__tcp_recvmsg(sk, msg)
  redis_resp_stash(sk, msg)
  0
end

def kretprobe__tcp_recvmsg(ret)
  redis_emit(ret)
  0
end
