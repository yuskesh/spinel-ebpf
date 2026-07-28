# Zero-code HTTP L7 RED. Parse other processes' HTTP into method/path/status +
# duration on top of the send/recv correlation (the core of OBI/Beyla, in Ruby).
#
#   send (tcp_sendmsg, process ctx): http_req_start reads the first 64 bytes of the send
#     buffer; if it is an HTTP request (real method, not an "HTTP" response), stores
#     {start, req[64]} keyed by sock. Server-side response-sends start with "HTTP" so they
#     never match -> only the CLIENT request is captured; non-HTTP traffic is ignored.
#   recv entry (tcp_recvmsg): http_resp_stash stashes {sk, buffer-start} by tid. The response
#     bytes are only in the user buffer AFTER the copy, so we read them in the kretprobe.
#   recv return (kretprobe/tcp_recvmsg): http_emit reads the stashed buffer (status), correlates
#     with the pending request by sock, and emits ONE combined record (method/path + status +
#     duration). method/path/status parsing is done in userspace (kernel does a bounded copy).
#
# tcp_recvmsg is static-linkage so fexit is denied; the entry-stash + kretprobe pattern
# gets the response payload. MVP: 1 request = 1 send burst; HTTP/2 multiplexing is out of scope.
def kprobe__tcp_sendmsg(sk, msg, size)
  http_req_start(sk, msg)
  0
end

def kprobe__tcp_recvmsg(sk, msg)
  http_resp_stash(sk, msg)
  0
end

def kretprobe__tcp_recvmsg(ret)
  http_emit(ret)
  0
end
