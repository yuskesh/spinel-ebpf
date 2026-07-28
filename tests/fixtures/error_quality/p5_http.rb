def kprobe__tcp_sendmsg(sk, msg)
  http_req_start(sk, msg)
end
