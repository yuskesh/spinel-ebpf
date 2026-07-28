def kprobe__tcp_sendmsg(sk, msg)
  http_req_start(sk, msg)
end

def kprobe__tcp_recvmsg(sk, msg)
  http_resp_stash(sk, msg)
end

def kretprobe__tcp_recvmsg(ret)
  http_emit(ret)
end
