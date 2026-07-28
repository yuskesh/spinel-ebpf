# Off-CPU / kernel-wait correlated into the L7 span -- "why is this request slow".
# Server-oriented: a request arrives (tcp_recvmsg, method), the handler thread does work
# (sleep / disk I/O / CPU spin), the response leaves (tcp_sendmsg, "HTTP"). Between recv and
# send, on the SAME tid, sched_switch accumulates the thread's VOLUNTARY off-CPU time
# (prev_state != 0) and captures the wait's kernel stack. The span then carries offcpu_ns /
# oncpu_ns / wait.kind: "the 306ms /sleep was 306ms off-CPU (timer wait); the 300ms /spin was
# 0ms off-CPU (CPU-bound)". Reuses the off-CPU profiler and the L7 request-window machinery.
#
# duration ~= oncpu + offcpu. MVP: 1 request = 1 handler thread; multiplexing is out of scope.
def kprobe__tcp_recvmsg(sk, msg)
  offcpu_recv_stash(sk, msg)
  0
end

def kretprobe__tcp_recvmsg(ret)
  offcpu_begin(ret)
  0
end

def tracepoint__sched__sched_switch(prev_pid, prev_state, next_pid)
  offcpu_account(prev_pid, prev_state, next_pid)
  0
end

def kprobe__tcp_sendmsg(sk, msg)
  offcpu_emit(sk, msg)
  0
end
