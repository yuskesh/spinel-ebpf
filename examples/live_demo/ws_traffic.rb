# Live demo: visualize, with eBPF, the bytes the server (:8080) serving this
# terminal pushes to the browser. The output of ls / cat / vi you type in the
# terminal above flows server -> browser as WebSocket frames, and a kprobe in the
# kernel catches the moment each frame is sent.
#
# Two filters:
#   port == 8080  -- only this deck server's socket (drop other traffic noise)
#   size  > 256   -- only "meaningful" sends (drop small ones: prompt echo, WS
#                    headers, etc.)
#
# The size > 256 filter also breaks the feedback loop: this tracer's own output
# lines (~25B each) are under 256, so they aren't observed -- running it from the
# terminal below won't spiral.
#
# Note: both port == 8080 (kfield reads sk->__sk_common.skc_num via CO-RE) and the
# size > 256 comparison sit inside `if ... end` (no else), which widens the return
# type to a nullable int. Nullability is orthogonal to eBPF eligibility, so this
# straightforward style compiles to eBPF as written.
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def kprobe__tcp_sendmsg(sk, msg, size)
  port = kfield(sk, "sock", "__sk_common.skc_num")
  if port == 8080 && size > 256
    spnl_emit(size)            # bytes pushed server (:8080) -> browser
  end
end

puts "[ws-traffic] eBPF: streaming :8080 server -> browser bytes (>256B only):"
Stream.spnl_stream(0)
