# Correlate off-CPU / kernel wait with an L7 span, so the span carries the reason
# it was slow -- what it was waiting on.
#
# The sibling L7 examples turn an event into a span. This one produces **a
# breakdown of where an L7 request spent its time**. It shows that "/slow took
# 309ms" really means it was waiting on disk I/O, or contending on a lock, or
# genuinely burning CPU. This is territory specific to eBPF, and one where
# OBI/Pixie are weak. It joins off-CPU accounting with the request window used by
# the L7 and HTTP examples.
#
# How it works (SERVER point of view, one thread per request):
#   1. tcp_recvmsg (the request arrives): offcpu_recv_stash stashes the receive
#      buffer, and offcpu_begin in the kretprobe **opens an off-CPU window for the
#      handling tid** if it is an HTTP request (start + req[64]).
#   2. sched:sched_switch: for a tid with an open window, offcpu_account
#      accumulates **the total voluntary off-CPU time (prev_state != 0)** and
#      captures **the kernel stack of the wait** -- why it went to sleep.
#   3. tcp_sendmsg (the response goes out): offcpu_emit closes the window and adds
#      **spnl.offcpu_ns / spnl.oncpu_ns (= duration - offcpu) / spnl.wait.kind**
#      to the method, path, status and duration to make the span.
#
# The L7 span then carries both "slow" and "why slow", which puts a breakdown
# behind the Duration axis of RED. Measured:
#   /sleep (nanosleep 300ms) -> offcpu ≈ duration, wait.kind=sleep
#   /spin  (300ms of CPU)    -> offcpu ≈ 0,        wait.kind=none  (CPU-bound)
#   /io    (fsync)           -> offcpu covers the I/O wait (wait.kind=io,
#                               depending on the storage)
#
# semconv: `spnl.offcpu_ns`, `spnl.oncpu_ns` and `spnl.wait.kind` are our own keys
#   -- semconv has nothing equivalent, so they are named explicitly. The http.*
#   attributes are shared with the cleartext HTTP example. span.kind=SERVER, since
#   what is being observed is the request handler. status >= 500 becomes ERROR.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_offcpu.rb --build -o build/audit_offcpu
#   OTEL_SERVICE_NAME=spinel-offcpu-breakdown \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_offcpu/audit_offcpu
#   # Point it at a cleartext HTTP server (nginx, gunicorn, anything not going
#   # through OpenSSL). Opening a slow span in APM shows the breakdown of the
#   # wait: off-CPU (I/O or sleep) versus on-CPU (CPU-bound).
#
# Notes, all measured:
#   - System-wide, from the SERVER point of view (recv = request, send = response),
#     assuming one request per handler tid.
#   - sched_switch is a high-frequency hook that fires on every CPU switch. The
#     overhead has not been measured.
#   - A full stack (flame graph) is out of scope here. wait.kind classifies the
#     top frame of the last wait's stack and is best-effort.

module Otlp
  ffi_func :spnl_otlp_offcpu_span_push, [:str], :int
end

def kprobe__tcp_recvmsg(sk, msg)
  offcpu_recv_stash(sk, msg)   # stash the request receive buffer
  0
end

def kretprobe__tcp_recvmsg(ret)
  offcpu_begin(ret)            # open the off-CPU window if this is an HTTP request
  0
end

def tracepoint__sched__sched_switch(prev_pid, prev_state, next_pid)
  offcpu_account(prev_pid, prev_state, next_pid)   # accumulate voluntary off-CPU inside the window
  0
end

def kprobe__tcp_sendmsg(sk, msg)
  offcpu_emit(sk, msg)         # sending the response closes the window and emits the span with its breakdown
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-offcpu] L7 request off-CPU breakdown (why slow) -> OTLP span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_offcpu_span_push(ep)
  puts "[audit-offcpu] offcpu spans pushed -> " + ep + " HTTP " + st.to_s
end
