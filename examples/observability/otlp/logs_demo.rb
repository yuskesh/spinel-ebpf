# emit -> OTLP logs demo.
#
# produce(n) runs in BPF through transparent dispatch and spnl_emits
# 0, 10, .., (n-1)*10 into the per-unit emit ringbuf. spnl_otlp_log_push drains
# that ringbuf, turns each event into an OTLP LogRecord (body=int) and POSTs it
# to the Collector. This path is general and does not depend on --instrument.
#
# build: bin/spinel-ebpf compile examples/observability/otlp/logs_demo.rb --build --ebpf-dispatch -o build
# run:   OTLP_ENDPOINT=http://127.0.0.1:4318 ./build/logs_demo
module Otlp
  ffi_func :spnl_otlp_log_push, [:str], :int
end

def produce(n)
  n.times { |i| spnl_emit(i * 10) }
end

produce(5)
ep = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
st = Otlp.spnl_otlp_log_push(ep)
puts "[logs_demo] OTLP logs push -> " + ep + " HTTP " + st.to_s
