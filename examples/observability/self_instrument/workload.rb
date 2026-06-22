# A multi-method, non-recursive instrumented workload.
#
# add / square / driver are all non-recursive. `cc -O2` normally inlines them
# away into their callers, but `--instrument` injects noinline into the selected
# methods, so sp_add / sp_square / sp_driver remain as symbols and can be
# measured with uprobes.
#
# build: bin/spinel-ebpf compile examples/observability/self_instrument/workload.rb --instrument -o build
# run (default = Prometheus /metrics):
#   SPNL_UPROBE_BINARY=$PWD/build/workload SPINEL_HTTP_PORT=9100 ./build/workload_agent &
#   ./build/workload    # N times, then curl localhost:9100/metrics
#   -> spnl_method_calls_total{method="add"} 10N  (and square), driver 1N,
#      spnl_method_latency_ns{...,quantile="0.5"} is driver >> add/square.
# To dump the histogram to stderr one-shot, use --instrument-dump.
# For a single self-attaching binary (no sidecar), use --instrument-self:
#   bin/spinel-ebpf compile <this> --instrument --instrument-self -o build
#   SPINEL_HTTP_PORT=9100 ./build/workload_self    # runs the workload -> /metrics
# For recursive methods, --instrument-depth-collapse measures only the outermost call.
def add(a, b)
  a + b
end

def square(x)
  x * x
end

def driver(n)
  i = 0
  total = 0
  while i < n
    total = add(total, square(i))
    i = i + 1
  end
  total
end

puts driver(10)   # calls add/square 10 times each, driver once -> 285
