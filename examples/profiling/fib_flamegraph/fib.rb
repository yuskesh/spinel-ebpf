# examples/profiling/fib_flamegraph/fib.rb
#
# Naive recursive Fibonacci, identical source for CRuby and spinel.
# Pure CPU-bound integer workload (no I/O), so an on-CPU flame graph shows
# exactly where the time goes. Run the SAME file two ways:
#
#   CRuby :  FIB_N=38 ruby fib.rb
#   spinel:  spinel-ebpf compile fib.rb -o build --build --native-only
#            FIB_N=38 ./build/fib
#
# FIB_LOOPS repeats the computation so the faster build (spinel, ~25x) can be
# sampled for a comparable wall-clock window without changing the call shape.
# This is NOT eBPF — it is userspace native (spinel AOT) vs the CRuby
# interpreter. Recursion is fine here; the eBPF verifier's no-recursion rule
# only applies to :ebpf methods.

def fib(n)
  if n < 2
    return n
  end
  fib(n - 1) + fib(n - 2)
end

n     = (ENV["FIB_N"]     || "32").to_i
loops = (ENV["FIB_LOOPS"] || "1").to_i
i = 0
acc = 0
while i < loops
  acc = fib(n)
  i = i + 1
end
puts acc
