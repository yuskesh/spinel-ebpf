# Observer for spinel-ebpf self-instrumentation.
#
# "spinel-ebpf instruments the AOT binary that spinel produced, using eBPF" — the
# inverse of the problem of fighting Go's DWARF. Because spinel is a compiler it
# can fix the function symbols (`sp_<method>`) and the argument ABI
# (PT_REGS_PARM<N>) at compile time, so it can attach uprobes without DWARF.
#
#   def uprobe__sp_fib(n)   ... attach a uprobe to `sp_fib` in the target binary,
#                               capturing the first argument n via PT_REGS_PARM1
#                               and emitting it to the ringbuf
#   on_emit do |v| ...      ... aggregate in userspace (the consumer DSL)
#
# build: bin/spinel-ebpf compile examples/observability/self_instrument/observer.rb \
#          --build --ebpf-dispatch -o build
# run:   SPNL_UPROBE_BINARY=$PWD/build/target ./build/observer &
#        ./build/target            # sp_fib fires 177 times
#   -> count=177  sum=364   (= 177 calls / sum of all n arguments)
@count = 0
@sum   = 0

def uprobe__sp_fib(n)
  spnl_emit(n)
end

on_emit do |v|
  @count = @count + 1
  @sum   = @sum + v
end

# Create a drain window via fixed-count polling (no sleep FFI, so we use the
# iteration count to make a time window). Each consume_events(100) is up to a
# 100ms epoll wait. 100 iterations = up to ~10s.
i = 0
while i < 100
  consume_events(100)
  i = i + 1
end

puts @count
puts @sum
