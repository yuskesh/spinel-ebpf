# Userspace consumer DSL (on_emit). spinel-ebpf lowers on_emit/consume_events to
# plain Ruby and wires in the glue drain FFI. Produces the same result as the
# hand-written consume_poc.rb (@sum=10) but with a boilerplate-free DSL.
#
# build: bin/spinel-ebpf compile examples/observability/consume_dsl.rb --build --ebpf-dispatch -o build
# run:   ./build/consume_dsl    # -> 10  (= 0+1+2+3+4)
@sum = 0

def produce(n)
  n.times { |i| spnl_emit(i) }    # :ebpf, dispatch emits 0..n-1
end

on_emit do |v|                    # userspace consumer (one call per emit)
  @sum = @sum + v
end

produce(5)
consume_events(200)               # drain + route each event to the on_emit handler
puts @sum
