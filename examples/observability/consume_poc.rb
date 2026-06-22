# PoC: userspace consumer — process eBPF events in Ruby.
#
# Demonstrates the core idea (spinel-Ruby userspace aggregating emitted events
# with Ruby logic) in a minimal hand-written form. The future
# `on_emit do |v| ... end` DSL hides this boilerplate (ffi_func drain + driver
# loop) inside the codegen.
#
# build:  bin/spinel-ebpf compile examples/observability/consume_poc.rb --build --ebpf-dispatch -o build
# run:    ./build/consume_poc        # -> 10 (=0+1+2+3+4) then 5 (event count)
#
# How it works:
#   - produce(5) is :ebpf + transparent dispatch. bpf_prog_test_run runs the
#     kernel-side BPF program, which spnl_emits 0..4 into a per-unit ringbuf.
#   - spnl_cdrain / spnl_cget are FFIs provided by the glue (spinel -> glue
#     direction). They drain the ringbuf into a static buffer and let Ruby read
#     the values out.
#   - Aggregation uses a top-level ivar (@sum) = a shared native global. The
#     consumer logic runs in userspace, so there are no verifier constraints
#     (full Ruby).
module Consume
  ffi_func :spnl_cdrain, [:int], :int   # drain int-emit ringbuf, returns count
  ffi_func :spnl_cget,   [:int], :int   # value of buffered event i
end

@sum = 0

def produce(n)
  n.times { |i| spnl_emit(i) }
end

produce(5)
cnt = Consume.spnl_cdrain(200)
i = 0
while i < cnt
  @sum = @sum + Consume.spnl_cget(i)
  i = i + 1
end
puts @sum
puts cnt
