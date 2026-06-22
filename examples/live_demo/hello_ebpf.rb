# Live demo: a method runs inside the kernel's eBPF VM.
# With --ebpf-dispatch, the add/square calls go through bpf_prog_test_run.
def add(a, b)
  a + b
end

def square(n)
  n * n
end

puts add(2, 3)     # => 5   (computed in-kernel by eBPF)
puts square(7)     # => 49  (same)
