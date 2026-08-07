def spnl_emit(x)
  # placeholder; codegen replaces with ringbuf reserve/submit
end

@total = 0

# Literal N -> open-coded iterator. The loop is inlined into the caller
# with bpf_iter_num_new/next/destroy, so the block writing an outer local
# (`total`) needs no capture struct at all — it is the same variable in the
# same function. Contrast fixture 16, where the same shape goes through a
# bpf_loop callback and a generated `*_caps` struct.
def sum_first_four
  total = 0
  4.times do |i|
    total = total + i * i
  end
  total
end

# Literal N with no outer local: the body touches only the block param and the
# unit-level ivar (which lives in a map, not the stack).
def kprobe__do_sys_openat2
  3.times do |i|
    @total = @total + i
    spnl_emit(@total)
  end
end

# Dynamic N still takes the bpf_loop callback path — the two lowerings
# have to coexist in one unit.
def sum_dynamic(n)
  acc = 0
  n.times do |i|
    acc = acc + i
  end
  acc
end

puts sum_first_four   # 0 + 1 + 4 + 9 = 14
puts sum_dynamic(5)   # 0+1+2+3+4 = 10
