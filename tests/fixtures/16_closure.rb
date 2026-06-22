def spnl_emit(x)
  # placeholder; codegen replaces with ringbuf reserve/submit
end

# Classic reduction: sum of squares 0..n-1.
# Captures `total` (outer local) for read+write in the block.
def sum_squares(n)
  total = 0
  n.times { |i| total = total + i * i }
  total
end

# Running sum, emitting each partial.
def emit_running_sum(n)
  acc = 0
  n.times do |i|
    acc = acc + i
    spnl_emit(acc)
  end
  acc
end

puts sum_squares(4)        # 0+1+4+9 = 14
puts emit_running_sum(5)   # final acc = 0+1+2+3+4 = 10
