def spnl_emit(x)
  # placeholder; codegen replaces with ringbuf reserve/submit
end

# Emit each i^2 for i in 0..n-1. Block body uses block param `i` only —
# no outer-local capture. This is the minimal supported shape.
def emit_squares(n)
  n.times { |i| spnl_emit(i * i) }
end

# Also test the trivial form without arithmetic in body.
def emit_indices(n)
  n.times { |i| spnl_emit(i) }
end

emit_squares(4)   # expect 0, 1, 4, 9 emitted
emit_indices(3)   # expect 0, 1, 2 emitted
