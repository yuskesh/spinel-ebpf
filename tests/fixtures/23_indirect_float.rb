# needs_float_indirect's body has NO literal FloatNode, but spinel infers
# its param type as float because main calls it with 2.5. Without T-record
# checking, partition would (wrongly) tag this method as :ebpf.

def needs_float_indirect(x)
  x * 2
end

def pure_int(a, b)
  a + b
end

puts needs_float_indirect(2.5)
puts pure_int(3, 4)
