def max(a, b)
  if a > b
    a
  else
    b
  end
end

def sign(x)
  if x > 0
    1
  elsif x < 0
    -1
  else
    0
  end
end

puts max(3, 7)
puts sign(-5)
