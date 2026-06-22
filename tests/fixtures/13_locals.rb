def calc(a, b)
  x = a + b
  y = x * 2
  y - 1
end

def step(n)
  inc = n + 1
  doubled = inc * 2
  doubled
end

def reassign(n)
  acc = 0
  acc = acc + n
  acc = acc + n
  acc
end

puts calc(3, 4)
puts step(5)
puts reassign(7)
