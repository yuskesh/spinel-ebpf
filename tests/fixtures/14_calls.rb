def twice(x)
  x * 2
end

def quad(x)
  twice(x) + twice(x)
end

def six_times(x)
  twice(x) + quad(x)
end

puts quad(3)
puts six_times(5)
