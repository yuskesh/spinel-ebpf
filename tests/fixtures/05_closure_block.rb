def sum_squares(n)
  total = 0
  n.times { |i| total += i * i }
  total
end

puts sum_squares(5)
