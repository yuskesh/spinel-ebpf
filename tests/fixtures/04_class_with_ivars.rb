class Counter
  def initialize ; @count = 0 ; end
  def incr ; @count += 1 ; end
  def value ; @count ; end
end

c = Counter.new
5.times { c.incr }
puts c.value
