# polymorphic dispatch — exercise spinel's @cls_meth_ptypes / poly type detection
class Shape
  def area ; 0 ; end
end

class Square < Shape
  def initialize(s) ; @side = s ; end
  def area ; @side * @side ; end
end

class Triangle < Shape
  def initialize(b, h) ; @b = b ; @h = h ; end
  def area ; @b * @h / 2 ; end  # int division to avoid Float
end

shapes = [Square.new(4), Triangle.new(3, 6)]
total = 0
shapes.each { |s| total += s.area }
puts total
