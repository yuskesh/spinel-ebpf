# dynamic string concat — partition should mark as eBPF-ineligible
def greet(name)
  "hello, " + name + "!"
end

s = greet("world")
puts s.length
puts s
