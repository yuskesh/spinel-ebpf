# exercises @needs_regexp — partition should mark methods using regex as eBPF-impossible
def looks_like_email?(s)
  s =~ /\A[^@\s]+@[^@\s]+\z/ ? true : false
end

puts looks_like_email?("a@b.com")
puts looks_like_email?("nope")
