def spnl_emit(x)
  # placeholder; codegen replaces with ringbuf reserve/submit
end

@last = 0

# `if` in EXPRESSION position. The temp-variable lowering was built for exactly
# this case, and the retired Ruby generator documented a dedicated
# expression-position path for it (`x = if ... end` and friends). The move to
# the in-process C generator wired IfNode into the statement lowering only, so
# the value form died while three neighbours kept working -- which is why no
# fixture noticed: the affordance line "if / elsif / else, including as an
# expression" was six-sevenths true.
def classify(a)
  n = if a > 10
    2
  elsif a > 0
    1
  else
    0
  end
  n
end

# The same node in the other two expression positions that were dead: the value
# of an ivar write, and an operand inside a larger expression.
def kprobe__do_sys_openat2(a)
  @last = if a > 0
    1
  else
    0
  end
  spnl_emit(classify(a) + (if a > 100 then 1 else 0 end))
end

# The statement form, which never broke -- kept beside the value form so the
# golden shows both lowerings of the same node in one unit.
def sign(a)
  if a > 0
    1
  else
    -1
  end
end

puts classify(42)
puts sign(-3)
