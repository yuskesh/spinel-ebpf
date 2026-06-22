# C keyword collision sanitizer smoke fixture.
# A kprobe handler whose param names (`double`, `register`) and local
# variables (`static`, `volatile`) collide with C reserved words.
# Without sanitizer this would not compile (`__s64 double = ...;` is invalid).

def kprobe__do_test(double, register)
  static = double + register
  volatile = static * 2
  spnl_emit(volatile)
end
