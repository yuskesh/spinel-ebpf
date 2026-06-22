# C keyword sanitizer demo.
#
# Param names and local variables that collide with C reserved words
# (`double`, `register`, `static`, `volatile`) — the sanitizer rewrites
# each to `<name>_` so the generated .bpf.c compiles. The Ruby source
# is unmodified; verifier sees `__s64 double_, __s64 register_` and
# `__s64 static_ = 0;` `__s64 volatile_ = 0;` etc.
#
# Without the sanitizer this example failed at clang invocation with:
#   error: expected identifier or '('
#   __s64 double = 0;
#         ^
#
# Build:
#   bin/spinel-ebpf compile examples/observability/c_keyword_collision_demo.rb \
#                   -o build/c_keyword --build
# Run:
#   ./build/c_keyword/c_keyword_collision_demo &
#   touch /tmp/probe_target   # fires the openat kprobe

@total = 0

def kprobe__do_sys_openat2(double, register, how)
  static   = double + register
  volatile = static * 2
  @total = @total + volatile
end

puts "c_keyword_collision_demo loaded — exercise with file open"
sleep 3600
