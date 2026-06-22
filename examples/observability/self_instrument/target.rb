# The instrumented program (target) for self-instrumentation.
#
# The binary spinel AOT-compiles lowers the Ruby method `def fib` to the C
# function `sp_fib`. Recursive methods are not inlined even with `cc -O2`, so the
# symbol remains in .symtab (a non-recursive method like `def work` disappears
# via inlining). observer.rb instruments this `sp_fib` symbol with a uprobe.
#
# build: bin/spinel-ebpf compile examples/observability/self_instrument/target.rb --native-only -o build
# run:   ./build/target            # -> 55 (fib(10))
#   fib(10) is naive recursion and calls sp_fib 2*fib(11)-1 = 177 times.
def fib(n)
  if n < 2
    n
  else
    fib(n - 1) + fib(n - 2)
  end
end

puts fib(10)
