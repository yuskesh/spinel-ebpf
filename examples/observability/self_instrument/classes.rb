# Class / instance-method self-instrumentation.
#
# --instrument now resolves real C symbols from upstream `--emit-symbol-map`, so
# instance methods (sp_Accumulator_add, ...) are instrumentable too — not just
# top-level sp_<name>. The /metrics labels use the Ruby name (`Accumulator#add`).
#
# build: bin/spinel-ebpf compile examples/observability/self_instrument/classes.rb --instrument --instrument-self -o build
# run:   SPINEL_HTTP_PORT=9100 ./build/classes_self    then curl localhost:9100/metrics
#   -> Accumulator#add 10, Accumulator#total 1, Accumulator#initialize 1, driver 1
class Accumulator
  def initialize
    @sum = 0
  end

  def add(x)
    @sum = @sum + x
  end

  def total
    @sum
  end
end

def driver(n)
  acc = Accumulator.new
  i = 0
  while i < n
    acc.add(i)
    i = i + 1
  end
  acc.total
end

puts driver(10)   # add x10, total/initialize/driver x1 -> sum 0+1+..+9 = 45
