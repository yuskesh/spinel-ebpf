# Built-in spnl_emit(x) pushes an int event into the ringbuf.
# The stub def below is required so spinel can type-check the call.

def spnl_emit(x)
  # placeholder — codegen replaces calls to this with ringbuf reserve/submit
end

def report(x)
  spnl_emit(x)
end

def report_doubled(x)
  spnl_emit(x + x)
end

report(42)
report_doubled(10)
