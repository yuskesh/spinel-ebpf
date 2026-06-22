# USDT (User Statically-Defined Tracing) smoke fixture.
# Provider/probe pair encoded in the method name; binary path comes from
# SPNL_USDT_BINARY env var. Args are read via bpf_usdt_arg().

@catches = 0
@throws = 0

def usdt__libstdcxx__throw(obj, tinfo, dest)
  @throws += 1
end

def usdt__libstdcxx__catch(obj, tinfo)
  @catches += 1
end
