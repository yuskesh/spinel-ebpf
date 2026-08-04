# The codegen must REJECT this.
#
# `param :verbosity` is declared and then never read. The declaration is a
# promise to the operator -- it puts SPNL_PARAM_VERBOSITY in `describe` and makes
# the loader accept it -- and nothing behind it changes. Setting it would produce
# exactly the output of not setting it, which is the failure mode that looks like
# "the filter matched nothing" and cannot be told apart from it at run time.
#
# There is no golden for this fixture; the refusal is the contract
# (tests/golden/codegen_reject.tsv + tests/spinel_ebpf/param_test.rb).
param :verbosity, default: 1

def spnl_emit(x)
  # placeholder (builtin)
end

def tracepoint__syscalls__sys_enter_openat(dfd)
  @opens += 1
  spnl_emit(dfd)
  0
end
