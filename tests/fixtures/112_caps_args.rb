# 6-param tracepoint handler. The wrapper->inner boundary would pass 6
# extracted args, exceeding BPF's 5 arg-registers (r1-r5), so codegen switches
# to the caps-struct form (the same pointer passing the loop captures use): the wrapper packs every
# extractor into a stack struct and passes its pointer (1 reg), and the inner
# expands them back to param-named locals in a prologue (body codegen unchanged).
@established = 0
@fingerprint = 0
def tracepoint__sock__inet_sock_set_state(skaddr, oldstate, newstate, sport, dport, family)
  if newstate == 1
    @established += 1
    @fingerprint = skaddr + oldstate + sport + dport + family
  end
  0
end
