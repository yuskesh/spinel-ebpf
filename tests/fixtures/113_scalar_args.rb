# Control case (below the boundary): the same handler with 5 params. The
# effective register count is 5 (no ctx forward, 5 extracted args), which fits
# BPF's 5 arg-registers, so codegen keeps the scalar arg-passing form. This is
# the proof that attach handlers with 5 or fewer params stay byte-identical.
@established = 0
@fingerprint = 0
def tracepoint__sock__inet_sock_set_state(skaddr, oldstate, newstate, sport, dport)
  if newstate == 1
    @established += 1
    @fingerprint = skaddr + oldstate + sport + dport
  end
  0
end
