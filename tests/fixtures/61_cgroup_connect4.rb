# cgroup/connect4 — deny outbound IPv4 connections to port 9999, allow
# everything else. The if-expression value is the verdict: 1 = allow, 0 = deny
# (a denied connect() returns -EPERM). ctx is struct bpf_sock_addr *.
def cgroup__connect4__guard
  if sock_addr_port() == 9999
    0
  else
    1
  end
end
