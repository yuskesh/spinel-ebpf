# AF_XDP (XSKMAP) + DEVMAP redirect. TCP frames are redirected to the
# AF_XDP socket in XSKMAP slot 0, UDP frames out the netdev in DEVMAP slot 0,
# everything else passes. Map slots are populated from userspace.
def xdp__redir
  p = pkt_l4_proto
  if p == IP::Proto::TCP
    xsk_redirect(0)
  elsif p == IP::Proto::UDP
    dev_redirect(0)
  else
    XDP::PASS
  end
end
