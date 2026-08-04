# Negative: has_cap() in an XDP handler.
#
# This is the failure the gate exists for, and it is the quiet kind. The read
# LOADS in every program type the codegen emits (24 of 24 measured, same as the
# bpf_probe_read_kernel that ungated kfield uses), and it returns a real
# capability set for a real process -- just not the one that sent the packet.
#
# Measured: with packets arriving on eth0 from another machine and CPU burners
# running, an XDP program asking this exact question answered TRUE about a
# burner, while the actual actor (running with CAP_SYS_ADMIN dropped) answered
# FALSE in a kprobe in the same run. Nothing downstream can tell the two apart.
#
# So the refusal is at compile time, not left to the verifier -- which has no
# opinion here -- and not to the author.
@suspicious = 0

def xdp__probe
  if has_cap(CAP::SYS_ADMIN) == 1
    @suspicious = @suspicious + 1
  end
  XDP_PASS
end
