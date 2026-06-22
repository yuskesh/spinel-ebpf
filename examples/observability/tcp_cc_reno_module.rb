# Reno-like TCP CC written with `module ... include BPF::TcpCC`.
#
# Equivalent to the class-form tcp_cc_reno_class.rb and the
# flat-prefix tcp_cc_reno.rb, but uses module semantics — which
# is what Ruby reaches for when the type is a namespace, never
# instantiated, never has instance state. The generated .bpf.c is
# byte-identical to the class form.
#
# Build:
#   spinel-ebpf compile examples/observability/tcp_cc_reno_module.rb \
#       -o build/tcp_cc_reno_module --build
# Run:
#   ./build/tcp_cc_reno_module/tcp_cc_reno_module &
#   echo spnl_cc > /proc/sys/net/ipv4/tcp_congestion_control

module RubyReno
  include BPF::TcpCC

  def init(sk)
    0
  end

  def ssthresh(sk)
    half = sk.snd_cwnd / 2
    if half < 2
      2
    else
      half
    end
  end

  def undo_cwnd(sk)
    sk.prior_cwnd
  end

  def cong_avoid(sk, ack, acked)
    if sk.snd_cwnd < sk.snd_ssthresh
      sk.snd_cwnd += acked
    else
      cnt = sk.snd_cwnd_cnt + acked
      if cnt >= sk.snd_cwnd
        sk.snd_cwnd += 1
        sk.snd_cwnd_cnt = 0
      else
        sk.snd_cwnd_cnt = cnt
      end
    end
  end

  def set_state(sk, new_state)
    0
  end
end

puts "RubyReno (spnl_cc) loaded via module + include BPF::TcpCC"
sleep 3600
