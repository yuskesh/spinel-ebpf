# Class-based attach. Same Reno-like CC as tcp_cc_reno.rb but
# written with `class MyCC < BPF::TcpCC` instead of the
# `def tcp_cc__<member>` flat-prefix form.
#
# Each method inside a `BPF::*` subclass is enumerated by partition.rb
# as if it were a top-level `<prefix>__<method_name>` method, so the
# rest of the codegen pipeline is untouched. Surface syntax only.
#
# Build:
#   spinel-ebpf compile examples/observability/tcp_cc_reno_class.rb \
#       -o build/tcp_cc_reno_class --build
# Run:
#   ./build/tcp_cc_reno_class/tcp_cc_reno_class &
#   echo spnl_cc > /proc/sys/net/ipv4/tcp_congestion_control

class RubyReno < BPF::TcpCC
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

puts "RubyReno (spnl_cc) loaded via class < BPF::TcpCC"
sleep 3600
