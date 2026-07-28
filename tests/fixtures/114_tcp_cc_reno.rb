# Reno-style TCP congestion control written in Ruby.
# Purpose: pin the codegen output for a tcp_congestion_ops struct_ops load, the
# tcp_sock_* field accessors (reader / writer / adder) and the sk.<field> dot
# accessor against the golden files.

class RenoCC < BPF::TcpCC
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
