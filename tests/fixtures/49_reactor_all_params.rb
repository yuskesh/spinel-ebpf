# Comprehensive reactor block params coverage test.
# Exercises every attach kind that takes params with `do |...| ... end`.

module ReactorAllParams
  include BPF::EventLoop

  on :kprobe, "do_sys_openat2" do |dfd, filename|
    @k_dfd = dfd
    @k_calls = @k_calls + 1
  end

  on :kretprobe, "do_sys_openat2" do |ret|
    @kr_ret = ret
  end

  on :fentry, "tcp_v4_rcv" do |skb|
    @fe_calls = @fe_calls + 1
  end

  on :fexit, "tcp_v4_rcv" do |skb, ret|
    @fx_ret = ret
  end

  on :tracepoint, "syscalls", "sys_enter_write" do |fd, buf, count|
    @tp_count = count
  end

  on :uprobe, "/usr/bin/bash:readline" do |prompt|
    @up_prompt = prompt
  end

  on :uretprobe, "/usr/bin/bash:readline" do |ret|
    @uret_ret = ret
  end

  on :usdt, "/usr/lib/aarch64-linux-gnu/libstdc++.so.6", "libstdcxx", "throw" do |obj, tinfo, dest|
    @us_obj = obj
  end
end

@k_dfd = 0
@k_calls = 0
@kr_ret = 0
@fe_calls = 0
@fx_ret = 0
@tp_count = 0
@up_prompt = 0
@uret_ret = 0
@us_obj = 0
