# Comprehensive reactor block params demo — every attach kind
# (kprobe/kretprobe/fentry/fexit/tracepoint/uprobe/uretprobe/USDT) extracts
# block params and uses them.

module ReactorAllParamsDemo
  include BPF::EventLoop

  on :kprobe, "do_sys_openat2" do |dfd, filename|
    @k_dfd = dfd
    @k_calls = @k_calls + 1
  end

  on :kretprobe, "do_sys_openat2" do |ret|
    @kr_ret = ret
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
    @us_count = @us_count + 1
  end
end

@k_dfd = 0
@k_calls = 0
@kr_ret = 0
@tp_count = 0
@up_prompt = 0
@uret_ret = 0
@us_obj = 0
@us_count = 0

puts "reactor_all_params_demo loaded — exercise then dump ivars"
sleep 3600
