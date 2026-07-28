def kprobe__do_sys_openat2(dfd, filename)
  hist_observ(dfd)
end
