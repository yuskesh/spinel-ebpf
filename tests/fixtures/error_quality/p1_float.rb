def kprobe__do_sys_openat2(dfd, filename)
  x = 1.5
  @count += x
end
