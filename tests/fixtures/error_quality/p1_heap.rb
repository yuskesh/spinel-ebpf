def kprobe__do_sys_openat2(dfd, filename)
  [1, 2, 3].map { |n| n * 2 }
  @count += 1
end
