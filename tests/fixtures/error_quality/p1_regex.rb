def kprobe__do_sys_openat2(dfd, filename)
  if filename =~ /secret/
    @count += 1
  end
end
