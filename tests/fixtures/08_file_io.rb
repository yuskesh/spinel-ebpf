# exercises @needs_file_io — eBPF-impossible (host-side only)
def read_first_line(path)
  File.open(path, "r") { |f| f.gets }
end

puts read_first_line("/etc/hostname")
