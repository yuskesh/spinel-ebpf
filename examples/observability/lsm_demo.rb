@opens = 0
def lsm__file_open(file, ret)
  @opens = @opens + 1
  0
end
puts "lsm/file_open attaching..."
sleep 3600
