# fmod_ret on a security hook. Observe-only (returns the original verdict
# unchanged) so it is safe to run; proves BPF_MODIFY_RETURN attaches and fires.
# Overriding `ret` to a negative errno would deny the access.
@fired = 0
def fmod_ret__security_file_open(file, ret)
  @fired = @fired + 1
  ret
end
puts "fmod_ret/security_file_open attaching..."
sleep 3600
