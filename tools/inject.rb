# inject — bcc inject equivalent: fault-inject errors into a kernel function.
#
# Overrides security_file_open via fmod_ret (BPF_MODIFY_RETURN): returning a
# non-zero value skips the real function and makes that value the return, so
# open() fails. We SCOPE the injection by process name (comm) — only a process
# named "injtest" gets -EPERM; every other process passes through the kernel's
# real verdict (return 0). This is the safe, predicate-driven form of bcc inject:
# the policy ("which process, which error") is written in Ruby and compiled.
#
#   cp /bin/cat /tmp/injtest                       # victim has comm "injtest"
#   bin/spinel-ebpf compile tools/inject.rb --build -o build/inject
#   sudo ./build/inject/inject &                   # arms the injection
#   /tmp/injtest /etc/hostname                     # -> Operation not permitted
#   cat /etc/hostname                              # -> works (not injected)
@injected = 0

def fmod_ret__security_file_open(file, ret)
  # 0x747365746a6e69 = first 8 bytes of comm "injtest" as little-endian s64.
  if comm_hash == 32777976880459369
    @injected += 1
    -1            # non-zero -> skip security_file_open, return -EPERM
  else
    0             # zero -> run the real LSM verdict
  end
end

puts "[inject] failing open() for comm=injtest via fmod_ret/security_file_open (8s)"
sleep 8
