# LSM + fmod_ret attach.
#
# lsm__<hook>  -> SEC("lsm/<hook>")      (BPF_PROG_TYPE_LSM): return 0 to allow,
#                                         a negative errno to deny the access.
# fmod_ret__<f> -> SEC("fmod_ret/<f>")   (BPF_MODIFY_RETURN): the handler's
#                                         return value replaces <f>'s.
# Both read args (and the trailing prior-verdict / ret) as ctx[i], like fexit.
@opens    = 0
@injected = 0

def lsm__file_open(file, ret)
  @opens = @opens + 1
  0
end

def fmod_ret__security_file_open(file, ret)
  @injected = @injected + 1
  ret
end
