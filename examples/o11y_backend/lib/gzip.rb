# gzip inflate, FFI surface. Implementation: native/o11y_gzip.c (zlib).
#
#   out = GZ.o11y_gunzip(data, data.length)   # :binstr
#   GZ.o11y_gunzip_err != 0 means failure (1 = size cap exceeded,
#   5 = truncated stream, negative = zlib code)
#
# A gzip of an empty message is legitimate (out = "" AND err = 0), so success
# must always be judged by err, never by emptiness.

module GZ
  ffi_lib "z"
  ffi_cflags "native/o11y_gzip.c"
  ffi_func :o11y_gunzip,     [:str, :int], :binstr
  ffi_func :o11y_gunzip_err, [],           :int
end
