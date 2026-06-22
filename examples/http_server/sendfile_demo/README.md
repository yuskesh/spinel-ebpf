# sendfile_demo — sendfile(2) zero-copy static-file serving

A server that adds a single `GET /static` route to the HTTP/1.0 accept loop.
Only `/static` streams its body straight from the file page cache to the socket
with `sendfile(2)` (equivalent to nginx's `sendfile on`). HTTP framing stays in
Ruby; only the body transfer drops into the kernel.

| Route | Response | Path |
|---|---|---|
| `GET /static` | contents of `$SPINEL_STATIC_FILE` (200) / 404 if missing | header = `write`, body = **`sendfile`** |
| `GET /` | `hello\n` (200) | `write` (for contrast) |
| `GET /health` | `OK\n` (200) | `write` |
| other / non-GET / invalid | 404 / 405 / 400 | `write` |

## Build + run (container)

```bash
container exec spnlbuild bash -c '
  export LANG=C.UTF-8
  cd /work
  ruby bin/spinel-ebpf compile examples/http_server/sendfile_demo/server.rb \
    -o /tmp/sfd --build --native-only
  head -c 1048576 /dev/urandom > /tmp/static.bin
  SPINEL_HTTP_PORT=8189 SPINEL_STATIC_FILE=/tmp/static.bin /tmp/sfd/server &
  sleep 1
  curl -s http://127.0.0.1:8189/static -o /tmp/out.bin
  cmp /tmp/static.bin /tmp/out.bin && echo "byte-identical"
'
```

## Proof that sendfile is issued (strace)

```bash
strace -f -e trace=sendfile,sendto,write -o strace.log \
  env SPINEL_STATIC_FILE=/tmp/static.bin /tmp/sfd/server &
# after curl /static:
#   sendto(4, "HTTP/1.0 200 OK...", 103, ...) = 103      <- only the header goes via write
#   sendfile(4, 5, [0] => [1048576], 1048576) = 1048576  <- the 1MB body is kernel zero-copy
```

Apart from the header (at most 103 bytes), the 1MB body never passes through
`write` / `sendto`.
