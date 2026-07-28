# examples/http_server/

HTTP servers written in Ruby and compiled with spinel-ebpf, demonstrating the
project goal: implement an HTTP server with spinel + eBPF. Each subdirectory is
a complete, working server that builds on the previous one with one more
optimization.

## Layout

```
examples/http_server/
├── README.md            # this file
├── http-1.0-server/     # single-process HTTP/1.0 server
│   ├── server.rb        # spinel input Ruby
│   └── http_parser.rb   # request-line parser
├── l7-path-counter/     # adds an L7 per-path counter living in a BPF map
│   └── server.rb
├── so-reuseport/        # multi-process, SO_REUSEPORT across workers
│   └── server.rb
├── keepalive/           # SO_REUSEPORT + HTTP/1.1 keepalive (persistent connections)
│   └── server.rb
├── epoll/               # event-driven epoll HTTP/1.1 server
│   └── server.rb
├── pure-xdp-tcp-slice/  # pure-XDP TCP "slice": handshake + request + response
│   ├── server.rb        #   with no kernel TCP socket
│   ├── ruby_slice.rb
│   └── tcp_slice.rb
├── kernel_cache_demo/   # declare a route; serve it from the kernel (pure-XDP)
│   ├── ping.rb
│   └── routes.rb
├── sendfile_demo/       # sendfile(2) zero-copy static-file serving + dogfooding demos
│   ├── server.rb
│   ├── http_parser.rb
│   ├── serve_deck.rb
│   ├── serve_deck_term.rb
│   ├── serve_deck_pty.rb
│   └── README.md
└── ws_echo.rb           # WebSocket echo server, frame handling all in Ruby
```

The directories progress from a plain single-process HTTP/1.0 server up to a
server whose responses never leave the kernel.

## Running (example)

```bash
# Inside an Apple container:
container exec dev bash -c '
  cd /work/examples/http_server/http-1.0-server
  /work/bin/spinel-ebpf compile server.rb -o build --build --native-only
  ./build/server &
  sleep 1
  curl -v http://127.0.0.1:8080/
'
```

## Variants at a glance

| Directory | What it adds |
|---|---|
| `http-1.0-server/` | The baseline. A single-process accept loop plus a request-line parser: `GET /` and `GET /health` return 200, unknown paths 404, non-GET 405, malformed request lines 400. One request per connection (`Connection: close`). |
| `l7-path-counter/` | An L7 per-path counter that lives entirely in a BPF map. Each served request calls `record_path_hit(path_key)`, which is partitioned to the eBPF side and lands in the `bpf_path_counts` HASH map -- readable with `bpftool map dump name bpf_path_counts`. |
| `so-reuseport/` | Multiple worker processes. Each worker opens its own listen socket with SO_REUSEPORT on the same port, and the kernel's 5-tuple hash spreads incoming SYNs across the group. Everything from the L7 counter variant still applies. |
| `keepalive/` | HTTP/1.1 persistent connections on top of SO_REUSEPORT. Without keepalive, one request per connection makes the server RTT-bound over a real network, so it cannot be compared fairly against nginx. Pure userspace (builds `--native-only`, no libbpf) to isolate the keepalive question. |
| `epoll/` | An event-driven worker. The blocking keepalive model occupies a worker for the whole life of one connection, so N workers serve only N concurrent connections. Here each worker runs an epoll loop and multiplexes many connections, the way nginx does, so one worker per core saturates the machine. |
| `pure-xdp-tcp-slice/` | The response never reaches userspace. The kernel TCP stack does not listen on the port at all; the XDP program answers SYN / data / FIN itself, using `bpf_tcp_raw_gen_syncookie_ipv4` for the handshake and a per-flow state map for the rest. No `accept`, `read`, `write` or `close` on the server side. `tcp_slice.rb` is the DSL form, `ruby_slice.rb` writes the same slice as a plain Ruby `xdp__` method, and `server.rb` is the earlier XDP_TX variant that still uses the kernel handshake. |
| `kernel_cache_demo/` | Declaring a route is enough. `kernel_cache "/ping", body` makes spinel-ebpf synthesize a pure-XDP TCP slice that serves that path from the kernel -- no hand-written eBPF. `ping.rb` builds the body at runtime and pushes it into a BPF map; `routes.rb` declares several routes dispatched by one slice. |
| `sendfile_demo/` | `sendfile(2)` zero-copy static-file serving: HTTP framing stays in Ruby, and only the body bytes go from the file page cache straight to the socket, never through a userspace buffer (nginx's `sendfile on`). Also contains the dogfooding demos that serve the project's own presentation deck and a browser terminal. |
| `ws_echo.rb` | A WebSocket echo server with RFC 6455 handshake and frame parse / unmask / build / mask written entirely in Ruby -- no C shims. Client frames are masked binary and routinely contain NUL bytes, so the I/O is binary-safe throughout. |
