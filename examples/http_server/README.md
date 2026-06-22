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
| `http-1.0-server` | single-process HTTP/1.0 accept loop |
| `l7-path-counter` | an L7 per-path counter that lives in a BPF map |
| `so-reuseport` | multiple worker processes sharing a port via SO_REUSEPORT |
| `keepalive` | HTTP/1.1 persistent connections on top of SO_REUSEPORT |
| `epoll` | one worker per core multiplexing many connections with epoll |
| `pure-xdp-tcp-slice` | handshake + request + response served entirely in XDP, no kernel TCP socket |
