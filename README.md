# spinel-ebpf

**Write eBPF programs in Ruby.** spinel-ebpf takes Ruby — the statically-typed
subset that [matz/spinel](https://github.com/matz/spinel) AOT-compiles to C —
and *partitions* your methods: the ones that fit the eBPF execution model are
emitted as `.bpf.c` and loaded into the kernel, the rest stay native C — with
transparent calls across the boundary.

The result is that XDP/TC packet processing, kprobe/uprobe/tracepoint
observability, `struct_ops` schedulers and qdiscs, and even a kernel-assisted
HTTP server can all be written as Ruby methods, type-inferred and compiled ahead
of time, with no interpreter and no hand-written C.

```ruby
# count packets per L4 protocol, entirely in the kernel (XDP)
class ProtoCounter < BPF::XDP
  def run
    @total += 1
    @icmp  += 1 if pkt.l4.proto == IP::Proto::ICMP
    @tcp   += 1 if pkt.l4.proto == IP::Proto::TCP
    XDP::PASS
  end
end
```

```sh
spinel-ebpf compile proto_counter.rb --build   # -> a single binary that loads
                                               #    and attaches the XDP program
```

## Why

eBPF is powerful but the authoring story is C (or Rust), plus a verifier that
rejects anything it can't prove safe. Ruby is expressive but interpreted. spinel
closes the gap on the language side — it is a whole-program type-inferring Ruby
AOT compiler that emits C. spinel-ebpf adds the missing half: a **partition +
codegen layer** that decides, per method, what can run as eBPF, emits verifier-
legal `.bpf.c` for it, and wires the native and kernel halves together.

You write Ruby. You get native binaries and kernel programs.

## How it works

```
your.rb
  │  spinel: parse (libprism) ─► whole-program type inference
  ▼
partition          decide per method: native C or eBPF-eligible
  │                 (eBPF needs: bounded loops, no heap/GC, helper-only calls, …)
  ├─► native C ─────────────────────────────────► cc ─► binary
  └─► eBPF codegen ─► .bpf.c ─► clang -target bpf ─► libbpf load ─► kernel
                                                          ▲
              transparent dispatch: a native call to an eBPF-tagged method
              crosses into the kernel program and back
```

The eBPF codegen runs **in-process**: it links against spinel's compiler objects
and reads spinel's typed AST directly, so it sees the same types the native
backend does. Partition failure is a hard error — there is no silent fallback to
slow paths.

## What you can write in Ruby today

A non-exhaustive tour of the surface the codegen supports:

- **Program types**: XDP, TC (ingress/egress), kprobe/kretprobe, uprobe/uretprobe,
  USDT, tracepoint, raw tracepoint, fentry/fexit, LSM/fmod_ret, perf_event,
  SOCK_OPS, sk_reuseport, sk_msg/sk_skb, cgroup hooks, BPF iterators, and
  `struct_ops` (sched_ext schedulers, BPF qdiscs, TCP congestion control).
- **Packet access**: typed header accessors (`pkt.ip4.src`, `pkt.tcp.flags`,
  IPv6, dynptr byte access), skb read/write + checksum fixup (NAT), FIB lookup,
  socket lookup, redirect.
- **Maps & data**: per-unit hash/array maps from instance variables, LPM-trie
  CIDR maps, ring buffers (`spnl_emit*`), user ring buffers, stack traces,
  log2 / linear / keyed histograms, QUEUE/STACK, map-in-map, task storage, and
  `bpf_arena` shared memory with hash/list data structures.
- **Control flow**: `if/elsif/else`, bounded `n.times` (open-coded or `bpf_loop`),
  local variables, BPF-to-BPF calls, closures with captures, boolean
  short-circuiting, bitwise ops.
- **A DSL**: class-based attach (`class C < BPF::XDP`), `module + include`, a
  reactor (`on :xdp`, `on :kprobe, "fn"`, `on :timer, every: 5.seconds`,
  `on :perf_event, hz: 99`), and module-style constants (`XDP::PASS`,
  `IP::Proto::TCP`).

Two things built on this surface:

- **Observability tools** under `examples/observability/` — a Ruby reimagining of
  many bcc tools (opensnoop, runqlat, biolatency, tcplife, profile, offcputime,
  memleak, …), plus live flame graphs served over HTTP.
- **A kernel-assisted HTTP server** under `examples/http_server/` — from a plain
  single-process HTTP/1.0 server, to SO_REUSEPORT multi-worker, to a pure-XDP TCP
  "slice" that completes the handshake, request and response without the kernel
  TCP stack ever creating a socket.

## Self-instrumentation

Because spinel is the compiler, it knows every method, its mangled symbol, and
its argument ABI at compile time — so it can instrument *itself* with no DWARF and
no source changes:

```sh
spinel-ebpf compile app.rb --instrument        # auto uprobe/uretprobe every method
                                               # -> per-method RED metrics on :9100/metrics
spinel-ebpf compile app.rb --instrument-self   # workload + agent in one self-attaching binary
```

Latency is aggregated in a kernel keyed-histogram (overflow-immune) and exposed
as Prometheus metrics.

## Getting started

Work inside a Linux build environment with `clang`/LLVM 19+, `libbpf`, `bpftool`,
`pahole`, plus `cc` / `make` / `ruby` / `git` / `curl` — all present in a
`debian:trixie` container.

### 1. An eBPF-capable kernel (needed to *run* the programs)

The generated programs require a kernel with BTF, the BPF JIT, `struct_ops`, and
the tracing stack. On Apple Silicon macOS, build one and install it into Apple
`container` with the companion
[apple-container-ebpf-kernel](https://github.com/yuskesh/apple-container-ebpf-kernel)
repo. (You can *compile* without it — you just can't load and run the result.)

### 2. Build the spinel compiler dependency

spinel-ebpf builds against a small [fork of spinel](https://github.com/yuskesh/spinel)
that carries a single **env-gated patch** — `SPINEL_EXTERN_METHODS` makes selected
top-level methods emit as `extern` declarations (spinel's canonical value ABI) so
their bodies can come from a separately-linked unit. spinel-ebpf uses it for
transparent native→eBPF dispatch (`--ebpf-dispatch`); with the variable unset the
patch is byte-identical to upstream (see the fork's
[FORK.md](https://github.com/yuskesh/spinel/blob/c-emit-ir/FORK.md)).

A setup script fetches the fork (at a pinned tag) and builds it into `deps/spinel`:

```sh
scripts/setup.sh
```

It produces `bin/spinel` + `build/csrc/*.o` + `build/libprism.a` (the in-process
codegen links against these). Afterwards `bin/spinel-ebpf` works with no further
configuration — its default `SPINEL_DIR` is `deps/spinel`. Override with
`SPINEL_REPO` / `SPINEL_REF` / `SPINEL_DIR` / `SPINEL_C_BIN`.

### 3. Compile

```sh
bin/spinel-ebpf compile your_program.rb --build   # or any file under examples/
```

This emits the native C and `.bpf.c`, compiles the BPF object, and links a single
binary that loads and attaches the program(s) on startup.

## Usage

```sh
spinel-ebpf compile foo.rb                      # emit C + .bpf.c (eBPF-mixed, default)
spinel-ebpf compile foo.rb --native-only        # emit only native C (no eBPF)
spinel-ebpf compile foo.rb --build              # build all the way to one binary
spinel-ebpf compile foo.rb --build --ebpf-dispatch   # native calls route into eBPF
spinel-ebpf compile foo.rb -o build/            # output directory (default build/)
```

See `spinel-ebpf --help` for the full flag set (`--instrument*`,
`--int-overflow`, etc.).

## Repository layout

```
bin/spinel-ebpf          the command-line driver
src/spinel_ebpf/         Ruby: IR/AST parsing, partition, eBPF codegen,
                         transparent dispatch, plugins, self-instrument
src/codegen_c/           the production in-process eBPF codegen (C)
src/runtime/             host-side C runtime (libbpf wrappers) + socket/PTY shims
include/spnl/            shared host<->kernel event header
examples/                observability tools, the HTTP server, profiling demos
tools/                   golden-output gate, helpers
tests/                   host unit tests + fixtures
docs/                    architecture and design notes
```

## Testing

Testing has two tiers. Tier 1 is kernel-independent and runs in CI; tier 2
needs a real eBPF-capable kernel and runs on a host (or container) booted on
one.

```sh
# --- tier 1: kernel-independent (also the GitHub CI) ---

# host unit tests (pure Ruby: parsing, partition, codegen)
for t in tests/spinel_ebpf/*_test.rb; do ruby -Isrc -Itests "$t" || break; done

# codegen regression gate: emitted .bpf.c must match the committed golden files
ruby tools/golden.rb            # use --update to regenerate after intended changes

# --- tier 2: needs an eBPF-capable kernel ---

# compile representative programs (XDP, kprobe, TC, struct_ops), then load +
# verify each in the running kernel. Run as root on a host booted on the
# custom kernel, after scripts/setup.sh has built the compiler.
sudo scripts/kernel-test.sh
```

CI stops at tier 1 because hosted runners can't boot the custom kernel.
Compile/load is exercised end-to-end by `scripts/kernel-test.sh` and by
building the examples with `bin/spinel-ebpf … --build`.

## License

Most of this project — the toolchain, the host runtime, the generated host glue,
the shared header, examples and tests — is dual-licensed **MIT OR Apache-2.0**
(see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE); use
whichever you prefer — Apache-2.0 adds an explicit patent grant, MIT is
GPLv2-compatible). spinel itself is MIT (© Yukihiro Matsumoto); the Linux kernel
and libbpf are under their own licenses and are not redistributed here.

The **generated eBPF programs** (`tests/golden/*.bpf.c`, and every `.bpf.c` the
codegen emits) are dual-licensed **GPL-2.0 OR MIT** and declare
`SEC("license") = "Dual MIT/GPL"` — this is the cilium model. An eBPF program that
calls GPL-only kernel helpers must present a GPL-compatible license to the kernel,
so the GPL arm satisfies the verifier while the MIT arm lets you reuse the program
permissively. See [LICENSE-GPL-2.0](LICENSE-GPL-2.0). Per-file SPDX identifiers
are authoritative.
