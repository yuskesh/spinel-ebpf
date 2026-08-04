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

The same source can also leave Linux entirely: with `--target amp-m7` or
`--target amp-m33` the bytecode is compiled ahead of time to a Thumb blob that
runs on a Cortex-M core beside the Linux one, with no VM and no JIT on the device.
And what a probe observes can be exported as OpenTelemetry — traces, metrics or
logs — straight from the compiled binary, with no collector in between.

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
  IPv6), skb read/write + checksum fixup (NAT), FIB lookup, socket lookup,
  redirect.
- **Maps & data**: per-unit hash/array maps from instance variables, LPM-trie
  CIDR maps, ring buffers (`spnl_emit*`), stack traces, log2 / linear / keyed
  histograms, QUEUE/STACK, map-in-map, task storage, and `bpf_arena` shared
  memory with hash/list data structures. `spinel-ebpf capabilities` prints the
  whole map vocabulary, including each map's capacity and what happens when it
  fills up.
- **Control flow**: `if/elsif/else`, bounded `n.times` (open-coded or `bpf_loop`),
  local variables, BPF-to-BPF calls, closures with captures, boolean
  short-circuiting, bitwise ops.
- **Reading kernel state**: `kfield` / `kptr` for scalars, `kfield_str` and
  `kfield_str_eq` for string fields, named `sock_*` accessors that return every
  value in host order, full-path predicates (`path_eq`, `path_starts_with`,
  `path_contains`), and predicates over the current task's capabilities,
  namespaces and a file's type.
- **A DSL**: class-based attach (`class C < BPF::XDP`), `module + include`, a
  reactor (`on :xdp`, `on :kprobe, "fn"`, `on :perf_event, hz: 99`), one
  definition attached to several symbols (`on :kprobe, %w[vfs_read vfs_write]`),
  and module-style constants (`XDP::PASS`, `IP::Proto::TCP`).
- **Declarative narrowing**: `param :target_pid, default: 0` becomes a read-only
  constant patched in before load, so an unused filter is folded away entirely;
  `filter_by` injects one filter into every handler in the unit, and `keep_if`
  drops records in userspace after the drain and before the send.
- **Typed consumers**: `on_emit :<channel> do |ev| … end` receives a record
  handle whose properties are generated from one declaration, so a misspelled
  field is a compile error rather than a silent zero. `to_span(ev)` turns a
  record into an OpenTelemetry span; which channel it means is resolved from the
  enclosing block, and an ambiguous use fails at compile time with the reason.

Three things built on this surface:

- **Observability tools** under `examples/observability/` — a Ruby reimagining of
  many bcc tools (opensnoop, runqlat, biolatency, tcplife, profile, offcputime,
  memleak, …), plus live flame graphs served over HTTP.
- **A kernel-assisted HTTP server** under `examples/http_server/` — from a plain
  single-process HTTP/1.0 server, to SO_REUSEPORT multi-worker, to a pure-XDP TCP
  "slice" that completes the handshake, request and response without the kernel
  TCP stack ever creating a socket.
- **OpenTelemetry export** under `examples/observability/otlp/` — see below.

## Telemetry, without a collector

A probe's events can leave the machine as OpenTelemetry directly from the compiled
binary. All three signals are supported over both transports — OTLP/HTTP+protobuf
and OTLP/gRPC (a minimal HTTP/2 client, no gRPC library) — with the encoders
committed in-tree, so building a probe that exports needs no protobuf toolchain.

```sh
spinel-ebpf compile app.rb --instrument --instrument-self \
    --instrument-otlp http://127.0.0.1:4318          # per-method RED as metrics
spinel-ebpf compile app.rb --instrument --instrument-self \
    --instrument-otlp-traces grpc://127.0.0.1:4317   # ... as a span tree instead
```

The endpoint's scheme picks the transport (`http://`, `grpc://`, and with TLS built
in, `https://` and `grpcs://`). Deployment details stay in the environment rather
than the binary, following the OpenTelemetry variables: `OTEL_EXPORTER_OTLP_HEADERS`
for token auth, `_COMPRESSION=gzip`, `_PROTOCOL=http/json` for a readable wire
format, per-signal `_TRACES_ENDPOINT` / `_METRICS_ENDPOINT` / `_LOGS_ENDPOINT`
honoured **verbatim including the path** (some vendors do not use `/v1/<signal>`),
and client certificates for mutual TLS. Which means a probe can talk to a
commercial backend with no collector in the path.

Above the raw export, the runtime adds context the probe does not have to know
about: Kubernetes pod, namespace and workload resolved from a cgroup id; the
container's real name from the CRI; a connection's peer classified as another pod,
a Service, or an external address; and related events assembled into a span tree
under one request rather than a flat list. Those are runtime enrichers, so a probe
gains them without changing a line — and on a machine that is not running
Kubernetes they are simply absent.

## Beyond Linux: the same Ruby on a real-time core

Many SoCs pair the Linux cores with a Cortex-M core. `--target amp-m7` and
`--target amp-m33` compile a probe for that core instead:

```sh
spinel-ebpf compile probe.rb --target amp-m33 --build   # -> a Thumb blob + a manifest
```

The eBPF bytecode becomes the portable, checkable intermediate form, and the
compilation to native Thumb happens **on the build host**, using the micro-bpf
JIT as an ahead-of-time compiler. A JIT is a pure function from bytes to bytes, so
running it early costs nothing and leaves the real-time core carrying no VM and no
JIT — only a loader, a helper table and a ring producer. The application core
stages a blob into shared memory and reads the events back out.

Two properties follow from fixing the memory ABI:

- **A probe can be swapped while the core runs.** The firmware is built once and
  the blob is replaced underneath it, over a command ring, with the instance
  variables zeroed per install so a new probe never reads the old one's state.
- **Verification is decoupled from execution.** That core has no verifier, so
  `amp_check` inspects the bytecode before it ships: a helper allowlist, no
  backward branches, every load and store inside the ABI's regions, a bound on
  stack-relative access — and it **denies anything it cannot interpret**, rather
  than passing along what it has no rule for. It also computes a static cost, so a
  program too expensive for an attach point is refused rather than discovered late.

Two board profiles ship (`include/spnl/amp_abi_*.h`), and a board is nothing but a
set of address values: one selector header names which to read, and nothing in the
generator, the runtime or the drain knows that boards exist. Measured on the same
Ruby source, the two blobs are the same length in instructions and differ in
exactly two operands — the two addresses that get baked in.

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

Three optional dependencies are off by default, because nothing in normal use
needs them:

```sh
SPNL_WITH_TLS=1   scripts/setup.sh   # mbedTLS: an https:// or grpcs:// OTLP endpoint
SPNL_WITH_PROTO=1 scripts/setup.sh   # OTLP schemas + nanopb: decode telemetry in tests,
                                     #   or regenerate the committed encoders
SPNL_WITH_AMP=1   scripts/setup.sh   # the micro-bpf VM: --target amp-m7 / amp-m33
```

The last one is worth a note, because the name is misleading. It fetches the
**micro-bpf fork** of rbpf, not upstream rbpf: upstream has an x86-64 JIT and a
Cranelift backend and no ARM or Thumb backend at all, while the fork keeps
upstream's package name and repository URL in its metadata — so a dependency
listing cannot tell them apart. The setup script checks for the Thumb emitter and
says so plainly if what it found is the wrong one.

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

spinel-ebpf compile foo.rb --target amp-m33 --build  # a Thumb blob for a Cortex-M core
                                                     #   (amp-m7 for the other profile)
```

Three subcommands answer questions about a program without running it:

```sh
spinel-ebpf check foo.rb            # partition -> codegen -> clang -> load+verifier,
                                    #   reporting {stage, ok, error} and stopping at
                                    #   the first failure. --json for tooling.
spinel-ebpf describe foo.rb         # which emit sites bind to which on_emit consumers,
                                    #   and the record channels a probe writes together
                                    #   with the telemetry attributes they become
spinel-ebpf capabilities foo.rb     # the builtin domains a file uses (or the whole
                                    #   registry with no file). --json emits the
                                    #   machine-readable contract: builtin signatures,
                                    #   attach kinds, the Ruby subset, record channels
```

`describe` and `capabilities --json` exist for a specific reason: the useful part of
a compiler that hides a class of bug is being able to state what it accepts. A
generator — a person or a model — can read the contract instead of guessing, and
`describe` shows the wire consequence of a probe without reading the emitted C.

See `spinel-ebpf --help` for the full flag set (`--instrument*`, `--int-overflow`,
`--amp-*`, etc.).

## When a probe produces nothing: `SPNL_CHANNEL_REPORT`

A probe that compiles, verifies, attaches and then produces an empty result is the
most common way to be wrong here, and the least self-announcing: nothing errors and
nothing warns. Set `SPNL_CHANNEL_REPORT=1` and every probe prints, on exit, how many
records came out of each ring buffer and what became of them.

```
[spinel-ebpf] channel balance
  audit_dns_dns_events    in 412   out 412
```

The counters live in the drain layer, not in the exporter, so a probe that only
prints lines to a console gets the same diagnosis as one that ships spans. Three
failures are reported in deliberately different wording, because the advice for each
is different:

```
  probe_events            ** never drained **
                            the probe writes to this ringbuf but no userspace code
                            reads it, so every record was discarded by the kernel.
```
The kernel side is fine; the userspace half is missing. `spinel-ebpf describe` names
the export call for that channel — call it, or consume the channel with `on_emit`.

```
  probe_events            in 0   ** nothing came out **
```
The channel was drained cleanly and no record ever arrived. The attach point never
fired, or the probe's own filter rejects everything. (`lsm/*` programs need
`lsm=...,bpf` on the kernel command line; `fmod_ret/*` do not.)

```
  audit_dns_dns_events    in 3   dropped 3
                            unparseable_qname: 3   ** suspicious **
                            the record's raw bytes are not a DNS query. ...
```
Records arrived but the runtime discarded them, because they do not satisfy the
channel's contract. Each drop reason carries what to check. `** suspicious **`
appears only when the drops dominate the traffic — discarding some records is
normal, discarding nearly all of them usually means the attach point is wrong.

Records that the probe's *own* consumer skipped are counted separately as
`filtered` and are never flagged. Emitting broadly and narrowing in userspace is a
design this project recommends, and a warning there would contradict it.

Two other values:

```sh
SPNL_CHANNEL_REPORT=0    # silent
SPNL_CHANNEL_REPORT=kv   # one machine-readable line per channel:
                         #   spnl.channel <name> drained=1 in=412 out=412 dropped=0 filtered=0
```

`kv` exists so that tools parse a stable projection rather than the prose; the prose
is meant to keep improving, and anything parsing it would make every improvement a
breaking change.

The report is armed by the first drain and prints on every exit path, including
`timeout N` and Ctrl-C — the ways these probes normally end, and the ones a plain
`atexit` handler misses. It is a diagnosis, never a gate: it does not change the
exit status.

**What it cannot catch.** It counts records; it does not know what they mean. A
probe that measures generic UDP while believing it measures DNS is deterministic,
balanced, and completely wrong — its report reads `in 30 out 30`. Judging that a
probe measures the thing it was meant to measure still needs intent, which is why
`spinel-ebpf describe` prints the author's stated intent next to the attributes the
probe actually emits, and leaves the comparison to a reader.

## Repository layout

```
bin/spinel-ebpf          the command-line driver
src/spinel_ebpf/         Ruby: IR/AST parsing, partition, eBPF codegen, transparent
                         dispatch, plugins, typed consumers, self-instrument
src/codegen_c/           the production in-process eBPF codegen (C), and the two
                         declarations it derives contracts from: the ringbuf record
                         layout and the probe context / attach-point schema
src/runtime/             host-side C runtime (libbpf wrappers) + socket/PTY shims
src/runtime/otlp/        the OpenTelemetry exporter: encoders, HTTP and gRPC
                         transports, TLS, and the enrichers (Kubernetes, CRI, peer)
src/runtime/amp/         the real-time-core side: the fixed-ABI runtime, the
                         pre-deployment bytecode checker, the capability table
include/spnl/            shared event header, ring layout, and one file per board ABI
examples/                observability tools, the HTTP server, OTLP demos, and the
                         Cortex-M firmware for both board profiles
tools/                   golden-output gate, the contract generators and their
                         evolution gates, a Ruby port of many bcc tools
tests/                   host unit tests + fixtures, and runtime harnesses that
                         drive the exporter and the real-time-core pieces
deps/                    fetched by scripts/setup.sh; not committed
docs/                    architecture notes
```

## Testing

Three tiers. Tier 1 is kernel-independent and runs in CI. Tier 2 needs no kernel
either but does need a compiler and a shell, so it runs locally. Tier 3 needs a
real eBPF-capable kernel and runs on a host booted on one.

```sh
# --- tier 1: kernel-independent (this is what CI runs) ---

# host unit tests (pure Ruby: parsing, partition, codegen, consumers, contracts)
for t in tests/spinel_ebpf/*_test.rb; do ruby -Isrc -Itests "$t" || break; done

# the emitted .bpf.c must match the committed golden files
ruby tools/golden.rb            # --update to regenerate after an intended change

# the two contract gates. Both refuse a change that is not append-only, because a
# record offset and a context field id are baked into artifacts already shipped.
ruby tools/record_gate.rb       # ringbuf record layout + the attributes it exposes
ruby tools/probe_ctx_gate.rb    # probe context fields + attach points

# this tree's own hygiene: English prose, and no reference to a path or document
# that does not exist here
ruby scripts/check-public-paths.rb
sh   scripts/check-public-prose.sh

# --- tier 2: needs a compiler, not a kernel ---

# end-to-end harnesses under tests/runtime -- each builds what it needs and
# asserts on the result. A few examples; there are around thirty.
sh tests/runtime/run_otlp_roundtrip.sh      # encode telemetry, decode it back
sh tests/runtime/run_amp_ring.sh            # the shared ring ABI, including wraparound
sh tests/runtime/run_amp_check.sh           # the pre-deployment bytecode checker
sh tests/runtime/run_probe_capability.sh    # publish -> read -> admit a capability table

# --- tier 3: needs an eBPF-capable kernel ---

# compile representative programs (XDP, kprobe, TC, struct_ops), then load and
# verify each in the running kernel. Run as root after scripts/setup.sh.
sudo scripts/kernel-test.sh
```

CI stops at tier 1 because hosted runners cannot boot the custom kernel. It does
build the compiler dependency and emit `.bpf.c` for a sample, so the in-process
codegen is exercised against the real spinel objects on every push.

Some tier-2 harnesses skip themselves when an optional dependency is absent — the
ones that decode a payload need `SPNL_WITH_PROTO=1`, the TLS ones need
`SPNL_WITH_TLS=1`. A skip is reported, not silently passed.

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
