# Architecture

spinel-ebpf sits on top of [spinel](https://github.com/matz/spinel), a
whole-program type-inferring Ruby AOT compiler that emits C. spinel-ebpf adds a
partition step and an eBPF code generator so that selected Ruby methods compile
to kernel programs instead of native functions.

## The partition principle

The eBPF verifier imposes hard limits: bounded loops, a 512-byte stack, no
dynamic memory or GC, no recursion, and only a fixed set of helper/kfunc calls.
Not all Ruby can run there. The central design decision is **where to draw the
boundary** between native C and eBPF.

Each method is classified:

- **eBPF-eligible** — integer/bitwise arithmetic, comparisons, `if/else`, bounded
  loops, fixed-size map lookups, packet/struct field access, helper calls. These
  become `.bpf.c`.
- **native** — anything needing the heap, strings, dynamic dispatch, unbounded
  loops, or arbitrary syscalls. These stay native C.

Classification is driven by spinel's whole-program type inference (so indirect
uses of disallowed types are caught too). If a method is tagged eBPF but uses
something the verifier won't accept, that is a **hard compile error** — there is
deliberately no silent fallback that would hide a performance cliff.

## Pipeline

```
Ruby source
  │
  ├─ spinel: parse (libprism) ─► whole-program type inference ─► typed AST
  │
  ├─ partition: per-method native vs eBPF, using the inferred signatures
  │
  ├─ native methods  ─► spinel C codegen ─► cc ─────────────► binary
  │
  └─ eBPF methods    ─► eBPF codegen ─► .bpf.c
                                          │ clang -target bpf (CO-RE)
                                          ▼
                                        .bpf.o ─► libbpf load/attach ─► kernel
```

A small glue layer and a host runtime (libbpf wrappers) tie the two halves into a
single binary that loads and attaches its kernel programs on startup.

## In-process eBPF codegen

The production code generator (`src/codegen_c/`) is a C program that **links
against spinel's own compiler objects** and reads spinel's `Compiler` structure
directly. That means the eBPF backend sees exactly the types the native backend
sees, with no lossy intermediate format. The driver builds this in-process
codegen on demand from spinel's object files.

A line-oriented text IR is still produced where the Ruby-side partition and
dispatch logic need to read method signatures, but it is no longer the join point
for codegen.

## Host <-> kernel communication

Programs exchange data with userspace through a small set of conventions:

- **Ring buffers** for kernel→host events. Every event carries a common 16-byte
  header (timestamp, kind, length) so the host can demultiplex generically;
  helpers like `spnl_emit`, `spnl_emit_pair`, `spnl_emit3/4`, and `spnl_emit_str`
  build on it.
- **User ring buffers** for host→kernel commands (FIFO, batch-friendly).
- **Hash / array maps** projected from instance variables, plus specialized maps
  (LPM-trie for CIDR matching, stack-trace, histogram, queue/stack, task storage,
  map-in-map).
- **`bpf_arena`** for memory shared (and mmap-able) between kernel and userspace,
  with flat-array, hash-table, and linked-list data structures built on top.

## Transparent dispatch

With dispatch enabled, a native call to an eBPF-tagged method is rewritten to
invoke the corresponding kernel program (via a test-run entry point) and return
its result, so the caller is unaware the work happened in the kernel. This is how,
for example, an HTTP server can call a Ruby method that transparently increments a
per-path counter living in a BPF map.

Integer overflow semantics are reconciled across the boundary: native code raises
by default while eBPF wraps in `__s64`, so dispatch defaults the native side to
wrapping for consistency (configurable with `--int-overflow`).

## The spinel boundary

spinel-ebpf carries a single, minimal patch to spinel: an env-gated hook that
lets top-level methods be emitted as `extern` declarations (so the native and
eBPF halves can be compiled separately and linked). The hook is generic — not
eBPF-specific — and is byte-identical to upstream when the gate is off, which
keeps the fork easy to rebase and the patch a candidate for upstreaming. The
host-side socket/PTY/runtime shims live in this repository, not in the compiler.

## Testing strategy

- **Host unit tests** cover IR/AST parsing and the partition decision in pure
  Ruby, with no kernel required.
- **A golden-output gate** asserts that the emitted `.bpf.c` matches committed
  reference files; intended changes regenerate the golden set for review.
- **End-to-end** builds compile, load, and attach real programs and verify
  behavior either with deterministic `BPF_PROG_TEST_RUN` inputs or live traffic.
