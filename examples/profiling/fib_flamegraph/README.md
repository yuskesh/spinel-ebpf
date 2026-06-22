# fib flame graph — visualizing "where spinel(AOT) beats CRuby"

Run the same `fib.rb` under the **CRuby interpreter** and as a **spinel AOT
native** binary, take on-CPU flame graphs with `perf` + FlameGraph, and compare.
The goal is not the raw speed difference but the visualization of **exactly which
work spinel's speedup eliminates**.

## Results (fib(38), Apple container / debian:trixie / Ruby 3.3.8)

| | wall time fib(35) | where the on-CPU time goes |
|---|---|---|
| CRuby | 0.93s | `vm_exec_core` **89.6%** (bytecode dispatch) + `vm_call_iseq_setup_*` 7.5% (method calls) + `vm_opt_plus` 2.1% (boxed `+`) |
| spinel | 0.037s (**~25x**) | `sp_fib` **100%** (native recursion, no interpreter) |

What spinel removes is **the interpreter machinery itself** (instruction
dispatch, method-call setup, integer boxing). The "actual computation" of `fib`
is buried inside `vm_exec_core` under CRuby; under spinel it becomes the native
instructions of `sp_fib` directly.

## Reproduction (inside the container)

```bash
container exec spnlbuild bash -c '
  set -e; export LANG=C.UTF-8; cd /work
  FG=/opt/FlameGraph   # flamegraph.pl / stackcollapse-perf.pl

  # --- spinel: build the AOT native binary with frame pointers ---
  # (perf/eBPF user-stack unwinding needs -fno-omit-frame-pointer) ---
  ruby bin/spinel-ebpf compile examples/profiling/fib_flamegraph/fib.rb \
    -o /tmp/fibb --native-only            # generates fib.c
  clang -O2 -g -fno-omit-frame-pointer -I deps/spinel/lib -I include \
    /tmp/fibb/fib.c deps/spinel/lib/libspinel_rt.a -lm -o /tmp/fib_spinel

  # --- fetch debug symbols so CRuby interpreter function names resolve ---
  export DEBUGINFOD_URLS="https://debuginfod.debian.net/"
  BID=$(readelf -n /lib/aarch64-linux-gnu/libruby-3.3.so.3.3 \
        | grep -oE "Build ID: [0-9a-f]+" | awk "{print \$3}")
  debuginfod-find debuginfo "$BID" >/dev/null
  mkdir -p /usr/lib/debug/.build-id/${BID:0:2}
  ln -sf /root/.cache/debuginfod_client/$BID/debuginfo \
         /usr/lib/debug/.build-id/${BID:0:2}/${BID:2}.debug

  # --- sampling (same fib(38), matched to ~4s wall via loops) ---
  perf record -e cpu-clock -F 299 --call-graph fp -o /tmp/cr.data -- \
    env FIB_N=38            ruby examples/profiling/fib_flamegraph/fib.rb
  perf record -e cpu-clock -F 299 --call-graph fp -o /tmp/sp.data -- \
    env FIB_N=38 FIB_LOOPS=30 /tmp/fib_spinel

  # --- folded -> SVG ---
  perf script -i /tmp/cr.data | $FG/stackcollapse-perf.pl > cruby.folded
  perf script -i /tmp/sp.data | $FG/stackcollapse-perf.pl > spinel.folded
  $FG/flamegraph.pl --colors java  cruby.folded  > cruby_flame.svg
  $FG/flamegraph.pl --colors green spinel.folded > spinel_flame.svg
'
```

## Notes

- `perf` works on the custom kernel via the software event `cpu-clock` (no PMU needed).
- A normally built spinel binary (`-O2`, frame pointers omitted) can't have its
  user stack unwound, so build a separate `-fno-omit-frame-pointer` binary for profiling.
- CRuby's `vm_exec_core` and friends are `static` (symtab stripped), so their
  names only appear once debug info is fetched via debuginfod. Without it you get
  `libruby+0x...` hex addresses, but the shape ("time scattered across the
  interpreter") looks the same.
- The above uses standard `perf`. A version that produces the same picture using
  **spinel-ebpf's own eBPF profiler** is `user_profile.rb` (below).

## Self-profiler version (no perf required)

`user_profile.rb` samples with `on :perf_event, hz: 99` + `user_stack_id`, and
the host emits folded output via `spnl_dump_folded_user`. `spnl_sym_user` was
given a build-id separate-debug-file fallback so CRuby's stripped statics like
`vm_exec_core` resolve too.

```bash
container exec spnlbuild bash -c '
  set -e; export LANG=C.UTF-8; cd /work; FG=/opt/FlameGraph
  ruby bin/spinel-ebpf compile examples/profiling/fib_flamegraph/user_profile.rb -o /tmp/uprof --build

  # fetch debug symbols into the build-id tree so CRuby interpreter static names resolve
  export DEBUGINFOD_URLS="https://debuginfod.debian.net/"
  BID=$(readelf -n /lib/aarch64-linux-gnu/libruby-3.3.so.3.3 | grep -oE "Build ID: [0-9a-f]+" | awk "{print \$2}")
  debuginfod-find debuginfo "$BID" >/dev/null
  mkdir -p /usr/lib/debug/.build-id/${BID:0:2}
  ln -sf /root/.cache/debuginfod_client/$BID/debuginfo /usr/lib/debug/.build-id/${BID:0:2}/${BID:2}.debug

  # SPNL_SYM_PID = the namespace-local pid of the target (BPF records init-ns pids, so this is required inside a container)
  FIB_N=35 FIB_LOOPS=20 ruby examples/profiling/fib_flamegraph/fib.rb >/dev/null 2>&1 & WL=$!
  sleep 0.5
  SPNL_SYM_PID=$WL PROFILE_SECS=6 /tmp/uprof/user_profile 2>cruby.folded >/dev/null
  kill $WL; wait $WL 2>/dev/null
  $FG/flamegraph.pl --colors java cruby.folded > cruby_selfprofiler.svg
'
```

Note: the target process must be alive at dump time (its maps are read then).
For short-lived processes, perf is the stronger choice.
