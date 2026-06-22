# spinel-ebpf turnkey tools

A set of **ready-to-run** observability tools, equivalent to bcc's `tools/`.
Each tool is a single Ruby file (spinel-ebpf subset) that uses the DSL idioms
established so far (kprobe / raw_tracepoint / latency hist / ivar counter /
hist dump FFI).

## Build & run

```bash
bin/spinel-ebpf compile tools/<tool>.rb --build -o build/<tool>
sudo ./build/<tool>/<tool>
```

Run `<tool>` inside the debian:trixie build container on a BTF-enabled kernel
(see the "Build / environment" section of the project documentation).

## Included tools

| Tool | bcc equivalent | Mechanism | Output |
|---|---|---|---|
| `funclatency.rb` | funclatency | kprobe `latency_start` + kretprobe `hist_observe(latency_end)` | **prints a log2 histogram after 5s of sampling** (`spnl_dump_log2_hist` FFI) |
| `syscount.rb` | syscount | raw_tracepoint `sys_enter` + counter | `bpftool map dump name syscount_top_c` |
| `funccount.rb` | funccount | kprobe + counter (edit the function name for any function) | `bpftool map dump name funccount_top_c` |
| `vfsstat.rb` | vfsstat | kprobe `vfs_read`/`vfs_write`/`vfs_open` + 3 counters | `bpftool map dump name vfsstat_top_{re,wr,op}` |
| `opensnoop.rb` | opensnoop | tracepoint `sys_enter_openat` + `spnl_emit_str` + streaming | **streams openat filenames in real time** (`spnl_stream` FFI) |
| `inject.rb` | inject | `fmod_ret/security_file_open` + comm scope | injects -EPERM into the victim process's open(), count via `@injected` |
| `sslsniff.rb` | sslsniff | uprobe `SSL_write` + `spnl_emit_str` + streaming | **streams TLS plaintext in real time**, `SPNL_UPROBE_BINARY=libssl.so.3` |
| `trace.rb` | trace | tracepoint + `if` predicate + `spnl_emit_str` + streaming | **predicate-filtered event trace**, in-kernel filter by comm etc. |
| `argdist.rb` | argdist | tracepoint arg + `path_counter_inc` (-C) / `hist_observe` (-H) | **frequency table / log2 distribution per expression value**, `bpftool map dump bpf_path_counts` |
| `memleak.rb` | memleak | kmem/kmalloc+kfree tracepoint + `leak_record`/`leak_forget` + `spnl_dump_leaks` | **un-freed kmalloc grouped per stack and symbolized**, kernel mode |
| `deadlock.rb` | deadlock | uprobe pthread_mutex_lock/unlock + `task_swap` + `lock_edge` + `spnl_dump_deadlocks` | **detects lock-order inversions (AB-BA)**, comm-scoped |
| `execsnoop.rb` | execsnoop | tracepoint sys_enter_execve + `emit_argv` + streaming | **streams execve with every argv element** |
| `runqlat.rb` | runqlat | sched_wakeup/sched_switch + `lat_start`/`lat_end` + `hist_observe` | **log2 histogram of run-queue latency** |
| `biolatency.rb` | biolatency | kprobe blk_mq_start/end_request + `lat_start`/`lat_end` (request ptr key) | **log2 histogram of block I/O latency** |
| `tcplife.rb` | tcplife | sock/inet_sock_set_state + `lat_start`/`lat_end` (sock key) + `spnl_emit3` + streaming | **streams TCP connection lifetimes** (MVP: ports+duration) |
| `tcpconnect.rb` | tcpconnect | sock/inet_sock_set_state (CLOSE->SYN_SENT) + ipv4 field + `spnl_emit_pair` | **streams outbound connects as daddr+dport** |
| `tcpaccept.rb` | tcpaccept | sock/inet_sock_set_state (SYN_RECV->ESTABLISHED) + ipv4 field | **streams inbound connects as lport+raddr** |
| `exitsnoop.rb` | exitsnoop | sched_process_exit + `spnl_emit` + `emit_comm` | **streams process exits (pid+comm)** |
| `killsnoop.rb` | killsnoop | sys_enter_kill + `spnl_emit_pair` | **streams kill(2) signals (target pid+signal)** |
| `cpudist.rb` | cpudist | sched_switch + `lat_start`/`lat_end` (pid key) + `hist_observe` | **log2 histogram of on-CPU time distribution** |
| `hardirqs.rb` | hardirqs | irq_handler_entry/exit + `cpu_id` key + `hist_observe` | **histogram of hard IRQ handler time** |
| `softirqs.rb` | softirqs | softirq_entry/exit + `cpu_id` key + `hist_observe` | **histogram of soft IRQ handler time** |
| `statsnoop.rb` | statsnoop | sys_enter_newfstatat/statx + `spnl_emit_str` | **streams stat(2) paths** |
| `syncsnoop.rb` | syncsnoop | sys_enter_sync/fsync/fdatasync + `spnl_emit` | **streams the pid that called sync(2)** |
| `tcpstates.rb` | tcpstates | sock/inet_sock_set_state (all transitions) + `spnl_emit4` | **streams TCP state transitions** |
| `capable.rb` | capable | kprobe cap_capable + `spnl_emit` + `emit_comm` | **streams capability checks (cap+comm)** |
| `gethostlatency.rb` | gethostlatency | uprobe/uretprobe getaddrinfo + `latency_start`/`latency_end` + `hist_observe` | **log2 histogram of name-resolution latency**, `SPNL_UPROBE_BINARY=libc.so.6` |
| `biosnoop.rb` | biosnoop | blk_mq_start/end_request + `lat_start`/`lat_end` + `kfield` + `spnl_emit3` | **per block I/O (sector,bytes,latency)** |
| `runqslower.rb` | runqslower | sched_wakeup/switch + keyed-latency + threshold | **streams run-queue waits > 1ms as (pid,latency)** |
| `fileslower.rb` | fileslower | kprobe/kretprobe vfs_read + tid-latency + threshold | **streams vfs_read > 1ms** |
| `tcpretrans.rb` | tcpretrans | kprobe tcp_retransmit_skb + `kfield` (dotted embedded path) | **streams TCP retransmits as (daddr,dport)** (load/attach+kfield verified; triggering real retransmits needs a real lossy link) |
| `mountsnoop.rb` | mountsnoop | sys_enter_mount/umount + `spnl_emit_str` | **streams mount/umount target paths** |
| `cachestat.rb` | cachestat | kprobe folio_mark_accessed/filemap_add_folio/mark_buffer_dirty + `path_counter_inc` | **page cache hit/miss statistics**, `bpftool map dump bpf_path_counts` |
| `filelife.rb` | filelife | security_inode_create->vfs_unlink + keyed-latency (dentry) | **streams the create->unlink lifetime of short-lived files** |
| `slabratetop.rb` | slabratetop | kmem/kmem_cache_alloc + `hist_observe(bytes_alloc)` | **slab allocation size distribution + rate** |
| `setuids.rb` | setuids | sys_enter_setuid/setresuid + `spnl_emit`/`spnl_emit3` | **streams the target uid of setuid/setresuid** |

### Measured results

- `funclatency`: prints `do_sys_openat2` latency as a log2 histogram (bcc ASCII art).
- `syscount`: counted **31,758 syscalls** in 1.3s.
- `vfsstat`: with `find /usr` etc., **opens=2215 / reads=76 / writes=195**.
- `opensnoop`: shows openat filenames live in arrival order (streaming foundation).
- `inject`: injects EPERM into open() only for comm=injtest, `@injected=4` confirmed on hardware.
- `sslsniff`: captures TLS plaintext `GET /sniffme` / `GET /curltest` (openssl s_client + curl) before encryption.
- `trace`: streams 33 lines of opens for comm=trycat only; `cat`'s opens are dropped by the predicate.
- `argdist`: tabulates the write size distribution as `{64:50, 4096:20}`, an exact match for the two dd runs.
- `memleak`: captures and symbolizes 30 un-freed kmalloc (9096 bytes / 18 stacks) from the mmap/munmap maple-tree RCU path.
- `deadlock`: detects the AB-BA demo's lock-order inversion exactly (2 edges / 1 inversion).
- `execsnoop`: captures the filename + every argv element of `echo ALPHA BETA GAMMA DELTA`, breaking at the terminator.
- `runqlat`: measures run-queue latency; under light load a peak at 2-4µs plus a ~2-4ms long tail.
- `biolatency`: measures block I/O latency with dd to vdb; peak 16-32µs plus a ~ms tail.
- `tcplife`: measures TCP connections held for 300/600/900ms as 310/610/910ms (matching).
- `tcpconnect`/`tcpaccept`: capture a connect to 127.0.0.1:8123 as daddr=16777343/dport=8123.
- `exitsnoop`/`killsnoop`: capture the exiting process name and kill signals (pid,15)/(pid,2).
- `cpudist`/`hardirqs`/`softirqs`: measure bimodal on-CPU time / hard IRQ 8-32µs / soft IRQ 8-16µs.
- `statsnoop`/`syncsnoop`: capture stat paths under /etc/* and the caller pid of sync/fsync.
- `tcpstates`: captures the full TCP state-machine lifecycle of one connection (client+server).
- `capable`: observes the `nice -n -5` CAP_SYS_NICE(23) check by cap number + comm.
- `gethostlatency`: distinguishes curl's getaddrinfo at localhost ~0.5ms vs failed DNS of tens to hundreds of ms.
- `biosnoop`: captures dd's 8 block I/Os per-I/O with sector/65536B/latency.
- `runqslower`/`fileslower`: capture run-queue waits of 1.2-14ms and vfs_read of 603/412ms above the threshold.


## Extending

By combining the attach kinds the DSL covers (kprobe/uprobe/USDT/tracepoint/
fentry/raw_tp/perf_event/LSM/fmod_ret/cgroup/iter) with the builtins (hist/
stack/latency/task_storage/emit/...), the other bcc tools (opensnoop /
execsnoop / biolatency / runqlat / tcplife ...) can be written the same way.
Just changing the two method names in `funclatency.rb` to another
kprobe/kretprobe pair turns it into a latency tool for any function.
