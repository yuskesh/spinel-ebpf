# spinel-ebpf turnkey tools

The equivalent of bcc's `tools/`: observability tools that **run as-is**. Each tool
is a single Ruby file (the spinel-ebpf subset) built out of the DSL idioms the
project has established (kprobe / raw_tracepoint / latency histogram / ivar
counter / histogram-dump FFI).

## Build & run

```bash
bin/spinel-ebpf compile tools/<tool>.rb --build -o build/<tool>
sudo ./build/<tool>/<tool>
```

Run `<tool>` in a `debian:trixie` build container on a BTF-enabled kernel (see the
top-level README for the environment).

## The tools

| Tool | bcc equivalent | How it works | Output |
|---|---|---|---|
| `funclatency.rb` | funclatency | kprobe `latency_start` + kretprobe `hist_observe(latency_end)` | **prints a log2 histogram itself after 5s of sampling** (`spnl_dump_log2_hist` FFI) |
| `syscount.rb` | syscount | raw_tracepoint `sys_enter` + counter | `bpftool map dump name syscount_top_c` |
| `funccount.rb` | funccount | kprobe + counter (edit the function name to target any function) | `bpftool map dump name funccount_top_c` |
| `vfsstat.rb` | vfsstat | kprobe `vfs_read`/`vfs_write`/`vfs_open` + 3 counters | `bpftool map dump name vfsstat_top_{re,wr,op}` |
| `opensnoop.rb` | opensnoop | tracepoint `sys_enter_openat` + `spnl_emit_str` + streaming | **streams openat filenames live** (`spnl_stream` FFI) |
| `inject.rb` | inject | `fmod_ret/security_file_open` + comm scope | injects -EPERM into the victim process's open(); `@injected` holds the count |
| `sslsniff.rb` | sslsniff | uprobe `SSL_write` + `spnl_emit_str` + streaming | **streams TLS plaintext live**, `SPNL_UPROBE_BINARY=libssl.so.3` |
| `trace.rb` | trace | tracepoint + `if` predicate + `spnl_emit_str` + streaming | **predicate-filtered event trace**, filtering in-kernel on comm and the like |
| `argdist.rb` | argdist | tracepoint arg + `path_counter_inc` (-C) / `hist_observe` (-H) | **frequency table per expression value / log2 distribution**, `bpftool map dump bpf_path_counts` |
| `memleak.rb` | memleak | kmem/kmalloc+kfree tracepoint + `leak_record`/`leak_forget` + `spnl_dump_leaks` | **un-freed kmallocs aggregated per stack and symbolized**, kernel mode |
| `deadlock.rb` | deadlock | uprobe pthread_mutex_lock/unlock + `task_swap` + `lock_edge` + `spnl_dump_deadlocks` | **detects lock-order inversion (AB-BA)**, scoped by comm |
| `execsnoop.rb` | execsnoop | tracepoint sys_enter_execve + `emit_argv` + streaming | **streams execve with every argv element** |
| `runqlat.rb` | runqlat | sched_wakeup/sched_switch + `lat_start`/`lat_end` + `hist_observe` | **log2 histogram of run-queue latency** |
| `biolatency.rb` | biolatency | kprobe blk_mq_start/end_request + `lat_start`/`lat_end` (request ptr key) | **log2 histogram of block I/O latency** |
| `tcplife.rb` | tcplife | sock/inet_sock_set_state + `lat_start`/`lat_end` (sock key) + `spnl_emit3` + streaming | **streams TCP connection lifetimes** (ports + duration) |
| `tcpconnect.rb` | tcpconnect | sock/inet_sock_set_state (CLOSE→SYN_SENT) + ipv4 field + `spnl_emit_pair` | **streams outbound connections as daddr+dport** |
| `tcpaccept.rb` | tcpaccept | sock/inet_sock_set_state (SYN_RECV→ESTABLISHED) + ipv4 field | **streams inbound connections as lport+raddr** |
| `exitsnoop.rb` | exitsnoop | sched_process_exit + `spnl_emit` + `emit_comm` | **streams process exits (pid+comm)** |
| `killsnoop.rb` | killsnoop | sys_enter_kill + `spnl_emit_pair` | **streams kill(2) signals (target pid+signal)** |
| `cpudist.rb` | cpudist | sched_switch + `lat_start`/`lat_end` (pid key) + `hist_observe` | **log2 histogram of on-CPU time** |
| `hardirqs.rb` | hardirqs | irq_handler_entry/exit + `cpu_id` key + `hist_observe` | **histogram of hard IRQ handler time** |
| `softirqs.rb` | softirqs | softirq_entry/exit + `cpu_id` key + `hist_observe` | **histogram of soft IRQ handler time** |
| `statsnoop.rb` | statsnoop | sys_enter_newfstatat/statx + `spnl_emit_str` | **streams the paths passed to stat(2)** |
| `syncsnoop.rb` | syncsnoop | sys_enter_sync/fsync/fdatasync + `spnl_emit` | **streams the pid that called sync(2)** |
| `tcpstates.rb` | tcpstates | sock/inet_sock_set_state (all transitions) + `spnl_emit4` | **streams TCP state transitions** |
| `capable.rb` | capable | kprobe cap_capable + `spnl_emit` + `emit_comm` | **streams capability checks (cap+comm)** |
| `gethostlatency.rb` | gethostlatency | uprobe/uretprobe getaddrinfo + `latency_start`/`latency_end` + `hist_observe` | **log2 histogram of name-resolution latency**, `SPNL_UPROBE_BINARY=libc.so.6` |
| `biosnoop.rb` | biosnoop | blk_mq_start/end_request + `lat_start`/`lat_end` + `kfield` + `spnl_emit3` | **(sector, bytes, latency) for each individual block I/O** |
| `runqslower.rb` | runqslower | sched_wakeup/switch + keyed latency + threshold | **streams (pid, latency) for run-queue waits > 1ms** |
| `fileslower.rb` | fileslower | kprobe/kretprobe vfs_read + tid latency + threshold | **streams vfs_read calls > 1ms** |
| `tcpretrans.rb` | tcpretrans | kprobe tcp_retransmit_skb + `kfield` (dotted embedded path) | **streams TCP retransmits as (daddr, dport)**; load/attach and the `kfield` read are verified, but provoking a real retransmit needs a genuinely lossy link |
| `mountsnoop.rb` | mountsnoop | sys_enter_mount/umount + `spnl_emit_str` | **streams the target path of mount/umount** |
| `cachestat.rb` | cachestat | kprobe folio_mark_accessed/filemap_add_folio/mark_buffer_dirty + `path_counter_inc` | **page cache hit/miss statistics**, `bpftool map dump bpf_path_counts` |
| `filelife.rb` | filelife | security_inode_create→vfs_unlink + keyed latency (dentry) | **streams the create→unlink lifetime of short-lived files** |
| `slabratetop.rb` | slabratetop | kmem/kmem_cache_alloc + `hist_observe(bytes_alloc)` | **slab allocation size distribution + rate** |
| `setuids.rb` | setuids | sys_enter_setuid/setresuid + `spnl_emit`/`spnl_emit3` | **streams the target uid of setuid/setresuid** |

### Measured results

Taken on the custom eBPF-enabled kernel inside the build container:

- `funclatency`: shows `do_sys_openat2` latency as a log2 histogram (bcc-style ASCII art).
- `syscount`: counted **31,758 syscalls** in 1.3s.
- `vfsstat`: **opens=2215 / reads=76 / writes=195** under `find /usr` and similar.
- `opensnoop`: displays openat filenames live, in arrival order.
- `inject`: injected EPERM into open() for comm=injtest only, `@injected=4` confirmed on real hardware.
- `sslsniff`: captured the TLS plaintext `GET /sniffme` / `GET /curltest` of openssl s_client and curl before encryption.
- `trace`: streamed 33 lines for comm=trycat opens only; `cat`'s opens were excluded by the predicate.
- `argdist`: tabulated the write size distribution as `{64:50, 4096:20}`, an exact match for the two dd runs.
- `memleak`: captured and symbolized 30 un-freed kmallocs (9096 bytes / 18 stacks) from the maple-tree RCU path of mmap/munmap.
- `deadlock`: correctly detected the lock-order inversion in an AB-BA demo, as 2 edges / 1 inversion.
- `execsnoop`: captured the filename and every argv element of `echo ALPHA BETA GAMMA DELTA`, breaking at the terminator.
- `runqlat`: measured run-queue latency, peaking at 2-4us under light load with a ~2-4ms long tail.
- `biolatency`: measured block I/O latency for a dd to vdb, peaking at 16-32us with a tail in the ms range.
- `tcplife`: measured TCP connections held for 300/600/900ms as 310/610/910ms.
- `tcpconnect`/`tcpaccept`: captured a connection to 127.0.0.1:8123 as daddr=16777343/dport=8123.
- `exitsnoop`/`killsnoop`: captured exiting process names and the kill signals (pid,15)/(pid,2).
- `cpudist`/`hardirqs`/`softirqs`: measured a bimodal on-CPU distribution, hard IRQs at 8-32us and soft IRQs at 8-16us.
- `statsnoop`/`syncsnoop`: captured the stat paths under /etc/* and the pid calling sync/fsync.
- `tcpstates`: captured the full TCP state-machine lifecycle of one connection (client + server).
- `capable`: observed the CAP_SYS_NICE(23) check of `nice -n -5`, by cap number and comm.
- `gethostlatency`: distinguished curl's getaddrinfo for localhost (~0.5ms) from failing DNS (tens to hundreds of ms).
- `biosnoop`: captured dd's 8 block I/Os individually, with sector / 65536B / latency.
- `runqslower`/`fileslower`: captured run-queue waits of 1.2-14ms and vfs_reads of 603/412ms as threshold crossings.


## Extending

Combine the attach kinds the DSL covers (kprobe / uprobe / USDT / tracepoint /
fentry / raw_tp / perf_event / LSM / fmod_ret / cgroup / iter) with the builtins
(histogram / stack / latency / task_storage / emit / ...) and bcc's other tools
(opensnoop / execsnoop / biolatency / runqlat / tcplife ...) can be written the
same way. Changing the two method names in `funclatency.rb` to a different
kprobe/kretprobe pair turns it into a latency tool for any function.
