/* SO_REUSEPORT worker sockarray -- the table `worker_select(idx)` picks
 * from.
 *
 * Slot i holds the listening socket of the worker that called
 * sp_bpf_reuseport_register(listen_fd, i). Nothing in this file says so: the
 * glue does the writing (bin/spinel-ebpf, _spnl_reuseport_map_fd) and it finds
 * this map by the literal name `bpf_worker_socks`. That name is the whole
 * contract between the two halves, and unlike the PROG_ARRAY there is
 * no ordering convention on top of it -- the index is whatever the worker
 * passed, so a wrong index is a userspace bug in the author's own Ruby.
 *
 * The failure that IS invisible is an EMPTY slot: bpf_sk_select_reuseport
 * returns -ENOENT and the kernel falls back to its own 5-tuple distribution.
 * The connection is still served, by a plausible worker, so "the program chose
 * this worker" and "the program chose nothing and the kernel did" look
 * identical from outside. That is why the codegen refuses to
 * silence the return value into a bare statement without saying so, and why
 * `describe` prints how many slots the author's own modulo can reach.
 *
 * Re-ported from the retired Ruby code generator, having been lost in the port
 * to C; the map type was withdrawn once the audit withdrew the two
 * builtins). The declaration below is byte-for-byte the oracle's, and the
 * oracle's whole output was measured to compile and load unchanged on
 * 7.1.5-ebpf / clang 19.1.7 / -mcpu=v1.
 *
 * max_entries is 64 -- the oracle's fixed size, not derived from anything the
 * codegen can see. The worker count lives in userspace (fork loop) and in the
 * author's own arithmetic; the codegen never learns it. */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} bpf_worker_socks SEC(".maps");
