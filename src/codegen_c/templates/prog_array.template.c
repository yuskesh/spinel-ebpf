/* PROG_ARRAY for bpf_tail_call dispatch.
 *
 * Slot i holds the i-th `def xdp_tail__<name>` of this unit, in DECLARATION
 * ORDER. Nothing in this file says so: the loader does the writing
 * (_spnl_prog_array_populate), and it finds this map by the literal name
 * `spnl_prog_array` and the programs by the literal prefix `xdp_tail__`. Those
 * two names and the ordering are the whole contract between the two halves --
 * a mismatch does not fail, it jumps somewhere else.
 *
 * Re-ported from the retired Ruby code generator, having been lost in the port
 * to C; the map type was withdrawn once the audit withdrew
 * `tail_call_to` and the `xdp_tail__` attach kind). The declaration below is
 * byte-for-byte the oracle's, and the oracle's whole output was measured to
 * compile and load unchanged on 7.1.5-ebpf / clang 19.1.7 / -mcpu=v1.
 *
 * max_entries is max(<tail targets>, 32) -- the oracle's rule. Slots past the
 * declared targets stay empty, and a bpf_tail_call into an empty slot FALLS
 * THROUGH (the caller keeps running) instead of failing, which is why a literal
 * slot outside the declared range is refused at compile time rather than left
 * to be discovered as "the packet took the wrong branch". */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, @N@);
} spnl_prog_array SEC(".maps");
