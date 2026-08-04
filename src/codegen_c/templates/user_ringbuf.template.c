/* USER_RINGBUF for the host-to-kernel command channel.
 *
 * The one direction a plain BPF ringbuf cannot go. `bpf_ringbuf_*` carries
 * kernel->host; this map carries host->kernel, in FIFO order, with the host
 * side batching through libbpf's reserve/submit (the channel exists to batch).
 *
 * Re-ported from the retired Ruby code generator, having been lost in the port
 * to C; the map type was withdrawn once the audit withdrew both
 * `user_ringbuf_drain` and the `user_ringbuf__` attach kind.
 * The declaration below is byte-for-byte the oracle's, and the oracle's whole
 * output was measured to compile and load unchanged on 7.1.5-ebpf /
 * clang 19.1.7 / -mcpu=v1.
 *
 * TWO NUMBERS LIVE IN TWO FILES HERE and nothing checks them at build time:
 *   - the map's literal name `bpf_user_cmds`, which the loader's
 *     `sp_bpf_user_cmd_push` finds by string, and
 *   - the 8-byte record, which the callback below reads with a fixed
 *     `sizeof(__s64)` and the loader reserves with a fixed `sizeof(long long)`.
 * Measured what a disagreement does: a SHORT
 * record still fires the callback and still counts, but `bpf_dynptr_read`
 * returns -E2BIG and the value stays 0 -- silently. That is why the shipped
 * pusher is the only advertised way in, and why `describe` prints the size.
 *
 * max_entries is a byte count (ring size), not a record count: 256 KB. */
struct {
    __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 262144);
} bpf_user_cmds SEC(".maps");

static long spnl_user_ringbuf_cb_@CB@(struct bpf_dynptr *dynptr, void *_uctx);
