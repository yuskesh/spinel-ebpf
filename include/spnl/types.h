/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * spinel-ebpf shared types -- used by both eBPF C (generated) and host C.
 * The host<->kernel ring-buffer record header.
 *
 * Layout MUST stay 16 bytes and field order MUST not change without bumping
 * SPNL_EVENT_HDR_VERSION; both sides assume the same layout.
 *
 * This header does NOT define __u16/__u32/__u64 — they must be provided
 * by including either <vmlinux.h> (BPF side) or <linux/types.h> /
 * <bpf/libbpf.h> (host side) before this file.
 */
#ifndef SPNL_TYPES_H
#define SPNL_TYPES_H

#define SPNL_EVENT_HDR_VERSION 1

/* Type tag namespacing:
 *   0x0000-0x00FF : reserved for spinel-ebpf runtime (errors, system events)
 *   0x0100-0xFFFF : user codegen-allocated (one per Ruby class/method/event)
 */
#define SPNL_EVT_ERROR     0x0001
#define SPNL_EVT_USER_BASE 0x0100

struct spnl_event_hdr {
    __u16 type;
    __u16 version;
    __u32 reserved;
    __u64 timestamp;        /* bpf_ktime_get_ns() at producer side */
};

#endif /* SPNL_TYPES_H */
