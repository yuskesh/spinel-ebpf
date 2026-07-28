/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * amp_producer.c -- amp-m7 M7 runtime (helpers + ring + blob loader).
 *
 * Two stages, both of which this file still supports:
 *   1. a 1 Hz k_timer writes the shared DDR ring directly (a hand-written
 *      producer) -- this validated the transport on real hardware.
 *   2. the same timer instead invokes the AOT'd Ruby probe (amp_blob), whose
 *      `amp_emit` (helper id 1) writes the ring. This runs the Ruby-authored
 *      bytecode on the real M7.
 *
 * amp_emit / amp_ktime are the M7 helper table. Their addresses are baked into
 * the blob at host-AOT time (2-pass: build -> nm -> AOT -> embed -> rebuild),
 * so they must be global, `used`, and never inlined. amp_ivars is the probe's
 * @ivar carveout (blob compiled with SPNL_AMP_IVARS_BASE = &amp_ivars).
 *
 * Wired via SYS_INIT; the openamp sample's main_remote.c stays verbatim.
 */
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/cache.h>
#include <zephyr/logging/log.h>
#include <stdint.h>

#include "spnl/amp_ring.h"
#include "amp_blob.inc"   /* generated: amp_blob[], amp_blob_installed (build-amp-blob.sh) */

LOG_MODULE_REGISTER(amp_producer, LOG_LEVEL_INF);

/* v0 ring placement: inside the openamp shmem grant (DT shmem@0x88000000 size
 * 0x500000), 4 MiB in. Production carves out a dedicated telemetry region
 * (0x8830_0000, declared in the system-manager config / device tree). Keep in
 * sync with a55_drain.c. */
#define AMP_RING_PHYS 0x88400000UL
#define AMP_RING_CAP  256U

static struct amp_ring *const ring = (struct amp_ring *)AMP_RING_PHYS;

/* Probe @ivar carveout. The blob is AOT'd with SPNL_AMP_IVARS_BASE = &amp_ivars,
 * so this address is read from the pass-1 firmware and baked into the bytecode.
 * `retain` + a reference in amp_producer_init keep the linker's --gc-sections
 * from dropping it (nothing in C references it -- only the baked blob does). */
uint32_t amp_ivars[16] __attribute__((aligned(4), used, retain));

/* --- M7 helper table (baked into the blob by address) --- */

/* helper id 1: spnl_emit -> publish to the ring + flush (per the cache ABI).
 * retain + non-static so --gc-sections keeps it: the blob calls it by baked
 * address (invisible to the linker), and with a blob installed the C fallback
 * that would otherwise reference it is dead. */
__attribute__((used, noinline, retain))
unsigned long long amp_emit(unsigned long long value)
{
	uint64_t ts = (uint64_t)k_uptime_get() * 1000000ULL;
	if (!amp_ring_emit(ring, ts, (int64_t)value)) {
		return 0;   /* full — drop, never clobber unread */
	}
	uint32_t slot = (ring->prod - 1U) % ring->capacity;
	sys_cache_data_flush_range(&amp_ring_slots(ring)[slot], sizeof(struct amp_ring_rec));
	sys_cache_data_flush_range(ring, sizeof(struct amp_ring));
	return 0;
}

/* helper id 2: ktime_ns -> uptime ns (S5 swaps in the NETC PHC / gPTP clock). */
__attribute__((used, noinline))
unsigned long long amp_ktime(void)
{
	return (uint64_t)k_uptime_get() * 1000000ULL;
}

/* --- timer: run the probe (blob) if installed, else the S3 hand-written counter --- */

static uint32_t fallback_counter;

static void amp_tick(struct k_timer *t)
{
	ARG_UNUSED(t);
	if (amp_blob_installed) {
		/* Invoke the AOT'd Ruby bytecode. Entry ABI = AAPCS fn(mbuff,len,mem,len)
		 * (micro-bpf JIT); blink ignores args. Thumb bit set on the entry. */
		int (*fn)(void *, unsigned, void *, unsigned) =
			(int (*)(void *, unsigned, void *, unsigned))((uintptr_t)amp_blob | 1u);
		(void)fn(0, 0, 0, 0);   /* its amp_emit(value) writes the ring */
	} else {
		(void)amp_emit(++fallback_counter);   /* fallback: hand-written producer */
	}
}

K_TIMER_DEFINE(amp_timer, amp_tick, NULL);

static int amp_producer_init(void)
{
	amp_ring_init(ring, AMP_RING_CAP);
	sys_cache_data_flush_range(ring, sizeof(struct amp_ring));
	amp_ivars[0] = 0;   /* reference &amp_ivars so the linker keeps it (blob's @ivar base) */
	k_timer_start(&amp_timer, K_SECONDS(1), K_SECONDS(1));
	LOG_INF("amp runtime up: ring @ %p, ivars @ %p, blob=%d",
		(void *)ring, (void *)amp_ivars, amp_blob_installed);
	return 0;
}
SYS_INIT(amp_producer_init, APPLICATION, 90);
