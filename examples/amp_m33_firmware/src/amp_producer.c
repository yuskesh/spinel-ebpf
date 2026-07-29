/* SPDX-License-Identifier: Apache-2.0
 *
 * amp_producer.c -- the M33 half of the AMP transport on STM32MP257F-DK.
 *
 * Writes event records into the shared DDR ring on a 1 Hz timer, exactly as
 * the i.MX95 firmware does. Everything specific to this board is an address; the
 * ring code itself is spnl/amp_ring.h, unmodified.
 *
 * --- Why this file is written defensively ---
 *
 * STM32MP2 enforces resource isolation (RIF) in hardware, and a master touching
 * memory it does not own does not get an error back: the illegal access
 * controller raises, and on this board that takes the whole system down. Both
 * directions have been measured:
 *
 *   A35 reading the M33's RETRAM (0x0A080000)  -> immediate board reset
 *   M33 touching an unassigned resource        -> A35 hangs (ST community
 *                                                 reports the same, IAC ID 156)
 *
 * What is NOT yet known is whether the M33 may write `spare1@81300000` -- the
 * carveout the A35 side already uses (proven from Linux). The vendor
 * device tree gives it to nobody in particular, and the RIF assignment lives in
 * the secure world where Linux cannot read it, so this is a question only the
 * hardware answers.
 *
 * So the first thing this does is write a BOOT MARKER, before anything else and
 * before any timer starts. That turns an unknown into a binary result the A35
 * can read with the tool from T2:
 *
 *   marker present  -> the M33 may write this carveout; the ring is viable here
 *   board hangs     -> it may not, and the ring belongs in the M33's own
 *                      carveout instead, with the A35 reading that
 *
 * Neither outcome is a surprise and neither loses work. The cost of being wrong
 * is one reset, which is why the marker is written first: if the write faults,
 * it faults immediately and unambiguously, rather than three seconds later from
 * inside a timer callback where the cause would be one of several things.
 */
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/cache.h>
#include <zephyr/devicetree.h>

#include "spnl/amp_ring.h"

/* The A35-facing window, taken from the device tree rather than written as a
 * literal. That is not style: this image has CONFIG_ARM_MPU=y with gap filling,
 * so an address the device tree does not describe is one the MPU refuses, and a
 * literal would fault on its first store instead of reaching the shared memory
 * it names. The node is `amp_shm` in the board overlay.
 *
 * No board ABI header yet, deliberately: T3 has not decided the STM32MP2 ABI map,
 * and writing amp_abi_stm32mp2m33.h before knowing which regions this core may
 * actually touch would be recording the answer before measuring it. */
#define MP2_SHM_BASE     DT_REG_ADDR(DT_NODELABEL(amp_shm))
#define MP2_SHM_SIZE     DT_REG_SIZE(DT_NODELABEL(amp_shm))
#define MP2_RING_BASE    MP2_SHM_BASE
#define MP2_MARKER_BASE  (MP2_SHM_BASE + 0x2000UL)   /* past the ring's pages */


#define MP2_MARKER_MAGIC 0x3333504DUL   /* 'MP33' (LE): "the M33 got this far" */
#define AMP_RING_CAPACITY 64u

struct amp_boot_marker {
	uint32_t magic;      /* MP2_MARKER_MAGIC */
	uint32_t seq;        /* bumped every tick, so liveness is visible, not just boot */
	uint64_t uptime_ms;  /* what the M33 thinks the time is */
};

BUILD_ASSERT(MP2_SHM_SIZE >= 0x2000UL + sizeof(struct amp_boot_marker),
	     "amp_shm is too small for the ring and the marker");

static struct amp_ring *const g_ring = (struct amp_ring *)MP2_RING_BASE;
static volatile struct amp_boot_marker *const g_marker =
	(volatile struct amp_boot_marker *)MP2_MARKER_BASE;

static struct k_timer amp_timer;
static uint32_t g_tick;

/* The cache maintenance the AMP profile requires: the record must be visible
 * before the index that publishes it. Zephyr's cache API is the portable
 * spelling of what the i.MX95 runtime does with sys_cache_data_flush_range. */
static void publish(void *addr, size_t len)
{
	sys_cache_data_flush_range(addr, len);
}

static void amp_tick(struct k_timer *t)
{
	ARG_UNUSED(t);

	g_tick++;

	/* liveness first, so a ring problem and a "the M33 is dead" problem look
	 * different from the A35 side */
	g_marker->seq = g_tick;
	g_marker->uptime_ms = (uint64_t)k_uptime_get();
	publish((void *)g_marker, sizeof(struct amp_boot_marker));

	/* the same series the i.MX95 firmware emits, so the two boards' output is
	 * directly comparable: 7, 14, 21, ... */
	amp_ring_emit(g_ring, (uint64_t)k_uptime_get() * 1000000ull, (int64_t)g_tick * 7);
	publish(g_ring, sizeof(struct amp_ring) +
			(size_t)AMP_RING_CAPACITY * sizeof(struct amp_ring_rec));
}

static int amp_producer_init(void)
{
	/* Step 1, before anything else: can this core write that carveout at all?
	 * If RIF says no, the system stops here and the absence of the marker is
	 * itself the measurement. */
	g_marker->magic = MP2_MARKER_MAGIC;
	g_marker->seq = 0;
	g_marker->uptime_ms = 0;
	publish((void *)g_marker, sizeof(struct amp_boot_marker));

	/* Step 2: the ring. Same ABI as the other board, same header, same record. */
	amp_ring_init(g_ring, AMP_RING_CAPACITY);
	publish(g_ring, sizeof(struct amp_ring) +
			(size_t)AMP_RING_CAPACITY * sizeof(struct amp_ring_rec));

	k_timer_init(&amp_timer, amp_tick, NULL);
	k_timer_start(&amp_timer, K_SECONDS(1), K_SECONDS(1));
	return 0;
}

/* APPLICATION phase, after the kernel and the openamp base are up. */
SYS_INIT(amp_producer_init, APPLICATION, 90);
