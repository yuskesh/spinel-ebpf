/* SPDX-License-Identifier: Apache-2.0
 *
 * amp_m7_runtime.c -- the reusable real-time-core runtime, with a fixed ABI.
 * See amp_m7_runtime.h. Cache ABI + helper table are copied verbatim from the
 * the known-good patterns from the earlier producer, deliberately without variation.
 * S4 adds A/B double-buffered exec slots + an A55->M7 cmd ring for no-restart
 * hot swap + traceless teardown.
 */
#include "amp_m7_runtime.h"

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/cache.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>            /* MPU->CTRL, __DSB, __ISB */
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(amp_m7_runtime, LOG_LEVEL_INF);

static struct amp_ring *const g_ring = (struct amp_ring *)(uintptr_t)AMP_RT_RING_BASE;
static struct amp_cmd_ring *const g_cmd = (struct amp_cmd_ring *)(uintptr_t)AMP_RT_CMD_RING_BASE;
static volatile uint32_t *const g_progress = (volatile uint32_t *)(uintptr_t)AMP_RT_PROGRESS_BASE;
static volatile int g_active_slot = -1;   /* -1 = none installed, 0/1 = A/B */

/* write a step code where the A55 can read it (devmem2) + flush to DDR, so
 * we can see where the M7 last reached without its console. Safe inside the ITCM
 * write-window (MPU off): the progress word is DDR, cache maintenance still works. */
void amp_m7_progress(uint32_t step)
{
	*g_progress = step;
	sys_cache_data_flush_range((void *)g_progress, sizeof(uint32_t));
}

/* helper id 2: ktime_ns -> uptime ns (S5 swaps in the NETC PHC / gPTP clock). */
uint64_t amp_ktime(void)
{
	return (uint64_t)k_uptime_get() * 1000000ULL;
}

/* helper id 1: emit -- publish to the ring and flush it, as the cache contract requires. */
uint64_t amp_emit(uint64_t value)
{
	uint64_t ts = amp_ktime();
	if (!amp_ring_emit(g_ring, ts, (int64_t)value)) {
		return 0;   /* full — drop, never clobber unread */
	}
	uint32_t slot = (g_ring->prod - 1U) % g_ring->capacity;
	sys_cache_data_flush_range(&amp_ring_slots(g_ring)[slot], sizeof(struct amp_ring_rec));
	sys_cache_data_flush_range(g_ring, sizeof(struct amp_ring));
	return 0;
}

/* Write one literal-jump helper slot: `ldr.w pc,[pc]` + literal(target|Thumb). */
static void amp_write_slot(uintptr_t slot_addr, void *target)
{
	volatile uint32_t *slot = (volatile uint32_t *)slot_addr;
	slot[0] = AMP_HELPER_LDR_PC_PC;
	slot[1] = AMP_HELPER_LITERAL((uint32_t)(uintptr_t)target);
}

/*
 * ITCM write-window. Under imx95 M7 default config (CONFIG_ARM_MPU=y, XIP=y) ITCM
 * is RX, so writes to the helper table / blob slots fault. Briefly disable the MPU
 * (IRQs locked) to write, then re-enable: execution afterwards runs under RX. ITCM
 * is non-cached (TCM) so no I-cache maintenance; DSB/ISB order writes before fetch.
 * QEMU builds with CONFIG_ARM_MPU=n; the window collapses to a direct write.
 */
struct amp_window { uint32_t key; uint32_t mpu_ctrl; };

static struct amp_window amp_itcm_window_begin(void)
{
	struct amp_window w = { irq_lock(), 0u };
#if defined(CONFIG_ARM_MPU)
	w.mpu_ctrl = MPU->CTRL;
	MPU->CTRL = 0U;
	__DSB();
	__ISB();
#endif
	return w;
}
static void amp_itcm_window_end(struct amp_window w)
{
#if defined(CONFIG_ARM_MPU)
	MPU->CTRL = w.mpu_ctrl;   /* restore exactly (S2 pattern) */
	__DSB();
	__ISB();
#endif
	__DSB();
	__ISB();
	irq_unlock(w.key);
}

/* Copy a position-independent blob into exec slot `slot` and zero IVARS by
 * `ivars_size` — inside the ITCM write-window. The blob does not run yet. */
static void install_to_slot(int slot, const uint8_t *blob, uint32_t len, uint32_t ivars_size)
{
	uint32_t zsize = ivars_size ? ivars_size : AMP_IVARS_SIZE;
	if (zsize > AMP_IVARS_SIZE) {
		zsize = AMP_IVARS_SIZE;
	}
	amp_m7_progress(AMP_STEP_PRE_WINDOW);      /* 45: about to disable MPU */
	struct amp_window w = amp_itcm_window_begin();
	amp_m7_progress(AMP_STEP_IN_WINDOW);       /* 50: MPU off, inside window */
	memset((void *)(uintptr_t)AMP_RT_IVARS_BASE, 0, zsize);
	amp_m7_progress(AMP_STEP_POST_IVARS);      /* 55 */
	memcpy((void *)(uintptr_t)AMP_RT_BLOB_SLOT(slot), blob, len);
	amp_m7_progress(AMP_STEP_POST_MEMCPY);     /* 60 */
	/* NOTE: I-cache invalidate for the just-written slot goes here (step 65)
	 * once the observe-first pass confirms the hang is not earlier — M7 has I-cache
	 * (unlike QEMU M4), and re-executing a rewritten slot needs it. Not applied yet. */
	amp_itcm_window_end(w);
	amp_m7_progress(AMP_STEP_POST_WINDOW);     /* 70: MPU restored */
}

static void helper_table_install(void)
{
	struct amp_window w = amp_itcm_window_begin();
	amp_write_slot(AMP_RT_HELPER_SLOT(1), (void *)&amp_emit);
	amp_write_slot(AMP_RT_HELPER_SLOT(2), (void *)&amp_ktime);
	amp_itcm_window_end(w);
}

int amp_m7_runtime_init(void)
{
	amp_ring_init(g_ring, AMP_RT_RING_CAP);
	sys_cache_data_flush_range(g_ring, sizeof(struct amp_ring));
	amp_cmd_ring_init(g_cmd);
	sys_cache_data_flush_range(g_cmd, sizeof(struct amp_cmd_ring));
	g_active_slot = -1;

	helper_table_install();

	/* Boot-staged blob -> slot A. */
	const struct amp_blob_staging *st =
		(const struct amp_blob_staging *)(uintptr_t)AMP_RT_STAGING_BASE;
	sys_cache_data_invd_range((void *)st, sizeof(*st));

	int status = AMP_LOAD_OK;
	if (st->magic != AMP_STAGING_MAGIC) {
		status = AMP_LOAD_NO_BLOB;
	} else if (st->abi_version != AMP_ABI_VERSION) {
		status = AMP_LOAD_ABI_MISMATCH;
	} else if (st->length == 0U || st->length > AMP_BLOB_MAX) {
		status = AMP_LOAD_TOO_BIG;
	}
	if (status == AMP_LOAD_OK) {
		const uint8_t *src = (const uint8_t *)(st + 1);
		sys_cache_data_invd_range((void *)src, st->length);
		install_to_slot(0, src, st->length, st->ivars_size);
		g_active_slot = 0;
		/* Mark the boot staging area consumed by zeroing its magic, so a restart
		 * without re-staging doesn't re-read a stale blob. The real-HW failure hit
		 * this: a residual blob persisted in memory and was picked up at boot.
		 * Boot staging is still supported, just single-shot. */
		((struct amp_blob_staging *)(uintptr_t)AMP_RT_STAGING_BASE)->magic = 0;
		sys_cache_data_flush_range((void *)st, sizeof(*st));
	}

	LOG_INF("amp runtime up: ring@%p cmd@%p ivars@0x%08x helper@0x%08x slots@0x%08x load=%d",
		(void *)g_ring, (void *)g_cmd, (unsigned)AMP_RT_IVARS_BASE,
		(unsigned)AMP_RT_HELPER_BASE, (unsigned)AMP_RT_BLOB_SLOT_BASE, status);
	if (status == AMP_LOAD_ABI_MISMATCH) {
		LOG_ERR("amp runtime: BOOT BLOB REJECTED — abi_version %u != %u", st->abi_version, AMP_ABI_VERSION);
	}
	return status;
}

void amp_m7_run(void)
{
	int slot = g_active_slot;   /* atomic read of the active-slot word */
	if (slot < 0) {
		return;
	}
	amp_m7_progress(AMP_STEP_RUN);   /* 90: about to execute the active slot */
	int (*fn)(void *, unsigned int, void *, unsigned int) =
		(int (*)(void *, unsigned int, void *, unsigned int))
		((uintptr_t)AMP_RT_BLOB_SLOT(slot) | 1u);
	(void)fn(0, 0, 0, 0);
	amp_m7_progress(AMP_STEP_RUN_DONE);   /* 95: blob returned (no hang in exec) */
}

void amp_m7_teardown(void)
{
	g_active_slot = -1;   /* stop emit (atomic) */
	/* IVARS is DTCM (RW) — no ITCM window needed. */
	memset((void *)(uintptr_t)AMP_RT_IVARS_BASE, 0, AMP_IVARS_SIZE);
}

int amp_m7_poll_cmd(void)
{
	amp_m7_progress(AMP_STEP_POLL);   /* 20 */
	sys_cache_data_invd_range(g_cmd, sizeof(struct amp_cmd_ring));
	if (g_cmd->magic != AMP_CMD_RING_MAGIC) {
		return 0;
	}
	amp_m7_progress(AMP_STEP_CMD_MAGIC);   /* 25 */
	int processed = 0;
	uint32_t cons = g_cmd->cons;
	while (cons != g_cmd->prod) {
		amp_m7_progress(AMP_STEP_CMD_FOUND);   /* 30 */
		struct amp_cmd_rec *rec = &amp_cmd_ring_recs(g_cmd)[cons % g_cmd->capacity];
		sys_cache_data_invd_range(rec, sizeof(*rec));   /* A55-written */

		if (rec->type == AMP_CMD_INSTALL) {
			/* The gate on this side; the application core has already run the checker. */
			if (rec->abi_version == AMP_ABI_VERSION &&
			    rec->length > 0U && rec->length <= AMP_BLOB_MAX) {
				int target = (g_active_slot == 0) ? 1 : 0;   /* inactive slot */
				amp_m7_progress(AMP_STEP_PRE_INSTALL);   /* 40 */
				install_to_slot(target, rec->blob, rec->length, rec->ivars_size);
				g_active_slot = target;                       /* atomic flip */
				amp_m7_progress(AMP_STEP_POST_FLIP);   /* 80 */
				LOG_INF("hot-swap: INSTALL len=%u -> slot %d (active, no restart)",
					rec->length, target);
			} else {
				LOG_ERR("hot-swap: INSTALL rejected (abi=%u len=%u)",
					rec->abi_version, rec->length);
			}
		} else if (rec->type == AMP_CMD_TEARDOWN) {
			amp_m7_teardown();
			LOG_INF("hot-swap: TEARDOWN (deactivated + IVARS zeroed)");
		}
		cons++;
		processed++;
	}
	g_cmd->cons = cons;
	sys_cache_data_flush_range(g_cmd, sizeof(struct amp_cmd_ring));   /* publish cons */
	return processed;
}
