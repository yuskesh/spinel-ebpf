/* SPDX-License-Identifier: Apache-2.0
 *
 * amp_sram_probe.c -- answer, in one bit, whether this core may use its own SRAM.
 *
 * The fixed ABI for this board (spnl/amp_abi_stm32mp2m33.h) puts the two addresses
 * that get baked into a blob in the M33's internal SRAM. It has to: this core
 * executes from DDR, every DDR address here has bit 31 set, and the ahead-of-time
 * compiler cannot bake such an immediate. The i.MX95 M7 never met the problem
 * because its ITCM and DTCM already sit below 0x80000000.
 *
 * That leaves a premise nobody has measured. The device tree reservations named
 * `cm33-sram1` and `cm33-sram2` only say "Linux, keep out". Whether the resource
 * isolation controller actually grants those banks to this core is decided in the
 * secure world, where Linux cannot read it. So before anything is built on top of
 * the ABI, this answers the question.
 *
 * It is written the way the producer beside it is written: **publish the result to
 * shared memory first**. The M33 console is readable today, but relying on it
 * makes "the console is not coming through" and "the SRAM is not usable"
 * indistinguishable -- a confusion that has already cost a day on this board.
 * Stamping progress into a word the application core can read over /dev/mem means
 * the outcome is legible either way:
 *
 *   status stays at STARTED         -> it faulted on the first SRAM access: not usable
 *   status at an intermediate value -> it got that far
 *   status == OK                    -> read, write and pattern retention all hold
 *
 * The cost of being wrong is one reset. What is bought is a definite answer about
 * where the ABI has to live.
 */
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/cache.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>            /* MPU->CTRL, __DSB, __ISB */
#include <zephyr/logging/log.h>

#include "spnl/amp_abi.h"

LOG_MODULE_REGISTER(amp_sram_probe, LOG_LEVEL_INF);

/* A bring-up observation window, not ABI. Putting it in the contract would make it
 * impossible to remove later, so it is derived from the shared reservation's base
 * and sits past everything the ABI defines. */
#define PROBE_STATUS_BASE  (AMP_SPARE1_BASE + 0x40000u)
#define PROBE_MAGIC        0x50524253u   /* 'S''B''R''P' (LE): sram bring-up probe */

enum {
	PROBE_STARTED     = 1,   /* shared memory is writable (the producer's boot marker, in effect) */
	PROBE_IVARS_WROTE = 2,   /* sram1 (the ivar carveout) took a write */
	PROBE_IVARS_READ  = 3,   /* sram1 read back */
	PROBE_CODE_WROTE  = 4,   /* unused: sram2 is written inside one MPU window */
	PROBE_CODE_READ   = 5,   /* sram2 read back */
	PROBE_OK          = 0x4F4B4F4Bu, /* every stage passed */
};

static volatile uint32_t *const g_status = (volatile uint32_t *)(uintptr_t)PROBE_STATUS_BASE;

static void publish(uint32_t step, uint32_t a, uint32_t b)
{
	g_status[1] = step;
	g_status[2] = a;
	g_status[3] = b;
	g_status[0] = PROBE_MAGIC;   /* magic last, so a half-written window never reads as OK */
	sys_cache_data_flush_range((void *)g_status, 16);
}

/* Write one word and read it back. The value is returned rather than a boolean
 * because "the store did not fault" and "the value stayed there" are different
 * facts: a firewall can drop a write silently. */
static uint32_t probe_word(uintptr_t addr, uint32_t pattern)
{
	volatile uint32_t *p = (volatile uint32_t *)addr;
	*p = pattern;
	__asm__ volatile("dsb sy" ::: "memory");
	return *p;
}

static int amp_sram_probe_init(void)
{
	publish(PROBE_STARTED, 0, 0);

	/* --- sram1: the ivar carveout, which has to be readable and writable --- */
	uint32_t iv = probe_word(AMP_IVARS_BASE, 0xA5A5001Au);
	publish(PROBE_IVARS_WROTE, iv, 0);
	uint32_t iv2 = probe_word(AMP_IVARS_BASE + AMP_IVARS_SIZE - 4u, 0x5A5A001Bu);
	publish(PROBE_IVARS_READ, iv, iv2);

	/* --- sram2: helper table and blob slots, which also have to be executable ---
	 * The MPU maps this read-execute, so a plain store would fault. Use the same
	 * window the runtime uses: interrupts locked, MPU off, write, restore. */
	unsigned int key = irq_lock();
#if defined(CONFIG_ARM_MPU)
	uint32_t mpu_ctrl = MPU->CTRL;
	MPU->CTRL = 0U;
	__DSB();
	__ISB();
#endif
	uint32_t cw = probe_word(AMP_HELPER_BASE, 0xC0DE001Cu);
	uint32_t cw2 = probe_word(AMP_HELPER_BASE + AMP_HELPER_SIZE - 4u, 0xC0DE001Du);
#if defined(CONFIG_ARM_MPU)
	MPU->CTRL = mpu_ctrl;
	__DSB();
	__ISB();
#endif
	irq_unlock(key);
	publish(PROBE_CODE_READ, cw, cw2);

	int ok = (iv == 0xA5A5001Au) && (iv2 == 0x5A5A001Bu) &&
		 (cw == 0xC0DE001Cu) && (cw2 == 0xC0DE001Du);

	publish(ok ? PROBE_OK : PROBE_CODE_READ, iv, cw);
	LOG_INF("sram probe: ivars@0x%08x -> 0x%08x/0x%08x  code@0x%08x -> 0x%08x/0x%08x  %s",
		(unsigned)AMP_IVARS_BASE, iv, iv2,
		(unsigned)AMP_HELPER_BASE, cw, cw2, ok ? "OK" : "MISMATCH");
	return 0;
}

/* Runs before the runtime (APPLICATION 90): the ABI's premise is measured ahead of
 * the code that depends on it. */
SYS_INIT(amp_sram_probe_init, APPLICATION, 80);
