/* SPDX-License-Identifier: GPL-2.0
 *
 * spnl/amp_abi_stm32mp2m33.h -- fixed AMP ABI (board profile: STM32MP257F-DK Cortex-M33)
 *
 * The sibling of spnl/amp_abi_imx95m7.h. Same structure, same macro names, same
 * meanings. **Only the values differ** -- which is the whole claim:
 *
 *   > Vendor dependence is confined to the fixed ABI address values and the
 *   > Zephyr board overlay; the runtime, the code generator and the drain go
 *   > across unchanged.
 *
 * The day this file needs a new *kind* of constant, or the runtime needs a board
 * conditional, that claim has weakened and the honest thing is to record it
 * rather than paper over it.
 *
 * ---------------------------------------------------------------------------
 * Why the values differ (measured)
 * ---------------------------------------------------------------------------
 *
 * **This core executes from DDR.** The Zephyr board device tree gives it
 *   zephyr,flash = &ddr_code  (memory0@80100000)
 *   zephyr,sram  = &ddr_sys   (memory1@80a00000)
 * and **both have bit 31 set**. The i.MX95 M7 met the constraint below by
 * accident: its ITCM and DTCM sit at 0x000... and 0x200....
 *
 * !!! JIT constraint (shared with the i.MX95 profile) !!!
 *   The ahead-of-time compiler's immediate load refuses a negative i32 -- any
 *   value with bit 31 set -- beyond 8 bits. So the addresses **baked into the
 *   blob** (AMP_HELPER_BASE and AMP_IVARS_BASE) must have bit 31 clear. The
 *   addresses that are *not* baked (ring, staging, command ring, progress,
 *   capability table, and the blob's own execution slot) carry no such
 *   restriction: the firmware reaches those, not the blob.
 *
 * The way out is this core's own internal SRAM, where bit 31 is clear. From the
 * vendor device tree's reservations:
 *
 *   cm33-sram1   0x0A041000  124 KB
 *   cm33-sram2   0x0A060000  128 KB
 *   cm33-retram  0x0A080000  124 KB
 *
 * 0x0A0... also lands inside the Cortex-M **Code** region (0x00000000 -
 * 0x1FFFFFFF), so it is executable under the default memory map -- which is the
 * helper table's other requirement, satisfied at the same time. The split below
 * mirrors i.MX95's ITCM/DTCM: executable code in one bank, writable data in the
 * other.
 *
 * ---------------------------------------------------------------------------
 * Why the ABI version differs from the other profile
 * ---------------------------------------------------------------------------
 *
 * The version gate answers "will this blob run on the firmware in front of it?".
 * A blob with these addresses baked in does not run correctly on i.MX95 firmware,
 * so it is **a different ABI** and gets a different number. The existing loud
 * rejection then catches a cross-board mix-up on its own, with no change to any
 * struct.
 *
 * The number identifies the (layout, address map) pair. It is not a chronology,
 * and a higher number does not mean newer.
 */
#ifndef SPNL_AMP_ABI_STM32MP2M33_H
#define SPNL_AMP_ABI_STM32MP2M33_H

#include <stdint.h>

#define AMP_ABI_VERSION 2u   /* the i.MX95 profile is 1; see above -- an identifier, not an order */

/* ======================================================================== *
 *  blob-facing ABI  (baked into the blob; bit 31 must be clear)              *
 * ======================================================================== */

/* --- this core's internal SRAM, matching the vendor device tree reservations --- */
#define AMP_SRAM1_BASE  0x0A041000u   /* data side: the instance-variable carveout */
#define AMP_SRAM1_SIZE  0x0001F000u   /* 124 KiB, ends at 0x0A060000 */
#define AMP_SRAM2_BASE  0x0A060000u   /* code side: helper table + blob slots */
#define AMP_SRAM2_SIZE  0x00020000u   /* 128 KiB, ends at 0x0A080000 */

/* --- helper entry table (same mechanism and macros as the other profile) ---
 * The firmware lays an 8-byte slot per helper at AMP_HELPER_BASE and patches the
 * literal at boot; the generator bakes `call <id>` into an immediate call to
 * AMP_HELPER_SLOT(id). See the i.MX95 profile for why the table is written as
 * data at boot rather than resolved by the linker.
 *
 * Placed in the **top 256 bytes of sram2**: inside the Code region so it can be
 * executed, bit 31 clear so it can be baked. Zephyr only uses DDR here, so this
 * bank is otherwise idle -- but with CONFIG_MPU_GAP_FILLING=y anything the device
 * tree does not describe is actively made inaccessible, so the board overlay has
 * to declare it. That declaration is the second half of the vendor dependence
 * this ABI is claiming to be confined to. */
#define AMP_HELPER_SLOT_BYTES 8u
#define AMP_HELPER_SLOTS      32u
#define AMP_HELPER_SIZE       (AMP_HELPER_SLOT_BYTES * AMP_HELPER_SLOTS)  /* 256 B */
#define AMP_HELPER_BASE       0x0A07FF00u  /* = top of sram2 - 256B */

#define AMP_HELPER_SLOT(id)   (AMP_HELPER_BASE + ((unsigned)(id) - 1u) * AMP_HELPER_SLOT_BYTES)
/* `ldr.w pc, [pc]` (T2 LDR-literal, Rt=PC, imm12=0). The encoding is identical on
 * ARMv7-M and ARMv8-M Mainline -- measured, by reassembling a blob for both and
 * comparing bytes. */
#define AMP_HELPER_LDR_PC_PC  0xF000F8DFu
#define AMP_HELPER_LITERAL(addr) (((unsigned)(addr)) | 1u)

#define AMP_HELPER_ID_EMIT    1u   /* spnl_emit -> publish to the ring */
#define AMP_HELPER_ID_KTIME   2u   /* ktime_ns  -> the time source */

/* --- instance-variable carveout (addressed by a baked immediate) ---
 * The **top 256 bytes of sram1**: bit 31 clear, and writable.
 *
 * The open question the i.MX95 profile carries -- whether the application core
 * can read the carveout through some alias -- does not arise here, because this
 * SRAM sits in the SoC's flat address space and the application core names the
 * same address. That does not make it readable: the resource isolation
 * controller assigns these banks to the real-time core, and an access from the
 * other side is treated as illegal rather than returning an error. So **the
 * application core does not read instance variables directly**; values reach it
 * through the ring, published by the core that owns them. */
#define AMP_IVARS_SIZE  0x00000100u    /* 256 B */
#define AMP_IVARS_BASE  0x0A05FF00u    /* = top of sram1 - 256B */

/* ======================================================================== *
 *  application-core-facing ABI (firmware <-> Linux; not baked, bit 31 free)  *
 * ======================================================================== */

/* All of this lives inside a 12.75 MB reservation the vendor device tree already
 * carries and hands to nobody in particular, so no device tree edit was needed to
 * make room -- unlike the first board.
 *
 * **The offsets are the same as the other profile's** (ring, +0x20000 staging,
 * +0x30000 command ring, +0x31000 progress, +0x32000 capability). Two maps that
 * can be read side by side are two maps whose differences are visible. */
#define AMP_SPARE1_BASE    0x81300000u
#define AMP_SPARE1_SIZE    0x00CC0000u

#define AMP_RING_BASE      0x81300000u

#define AMP_STAGING_BASE   0x81320000u
#define AMP_STAGING_SIZE   0x1000u
#define AMP_STAGING_MAGIC  0x42504D41u    /* 'A''M''P''B' (LE) */
#define AMP_BLOB_MAX       512u

struct amp_blob_staging {
	uint32_t magic;
	uint32_t abi_version;
	uint32_t length;
	uint32_t ivars_size;
	/* uint8_t blob[length] follows */
};

#define AMP_CMD_RING_BASE  0x81330000u
#define AMP_CMD_RING_SIZE  0x1000u

#define AMP_PROGRESS_BASE  0x81331000u
enum amp_step {
	AMP_STEP_TICK        = 10,
	AMP_STEP_POLL        = 20,
	AMP_STEP_CMD_MAGIC   = 25,
	AMP_STEP_CMD_FOUND   = 30,
	AMP_STEP_PRE_INSTALL = 40,
	AMP_STEP_PRE_WINDOW  = 45,
	AMP_STEP_IN_WINDOW   = 50,
	AMP_STEP_POST_IVARS  = 55,
	AMP_STEP_POST_MEMCPY = 60,
	AMP_STEP_POST_ICACHE = 65,
	AMP_STEP_POST_WINDOW = 70,
	AMP_STEP_POST_FLIP   = 80,
	AMP_STEP_RUN         = 90,
	AMP_STEP_RUN_DONE    = 95,
	AMP_STEP_TICK_DONE   = 100,
};

#define AMP_CAPABILITY_BASE 0x81332000u
#define AMP_CAPABILITY_SIZE 0x1000u

#define AMP_CMD_RING_MAGIC 0x444D4341u     /* 'A''C''M''D' (LE) */
#define AMP_CMD_RING_CAP   2u

enum amp_cmd_type {
	AMP_CMD_NONE = 0,
	AMP_CMD_INSTALL = 1,
	AMP_CMD_TEARDOWN = 2,
};

struct amp_cmd_rec {
	uint32_t type;
	uint32_t abi_version;
	uint32_t length;
	uint32_t ivars_size;
	uint8_t  blob[AMP_BLOB_MAX];
};

struct amp_cmd_ring {
	uint32_t magic;
	uint32_t version;
	uint32_t capacity;
	uint32_t rec_size;
	volatile uint32_t prod;
	volatile uint32_t cons;
	uint32_t _pad[2];
};

static inline struct amp_cmd_rec *amp_cmd_ring_recs(struct amp_cmd_ring *r) {
	return (struct amp_cmd_rec *)((char *)r + sizeof(struct amp_cmd_ring));
}

static inline void amp_cmd_ring_init(struct amp_cmd_ring *r) {
	r->version = 1;
	r->capacity = AMP_CMD_RING_CAP;
	r->rec_size = (uint32_t)sizeof(struct amp_cmd_rec);
	r->prod = 0;
	r->cons = 0;
	r->_pad[0] = r->_pad[1] = 0;
	r->magic = AMP_CMD_RING_MAGIC;   /* publish last */
}

static inline int amp_cmd_ring_push(struct amp_cmd_ring *r, const struct amp_cmd_rec *rec) {
	if (r->magic != AMP_CMD_RING_MAGIC) return 0;
	uint32_t prod = r->prod, cons = r->cons;
	if (prod - cons >= r->capacity) return 0;   /* full */
	amp_cmd_ring_recs(r)[prod % r->capacity] = *rec;
	r->prod = prod + 1;                          /* publish */
	return 1;
}

#endif /* SPNL_AMP_ABI_STM32MP2M33_H */
