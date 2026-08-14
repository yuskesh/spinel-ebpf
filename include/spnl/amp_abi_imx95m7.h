/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * spnl/amp_abi_imx95m7.h -- fixed AMP ABI (board profile: FRDM-IMX95 Cortex-M7)
 *
 * The point of fixing the memory ABI is that the amp-m7 codegen can bake fixed
 * constants without consulting `nm`, which makes the blob a single-pass,
 * firmware-independent artifact (it replaces an earlier two-pass build that had
 * to link against a specific firmware image). "firmware-independent" is a claim
 * **within one board profile** -- that is, within this one file.
 *
 * The ABI has two faces:
 *   - blob-facing : constants baked into the blob. Changing one means re-AOT'ing
 *                   every blob, so keep this set minimal and change it carefully.
 *   - A55-facing  : the firmware<->A55 contract. Irrelevant to the blob (the blob
 *                   never touches the ring; spnl_emit is a helper call and only
 *                   the firmware side knows about the ring).
 *
 * What the numbers are based on:
 *   - The ITCM/DTCM addresses and sizes come from the Zephyr SoC dtsi
 *     (nxp_imx95_m7.dtsi): ITCM 0x00000000 / 256 KiB, DTCM 0x20000000 / 256 KiB.
 *     The board has flash=&itcm (code) and sram=&dtcm (data). This matches what
 *     real hardware shows (code @ ITCM 0xe60, .bss @ DTCM 0x20000d1c).
 *   - Helper indirection (the H1 literal-jump below) and direct ivar RMW were
 *     both shown to work under QEMU (an386).
 *
 * !!! IMPORTANT JIT CONSTRAINT (measured) !!!
 *   The micro-bpf host JIT's immediate load (MoveImmediate) **rejects a negative
 *   i32 (i.e. any value with bit31 set) wider than 8 bits**. So every address
 *   baked into the blob -- AMP_HELPER_BASE, and AMP_IVARS_BASE for direct ivar
 *   RMW -- **must have bit31 = 0**. ITCM/DTCM (0x00xxxxxx / 0x20xxxxxx) satisfy
 *   this; a DDR carveout (0x8xxxxxxx) does not. So putting IVARS in DDR would
 *   mean giving up direct RMW and switching to **helper-mediated ivar access**
 *   instead (a codegen change). That constraint is the heart of the IVARS TODO
 *   below.
 */
#ifndef SPNL_AMP_ABI_IMX95M7_H
#define SPNL_AMP_ABI_IMX95M7_H

#include <stdint.h>   /* struct amp_blob_staging (A55-facing) */

/*
 * ABI version. The gate that makes "runs on any firmware that honours the ABI"
 * checkable. The manifest carries the blob's required version and the loader
 * **rejects a mismatch loudly** (never a silent breakage). On the A55-facing
 * side, AMP_RING_VERSION in the ring control block (spnl/amp_ring.h) plays the
 * same role.
 * Bump this only when one of the blob-facing constants below changes.
 */
#define AMP_ABI_VERSION 1u

/* ======================================================================== *
 *  blob-facing ABI  (baked into the blob. bit31 = 0 required.               *
 *                    a change here means bumping the ABI version)           *
 * ======================================================================== */

/* --- i.MX95 M7 TCM map (Zephyr nxp_imx95_m7.dtsi; matches real hardware) --- */
#define AMP_ITCM_BASE   0x00000000u   /* ITCM base (Code region: executable in the default map) */
#define AMP_ITCM_SIZE   0x00040000u   /* 256 KiB */
#define AMP_DTCM_BASE   0x20000000u   /* DTCM base (M7-local view) */
#define AMP_DTCM_SIZE   0x00040000u   /* 256 KiB */

/* --- helper entry table (H1: fixed literal-jump, no JIT changes) ---
 * The firmware places a table of 8-byte slots at AMP_HELPER_BASE. Each slot is
 *   [0]=`ldr.w pc,[pc]` (AMP_HELPER_LDR_PC_PC) / [1]=literal (real helper addr|Thumb).
 * The literal is **patched by the firmware at boot as a data write**, not resolved
 * by the linker, which removes b.w range problems, veneers and gc-sections drift
 * (all of which bit the earlier linked-against-firmware build). The codegen bakes
 * `call <id>` into an immediate call to AMP_HELPER_SLOT(id) (the JIT adds the
 * Thumb bit). 8B x 32 slots = 256B is reserved up front so new helpers are
 * absorbed by adding a slot, leaving the ABI unchanged.
 *
 * Placement: the top 256B of ITCM. ITCM is a Code region (executable) and TCM
 * (patchable at boot, uncached so no I-cache coherency is needed), and bit31=0
 * so the JIT can bake it. The firmware must **reserve** this by ending its ITCM
 * code region 256B short of the top (the ITCM counterpart of the mechanism
 * demonstrated under QEMU by shrinking sram0 by 8 KiB).
 *
 * TODO (real hardware): confirm that this ITCM region is actually **executable**
 *   under the real M7's MPU/XN settings. Zephyr's memory-region flags are
 *   advisory (they do not drive the MPU), so the MPU configuration (region entry)
 *   has to allow exec. The QEMU spike sidestepped this by building with MPU=n,
 *   so it needs confirming on real hardware.
 */
#define AMP_HELPER_SLOT_BYTES 8u
#define AMP_HELPER_SLOTS      32u
#define AMP_HELPER_SIZE       (AMP_HELPER_SLOT_BYTES * AMP_HELPER_SLOTS)  /* 256 B */
#define AMP_HELPER_BASE       0x0003FF00u  /* = ITCM top - 256B (0x40000 - 0x100) */

/* offsets inside a slot: [0]=instruction, [1]=literal */
#define AMP_HELPER_SLOT(id)   (AMP_HELPER_BASE + ((unsigned)(id) - 1u) * AMP_HELPER_SLOT_BYTES)
/* `ldr.w pc, [pc]` (T2 LDR-literal, Rt=PC, imm12=0): loads the literal at slot+4 into PC.
 * (encoding measured from arm-none-eabi-as: bytes df f8 00 f0 = word 0xF000F8DF) */
#define AMP_HELPER_LDR_PC_PC  0xF000F8DFu
/* value written into the literal = real helper address | Thumb bit */
#define AMP_HELPER_LITERAL(addr) (((unsigned)(addr)) | 1u)

/* helper id space (matches the firmware: id 1=emit, id 2=ktime) */
#define AMP_HELPER_ID_EMIT    1u   /* spnl_emit -> ring publish (the cache flush is inside the helper) */
#define AMP_HELPER_ID_KTIME   2u   /* ktime_ns  -> uptime ns (PHC/gPTP-backed time is future work) */

/* --- where the ivars live (direct RMW of @ivar; the address is a bytecode immediate) ---
 * The codegen bakes `SPNL_AMP_IVARS_BASE = AMP_IVARS_BASE` as a MOV/LDDW immediate,
 * never going through a .data/.rodata relocation, so no address-parameterizing
 * patch step is needed.
 * The loader **zeroes AMP_IVARS_SIZE on every slot install**: doing it only at boot
 * would let a hot-swapped probe read the previous probe's leftovers.
 *
 * Placement: the top 256B of DTCM. bit31=0, so the JIT can bake it (see the JIT
 * constraint above). An earlier build used DTCM .bss (0x20000d1c). The firmware
 * must keep its DTCM .bss/heap/stack below this 256B and **reserve** the region
 * (the DTCM counterpart of the sram0 shrink used under QEMU).
 *
 * !!! UNDECIDED (do not settle this silently) !!!
 *   The design requires that the A55 be able to mmap and read the ivars. DTCM is
 *   M7-local (0x20000000) and is only visible from the A55 through a **TCM system
 *   alias**, if one exists at all. Decision tree:
 *     (a) the A55 can read a DTCM alias -> pin down AMP_IVARS_A55_ALIAS in the
 *         A55-facing section below and keep direct RMW into DTCM (the current
 *         design, which also satisfies the JIT constraint). <- first choice
 *     (b) the A55 cannot see DTCM at all -> IVARS has to move to a DDR carveout,
 *         but then bit31 is set and direct RMW from the JIT is impossible, so
 *         either **ivar access changes to go through a helper** (a codegen change)
 *         or the M7 periodically dumps the ivars into the ring.
 *   TODO (real hardware / reference manual): establish whether i.MX95 has an alias
 *     through which the A55 can see the M7's DTCM, and at what address, then pick
 *     (a) or (b). Until that is settled AMP_IVARS_A55_ALIAS stays undefined.
 */
#define AMP_IVARS_SIZE  0x00000100u    /* 256 B (>= the @ivar set of one probe; the checker range-checks it) */
#define AMP_IVARS_BASE  0x2003FF00u    /* = DTCM top - 256B (0x20040000 - 0x100) */

/* ======================================================================== *
 *  A55-facing ABI  (the firmware<->A55 contract. irrelevant to the blob)    *
 * ======================================================================== */

/* Base of the shared DDR SPSC event ring (M7 producer / A55 mmap consumer).
 * The ring control block, record format and version gate are in spnl/amp_ring.h
 * (AMP_RING_MAGIC / AMP_RING_VERSION). Because this is outside the blob ABI,
 * moving it from the borrowed address (0x88400000) to a dedicated carveout does
 * not require re-AOT'ing any blob.
 *
 * Currently it borrows space in the openamp shmem at 0x88400000 (inside the grant
 * 0x88000000..0x88500000, kept 4 MiB away from the vrings; matches
 * examples/amp_m7_firmware).
 * TODO (board bring-up): move it to a dedicated carveout at 0x8830_0000 declared
 * in the system-manager config / device tree.
 */
#define AMP_RING_BASE   0x88400000u

/* blob staging (A55 -> M7). The A55 writes a `struct amp_blob_staging` header
 * followed by the blob bytes into a **fixed staging region** of shared memory,
 * and the M7 loader reads it at boot (remoteproc restart). This is what lets the
 * **firmware be built and fixed before any probe exists**, so the blob is
 * replaceable rather than embedded in the firmware. (Swapping without a restart
 * is the cmd ring below.)
 *
 * Placement: inside the openamp shmem grant (0x88000000..0x88500000), past the
 * event ring (0x88400000). The vrings/rsc_table sit low in the grant
 * (rsc_table=0x88220000) and the ring is 4 MiB in, so 0x8842_0000 is safely clear
 * of both the ring (a few KiB) and the vrings. Like the ring, it is accessed by
 * raw physical address (no DT node needed), the same way amp_producer.c reaches
 * the ring.
 * TODO (board bring-up): when the ring moves to a dedicated carveout, move the
 * staging region with it. */
#define AMP_STAGING_BASE   0x88420000u
#define AMP_STAGING_SIZE   0x1000u        /* 4 KiB: header + blob (<= AMP_BLOB_MAX 512B) */
#define AMP_STAGING_MAGIC  0x42504D41u    /* 'A''M''P''B' (LE): amp blob staging */
#define AMP_BLOB_MAX       512u           /* maximum blob size (staging / exec slot) */

/* staging small header (written by the A55, validated by the M7 loader). The blob
 * bytes follow immediately after it. */
struct amp_blob_staging {
	uint32_t magic;        /* == AMP_STAGING_MAGIC (invalid = no blob loaded) */
	uint32_t abi_version;  /* == AMP_ABI_VERSION (the loader rejects a mismatch loudly) */
	uint32_t length;       /* blob size in bytes (<= AMP_BLOB_MAX) */
	uint32_t ivars_size;   /* the manifest's amp_ivars_size (the loader zeroes IVARS to this width) */
	/* uint8_t blob[length] continues from here */
};

/* cmd ring (A55 -> M7): runtime commands while the M7 is running (distributing a
 * blob for hot swap / tearing one down). The analogue of a BPF user_ringbuf, with
 * the A55 as producer and the M7 as consumer. The M7 loader drains it each tick;
 * INSTALL writes into the inactive one of the A/B slots and then flips which is
 * active, so the swap happens without stopping.
 * The blob is inline in the record (<= AMP_BLOB_MAX). It is placed just past the
 * staging region (0x88420000).
 * Decoupled verification: the A55 runs amp_check before pushing, and the M7 loader
 * gates on magic/abi_version/length -- defence on both sides. */
#define AMP_CMD_RING_BASE  0x88430000u
#define AMP_CMD_RING_SIZE  0x1000u         /* control + AMP_CMD_RING_CAP records */

/* Progress word (M7 -> A55 debug): the runtime writes a step code here +
 * flushes at each hot-swap step, so the A55 can read (devmem2) where the M7 last
 * reached WITHOUT the M7 console (unreachable from the host). Observability, not a
 * data-plane contract. Step table = AMP_STEP_* below. */
#define AMP_PROGRESS_BASE  0x88431000u     /* shmem, just past the cmd ring */
enum amp_step {
	AMP_STEP_TICK        = 10,   /* amp_tick entry */
	AMP_STEP_POLL        = 20,   /* amp_m7_poll_cmd entry */
	AMP_STEP_CMD_MAGIC   = 25,   /* cmd ring magic OK */
	AMP_STEP_CMD_FOUND   = 30,   /* a command is pending */
	AMP_STEP_PRE_INSTALL = 40,   /* about to install_to_slot */
	AMP_STEP_PRE_WINDOW  = 45,   /* about to open the ITCM write-window (MPU off) */
	AMP_STEP_IN_WINDOW   = 50,   /* MPU disabled, inside the window */
	AMP_STEP_POST_IVARS  = 55,   /* IVARS zeroed */
	AMP_STEP_POST_MEMCPY = 60,   /* blob copied into the slot */
	AMP_STEP_POST_ICACHE = 65,   /* I-cache invalidated (if present) */
	AMP_STEP_POST_WINDOW = 70,   /* MPU restored, window closed */
	AMP_STEP_POST_FLIP   = 80,   /* active slot flipped */
	AMP_STEP_RUN         = 90,   /* about to run the active blob */
	AMP_STEP_RUN_DONE    = 95,   /* blob returned */
	AMP_STEP_TICK_DONE   = 100,  /* amp_tick exit */
};
#define AMP_CMD_RING_MAGIC 0x444D4341u     /* 'A''C''M''D' (LE) */
#define AMP_CMD_RING_CAP   2u

enum amp_cmd_type {
	AMP_CMD_NONE = 0,
	AMP_CMD_INSTALL = 1,   /* install blob[] into the inactive A/B slot, flip active */
	AMP_CMD_TEARDOWN = 2,  /* deactivate (stop emit) + zero IVARS (traceless removal) */
};

struct amp_cmd_rec {
	uint32_t type;         /* enum amp_cmd_type */
	uint32_t abi_version;  /* == AMP_ABI_VERSION (loader gate) */
	uint32_t length;       /* blob bytes (INSTALL; <= AMP_BLOB_MAX) */
	uint32_t ivars_size;   /* per-install IVARS zeroing width */
	uint8_t  blob[AMP_BLOB_MAX];
};

struct amp_cmd_ring {
	uint32_t magic;        /* AMP_CMD_RING_MAGIC */
	uint32_t version;
	uint32_t capacity;
	uint32_t rec_size;     /* sizeof(struct amp_cmd_rec) */
	volatile uint32_t prod;  /* A55 producer index */
	volatile uint32_t cons;  /* M7 consumer index */
	uint32_t _pad[2];
	/* struct amp_cmd_rec recs[capacity] follows immediately */
};

static inline struct amp_cmd_rec *amp_cmd_ring_recs(struct amp_cmd_ring *r) {
	return (struct amp_cmd_rec *)((char *)r + sizeof(struct amp_cmd_ring));
}

/* M7 inits the cmd ring at boot (fresh); the A55 syncs on the magic before pushing. */
static inline void amp_cmd_ring_init(struct amp_cmd_ring *r) {
	r->version = 1;
	r->capacity = AMP_CMD_RING_CAP;
	r->rec_size = (uint32_t)sizeof(struct amp_cmd_rec);
	r->prod = 0;
	r->cons = 0;
	r->_pad[0] = r->_pad[1] = 0;
	r->magic = AMP_CMD_RING_MAGIC;   /* publish last */
}

/* A55 producer: push one command (returns 1 on success, 0 if the ring is full). */
static inline int amp_cmd_ring_push(struct amp_cmd_ring *r, const struct amp_cmd_rec *rec) {
	if (r->magic != AMP_CMD_RING_MAGIC) return 0;
	uint32_t prod = r->prod, cons = r->cons;
	if (prod - cons >= r->capacity) return 0;   /* full */
	amp_cmd_ring_recs(r)[prod % r->capacity] = *rec;
	r->prod = prod + 1;                          /* publish */
	return 1;
}

/* The **system-bus alias** through which the A55 would read the M7's DTCM ivars
 * (branch (a) of the IVARS decision tree above).
 * TODO: **deliberately left undefined** until it is confirmed against real
 *   hardware / the reference manual. Once confirmed:
 *   #define AMP_IVARS_A55_ALIAS  0x????????u   (= AMP_IVARS_BASE as the A55 sees it)
 * If branch (b) is taken instead, this macro is not needed at all (IVARS then
 * lives in DDR or is reached through a helper).
 */
/* #define AMP_IVARS_A55_ALIAS  0x00000000u */  /* TODO: not yet determined */

#endif /* SPNL_AMP_ABI_IMX95M7_H */
