/* SPDX-License-Identifier: Apache-2.0
 *
 * amp_m7_runtime.h -- the reusable real-time-core runtime, with a fixed ABI.
 *
 * A single reusable library (NOT per-probe generated) that any amp-m7 firmware
 * links. It owns the four fixed-ABI mechanisms (spnl/amp_abi_imx95m7.h):
 *   - helper table  : literal-jump slots at AMP_HELPER_BASE, patched at
 *                     boot. id 1 = amp_emit (ring publish + cache flush),
 *                     id 2 = amp_ktime.
 *   - ivars         : @ivar carveout at AMP_IVARS_BASE (loader zeroes it per
 *                     install by the manifest's ivars_size).
 *   - ring producer : the single-producer/single-consumer ring, plus a cache flush.
 *   - blob loader   : reads a single-pass blob from the A55 staging region
 *                     (struct amp_blob_staging), gates abi_version, copies the
 *                     (position-independent) blob to an executable slot, runs it.
 *
 * Addresses default to the fixed ABI (header). QEMU sanity overrides each to SRAM
 * with -DAMP_RT_* ; the canonical values are the header. Overrides MUST match how
 * the blob was AOT'd (build-singlepass.sh helper_base + codegen default IVARS).
 */
#ifndef SPNL_AMP_M7_RUNTIME_H
#define SPNL_AMP_M7_RUNTIME_H

#include <stdint.h>
#include "spnl/amp_abi_imx95m7.h"
#include "spnl/amp_ring.h"

#ifndef AMP_RT_HELPER_BASE
#define AMP_RT_HELPER_BASE   AMP_HELPER_BASE
#endif
#ifndef AMP_RT_IVARS_BASE
#define AMP_RT_IVARS_BASE    AMP_IVARS_BASE
#endif
#ifndef AMP_RT_RING_BASE
#define AMP_RT_RING_BASE     AMP_RING_BASE
#endif
#ifndef AMP_RT_STAGING_BASE
#define AMP_RT_STAGING_BASE  AMP_STAGING_BASE
#endif
/* Blob execution slots, an A/B pair so a blob can be swapped while one runs. The position-independent
 * blob is copied into the INACTIVE slot; an atomic active-slot flip swaps it in
 * without disturbing a possibly-executing old blob. Runtime-internal (the blob
 * never references its own load address). Real board: two slots in ITCM just
 * below the helper table (executable RX after boot). */
#define AMP_BLOB_SLOTS 2u
#ifndef AMP_RT_BLOB_SLOT_BASE
#define AMP_RT_BLOB_SLOT_BASE  (AMP_RT_HELPER_BASE - AMP_BLOB_SLOTS * AMP_BLOB_MAX)
#endif
#define AMP_RT_BLOB_SLOT(i)  (AMP_RT_BLOB_SLOT_BASE + (unsigned)(i) * AMP_BLOB_MAX)
#ifndef AMP_RT_CMD_RING_BASE
#define AMP_RT_CMD_RING_BASE  AMP_CMD_RING_BASE
#endif
#ifndef AMP_RT_PROGRESS_BASE
#define AMP_RT_PROGRESS_BASE  AMP_PROGRESS_BASE
#endif
#ifndef AMP_RT_RING_CAP
#define AMP_RT_RING_CAP  256u
#endif

#define AMP_RT_HELPER_SLOT(id)  (AMP_RT_HELPER_BASE + ((unsigned)(id) - 1u) * AMP_HELPER_SLOT_BYTES)

enum amp_load_status {
	AMP_LOAD_OK = 0,
	AMP_LOAD_NO_BLOB = -1,       /* staging magic invalid: nothing staged */
	AMP_LOAD_ABI_MISMATCH = -2,  /* abi_version != AMP_ABI_VERSION (loud reject) */
	AMP_LOAD_TOO_BIG = -3,       /* length > AMP_BLOB_MAX */
};

/* Init: write the helper table, init the ring, load+validate the staged blob
 * (abi gate + IVARS zeroing + copy to exec slot). Returns enum amp_load_status. */
int amp_m7_runtime_init(void);

/* Run the active blob once (its amp_emit publishes to the ring). No-op unless a
 * blob is installed and active. */
void amp_m7_run(void);

/* Drain the command ring from the application core. INSTALL writes
 * the blob into the inactive A/B slot (MPU window), zeroes IVARS by ivars_size,
 * then atomically flips the active slot (no restart; a mid-run old blob is
 * untouched). TEARDOWN deactivates + zeroes IVARS. The M7 loader re-gates each
 * command on magic, ABI version and length; the application core has already run the checker.
 * Returns the number of commands processed. Call it before amp_m7_run() per tick. */
int amp_m7_poll_cmd(void);

/* Deactivate the active slot (stop emit) and zero IVARS. Traceless removal step
 * (also reachable via AMP_CMD_TEARDOWN). */
void amp_m7_teardown(void);

/* Write `step` (an enum amp_step) to the progress slot and flush it,
 * so the A55 can read (devmem2) where the M7 last reached without its console. The
 * runtime calls this internally through poll_cmd/install; the firmware calls it for
 * tick entry/exit. */
void amp_m7_progress(uint32_t step);

/* Helper table targets (the blob reaches these via the boot-patched table). */
uint64_t amp_emit(uint64_t value);
uint64_t amp_ktime(void);

#endif /* SPNL_AMP_M7_RUNTIME_H */
