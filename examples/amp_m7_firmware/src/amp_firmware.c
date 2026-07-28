/* SPDX-License-Identifier: Apache-2.0
 *
 * amp_firmware.c -- amp-m7 firmware glue (replaces amp_producer.c).
 *
 * Links the fixed-ABI runtime (src/runtime/amp/amp_m7_runtime) and runs the
 * installed blob on a 1 Hz timer. The blob is NOT embedded: the A55 stages it in
 * the shared-memory staging region (struct amp_blob_staging, spnl/amp_abi_imx95m7.h)
 * and this loader reads it at boot. => the firmware is built ONCE, probe-independent
 * ("firmware fixed, blob swapped"); a new probe only needs re-staging plus a
 * remoteproc restart, and the cmd ring can swap one in without stopping at all.
 * Cf. amp_producer.c (the older 2-pass embed), kept for history.
 *
 * Wired via SYS_INIT; main_remote.c (openamp base) stays verbatim.
 */
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include "amp_m7_runtime.h"

LOG_MODULE_REGISTER(amp_firmware, LOG_LEVEL_INF);

static void amp_tick(struct k_timer *t)
{
	ARG_UNUSED(t);
	amp_m7_progress(AMP_STEP_TICK);        /* 10: the A55 reads the last step reached */
	amp_m7_poll_cmd();   /* drain the A55->M7 cmd ring (hot swap / teardown) */
	amp_m7_run();        /* the active blob's amp_emit publishes to the shared ring */
	amp_m7_progress(AMP_STEP_TICK_DONE);   /* 100: full tick, no hang */
}

K_TIMER_DEFINE(amp_timer, amp_tick, NULL);

static int amp_firmware_init(void)
{
	int status = amp_m7_runtime_init();

	/* Always run the timer: even with no boot-staged blob, the cmd ring can
	 * INSTALL one live (hot swap). amp_m7_run() is a no-op until a blob is
	 * active. */
	k_timer_start(&amp_timer, K_SECONDS(1), K_SECONDS(1));
	if (status != AMP_LOAD_OK) {
		LOG_WRN("amp firmware: no boot blob (status=%d); waiting for a cmd-ring "
			"INSTALL (hot swap)", status);
	}
	return 0;
}
SYS_INIT(amp_firmware_init, APPLICATION, 90);
