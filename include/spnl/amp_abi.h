/* SPDX-License-Identifier: GPL-2.0
 *
 * spnl/amp_abi.h -- selects a board profile, and does nothing else.
 *
 * What is here is one choice: which board's fixed ABI to read. **None of the ABI
 * itself is written here.** That is the point.
 *
 * The claim this file exists to protect is that vendor dependence is confined to
 * two places -- the fixed ABI address values, and the Zephyr board overlay --
 * while the code generator, the real-time-core runtime and the application-core
 * drain go across unchanged. A claim like that is only worth something if it can
 * fail visibly, so the conditional is kept in this one file and everything else
 * writes `#include "spnl/amp_abi.h"`. The runtime, the checker, the drain and the
 * staging tools do not know that boards exist.
 *
 * "Isn't a selecting #ifdef still an #ifdef?" Yes, and there is no point
 * pretending otherwise. The distinction being drawn is about *where* it lives:
 * this is a choice of which set of address values to read, not a branch in any
 * logic. The day a runtime function needs a per-board path, that is a real
 * weakening of the claim and belongs in the record rather than hidden behind a
 * conditional here.
 *
 * The default is the first board that was brought up. Keeping it the default
 * means an existing build that names no board produces byte-for-byte the same
 * output it did before this file existed -- which is the regression check that
 * makes adding a second board safe.
 */
#ifndef SPNL_AMP_ABI_H
#define SPNL_AMP_ABI_H

#if defined(SPNL_AMP_BOARD_STM32MP2M33)
#  include "spnl/amp_abi_stm32mp2m33.h"
#elif defined(SPNL_AMP_BOARD_IMX95M7) || !defined(SPNL_AMP_BOARD)
#  include "spnl/amp_abi_imx95m7.h"
#else
#  error "spnl/amp_abi.h: unknown AMP board profile -- define SPNL_AMP_BOARD_IMX95M7 or SPNL_AMP_BOARD_STM32MP2M33"
#endif

#endif /* SPNL_AMP_ABI_H */
