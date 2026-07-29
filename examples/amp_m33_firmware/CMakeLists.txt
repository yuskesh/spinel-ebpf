# SPDX-License-Identifier: Apache-2.0
#
# amp_m33_firmware -- the STM32MP257F-DK (Cortex-M33) side of the AMP profile.
#
# The base is Zephyr's samples/subsys/ipc/openamp_rsc_table, taken verbatim, for
# the same reason the i.MX95 firmware takes it: remoteproc needs a resource table
# and that sample's boot path is known good. On this board it is known good by
# measurement -- it was built, loaded and reached `running` with its RPMsg
# endpoints live before a single line of ours was added.
#
# --- What T4 changed, and why the file list is the point ---
#
# T3 wrote its own producer (src/amp_producer.c, kept for history) that emitted a
# hand-written arithmetic series. T4 replaces it with the **fixed-ABI runtime**,
# which loads a blob the A35 stages and runs it -- so the firmware is built once
# and the probe is swapped underneath it.
#
# The runtime and the firmware glue are **not copied here**. They are compiled
# straight out of the shared tree:
#
#   ../../src/runtime/amp/amp_m7_runtime.c   (shared, unmodified)
#   ../amp_m7_firmware/src/amp_firmware.c    (shared, unmodified)
#
# The paths look odd, and that is deliberate. The claim being made is that vendor
# dependence is confined to the ABI address values and this board overlay; copying those two
# files here would make the claim unfalsifiable, because two copies drift and
# nobody notices. Compiling the *same* files, with nothing but
# -DSPNL_AMP_BOARD_STM32MP2M33 to tell them apart, means that if either ever needs
# a board conditional, this build is where it shows up. ("m7" in the names is now
# historical: the runtime is board-agnostic and only its first board is in its
# filename.)
#
# The one genuinely board-specific file added is src/amp_sram_probe.c, which
# answers a question this board raises and i.MX95 did not -- whether the M33 may
# use its own internal SRAM, where the JIT's bit31 constraint forces the ABI to
# live. It runs before the runtime, so the assumption is measured before anything
# is built on top of it.
#
# build:
#   cd ~/sdk/zephyrproject
#   export ZEPHYR_BASE=$PWD/zephyr ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
#          ZEPHYR_SDK_INSTALL_DIR=$HOME/sdk/zephyr-sdk-0.17.0
#   west build -p always -b stm32mp257f_dk/stm32mp257fxx/m33 \
#       ~/projects/spinel-ebpf/examples/amp_m33_firmware -d /tmp/amp-m33
#
# load (from the board, factory firmware backed up first):
#   scp .../zephyr.elf root@<board>:/lib/firmware/spnl_m33.elf
#   echo stop  > /sys/class/remoteproc/remoteproc0/state
#   echo spnl_m33.elf > /sys/class/remoteproc/remoteproc0/firmware
#   echo start > /sys/class/remoteproc/remoteproc0/state

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(amp_m33_firmware)

set(SPNL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

target_include_directories(app PRIVATE
	${LIBMETAL_INCLUDE_DIR} ${OPENAMP_INCLUDE_DIR} ${PLATFORM_DIR}
	${SPNL_ROOT}/include                 # spnl/amp_abi.h, spnl/amp_ring.h
	${SPNL_ROOT}/src/runtime/amp)        # amp_m7_runtime.h

# Selects which board's fixed ABI every shared file reads (spnl/amp_abi.h).
# This macro is the whole of the vendor dependence on the code side.
target_compile_definitions(app PRIVATE SPNL_AMP_BOARD_STM32MP2M33)

target_sources(app PRIVATE
	src/main_remote.c                              # openamp base, verbatim
	src/amp_sram_probe.c                           # board-specific: measures the ABI's premise
	${SPNL_ROOT}/src/runtime/amp/amp_m7_runtime.c  # shared, unmodified
	${SPNL_ROOT}/examples/amp_m7_firmware/src/amp_firmware.c)  # shared, unmodified
