# SPDX-License-Identifier: Apache-2.0
#
# amp_m7_firmware -- minimal amp-m7 firmware.
# Based on Zephyr's samples/subsys/ipc/openamp_rsc_table (known-good boot +
# resource_table, avoids the FCCU crash-loop), plus src/amp_producer.c which
# writes the shared DDR ring (spnl/amp_ring.h) on a 1 Hz timer.
#
# build:
#   cd ~/sdk/zephyrproject && source .venv/bin/activate
#   export ZEPHYR_BASE=$PWD/zephyr ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
#          ZEPHYR_SDK_INSTALL_DIR=$HOME/sdk/zephyr-sdk-1.0.1
#   west build -p always -b imx95_evk/mimx9596/m7 \
#       ~/projects/spinel-ebpf/examples/amp_m7_firmware -d /tmp/amp-m7

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(amp_m7_firmware)

target_include_directories(app PRIVATE
	${LIBMETAL_INCLUDE_DIR} ${OPENAMP_INCLUDE_DIR} ${PLATFORM_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/../../include        # spnl/amp_ring.h, spnl/amp_abi_imx95m7.h
	${CMAKE_CURRENT_SOURCE_DIR}/../../src/runtime/amp)  # amp_m7_runtime.h

target_sources(app PRIVATE
	src/main_remote.c      # openamp base (resource_table + boot), verbatim
	src/amp_firmware.c     # fixed-ABI runtime glue (SYS_INIT + 1 Hz timer)
	${CMAKE_CURRENT_SOURCE_DIR}/../../src/runtime/amp/amp_m7_runtime.c)  # libamp_m7
# (The older 2-pass reference amp_producer.c + build-amp-blob.sh are kept on disk, unwired.)
