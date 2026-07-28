# amp_m7_firmware -- amp-m7 firmware (Zephyr, FRDM-IMX95)

A minimal Zephyr M7 firmware that links the **reusable fixed-ABI runtime**
(`src/runtime/amp/amp_m7_runtime.{c,h}` = libamp_m7) and **receives probes through
a staging region**. The firmware is **built once, independently of any probe**;
the A55 places a single-pass blob in the shared-memory staging area
(`AMP_STAGING_BASE`) and a remoteproc restart makes the M7 loader read it, so the
**firmware stays fixed while the blob is swapped**. `src/amp_firmware.c` starts
the runtime with SYS_INIT and runs the installed blob from a 1 Hz timer. The
runtime owns the helper table (literal-jump), the ring producer (`amp_ring.h` +
cache flush) and the blob loader (abi_version gate + IVARS zeroing). It is built
on openamp's `samples/subsys/ipc/openamp_rsc_table`, which gives a known-good boot
plus a resource_table -- that combination is what avoids the FCCU fault loop
(`main_remote.c` is taken verbatim). On the A55 side, `a55_stage.c` places the
blob and `a55_drain.c` reads the ring.

- **Fixed ABI** (`include/spnl/amp_abi_imx95m7.h`): helper table = ITCM top
  `0x0003FF00`, IVARS = DTCM top `0x2003FF00`, ring = `0x88400000`, staging =
  `0x88420000`. The tops of ITCM and DTCM are reserved in the board overlay (by
  shrinking `&itcm`/`&dtcm` and declaring a memory-region).
- **MPU/XN**: on imx95 the M7 builds with `CONFIG_ARM_MPU=y` / `CONFIG_XIP=y`,
  giving ITCM=RX and DTCM=RW+XN. The runtime writes the helper table and copies
  the blob inside a **window where the MPU is temporarily disabled** at boot, and
  runs with ITCM=RX afterwards (the method is described in the comment at the top
  of `amp_m7_runtime.c`). **Confirming MPU/XN behaviour on real hardware is still
  outstanding.**
- The earlier two-pass approach (`src/amp_producer.c` + `build-amp-blob.sh`, which
  embedded the blob into the firmware) is kept on disk for reference but is not
  linked by CMakeLists. The staging approach above is the current one.

## Build (Mac / Zephyr workspace)

```bash
cd ~/sdk/zephyrproject && source .venv/bin/activate
export ZEPHYR_BASE=$PWD/zephyr ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
       ZEPHYR_SDK_INSTALL_DIR=$HOME/sdk/zephyr-sdk-1.0.1
west build -p always -b imx95_evk/mimx9596/m7 \
    ~/projects/spinel-ebpf/examples/amp_m7_firmware -d /tmp/amp-m7
# artifact: /tmp/amp-m7/zephyr/zephyr.elf (with .resource_table built in)
```

## Load (A55 remoteproc, assuming the M7 is off)

Every command from here on talks to the board over ssh as root. Set its address
once:

```bash
export BOARD=<board-ip>
```

```bash
scp /tmp/amp-m7/zephyr/zephyr.elf root@$BOARD:/lib/firmware/amp-m7.elf
ssh root@$BOARD '
  RP=/sys/class/remoteproc/remoteproc1
  echo stop > $RP/state 2>/dev/null; sleep 1
  echo amp-m7.elf > $RP/firmware
  echo start > $RP/state; sleep 4
  cat $RP/state'                       # => running
# liveness from the system manager: `lm info`  => 001: M7 = on
```

## Check (read the shared ring from the A55)

```bash
# quick: watch the prod index (0x88400010) increase with devmem2
ssh root@$BOARD 'for i in 1 2 3; do devmem2 0x88400010 w; sleep 1; done'

# properly: build + run the drain tool on the board
scp a55_drain.c root@$BOARD:/tmp/; scp -r ../../include root@$BOARD:/tmp/
ssh root@$BOARD 'gcc -O2 -I/tmp/include /tmp/a55_drain.c -o /tmp/a55_drain && /tmp/a55_drain'
# => [a55_drain] rec #0: value=1 ... / #1: value=2 ... streaming at 1 Hz
```

## Teardown

```bash
ssh root@$BOARD 'echo stop > /sys/class/remoteproc/remoteproc1/state'
```

## Pitfalls (from working notes on this board)

- **A resource_table is mandatory**: without one, start is immediately followed by
  an FCCU fault, the system manager resets LM1, and it loops. This firmware is
  openamp-based, so it has one built in.
- **The firmware name must be given explicitly** (`echo amp-m7.elf > .../firmware`).
  Letting it search for a default name fails.
- **The M7 console (LPUART3, ser2net port 7895)** can be silent depending on clock
  state. Judge liveness from `lm info`, the remoteproc `state`, or the shared
  ring's prod index instead -- none of which depend on RPMsg being up.
- If the system manager auto-booted the flash demo after a cold boot and
  remoteproc shows `attached`, run `lm 1 shutdown` on the system manager, then
  unbind/bind, then firmware/start.
