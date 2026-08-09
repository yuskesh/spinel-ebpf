#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One-shot setup: fetch + build the spinel compiler that spinel-ebpf depends on
# (the patched fork) into deps/spinel. After this, bin/spinel-ebpf works
# out of the box -- its default SPINEL_DIR is deps/spinel.
#
# Run from anywhere, inside a Linux build environment (e.g. debian:trixie) that
# has cc, make, ruby, git and curl:
#
#   scripts/setup.sh
#
# Not on a macOS host directly. There, mount the repo into a container and give
# the VM enough memory -- Apple `container` defaults to 1 GB, which OOM-kills
# the parallel compiler jobs ("cc: fatal error: Killed signal ..."):
#
#   container run --rm --memory 8g --volume "$PWD:/work" --workdir /work \
#     docker.io/library/debian:trixie sh -c 'scripts/setup.sh'
#
# Produces, under deps/spinel:
#   bin/spinel              the compiler (used for --dump-ast and the --ir mode)
#   build/csrc/*.o          compiler objects the in-process eBPF codegen links
#   build/libprism.a        the prism parser library
#
# Optionally also fetches and builds mbedTLS into deps/mbedtls, which is only
# needed to send telemetry over TLS (an https:// or grpcs:// OTLP endpoint). It
# is off by default: a probe that posts to a plain http:// collector never links
# mbedTLS, so most users do not need the ~50 MB checkout.
#
#   SPNL_WITH_TLS=1 scripts/setup.sh
#
# Optionally also fetches the OTLP protobuf schemas and the nanopb generator,
# which nothing in normal use needs. The protobuf *encoders* are already here,
# pre-generated under src/runtime/otlp/pb/ and committed, so building a probe and
# sending telemetry needs neither checkout. They are for the two jobs that read
# or rebuild that wire format: the harnesses under tests/runtime/ that decode a
# payload back into text with protoc, and scripts/regen-otlp-pb.sh.
#
#   SPNL_WITH_PROTO=1 scripts/setup.sh
#
# Tunables (environment variables):
#   SPINEL_REPO   git URL of the fork     (default https://github.com/yuskesh/spinel.git)
#   SPINEL_REF    branch / tag / commit   (default: a tag on c-emit-ir = upstream + Patch 1)
#   SPINEL_DIR    checkout location       (default <repo>/deps/spinel)
#   SPNL_WITH_TLS set to 1 to also fetch + build mbedTLS (default: off)
#   MBEDTLS_REPO  git URL                 (default https://github.com/Mbed-TLS/mbedtls.git)
#   MBEDTLS_REF   tag / branch / commit   (default v3.6.6, an LTS release)
#   MBEDTLS_DIR   checkout location       (default <repo>/deps/mbedtls)
#   SPNL_WITH_PROTO set to 1 to also fetch opentelemetry-proto + nanopb (default: off)
#   SPNL_WITH_AMP   set to 1 to also fetch the micro-bpf VM (default: off)
#   PROTO_REPO    git URL                 (default https://github.com/open-telemetry/opentelemetry-proto.git)
#   PROTO_REF     tag / branch / commit   (default v1.10.0, the pin the encoders were generated from)
#   PROTO_DIR     checkout location       (default <repo>/deps/opentelemetry-proto)
#   NANOPB_REPO   git URL                 (default https://github.com/nanopb/nanopb.git)
#   NANOPB_REF    tag / branch / commit   (default 0.4.9.1, matching the vendored runtime)
#   NANOPB_DIR    checkout location       (default <repo>/deps/nanopb)
#   UBPF_REPO     git URL                 (default https://github.com/SzymonKubica/rbpf-for-microcontrollers.git)
#   UBPF_REF      tag / branch / commit   (default 84ecb5b, the pin the driver was built against)
#   UBPF_DIR      checkout location       (default <repo>/tools/rbpf-for-microcontrollers)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SPINEL_REPO="${SPINEL_REPO:-https://github.com/yuskesh/spinel.git}"
SPINEL_REF="${SPINEL_REF:-spinel-ebpf-base-2026.08.02}"
SPINEL_DIR="${SPINEL_DIR:-$HERE/deps/spinel}"
MBEDTLS_REPO="${MBEDTLS_REPO:-https://github.com/Mbed-TLS/mbedtls.git}"
MBEDTLS_REF="${MBEDTLS_REF:-v3.6.6}"
MBEDTLS_DIR="${MBEDTLS_DIR:-$HERE/deps/mbedtls}"
PROTO_REPO="${PROTO_REPO:-https://github.com/open-telemetry/opentelemetry-proto.git}"
PROTO_REF="${PROTO_REF:-v1.10.0}"
PROTO_DIR="${PROTO_DIR:-$HERE/deps/opentelemetry-proto}"
NANOPB_REPO="${NANOPB_REPO:-https://github.com/nanopb/nanopb.git}"
NANOPB_REF="${NANOPB_REF:-0.4.9.1}"
NANOPB_DIR="${NANOPB_DIR:-$HERE/deps/nanopb}"
UBPF_REPO="${UBPF_REPO:-https://github.com/SzymonKubica/rbpf-for-microcontrollers.git}"
UBPF_REF="${UBPF_REF:-84ecb5b}"
UBPF_DIR="${UBPF_DIR:-$HERE/tools/rbpf-for-microcontrollers}"

echo ">>> spinel: $SPINEL_REPO @ $SPINEL_REF"
echo ">>> into:   $SPINEL_DIR"

# Bootstrap build prerequisites on Debian/Ubuntu when running as root (the
# expected build container). Skipped for non-root (CI runners / dev machines
# already have the tools); the check below enforces them either way.
if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  apt-get install -y -qq --no-install-recommends \
    build-essential ruby git curl ca-certificates >/dev/null || true
fi

for tool in cc make ruby git curl; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "!!! missing required tool: $tool (install it, e.g. apt-get install $tool)"; exit 1; }
done

# 1. Clone (first run) or fetch (subsequent runs), then pin to SPINEL_REF.
if [ ! -d "$SPINEL_DIR/.git" ]; then
  mkdir -p "$(dirname "$SPINEL_DIR")"
  git clone "$SPINEL_REPO" "$SPINEL_DIR"
else
  git -C "$SPINEL_DIR" remote set-url origin "$SPINEL_REPO"
  git -C "$SPINEL_DIR" fetch --tags origin
fi
git -C "$SPINEL_DIR" checkout -q "$SPINEL_REF"
# If SPINEL_REF is a branch, fast-forward to its remote tip (no-op for a commit/tag).
git -C "$SPINEL_DIR" merge --ff-only "origin/$SPINEL_REF" 2>/dev/null || true
echo ">>> checked out $(git -C "$SPINEL_DIR" rev-parse --short HEAD)"

# 2. Build: make deps fetches vendor/prism + vendor/rbs, make builds the compiler.
make -C "$SPINEL_DIR" deps
make -C "$SPINEL_DIR"

# 3. Verify the artifacts bin/spinel-ebpf needs are present.
bin="$SPINEL_DIR/bin/spinel"
lib="$SPINEL_DIR/build/libprism.a"
objs=$(ls "$SPINEL_DIR"/build/csrc/*.o 2>/dev/null | grep -v '/main\.o$' | wc -l | tr -d ' ')
[ -x "$bin" ]      || { echo "!!! missing: $bin";        exit 1; }
[ -f "$lib" ]      || { echo "!!! missing: $lib";        exit 1; }
[ "${objs:-0}" -gt 0 ] || { echo "!!! missing: build/csrc/*.o"; exit 1; }

echo ">>> OK: bin/spinel + $objs codegen objects + libprism.a"

# 4. Optional: mbedTLS, for OTLP over TLS (https:// / grpcs:// endpoints).
#    Skipped unless asked for. bin/spinel-ebpf links it only when the generated C
#    contains such an endpoint, so a plain-http setup never needs this step.
if [ "${SPNL_WITH_TLS:-0}" = "1" ]; then
  echo ">>> mbedTLS: $MBEDTLS_REPO @ $MBEDTLS_REF"
  echo ">>> into:    $MBEDTLS_DIR"
  if [ ! -d "$MBEDTLS_DIR/.git" ]; then
    mkdir -p "$(dirname "$MBEDTLS_DIR")"
    # Shallow, single-tag clone: mbedTLS carries a lot of history we never read.
    # --recurse-submodules picks up the `framework` submodule the build needs.
    git clone --depth 1 --branch "$MBEDTLS_REF" \
      --recurse-submodules --shallow-submodules "$MBEDTLS_REPO" "$MBEDTLS_DIR"
  else
    git -C "$MBEDTLS_DIR" remote set-url origin "$MBEDTLS_REPO"
    git -C "$MBEDTLS_DIR" fetch --depth 1 --tags origin "$MBEDTLS_REF"
    git -C "$MBEDTLS_DIR" checkout -q FETCH_HEAD
    git -C "$MBEDTLS_DIR" submodule update --init --recursive --depth 1
  fi
  "$HERE/scripts/build-mbedtls.sh"
  tls_note=", with TLS"
else
  tls_note=""
fi

# 5. Optional: the OTLP schemas and the nanopb generator. Neither is needed to
#    build a probe or to send telemetry -- the encoders are committed. These are
#    for decoding a payload back into text (tests/runtime) and for regenerating
#    those encoders (scripts/regen-otlp-pb.sh).
if [ "${SPNL_WITH_PROTO:-0}" = "1" ]; then
  fetch_pin() {   # <repo> <ref> <dir>
    echo ">>> $(basename "$3"): $1 @ $2"
    if [ ! -d "$3/.git" ]; then
      mkdir -p "$(dirname "$3")"
      git clone --depth 1 --branch "$2" "$1" "$3"
    else
      git -C "$3" remote set-url origin "$1"
      git -C "$3" fetch --depth 1 --tags origin "$2"
      git -C "$3" checkout -q FETCH_HEAD
    fi
  }
  fetch_pin "$PROTO_REPO" "$PROTO_REF" "$PROTO_DIR"
  fetch_pin "$NANOPB_REPO" "$NANOPB_REF" "$NANOPB_DIR"
  [ -d "$PROTO_DIR/opentelemetry" ] || { echo "!!! missing: $PROTO_DIR/opentelemetry"; exit 1; }
  [ -f "$NANOPB_DIR/generator/nanopb_generator.py" ] || {
    echo "!!! missing: $NANOPB_DIR/generator/nanopb_generator.py"; exit 1; }
  echo ">>> OK: OTLP schemas + nanopb generator"
fi

# 6. Optional: the ahead-of-time compiler for the real-time-core targets
#    (--target amp-m7 / amp-m33). Only needed to turn bytecode into a Thumb blob.
#
#    **Which rbpf.** This is the micro-bpf fork, not upstream rbpf. Upstream has an
#    x86-64 JIT and a Cranelift backend and **no ARM or Thumb backend at all**; the
#    Thumb emitter these targets depend on exists only in the fork. The fork keeps
#    upstream's package metadata (name "rbpf", repository qmonnet/rbpf), so a
#    dependency listing cannot tell them apart -- hence this note rather than a
#    bare URL.
#
#    It lands in tools/ rather than deps/ because tools/amp_aot_driver names it by
#    relative path, and that driver is sixty lines of glue: it loads the bytecode,
#    runs the interpreter as an oracle, and calls the fork's JIT on the build host
#    so the result is ahead-of-time rather than on-device. The real-time core then
#    carries no VM and no JIT.
if [ "${SPNL_WITH_AMP:-0}" = "1" ]; then
  echo ">>> micro-bpf VM: $UBPF_REPO @ $UBPF_REF"
  if [ ! -d "$UBPF_DIR/.git" ]; then
    mkdir -p "$(dirname "$UBPF_DIR")"
    git clone "$UBPF_REPO" "$UBPF_DIR"
    git -C "$UBPF_DIR" checkout -q "$UBPF_REF"
  else
    git -C "$UBPF_DIR" remote set-url origin "$UBPF_REPO"
    git -C "$UBPF_DIR" fetch origin
    git -C "$UBPF_DIR" checkout -q "$UBPF_REF"
  fi
  [ -f "$UBPF_DIR/src/jit_thumbv7em.rs" ] || {
    echo "!!! missing: $UBPF_DIR/src/jit_thumbv7em.rs"
    echo "!!! That file is the Thumb emitter, and its absence means this checkout is"
    echo "!!! upstream rbpf rather than the micro-bpf fork. The amp targets cannot"
    echo "!!! produce a blob without it."
    exit 1; }
  echo ">>> OK: micro-bpf VM. Build the driver with: (cd tools/amp_aot_driver && cargo build --release)"
fi

echo ">>> spinel-ebpf is ready$tls_note. Try: bin/spinel-ebpf compile <file>.rb --build"
[ "${SPNL_WITH_TLS:-0}" = "1" ] ||
  echo ">>> (TLS is off. For an https:// or grpcs:// OTLP endpoint, re-run with SPNL_WITH_TLS=1.)"
[ "${SPNL_WITH_PROTO:-0}" = "1" ] ||
  echo ">>> (OTLP schemas are off. To decode telemetry in tests/runtime, re-run with SPNL_WITH_PROTO=1.)"
[ "${SPNL_WITH_AMP:-0}" = "1" ] ||
  echo ">>> (The real-time-core compiler is off. For --target amp-m7 or amp-m33, re-run with SPNL_WITH_AMP=1.)"
