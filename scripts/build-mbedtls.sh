#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build the mbedTLS static libraries that the OTLP exporter links when the
# endpoint is https:// or grpcs://.
#
# Produces libmbedtls.a, libmbedx509.a and libmbedcrypto.a in
# deps/mbedtls/library/. These are platform-specific object files, so they are
# never committed -- build them in each environment you compile probes in.
#
# scripts/setup.sh runs this for you when SPNL_WITH_TLS=1. Run it directly if
# you fetched mbedTLS yourself, or to rebuild after switching architectures.
#
#   MBEDTLS_DIR  checkout location (default <repo>/deps/mbedtls)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MBED="${MBEDTLS_DIR:-$REPO_ROOT/deps/mbedtls}"

if [ ! -f "$MBED/Makefile" ]; then
  echo "error: no mbedTLS checkout at $MBED" >&2
  echo "       fetch it with:  SPNL_WITH_TLS=1 scripts/setup.sh" >&2
  echo "       (or point MBEDTLS_DIR at an existing checkout)" >&2
  exit 1
fi

# One checkout can be shared between a host and a container of a different
# architecture (a bind mount, say). Object files from the other architecture
# would fail to link, so rebuild from clean whenever the architecture changes.
# Re-running for the same architecture stays incremental, and fast.
ARCH="$(uname -s)-$(uname -m)"
mkdir -p "$REPO_ROOT/build"
STAMP="$REPO_ROOT/build/.mbedtls_arch"   # kept outside the checkout; build/ is gitignored
if [ -f "$STAMP" ] && [ "$(cat "$STAMP" 2>/dev/null)" != "$ARCH" ]; then
  echo "[build-mbedtls] architecture changed ($(cat "$STAMP") -> $ARCH): make clean"
  make -C "$MBED" clean >/dev/null 2>&1 || true
fi

J="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
echo "[build-mbedtls] building static libraries for $ARCH (-j$J)"
make -C "$MBED" lib -j"$J" CFLAGS="-O2"
echo "$ARCH" > "$STAMP"

echo "[build-mbedtls] done:"
ls -1 "$MBED/library"/libmbed*.a
