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
# Produces, under deps/spinel:
#   bin/spinel              the compiler (used for --dump-ast and the --ir mode)
#   build/csrc/*.o          compiler objects the in-process eBPF codegen links
#   build/libprism.a        the prism parser library
#
# Tunables (environment variables):
#   SPINEL_REPO  git URL of the fork     (default https://github.com/yuskesh/spinel.git)
#   SPINEL_REF   branch / tag / commit   (default: a tag on c-emit-ir = upstream + Patch 1)
#   SPINEL_DIR   checkout location       (default <repo>/deps/spinel)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SPINEL_REPO="${SPINEL_REPO:-https://github.com/yuskesh/spinel.git}"
SPINEL_REF="${SPINEL_REF:-spinel-ebpf-base-2026.06.23}"
SPINEL_DIR="${SPINEL_DIR:-$HERE/deps/spinel}"

echo ">>> spinel: $SPINEL_REPO @ $SPINEL_REF"
echo ">>> into:   $SPINEL_DIR"

# Bootstrap build prerequisites on Debian/Ubuntu (the expected build container).
# Harmless if already present; skipped on other distros (the check below still
# enforces them).
if command -v apt-get >/dev/null 2>&1; then
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
echo ">>> spinel-ebpf is ready. Try: bin/spinel-ebpf compile <file>.rb --build"
