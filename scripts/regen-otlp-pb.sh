#!/usr/bin/env bash
#
# regen-otlp-pb.sh -- regenerate the nanopb C encoders for the OTLP protobufs.
#
# Runs nanopb over the .proto files of opentelemetry-proto and writes the
# resulting *.pb.{c,h} into src/runtime/otlp/pb/. Those outputs are committed:
# they are portable, and regenerating them is reproducible.
#
# A host protoc and whatever python-protobuf happens to be installed tend to
# disagree on major version -- a Homebrew protoc 35 against a conda protobuf 6, say.
# To avoid that, this bootstraps an isolated virtualenv with grpcio-tools, which
# bundles a matched protoc and protobuf pair, and runs the vendored nanopb
# generator through it. Your own Python environment is left untouched.
#
# Needs two upstream checkouts that normal use does not: the nanopb generator
# and the OTLP .proto schemas. Get both with `SPNL_WITH_PROTO=1 scripts/setup.sh`,
# which pins nanopb 0.4.9.1 and opentelemetry-proto v1.10.0 -- the versions these
# committed encoders were generated from.
#
# Usage: sh scripts/regen-otlp-pb.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VENV="$REPO_ROOT/.venv-otlp"
PROTO_ROOT="${PROTO_DIR:-$REPO_ROOT/deps/opentelemetry-proto}"
NANOPB="${NANOPB_DIR:-$REPO_ROOT/deps/nanopb}"
GENERATOR="$NANOPB/generator/nanopb_generator.py"
OUT="$REPO_ROOT/src/runtime/otlp/pb"

# What to generate. Everything is needed, including the common and resource
# definitions the others import.
PROTOS="
opentelemetry/proto/common/v1/common.proto
opentelemetry/proto/resource/v1/resource.proto
opentelemetry/proto/metrics/v1/metrics.proto
opentelemetry/proto/trace/v1/trace.proto
opentelemetry/proto/logs/v1/logs.proto
opentelemetry/proto/collector/metrics/v1/metrics_service.proto
opentelemetry/proto/collector/trace/v1/trace_service.proto
opentelemetry/proto/collector/logs/v1/logs_service.proto
"

# Fail loud, and say the thing that actually fixes it. This repository has no
# submodules: both checkouts come from setup.sh, on demand.
if [ ! -f "$GENERATOR" ]; then
  echo "error: no nanopb generator at $GENERATOR" >&2
  echo "       fix:  SPNL_WITH_PROTO=1 scripts/setup.sh" >&2
  echo "       or:   NANOPB_DIR=<path to a nanopb checkout> sh scripts/regen-otlp-pb.sh" >&2
  exit 1
fi
if [ ! -d "$PROTO_ROOT/opentelemetry" ]; then
  echo "error: no OTLP schemas at $PROTO_ROOT" >&2
  echo "       fix:  SPNL_WITH_PROTO=1 scripts/setup.sh" >&2
  echo "       or:   PROTO_DIR=<path to an opentelemetry-proto checkout> sh scripts/regen-otlp-pb.sh" >&2
  exit 1
fi

# --- bootstrap the isolated virtualenv, idempotently ---
if [ ! -x "$VENV/bin/python" ]; then
  echo "[regen-otlp-pb] creating venv: $VENV"
  python3 -m venv "$VENV"
fi
if ! "$VENV/bin/python" -c "import grpc_tools.protoc" >/dev/null 2>&1; then
  echo "[regen-otlp-pb] installing grpcio-tools into venv"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet grpcio-tools
fi

echo "[regen-otlp-pb] protoc: $("$VENV/bin/python" -m grpc_tools.protoc --version)"
echo "[regen-otlp-pb] generating into $OUT"
rm -rf "$OUT/opentelemetry"
mkdir -p "$OUT"

# shellcheck disable=SC2086
"$VENV/bin/python" "$GENERATOR" \
  -I "$PROTO_ROOT" \
  -D "$OUT" \
  $PROTOS

echo "[regen-otlp-pb] generated files:"
find "$OUT" -name '*.pb.*' | sort | sed "s|$REPO_ROOT/||"
echo "[regen-otlp-pb] done."
