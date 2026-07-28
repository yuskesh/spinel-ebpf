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
# pin: nanopb 0.4.9.1 / opentelemetry-proto v1.10.0 (third_party submodule)
#
# Usage: sh scripts/regen-otlp-pb.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VENV="$REPO_ROOT/.venv-otlp"
PROTO_ROOT="$REPO_ROOT/third_party/opentelemetry-proto"
NANOPB="$REPO_ROOT/third_party/nanopb"
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

if [ ! -f "$GENERATOR" ]; then
  echo "error: no nanopb generator at $GENERATOR" >&2
  echo "       git submodule update --init third_party/nanopb third_party/opentelemetry-proto" >&2
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
