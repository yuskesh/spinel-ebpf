#!/usr/bin/env bash
#
# run_otlp_traces.sh -- span assembly and the conversion to OTLP traces.
#
# otlp_traces_test asserts the tree structure at the C level and emits the OTLP
# bytes. Those are then run through `protoc --decode` to check the span names,
# parent_span_id, the code.* attributes and service.name.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PROTO_ROOT="$REPO_ROOT/third_party/opentelemetry-proto"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)

echo "[traces] compiling traces test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_traces_test.c \
  "$OTLP/otlp_traces.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -o "$TMP/otlp_traces"

echo "[traces] assembling + encoding -> $TMP/out.pb"
"$TMP/otlp_traces" "$TMP/out.pb"

echo "[traces] decoding with protoc"
"$PROTOC" --decode=opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest \
  -I "$PROTO_ROOT" \
  opentelemetry/proto/collector/trace/v1/trace_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"

echo "----- decoded -----"; cat "$TMP/decoded.txt"; echo "-------------------"

echo "[traces] asserting span tree round-tripped"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
count()  { otlp_count  "$TMP/decoded.txt" "$1" "$2"; }
assert 'name: "driver"'
assert 'name: "add"'
assert 'name: "square"'
assert 'kind: SPAN_KIND_INTERNAL'
assert 'parent_span_id:'
assert 'key: "code.function"'
assert 'string_value: "spinel-app"'
count 'name: "driver"' 1
count 'parent_span_id:' 2

otlp_done "method call tree -> OTLP spans (parent-linked, single trace)"
