#!/usr/bin/env bash
#
# run_otlp_trace_asm.sh -- host verification of multi-span trace assembly.
#
# otlp_trace_asm_test asserts the tree structure at the C level (shared trace_id,
# parent/child link, kinds, nesting, traceparent inheritance) and writes the two
# /sleep spans out as OTLP bytes. Those are then decoded with protoc --decode to
# check the span names, parent_span_id, kinds, the single trace and service.name.
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

echo "[trace-asm] compiling trace-assembler test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror \
  -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_trace_asm_test.c \
  "$OTLP/otlp_traces.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -o "$TMP/otlp_trace_asm"

echo "[trace-asm] assembling + encoding -> $TMP/out.pb"
"$TMP/otlp_trace_asm" "$TMP/out.pb"

echo "[trace-asm] decoding with protoc"
"$PROTOC" --decode=opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest \
  -I "$PROTO_ROOT" \
  opentelemetry/proto/collector/trace/v1/trace_service.proto \
  < "$TMP/out.pb" > "$TMP/decoded.txt"

echo "----- decoded -----"; cat "$TMP/decoded.txt"; echo "-------------------"

echo "[trace-asm] asserting 2-span tree round-tripped"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"
assert() { otlp_assert "$TMP/decoded.txt" "$1"; }
count()  { otlp_count  "$TMP/decoded.txt" "$1" "$2"; }
assert 'name: "GET /sleep"'
assert 'name: "off-CPU wait (sleep)"'
assert 'kind: SPAN_KIND_SERVER'
assert 'kind: SPAN_KIND_INTERNAL'
assert 'parent_span_id:'
assert 'string_value: "spinel-e312-test"'
count 'parent_span_id:' 1     # only the child has a parent; the parent is the root
count 'trace_id:' 2           # 2 spans (parent + child): same trace_id value, printed on 2 lines

otlp_done "off-CPU record -> 2-span tree (parent SERVER + child INTERNAL, single trace)"
