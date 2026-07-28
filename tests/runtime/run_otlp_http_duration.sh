#!/usr/bin/env bash
#
# run_otlp_http_duration.sh -- verification of http.server.request.duration, in
# seconds, using the same explicit bucket boundaries the OpenTelemetry eBPF
# instrumentation uses.
# Records spans with known durations, then pushes the metrics. Confirms, over both
# protobuf and JSON, that the mock receiver recovers the explicit-bucket Histogram:
# its name, unit, explicit_bounds, the correct buckets, and the attributes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
PROTOC="${PROTOC:-protoc}"
PY="${PYTHON:-python3}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PORT="${OTLP_DUR_PORT:-18489}"
TMP="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
echo "[dur] compiling http-duration test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_http_duration_test.c \
  "$OTLP/otlp_httpspan.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C -lz -o "$TMP/dur"

start_mock() { "$PY" tests/runtime/mock_otlp_receiver.py --port "$PORT" --out "$1" \
  --protoc "$PROTOC" --repo-root "$REPO_ROOT" >"$2" 2>&1 & SRV=$!; }

echo "[dur] (1) protobuf: explicit-bounds Histogram + attributes"
start_mock "$TMP/pb.txt" "$TMP/pb.log"
"$TMP/dur" "http://127.0.0.1:$PORT"
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (protobuf) -----"; sed -n '1,80p' "$TMP/pb.txt"; echo "------------------------------"
otlp_assert "$TMP/pb.txt" 'name: "http.server.request.duration"'
otlp_assert "$TMP/pb.txt" 'unit: "s"'
otlp_assert "$TMP/pb.txt" 'explicit_bounds: 0.005'
otlp_assert "$TMP/pb.txt" 'explicit_bounds: 2.5'
otlp_assert "$TMP/pb.txt" 'count: 2'   # series A (/fast x2)
otlp_assert "$TMP/pb.txt" 'count: 1'   # series B (/slow x1)
otlp_assert "$TMP/pb.txt" 'key: "http.request.method"'
otlp_assert "$TMP/pb.txt" 'string_value: "GET"'
otlp_assert "$TMP/pb.txt" 'key: "http.route"'
otlp_assert "$TMP/pb.txt" 'string_value: "/fast"'
otlp_assert "$TMP/pb.txt" 'string_value: "/slow"'
otlp_assert "$TMP/pb.txt" 'key: "http.response.status_code"'
otlp_assert "$TMP/pb.txt" 'string_value: "200"'
otlp_assert "$TMP/pb.txt" 'aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE'

echo "[dur] (2) JSON: the counts land in the right buckets (3ms->idx1, 1.2s->idx11)"
start_mock "$TMP/json.txt" "$TMP/json.log"
OTEL_EXPORTER_OTLP_PROTOCOL=http/json "$TMP/dur" "http://127.0.0.1:$PORT"
kill "$SRV" 2>/dev/null || true; SRV=""
echo "----- decoded (json) -----"; cat "$TMP/json.txt"; echo; echo "--------------------------"
"$PY" - "$TMP/json.txt" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
m = d["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
assert m["name"] == "http.server.request.duration", m["name"]
assert m.get("unit") == "s", m.get("unit")
h = m["histogram"]
assert h["aggregationTemporality"] == 2, h["aggregationTemporality"]
dps = h["dataPoints"]
bounds = [0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10]
by_route = {}
for dp in dps:
    attrs = {a["key"]: a["value"]["stringValue"] for a in dp["attributes"]}
    by_route[attrs.get("http.route")] = dp
    # the explicit bounds match the OpenTelemetry eBPF instrumentation defaults
    assert [float(x) for x in dp["explicitBounds"]] == bounds, dp["explicitBounds"]
    # len(bucketCounts) == number of boundaries + 1
    assert len(dp["bucketCounts"]) == len(bounds) + 1, len(dp["bucketCounts"])
    assert attrs.get("http.request.method") == "GET"
    assert attrs.get("http.response.status_code") == "200"
fast = by_route["/fast"]; slow = by_route["/slow"]
# 3ms=0.003 -> (0, 0.005] = index 1; 1.2s -> (1, 2.5] = index 11
assert fast["count"] == "2", fast["count"]
assert fast["bucketCounts"][1] == "2", fast["bucketCounts"]
assert sum(int(x) for x in fast["bucketCounts"]) == 2, fast["bucketCounts"]
assert slow["count"] == "1", slow["count"]
assert slow["bucketCounts"][11] == "1", slow["bucketCounts"]
assert sum(int(x) for x in slow["bucketCounts"]) == 1, slow["bucketCounts"]
print("  ok: /fast count=2 bucket[1]=2 (3ms -> (0,0.005])")
print("  ok: /slow count=1 bucket[11]=1 (1.2s -> (1,2.5])")
print("  ok: explicitBounds match the reference defaults, len(bucketCounts) = 16, attributes method/route/status")
PYEOF

otlp_done "OTLP http.server.request.duration (seconds, reference bucket boundaries)"
