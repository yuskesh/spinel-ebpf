#!/usr/bin/env bash
# run_otlp_k8s.sh -- verifies cgroup_id -> k8s pod resolution and the resulting
# k8s.* span attributes.
#  (1) unit test of the resolution logic, on data captured from a real k3s VM
#      (cgroup_id 674 -> coredns, 592 -> local-path)
#  (2) attaches k8s.* to a file-audit span and confirms with protoc --decode that
#      the real pod name reaches the wire
# No libbpf dependency -- this is the span-builder path, so it runs on a host.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tests/runtime/otlp_common.sh"

CC="${CC:-clang}"
NANOPB="$REPO_ROOT/third_party/nanopb"
PB="$REPO_ROOT/src/runtime/otlp/pb"
OTLP="$REPO_ROOT/src/runtime/otlp"
PROTO_ROOT="${PROTO_ROOT:-$REPO_ROOT/third_party/opentelemetry-proto}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[k8s] (1) unit test: cgroup_id -> pod resolution"
"$CC" -O2 -Wall -Wextra -I "$OTLP" \
  tests/runtime/otlp_k8s_test.c "$OTLP/otlp_k8s.c" -o "$TMP/k8s"
"$TMP/k8s"

echo "[k8s] (2) attach k8s.* to an audit span, encode as OTLP protobuf, decode the wire"
PB_C=$(find "$PB/opentelemetry" -name '*.pb.c' | sort)
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -I "$NANOPB" -I "$PB" -I "$OTLP" \
  tests/runtime/otlp_k8s_span_test.c \
  "$OTLP/otlp_k8s.c" "$OTLP/otlp_traces.c" "$OTLP/otlp_json.c" "$OTLP/otlp_http.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" $PB_C -lz -o "$TMP/span"
"$TMP/span" > "$TMP/span.pb"
echo "  span protobuf bytes: $(wc -c < "$TMP/span.pb")"

otlp_decode "opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest" \
  "opentelemetry/proto/collector/trace/v1/trace_service.proto" "$TMP/span.pb" "$TMP/span.txt"
echo "----- wire-decoded span (protoc) -----"; sed -n '1,120p' "$TMP/span.txt"; echo "--------------------------------------"

# semconv k8s.* reaches the wire carrying the real pod name
otlp_assert "$TMP/span.txt" 'key: "k8s.pod.name"'
otlp_assert "$TMP/span.txt" 'string_value: "coredns-ccb96694c-5kpb7"'
otlp_assert "$TMP/span.txt" 'key: "k8s.namespace.name"'
otlp_assert "$TMP/span.txt" 'string_value: "kube-system"'
otlp_assert "$TMP/span.txt" 'key: "k8s.pod.uid"'
otlp_assert "$TMP/span.txt" 'key: "k8s.container.name"'
# the pre-existing audit attributes coexist (file audit plus the deny verdict)
otlp_assert "$TMP/span.txt" 'key: "file.path"'
otlp_assert "$TMP/span.txt" 'string_value: "/etc/shadow"'
otlp_assert "$TMP/span.txt" 'key: "process.executable.name"'
otlp_assert "$TMP/span.txt" 'key: "verdict"'

otlp_done "k8s pod correlation span (k8s.pod.name=coredns rides the wire)"
