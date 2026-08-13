#!/bin/sh
# Encode ../tests/payload_logs.textproto into its .bin wire form.
# Encoded with protoc against the opentelemetry-proto schemas. Fetch those
# first with `SPNL_WITH_PROTO=1 scripts/setup.sh` (repo root); run this inside
# the Linux build environment.
set -e
base="$(cd "$(dirname "$0")/.." && pwd)"
proto_root="$base/../../deps/opentelemetry-proto"
command -v protoc >/dev/null || { echo "gen-test-payload: protoc not found (apt-get install protobuf-compiler)" >&2; exit 1; }
protoc --encode=opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest \
  -I "$proto_root" \
  "$proto_root/opentelemetry/proto/collector/logs/v1/logs_service.proto" \
  < "$base/tests/payload_logs.textproto" \
  > "$base/tests/payload_logs.bin"
wc -c "$base/tests/payload_logs.bin"
