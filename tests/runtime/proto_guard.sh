#!/usr/bin/env bash
# proto_guard.sh -- skip a harness that needs the opentelemetry-proto checkout.
#
# Source this right after setting PROTO_ROOT. The harnesses that decode a
# generated payload back into text do it with `protoc --decode`, which needs the
# .proto schemas -- and those are a separate upstream checkout, not something
# this repository carries. The encoders are: they live pre-generated under
# src/runtime/otlp/pb/, so building and sending telemetry needs nothing extra.
# Only reading it back does.
#
# The checkout is therefore optional, and its absence is not a failure. Skipping
# with the exact command that would provide it is the honest outcome; failing
# with "no such file" would report a missing test dependency as a broken test.
# Exported, not just set: the harnesses that decode through mock_otlp_receiver.py
# hand the job to a child process, which reads PROTO_ROOT from the environment.
export PROTO_ROOT

if [ ! -d "${PROTO_ROOT:-}/opentelemetry" ]; then
  echo "SKIP: $(basename "$0") needs the opentelemetry-proto schemas to decode"
  echo "      what it produced, and they are not at: ${PROTO_ROOT:-<unset>}"
  echo "      get them with:  SPNL_WITH_PROTO=1 scripts/setup.sh"
  echo "      or point at an existing checkout:  PROTO_ROOT=<path> $0"
  exit 0
fi

command -v "${PROTOC:-protoc}" >/dev/null 2>&1 || {
  echo "SKIP: $(basename "$0") needs protoc to decode what it produced"
  echo "      install it (e.g. apt-get install protobuf-compiler), or set PROTOC=<path>"
  exit 0
}
