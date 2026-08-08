#!/usr/bin/env bash
#
# run_egress_contract.sh -- the egress DECLARATION vs the span the runtime
# builds. egress_contract_test.c includes otlp_agent.c as a TU so that it can
# call the static per-channel span builders, feeds synthetic records through
# both the generated rule tables and those builders, and compares the attribute
# sets and the span's start/end.
#
# No kernel, no probe, no collector. libbpf is linked because otlp_agent.c
# drains ringbufs (never called here) => runs in the container.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
OTLP="$REPO_ROOT/src/runtime/otlp"
NANOPB="$REPO_ROOT/src/runtime/otlp/nanopb"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PB_C=$(find "$OTLP/pb/opentelemetry" -name '*.pb.c' | sort)

INC="-I $REPO_ROOT/include -I $OTLP -I $OTLP/pb -I $NANOPB -I $REPO_ROOT/src/runtime"

# 被験体 (test TU = otlp_agent.c を include した TU) だけ厳格に。他の runtime/nanopb は
# 巻き添えで -Werror を課さない (この test の関心ではないし、既存 runner も同じ扱い)。
echo "[egress] compiling egress contract test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -c $INC \
  tests/runtime/egress_contract_test.c -o "$TMP/parity.o"

# shellcheck disable=SC2086
"$CC" -O2 $INC "$TMP/parity.o" \
  "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_logs.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_httpspan.c" "$OTLP/otlp_enrich.c" "$OTLP/otlp_k8s.c" \
  "$OTLP/otlp_peer.c" "$OTLP/otlp_cri.c" "$OTLP/otlp_recmetric.c" \
  "$REPO_ROOT/src/runtime/spnl_runtime.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -lbpf -lelf -lz \
  -o "$TMP/egress_contract"

echo "[egress] running"
"$TMP/egress_contract"
