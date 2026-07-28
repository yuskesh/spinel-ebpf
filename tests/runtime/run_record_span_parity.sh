#!/usr/bin/env bash
#
# run_record_span_parity.sh -- checks, on synthetic records, that every property
# a typed consumer can read from Ruby holds the same value that ends up on the
# emitted span.
#
# record_span_parity_test.c includes otlp_agent.c as a whole translation unit and
# applies both sides to the same record:
#   the accessor (spnl_rec_<ch>_<prop>, i.e. what `ev.<prop>` returns in Ruby) and
#   the builder  (<ch>_fill_span, the path shared by the implicit push form and
#                 the explicit to_span form)
# then compares attribute values, span names and span durations.
#
# No real kernel, probe or collector is needed. libbpf only has to be linked
# because otlp_agent.c uses it for the ringbuf drain (the drain is never called),
# so this runs on Linux (in a container).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-clang}"
OTLP="$REPO_ROOT/src/runtime/otlp"
NANOPB="$REPO_ROOT/third_party/nanopb"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PB_C=$(find "$OTLP/pb/opentelemetry" -name '*.pb.c' | sort)

INC="-I $REPO_ROOT/include -I $OTLP -I $OTLP/pb -I $NANOPB -I $REPO_ROOT/src/runtime"

# Only the unit under test (the TU that includes otlp_agent.c) is built strictly.
# The rest of the runtime and nanopb are not held to -Werror: they are not what
# this test is about, and the other runners treat them the same way.
echo "[parity] compiling record/span parity test"
# shellcheck disable=SC2086
"$CC" -O2 -Wall -Wextra -Werror -c $INC \
  tests/runtime/record_span_parity_test.c -o "$TMP/parity.o"

# shellcheck disable=SC2086
"$CC" -O2 $INC "$TMP/parity.o" \
  "$OTLP/otlp_traces.c" "$OTLP/otlp_metrics.c" "$OTLP/otlp_logs.c" \
  "$OTLP/otlp_http.c" "$OTLP/otlp_grpc.c" "$OTLP/otlp_json.c" \
  "$OTLP/otlp_httpspan.c" "$OTLP/otlp_enrich.c" "$OTLP/otlp_k8s.c" \
  "$OTLP/otlp_peer.c" "$OTLP/otlp_cri.c" \
  "$REPO_ROOT/src/runtime/spnl_runtime.c" \
  "$NANOPB/pb_encode.c" "$NANOPB/pb_common.c" \
  $PB_C \
  -lbpf -lelf -lz \
  -o "$TMP/record_span_parity"

echo "[parity] running"
"$TMP/record_span_parity"

# cgid never becomes an attribute itself, but it is the input to the runtime
# enrichers. Whether they are active is decided lazily, once per process, so this
# case has to run as a separate process.
echo
"$TMP/record_span_parity" --cgid-enricher
