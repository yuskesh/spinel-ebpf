#!/usr/bin/env bash
# otlp_common.sh -- shared helpers for the run_otlp_*.sh harnesses. Source it with
# `. otlp_common.sh`. The caller must set PROTOC (defaults to protoc) and PROTO_ROOT
# (the root of the opentelemetry-proto checkout).

OTLP_FAIL=0

# otlp_decode <message-fqn> <proto-rel-path> <in-bytes> <out-text>
otlp_decode() {
  "${PROTOC:-protoc}" --decode="$1" -I "$PROTO_ROOT" "$2" < "$3" > "$4"
}

# otlp_assert <file> <needle>    -- ok if the needle is present, otherwise mark FAIL
otlp_assert() {
  if grep -qF "$2" "$1"; then echo "  ok: $2"; else echo "  MISSING: $2"; OTLP_FAIL=1; fi
}

# otlp_count <file> <needle> <n> -- check that the needle occurs exactly n times
otlp_count() {
  c=$(grep -cF "$2" "$1")
  if [ "$c" = "$3" ]; then echo "  ok: $2 x$3"; else echo "  WRONG COUNT $2 = $c (want $3)"; OTLP_FAIL=1; fi
}

# otlp_done <label> -- exit 1 if anything above failed
otlp_done() {
  if [ "$OTLP_FAIL" -ne 0 ]; then echo "FAIL: $1"; exit 1; fi
  echo "PASS: $1"
}
