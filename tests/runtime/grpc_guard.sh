#!/usr/bin/env bash
# grpc_guard.sh -- find a python that can run the gRPC mock, or skip.
#
# Source this before starting mock_otlp_grpc.py. It sets VENV_PY to a python that
# can `import grpc`, looking at, in order: whatever the caller passed in VENV_PY,
# the .venv-otlp virtualenv that scripts/regen-otlp-pb.sh builds, and the system
# python3. If none of them has grpcio, it skips and says how to get it.
#
# The reason it exists: a virtualenv created on a macOS host and read from inside
# a Linux container has a bin/python symlink pointing at an interpreter that does
# not exist there. The harnesses did not check -- they launched
# `"$VENV_PY" mock_otlp_grpc.py &` regardless, the mock never started, and the
# client then reported `[otlp_grpc] transport error: connect failed`. A missing
# interpreter announced as a connection problem, which sends whoever is reading
# it looking at the wrong layer entirely. Resolve the interpreter first, and if
# there is none, say so.
#
# In practice the system python3 usually has grpcio and no virtualenv is needed.
# The one regen-otlp-pb.sh builds exists to pin protoc and protobuf to matching
# versions, not to run this mock.

_grpc_ok() { [ -n "${1:-}" ] && [ -x "$1" ] && "$1" -c 'import grpc' >/dev/null 2>&1; }

_pick=""
for _cand in "${VENV_PY:-}" "${REPO_ROOT:-.}/.venv-otlp/bin/python" "$(command -v python3 || true)"; do
    if _grpc_ok "$_cand"; then _pick="$_cand"; break; fi
done

if [ -z "$_pick" ]; then
    echo "SKIP: $(basename "$0") needs a python with grpcio to run the gRPC mock"
    echo "      looked at: VENV_PY / ${REPO_ROOT:-.}/.venv-otlp/bin/python / python3"
    echo "      get one with:  python3 -m venv .venv-otlp && .venv-otlp/bin/pip install grpcio grpcio-tools"
    echo "      or point at one:  VENV_PY=<python with grpcio> $0"
    exit 0
fi

VENV_PY="$_pick"
export VENV_PY
unset _pick _cand
