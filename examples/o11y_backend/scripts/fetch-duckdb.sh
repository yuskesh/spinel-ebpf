#!/bin/sh
# Fetch libduckdb (C API, linux arm64) into vendor/duckdb/. Run inside the
# Linux build environment. Pin with DUCKDB_VERSION, otherwise the latest
# GitHub release is resolved and recorded in VERSION.
set -e
base="$(cd "$(dirname "$0")/.." && pwd)"
dir="$base/vendor/duckdb"
mkdir -p "$dir"
cd "$dir"

ver="${DUCKDB_VERSION:-}"
if [ -z "$ver" ]; then
  ver=$(curl -fsSL https://api.github.com/repos/duckdb/duckdb/releases/latest \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)
fi
[ -n "$ver" ] || { echo "fetch-duckdb: could not resolve latest release tag; set DUCKDB_VERSION=vX.Y.Z" >&2; exit 1; }

# The asset name has been both libduckdb-linux-arm64 and -aarch64 across releases; try both
for asset in libduckdb-linux-arm64.zip libduckdb-linux-aarch64.zip; do
  if curl -fsSL -o libduckdb.zip "https://github.com/duckdb/duckdb/releases/download/$ver/$asset"; then
    got="$asset"; break
  fi
done
[ -n "${got:-}" ] || { echo "fetch-duckdb: no arm64 asset found for $ver" >&2; exit 1; }

unzip -o -q libduckdb.zip
rm -f libduckdb.zip
echo "$ver" > VERSION
echo "fetched libduckdb $ver ($got) -> $dir"
ls -l "$dir"
