#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Check that the tree contains only English prose and no reference to a document
# that does not exist here.
#
# This repository is published from a larger private one, and its history is not
# shared. Two rules make it readable on its own:
#
#   1. All prose is English -- comments, doc blocks, and anything a user reads.
#   2. No reference to an internal document survives. Where such a reference
#      carried information, that information is written out instead, because a
#      reader here cannot follow the pointer.
#
# The second rule is the easy one to break, and the easy one to break *quietly*:
# a stripped reference leaves prose that still parses and still reads fluently
# while the fact it carried is gone. This script cannot detect that. What it does
# detect is the reference itself, in every spelling that has leaked before:
# numbered documents, the words for their kinds, and paths into directories this
# repository does not have.
#
#   sh scripts/check-public-prose.sh          # exit 1 on any violation
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Prune what is not ours to police: the checkouts scripts/setup.sh fetches, build
# output, vendored third-party code, and lockfiles full of hex that trips the
# numeric patterns.
FILES="$(find . \
  -path ./.git -prune -o \
  -path ./deps -prune -o \
  -path "*/vendor" -prune -o \
  -path "*/build" -prune -o \
  -path "*/data" -prune -o \
  -path ./build -prune -o \
  -path ./src/runtime/otlp/nanopb -prune -o \
  -path ./tools/rbpf-for-microcontrollers -prune -o \
  -name Cargo.lock -prune -o \
  -name check-public-prose.sh -prune -o \
  -type f -print)"

fail=0

# Rule 1. One exception: a literal that exists to test UTF-8 handling.
UTF8_TEST=./tests/spinel_ebpf/parse_spinel_ast_test.rb
ja=$(printf '%s\n' "$FILES" | grep -v "^$UTF8_TEST\$" | while IFS= read -r f; do
  LC_ALL=C grep -lP '[\x{3040}-\x{30ff}\x{4e00}-\x{9faf}]' "$f" 2>/dev/null || true
done)
if [ -n "$ja" ]; then
  echo "!!! non-English prose:"; printf '%s\n' "$ja" | sed 's/^/      /'; fail=1
fi

# Rule 2. Numbered documents (E001, ADR-001, P001, L001, M001), the words for
# their kinds, and paths into directories that do not exist here.
#
# The numbered forms are matched without word boundaries on the right, so that an
# identifier like `spnl_e287_secret` or a temporary path like `/tmp/e313_x` is
# caught too -- those have leaked before, and a lowercase spelling is still a
# reference to something a reader cannot see.
refs=$(printf '%s\n' "$FILES" | while IFS= read -r f; do
  grep -lniE '(\b|_|/)(E[0-9]{3}|P0[0-9]{2}|L[0-9]{3}|M00[0-9])(\b|_|-)|ADR-[0-9]{3}|\bEdoc\b|\bADR\b|docs/(experiments|adr|logs|plan|research|tasks|memo)|(^|[^a-z])benchmarks/' "$f" 2>/dev/null || true
done)
if [ -n "$refs" ]; then
  echo "!!! reference to a document that is not in this repository:"
  printf '%s\n' "$refs" | while IFS= read -r f; do
    echo "      $f"
    grep -niE '(\b|_|/)(E[0-9]{3}|P0[0-9]{2}|L[0-9]{3}|M00[0-9])(\b|_|-)|ADR-[0-9]{3}|\bEdoc\b|\bADR\b|docs/(experiments|adr|logs|plan|research|tasks|memo)|(^|[^a-z])benchmarks/' "$f" \
      | head -3 | sed 's/^/          /' | cut -c1-140
  done
  fail=1
fi

if [ "$fail" = 0 ]; then
  echo "prose check: OK -- English only, and no dangling document references"
fi
exit "$fail"
