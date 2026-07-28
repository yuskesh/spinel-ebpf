# nanopb (vendored)

This directory is a verbatim copy of the five [nanopb](https://github.com/nanopb/nanopb)
files that the OTLP exporter needs, taken from **nanopb 0.4.9.1**:

| File | Role |
|---|---|
| `pb.h` | core types and field descriptors |
| `pb_encode.c` / `pb_encode.h` | the encoder (this project only encodes) |
| `pb_common.c` / `pb_common.h` | field iteration shared by encoder and decoder |

The decoder (`pb_decode.*`) is not vendored: spinel-ebpf writes OTLP payloads and
never parses them.

## Why vendored rather than fetched

The generated message code under `../pb/` is produced by nanopb's generator and
**must match the runtime it is compiled against**. Keeping both in the same commit
makes that impossible to get wrong; fetching nanopb separately would introduce a
version skew that only shows up as a corrupt payload at run time.

nanopb is distributed under the zlib license, which permits this. The upstream
license text is in `LICENSE.txt` and applies unchanged to these files.

## Updating

Copy the same five files from a newer nanopb release, regenerate `../pb/` with
that release's generator (`scripts/regen-otlp-pb.sh`), and commit both together.
