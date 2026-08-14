# C port of spinel-ebpf's eBPF codegen.
# Pure host text processing — builds with the system cc on macOS/Linux.
#
#   make            # build ../../build/codegen_c/spinel_ebpf_cc
#   make golden     # build + run the golden-snapshot regression gate
#   make templates  # regenerate templates_gen.h from templates/*.template.c (commit it)
#   make mirror     # regenerate the userspace record mirror from record_schema.h (commit it)
#   make loader-contract # regenerate the codegen<->loader seam from loader_contract.h (commit it)
#   make attach-schema   # regenerate the attach vocabulary JSON from attach_schema.h (commit it)
#   make builtin-schema  # regenerate the builtin schema JSON from builtin_schema.h (commit it)
#   make gate       # record-contract gate: artifacts fresh + evolution append-only,
#                   # plus the reader gate (every rule a consumer must act on is
#                   # machine-readable, or declared unexpressible)
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
ROOT    := ../..
OUT     := $(ROOT)/build/codegen_c
BIN     := $(OUT)/spinel_ebpf_cc
TEMPLATES := $(wildcard templates/*.template.c)
MIRROR_GEN := $(ROOT)/tools/gen_record_mirror.c
PCTX_GEN := $(ROOT)/tools/gen_probe_ctx.c
PCTX_OUT := $(ROOT)/src/runtime/amp/probe_ctx_gen.h
PCTX_JSON := $(ROOT)/src/spinel_ebpf/probe_ctx_schema_gen.json
MIRROR_OUT := $(ROOT)/src/runtime/otlp/record_mirror_gen.h
SCHEMA_JSON := $(ROOT)/src/spinel_ebpf/record_schema_gen.json
LOADER_GEN := $(ROOT)/tools/gen_loader_contract.c
LOADER_RB  := $(ROOT)/src/spinel_ebpf/loader_contract_gen.rb
LOADER_JSON := $(ROOT)/src/spinel_ebpf/loader_contract_gen.json
ATTACH_GEN := $(ROOT)/tools/gen_attach_schema.c
ATTACH_JSON := $(ROOT)/src/spinel_ebpf/attach_schema_gen.json
BUILTIN_GEN := $(ROOT)/tools/gen_builtin_schema.c
BUILTIN_JSON := $(ROOT)/src/spinel_ebpf/builtin_schema_gen.json

# templates_gen.h is a committed derived artifact (embedded fixed BPF C helpers);
# the build only depends on the committed header, so regen is an explicit step.
# record_schema.h is #included directly -- listed so that editing the
# record contract actually rebuilds the codegen instead of silently reusing it.
$(BIN): spinel_ebpf_cc.c templates_gen.h record_schema.h attach_schema.h builtin_schema.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: templates mirror loader-contract gate golden oracle clean probe-ctx \
        attach-schema builtin-schema
templates: $(TEMPLATES)
	@ruby $(ROOT)/tools/embed_templates.rb

# Both derived views of the ringbuf record contracts come from
# the same record_schema.h the kernel struct comes from — the userspace mirror
# (offsets computed, never hand-typed) and the JSON the Ruby affordance surface
# reads. Committed derived artifacts: the runtime build just #includes the header
# and the Ruby lib just reads the JSON; neither runs this generator.
mirror: record_schema.h $(MIRROR_GEN)
	@mkdir -p $(OUT)
	@$(CC) $(CFLAGS) -o $(OUT)/gen_record_mirror $(MIRROR_GEN)
	@$(OUT)/gen_record_mirror        > $(MIRROR_OUT)
	@$(OUT)/gen_record_mirror --json > $(SCHEMA_JSON)
	@echo "wrote $(MIRROR_OUT) $(SCHEMA_JSON)"

probe-ctx: probe_ctx_schema.h $(PCTX_GEN)
	@mkdir -p $(OUT)
	@$(CC) $(CFLAGS) -o $(OUT)/gen_probe_ctx $(PCTX_GEN)
	@$(OUT)/gen_probe_ctx        > $(PCTX_OUT)
	@$(OUT)/gen_probe_ctx --json > $(PCTX_JSON)
	@echo "wrote $(PCTX_OUT) $(PCTX_JSON)"

# The attach vocabulary, declared once in attach_schema.h, rendered for the Ruby
# side. Committed derived artifact like the others.
attach-schema: attach_schema.h $(ATTACH_GEN)
	@mkdir -p $(OUT)
	@$(CC) $(CFLAGS) -o $(OUT)/gen_attach_schema $(ATTACH_GEN)
	@$(OUT)/gen_attach_schema > $(ATTACH_JSON)
	@echo "wrote $(ATTACH_JSON)"

# The builtin schema (declared arity + per-target existence), rendered for the
# Ruby side. Committed derived artifact like the others.
builtin-schema: builtin_schema.h $(BUILTIN_GEN)
	@mkdir -p $(OUT)
	@$(CC) $(CFLAGS) -o $(OUT)/gen_builtin_schema $(BUILTIN_GEN)
	@$(OUT)/gen_builtin_schema > $(BUILTIN_JSON)
	@echo "wrote $(BUILTIN_JSON)"


# The record contract may only grow. Checks (a) the committed derived
# artifacts are what record_schema.h generates now, (b) nothing published has
# moved, changed type, lost its Ruby exposure or lost an egress key, against
# tests/golden/record_schema.snapshot.json. `ruby tools/record_gate.rb --update`
# moves the baseline (reviewable diff, like tests/golden/).
gate:
	@ruby $(ROOT)/tools/record_gate.rb
	@ruby $(ROOT)/tools/loader_gate.rb
	@ruby $(ROOT)/tools/reader_gate.rb
	@ruby $(ROOT)/tools/attach_gate.rb
	@ruby $(ROOT)/tools/builtin_gate.rb

golden: $(BIN)
	@ruby $(ROOT)/tools/golden.rb

oracle: $(BIN)   # historical Ruby-parity check (not a gate; see tools/cgen_oracle.rb)
	@ruby $(ROOT)/tools/cgen_oracle.rb

clean:
	rm -f $(BIN)

# The codegen <-> loader seam. One declaration (loader_contract.h) from which the
# LOADER's half is generated -- bin/spinel-ebpf interpolates these constants
# instead of writing map names, strncmp lengths and record widths as literals
# inside a 2,200-line heredoc that nothing compiles. Committed derived
# artifacts, like `mirror`; tools/loader_gate.rb fails when they go stale.
loader-contract: loader_contract.h $(LOADER_GEN)
	@mkdir -p $(OUT)
	@$(CC) $(CFLAGS) -o $(OUT)/gen_loader_contract $(LOADER_GEN)
	@$(OUT)/gen_loader_contract        > $(LOADER_RB)
	@$(OUT)/gen_loader_contract --json > $(LOADER_JSON)
	@echo "wrote $(LOADER_RB) $(LOADER_JSON)"
