# C port of spinel-ebpf's eBPF codegen.
# Pure host text processing — builds with the system cc on macOS/Linux.
#
#   make            # build ../../build/codegen_c/spinel_ebpf_cc
#   make golden     # build + run the golden-snapshot regression gate
#   make templates  # regenerate templates_gen.h from templates/*.template.c (commit it)
#   make mirror     # regenerate the userspace record mirror from record_schema.h (commit it)
#   make gate       # record-contract gate: artifacts fresh + evolution append-only
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
ROOT    := ../..
OUT     := $(ROOT)/build/codegen_c
BIN     := $(OUT)/spinel_ebpf_cc
TEMPLATES := $(wildcard templates/*.template.c)
MIRROR_GEN := $(ROOT)/tools/gen_record_mirror.c
MIRROR_OUT := $(ROOT)/src/runtime/otlp/record_mirror_gen.h
SCHEMA_JSON := $(ROOT)/src/spinel_ebpf/record_schema_gen.json

# templates_gen.h is a committed derived artifact (embedded fixed BPF C helpers);
# the build only depends on the committed header, so regen is an explicit step.
# record_schema.h is #included directly -- listed so that editing the
# record contract actually rebuilds the codegen instead of silently reusing it.
$(BIN): spinel_ebpf_cc.c templates_gen.h record_schema.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: templates mirror gate golden oracle clean
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

# The record contract may only grow. Checks (a) the committed derived
# artifacts are what record_schema.h generates now, (b) nothing published has
# moved, changed type, lost its Ruby exposure or lost an egress key, against
# tests/golden/record_schema.snapshot.json. `ruby tools/record_gate.rb --update`
# moves the baseline (reviewable diff, like tests/golden/).
gate:
	@ruby $(ROOT)/tools/record_gate.rb

golden: $(BIN)
	@ruby $(ROOT)/tools/golden.rb

oracle: $(BIN)   # historical Ruby-parity check (not a gate; see tools/cgen_oracle.rb)
	@ruby $(ROOT)/tools/cgen_oracle.rb

clean:
	rm -f $(BIN)
