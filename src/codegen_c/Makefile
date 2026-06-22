# C port of spinel-ebpf's eBPF codegen (Stage 1).
# Pure host text processing -- builds with the system cc on macOS/Linux.
#
#   make            # build ../../build/codegen_c/spinel_ebpf_cc
#   make golden     # build + run the golden-snapshot regression gate
#   make templates  # regenerate templates_gen.h from templates/*.template.c (commit it)
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
ROOT    := ../..
OUT     := $(ROOT)/build/codegen_c
BIN     := $(OUT)/spinel_ebpf_cc
TEMPLATES := $(wildcard templates/*.template.c)

# templates_gen.h is a committed derived artifact (embedded fixed BPF C helpers);
# the build only depends on the committed header, so regen is an explicit step.
$(BIN): spinel_ebpf_cc.c templates_gen.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: templates golden oracle clean
templates: $(TEMPLATES)
	@ruby $(ROOT)/tools/embed_templates.rb

golden: $(BIN)
	@ruby $(ROOT)/tools/golden.rb

oracle: $(BIN)   # historical Ruby-parity check (not a gate; see tools/cgen_oracle.rb)
	@ruby $(ROOT)/tools/cgen_oracle.rb

clean:
	rm -f $(BIN)
