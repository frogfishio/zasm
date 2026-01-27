# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

# zasm (zas) Makefile
# Builds:
#   bin/<platform>/zas  (ZASM -> JSONL IR)

SHELL := /bin/bash
.ONESHELL:
.SUFFIXES:

CC      ?= clang
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS?= -Isrc/zas -Isrc/common -Ibuild/zas -Iinclude -Izcc/include
CPPFLAGS += -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=

# You can override these:
#   make BISON=/opt/homebrew/opt/bison/bin/bison FLEX=/opt/homebrew/opt/flex/bin/flex
BISON ?= bison
FLEX  ?= flex
RG ?= $(shell command -v rg 2>/dev/null || command -v grep 2>/dev/null)

BUILD := build
BIN_ROOT := bin
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

VERSION_FILE ?= VERSION
VERSION_HEADER := include/version.h
DIST_DIR := dist
DIST_PLATFORM_DIR = $(DIST_DIR)/$(PLATFORM)

# Wasmtime C API location (moved from external/ to ext/)
WASMTIME_C_API_DIR_BASE := ext/wasmtime-c-api

ZAS_BUILD := $(BUILD)/zas
ZOP_BUILD := $(BUILD)/zop
ZXC_BUILD := $(BUILD)/zxc
ZIR_BUILD := $(BUILD)/zir
ZRUN_BUILD := $(BUILD)/zrun
LOWER_BUILD := $(BUILD)/lower
CLOAK_BUILD := $(BUILD)/cloak
CLOAK_TEST_BUILD := $(BUILD)/cloak_tests
ZEM_BUILD := $(BUILD)/zem

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  PLATFORM_OS := macos
  SHLIB_EXT := .dylib
  SHLIB_LDFLAGS := -dynamiclib
  SHLIB_RPATH := -Wl,-rpath,@loader_path
else ifeq ($(UNAME_S),Linux)
  PLATFORM_OS := linux
  SHLIB_EXT := .so
  SHLIB_LDFLAGS := -shared -Wl,-soname,liblembeh_cloak.so
  SHLIB_RPATH := -Wl,-rpath,'$$ORIGIN'
  SHLIB_LDLIBS := -ldl
else
  PLATFORM_OS := $(UNAME_S)
  SHLIB_EXT := .so
  SHLIB_LDFLAGS := -shared
  SHLIB_RPATH := -Wl,-rpath,'$$ORIGIN'
  SHLIB_LDLIBS := -ldl
endif

ifeq ($(UNAME_M),x86_64)
  PLATFORM_ARCH := x86_64
else ifeq ($(UNAME_M),amd64)
  PLATFORM_ARCH := x86_64
else ifeq ($(UNAME_M),aarch64)
  PLATFORM_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
  PLATFORM_ARCH := arm64
else
  PLATFORM_ARCH := $(UNAME_M)
endif

PLATFORM ?= $(PLATFORM_OS)-$(PLATFORM_ARCH)

BIN := $(BIN_ROOT)/$(PLATFORM)

WASMTIME_C_API_DIR ?= $(if $(wildcard $(WASMTIME_C_API_DIR_BASE)/$(PLATFORM)),$(WASMTIME_C_API_DIR_BASE)/$(PLATFORM),$(WASMTIME_C_API_DIR_BASE))

ZAS_SRC := \
  src/zas/main.c \
  src/zas/emit_json.c

ZAS_GEN := \
  $(ZAS_BUILD)/zasm.tab.c \
  $(ZAS_BUILD)/zasm.tab.h \
  $(ZAS_BUILD)/lex.yy.c

ZAS_OBJ := \
  $(ZAS_BUILD)/main.o \
  $(ZAS_BUILD)/emit_json.o \
	$(ZAS_BUILD)/diag.o \
  $(ZAS_BUILD)/zasm.tab.o \
  $(ZAS_BUILD)/lex.yy.o

ZAS_GEN_CFLAGS := $(CFLAGS) -Wno-sign-compare -Wno-unused-function -Wno-unneeded-internal-declaration

.PHONY: \
	all clean zas zld zrun zlnt zop zxc zxc-lib zir lower dirs install \
	build pipeline bump bump-version dist dist-$(PLATFORM) zem \
  zcloak zcloak-jit cloak-lib cloak-example cloak-tests zasm-bin-wrap \
  test test-all test-smoke test-asm test-runtime test-negative test-validation test-fuzz test-abi test-cloak-smoke test-cloak-abi test-cloak \
  integrator-pack dist-integrator-pack \
  test-asm-suite \
  test-hello test-wat test-loop-wat test-loop \
  test-ld-regreg test-add-hl-imm test-data-directives test-compare-conds \
  test-arithmetic test-regmoves test-names test-linkage test-manifest test-bytes test-str-equ \
  test-cat test-upper test-stream test-alloc test-isa-smoke test-fizzbuzz test-twofile \
  test-strict test-trap test-zrun-log \
  test-unknownsym test-badcond test-badlabel test-badmem \
	test-wat-validate test-wasm-opt test-zlnt test-opcode-golden test-abi-linker test-abi-alloc test-abi-stream test-abi-log test-abi-entry test-abi-imports test-abi-ctl test-conform-zld \
	test-fuzz-zas test-fuzz-zld test-zxc-arm64 test-zxc-x86 test-zxc-cli test-zir \
	test-diagnostics-jsonl test-zem-stdin-program
	  test-zem-zi-write
	  test-zem-zi-read test-zem-zi-abi-version
	  test-zem-caps

all: zas zld

build: zas zld zrun zlnt zop zxc zir zem lower zasm-bin-wrap

pipeline: build
	./scripts/pipeline.sh --skip-build

install: zas zld zrun zlnt zop zxc zir zem lower zasm-bin-wrap
	@mkdir -p $(DESTDIR)$(BINDIR)
	@cp tools/zasm_bin_wrap.py $(DESTDIR)$(BINDIR)/zasm-bin-wrap
	@install -m 0755 $(BIN)/zas $(DESTDIR)$(BINDIR)/zas
	@install -m 0755 $(BIN)/zld $(DESTDIR)$(BINDIR)/zld
	@install -m 0755 $(BIN)/zrun $(DESTDIR)$(BINDIR)/zrun
	@install -m 0755 $(BIN)/zlnt $(DESTDIR)$(BINDIR)/zlnt
	@install -m 0755 $(BIN)/zop $(DESTDIR)$(BINDIR)/zop
	@install -m 0755 $(BIN)/zxc $(DESTDIR)$(BINDIR)/zxc
	@install -m 0755 $(BIN)/zir $(DESTDIR)$(BINDIR)/zir
	@install -m 0755 $(BIN)/zem $(DESTDIR)$(BINDIR)/zem
	@install -m 0755 $(BIN)/lower $(DESTDIR)$(BINDIR)/lower

dirs:
	mkdir -p $(BIN) $(ZAS_BUILD) $(ZOP_BUILD) $(ZXC_BUILD) $(ZIR_BUILD) $(ZLD_BUILD) $(ZRUN_BUILD) $(ZLNT_BUILD) $(LOWER_BUILD) $(CLOAK_BUILD) $(CLOAK_TEST_BUILD) $(ZEM_BUILD) $(ZEM_BUILD)/exec

$(VERSION_HEADER): $(VERSION_FILE)
	@ver=$$(cat $(VERSION_FILE)); \
	printf "/* Auto-generated. */\n#ifndef ZASM_VERSION_H\n#define ZASM_VERSION_H\n#define ZASM_VERSION \"%s\"\n#endif\n" "$$ver" > $(VERSION_HEADER)

zas zld zrun zlnt lower: $(VERSION_HEADER)

dist: build
	$(MAKE) clean
	$(MAKE) dist-$(PLATFORM)

DIST_TOOLS := zas zld zlnt zop zxc zir
ifneq ($(NO_ZRUN),1)
  DIST_TOOLS += zrun
endif
DIST_TOOLS += lower
DIST_LIBS := libzxc.a

dist-$(PLATFORM): $(DIST_TOOLS) zxc-lib $(VERSION_HEADER)
	@mkdir -p $(DIST_PLATFORM_DIR)/bin
	@mkdir -p $(DIST_PLATFORM_DIR)/lib
	@cp $(foreach t,$(DIST_TOOLS),$(BIN)/$(t)) $(DIST_PLATFORM_DIR)/bin/
	@cp $(foreach l,$(DIST_LIBS),$(BIN)/$(l)) $(DIST_PLATFORM_DIR)/lib/
	@cp $(VERSION_FILE) $(DIST_PLATFORM_DIR)/
	@mkdir -p $(DIST_PLATFORM_DIR)/docs
	@cp -R docs/tools $(DIST_PLATFORM_DIR)/docs/
	@mkdir -p $(DIST_PLATFORM_DIR)/docs/spec
	@cp docs/spec/zxc.md $(DIST_PLATFORM_DIR)/docs/spec/

bump: bump-version

bump-version: $(VERSION_FILE)
	@old=$$(cat $(VERSION_FILE)); \
	IFS=. read -r major minor patch <<< "$$old"; \
	patch=$$((patch + 1)); \
	new="$$major.$$minor.$$patch"; \
	printf "%s\n" "$$new" > $(VERSION_FILE); \
	echo "Bumped $$old -> $$new"

# --- Generator rules ---

# Bison (parser)
$(ZAS_BUILD)/zasm.tab.c $(ZAS_BUILD)/zasm.tab.h: src/zas/zasm.y | dirs
	$(BISON) -d -o $(ZAS_BUILD)/zasm.tab.c src/zas/zasm.y

# Flex (lexer) depends on the generated bison header
$(ZAS_BUILD)/lex.yy.c: src/zas/zasm.l $(ZAS_BUILD)/zasm.tab.h | dirs
	$(FLEX) -o $(ZAS_BUILD)/lex.yy.c src/zas/zasm.l

# --- Compile rules ---

$(ZAS_BUILD)/%.o: src/zas/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(ZAS_BUILD)/diag.o: src/common/diag.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(ZAS_BUILD)/zasm.tab.o: $(ZAS_BUILD)/zasm.tab.c $(ZAS_BUILD)/zasm.tab.h | dirs
	$(CC) $(CPPFLAGS) $(ZAS_GEN_CFLAGS) -c $(ZAS_BUILD)/zasm.tab.c -o $@

$(ZAS_BUILD)/lex.yy.o: $(ZAS_BUILD)/lex.yy.c $(ZAS_BUILD)/zasm.tab.h | dirs
	$(CC) $(CPPFLAGS) $(ZAS_GEN_CFLAGS) -c $(ZAS_BUILD)/lex.yy.c -o $@

# --- Link ---

zas: $(ZAS_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZAS_OBJ) -o $(BIN)/zas $(LDFLAGS)
	ln -sf $(PLATFORM)/zas $(BIN_ROOT)/zas

# --- Test groups ---

test: test-all

test-all: test-smoke test-asm test-runtime test-negative test-validation test-fuzz test-abi

test-smoke: test-hello test-wat test-loop

test-asm: test-ld-regreg test-add-hl-imm test-data-directives test-compare-conds \
  test-arithmetic test-regmoves test-names test-linkage test-manifest test-bytes \
  test-str-equ

test-runtime: test-cat test-upper test-stream test-alloc test-isa-smoke test-fizzbuzz \
  test-twofile test-strict test-trap test-zrun-log

test-negative: test-unknownsym test-badcond test-badlabel test-badmem

test-validation: test-wat-validate test-wasm-opt test-zlnt test-opcode-golden test-conform-zld
test-validation: test-zlnt-enum-oob
test-validation: test-zop-bytes test-zas-opcodes-directives test-zxc-x86 test-zxc-cli test-zir
test-validation: test-diagnostics-jsonl
test-validation: test-zem-stdin-program
test-validation: test-zem-emit-cert-smoke
test-validation: test-zem-zi-write
test-validation: test-zem-zi-read
test-validation: test-zem-zi-abi-version
test-validation: test-zem-zi-hop-alloc
test-validation: test-zem-zi-enum-alloc
test-validation: test-zem-zi-proc-env
test-validation: test-zem-inherit-env
test-validation: test-zem-caps
test-validation: test-zem-sniff-ret-trunc
test-validation: test-zem-diag-ret-trunc-ld32s64
test-validation: test-zem-coverage-smoke
test-validation: test-zem-coverage-blackholes
test-validation: test-zem-rep-scan
test-validation: test-zem-rep-render-from-report
test-validation: test-zem-strip-uncovered-ret
test-validation: test-zem-strip-uncovered-delete
test-validation: test-zem-shake-smoke
test-validation: test-zem-shake-redzone test-zem-shake-quarantine test-zem-shake-io-chunking
test-validation: test-zem-ir-v11-parser-robust
test-validation: test-zem-break-src-file-line
test-validation: test-zem-ir-id-debug-events
test-validation: test-zem-ir-id-coverage

# Experimental / local-only debloat playground (large fixture).
# Not included in test-all/test-validation.
test-zem-debloat-hello-big: zem
	sh test/zem_debloat_hello_big.sh

test-fuzz: test-fuzz-zas test-fuzz-zld

test-zop-bytes: zop
	sh test/zop_bytes.sh

test-diagnostics-jsonl: zas
	sh test/diagnostics_jsonl.sh

test-zem-stdin-program: zas zem
	sh test/zem_stdin_program.sh

test-zem-emit-cert-smoke: zas zem
	sh test/zem_emit_cert_smoke.sh

test-zem-emit-cert-prove: zas zem
	sh test/zem_emit_cert_prove.sh

test-zem-zi-write: zas zem
	sh test/zem_zi_write.sh

test-zem-zi-read: zas zem
	sh test/zem_zi_read.sh

test-zem-zi-abi-version: zas zem
	sh test/zem_zi_abi_version.sh

test-zem-zi-hop-alloc: zas zem
	sh test/zem_zi_hop_alloc.sh

test-zem-zi-enum-alloc: zas zem
	sh test/zem_zi_enum_alloc.sh

test-zem-shake-smoke: zas zem
	sh test/zem_shake_smoke.sh

test-zem-shake-redzone: zas zem
	sh test/zem_shake_redzone.sh

test-zem-shake-quarantine: zas zem
	sh test/zem_shake_quarantine.sh

test-zem-shake-io-chunking: zas zem
	sh test/zem_shake_io_chunking.sh

test-zem-zi-proc-env: zas zem
	sh test/zem_zi_proc_env.sh

test-zem-inherit-env: zas zem
	sh test/zem_inherit_env.sh

test-zem-sniff-ret-trunc: zas zem
	sh test/zem_sniff_ret_trunc.sh

test-zem-diag-ret-trunc-ld32s64: zas zem
	sh test/zem_diag_ret_trunc_ld32s64.sh

test-zem-coverage-smoke: zas zem
	sh test/zem_coverage_smoke.sh

test-zem-coverage-blackholes: zas zem
	sh test/zem_coverage_blackholes.sh

test-zem-rep-scan: zem
	sh test/zem_rep_scan.sh

test-zem-rep-render-from-report:
	sh test/zem_rep_render_from_report.sh

test-zem-ir-v11-parser-robust: zem
	sh test/zem_ir_v11_parser_robust.sh

test-zem-break-src-file-line: zem
	sh test/zem_break_src_file_line.sh

test-zem-ir-id-debug-events: zem
	sh test/zem_ir_id_debug_events.sh

test-zem-ir-id-coverage: zem
	sh test/zem_ir_id_coverage.sh

test-zem-caps: zem
	sh test/zem_caps.sh

test-zem-strip-uncovered-ret: zas zem
	sh test/zem_strip_uncovered_ret.sh

test-zem-strip-uncovered-delete: zas zem
	sh test/zem_strip_uncovered_delete.sh

test-zas-opcodes-directives: zas zop
	sh test/zas_opcodes_directives.sh

test-zxc-arm64: zxc-lib
	@arch=$$(uname -m); \
	if [ "$$arch" != "arm64" ] && [ "$$arch" != "aarch64" ]; then \
	  echo "zxc arm64 smoke: skipped (arch=$$arch)"; \
	  exit 0; \
	fi; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_smoke.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_smoke; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_load_store.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_load_store; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_ld_ext.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_ld_ext; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_compare_branch.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_compare_branch; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_call.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_call; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_macro.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_macro; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_div_guard.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_div_guard; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_errors.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_errors; \
	$(CC) $(CFLAGS) -Iinclude test/zxc_arm64_primitives.c $(BIN)/libzxc.a -o $(BUILD)/zxc_arm64_primitives; \
	$(BUILD)/zxc_arm64_smoke; \
	$(BUILD)/zxc_arm64_load_store; \
	$(BUILD)/zxc_arm64_ld_ext; \
	$(BUILD)/zxc_arm64_compare_branch; \
	$(BUILD)/zxc_arm64_call; \
	$(BUILD)/zxc_arm64_macro; \
	$(BUILD)/zxc_arm64_div_guard; \
	$(BUILD)/zxc_arm64_errors; \
	$(BUILD)/zxc_arm64_primitives

test-zxc-x86: zxc-lib
	$(CC) $(CFLAGS) -Iinclude test/zxc_x86_64_errors.c $(BIN)/libzxc.a -o $(BUILD)/zxc_x86_64_errors; \
	$(BUILD)/zxc_x86_64_errors

test-zxc-cli: zxc
	sh test/zxc_cli_smoke.sh

test-zir: zir zop
	sh test/zir_smoke.sh

test-asm-suite: test-asm test-runtime test-validation test-fuzz-zld

test-abi: test-abi-linker test-abi-alloc test-abi-stream test-abi-log test-abi-entry test-abi-imports test-abi-ctl

lembeh-host-stub:
	$(CC) $(CFLAGS) -Idocs/integrator_pack/jit -Isrc/cloak -Iinclude tools/lembeh_host_stub.c \
	  src/cloak/lembeh_cloak.c -o $(BUILD)/lembeh_host_stub

native-runner:
	$(CC) $(CFLAGS) -Idocs/integrator_pack/jit -Isrc/cloak -Iinclude tools/native_runner.c \
	  src/cloak/lembeh_cloak.c bin/macos-arm64/libzxc.a -o $(BUILD)/native_runner

# --- Smoke tests ---

test-hello: zas
	@if [[ -f examples/hello.asm ]]; then \
	  cat examples/hello.asm | $(BIN)/zas ; \
	else \
	  echo "Missing examples/hello.asm"; \
	  exit 1; \
	fi

test-wat: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld > out.wat
	@echo "Wrote out.wat"

test-loop-wat: zas zld
	cat examples/loop.asm | $(BIN)/zas | $(BIN)/zld > loop.wat
	@echo "Wrote loop.wat"

test-loop: test-loop-wat

# --- Assembler/IR tests ---

test-ld-regreg: zas zld
	cat examples/cat.asm | $(BIN)/zas | $(BIN)/zld > build/cat.wat
	@$(RG) -q -F 'local.get $$HL' build/cat.wat
	@$(RG) -q -F 'local.set $$DE' build/cat.wat

test-add-hl-imm: zas zld
	cat examples/ptrstep.asm | $(BIN)/zas | $(BIN)/zld > build/ptrstep.wat
	@awk '/local.get .*HL/{getline a; getline b; getline c; if (a ~ /i32.const 4/ && b ~ /i32.add/ && c ~ /local.(set|tee) .*HL/) f=1} END{exit !f}' build/ptrstep.wat
	@awk '/local.get .*HL/{getline a; getline b; getline c; if (a ~ /i32.const 8/ && b ~ /i32.add/ && c ~ /local.(set|tee) .*HL/) f=1} END{exit !f}' build/ptrstep.wat

test-data-directives: zas zld zrun
	cat examples/data.asm | $(BIN)/zas | $(BIN)/zld > build/data.wat
	@$(RG) -q -F '(global $$msg i32 (i32.const ' build/data.wat
	@$(RG) -q -F '(global $$msg_len i32 (i32.const 3))' build/data.wat
	@$(RG) -q -F '(global $$buf i32 (i32.const ' build/data.wat
	@awk '/A\\0a\\00/ {found=1} END{exit !found}' build/data.wat
	$(BIN)/zrun build/data.wat > build/data.out 2>build/data.err
	@od -An -tx1 build/data.out | tr -d ' \\n' | $(RG) -q '^410a00$$'

test-compare-conds: zas zld
	cat examples/compare_conds.asm | $(BIN)/zas | $(BIN)/zld > build/compare_conds.wat

test-arithmetic: zas zld
	cat examples/arithmetic.asm | $(BIN)/zas | $(BIN)/zld > build/arithmetic.wat

test-regmoves: zas zld
	cat examples/regmoves.asm | $(BIN)/zas | $(BIN)/zld > build/regmoves.wat

test-names: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld --names > build/hello.names.wat
	@$(RG) -q -F '(custom "name"' build/hello.names.wat

test-linkage: zas zld
	cat examples/export.asm | $(BIN)/zas | $(BIN)/zld > build/export.wat
	@$(RG) -q -F '(export "main" (func $$main))' build/export.wat
	cat examples/extern.asm | $(BIN)/zas | $(BIN)/zld > build/extern.wat
	@$(RG) -q -F '(import "env" "noop" (func $$noop (param i32 i32)))' build/extern.wat

test-manifest: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld --manifest > build/hello.manifest.json
	@$(RG) -q -F '"manifest":"zasm-v1.0"' build/hello.manifest.json
	@$(RG) -q -F '"lembeh_handle"' build/hello.manifest.json
	@$(RG) -q -F '"_out"' build/hello.manifest.json

test-bytes: zas zld zrun
	cat examples/bytes.asm | $(BIN)/zas | $(BIN)/zld > build/bytes.wat
	$(BIN)/zrun build/bytes.wat > build/bytes.out 2>build/bytes.err
	@od -An -tx1 build/bytes.out | tr -d ' \\n' | $(RG) -q '^41$$'

test-str-equ: zas zld zrun
	cat examples/str_equ.asm | $(BIN)/zas | $(BIN)/zld > build/str_equ.wat
	@$(RG) -q -F '(global $$msg_len i32 (i32.const 3))' build/str_equ.wat
	@$(RG) -q -F '(global $$buf_size i32 (i32.const 16))' build/str_equ.wat
	$(BIN)/zrun build/str_equ.wat > build/str_equ.out 2>build/str_equ.err
	@od -An -tx1 build/str_equ.out | tr -d ' \\n' | $(RG) -q '^48690a$$'

# --- Runtime/integration tests ---

test-cat: zas zld zrun
	test/run.sh examples/cat.asm test/fixtures/cat.in test/fixtures/cat.out

test-upper: zas zld zrun
	test/run.sh examples/upper.asm test/fixtures/upper.in test/fixtures/upper.out

test-stream: test-cat test-upper

test-alloc: zas zld zrun
	test/run.sh examples/alloc.asm test/fixtures/alloc.in test/fixtures/alloc.out

test-isa-smoke: zas zld zrun
	test/run.sh examples/isa_smoke.asm test/fixtures/isa_smoke.in test/fixtures/isa_smoke.out

test-fizzbuzz: zas zld zrun
	cat examples/fizzbuzz.asm | $(BIN)/zas | $(BIN)/zld > build/fizzbuzz.wat
	$(BIN)/zrun build/fizzbuzz.wat > build/fizzbuzz.out 2>build/fizzbuzz.err
	@$(RG) -q -F 'FizzBuzz' build/fizzbuzz.out

test-twofile: zas zld zrun
	cat examples/hello_twofile.asm examples/lib_hello.asm | $(BIN)/zas | $(BIN)/zld > build/twofile.wat
	$(BIN)/zrun build/twofile.wat > build/twofile.out 2>build/twofile.err
	@$(RG) -q -F 'Hello from lib' build/twofile.out

test-strict: zas zld zrun
	cat examples/bad_strict.asm | $(BIN)/zas | $(BIN)/zld > build/bad_strict.wat
	@$(BIN)/zrun build/bad_strict.wat > build/bad_strict.out 2>build/bad_strict.err
	@bash -ec "if $(BIN)/zrun --strict build/bad_strict.wat > build/bad_strict_strict.out 2>build/bad_strict_strict.err; then echo \"expected strict failure\"; exit 1; fi; $(RG) -q -F 'res_write OOB' build/bad_strict_strict.err"

test-trap: zas zld zrun
	cat examples/bad_trap.asm | $(BIN)/zas | $(BIN)/zld > build/bad_trap.wat
	@bash -ec "if $(BIN)/zrun build/bad_trap.wat > build/bad_trap.out 2>build/bad_trap.err; then echo \"expected trap\"; exit 1; fi; $(RG) -q -F 'trap' build/bad_trap.err"

test-zrun-log: zas zld zrun
	cat examples/log.asm | $(BIN)/zas | $(BIN)/zld > build/log.wat
	$(BIN)/zrun build/log.wat 1>/tmp/log.out 2>/tmp/log.err
	@$(RG) -q "^\\[demo\\] hello" /tmp/log.err

# --- Negative/error tests ---

test-unknownsym: zas zld
	@bash -ec 'if cat examples/unknownsym.asm | $(BIN)/zas | $(BIN)/zld > /tmp/unknownsym.wat 2>/tmp/unknownsym.err; then echo "expected failure"; exit 1; fi; $(RG) -q "unknown symbol does_not_exist" /tmp/unknownsym.err'

test-badcond: zas zld
	@bash -ec 'if cat examples/badcond.asm | $(BIN)/zas | $(BIN)/zld > /tmp/badcond.wat 2>/tmp/badcond.err; then echo "expected failure"; exit 1; fi; $(RG) -q "unknown JR condition WTF" /tmp/badcond.err'

test-badlabel: zas zld
	@bash -ec 'if cat examples/badlabel.asm | $(BIN)/zas | $(BIN)/zld > /tmp/badlabel.wat 2>/tmp/badlabel.err; then echo "expected failure"; exit 1; fi; $(RG) -q "unknown label missing_label" /tmp/badlabel.err'

test-badmem: zas zld
	@bash -ec 'if cat examples/badmem.asm | $(BIN)/zas | $(BIN)/zld > /tmp/badmem.wat 2>/tmp/badmem.err; then echo "expected failure"; exit 1; fi; $(RG) -q "only \\(HL\\) supported" /tmp/badmem.err'

# --- Validation/tools ---

test-wat-validate: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld > build/hello.wat
	cat examples/loop.asm | $(BIN)/zas | $(BIN)/zld > build/loop.wat
	test/validate_wat.sh build/hello.wat build/loop.wat

test-wasm-opt: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld > build/hello.wat
	cat examples/loop.asm | $(BIN)/zas | $(BIN)/zld > build/loop.wat
	test/wasm_opt.sh build/hello.wat build/loop.wat

test-zlnt: zas zlnt
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zlnt
	cat examples/upper.asm | $(BIN)/zas | $(BIN)/zlnt

test-zlnt-enum-oob: zas zlnt
	sh test/zlnt_enum_oob.sh

test-opcode-golden:
	test/opcode_golden.sh

# --- Fuzz tests ---

test-fuzz-zas: zas
	test/fuzz_zas.sh

test-fuzz-zld: zld
	test/fuzz_zld_jsonl.sh

test-abi-linker: zas zld
	test/abi_linker.sh

test-abi-alloc: zas zld zrun
	test/abi_alloc.sh

test-abi-stream: zas zld zrun
	test/abi_stream.sh

test-abi-log: zas zld zlnt zrun
	test/abi_log.sh

test-abi-entry: zas zld
	test/abi_entry.sh

test-abi-imports: zas zld
	test/abi_imports.sh

test-abi-ctl: zrun
	test/abi_ctl.sh

test-conform-zld: zld
	test/conform_zld.sh

test-cloak-smoke: zcloak zcloak-jit cloak-example test-cloak-jit

test-cloak-jit: zcloak-jit
	sh test/cloak_jit_smoke.sh
	sh test/cloak_jit_negative.sh
	test/cloak_smoke.sh

test-cloak-abi: zcloak cloak-tests
	test/cloak_abi_alloc.sh
	test/cloak_abi_stream.sh
	test/cloak_abi_log.sh
	test/cloak_abi_ctl.sh

test-cloak: test-cloak-smoke test-cloak-abi

integrator-pack:
	./docs/integrator_pack/pack.sh $(CURDIR)/integrator_pack

dist-integrator-pack:
	./docs/integrator_pack/pack.sh $(CURDIR)/dist/integrator_pack

clean:
	rm -rf $(BUILD) $(BIN_ROOT)


# ---- cloak (native C host) ----

CLOAK_CPPFLAGS := -Isrc/cloak -Iinclude
CLOAK_CFLAGS := $(CFLAGS) -fPIC
CLOAK_LIB := $(BIN)/liblembeh_cloak$(SHLIB_EXT)
ZCLOAK_OBJ := $(CLOAK_BUILD)/main.o $(CLOAK_BUILD)/host.o
ZCLOAK_JIT_OBJ := $(CLOAK_BUILD)/jit_main.o $(CLOAK_BUILD)/host.o
CLOAK_OBJ := $(CLOAK_BUILD)/lembeh_cloak.o
CLOAK_EXAMPLE := $(CLOAK_BUILD)/echo_guest$(SHLIB_EXT)
CLOAK_TEST_SRCS := $(wildcard test/cloak_guests/*.c)
CLOAK_TEST_LIBS := $(patsubst test/cloak_guests/%.c,$(CLOAK_TEST_BUILD)/%$(SHLIB_EXT),$(CLOAK_TEST_SRCS))

$(CLOAK_BUILD)/%.o: src/cloak/%.c | dirs
	$(CC) $(CLOAK_CPPFLAGS) $(CLOAK_CFLAGS) -c $< -o $@

cloak-lib: $(CLOAK_LIB)

$(CLOAK_LIB): $(CLOAK_OBJ) | dirs
	$(CC) $(CLOAK_CFLAGS) $(SHLIB_LDFLAGS) $^ -o $@

zcloak: cloak-lib $(ZCLOAK_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZCLOAK_OBJ) -L$(BIN) -llembeh_cloak $(SHLIB_RPATH) $(SHLIB_LDLIBS) -o $(BIN)/zcloak
	ln -sf $(PLATFORM)/zcloak $(BIN_ROOT)/zcloak

zcloak-jit: cloak-lib zxc-lib $(ZCLOAK_JIT_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZCLOAK_JIT_OBJ) -L$(BIN) -llembeh_cloak -lzxc $(SHLIB_RPATH) $(SHLIB_LDLIBS) -o $(BIN)/zcloak-jit
	ln -sf $(PLATFORM)/zcloak-jit $(BIN_ROOT)/zcloak-jit

cloak-example: $(CLOAK_EXAMPLE)

$(CLOAK_EXAMPLE): examples/cloak/echo_guest.c cloak-lib | dirs
	$(CC) $(CLOAK_CFLAGS) -Isrc/cloak $(SHLIB_LDFLAGS) $< -L$(BIN) -llembeh_cloak -o $@

cloak-tests: $(CLOAK_TEST_LIBS)

$(CLOAK_TEST_BUILD)/%$(SHLIB_EXT): test/cloak_guests/%.c cloak-lib | dirs
	$(CC) $(CLOAK_CFLAGS) -Isrc/cloak $(SHLIB_LDFLAGS) $< -L$(BIN) -llembeh_cloak -o $@


# ---- zld (IR -> WAT) ----

ZLD_BUILD := $(BUILD)/zld

ZLD_SRC := \
  src/zld/main.c \
  src/zld/jsonl.c \
  src/zld/wat_emit.c

ZLD_OBJ := \
  $(ZLD_BUILD)/main.o \
  $(ZLD_BUILD)/jsonl.o \
  $(ZLD_BUILD)/wat_emit.o

$(ZLD_BUILD)/%.o: src/zld/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

zld: $(ZLD_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZLD_OBJ) -o $(BIN)/zld $(LDFLAGS)
	ln -sf $(PLATFORM)/zld $(BIN_ROOT)/zld

.PHONY: zld

# ---- lower (IR -> Mach-O arm64) ----

LOWER_SRC := \
  src/lower/arm64/ir.c \
  src/lower/arm64/json_ir.c \
  src/lower/arm64/codegen.c \
  src/lower/arm64/mach_o.c \
  src/lower/arm64/main.c

LOWER_OBJ := \
  $(LOWER_BUILD)/ir.o \
  $(LOWER_BUILD)/json_ir.o \
  $(LOWER_BUILD)/codegen.o \
  $(LOWER_BUILD)/mach_o.o \
  $(LOWER_BUILD)/main.o

$(LOWER_BUILD)/%.o: src/lower/arm64/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/lower/arm64 -c $< -o $@

lower: $(LOWER_OBJ) | dirs
	$(CC) $(CFLAGS) $(LOWER_OBJ) -o $(BIN)/lower $(LDFLAGS)
	ln -sf $(PLATFORM)/lower $(BIN_ROOT)/lower

.PHONY: lower

# ---- zem (IR v1.1 emulator) ----

ZEM_HOST_BUILD := $(BUILD)/zem_host
ZEM_HOST_LIBZING := $(ZEM_HOST_BUILD)/libzingcore.a
ZEM_HOST_LIBHOPPER := $(ZEM_HOST_BUILD)/libhopper.a
ZEM_HOST_LIBCAP_ASYNC := $(ZEM_HOST_BUILD)/libzingcap_async.a
ZEM_HOST_LIBCAP_EXEC := $(ZEM_HOST_BUILD)/libzingcap_exec.a

ZEM_OBJ := \
	$(ZEM_BUILD)/main.o \
	$(ZEM_BUILD)/zem_debug.o \
	$(ZEM_BUILD)/zem_srcmap.o \
	$(ZEM_BUILD)/exec/zem_exec_program.o \
	$(ZEM_BUILD)/exec/zem_exec_helpers_base.o \
	$(ZEM_BUILD)/exec/zem_exec_helpers_diag.o \
	$(ZEM_BUILD)/exec/zem_exec_helpers_fail.o \
	$(ZEM_BUILD)/exec/zem_exec_ops_ld.o \
	$(ZEM_BUILD)/exec/zem_exec_ops_alu.o \
	$(ZEM_BUILD)/exec/zem_exec_ops_cmp.o \
	$(ZEM_BUILD)/exec/zem_exec_ops_mem.o \
	$(ZEM_BUILD)/exec/zem_exec_ops_jr.o \
	$(ZEM_BUILD)/exec/zem_exec_call_env_time_proc.o \
	$(ZEM_BUILD)/exec/zem_exec_call_alloc.o \
	$(ZEM_BUILD)/exec/zem_exec_call_io.o \
	$(ZEM_BUILD)/exec/zem_exec_call_misc.o \
	$(ZEM_BUILD)/exec/zem_exec_call_label.o \
	$(ZEM_BUILD)/zem_rep.o \
	$(ZEM_BUILD)/zem_strip.o \
	$(ZEM_BUILD)/zem_hash.o \
	$(ZEM_BUILD)/zem_mem.o \
	$(ZEM_BUILD)/zem_heap.o \
	$(ZEM_BUILD)/zem_op.o \
	$(ZEM_BUILD)/zem_build.o \
	$(ZEM_BUILD)/zem_util.o \
	$(ZEM_BUILD)/zem_trace.o \
	$(ZEM_BUILD)/zem_cert.o \
	$(ZEM_BUILD)/zem.o \
	$(ZEM_BUILD)/jsonl.o

$(ZEM_BUILD)/%.o: src/zem/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zem -c $< -o $@

$(ZEM_BUILD)/exec/%.o: src/zem/exec/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zem -Isrc/zem/exec -c $< -o $@

$(ZEM_BUILD)/jsonl.o: src/zld/jsonl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

zem-host: | dirs
	$(MAKE) -C src/zem/host \
	  BUILD="$(abspath $(ZEM_HOST_BUILD))" \
	  CC="$(CC)" \
	  CFLAGS="$(CFLAGS)" \
	  AR="$(AR)" \
	  ARFLAGS="$(ARFLAGS)" \
	  $(abspath $(ZEM_HOST_LIBZING)) $(abspath $(ZEM_HOST_LIBHOPPER)) \
	  $(abspath $(ZEM_HOST_LIBCAP_ASYNC)) $(abspath $(ZEM_HOST_LIBCAP_EXEC))

zem: zem-host $(ZEM_OBJ) | dirs
	@cap_link_flags=""; \
	if [ "$(UNAME_S)" = "Darwin" ]; then \
	  cap_link_flags="-Wl,-force_load,$(abspath $(ZEM_HOST_LIBCAP_ASYNC)) -Wl,-force_load,$(abspath $(ZEM_HOST_LIBCAP_EXEC))"; \
	elif [ "$(UNAME_S)" = "Linux" ]; then \
	  cap_link_flags="-Wl,--whole-archive $(abspath $(ZEM_HOST_LIBCAP_ASYNC)) $(abspath $(ZEM_HOST_LIBCAP_EXEC)) -Wl,--no-whole-archive"; \
	else \
	  cap_link_flags="$(abspath $(ZEM_HOST_LIBCAP_ASYNC)) $(abspath $(ZEM_HOST_LIBCAP_EXEC))"; \
	fi; \
	$(CC) $(CFLAGS) $(ZEM_OBJ) $(ZEM_HOST_LIBZING) $$cap_link_flags $(ZEM_HOST_LIBHOPPER) -o $(BIN)/zem $(LDFLAGS)
	ln -sf $(PLATFORM)/zem $(BIN_ROOT)/zem

# Allow explicit file target builds, e.g. `make bin/$(PLATFORM)/zem`.
$(BIN)/zem: zem
	@true

.PHONY: zem zem-host

# ---- zop (opcode JSONL -> raw bytes) ----

ZOP_SRC := \
  src/zop/main.c

ZOP_OBJ := \
  $(ZOP_BUILD)/main.o

$(ZOP_BUILD)/%.o: src/zop/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zop -c $< -o $@

zop: $(ZOP_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZOP_OBJ) -o $(BIN)/zop $(LDFLAGS)
	ln -sf $(PLATFORM)/zop $(BIN_ROOT)/zop

.PHONY: zop

# ---- zir (IR JSONL -> opcode JSONL) ----

ZIR_SRC := \
  src/zir/main.c

ZIR_OBJ := \
  $(ZIR_BUILD)/main.o \
  $(ZIR_BUILD)/jsonl.o

$(ZIR_BUILD)/%.o: src/zir/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

$(ZIR_BUILD)/jsonl.o: src/zld/jsonl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

zir: $(ZIR_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZIR_OBJ) -o $(BIN)/zir $(LDFLAGS)
	ln -sf $(PLATFORM)/zir $(BIN_ROOT)/zir

.PHONY: zir

# ---- zxc (opcode -> native) ----

ZXC_SRC := \
  src/zxc/arm64.c \
  src/zxc/x86_64.c

ZXC_OBJ := \
  $(ZXC_BUILD)/arm64.o \
  $(ZXC_BUILD)/x86_64.o

ZXC_LIB := $(BIN)/libzxc.a
ZXC_CLI_OBJ := $(ZXC_BUILD)/main.o

$(ZXC_BUILD)/%.o: src/zxc/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zxc -c $< -o $@

zxc-lib: $(ZXC_LIB)

$(ZXC_LIB): $(ZXC_OBJ) | dirs
	@rm -f $@
	@ar rcs $@ $^

zxc: zxc-lib $(ZXC_CLI_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZXC_CLI_OBJ) -L$(BIN) -lzxc -o $(BIN)/zxc $(LDFLAGS)
	ln -sf $(PLATFORM)/zxc $(BIN_ROOT)/zxc

.PHONY: zxc zxc-lib

# ---- zcc (IR -> C) ----

zcc:
	$(MAKE) -C $(ZCC_DIR) \
	  CC="$(CC)" \
	  CFLAGS="$(CFLAGS)" \
	  CPPFLAGS="$(CPPFLAGS)" \
	  LDFLAGS="$(LDFLAGS)" \
	  BIN="$(abspath $(BIN))" \
	  BUILD="$(ZCC_BUILD_DIR)" \
	  ZASM_ROOT="$(CURDIR)"

.PHONY: zcc

# ---- zlnt (JSONL analyzer) ----

ZLNT_BUILD := $(BUILD)/zlnt

ZLNT_SRC := \
  src/zlnt/main.c \
  src/zld/jsonl.c

ZLNT_OBJ := \
  $(ZLNT_BUILD)/main.o \
  $(ZLNT_BUILD)/jsonl.o

$(ZLNT_BUILD)/%.o: src/zlnt/%.c $(VERSION_HEADER) | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -Isrc/zlnt -c $< -o $@

$(ZLNT_BUILD)/jsonl.o: src/zld/jsonl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

zlnt: $(ZLNT_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZLNT_OBJ) -o $(BIN)/zlnt $(LDFLAGS)
	ln -sf $(PLATFORM)/zlnt $(BIN_ROOT)/zlnt

.PHONY: zlnt

# ---- zrun (local Lembeh ABI test harness) ----

ZRUN_SRC := \
  src/zrun/main.c \
  src/zrun/host_abi.c \
  src/zrun/wasmtime_embed.c

ZRUN_OBJ := \
  $(ZRUN_BUILD)/main.o \
  $(ZRUN_BUILD)/host_abi.o \
  $(ZRUN_BUILD)/wasmtime_embed.o

ZRUN_CPPFLAGS := -I$(WASMTIME_C_API_DIR)/include
ZRUN_LDFLAGS := $(WASMTIME_C_API_DIR)/lib/libwasmtime.a
ZRUN_CFLAGS := $(CFLAGS) -Wno-strict-prototypes

ifeq ($(UNAME_S),Linux)
  ZRUN_LDFLAGS += -ldl -pthread -lm
endif
ifeq ($(UNAME_S),Darwin)
  ZRUN_LDFLAGS += -pthread
endif

$(ZRUN_BUILD)/%.o: src/zrun/%.c | dirs
	$(CC) $(CPPFLAGS) $(ZRUN_CPPFLAGS) $(ZRUN_CFLAGS) -Isrc/zrun -c $< -o $@

zrun: $(ZRUN_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZRUN_OBJ) -o $(BIN)/zrun $(LDFLAGS) $(ZRUN_LDFLAGS)
	ln -sf $(PLATFORM)/zrun $(BIN_ROOT)/zrun

# ---- helper tools ----

zasm-bin-wrap:
	@chmod +x tools/zasm_bin_wrap.py
