# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

# zasm (zas) Makefile
# Builds:
#   bin/zas  (ZASM -> JSONL IR)

SHELL := /bin/bash
.ONESHELL:
.SUFFIXES:

CC      ?= clang
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS?= -Isrc/zas -Isrc/common -Ibuild/zas -Iinclude -Izcc/include
LDFLAGS ?=

# You can override these:
#   make BISON=/opt/homebrew/opt/bison/bin/bison FLEX=/opt/homebrew/opt/flex/bin/flex
BISON ?= bison
FLEX  ?= flex

BUILD := build
BIN   := bin
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

WASMTIME_C_API_DIR ?= external/wasmtime-c-api

ZAS_BUILD := $(BUILD)/zas
ZRUN_BUILD := $(BUILD)/zrun

ZCC_DIR := zcc
ZCC_BUILD_DIR := $(abspath $(BUILD))/zcc

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
  $(ZAS_BUILD)/zasm.tab.o \
  $(ZAS_BUILD)/lex.yy.o

ZAS_GEN_CFLAGS := $(CFLAGS) -Wno-sign-compare -Wno-unused-function -Wno-unneeded-internal-declaration

.PHONY: all clean zas zld zcc zrun zlnt dirs install test-hello test-wat test-loop-wat test-loop test-zrun-log test-ld-regreg test-add-hl-imm test-data-directives test-unknownsym test-compare-conds test-badcond test-badlabel test-bytes test-badmem test-arithmetic test-cat test-upper test-stream test-regmoves test-asm-suite test-alloc test-isa-smoke test-fuzz-zas test-fuzz-zld test-wat-validate test-wasm-opt test-linkage test-manifest test-str-equ test-zlnt test-fizzbuzz test-twofile test-strict test-trap

all: zas zld zcc

install: zas zld zcc zrun zlnt
	@mkdir -p $(DESTDIR)$(BINDIR)
	@install -m 0755 $(BIN)/zas $(DESTDIR)$(BINDIR)/zas
	@install -m 0755 $(BIN)/zld $(DESTDIR)$(BINDIR)/zld
	@install -m 0755 $(BIN)/zrun $(DESTDIR)$(BINDIR)/zrun
	@install -m 0755 $(BIN)/zlnt $(DESTDIR)$(BINDIR)/zlnt
	$(MAKE) -C $(ZCC_DIR) install \
	  DESTDIR="$(DESTDIR)" \
	  PREFIX="$(PREFIX)" \
	  BIN="$(abspath $(BIN))" \
	  BUILD="$(ZCC_BUILD_DIR)" \
	  ZASM_ROOT="$(CURDIR)"

dirs:
	mkdir -p $(BIN) $(ZAS_BUILD) $(ZLD_BUILD) $(ZRUN_BUILD) $(ZLNT_BUILD)

# --- Generator rules ---

# Bison (parser)
$(ZAS_BUILD)/zasm.tab.c $(ZAS_BUILD)/zasm.tab.h: src/zas/zasm.y | dirs
	$(BISON) -d -o $(ZAS_BUILD)/zasm.tab.c src/zas/zasm.y

# Flex (lexer) depends on the generated bison header
$(ZAS_BUILD)/lex.yy.c: src/zas/zasm.l $(ZAS_BUILD)/zasm.tab.h | dirs
	$(FLEX) -o $(ZAS_BUILD)/lex.yy.c src/zas/zasm.l

# --- Compile rules ---

$(ZAS_BUILD)/%.o: src/zas/%.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(ZAS_BUILD)/zasm.tab.o: $(ZAS_BUILD)/zasm.tab.c $(ZAS_BUILD)/zasm.tab.h | dirs
	$(CC) $(CPPFLAGS) $(ZAS_GEN_CFLAGS) -c $(ZAS_BUILD)/zasm.tab.c -o $@

$(ZAS_BUILD)/lex.yy.o: $(ZAS_BUILD)/lex.yy.c $(ZAS_BUILD)/zasm.tab.h | dirs
	$(CC) $(CPPFLAGS) $(ZAS_GEN_CFLAGS) -c $(ZAS_BUILD)/lex.yy.c -o $@

# --- Link ---

zas: $(ZAS_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZAS_OBJ) -o $(BIN)/zas $(LDFLAGS)

# --- Quick sanity test ---

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

test-ld-regreg: zas zld
	cat examples/cat.asm | $(BIN)/zas | $(BIN)/zld > build/cat.wat
	@rg -q -F 'local.get $$HL' build/cat.wat
	@rg -q -F 'local.set $$DE' build/cat.wat

test-add-hl-imm: zas zld
	cat examples/ptrstep.asm | $(BIN)/zas | $(BIN)/zld > build/ptrstep.wat
	@awk '/local.get .*HL/{getline a; getline b; getline c; if (a ~ /i32.const 4/ && b ~ /i32.add/ && c ~ /local.set .*HL/) f=1} END{exit !f}' build/ptrstep.wat
	@awk '/local.get .*HL/{getline a; getline b; getline c; if (a ~ /i32.const 8/ && b ~ /i32.add/ && c ~ /local.set .*HL/) f=1} END{exit !f}' build/ptrstep.wat

test-data-directives: zas zld zrun
	cat examples/data.asm | $(BIN)/zas | $(BIN)/zld > build/data.wat
	@rg -q -F '(global $$msg i32 (i32.const ' build/data.wat
	@rg -q -F '(global $$msg_len i32 (i32.const 3))' build/data.wat
	@rg -q -F '(global $$buf i32 (i32.const ' build/data.wat
	@awk '/A\\0a\\00/ {found=1} END{exit !found}' build/data.wat
	$(BIN)/zrun build/data.wat > build/data.out 2>build/data.err
	@od -An -tx1 build/data.out | tr -d ' \\n' | rg -q '^410a00$$'

test-unknownsym: zas zld
	@bash -ec 'if cat examples/unknownsym.asm | $(BIN)/zas | $(BIN)/zld > /tmp/unknownsym.wat 2>/tmp/unknownsym.err; then echo "expected failure"; exit 1; fi; rg -q "unknown symbol does_not_exist" /tmp/unknownsym.err'

test-compare-conds: zas zld
	cat examples/compare_conds.asm | $(BIN)/zas | $(BIN)/zld > build/compare_conds.wat

test-arithmetic: zas zld
	cat examples/arithmetic.asm | $(BIN)/zas | $(BIN)/zld > build/arithmetic.wat

test-regmoves: zas zld
	cat examples/regmoves.asm | $(BIN)/zas | $(BIN)/zld > build/regmoves.wat

test-fizzbuzz: zas zld zrun
	cat examples/fizzbuzz.asm | $(BIN)/zas | $(BIN)/zld > build/fizzbuzz.wat
	$(BIN)/zrun build/fizzbuzz.wat > build/fizzbuzz.out 2>build/fizzbuzz.err
	@rg -q -F 'FizzBuzz' build/fizzbuzz.out

test-twofile: zas zld zrun
	cat examples/hello_twofile.asm examples/lib_hello.asm | $(BIN)/zas | $(BIN)/zld > build/twofile.wat
	$(BIN)/zrun build/twofile.wat > build/twofile.out 2>build/twofile.err
	@rg -q -F 'Hello from lib' build/twofile.out

test-strict: zas zld zrun
	cat examples/bad_strict.asm | $(BIN)/zas | $(BIN)/zld > build/bad_strict.wat
	@$(BIN)/zrun build/bad_strict.wat > build/bad_strict.out 2>build/bad_strict.err
	@bash -ec "if $(BIN)/zrun --strict build/bad_strict.wat > build/bad_strict_strict.out 2>build/bad_strict_strict.err; then echo \"expected strict failure\"; exit 1; fi; rg -q -F 'res_write OOB' build/bad_strict_strict.err"

test-trap: zas zld zrun
	cat examples/bad_trap.asm | $(BIN)/zas | $(BIN)/zld > build/bad_trap.wat
	@bash -ec "if $(BIN)/zrun build/bad_trap.wat > build/bad_trap.out 2>build/bad_trap.err; then echo \"expected trap\"; exit 1; fi; rg -q -F 'trap' build/bad_trap.err"

test-cat: zas zld zrun
	test/run.sh examples/cat.asm test/fixtures/cat.in test/fixtures/cat.out

test-upper: zas zld zrun
	test/run.sh examples/upper.asm test/fixtures/upper.in test/fixtures/upper.out

test-alloc: zas zld zrun
	test/run.sh examples/alloc.asm test/fixtures/alloc.in test/fixtures/alloc.out

test-isa-smoke: zas zld zrun
	test/run.sh examples/isa_smoke.asm test/fixtures/isa_smoke.in test/fixtures/isa_smoke.out

test-stream: test-cat test-upper

test-asm-suite: test-data-directives test-regmoves test-arithmetic test-compare-conds test-bytes test-cat test-upper test-alloc test-isa-smoke test-linkage test-manifest test-str-equ test-zlnt test-fuzz-zld test-wat-validate test-wasm-opt test-names test-fizzbuzz test-twofile test-strict test-trap

test-fuzz-zas: zas
	test/fuzz_zas.sh

test-fuzz-zld: zld
	test/fuzz_zld_jsonl.sh

test-names: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld --names > build/hello.names.wat
	@rg -q -F '(custom "name"' build/hello.names.wat

test-wat-validate: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld > build/hello.wat
	cat examples/loop.asm | $(BIN)/zas | $(BIN)/zld > build/loop.wat
	test/validate_wat.sh build/hello.wat build/loop.wat

test-wasm-opt: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld > build/hello.wat
	cat examples/loop.asm | $(BIN)/zas | $(BIN)/zld > build/loop.wat
	test/wasm_opt.sh build/hello.wat build/loop.wat

test-linkage: zas zld
	cat examples/export.asm | $(BIN)/zas | $(BIN)/zld > build/export.wat
	@rg -q -F '(export "main" (func $$main))' build/export.wat
	cat examples/extern.asm | $(BIN)/zas | $(BIN)/zld > build/extern.wat
	@rg -q -F '(import "env" "noop" (func $$noop (param i32 i32)))' build/extern.wat

test-manifest: zas zld
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zld --manifest > build/hello.manifest.json
	@rg -q -F '"manifest":"zasm-v1.0"' build/hello.manifest.json
	@rg -q -F '"lembeh_handle"' build/hello.manifest.json
	@rg -q -F '"_out"' build/hello.manifest.json

test-str-equ: zas zld zrun
	cat examples/str_equ.asm | $(BIN)/zas | $(BIN)/zld > build/str_equ.wat
	@rg -q -F '(global $$msg_len i32 (i32.const 3))' build/str_equ.wat
	@rg -q -F '(global $$buf_size i32 (i32.const 16))' build/str_equ.wat
	$(BIN)/zrun build/str_equ.wat > build/str_equ.out 2>build/str_equ.err
	@od -An -tx1 build/str_equ.out | tr -d ' \\n' | rg -q '^48690a$$'

test-zlnt: zas zlnt
	cat examples/hello.asm | $(BIN)/zas | $(BIN)/zlnt
	cat examples/upper.asm | $(BIN)/zas | $(BIN)/zlnt

test-badcond: zas zld
	@bash -ec 'if cat examples/badcond.asm | $(BIN)/zas | $(BIN)/zld > /tmp/badcond.wat 2>/tmp/badcond.err; then echo "expected failure"; exit 1; fi; rg -q "unknown JR condition WTF" /tmp/badcond.err'

test-badlabel: zas zld
	@bash -ec 'if cat examples/badlabel.asm | $(BIN)/zas | $(BIN)/zld > /tmp/badlabel.wat 2>/tmp/badlabel.err; then echo "expected failure"; exit 1; fi; rg -q "unknown label missing_label" /tmp/badlabel.err'

test-bytes: zas zld zrun
	cat examples/bytes.asm | $(BIN)/zas | $(BIN)/zld > build/bytes.wat
	$(BIN)/zrun build/bytes.wat > build/bytes.out 2>build/bytes.err
	@od -An -tx1 build/bytes.out | tr -d ' \\n' | rg -q '^41$$'

test-badmem: zas zld
	@bash -ec 'if cat examples/badmem.asm | $(BIN)/zas | $(BIN)/zld > /tmp/badmem.wat 2>/tmp/badmem.err; then echo "expected failure"; exit 1; fi; rg -q "only \\(HL\\) supported" /tmp/badmem.err'

test-zrun-log: zas zld zrun
	cat examples/log.asm | $(BIN)/zas | $(BIN)/zld > build/log.wat
	$(BIN)/zrun build/log.wat 1>/tmp/log.out 2>/tmp/log.err
	@rg -q "^\\[demo\\] hello" /tmp/log.err

clean:
	rm -rf $(BUILD) $(BIN)


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

$(ZLD_BUILD)/%.o: src/zld/%.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

zld: $(ZLD_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZLD_OBJ) -o $(BIN)/zld $(LDFLAGS)

.PHONY: zld

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

$(ZLNT_BUILD)/%.o: src/zlnt/%.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -Isrc/zlnt -c $< -o $@

$(ZLNT_BUILD)/jsonl.o: src/zld/jsonl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc/zld -c $< -o $@

zlnt: $(ZLNT_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZLNT_OBJ) -o $(BIN)/zlnt $(LDFLAGS)

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
ZRUN_LDFLAGS := -L$(WASMTIME_C_API_DIR)/lib -lwasmtime
ZRUN_CFLAGS := $(CFLAGS) -Wno-strict-prototypes

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  ZRUN_LDFLAGS += -ldl -pthread
endif
ifeq ($(UNAME_S),Darwin)
  ZRUN_LDFLAGS += -pthread -Wl,-rpath,$(WASMTIME_C_API_DIR)/lib
endif

$(ZRUN_BUILD)/%.o: src/zrun/%.c | dirs
	$(CC) $(CPPFLAGS) $(ZRUN_CPPFLAGS) $(ZRUN_CFLAGS) -Isrc/zrun -c $< -o $@

zrun: $(ZRUN_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZRUN_OBJ) -o $(BIN)/zrun $(LDFLAGS) $(ZRUN_LDFLAGS)
