CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
AR      ?= ar
ARFLAGS ?= rcs

BUILD       ?= build
DIST        ?= dist
DIST_DEBUG  ?= $(DIST)/debug
DIST_LIB    ?= $(DIST_DEBUG)/lib
DIST_INCLUDE?= $(DIST_DEBUG)/include

SRCDIR := zingcore/src
INCDIR := zingcore/include
TESTDIR := zingcore/tests

LIB := $(BUILD)/libzingcore25.a

SRC := \
	$(SRCDIR)/zingcore25.c \
	$(SRCDIR)/zi_caps.c \
	$(SRCDIR)/zi_async.c \
	$(SRCDIR)/zi_problem.c \
	$(SRCDIR)/zi_telemetry.c

OBJ := \
	$(BUILD)/zingcore25.o \
	$(BUILD)/zi_caps.o \
	$(BUILD)/zi_async.o \
	$(BUILD)/zi_problem.o \
	$(BUILD)/zi_telemetry.o

TESTS := test_caps test_async_registry test_zingcore25_api test_problem test_telemetry_jsonl

.PHONY: test

.PHONY: all clean dirs dist-dirs dist-debug

all: dirs $(LIB)

dirs:
	mkdir -p $(BUILD)

dist-dirs:
	mkdir -p $(DIST_LIB) $(DIST_INCLUDE)

$(BUILD)/%.o: $(SRCDIR)/%.c | dirs
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(BUILD)/test_%.o: $(TESTDIR)/test_%.c | dirs
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^

test: $(LIB) $(addprefix $(BUILD)/,$(addsuffix .o,$(TESTS)))
	@set -e; \
	for t in $(TESTS); do \
	  bin="$(BUILD)/$$t"; \
	  $(CC) $(CFLAGS) "$(BUILD)/$$t.o" $(LIB) -o "$$bin"; \
	  "$$bin"; \
	done

dist-debug: all dist-dirs
	cp $(LIB) $(DIST_LIB)/
	rsync -a $(INCDIR)/ $(DIST_INCLUDE)/

clean:
	rm -rf $(BUILD) $(DIST)
