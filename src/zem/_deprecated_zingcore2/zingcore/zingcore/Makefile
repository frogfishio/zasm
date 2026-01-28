CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra
AR      ?= ar
ARFLAGS ?= rcs

SANITIZE ?=
ifeq ($(SANITIZE),address)
CFLAGS += -fsanitize=address -fno-omit-frame-pointer
endif

BUILD ?= build

HOPPER_DIR ?= ../ext/hopper
HOPPER_INC ?= $(HOPPER_DIR)/include
HOPPER_LIB_SRC ?= $(HOPPER_DIR)/lib/libhopper.a
HOPPER_LIB ?= $(BUILD)/libhopper.a

CFLAGS += -Iinclude -I$(HOPPER_INC)

CORE_OBJS = \
	$(BUILD)/caps/ctl_common.o \
	$(BUILD)/src/zi_async.o \
	$(BUILD)/src/zi_hopper.o \
	$(BUILD)/src/zingcore.o

CORE_LIB = $(BUILD)/libzingcore.a

CAP_ASYNC_OBJS = \
	$(BUILD)/caps/async/cap_async_simple.o \
	$(BUILD)/caps/async/selector_ping.o \
	$(BUILD)/caps/async/selector_pending.o
CAP_ASYNC_LIB = $(BUILD)/libzingcap_async.a

CAP_EXEC_OBJS = \
	$(BUILD)/caps/exec/selector_exec_fake.o \
	$(BUILD)/caps/exec/selector_exec_run.o
CAP_EXEC_LIB = $(BUILD)/libzingcap_exec.a

CAP_NET_OBJS = \
	$(BUILD)/caps/net/selector_net_echo.o \
	$(BUILD)/caps/net/selector_net_loop.o \
	$(BUILD)/caps/net/selector_net_tcp_connect.o \
	$(BUILD)/caps/net/selector_net_tcp_listen.o \
	$(BUILD)/caps/net/selector_net_tcp_accept.o
CAP_NET_LIB = $(BUILD)/libzingcap_net.a

CAP_FILES_OBJS = \
	$(BUILD)/caps/files/cap_files_cap.o \
	$(BUILD)/caps/files/selector_files_list.o \
	$(BUILD)/caps/files/selector_files_open.o \
	$(BUILD)/caps/files/selector_files_create.o \
	$(BUILD)/caps/files/selector_files_overwrite.o \
	$(BUILD)/caps/files/selector_files_truncate.o \
	$(BUILD)/caps/files/selector_files_seek.o \
	$(BUILD)/caps/files/selector_files_delete.o \
	$(BUILD)/caps/files/selector_files_write_all_path.o \
	$(BUILD)/caps/files/selector_files_read_all_path.o \
	$(BUILD)/caps/files/files_store.o
CAP_FILES_LIB = $(BUILD)/libzingcap_files.a

CAP_REACTOR_OBJS = \
	$(BUILD)/caps/reactor/cap_reactor.o
CAP_REACTOR_LIB = $(BUILD)/libzingcap_reactor.a

CAP_IO_OBJS = \
	$(BUILD)/caps/io/cap_io_stdout.o \
	$(BUILD)/caps/io/selector_io_write_bytes.o \
	$(BUILD)/caps/io/selector_io_write_i32.o \
	$(BUILD)/caps/io/selector_io_write_u32.o \
	$(BUILD)/caps/io/selector_io_write_i64.o \
	$(BUILD)/caps/io/selector_io_write_u64.o \
	$(BUILD)/caps/io/selector_io_pump_bytes.o \
	$(BUILD)/caps/io/selector_io_pump_bytes_stages.o
CAP_IO_LIB = $(BUILD)/libzingcap_io.a

.PHONY: all clean dirs dist

all: dirs $(HOPPER_LIB) $(CORE_LIB) $(CAP_ASYNC_LIB) $(CAP_EXEC_LIB) $(CAP_NET_LIB) $(CAP_FILES_LIB) $(CAP_REACTOR_LIB) $(CAP_IO_LIB)

dirs:
	mkdir -p $(BUILD)

$(HOPPER_LIB): $(HOPPER_LIB_SRC) | dirs
	cp $< $@

$(CORE_LIB): $(CORE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(CAP_ASYNC_LIB): $(CAP_ASYNC_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(CAP_EXEC_LIB): $(CAP_EXEC_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(CAP_NET_LIB): $(CAP_NET_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(CAP_FILES_LIB): $(CAP_FILES_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(CAP_REACTOR_LIB): $(CAP_REACTOR_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(CAP_IO_LIB): $(CAP_IO_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

dist: all
	@mkdir -p dist/lib dist/include dist/caps
	cp $(CORE_LIB) $(CAP_ASYNC_LIB) $(CAP_EXEC_LIB) $(CAP_NET_LIB) $(CAP_FILES_LIB) $(CAP_REACTOR_LIB) $(CAP_IO_LIB) dist/lib/
	cp $(HOPPER_LIB) dist/lib/
	rsync -a include/ dist/include/
	rsync -a caps/ctl_common.h dist/caps/

clean:
	rm -rf $(BUILD) dist
