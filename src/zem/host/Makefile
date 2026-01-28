CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra
AR      ?= ar
ARFLAGS ?= rcs

BUILD       ?= ../build
DIST        ?= ../dist
DIST_DEBUG  ?= $(DIST)/debug
DIST_LIB    ?= $(DIST_DEBUG)/lib
DIST_INCLUDE?= $(DIST_DEBUG)/include
DIST_CAP    ?= $(DIST_DEBUG)/cap
DIST_TESTS  ?= $(DIST_DEBUG)/tests
HOPPER_LIB_SRC ?= hopper/lib/libhopper.a
HOPPER_INC     ?= hopper/include
HOPPER_LIB     ?= $(BUILD)/libhopper.a

CFLAGS += -I$(HOPPER_INC)

ZINGCORE_OBJS = $(BUILD)/ctl_common.o $(BUILD)/zi_async.o $(BUILD)/zi_hopper.o $(BUILD)/zingcore.o
ZINGMAIN_OBJ = $(BUILD)/main.o $(BUILD)/test_files.o $(BUILD)/test_exec.o $(BUILD)/test_exec_run.o $(BUILD)/test_net.o $(BUILD)/test_net_loop.o $(BUILD)/test_hopper.o
ZINGCAP_ASYNC_OBJ = $(BUILD)/cap_async.o $(BUILD)/cap_async_ping.o $(BUILD)/cap_async_pending.o
ZINGCAP_EXEC_OBJ = $(BUILD)/cap_exec_run.o
ZINGCAP_NET_OBJ  = $(BUILD)/cap_net_echo.o $(BUILD)/cap_net_loop.o
ZINGCAP_FILES_OBJ = $(BUILD)/cap_files_cap.o $(BUILD)/cap_files_list.o $(BUILD)/cap_files_open.o $(BUILD)/cap_files_create.o $(BUILD)/cap_files_overwrite.o $(BUILD)/cap_files_truncate.o $(BUILD)/cap_files_seek.o $(BUILD)/cap_files_delete.o $(BUILD)/files_store.o

ZINGCORE_LIB = $(BUILD)/libzingcore.a
ZINGMAIN_LIB = $(BUILD)/libzingmain.a
ZINGCAP_ASYNC_LIB = $(BUILD)/libzingcap_async.a
ZINGCAP_EXEC_LIB = $(BUILD)/libzingcap_exec.a
ZINGCAP_NET_LIB = $(BUILD)/libzingcap_net.a
ZINGCAP_FILES_LIB = $(BUILD)/libzingcap_files.a

.PHONY: all clean dirs dist-dirs dist-debug

all: dirs $(HOPPER_LIB) $(ZINGCORE_LIB) $(ZINGMAIN_LIB) $(ZINGCAP_ASYNC_LIB) $(ZINGCAP_EXEC_LIB) $(ZINGCAP_NET_LIB) $(ZINGCAP_FILES_LIB)

dirs:
	mkdir -p $(BUILD)

dist-dirs:
	mkdir -p $(DIST_LIB) $(DIST_INCLUDE) $(DIST_CAP) $(DIST_TESTS) $(DIST_DEBUG)/src

$(BUILD)/ctl_common.o: cap/ctl_common.c cap/ctl_common.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/zi_async.o: zi_async.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/zi_hopper.o: zi_hopper.c include/zi_hopper.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/zingcore.o: zingcore.c cap/ctl_common.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/main.o: main.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_files.o: tests/test_files.c tests/test_files.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_exec.o: tests/test_exec.c tests/test_exec.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_net.o: tests/test_net.c tests/test_net.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_hopper.o: tests/test_hopper.c tests/test_hopper.h include/zi_hopper.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_exec_run.o: tests/test_exec_run.c tests/test_exec.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_net_loop.o: tests/test_net_loop.c tests/test_net_loop.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_async.o: cap/async/cap_async_simple.c cap/ctl_common.h include/zi_caps.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_async_ping.o: cap/async/selector_ping.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_async_pending.o: cap/async/selector_pending.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_exec_run.o: cap/async/exec/selector_exec_run.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_net_echo.o: cap/async/net/selector_net_echo.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_net_loop.o: cap/async/net/selector_net_loop.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_list.o: cap/files/selector_files_list.c include/zi_async.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_cap.o: cap/files/cap_files_cap.c cap/ctl_common.h include/zi_caps.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_open.o: cap/files/selector_files_open.c include/zi_async.h include/zi_handles.h cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_create.o: cap/files/selector_files_create.c include/zi_async.h cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_delete.o: cap/files/selector_files_delete.c include/zi_async.h cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_overwrite.o: cap/files/selector_files_overwrite.c include/zi_async.h cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_truncate.o: cap/files/selector_files_truncate.c include/zi_async.h cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/cap_files_seek.o: cap/files/selector_files_seek.c include/zi_async.h include/zi_handles.h cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/files_store.o: cap/files/files_store.c cap/files/files_store.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(ZINGCORE_LIB): $(ZINGCORE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(ZINGMAIN_LIB): $(ZINGMAIN_OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(ZINGCAP_ASYNC_LIB): $(ZINGCAP_ASYNC_OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(ZINGCAP_EXEC_LIB): $(ZINGCAP_EXEC_OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(ZINGCAP_NET_LIB): $(ZINGCAP_NET_OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(ZINGCAP_FILES_LIB): $(ZINGCAP_FILES_OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(HOPPER_LIB): $(HOPPER_LIB_SRC) | dirs
	cp $< $@

dist-debug: all dist-dirs
	cp $(ZINGCORE_LIB) $(ZINGCAP_ASYNC_LIB) $(ZINGCAP_EXEC_LIB) $(ZINGCAP_NET_LIB) $(ZINGCAP_FILES_LIB) $(ZINGMAIN_LIB) $(DIST_LIB)/
	cp $(HOPPER_LIB) $(DIST_LIB)/
	rsync -a include/ $(DIST_INCLUDE)/
	rsync -a $(HOPPER_INC)/hopper.h $(DIST_INCLUDE)/
	rsync -a cap/ctl_common.h $(DIST_CAP)/
	rsync -a tests/ $(DIST_TESTS)/
	cp main.c $(DIST_DEBUG)/src/main.c
	cp dist/hopper_sample.c $(DIST_DEBUG)/src/hopper_sample.c
	cp dist/README_DEBUG.md $(DIST_DEBUG)/README.md

clean:
	rm -rf $(BUILD)
