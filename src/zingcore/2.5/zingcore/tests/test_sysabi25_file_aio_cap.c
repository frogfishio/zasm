#include "zi_caps.h"
#include "zi_file_aio25.h"
#include "zi_handles25.h"
#include "zi_runtime25.h"
#include "zi_sys_loop25.h"
#include "zi_sysabi25.h"
#include "zi_zcl1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_u32le(uint8_t *p, uint32_t v) { zi_zcl1_write_u32(p, v); }

static void write_u64le(uint8_t *p, uint64_t v) {
  write_u32le(p + 0, (uint32_t)(v & 0xFFFFFFFFu));
  write_u32le(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

static uint64_t read_u64le(const uint8_t *p);

static void build_open_req(uint8_t req[40], const char *kind, const char *name, const void *params, uint32_t params_len) {
  write_u64le(req + 0, (uint64_t)(uintptr_t)kind);
  write_u32le(req + 8, (uint32_t)strlen(kind));
  write_u64le(req + 12, (uint64_t)(uintptr_t)name);
  write_u32le(req + 20, (uint32_t)strlen(name));
  write_u32le(req + 24, 0);
  write_u64le(req + 28, (uint64_t)(uintptr_t)params);
  write_u32le(req + 36, params_len);
}

static int write_all_handle(zi_handle_t h, const void *p, uint32_t n) {
  const uint8_t *b = (const uint8_t *)p;
  uint32_t off = 0;
  while (off < n) {
    int32_t w = zi_write(h, (zi_ptr_t)(uintptr_t)(b + off), (zi_size32_t)(n - off));
    if (w < 0) return (int)w;
    if (w == 0) return -1;
    off += (uint32_t)w;
  }
  return 0;
}

static int read_some(zi_handle_t h, uint8_t *buf, uint32_t cap, uint32_t *inout_have) {
  if (!buf || !inout_have || *inout_have >= cap) return 0;
  int32_t n = zi_read(h, (zi_ptr_t)(uintptr_t)(buf + *inout_have), (zi_size32_t)(cap - *inout_have));
  if (n < 0) return (int)n;
  if (n == 0) return -1;
  *inout_have += (uint32_t)n;
  return 1;
}

static void build_zcl1_req(uint8_t *out, uint16_t op, uint32_t rid, const uint8_t *payload, uint32_t payload_len) {
  memcpy(out + 0, "ZCL1", 4);
  zi_zcl1_write_u16(out + 4, 1);
  zi_zcl1_write_u16(out + 6, op);
  zi_zcl1_write_u32(out + 8, rid);
  zi_zcl1_write_u32(out + 12, 0);
  zi_zcl1_write_u32(out + 16, 0);
  zi_zcl1_write_u32(out + 20, payload_len);
  if (payload_len && payload) memcpy(out + 24, payload, payload_len);
}

static int expect_ok_frame(const uint8_t *fr, uint32_t fr_len, uint16_t op, uint32_t rid) {
  zi_zcl1_frame z;
  if (!zi_zcl1_parse(fr, fr_len, &z)) return 0;
  if (z.op != op || z.rid != rid) return 0;
  if (zi_zcl1_read_u32(fr + 12) != 1u) return 0;
  return 1;
}

static int loop_watch(zi_handle_t loop_h, zi_handle_t target_h, uint32_t events, uint64_t watch_id) {
  uint8_t watch_pl[20];
  zi_zcl1_write_u32(watch_pl + 0, (uint32_t)target_h);
  zi_zcl1_write_u32(watch_pl + 4, events);
  write_u64le(watch_pl + 8, watch_id);
  zi_zcl1_write_u32(watch_pl + 16, 0);

  uint8_t req[24 + 20];
  build_zcl1_req(req, (uint16_t)ZI_SYS_LOOP_OP_WATCH, 1u, watch_pl, (uint32_t)sizeof(watch_pl));
  if (write_all_handle(loop_h, req, (uint32_t)sizeof(req)) != 0) return 0;

  uint8_t fr[256];
  uint32_t have = 0;
  for (;;) {
    int r = read_some(loop_h, fr, (uint32_t)sizeof(fr), &have);
    if (r == ZI_E_AGAIN) continue;
    if (r <= 0) return 0;
    if (have >= 24) {
      uint32_t pl = zi_zcl1_read_u32(fr + 20);
      if (have >= 24u + pl) break;
    }
  }
  return expect_ok_frame(fr, have, (uint16_t)ZI_SYS_LOOP_OP_WATCH, 1u);
}

static int loop_wait_readable(zi_handle_t loop_h, zi_handle_t target_h, uint64_t watch_id, uint32_t timeout_ms) {
  uint8_t poll_pl[8];
  zi_zcl1_write_u32(poll_pl + 0, 8u); // max_events
  zi_zcl1_write_u32(poll_pl + 4, timeout_ms);

  uint8_t req[24 + sizeof(poll_pl)];
  build_zcl1_req(req, (uint16_t)ZI_SYS_LOOP_OP_POLL, 2u, poll_pl, (uint32_t)sizeof(poll_pl));
  if (write_all_handle(loop_h, req, (uint32_t)sizeof(req)) != 0) return 0;

  uint8_t fr[65536];
  uint32_t have = 0;
  for (;;) {
    int r = read_some(loop_h, fr, (uint32_t)sizeof(fr), &have);
    if (r == ZI_E_AGAIN) continue;
    if (r <= 0) return 0;
    if (have >= 24) {
      uint32_t pl = zi_zcl1_read_u32(fr + 20);
      if (have >= 24u + pl) break;
    }
  }

  zi_zcl1_frame z;
  if (!zi_zcl1_parse(fr, have, &z)) return 0;
  if (z.op != (uint16_t)ZI_SYS_LOOP_OP_POLL || z.rid != 2u) return 0;
  if (zi_zcl1_read_u32(fr + 12) != 1u) return 0;

  // payload:
  //   u32 ver
  //   u32 flags
  //   u32 count
  //   u32 reserved
  //   events[count] each 32 bytes
  if (z.payload_len < 16u) return 0;
  uint32_t count = zi_zcl1_read_u32(z.payload + 8);
  const uint8_t *p = z.payload + 16;
  uint32_t left = z.payload_len - 16u;
  for (uint32_t i = 0; i < count; i++) {
    if (left < 32u) return 0;
    uint32_t kind = zi_zcl1_read_u32(p + 0);
    uint32_t events = zi_zcl1_read_u32(p + 4);
    uint32_t handle = zi_zcl1_read_u32(p + 8);
    uint64_t id = read_u64le(p + 16);
    if (kind == 1u && handle == (uint32_t)target_h && id == watch_id && (events & 0x1u)) {
      return 1;
    }
    p += 32u;
    left -= 32u;
  }

  return 0;
}

static int read_full_frame_wait(zi_handle_t loop_h, zi_handle_t h, uint64_t watch_id, uint8_t *out, uint32_t cap, uint32_t timeout_ms) {
  uint32_t have = 0;
  while (have < 24) {
    int32_t r = zi_read(h, (zi_ptr_t)(uintptr_t)(out + have), (zi_size32_t)(cap - have));
    if (r == ZI_E_AGAIN) {
      if (!loop_wait_readable(loop_h, h, watch_id, timeout_ms)) return 0;
      continue;
    }
    if (r <= 0) return 0;
    have += (uint32_t)r;
  }
  uint32_t pl = zi_zcl1_read_u32(out + 20);
  uint32_t need = 24u + pl;
  if (need > cap) return 0;
  while (have < need) {
    int32_t r = zi_read(h, (zi_ptr_t)(uintptr_t)(out + have), (zi_size32_t)(need - have));
    if (r == ZI_E_AGAIN) {
      if (!loop_wait_readable(loop_h, h, watch_id, timeout_ms)) return 0;
      continue;
    }
    if (r <= 0) return 0;
    have += (uint32_t)r;
  }
  return (int)need;
}

static uint64_t read_u64le(const uint8_t *p) {
  uint64_t lo = (uint64_t)zi_zcl1_read_u32(p + 0);
  uint64_t hi = (uint64_t)zi_zcl1_read_u32(p + 4);
  return lo | (hi << 32);
}

int main(void) {
  zi_mem_v1 mem;
  zi_mem_v1_native_init(&mem);
  zi_runtime25_set_mem(&mem);

  zi_caps_reset_for_test();
  zi_handles25_reset_for_test();

  if (!zi_caps_init()) {
    fprintf(stderr, "zi_caps_init failed\n");
    return 1;
  }
  if (!zi_file_aio25_register()) {
    fprintf(stderr, "zi_file_aio25_register failed\n");
    return 1;
  }
  if (!zi_sys_loop25_register()) {
    fprintf(stderr, "zi_sys_loop25_register failed\n");
    return 1;
  }

  char root_template[] = "/tmp/zi_fs_root_XXXXXX";
  char *root = mkdtemp(root_template);
  if (!root) {
    perror("mkdtemp");
    return 1;
  }
  if (setenv("ZI_FS_ROOT", root, 1) != 0) {
    perror("setenv");
    return 1;
  }

  // Open file/aio
  uint8_t open_req[40];
  build_open_req(open_req, ZI_CAP_KIND_FILE, ZI_CAP_NAME_AIO, NULL, 0);
  zi_handle_t aio_h = zi_cap_open((zi_ptr_t)(uintptr_t)open_req);
  if (aio_h < 3) {
    fprintf(stderr, "file/aio open failed: %d\n", aio_h);
    return 1;
  }

  // Open sys/loop
  build_open_req(open_req, ZI_CAP_KIND_SYS, ZI_CAP_NAME_LOOP, NULL, 0);
  zi_handle_t loop_h = zi_cap_open((zi_ptr_t)(uintptr_t)open_req);
  if (loop_h < 3) {
    fprintf(stderr, "sys/loop open failed: %d\n", loop_h);
    (void)zi_end(aio_h);
    return 1;
  }

  const uint64_t WATCH_AIO = 0xA10A10A1ull;
  if (!loop_watch(loop_h, aio_h, 0x1u, WATCH_AIO)) {
    fprintf(stderr, "loop WATCH aio failed\n");
    (void)zi_end(loop_h);
    (void)zi_end(aio_h);
    return 1;
  }

  const char *guest_path = "/hello.txt";
  const char msg[] = "hello aio\n";

  // Submit OPEN (rid=1)
  uint8_t open_pl[20];
  write_u64le(open_pl + 0, (uint64_t)(uintptr_t)guest_path);
  write_u32le(open_pl + 8, (uint32_t)strlen(guest_path));
  write_u32le(open_pl + 12, ZI_FILE_O_READ | ZI_FILE_O_WRITE | ZI_FILE_O_CREATE | ZI_FILE_O_TRUNC);
  write_u32le(open_pl + 16, 0644);

  uint8_t req[24 + 64];
  build_zcl1_req(req, (uint16_t)ZI_FILE_AIO_OP_OPEN, 1u, open_pl, (uint32_t)sizeof(open_pl));
  if (write_all_handle(aio_h, req, 24u + (uint32_t)sizeof(open_pl)) != 0) {
    fprintf(stderr, "aio OPEN write failed\n");
    return 1;
  }

  uint8_t fr[65536];
  int n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !expect_ok_frame(fr, (uint32_t)n, (uint16_t)ZI_FILE_AIO_OP_OPEN, 1u)) {
    fprintf(stderr, "aio OPEN ack failed\n");
    return 1;
  }

  // Completion
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0) {
    fprintf(stderr, "aio OPEN done missing\n");
    return 1;
  }
  zi_zcl1_frame z;
  if (!zi_zcl1_parse(fr, (uint32_t)n, &z) || z.op != (uint16_t)ZI_FILE_AIO_EV_DONE || z.rid != 1u) {
    fprintf(stderr, "aio OPEN done bad frame\n");
    return 1;
  }
  if (zi_zcl1_read_u32(fr + 12) != 1u || z.payload_len != 16u) {
    fprintf(stderr, "aio OPEN done bad status/payload\n");
    return 1;
  }
  if (zi_zcl1_read_u16(z.payload + 0) != (uint16_t)ZI_FILE_AIO_OP_OPEN) {
    fprintf(stderr, "aio OPEN done orig_op mismatch\n");
    return 1;
  }
  uint64_t file_id = read_u64le(z.payload + 8);
  if (file_id == 0) {
    fprintf(stderr, "aio OPEN got file_id=0\n");
    return 1;
  }

  // Submit WRITE (rid=2)
  uint8_t write_pl[32];
  write_u64le(write_pl + 0, file_id);
  write_u64le(write_pl + 8, 0);
  write_u64le(write_pl + 16, (uint64_t)(uintptr_t)msg);
  write_u32le(write_pl + 24, (uint32_t)strlen(msg));
  write_u32le(write_pl + 28, 0);
  build_zcl1_req(req, (uint16_t)ZI_FILE_AIO_OP_WRITE, 2u, write_pl, (uint32_t)sizeof(write_pl));
  if (write_all_handle(aio_h, req, 24u + (uint32_t)sizeof(write_pl)) != 0) {
    fprintf(stderr, "aio WRITE write failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !expect_ok_frame(fr, (uint32_t)n, (uint16_t)ZI_FILE_AIO_OP_WRITE, 2u)) {
    fprintf(stderr, "aio WRITE ack failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !zi_zcl1_parse(fr, (uint32_t)n, &z) || z.op != (uint16_t)ZI_FILE_AIO_EV_DONE || z.rid != 2u) {
    fprintf(stderr, "aio WRITE done bad\n");
    return 1;
  }
  if (zi_zcl1_read_u32(fr + 12) != 1u || z.payload_len != 8u) {
    fprintf(stderr, "aio WRITE done bad status/payload\n");
    return 1;
  }
  if (zi_zcl1_read_u16(z.payload + 0) != (uint16_t)ZI_FILE_AIO_OP_WRITE) {
    fprintf(stderr, "aio WRITE done orig_op mismatch\n");
    return 1;
  }
  if (zi_zcl1_read_u32(z.payload + 4) != (uint32_t)strlen(msg)) {
    fprintf(stderr, "aio WRITE done result mismatch\n");
    return 1;
  }

  // Submit READ (rid=3)
  uint8_t read_pl[24];
  write_u64le(read_pl + 0, file_id);
  write_u64le(read_pl + 8, 0);
  write_u32le(read_pl + 16, 64u);
  write_u32le(read_pl + 20, 0u);
  build_zcl1_req(req, (uint16_t)ZI_FILE_AIO_OP_READ, 3u, read_pl, (uint32_t)sizeof(read_pl));
  if (write_all_handle(aio_h, req, 24u + (uint32_t)sizeof(read_pl)) != 0) {
    fprintf(stderr, "aio READ write failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !expect_ok_frame(fr, (uint32_t)n, (uint16_t)ZI_FILE_AIO_OP_READ, 3u)) {
    fprintf(stderr, "aio READ ack failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !zi_zcl1_parse(fr, (uint32_t)n, &z) || z.op != (uint16_t)ZI_FILE_AIO_EV_DONE || z.rid != 3u) {
    fprintf(stderr, "aio READ done bad\n");
    return 1;
  }
  if (zi_zcl1_read_u32(fr + 12) != 1u || z.payload_len < 8u) {
    fprintf(stderr, "aio READ done bad status/payload\n");
    return 1;
  }
  if (zi_zcl1_read_u16(z.payload + 0) != (uint16_t)ZI_FILE_AIO_OP_READ) {
    fprintf(stderr, "aio READ done orig_op mismatch\n");
    return 1;
  }
  uint32_t got = zi_zcl1_read_u32(z.payload + 4);
  if (got != (uint32_t)strlen(msg) || z.payload_len != 8u + got) {
    fprintf(stderr, "aio READ done length mismatch\n");
    return 1;
  }
  if (memcmp(z.payload + 8, msg, got) != 0) {
    fprintf(stderr, "aio READ content mismatch\n");
    return 1;
  }

  // Submit CLOSE (rid=4)
  uint8_t close_pl[8];
  write_u64le(close_pl, file_id);
  build_zcl1_req(req, (uint16_t)ZI_FILE_AIO_OP_CLOSE, 4u, close_pl, (uint32_t)sizeof(close_pl));
  if (write_all_handle(aio_h, req, 24u + (uint32_t)sizeof(close_pl)) != 0) {
    fprintf(stderr, "aio CLOSE write failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !expect_ok_frame(fr, (uint32_t)n, (uint16_t)ZI_FILE_AIO_OP_CLOSE, 4u)) {
    fprintf(stderr, "aio CLOSE ack failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !zi_zcl1_parse(fr, (uint32_t)n, &z) || z.op != (uint16_t)ZI_FILE_AIO_EV_DONE || z.rid != 4u) {
    fprintf(stderr, "aio CLOSE done bad\n");
    return 1;
  }
  if (zi_zcl1_read_u32(fr + 12) != 1u || z.payload_len != 8u) {
    fprintf(stderr, "aio CLOSE done bad status/payload\n");
    return 1;
  }

  // Sandbox escape should fail (completion error)
  const char *bad_path = "/../escape.txt";
  write_u64le(open_pl + 0, (uint64_t)(uintptr_t)bad_path);
  write_u32le(open_pl + 8, (uint32_t)strlen(bad_path));
  write_u32le(open_pl + 12, ZI_FILE_O_READ);
  write_u32le(open_pl + 16, 0);
  build_zcl1_req(req, (uint16_t)ZI_FILE_AIO_OP_OPEN, 5u, open_pl, (uint32_t)sizeof(open_pl));
  if (write_all_handle(aio_h, req, 24u + (uint32_t)sizeof(open_pl)) != 0) {
    fprintf(stderr, "aio OPEN(bad) write failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !expect_ok_frame(fr, (uint32_t)n, (uint16_t)ZI_FILE_AIO_OP_OPEN, 5u)) {
    fprintf(stderr, "aio OPEN(bad) ack failed\n");
    return 1;
  }
  n = read_full_frame_wait(loop_h, aio_h, WATCH_AIO, fr, (uint32_t)sizeof(fr), 1000u);
  if (n <= 0 || !zi_zcl1_parse(fr, (uint32_t)n, &z) || z.op != (uint16_t)ZI_FILE_AIO_EV_DONE || z.rid != 5u) {
    fprintf(stderr, "aio OPEN(bad) done bad\n");
    return 1;
  }
  if (zi_zcl1_read_u32(fr + 12) != 0u) {
    fprintf(stderr, "expected aio OPEN(bad) completion error\n");
    return 1;
  }

  (void)zi_end(loop_h);
  (void)zi_end(aio_h);

  printf("ok\n");
  return 0;
}
