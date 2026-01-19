/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later
//
#include "../caps/ctl_common.h"
#include "tests/test_files.h"
#include "tests/test_exec.h"
#include "tests/test_net.h"
#include "tests/test_net_loop.h"
#include "tests/test_hopper.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// Zing ABI surface we are validating.
uintptr_t zi_str_concat(const void *a, const void *b);
void _free(uintptr_t ptr);
int32_t _ctl(const void *req_ptr, size_t req_len,
             void *resp_ptr, size_t resp_cap);
int32_t res_write(int32_t handle, const void *ptr, size_t len);
int32_t req_read(int32_t handle, void *ptr, size_t cap);

static const char k_async_kind[] = "async";
static const char k_async_name[] = "default";

enum {
  TAG_STR = 3,
  STR_HEADER = 8,
};

typedef struct {
  uint32_t tag;
  uint32_t len;
  unsigned char bytes[];
} zi_str_t;

static int verify_concat(void) {
  static const struct {
    uint32_t tag;
    uint32_t len;
    unsigned char bytes[6];
  } a = { TAG_STR, 6, { 'h', 'e', 'l', 'l', 'o', ' ' } };
  static const struct {
    uint32_t tag;
    uint32_t len;
    unsigned char bytes[5];
  } b = { TAG_STR, 5, { 'w', 'o', 'r', 'l', 'd' } };

  uintptr_t addr = zi_str_concat(&a, &b);
  if (!addr) return 1;

  zi_str_t *out = (zi_str_t *)addr;
  int ret = 0;
  if (out->tag != TAG_STR) {
    ret = 2;
    goto done;
  }
  if (out->len != 11) {
    ret = 3;
    goto done;
  }
  static const unsigned char expected[] =
      { 'h','e','l','l','o',' ','w','o','r','l','d' };
  if (memcmp(out->bytes, expected, sizeof(expected)) != 0) {
    ret = 4;
    goto done;
  }

  (void)write(STDOUT_FILENO, "hello world\n", 12);

done:
  _free((uintptr_t)out);
  return ret;
}

static void write_req_header(uint8_t *req, uint16_t op, uint32_t rid,
                             uint32_t payload_len) {
  memcpy(req + 0, "ZCL1", 4);
  ctl_write_u16(req + 4, 1);
  ctl_write_u16(req + 6, op);
  ctl_write_u32(req + 8, rid);
  ctl_write_u32(req + 12, 0); /* timeout_ms */
  ctl_write_u32(req + 16, 0); /* flags */
  ctl_write_u32(req + 20, payload_len);
}

static int test_caps_list_async(void) {
  uint8_t req[24];
  uint8_t resp[128];
  write_req_header(req, 1, 1, 0);
  int32_t nresp = _ctl(req, sizeof(req), resp, sizeof(resp));
  if (nresp <= 0) return 10;
  if (memcmp(resp, "ZCL1", 4) != 0) return 11;
  if (ctl_read_u16(resp + 6) != 1) return 12;
  if (ctl_read_u32(resp + 8) != 1) return 13;
  uint32_t payload_len = ctl_read_u32(resp + 16);
  if (20u + payload_len != (uint32_t)nresp) return 14;
  if (payload_len < 8) return 15;
  const uint8_t *payload = resp + 20;
  if (payload[0] != 1) return 16;
  uint32_t n = ctl_read_u32(payload + 4);
  if (n < 2) return 17;
  uint32_t off = 8;
  const char* expect[][2] = { {"async","default"}, {"file","view"} };
  for (uint32_t i = 0; i < n && i < 2; i++) {
    uint32_t kind_len = ctl_read_u32(payload + off); off += 4;
    if (off + kind_len > payload_len) return 18;
    if (kind_len != strlen(expect[i][0]) ||
        memcmp(payload + off, expect[i][0], kind_len) != 0) return 19;
    off += kind_len;
    uint32_t name_len = ctl_read_u32(payload + off); off += 4;
    if (off + name_len > payload_len) return 20;
    if (name_len != strlen(expect[i][1]) ||
        memcmp(payload + off, expect[i][1], name_len) != 0) return 21;
    off += name_len;
    uint32_t cap_flags = ctl_read_u32(payload + off); off += 4;
    (void)cap_flags;
    if (off + 4 > payload_len) return 23;
    uint32_t meta_len = ctl_read_u32(payload + off); off += 4;
    if (off + meta_len > payload_len) return 24;
    off += meta_len;
  }
  return 0;
}

static int test_unknown_op_trace(void) {
  uint8_t req[24];
  uint8_t resp[128];
  write_req_header(req, 0xFF, 5, 0);
  int32_t n = _ctl(req, sizeof(req), resp, sizeof(resp));
  if (n <= 0) return 20;
  uint32_t payload_len = ctl_read_u32(resp + 16);
  if (20u + payload_len != (uint32_t)n) return 21;
  const uint8_t *payload = resp + 20;
  if (payload_len < 12) return 22;
  if (payload[0] != 0) return 23;
  uint32_t off = 4;
  uint32_t trace_len = ctl_read_u32(payload + off); off += 4;
  if (off + trace_len > payload_len) return 24;
  static const char expect[] = "t_ctl_unknown_op";
  if (trace_len != sizeof(expect) - 1) return 25;
  if (memcmp(payload + off, expect, trace_len) != 0) return 26;
  return 0;
}

static int check_cap_missing(uint16_t op) {
  uint8_t req[128];
  uint8_t resp[128];
  /* build payload: kind="foo", name="bar" (+ mode/params if open) */
  const char kind[] = "foo";
  const char name[] = "bar";
  uint32_t payload_len = 4 + sizeof(kind) - 1 + 4 + sizeof(name) - 1;
  uint32_t params_len = 0;
  if (op == 3) {
    payload_len += 4; /* mode */
    payload_len += 4; /* params len */
  }
  write_req_header(req, op, 7 + op, payload_len);
  uint32_t off = 24;
  ctl_write_u32(req + off, sizeof(kind) - 1); off += 4;
  memcpy(req + off, kind, sizeof(kind) - 1); off += (uint32_t)(sizeof(kind) - 1);
  ctl_write_u32(req + off, sizeof(name) - 1); off += 4;
  memcpy(req + off, name, sizeof(name) - 1); off += (uint32_t)(sizeof(name) - 1);
  if (op == 3) {
    ctl_write_u32(req + off, 0); off += 4; /* mode */
    ctl_write_u32(req + off, params_len); off += 4;
  }
  int32_t n = _ctl(req, 24 + payload_len, resp, sizeof(resp));
  if (n <= 0) return 30;
  uint32_t payload_out = ctl_read_u32(resp + 16);
  if (20u + payload_out != (uint32_t)n) return 31;
  const uint8_t *p = resp + 20;
  if (p[0] != 0) return 32;
  uint32_t trace_len = ctl_read_u32(p + 4);
  if (4 + 4 + trace_len > payload_out) return 33;
  static const char expect[] = "t_cap_missing";
  if (trace_len != sizeof(expect) - 1) return 34;
  if (memcmp(p + 8, expect, trace_len) != 0) return 35;
  return 0;
}

static int test_caps_open_async(void) {
  uint8_t req[128];
  uint8_t resp[128];
  const char kind[] = "async";
  const char name[] = "default";
  uint32_t payload_len = 4 + sizeof(kind) - 1 + 4 + sizeof(name) - 1 + 4 + 4;
  write_req_header(req, 3, 9, payload_len);
  uint32_t off = 24;
  ctl_write_u32(req + off, sizeof(kind) - 1); off += 4;
  memcpy(req + off, kind, sizeof(kind) - 1); off += (uint32_t)(sizeof(kind) - 1);
  ctl_write_u32(req + off, sizeof(name) - 1); off += 4;
  memcpy(req + off, name, sizeof(name) - 1); off += (uint32_t)(sizeof(name) - 1);
  ctl_write_u32(req + off, 0); off += 4; /* mode */
  ctl_write_u32(req + off, 0); off += 4; /* params len */
  int32_t n = _ctl(req, 24 + payload_len, resp, sizeof(resp));
  if (n <= 0) return 40;
  uint32_t payload_out = ctl_read_u32(resp + 16);
  if (20u + payload_out != (uint32_t)n) return 41;
  const uint8_t *p = resp + 20;
  if (payload_out < 20) return 42;
  if (p[0] != 1) return 43;
  uint32_t handle = ctl_read_u32(p + 4);
  if (handle < 3) return 44;
  uint32_t hflags = ctl_read_u32(p + 8);
  if ((hflags & 1u) == 0 && (hflags & 2u) == 0) return 45;
  uint32_t meta_len = ctl_read_u32(p + 12);
  if (meta_len < 4) return 46;
  if (16u + meta_len > payload_out) return 47;
  uint32_t cap_bytes = ctl_read_u32(p + 16);
  if (cap_bytes != 1048576u) return 48;
  return 0;
}

static int32_t open_async_handle(uint32_t rid, uint32_t* out_handle) {
  uint8_t req[128];
  uint8_t resp[128];
  const char kind[] = "async";
  const char name[] = "default";
  uint32_t payload_len = 4 + sizeof(kind) - 1 + 4 + sizeof(name) - 1 + 4 + 4;
  write_req_header(req, 3, rid, payload_len);
  uint32_t off = 24;
  ctl_write_u32(req + off, sizeof(kind) - 1); off += 4;
  memcpy(req + off, kind, sizeof(kind) - 1); off += (uint32_t)(sizeof(kind) - 1);
  ctl_write_u32(req + off, sizeof(name) - 1); off += 4;
  memcpy(req + off, name, sizeof(name) - 1); off += (uint32_t)(sizeof(name) - 1);
  ctl_write_u32(req + off, 1); off += 4; /* mode */
  ctl_write_u32(req + off, 0); off += 4; /* params len */
  int32_t n = _ctl(req, 24 + payload_len, resp, sizeof(resp));
  if (n <= 0) return -1;
  uint32_t payload_out = ctl_read_u32(resp + 16);
  const uint8_t *p = resp + 20;
  if (payload_out < 16 || p[0] != 1) return -1;
  uint32_t handle = ctl_read_u32(p + 4);
  if (handle < 3) return -1;
  if (out_handle) *out_handle = handle;
  return 0;
}

static void write_zax_header(uint8_t* p, uint16_t kind, uint16_t op,
                             uint64_t req_id, uint64_t future_id,
                             uint32_t payload_len) {
  memcpy(p, "ZAX1", 4);
  p[4] = 1; p[5] = 0;
  p[6] = (uint8_t)(kind & 0xFF);
  p[7] = (uint8_t)(kind >> 8);
  p[8] = (uint8_t)(op & 0xFF);
  p[9] = (uint8_t)(op >> 8);
  p[10] = 0; p[11] = 0;
  ctl_write_u32(p + 12, (uint32_t)(req_id & 0xFFFFFFFFu));
  ctl_write_u32(p + 16, (uint32_t)(req_id >> 32));
  ctl_write_u32(p + 20, 0);
  ctl_write_u32(p + 24, 0);
  ctl_write_u32(p + 28, 0);
  ctl_write_u32(p + 32, 0);
  ctl_write_u32(p + 36, (uint32_t)(future_id & 0xFFFFFFFFu));
  ctl_write_u32(p + 40, (uint32_t)(future_id >> 32));
  ctl_write_u32(p + 44, payload_len);
}

static int parse_zax_frame(const uint8_t* buf, size_t len,
                           uint16_t* kind, uint16_t* op,
                           uint64_t* req_id, uint64_t* future_id,
                           const uint8_t** payload, uint32_t* payload_len) {
  if (len < 48) return 0;
  if (memcmp(buf, "ZAX1", 4) != 0) return 0;
  *kind = (uint16_t)(buf[6] | (buf[7] << 8));
  *op = (uint16_t)(buf[8] | (buf[9] << 8));
  uint32_t rid_lo = ctl_read_u32(buf + 12);
  uint32_t rid_hi = ctl_read_u32(buf + 16);
  *req_id = ((uint64_t)rid_hi << 32) | rid_lo;
  uint32_t fid_lo = ctl_read_u32(buf + 36);
  uint32_t fid_hi = ctl_read_u32(buf + 40);
  *future_id = ((uint64_t)fid_hi << 32) | fid_lo;
  *payload_len = ctl_read_u32(buf + 44);
  if (48u + *payload_len > len) return 0;
  *payload = buf + 48;
  return 1;
}

static int test_async_ping(void) {
  uint32_t handle = 0;
  if (open_async_handle(11, &handle) != 0) return 50;

  /* Build REGISTER_FUTURE for selector ping.v1 */
  uint8_t zax[256];
  const char selector[] = "ping.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_async_kind) - 1 +
                      4 + (uint32_t)sizeof(k_async_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 0;
  uint32_t payload_zax = 1 /* variant */ + 4 /* body len */ + body_len;
  write_zax_header(zax, 1, 1, 1, 42, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2; /* variant B */
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_async_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_async_kind, sizeof(k_async_kind) - 1); zoff += sizeof(k_async_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_async_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_async_name, sizeof(k_async_name) - 1); zoff += sizeof(k_async_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 0); zoff += 4; /* params len */
  int32_t wn = res_write((int32_t)handle, zax, zoff);
  if (wn <= 0) return 54;

  uint8_t zresp[512];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 101 && rid == 1) {
        saw_ack = 1;
      } else if (k == 2 && op == 110 && fid == 42) {
        if (plen < 4) return 56;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen != 2) return 57;
        if (pay[4] != 'o' || pay[5] != 'k') return 58;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  if (!saw_ack || !saw_ok) return 59;
  return 0;
}

int main(void) {
#define RUN_TEST(fn) do { const char msg_start[] = "-> " #fn "\n"; write(STDOUT_FILENO, msg_start, sizeof(msg_start)-1); int r_ = (fn); if (r_ != 0) { const char msg[] = #fn "\n"; write(STDERR_FILENO, msg, sizeof(msg)-1); return r_; } } while (0)
  RUN_TEST(verify_concat());
  RUN_TEST(test_caps_list_async());
  RUN_TEST(test_unknown_op_trace());
  RUN_TEST(check_cap_missing(2));
  RUN_TEST(check_cap_missing(3));
  RUN_TEST(test_caps_open_async());
  RUN_TEST(test_async_ping());
  RUN_TEST(test_async_files_list());
  RUN_TEST(test_async_files_open_read());
  RUN_TEST(test_async_files_create_and_list());
  RUN_TEST(test_async_files_write_update());
  RUN_TEST(test_async_files_overwrite());
  RUN_TEST(test_async_files_truncate_seek());
  RUN_TEST(test_async_files_seek_whence());
  RUN_TEST(test_async_files_concurrent_handles());
  RUN_TEST(test_async_files_errors());
  RUN_TEST(test_async_files_open_bad_params());
  RUN_TEST(test_async_files_create_bad_params());
  RUN_TEST(test_async_files_seek_bad_len());
  RUN_TEST(test_async_files_seek_bad_whence());
  RUN_TEST(test_async_join_cancel());
  RUN_TEST(test_async_join_cancel_cross_handle());
  RUN_TEST(test_async_payload_cap_meta());
  RUN_TEST(test_async_payload_cap());
  RUN_TEST(test_async_cancel());
  RUN_TEST(test_async_opaque_source());
  RUN_TEST(test_async_join_detach());
  RUN_TEST(test_async_timeout_cancel());
  RUN_TEST(test_async_files_delete());
  RUN_TEST(test_async_files_bad_scope());
  RUN_TEST(test_hopper_basic());
  RUN_TEST(test_hopper_bounds());
  RUN_TEST(test_async_exec_fake());
  RUN_TEST(test_async_exec_run_echo());
  RUN_TEST(test_async_exec_run_nonzero());
  RUN_TEST(test_async_exec_run_not_allowed());
  RUN_TEST(test_async_exec_run_bad_params());
  RUN_TEST(test_async_exec_run_too_long());
  RUN_TEST(test_async_net_echo());
  RUN_TEST(test_async_net_loop());
  RUN_TEST(test_async_net_connect_bad_params());
  RUN_TEST(test_async_net_send_overflow());
  RUN_TEST(test_async_net_send_badlen());
  return 0;
}
