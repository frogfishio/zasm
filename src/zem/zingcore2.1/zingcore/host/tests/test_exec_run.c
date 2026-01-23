/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../caps/ctl_common.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

static int contains_bytes(const uint8_t* hay, uint32_t hay_len,
                          const char* needle, size_t needle_len) {
  if (!hay || !needle || needle_len == 0 || hay_len < needle_len) return 0;
  for (uint32_t i = 0; i + needle_len <= hay_len; i++) {
    if (memcmp(hay + i, needle, needle_len) == 0) return 1;
  }
  return 0;
}

int32_t _ctl(const void *req_ptr, size_t req_len, void *resp_ptr, size_t resp_cap);
int32_t res_write(int32_t handle, const void *ptr, size_t len);
int32_t req_read(int32_t handle, void *ptr, size_t cap);

static void write_req_header(uint8_t *req, uint16_t op, uint32_t rid,
                             uint32_t payload_len) {
  memcpy(req + 0, "ZCL1", 4);
  ctl_write_u16(req + 4, 1);
  ctl_write_u16(req + 6, op);
  ctl_write_u32(req + 8, rid);
  ctl_write_u32(req + 12, 0);
  ctl_write_u32(req + 16, 0);
  ctl_write_u32(req + 20, payload_len);
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

static int open_async_handle(uint32_t rid, uint32_t* out_handle) {
  uint8_t req[128];
  uint8_t resp[128];
  const char kind[] = "async";
  const char name[] = "default";
  uint32_t payload_len = 4 + sizeof(kind) - 1 + 4 + sizeof(name) - 1 + 4 + 4 + 0;
  write_req_header(req, 3, rid, payload_len);
  uint32_t off = 24;
  ctl_write_u32(req + off, sizeof(kind) - 1); off += 4;
  memcpy(req + off, kind, sizeof(kind) - 1); off += sizeof(kind) - 1;
  ctl_write_u32(req + off, sizeof(name) - 1); off += 4;
  memcpy(req + off, name, sizeof(name) - 1); off += sizeof(name) - 1;
  ctl_write_u32(req + off, 0); off += 4;
  ctl_write_u32(req + off, 0); off += 4;
  int32_t n = _ctl(req, 24 + payload_len, resp, sizeof(resp));
  if (n <= 0) {
    return 10;
  }
  if ((uint32_t)n < 20 + 16) {
    return 11;
  }
  const uint8_t* p = resp + 20;
  uint32_t ok = ctl_read_u32(p);
  if (ok != 1) return 12;
  *out_handle = ctl_read_u32(p + 4);
  return 0;
}

static int parse_zax_frame(const uint8_t* buf, size_t len,
                           uint16_t* kind, uint16_t* op,
                           uint64_t* req_id, uint64_t* future_id,
                           const uint8_t** payload, uint32_t* payload_len) {
  if (len < 48) return 0;
  if (buf[0] != 'Z' || buf[1] != 'A' || buf[2] != 'X' || buf[3] != '1') return 0;
  *kind = (uint16_t)(buf[6] | (buf[7] << 8));
  *op = (uint16_t)(buf[8] | (buf[9] << 8));
  *req_id = (uint32_t)ctl_read_u32(buf + 12) | ((uint64_t)ctl_read_u32(buf + 16) << 32);
  *future_id = (uint32_t)ctl_read_u32(buf + 36) | ((uint64_t)ctl_read_u32(buf + 40) << 32);
  *payload_len = ctl_read_u32(buf + 44);
  if (48u + *payload_len > len) return 0;
  *payload = buf + 48;
  return 1;
}

static int build_exec_req(uint8_t* zax, size_t cap,
                          uint64_t req_id, uint64_t future_id,
                          const uint8_t* cmd_bytes,
                          uint32_t cmd_len_field, uint32_t cmd_actual_len) {
  const char kind[] = "exec";
  const char name[] = "default";
  const char selector[] = "exec.run.v1";
  uint32_t params_len = 4 + cmd_actual_len;
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  size_t need = 48u + payload_zax;
  if (need > cap) return -1;
  write_zax_header(zax, 1, 1, req_id, future_id, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, cmd_len_field); zoff += 4;
  if (cmd_actual_len) {
    memcpy(zax + zoff, cmd_bytes, cmd_actual_len);
    zoff += cmd_actual_len;
  }
  return (int)zoff;
}

static int wait_for_fail_code(uint32_t handle, uint64_t expect_rid,
                              uint64_t expect_fid, const char* expect_code) {
  uint8_t resp[512];
  int saw_ack = 0;
  int32_t rn = 0;
  size_t expect_code_len = strlen(expect_code);
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 101 && rid == expect_rid) saw_ack = 1;
      if (k == 2 && op == 111 && fid == expect_fid) {
        if (plen < 8) return 800;
        uint32_t code_len = ctl_read_u32(pay);
        uint32_t msg_len = ctl_read_u32(pay + 4);
        if (8u + code_len + msg_len != plen) return 801;
        if (code_len != expect_code_len) return 802;
        if (memcmp(pay + 8, expect_code, code_len) != 0) return 803;
        return saw_ack ? 0 : 804;
      }
      pos += 48u + plen;
    }
  }
  return 805;
}

int test_async_exec_run_echo(void) {
  uint32_t handle = 0;
  int orc = open_async_handle(810, &handle);
  if (orc != 0) {
    fprintf(stderr, "open_async_handle exec_run failed: %d\n", orc);
    return 200 + orc;
  }
  if (handle < 3) {
    fprintf(stderr, "exec_run bad handle %u\n", handle);
    return 199;
  }
  {
    char msg[64];
    int m = snprintf(msg, sizeof(msg), "exec_run handle=%u\n", handle);
    if (m > 0) write(STDOUT_FILENO, msg, (size_t)m);
  }
  uint8_t zax[256];
  const char kind[] = "exec";
  const char name[] = "default";
  const char selector[] = "exec.run.v1";
  const char cmd[] = "echo hi";
  uint32_t cmd_len = (uint32_t)sizeof(cmd) - 1;
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + cmd_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 502, 8100, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + cmd_len); zoff += 4;
  ctl_write_u32(zax + zoff, cmd_len); zoff += 4;
  memcpy(zax + zoff, cmd, cmd_len); zoff += cmd_len;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 212;
  uint8_t resp[256];
  int saw_ack = 0, saw_ok = 0, saw_fail = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 101 && rid == 502) saw_ack = 1;
      if (k == 2 && op == 111 && fid == 8100) {
        if (plen >= 8) {
          uint32_t code_len = ctl_read_u32(pay);
          uint32_t msg_len = ctl_read_u32(pay + 4);
          if (code_len + msg_len + 8 <= plen && code_len < 32) {
            char code[64], msg[128];
            memcpy(code, pay + 8, code_len); code[code_len] = 0;
            memcpy(msg, pay + 8 + code_len, msg_len < sizeof(msg) ? msg_len : sizeof(msg)-1);
            msg[msg_len < sizeof(msg) ? msg_len : sizeof(msg)-1] = 0;
            saw_fail = 1000 + (int)code_len;
          } else {
            saw_fail = 900;
          }
        } else {
          saw_fail = 800;
        }
      }
      if (k == 2 && op == 110 && fid == 8100) {
        if (plen < 4) return 213;
        uint32_t vlen = ctl_read_u32(pay);
        if (4u + vlen != plen) return 214;
        if (vlen < 4) return 215;
        uint32_t status = ctl_read_u32(pay + 4);
        if (status != 0) return 216;
        if (vlen < 6) return 217;
        /* output should contain "hi" */
        if (memcmp(pay + 8, "hi", 2) != 0) return 218;
        saw_ok = 1;
      }
      pos += 48u + plen;
    }
    if (saw_ack && saw_ok) break;
  }
  if (saw_fail) return 217 + saw_fail;
  if (!saw_ack || !saw_ok) return 299;
  return 0;
}

int test_async_exec_run_not_allowed(void) {
  uint32_t handle = 0;
  if (open_async_handle(820, &handle) != 0) return 400;
  const char cmd[] = "ls";
  uint8_t zax[256];
  int zlen = build_exec_req(zax, sizeof(zax), 8202, 8203,
                            (const uint8_t*)cmd, (uint32_t)(sizeof(cmd) - 1),
                            (uint32_t)(sizeof(cmd) - 1));
  if (zlen <= 0) return 401;
  if (res_write((int32_t)handle, zax, (size_t)zlen) <= 0) return 402;
  return wait_for_fail_code(handle, 8202, 8203, "t_exec_not_allowed");
}

int test_async_exec_run_nonzero(void) {
  uint32_t handle = 0;
  if (open_async_handle(821, &handle) != 0) return 420;
  const char cmd[] = "echo err >&2; exit 7";
  uint8_t zax[256];
  int zlen = build_exec_req(zax, sizeof(zax), 8212, 8213,
                            (const uint8_t*)cmd, (uint32_t)(sizeof(cmd) - 1),
                            (uint32_t)(sizeof(cmd) - 1));
  if (zlen <= 0) return 421;
  if (res_write((int32_t)handle, zax, (size_t)zlen) <= 0) return 422;
  uint8_t resp[512];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 101 && rid == 8212) saw_ack = 1;
      if (k == 2 && op == 110 && fid == 8213) {
        if (plen < 8) return 430;
        uint32_t vlen = ctl_read_u32(pay);
        if (4u + vlen != plen) return 431;
        if (vlen < 4) return 432;
        uint32_t status = ctl_read_u32(pay + 4);
        if (status != 7) return 433;
        if (vlen > 4) {
          const uint8_t* out = pay + 8;
          uint32_t out_len = vlen - 4;
          if (out_len < 3 || !contains_bytes(out, out_len, "err", 3)) return 434;
        } else {
          return 435;
        }
        saw_ok = 1;
      }
      pos += 48u + plen;
    }
    if (saw_ack && saw_ok) break;
  }
  return (saw_ack && saw_ok) ? 0 : 440;
}

int test_async_exec_run_bad_params(void) {
  uint32_t handle = 0;
  if (open_async_handle(822, &handle) != 0) return 450;
  const uint8_t cmd[] = { 'a', 'b', 'c' };
  uint8_t zax[256];
  int zlen = build_exec_req(zax, sizeof(zax), 8222, 8223,
                            cmd, 5, (uint32_t)sizeof(cmd));
  if (zlen <= 0) return 451;
  if (res_write((int32_t)handle, zax, (size_t)zlen) <= 0) return 452;
  return wait_for_fail_code(handle, 8222, 8223, "t_async_bad_params");
}

int test_async_exec_run_too_long(void) {
  uint32_t handle = 0;
  if (open_async_handle(823, &handle) != 0) return 470;
  uint8_t long_cmd[520];
  memset(long_cmd, 'x', sizeof(long_cmd));
  uint8_t zax[640];
  int zlen = build_exec_req(zax, sizeof(zax), 8232, 8233,
                            long_cmd, (uint32_t)sizeof(long_cmd),
                            (uint32_t)sizeof(long_cmd));
  if (zlen <= 0) return 471;
  if (res_write((int32_t)handle, zax, (size_t)zlen) <= 0) return 472;
  return wait_for_fail_code(handle, 8232, 8233, "t_exec_bad_params");
}
