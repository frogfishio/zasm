/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../../caps/ctl_common.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
  if (n <= 0) return 10;
  if ((uint32_t)n < 20 + 16) return 11;
  const uint8_t* p = resp + 20;
  if (ctl_read_u32(p) != 1) return 12;
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

static int wait_for_fail_code(uint32_t handle, uint64_t expect_rid,
                              uint64_t expect_fid, const char* expect_code) {
  uint8_t resp[512];
  int saw_ack = 0;
  int32_t rn = 0;
  size_t code_len = strlen(expect_code);
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
        uint32_t c_len = ctl_read_u32(pay);
        uint32_t m_len = ctl_read_u32(pay + 4);
        if (8u + c_len + m_len != plen) return 801;
        if (c_len != code_len) return 802;
        if (memcmp(pay + 8, expect_code, c_len) != 0) return 803;
        return saw_ack ? 0 : 804;
      }
      pos += 48u + plen;
    }
  }
  return 805;
}

static int net_connect(uint32_t async_handle, uint64_t req_id, uint64_t future_id, uint32_t* out_handle) {
  uint8_t zax[256];
  const char kind[] = "net";
  const char name[] = "default";
  const char sel_connect[] = "net.connect.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(sel_connect) - 1 +
                      4 + 0;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, req_id, future_id, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_connect) - 1); zoff += 4;
  memcpy(zax + zoff, sel_connect, sizeof(sel_connect) - 1); zoff += sizeof(sel_connect) - 1;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  if (res_write((int32_t)async_handle, zax, zoff) <= 0) return 10;

  uint8_t resp[256];
  int32_t rn = 0;
  while ((rn = req_read((int32_t)async_handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 110 && fid == future_id) {
        if (plen < 12) return 11;
        *out_handle = ctl_read_u32(pay);
        return (*out_handle != 0) ? 0 : 12;
      }
      if (k == 2 && op == 111 && fid == future_id) return 13;
      pos += 48u + plen;
    }
  }
  return 14;
}

int test_async_net_loop(void) {
  uint32_t handle = 0;
  if (open_async_handle(950, &handle) != 0) return 200;
  uint8_t zax[256];
  const char kind[] = "net";
  const char name[] = "default";
  const char sel_connect[] = "net.connect.v1";
  const char sel_send[] = "net.send.v1";
  const char sel_recv[] = "net.recv.v1";
  const char payload_data[] = "loop-data";

  /* connect */
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(sel_connect) - 1 +
                      4 + 0;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 700, 9500, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_connect) - 1); zoff += 4;
  memcpy(zax + zoff, sel_connect, sizeof(sel_connect) - 1); zoff += sizeof(sel_connect) - 1;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 201;
  uint32_t net_handle = 0;
  uint8_t resp[256];
  int saw_connect = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 110 && fid == 9500) {
        if (plen < 12) return 202;
        net_handle = ctl_read_u32(pay);
        saw_connect = 1;
      }
      pos += 48u + plen;
    }
    if (saw_connect) break;
  }
  if (!saw_connect || net_handle == 0) return 203;

  /* send */
  body_len = 4 + (uint32_t)sizeof(kind) - 1 +
             4 + (uint32_t)sizeof(name) - 1 +
             4 + (uint32_t)sizeof(sel_send) - 1 +
             4 + 8 + (uint32_t)sizeof(payload_data) - 1;
  payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 701, 9501, payload_zax);
  zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_send) - 1); zoff += 4;
  memcpy(zax + zoff, sel_send, sizeof(sel_send) - 1); zoff += sizeof(sel_send) - 1;
  ctl_write_u32(zax + zoff, 8 + (uint32_t)sizeof(payload_data) - 1); zoff += 4;
  ctl_write_u32(zax + zoff, net_handle); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(payload_data) - 1); zoff += 4;
  memcpy(zax + zoff, payload_data, sizeof(payload_data) - 1); zoff += sizeof(payload_data) - 1;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 204;

  /* recv */
  body_len = 4 + (uint32_t)sizeof(kind) - 1 +
             4 + (uint32_t)sizeof(name) - 1 +
             4 + (uint32_t)sizeof(sel_recv) - 1 +
             4 + 8;
  payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 702, 9502, payload_zax);
  zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_recv) - 1); zoff += 4;
  memcpy(zax + zoff, sel_recv, sizeof(sel_recv) - 1); zoff += sizeof(sel_recv) - 1;
  ctl_write_u32(zax + zoff, 8); zoff += 4;
  ctl_write_u32(zax + zoff, net_handle); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(payload_data) - 1); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 205;

  int saw_recv = 0;
  int saw_fail = 0;
  uint8_t agg[1024];
  size_t agg_len = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    if (agg_len + (size_t)rn < sizeof(agg)) {
      memcpy(agg + agg_len, resp, (size_t)rn);
      agg_len += (size_t)rn;
    }
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 111 && fid == 9502) saw_fail = 1;
      if (k == 2 && op == 110 && fid == 9502) {
        saw_recv = 1;
      }
      pos += 48u + plen;
    }
    if (saw_recv) break;
  }
  if (saw_fail) return 210;
  if (!saw_recv && agg_len == 0) return 211;
  return saw_recv ? 0 : 212;
}

int test_async_net_connect_bad_params(void) {
  uint32_t handle = 0;
  if (open_async_handle(960, &handle) != 0) return 300;
  uint8_t zax[256];
  const char kind[] = "net";
  const char name[] = "default";
  const char sel_connect[] = "net.connect.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(sel_connect) - 1 +
                      4 + 1;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 9601, 9602, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_connect) - 1); zoff += 4;
  memcpy(zax + zoff, sel_connect, sizeof(sel_connect) - 1); zoff += sizeof(sel_connect) - 1;
  ctl_write_u32(zax + zoff, 1); zoff += 4;
  zax[zoff++] = 0xAA;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 301;
  return wait_for_fail_code(handle, 9601, 9602, "t_async_bad_params");
}

int test_async_net_send_overflow(void) {
  uint32_t handle = 0;
  if (open_async_handle(961, &handle) != 0) return 320;
  uint32_t net_handle = 0;
  if (net_connect(handle, 9611, 9612, &net_handle) != 0) return 321;
  uint8_t payload_data[3000];
  memset(payload_data, 0xAB, sizeof(payload_data));
  uint8_t zax[3600];
  const char kind[] = "net";
  const char name[] = "default";
  const char sel_send[] = "net.send.v1";
  uint32_t params_len = 8 + (uint32_t)sizeof(payload_data);
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(sel_send) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 9613, 9614, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_send) - 1); zoff += 4;
  memcpy(zax + zoff, sel_send, sizeof(sel_send) - 1); zoff += sizeof(sel_send) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, net_handle); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)sizeof(payload_data)); zoff += 4;
  memcpy(zax + zoff, payload_data, sizeof(payload_data)); zoff += sizeof(payload_data);
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 322;
  return wait_for_fail_code(handle, 9613, 9614, "t_net_overflow");
}

int test_async_net_send_badlen(void) {
  uint32_t handle = 0;
  if (open_async_handle(962, &handle) != 0) return 340;
  uint32_t net_handle = 0;
  if (net_connect(handle, 9621, 9622, &net_handle) != 0) return 341;
  const char kind[] = "net";
  const char name[] = "default";
  const char sel_send[] = "net.send.v1";
  const uint8_t data[] = { 1, 2, 3 };
  uint32_t params_len = 8 + (uint32_t)sizeof(data);
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(sel_send) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  uint8_t zax[256];
  write_zax_header(zax, 1, 1, 9623, 9624, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(sel_send) - 1); zoff += 4;
  memcpy(zax + zoff, sel_send, sizeof(sel_send) - 1); zoff += sizeof(sel_send) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, net_handle); zoff += 4;
  ctl_write_u32(zax + zoff, 5); zoff += 4; /* declare more bytes than present */
  memcpy(zax + zoff, data, sizeof(data)); zoff += sizeof(data);
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 342;
  return wait_for_fail_code(handle, 9623, 9624, "t_async_bad_params");
}
