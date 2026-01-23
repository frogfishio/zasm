/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../caps/ctl_common.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
  ctl_write_u32(req + off, 0); off += 4; /* mode */
  ctl_write_u32(req + off, 0); off += 4; /* params len */
  int32_t n = _ctl(req, 24 + payload_len, resp, sizeof(resp));
  if (n <= 0) return 10;
  if ((uint32_t)n < 20 + 16) return 11;
  const uint8_t* p = resp + 20;
  uint32_t ok = ctl_read_u32(p);
  if (ok != 1) {
    uint32_t tlen = ctl_read_u32(p);
    if (20u + tlen + 4 <= (uint32_t)n && tlen < 32) {
      char trace[32];
      memcpy(trace, p + 4, tlen);
      trace[tlen] = '\0';
      fprintf(stderr, "open_async_handle exec: trace=%s\n", trace);
      if (strcmp(trace, "t_ctl_overflow") == 0) return 130;
      if (strcmp(trace, "t_cap_missing") == 0) return 131;
    }
    fprintf(stderr, "open_async_handle exec: raw ok=%u len=%d\n", ok, n);
    for (int i = 0; i < n && i < 80; i++) {
      fprintf(stderr, "%02x ", (unsigned char)resp[i]);
    }
    fprintf(stderr, "\n");
    return 120;
  }
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

int test_async_exec_fake(void) {
  uint32_t handle = 0;
  int r = open_async_handle(800, &handle);
  if (r != 0) return 100 + r;
  uint8_t zax[256];
  const char kind[] = "exec";
  const char name[] = "default";
  const char selector[] = "exec.fake.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(kind) - 1 +
                      4 + (uint32_t)sizeof(name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 0;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 501, 8000, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(kind) - 1); zoff += 4;
  memcpy(zax + zoff, kind, sizeof(kind) - 1); zoff += sizeof(kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(name) - 1); zoff += 4;
  memcpy(zax + zoff, name, sizeof(name) - 1); zoff += sizeof(name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 101;
  uint8_t resp[256];
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
      if (k == 2 && op == 101 && rid == 501) saw_ack = 1;
      if (k == 2 && op == 110 && fid == 8000) {
        if (plen < 4) return 102;
        uint32_t vlen = ctl_read_u32(pay);
        if (4u + vlen != plen) return 103;
        if (vlen != 7) return 104;
        if (memcmp(pay + 4, "exec-ok", 7) != 0) return 105;
        saw_ok = 1;
      }
      pos += 48u + plen;
    }
    if (saw_ack && saw_ok) break;
  }
  return (saw_ack && saw_ok) ? 0 : 106;
}
