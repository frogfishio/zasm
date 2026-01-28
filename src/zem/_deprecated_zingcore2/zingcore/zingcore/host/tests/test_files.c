/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../caps/ctl_common.h"
#include "../include/zi_async.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int32_t _ctl(const void *req_ptr, size_t req_len, void *resp_ptr, size_t resp_cap);
int32_t res_write(int32_t handle, const void *ptr, size_t len);
int32_t req_read(int32_t handle, void *ptr, size_t cap);

static const char k_async_kind[] = "async";
static const char k_async_name[] = "default";
static const char k_file_kind[] = "file";
static const char k_file_name[] = "view";

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

static int wait_for_fail_code(uint32_t handle, uint64_t expect_rid,
                              uint64_t expect_fid, const char* expect_code) {
  uint8_t resp[512];
  int saw_ack = 0;
  size_t code_len = strlen(expect_code);
  int32_t rn = 0;
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
        if (plen < 8) return 900;
        uint32_t c_len = ctl_read_u32(pay);
        uint32_t m_len = ctl_read_u32(pay + 4);
        if (8u + c_len + m_len != plen) return 901;
        if (c_len != code_len) return 902;
        if (memcmp(pay + 8, expect_code, c_len) != 0) return 903;
        return saw_ack ? 0 : 904;
      }
      pos += 48u + plen;
    }
  }
  return 905;
}

static int32_t open_async_handle(uint32_t rid, uint32_t* out_handle) {
  uint8_t req[128];
  uint8_t resp[128];
  uint32_t payload_len = 4 + sizeof(k_async_kind) - 1 + 4 + sizeof(k_async_name) - 1 + 4 + 4;
  write_req_header(req, 3, rid, payload_len);
  uint32_t off = 24;
  ctl_write_u32(req + off, sizeof(k_async_kind) - 1); off += 4;
  memcpy(req + off, k_async_kind, sizeof(k_async_kind) - 1); off += (uint32_t)(sizeof(k_async_kind) - 1);
  ctl_write_u32(req + off, sizeof(k_async_name) - 1); off += 4;
  memcpy(req + off, k_async_name, sizeof(k_async_name) - 1); off += (uint32_t)(sizeof(k_async_name) - 1);
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

static int list_expect(uint32_t req_id, uint64_t fid,
                       const char** expect_ids, size_t expect_count) {
  uint32_t handle = 0;
  if (open_async_handle(req_id, &handle) != 0) return 1;
  uint8_t zax[256];
  const char selector[] = "files.list.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  uint64_t req_id_wire = (uint64_t)req_id + 1000;
  write_zax_header(zax, 1, 1, req_id_wire, fid, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2; /* variant B */
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4); zoff += 4;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  int32_t wn = res_write((int32_t)handle, zax, zoff);
  if (wn <= 0) return 61;

  uint8_t zresp[512];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 101 && rid_seen == req_id_wire) {
        saw_ack = 1;
      } else if (k == 2 && op == 110 && fid_seen == fid) {
        if (plen < 4) return 63;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen < 4) return 64;
        if (4u + vlen != plen) return 65;
        uint32_t n = ctl_read_u32(pay + 4);
        if (n != expect_count) return 66;
        uint32_t off = 8;
        for (uint32_t i = 0; i < n; i++) {
          uint32_t id_len = ctl_read_u32(pay + off); off += 4;
          if (off + id_len > 4 + vlen) return 67;
          if (strlen(expect_ids[i]) != id_len ||
              strncmp((const char*)(pay + off), expect_ids[i], id_len) != 0) return 68;
          off += id_len;
          uint32_t disp_len = ctl_read_u32(pay + off); off += 4;
          if (off + disp_len > 4 + vlen) return 69;
          if (disp_len != id_len ||
              strncmp((const char*)(pay + off), expect_ids[i], disp_len) != 0) return 71;
          off += disp_len;
          uint32_t flags = ctl_read_u32(pay + off); off += 4;
          if ((flags & 0x2u) == 0) return 72;
        }
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  if (!saw_ack || !saw_ok) return 75;
  return 0;
}

int test_async_files_list(void) {
  const char* expect[] = { "a.zing", "b.zing" };
  return list_expect(12, 77, expect, 2);
}

int test_async_files_open_read(void) {
  uint32_t handle = 0;
  if (open_async_handle(13, &handle) != 0) return 80;
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  const char file_id[] = "a.zing";
  const char expect[] = "hello from file a\n";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 3, 88, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 1); zoff += 4; /* mode */

  int32_t wn = res_write((int32_t)handle, zax, zoff);
  if (wn <= 0) return 81;

  uint8_t zresp[512];
  int saw_ack = 0, saw_ok = 0;
  uint32_t file_handle = 0;
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
      if (k == 2 && op == 101 && rid == 3) {
        saw_ack = 1;
      } else if (k == 2 && op == 110 && fid == 88) {
        if (plen < 4) return 83;
        uint32_t vlen = ctl_read_u32(pay);
        if (4u + vlen != plen) return 84;
        if (vlen < 12) return 85;
        uint32_t off = 4;
        file_handle = ctl_read_u32(pay + off); off += 4;
        uint32_t hflags = ctl_read_u32(pay + off); off += 4;
        if ((hflags & 1u) == 0) return 84;
        uint32_t meta_len = ctl_read_u32(pay + off); off += 4;
        if (meta_len != 4 || off + meta_len != 4u + vlen) return 86;
        uint32_t file_len = ctl_read_u32(pay + off);
        if (file_len != (uint32_t)strlen(expect)) return 87;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  if (!saw_ack || !saw_ok) return 87;
  if (file_handle < 3) return 88;

  /* Read file contents */
  uint8_t buf[64];
  int32_t r1 = req_read((int32_t)file_handle, buf, sizeof(buf));
  if (r1 <= 0) return 89;
  if ((size_t)r1 != strlen(expect)) return 90;
  if (memcmp(buf, expect, (size_t)r1) != 0) return 91;
  int32_t r2 = req_read((int32_t)file_handle, buf, sizeof(buf));
  if (r2 != 0) return 92;
  int32_t w = res_write((int32_t)file_handle, "x", 1);
  if (w != -1) return 93;
  return 0;
}

static int send_create(const char* id, const char* contents,
                       uint32_t rid, uint64_t fid) {
  uint32_t handle = 0;
  if (open_async_handle(rid, &handle) != 0) return 1;
  uint8_t zax[256];
  const char selector[] = "files.create.v1";
  uint32_t params_len = 4 + (uint32_t)strlen(id) + 4 + (uint32_t)strlen(contents);
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, (uint64_t)rid + 2000, fid, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)strlen(id)); zoff += 4;
  memcpy(zax + zoff, id, strlen(id)); zoff += (uint32_t)strlen(id);
  ctl_write_u32(zax + zoff, (uint32_t)strlen(contents)); zoff += 4;
  memcpy(zax + zoff, contents, strlen(contents)); zoff += (uint32_t)strlen(contents);
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 2;
  uint8_t zresp[256];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 101 && rid_seen == (uint64_t)rid + 2000) saw_ack = 1;
      if (k == 2 && op == 110 && fid_seen == fid) {
        if (plen != 4) return 3;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen != 0) return 4;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  return (saw_ack && saw_ok) ? 0 : 5;
}

static int send_delete(const char* id, uint32_t rid, uint64_t fid) {
  uint32_t handle = 0;
  if (open_async_handle(rid, &handle) != 0) return 1;
  uint8_t zax[256];
  const char selector[] = "files.delete.v1";
  uint32_t params_len = 4 + (uint32_t)strlen(id);
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, (uint64_t)rid + 3000, fid, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)strlen(id)); zoff += 4;
  memcpy(zax + zoff, id, strlen(id)); zoff += (uint32_t)strlen(id);
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 2;
  uint8_t zresp[256];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 101 && rid_seen == (uint64_t)rid + 3000) saw_ack = 1;
      if (k == 2 && op == 110 && fid_seen == fid) {
        if (plen != 4) return 3;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen != 0) return 4;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  return (saw_ack && saw_ok) ? 0 : 5;
}

int test_async_files_create_and_list(void) {
  if (send_create("c.zing", "created data\n", 20, 1200) != 0) return 110;
  const char* expect[] = { "a.zing", "b.zing", "c.zing" };
  return list_expect(21, 1201, expect, 3);
}

int test_async_files_write_update(void) {
  /* Ensure file exists */
  if (send_create("d.zing", "orig", 22, 1300) != 0) return 120;
  uint32_t handle = 0;
  if (open_async_handle(23, &handle) != 0) return 121;
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  const char file_id[] = "d.zing";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 5, 1301, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 3); zoff += 4; /* mode append */
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 122;

  uint8_t zresp[256];
  int saw_ok = 0;
  uint32_t file_handle = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 110 && fid_seen == 1301) {
        if (plen < 4) return 124;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen < 12 || 4u + vlen != plen) return 125;
        file_handle = ctl_read_u32(pay + 4);
        uint32_t hflags = ctl_read_u32(pay + 8);
        if ((hflags & 0x2u) == 0) return 126;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ok) break;
  }
  if (!saw_ok || file_handle < 3) return 127;

  if (res_write((int32_t)file_handle, "++", 2) != 2) return 128;

  /* Re-open for read and confirm contents */
  uint32_t read_handle = 0;
  if (open_async_handle(24, &read_handle) != 0) return 129;
  /* reuse open read path but simpler copy */
  const char* expect = "orig++";
  /* request read handle */
  zoff = 48;
  write_zax_header(zax, 1, 1, 6, 1302, payload_zax);
  zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 1); zoff += 4;
  if (res_write((int32_t)read_handle, zax, zoff) <= 0) return 130;
  rn = 0;
  uint32_t read_file_handle = 0;
  int saw_read_ok = 0;
  while ((rn = req_read((int32_t)read_handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 110 && fid_seen == 1302) {
        if (plen < 16) return 132;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen < 12 || 4u + vlen != plen) return 133;
        read_file_handle = ctl_read_u32(pay + 4);
        saw_read_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_read_ok) break;
  }
  if (!saw_read_ok || read_file_handle < 3) return 134;
  uint8_t buf[64];
  int32_t r = req_read((int32_t)read_file_handle, buf, sizeof(buf));
  if (r <= 0) return 135;
  if ((size_t)r != strlen(expect)) return 136;
  if (memcmp(buf, expect, (size_t)r) != 0) return 137;
  return 0;
}

int test_async_files_concurrent_handles(void) {
  uint32_t async_handle = 0;
  if (open_async_handle(50, &async_handle) != 0) return 210;
  /* open same file twice for read */
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  const char file_id[] = "a.zing";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  uint32_t handles[2] = {0,0};
  for (int open_idx = 0; open_idx < 2; open_idx++) {
    write_zax_header(zax, 1, 1, 30 + (uint32_t)open_idx, 1900 + (uint64_t)open_idx, payload_zax);
    uint32_t zoff = 48;
    zax[zoff++] = 2;
    ctl_write_u32(zax + zoff, body_len); zoff += 4;
    ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
    memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
    ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
    memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
    ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
    memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
    ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
    ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
    memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
    ctl_write_u32(zax + zoff, 1); zoff += 4;
    if (res_write((int32_t)async_handle, zax, zoff) <= 0) return 211;
  }
  uint8_t zresp[512];
  int count_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)async_handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 110 && (fid_seen == 1900 || fid_seen == 1901)) {
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen < 12 || 4u + vlen != plen) return 212;
        uint32_t h = ctl_read_u32(pay + 4);
        handles[count_ok++] = h;
      }
      pos += frame_len;
    }
    if (count_ok == 2) break;
  }
  if (count_ok != 2 || handles[0] < 3 || handles[1] < 3 || handles[0] == handles[1]) return 213;
  /* read one byte from each; expect both start at beginning */
  uint8_t buf[8];
  int32_t r0 = req_read((int32_t)handles[0], buf, sizeof(buf));
  if (r0 <= 0 || buf[0] != 'h') return 214;
  int32_t r1 = req_read((int32_t)handles[1], buf, sizeof(buf));
  if (r1 <= 0 || buf[0] != 'h') return 215;
  return 0;
}
static int send_overwrite(const char* id, const char* contents,
                          uint32_t rid, uint64_t fid) {
  uint32_t handle = 0;
  if (open_async_handle(rid, &handle) != 0) return 1;
  uint8_t zax[256];
  const char selector[] = "files.overwrite.v1";
  uint32_t params_len = 4 + (uint32_t)strlen(id) + 4 + (uint32_t)strlen(contents);
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, (uint64_t)rid + 4000, fid, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)strlen(id)); zoff += 4;
  memcpy(zax + zoff, id, strlen(id)); zoff += (uint32_t)strlen(id);
  ctl_write_u32(zax + zoff, (uint32_t)strlen(contents)); zoff += 4;
  memcpy(zax + zoff, contents, strlen(contents)); zoff += (uint32_t)strlen(contents);
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 2;
  uint8_t zresp[256];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 101 && rid_seen == (uint64_t)rid + 4000) saw_ack = 1;
      if (k == 2 && op == 110 && fid_seen == fid) {
        if (plen != 4) return 3;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen != 0) return 4;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  return (saw_ack && saw_ok) ? 0 : 5;
}

int test_async_files_overwrite(void) {
  if (send_overwrite("b.zing", "replaced\n", 27, 1500) != 0) return 160;
  /* open for read */
  uint32_t handle = 0;
  if (open_async_handle(28, &handle) != 0) return 161;
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  const char file_id[] = "b.zing";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 7, 1501, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 1); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 162;
  uint8_t zresp[256];
  int32_t rn = req_read((int32_t)handle, zresp, sizeof(zresp));
  if (rn <= 0) return 163;
  size_t pos = 0;
  uint32_t file_handle = 0;
  while ((size_t)rn - pos >= 48) {
    uint16_t k, op;
    uint64_t rid_seen, fid_seen;
    const uint8_t* pay;
    uint32_t plen;
    if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
    size_t frame_len = 48u + plen;
    if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
    if (k == 2 && op == 110 && fid_seen == 1501) {
      if (plen < 16) return 164;
      uint32_t vlen = ctl_read_u32(pay);
      if (vlen < 12 || 4u + vlen != plen) return 165;
      file_handle = ctl_read_u32(pay + 4);
    }
    pos += frame_len;
  }
  if (file_handle < 3) return 166;
  uint8_t buf[64];
  int32_t r = req_read((int32_t)file_handle, buf, sizeof(buf));
  if (r <= 0) return 167;
  const char expect[] = "replaced\n";
  if ((size_t)r != strlen(expect)) return 168;
  if (memcmp(buf, expect, (size_t)r) != 0) return 169;
  return 0;
}

static int send_truncate(const char* id, uint32_t new_len,
                         uint32_t rid, uint64_t fid) {
  uint32_t handle = 0;
  if (open_async_handle(rid, &handle) != 0) return 1;
  uint8_t zax[256];
  const char selector[] = "files.truncate.v1";
  uint32_t params_len = 4 + (uint32_t)strlen(id) + 4;
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, (uint64_t)rid + 5000, fid, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)strlen(id)); zoff += 4;
  memcpy(zax + zoff, id, strlen(id)); zoff += (uint32_t)strlen(id);
  ctl_write_u32(zax + zoff, new_len); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 2;
  uint8_t zresp[256];
  int saw_ack = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 101 && rid_seen == (uint64_t)rid + 5000) saw_ack = 1;
      if (k == 2 && op == 110 && fid_seen == fid) {
        if (plen != 4) return 3;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen != 0) return 4;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ack && saw_ok) break;
  }
  return (saw_ack && saw_ok) ? 0 : 5;
}

int test_async_files_truncate_seek(void) {
  /* Truncate b.zing to 3 bytes, then open with offset */
  if (send_truncate("b.zing", 3, 29, 1600) != 0) return 170;
  uint32_t handle = 0;
  if (open_async_handle(30, &handle) != 0) return 171;
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  const char file_id[] = "b.zing";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 8, 1601, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 1); zoff += 4; /* mode read */
  ctl_write_u32(zax + zoff, 2); zoff += 4; /* offset */
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 172;
  uint8_t zresp[256];
  int32_t rn = req_read((int32_t)handle, zresp, sizeof(zresp));
  if (rn <= 0) return 173;
  size_t pos = 0;
  uint32_t file_handle = 0;
  while ((size_t)rn - pos >= 48) {
    uint16_t k, op;
    uint64_t rid_seen, fid_seen;
    const uint8_t* pay;
    uint32_t plen;
    if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
    size_t frame_len = 48u + plen;
    if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
    if (k == 2 && op == 110 && fid_seen == 1601) {
      if (plen < 16) return 174;
      uint32_t vlen = ctl_read_u32(pay);
      if (vlen < 12 || 4u + vlen != plen) return 175;
      file_handle = ctl_read_u32(pay + 4);
    }
    pos += frame_len;
  }
  if (file_handle < 3) return 176;
  uint8_t buf[64];
  int32_t r = req_read((int32_t)file_handle, buf, sizeof(buf));
  if (r < 0) return 177;
  /* After truncate to 3 bytes and offset 2, expect 1 byte available (or 0 if shorter). */
  if (r != 1) return 178;
  return 0;
}

static int send_seek_handle(uint32_t async_handle, uint32_t req_id,
                            uint64_t future_id, int32_t file_handle,
                            int32_t offset, uint32_t whence) {
  uint8_t zax[128];
  const char selector[] = "files.seek.v1";
  uint32_t params_len = 12;
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, req_id, future_id, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)file_handle); zoff += 4;
  ctl_write_u32(zax + zoff, (uint32_t)offset); zoff += 4;
  ctl_write_u32(zax + zoff, whence); zoff += 4;
  int32_t wn = res_write((int32_t)async_handle, zax, zoff);
  if (wn <= 0) return 1;
  uint8_t zresp[256];
  int saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)async_handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 110 && fid_seen == future_id) {
        if (plen != 8) return 2;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen != 4) return 3;
        saw_ok = 1;
      }
      pos += frame_len;
    }
    if (saw_ok) break;
  }
  return saw_ok ? 0 : 4;
}

int test_async_files_seek_whence(void) {
  /* Create file and open for write to allow extend. */
  if (send_create("seek.txt", "12345", 31, 1700) != 0) return 180;
  uint32_t async_handle = 0;
  if (open_async_handle(32, &async_handle) != 0) return 181;
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  const char file_id[] = "seek.txt";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 9, 1701, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 2); zoff += 4; /* mode overwrite (truncate to 0) */
  if (res_write((int32_t)async_handle, zax, zoff) <= 0) return 182;
  uint8_t zresp[256];
  int32_t rn = req_read((int32_t)async_handle, zresp, sizeof(zresp));
  if (rn <= 0) return 183;
  size_t pos = 0;
  uint32_t file_handle = 0;
  while ((size_t)rn - pos >= 48) {
    uint16_t k, op;
    uint64_t rid_seen, fid_seen;
    const uint8_t* pay;
    uint32_t plen;
    if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
    size_t frame_len = 48u + plen;
    if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
    if (k == 2 && op == 110 && fid_seen == 1701) {
      if (plen < 16) return 184;
      uint32_t vlen = ctl_read_u32(pay);
      if (vlen < 12 || 4u + vlen != plen) return 185;
      file_handle = ctl_read_u32(pay + 4);
    }
    pos += frame_len;
  }
  if (file_handle < 3) return 186;
  /* Seek to end (whence=2) with negative offset to position 0, then write, then extend */
  if (send_seek_handle(async_handle, 10, 1702, (int32_t)file_handle, -0, 0) != 0) return 187;
  if (send_seek_handle(async_handle, 11, 1703, (int32_t)file_handle, 0, 2) != 0) return 188;
  if (res_write((int32_t)file_handle, "abc", 3) != 3) return 189;
  if (send_seek_handle(async_handle, 12, 1704, (int32_t)file_handle, -1, 1) != 0) return 190;
  if (res_write((int32_t)file_handle, "Z", 1) != 1) return 191;
  /* Rewind and read back */
  if (send_seek_handle(async_handle, 13, 1705, (int32_t)file_handle, 0, 0) != 0) return 192;
  uint8_t buf[32];
  int32_t r = req_read((int32_t)file_handle, buf, sizeof(buf));
  if (r <= 0) return 193;
  const char expect[] = "abZ";
  if ((size_t)r != strlen(expect)) return 194;
  if (memcmp(buf, expect, (size_t)r) != 0) return 195;
  return 0;
}

int test_async_files_errors(void) {
  /* Open missing file -> expect future_fail */
  uint32_t handle = 0;
  if (open_async_handle(40, &handle) != 0) return 200;
  uint8_t zax[128];
  const char selector[] = "files.open.v1";
  const char file_id[] = "missing.txt";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(file_id) - 1 + 4;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 20, 1800, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(file_id) - 1 + 4); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(file_id) - 1); zoff += 4;
  memcpy(zax + zoff, file_id, sizeof(file_id) - 1); zoff += sizeof(file_id) - 1;
  ctl_write_u32(zax + zoff, 1); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 201;
  uint8_t zresp[256];
  int saw_fail = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, zresp, sizeof(zresp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(zresp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      size_t frame_len = 48u + plen;
      if (frame_len == 0 || pos + frame_len > (size_t)rn) break;
      if (k == 2 && op == 111 && fid_seen == 1800) saw_fail = 1;
      pos += frame_len;
    }
    if (saw_fail) break;
  }
  if (!saw_fail) return 202;

  /* Seek invalid handle */
  if (send_seek_handle(handle, 21, 1801, 999, 0, 0) == 0) return 203;

  /* Overwrite missing file */
  if (send_overwrite("nope", "x", 41, 1802) == 0) return 204;

  /* Truncate missing file */
  if (send_truncate("nope", 1, 42, 1803) == 0) return 205;

  return 0;
}

int test_async_payload_cap(void) {
  uint32_t handle = 0;
  if (open_async_handle(60, &handle) != 0) return 300;
  size_t big_len = 1100000;
  uint8_t* payload = (uint8_t*)malloc(big_len + 48);
  if (!payload) return 301;
  memset(payload, 0xAB, big_len + 48);
  write_zax_header(payload, 1, 1, 100, 9999, (uint32_t)big_len);
  int32_t wn = res_write((int32_t)handle, payload, 48 + big_len);
  free(payload);
  if (wn <= 0) return 302;
  uint8_t resp[256];
  int saw_fail = 0;
  int32_t rn = req_read((int32_t)handle, resp, sizeof(resp));
  if (rn <= 0) return 303;
  size_t pos = 0;
  while ((size_t)rn - pos >= 48) {
    uint16_t k, op;
    uint64_t rid, fid;
    const uint8_t* pay;
    uint32_t plen;
    if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
    if (k == 2 && op == 102 && rid == 100) saw_fail = 1;
    pos += 48u + plen;
  }
  return saw_fail ? 0 : 304;
}

int test_async_cancel(void) {
  uint32_t handle = 0;
  if (open_async_handle(61, &handle) != 0) return 310;
  /* Register ping future, then cancel it. */
  uint8_t zax[256];
  const char selector[] = "ping.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_async_kind) - 1 +
                      4 + (uint32_t)sizeof(k_async_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 0;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 200, 2000, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2; /* variant B */
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_async_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_async_kind, sizeof(k_async_kind) - 1); zoff += sizeof(k_async_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_async_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_async_name, sizeof(k_async_name) - 1); zoff += sizeof(k_async_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 311;
  /* Send cancel */
  write_zax_header(zax, 1, 2, 201, 2000, 0);
  if (res_write((int32_t)handle, zax, 48) <= 0) return 312;
  uint8_t resp[512];
  int saw_ack_reg = 0, saw_ack_cancel = 0, saw_cancel = 0, saw_ok = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 101 && rid == 200) saw_ack_reg = 1;
      if (k == 2 && op == 101 && rid == 201) saw_ack_cancel = 1;
      if (k == 2 && op == 112 && fid == 2000) saw_cancel = 1;
      if (k == 2 && op == 110 && fid == 2000) saw_ok = 1;
      pos += 48u + plen;
    }
    if (saw_ack_reg && saw_ack_cancel && saw_cancel) break;
  }
  if (!saw_ack_reg || !saw_ack_cancel || !saw_cancel) return 313;
  if (saw_ok) return 314; /* should have been dropped */
  return 0;
}

int test_async_opaque_source(void) {
  uint32_t handle = 0;
  if (open_async_handle(62, &handle) != 0) return 320;
  uint8_t zax[128];
  uint8_t body[] = {1,2,3,4};
  uint32_t payload_len = 1 + 4 + sizeof(body);
  write_zax_header(zax, 1, 1, 300, 3000, payload_len);
  uint32_t zoff = 48;
  zax[zoff++] = 1; /* variant A opaque */
  ctl_write_u32(zax + zoff, sizeof(body)); zoff += 4;
  memcpy(zax + zoff, body, sizeof(body)); zoff += sizeof(body);
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 321;
  uint8_t resp[256];
  int saw_ack = 0, saw_fail = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 101 && rid == 300) saw_ack = 1;
      if (k == 2 && op == 111 && fid == 3000) saw_fail = 1;
      pos += 48u + plen;
    }
    if (saw_ack && saw_fail) break;
  }
  return (saw_ack && saw_fail) ? 0 : 322;
}

int test_async_join_detach(void) {
  uint32_t handle = 0;
  if (open_async_handle(63, &handle) != 0) return 330;
  uint8_t zax[96];
  /* detach */
  const char owner[] = "main";
  write_zax_header(zax, 1, 3, 400, 0, 4 + (uint32_t)sizeof(owner) - 1);
  ctl_write_u32(zax + 48, (uint32_t)sizeof(owner) - 1);
  memcpy(zax + 52, owner, sizeof(owner) - 1);
  if (res_write((int32_t)handle, zax, 52 + (int32_t)sizeof(owner) - 1) <= 0) return 331;
  /* join */
  write_zax_header(zax, 1, 4, 401, 0, 8);
  ctl_write_u32(zax + 48, 10); /* fuelLo */
  ctl_write_u32(zax + 52, 0); /* fuelHi */
  if (res_write((int32_t)handle, zax, 56) <= 0) return 332;
  uint8_t resp[256];
  int saw_ack = 0, saw_join = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 101 && rid == 400) saw_ack = 1;
      if (k == 2 && op == 120 && rid == 401) saw_join = 1;
      pos += 48u + plen;
    }
    if (saw_ack && saw_join) break;
  }
  return (saw_ack && saw_join) ? 0 : 333;
}

int test_async_timeout_cancel(void) {
  uint32_t handle = 0;
  if (open_async_handle(65, &handle) != 0) return 334;
  uint8_t zax[256];
  const char selector[] = "pending.v1";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_async_kind) - 1 +
                      4 + (uint32_t)sizeof(k_async_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 0;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 410, 9000, payload_zax);
  /* timeout_ms in header */
  zax[10] = 5; zax[11] = 0; /* 5 ms */
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_async_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_async_kind, sizeof(k_async_kind) - 1); zoff += sizeof(k_async_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_async_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_async_name, sizeof(k_async_name) - 1); zoff += sizeof(k_async_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 335;
  /* Give timeout a chance to elapse. */
  usleep(10000);
  uint8_t resp[256];
  int saw_cancel = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) >= 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 112 && fid == 9000) { saw_cancel = 1; break; }
      pos += 48u + plen;
    }
    if (saw_cancel || rn == 0) break;
  }
  return saw_cancel ? 0 : 336;
}

int test_async_join_cancel(void) {
  /* Join should emit FUTURE_CANCEL for scoped futures. */
  uint32_t handle = 0;
  if (open_async_handle(64, &handle) != 0) return 340;
  uint8_t zax[256];
  const char selector[] = "pending.v1";
  /* register two futures with same scope */
  for (uint64_t fid = 5000; fid < 5002; fid++) {
    uint32_t body_len = 4 + (uint32_t)sizeof(k_async_kind) - 1 +
                        4 + (uint32_t)sizeof(k_async_name) - 1 +
                        4 + (uint32_t)sizeof(selector) - 1 +
                        4 + 0;
    uint32_t payload_zax = 1 + 4 + body_len;
    write_zax_header(zax, 1, 1, (uint32_t)(300 + (fid - 5000)), fid, payload_zax);
    /* set scope id to 42 */
    ctl_write_u32(zax + 20, 42);
    ctl_write_u32(zax + 24, 0);
    uint32_t zoff = 48;
    zax[zoff++] = 2;
    ctl_write_u32(zax + zoff, body_len); zoff += 4;
    ctl_write_u32(zax + zoff, sizeof(k_async_kind) - 1); zoff += 4;
    memcpy(zax + zoff, k_async_kind, sizeof(k_async_kind) - 1); zoff += sizeof(k_async_kind) - 1;
    ctl_write_u32(zax + zoff, sizeof(k_async_name) - 1); zoff += 4;
    memcpy(zax + zoff, k_async_name, sizeof(k_async_name) - 1); zoff += sizeof(k_async_name) - 1;
    ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
    memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
    ctl_write_u32(zax + zoff, 0); zoff += 4;
    if (res_write((int32_t)handle, zax, zoff) <= 0) return 341;
  }
  /* join on scope of handle (same scope_id stored in handle) */
  write_zax_header(zax, 1, 4, 305, 0, 8);
  ctl_write_u32(zax + 20, 42);
  ctl_write_u32(zax + 24, 0);
  ctl_write_u32(zax + 48, 10);
  ctl_write_u32(zax + 52, 0);
  if (res_write((int32_t)handle, zax, 56) <= 0) return 342;
  uint8_t resp[512];
  int saw_join = 0;
  int cancel_seen = 0;
  int32_t rn = 0;
  while ((rn = req_read((int32_t)handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid, fid;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
      if (k == 2 && op == 120 && rid == 305) saw_join = 1;
      if (k == 2 && op == 112 && (fid == 5000 || fid == 5001)) cancel_seen++;
      pos += 48u + plen;
    }
    if (saw_join && cancel_seen >= 2) break;
  }
  return (saw_join && cancel_seen >= 2) ? 0 : 343;
}

int test_async_join_cancel_cross_handle(void) {
  /* Register futures on two handles with same scope; join on second should cancel both. */
  uint32_t h1 = 0, h2 = 0;
  if (open_async_handle(65, &h1) != 0) return 350;
  if (open_async_handle(66, &h2) != 0) return 351;
  uint8_t zax[256];
  const char selector[] = "pending.v1";
  /* register one future on h1, one on h2 with scope 99 */
  uint64_t futures[] = {6000, 6001};
  uint32_t handles[] = {h1, h2};
  for (int i = 0; i < 2; i++) {
    uint32_t body_len = 4 + (uint32_t)sizeof(k_async_kind) - 1 +
                        4 + (uint32_t)sizeof(k_async_name) - 1 +
                        4 + (uint32_t)sizeof(selector) - 1 +
                        4 + 0;
    uint32_t payload_zax = 1 + 4 + body_len;
    write_zax_header(zax, 1, 1, 400 + (uint32_t)i, futures[i], payload_zax);
    ctl_write_u32(zax + 20, 99);
    ctl_write_u32(zax + 24, 0);
    uint32_t zoff = 48;
    zax[zoff++] = 2;
    ctl_write_u32(zax + zoff, body_len); zoff += 4;
    ctl_write_u32(zax + zoff, sizeof(k_async_kind) - 1); zoff += 4;
    memcpy(zax + zoff, k_async_kind, sizeof(k_async_kind) - 1); zoff += sizeof(k_async_kind) - 1;
    ctl_write_u32(zax + zoff, sizeof(k_async_name) - 1); zoff += 4;
    memcpy(zax + zoff, k_async_name, sizeof(k_async_name) - 1); zoff += sizeof(k_async_name) - 1;
    ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
    memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
    ctl_write_u32(zax + zoff, 0); zoff += 4;
    if (res_write((int32_t)handles[i], zax, zoff) <= 0) return 352;
  }
  /* join on h2 */
  write_zax_header(zax, 1, 4, 410, 0, 8);
  ctl_write_u32(zax + 20, 99);
  ctl_write_u32(zax + 24, 0);
  ctl_write_u32(zax + 48, 10); /* fuelLo */
  ctl_write_u32(zax + 52, 0); /* fuelHi */
  if (res_write((int32_t)h2, zax, 56) <= 0) return 353;
  int cancels_h1 = 0, cancels_h2 = 0, saw_join = 0;
  uint8_t buf[256];
  int32_t rn = 0;
  /* read from both handles */
  for (int pass = 0; pass < 4; pass++) {
    rn = req_read((int32_t)h1, buf, sizeof(buf));
    if (rn > 0) {
      size_t pos = 0;
      while ((size_t)rn - pos >= 48) {
        uint16_t k, op;
        uint64_t rid, fid;
        const uint8_t* pay;
        uint32_t plen;
        if (!parse_zax_frame(buf + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
        if (k == 2 && op == 112 && fid == 6000) cancels_h1++;
        pos += 48u + plen;
      }
    }
    rn = req_read((int32_t)h2, buf, sizeof(buf));
    if (rn > 0) {
      size_t pos = 0;
      while ((size_t)rn - pos >= 48) {
        uint16_t k, op;
        uint64_t rid, fid;
        const uint8_t* pay;
        uint32_t plen;
        if (!parse_zax_frame(buf + pos, (size_t)rn - pos, &k, &op, &rid, &fid, &pay, &plen)) break;
        if (k == 2 && op == 112 && fid == 6001) cancels_h2++;
        if (k == 2 && op == 120 && rid == 410) saw_join = 1;
        pos += 48u + plen;
      }
    }
    if (saw_join && cancels_h1 && cancels_h2) break;
  }
  if (!saw_join || !cancels_h1 || !cancels_h2) return 354;
  return 0;
}

int test_async_payload_cap_meta(void) {
  uint8_t req[128];
  uint8_t resp[128];
  const char kind[] = "async";
  const char name[] = "default";
  uint32_t payload_len = 4 + sizeof(kind) - 1 + 4 + sizeof(name) - 1;
  write_req_header(req, 2, 501, payload_len);
  uint32_t off = 24;
  ctl_write_u32(req + off, sizeof(kind) - 1); off += 4;
  memcpy(req + off, kind, sizeof(kind) - 1); off += sizeof(kind) - 1;
  ctl_write_u32(req + off, sizeof(name) - 1); off += 4;
  memcpy(req + off, name, sizeof(name) - 1); off += sizeof(name) - 1;
  int32_t n = _ctl(req, 24 + payload_len, resp, sizeof(resp));
  if (n <= 0) return 360;
  uint32_t plen = ctl_read_u32(resp + 16);
  if (20u + plen != (uint32_t)n) return 361;
  const uint8_t* p = resp + 20;
  if (plen < 28) return 362;
  uint32_t ok = ctl_read_u32(p + 0);
  if (ok != 1) return 363;
  uint32_t cap_flags = ctl_read_u32(p + 4);
  (void)cap_flags;
  uint32_t meta_len = ctl_read_u32(p + 8);
  if (meta_len != 16) return 364;
  if (12u + meta_len > plen) return 365;
  uint32_t max_payload = ctl_read_u32(p + 12);
  uint32_t max_futures = ctl_read_u32(p + 16);
  uint32_t max_queue = ctl_read_u32(p + 20);
  uint32_t meta_flags = ctl_read_u32(p + 24);
  if (max_payload != 1048576u) return 366;
  if (max_futures != 32u) return 367;
  if (max_queue != 65536u) return 368;
  if ((meta_flags & 0x7u) != 0x7u) return 369;
  return 0;
}

int test_async_files_delete(void) {
  if (send_delete("c.zing", 25, 1400) != 0) return 150;
  /* ignore result for seek.txt delete; it may or may not exist depending on prior tests */
  (void)send_delete("seek.txt", 26, 1402);
  const char* expect4[] = { "a.zing", "b.zing", "d.zing", "seek.txt" };
  int r = list_expect(27, 1401, expect4, 4);
  if (r == 0) return 0;
  const char* expect3[] = { "a.zing", "b.zing", "d.zing" };
  return list_expect(28, 1403, expect3, 3);
}

int test_async_files_bad_scope(void) {
  uint32_t handle = 0;
  if (open_async_handle(14, &handle) != 0) return 100;
  uint8_t zax[256];
  const char selector[] = "files.list.v1";
  const char scope[] = "nope";
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + 4 + (uint32_t)sizeof(scope) - 1;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 4, 99, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, 4 + (uint32_t)sizeof(scope) - 1); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(scope) - 1); zoff += 4;
  memcpy(zax + zoff, scope, sizeof(scope) - 1); zoff += sizeof(scope) - 1;
  int32_t wn = res_write((int32_t)handle, zax, zoff);
  if (wn <= 0) return 101;
  uint8_t zresp[256];
  int saw_fail = 0;
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
      if (k == 2 && (op == 111 || op == 102)) {
        saw_fail = 1;
        break;
      }
      pos += frame_len;
    }
    if (saw_fail) break;
  }
  if (!saw_fail) return 104;
  return 0;
}

int test_async_files_open_bad_params(void) {
  uint32_t handle = 0;
  if (open_async_handle(70, &handle) != 0) return 270;
  uint8_t zax[128];
  const char selector[] = "files.open.v1";
  uint32_t params_len = 1; /* too short */
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 70, 2101, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  zax[zoff++] = 0xAA; /* incomplete params */
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 271;
  return wait_for_fail_code(handle, 70, 2101, "t_async_bad_params");
}

int test_async_files_create_bad_params(void) {
  uint32_t handle = 0;
  if (open_async_handle(71, &handle) != 0) return 280;
  uint8_t zax[128];
  const char selector[] = "files.create.v1";
  uint32_t params_len = 2; /* less than id len field */
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 71, 2102, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  zax[zoff++] = 0x01;
  zax[zoff++] = 0x02;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 281;
  return wait_for_fail_code(handle, 71, 2102, "t_async_bad_params");
}

static int open_file_handle_simple(uint32_t async_handle, const char* id,
                                   uint32_t mode, uint64_t req_id,
                                   uint64_t future_id, uint32_t* out_handle) {
  uint8_t zax[256];
  const char selector[] = "files.open.v1";
  uint32_t id_len = (uint32_t)strlen(id);
  uint32_t params_len = 4 + id_len + 4;
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, req_id, future_id, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, id_len); zoff += 4;
  memcpy(zax + zoff, id, id_len); zoff += id_len;
  ctl_write_u32(zax + zoff, mode); zoff += 4;
  if (res_write((int32_t)async_handle, zax, zoff) <= 0) return 1;
  uint8_t resp[256];
  int32_t rn = 0;
  while ((rn = req_read((int32_t)async_handle, resp, sizeof(resp))) > 0) {
    size_t pos = 0;
    while ((size_t)rn - pos >= 48) {
      uint16_t k, op;
      uint64_t rid_seen, fid_seen;
      const uint8_t* pay;
      uint32_t plen;
      if (!parse_zax_frame(resp + pos, (size_t)rn - pos, &k, &op, &rid_seen, &fid_seen, &pay, &plen)) break;
      if (k == 2 && op == 110 && fid_seen == future_id) {
        if (plen < 16) return 2;
        uint32_t vlen = ctl_read_u32(pay);
        if (vlen < 12 || 4u + vlen != plen) return 3;
        uint32_t h = ctl_read_u32(pay + 4);
        if (h < 3) return 4;
        if (out_handle) *out_handle = h;
        return 0;
      }
      if (k == 2 && op == 111 && fid_seen == future_id) return 5;
      pos += 48u + plen;
    }
  }
  return 6;
}

int test_async_files_seek_bad_len(void) {
  uint32_t handle = 0;
  if (open_async_handle(72, &handle) != 0) return 300;
  uint8_t zax[128];
  const char selector[] = "files.seek.v1";
  uint32_t params_len = 8; /* should be 12 */
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 72, 2103, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, 1234); zoff += 4;
  ctl_write_u32(zax + zoff, 0xFFFFFFFFu); zoff += 4;
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 301;
  return wait_for_fail_code(handle, 72, 2103, "t_async_bad_params");
}

int test_async_files_seek_bad_whence(void) {
  uint32_t handle = 0;
  if (open_async_handle(73, &handle) != 0) return 320;
  uint32_t file_handle = 0;
  if (open_file_handle_simple(handle, "a.zing", 1, 73, 2104, &file_handle) != 0) return 321;
  uint8_t zax[128];
  const char selector[] = "files.seek.v1";
  uint32_t params_len = 12;
  uint32_t body_len = 4 + (uint32_t)sizeof(k_file_kind) - 1 +
                      4 + (uint32_t)sizeof(k_file_name) - 1 +
                      4 + (uint32_t)sizeof(selector) - 1 +
                      4 + params_len;
  uint32_t payload_zax = 1 + 4 + body_len;
  write_zax_header(zax, 1, 1, 74, 2105, payload_zax);
  uint32_t zoff = 48;
  zax[zoff++] = 2;
  ctl_write_u32(zax + zoff, body_len); zoff += 4;
  ctl_write_u32(zax + zoff, sizeof(k_file_kind) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_kind, sizeof(k_file_kind) - 1); zoff += sizeof(k_file_kind) - 1;
  ctl_write_u32(zax + zoff, sizeof(k_file_name) - 1); zoff += 4;
  memcpy(zax + zoff, k_file_name, sizeof(k_file_name) - 1); zoff += sizeof(k_file_name) - 1;
  ctl_write_u32(zax + zoff, sizeof(selector) - 1); zoff += 4;
  memcpy(zax + zoff, selector, sizeof(selector) - 1); zoff += sizeof(selector) - 1;
  ctl_write_u32(zax + zoff, params_len); zoff += 4;
  ctl_write_u32(zax + zoff, file_handle); zoff += 4;
  ctl_write_u32(zax + zoff, 0); zoff += 4;
  ctl_write_u32(zax + zoff, 9); zoff += 4; /* invalid whence */
  if (res_write((int32_t)handle, zax, zoff) <= 0) return 322;
  return wait_for_fail_code(handle, 74, 2105, "t_async_bad_params");
}
