/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ctl_common.h"

int ctl_parse(const uint8_t* req, uint32_t req_len, ctl_frame_t* out) {
  if (!req || !out) return 0;
  if (req_len < 24) return 0;
  if (req[0] != 'Z' || req[1] != 'C' || req[2] != 'L' || req[3] != '1') return 0;
  uint16_t v = ctl_read_u16(req + 4);
  uint16_t op = ctl_read_u16(req + 6);
  uint32_t rid = ctl_read_u32(req + 8);
  uint32_t payload_len = ctl_read_u32(req + 20);
  if (v != 1) return 0;
  if (24u + payload_len > req_len) return 0;
  out->req = req;
  out->req_len = req_len;
  out->op = op;
  out->rid = rid;
  out->payload = req + 24;
  out->payload_len = payload_len;
  return 1;
}

int ctl_write_error(uint8_t* out, uint32_t cap, uint16_t op, uint32_t rid,
                    const char* trace, const char* msg) {
  uint32_t tlen = (uint32_t)strlen(trace);
  uint32_t mlen = (uint32_t)strlen(msg);
  uint32_t clen = 0;
  uint32_t payload_len = 4 + 4 + tlen + 4 + mlen + 4 + clen;
  uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  memcpy(out + 0, "ZCL1", 4);
  ctl_write_u16(out + 4, 1);
  ctl_write_u16(out + 6, op);
  ctl_write_u32(out + 8, rid);
  ctl_write_u32(out + 12, 0);
  ctl_write_u32(out + 16, payload_len);
  out[20] = 0; out[21] = 0; out[22] = 0; out[23] = 0;
  ctl_write_u32(out + 24, tlen);
  memcpy(out + 28, trace, tlen);
  ctl_write_u32(out + 28 + tlen, mlen);
  memcpy(out + 32 + tlen, msg, mlen);
  ctl_write_u32(out + 32 + tlen + mlen, clen);
  return (int)frame_len;
}

int ctl_write_ok(uint8_t* out, uint32_t cap, uint16_t op, uint32_t rid,
                 const uint8_t* payload, uint32_t payload_len) {
  uint32_t frame_len = 20 + payload_len;
  if (cap < frame_len) return -1;
  memcpy(out + 0, "ZCL1", 4);
  ctl_write_u16(out + 4, 1);
  ctl_write_u16(out + 6, op);
  ctl_write_u32(out + 8, rid);
  ctl_write_u32(out + 12, 0);
  ctl_write_u32(out + 16, payload_len);
  if (payload_len) memcpy(out + 20, payload, payload_len);
  return (int)frame_len;
}

void ctl_handles_init(ctl_handles_t* h) { if (h) h->next = 3; }

uint32_t ctl_handle_alloc(ctl_handles_t* h) {
  if (!h) return 0;
  uint32_t out = h->next;
  if (out == 0xFFFFFFFFu) return 0;
  h->next++;
  return out;
}
