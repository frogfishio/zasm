/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint16_t ctl_read_u16(const uint8_t* p) {
  return (uint16_t)p[0] | (uint16_t)(p[1] << 8);
}

static inline uint32_t ctl_read_u32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void ctl_write_u16(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void ctl_write_u32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/* Minimal ZCL1 helpers */
typedef struct ctl_frame {
  const uint8_t* req;    /* points to start of frame */
  uint32_t req_len;
  uint16_t op;
  uint32_t rid;
  const uint8_t* payload;
  uint32_t payload_len;
} ctl_frame_t;

int ctl_parse(const uint8_t* req, uint32_t req_len, ctl_frame_t* out);
int ctl_write_error(uint8_t* out, uint32_t cap, uint16_t op, uint32_t rid,
                    const char* trace, const char* msg);
int ctl_write_ok(uint8_t* out, uint32_t cap, uint16_t op, uint32_t rid,
                 const uint8_t* payload, uint32_t payload_len);

/* Handle allocator: 0/1/2 reserved */
typedef struct ctl_handles {
  uint32_t next;
} ctl_handles_t;

void ctl_handles_init(ctl_handles_t* h);
uint32_t ctl_handle_alloc(ctl_handles_t* h);
