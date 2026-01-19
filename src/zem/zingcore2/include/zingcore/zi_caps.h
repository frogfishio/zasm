/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct zi_cap_v1 {
  const char* kind;    /* e.g., "async", "file" */
  const char* name;    /* e.g., "default", "view" */
  uint32_t    version; /* capability semantic version */
  uint32_t    cap_flags;
  const uint8_t* meta;
  size_t meta_len;
  int (*describe)(uint8_t* out, size_t cap,
                  uint16_t op, uint32_t rid,
                  const uint8_t* payload, uint32_t payload_len);
  int (*open)(uint8_t* out, size_t cap,
              uint16_t op, uint32_t rid,
              const uint8_t* payload, uint32_t payload_len);
} zi_cap_v1;

typedef struct zi_cap_registry_v1 {
  const zi_cap_v1* const* caps;
  size_t cap_count;
} zi_cap_registry_v1;

#if defined(__APPLE__)
  #define ZI_WEAK_IMPORT __attribute__((weak_import))
#elif defined(__GNUC__) || defined(__clang__)
  #define ZI_WEAK_IMPORT __attribute__((weak))
#else
  #define ZI_WEAK_IMPORT
#endif

/* Core registry API */
int zi_cap_register(const zi_cap_v1* cap);          /* returns 1 on success, 0 on reject */
const zi_cap_registry_v1* zi_cap_registry(void);    /* sorted, stable view */

/* Common cap_flags bits */
enum {
  ZI_CAP_CAN_OPEN = 1u << 0,
};
